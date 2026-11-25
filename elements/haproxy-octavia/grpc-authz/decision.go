// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/net/http/httpguts"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
)

var errInvalidDecision = errors.New("unsupported authorization decision")

type decisionFields struct {
	encoded strings.Builder
	err     error
}

func (d *decisionFields) add(key, value string) {
	if d.err != nil {
		return
	}
	field := url.QueryEscape(key) + "=" + url.QueryEscape(value)
	if d.encoded.Len() != 0 {
		field = "&" + field
	}
	if d.encoded.Len()+len(field) > maxFormSize {
		d.err = errInvalidDecision
		return
	}
	d.encoded.WriteString(field)
}

func decisionForm(response *auth.CheckResponse, path string) (string, error) {
	if response == nil || response.Status == nil || hasUnknownFields(response) {
		return "", errInvalidDecision
	}
	code := response.Status.Code
	if code < 0 || code > int32(codes.Unauthenticated) {
		return "", errInvalidDecision
	}
	var form decisionFields
	var err error
	switch decision := response.HttpResponse.(type) {
	case nil:
		if code == int32(codes.OK) {
			form.add("decision", "allow")
		} else {
			err = form.deny(nil)
		}
	case *auth.CheckResponse_OkResponse:
		if code != int32(codes.OK) || decision.OkResponse == nil || hasUnknownFields(decision.OkResponse) {
			return "", errInvalidDecision
		}
		err = form.allow(decision.OkResponse, path)
	case *auth.CheckResponse_DeniedResponse:
		if code == int32(codes.OK) || decision.DeniedResponse == nil || hasUnknownFields(decision.DeniedResponse) {
			return "", errInvalidDecision
		}
		err = form.deny(decision.DeniedResponse)
	case *auth.CheckResponse_ErrorResponse:
		if code == int32(codes.OK) || decision.ErrorResponse == nil || hasUnknownFields(decision.ErrorResponse) {
			return "", errInvalidDecision
		}
		// An explicit error reply supplies the response to send downstream.
		// Transport failures never reach this decision.
		err = form.deny(decision.ErrorResponse)
	default:
		return "", errInvalidDecision
	}
	if err != nil {
		return "", err
	}
	return form.encoded.String(), form.err
}

func (d *decisionFields) allow(allow *auth.OkHttpResponse, path string) error {
	d.add("decision", "allow")
	for _, key := range allow.HeadersToRemove {
		name := strings.ToLower(key)
		// Envoy ignores attempts to remove Host or a pseudo-header.
		if name == "host" || strings.HasPrefix(name, ":") {
			continue
		}
		if !httpguts.ValidHeaderFieldName(key) || !mutableHeader(name) {
			return errInvalidDecision
		}
		d.add("remove", name)
	}
	if err := d.addHeaders(allow.Headers, "", false); err != nil {
		return err
	}
	if len(allow.QueryParametersToSet) != 0 || len(allow.QueryParametersToRemove) != 0 {
		_, query, _ := strings.Cut(path, "?")
		updated, err := updateQuery(query, allow.QueryParametersToSet, allow.QueryParametersToRemove)
		if err != nil {
			return err
		}
		if updated != query {
			if !strings.HasPrefix(path, "/") {
				return errInvalidDecision
			}
			d.add("query", updated)
		}
	}
	return d.addHeaders(allow.ResponseHeadersToAdd, "response.", false)
}

func (d *decisionFields) deny(deny *auth.DeniedHttpResponse) error {
	status := int(deny.GetStatus().GetCode())
	if status == 0 {
		status = http.StatusForbidden
	}
	body := deny.GetBody()
	switch {
	case status < 200 || status > 599:
		return errInvalidDecision
	case body != "" && (status == http.StatusNoContent || status == http.StatusResetContent || status == http.StatusNotModified):
		return errInvalidDecision
	}
	d.add("decision", "deny")
	d.add("status", strconv.Itoa(status))
	d.add("body", body)
	return d.addHeaders(deny.GetHeaders(), "", true)
}

func (d *decisionFields) addHeaders(options []*core.HeaderValueOption, prefix string, denial bool) error {
	// Envoy removes default denial headers that will be replaced, then emits
	// every supplied value. This preserves repeated fields such as Set-Cookie.
	var defaultDenialHeaders map[string]bool
	if denial {
		defaultDenialHeaders = make(map[string]bool)
	}
	for _, option := range options {
		header := option.GetHeader()
		if header == nil || hasUnknownFields(option) || hasUnknownFields(header) {
			return errInvalidDecision
		}
		name := strings.ToLower(header.Key)
		if !httpguts.ValidHeaderFieldName(header.Key) || !mutableHeader(name) {
			return errInvalidDecision
		}
		value := header.Value
		if len(header.RawValue) != 0 {
			if value != "" {
				return errInvalidDecision
			}
			value = string(header.RawValue)
		}
		if !httpguts.ValidHeaderFieldValue(value) {
			return errInvalidDecision
		}
		op, err := headerOperation(option, prefix == "response.")
		if err != nil {
			return err
		}
		if value == "" && !option.KeepEmptyValue {
			continue
		}
		if denial && op == "set." && option.AppendAction == core.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
			if defaultDenialHeaders[name] {
				op = "add."
			}
			defaultDenialHeaders[name] = true
		} else if op == "set." || op == "ifpresent." {
			delete(defaultDenialHeaders, name)
		}
		d.add(prefix+op+name, value)
	}
	return d.err
}

func headerOperation(option *core.HeaderValueOption, downstream bool) (string, error) {
	if option.GetAppend() != nil {
		if option.AppendAction != core.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD {
			return "", errInvalidDecision
		}
		if option.GetAppend().GetValue() {
			return "add.", nil
		}
		return "set.", nil
	}
	switch option.GetAppendAction() {
	case core.HeaderValueOption_APPEND_IF_EXISTS_OR_ADD:
		// Proto3 omits zero-valued enums, including APPEND_IF_EXISTS_OR_ADD.
		// Envoy defaults to append for response_headers_to_add and to replace
		// for request and denial headers. An explicit append uses the wrapper.
		if downstream {
			return "add.", nil
		}
		return "set.", nil
	case core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD:
		return "set.", nil
	case core.HeaderValueOption_ADD_IF_ABSENT:
		return "ifabsent.", nil
	case core.HeaderValueOption_OVERWRITE_IF_EXISTS:
		return "ifpresent.", nil
	default:
		return "", errInvalidDecision
	}
}

func mutableHeader(name string) bool {
	switch name {
	case "host", "content-length", "connection", "proxy-connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade":
		return false
	default:
		return httpguts.ValidHeaderFieldName(name)
	}
}

func updateQuery(query string, set []*core.QueryParameter, remove []string) (string, error) {
	values := make(map[string]string, len(set))
	removed := make(map[string]bool, len(remove))
	keys := make([]string, 0, len(set))
	for _, param := range set {
		if param == nil || hasUnknownFields(param) || !validQueryPart(param.Key, true) || !validQueryPart(param.Value, false) {
			return "", errInvalidDecision
		}
		if _, exists := values[param.Key]; !exists {
			keys = append(keys, param.Key)
		}
		values[param.Key] = param.Value
	}
	for _, name := range remove {
		if !validQueryPart(name, true) {
			return "", errInvalidDecision
		}
		removed[name] = true
	}

	// Match the raw parameter names as Envoy does. Keep unaffected segments
	// byte-for-byte, including repeated values and their original escaping.
	var parts []string
	if query != "" {
		for part := range strings.SplitSeq(query, "&") {
			name, _, _ := strings.Cut(part, "=")
			if removed[name] {
				continue
			}
			if value, exists := values[name]; exists {
				parts = append(parts, name+"="+value)
				removed[name] = true
				continue
			}
			parts = append(parts, part)
		}
	}
	for _, name := range keys {
		if !removed[name] {
			parts = append(parts, name+"="+values[name])
		}
	}
	return strings.Join(parts, "&"), nil
}

func validQueryPart(part string, name bool) bool {
	if strings.ContainsAny(part, "&#") || (name && (part == "" || strings.Contains(part, "="))) {
		return false
	}
	for i := 0; i < len(part); i++ {
		if part[i] <= ' ' || part[i] >= 0x7f {
			return false
		}
	}
	_, err := url.QueryUnescape(part)
	return err == nil
}

func hasUnknownFields(message proto.Message) bool {
	return len(message.ProtoReflect().GetUnknown()) != 0
}
