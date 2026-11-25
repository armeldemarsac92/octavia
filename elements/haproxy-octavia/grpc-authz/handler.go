// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/net/http/httpguts"
)

const (
	formContentType  = "application/x-www-form-urlencoded"
	bodyContentType  = "application/vnd.octavia.grpc-authz-body"
	formLengthHeader = "Octavia-Form-Length"
	// The protobuf envelope and selected headers must fit alongside raw_body.
	maxForwardBodySize = math.MaxInt32 - 4*maxFormSize
)

var (
	poolID         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	errInvalidForm = errors.New("invalid authorization form")
)

type checkFunc func(context.Context, string, *auth.CheckRequest) (*auth.CheckResponse, error)

func newHandler(check checkFunc) http.Handler {
	var inFlightBodyBytes atomic.Int64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Value(socketDeadlineKey{}).(time.Time)
		if !ok {
			deadline = time.Now().Add(checkTimeout)
		}
		// Reserve time to write a 503 after a timed-out Check.
		workDeadline := deadline.Add(-100 * time.Millisecond)
		ctx, cancel := context.WithDeadline(r.Context(), workDeadline)
		defer cancel()
		controller := http.NewResponseController(w)
		_ = controller.SetReadDeadline(workDeadline)
		_ = controller.SetWriteDeadline(deadline)

		pool, pathOK := strings.CutPrefix(r.RequestURI, "/v1/check/")
		if r.Method != http.MethodPost || !pathOK || !poolID.MatchString(pool) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		httpRequest, err := readCheckRequest(w, r)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if size := httpRequest.Size; size > 0 {
			// Bound the total amount declared by concurrent checks while letting
			// each read allocate only as the raw bytes actually arrive.
			reserved := inFlightBodyBytes.Add(size)
			defer inFlightBodyBytes.Add(-size)
			if reserved > maxForwardBodySize {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			body, err := io.ReadAll(io.LimitReader(r.Body, size))
			if err != nil || int64(len(body)) != size {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			httpRequest.RawBody = body
		}
		if ctx.Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		request := &auth.CheckRequest{Attributes: &auth.AttributeContext{
			Request: &auth.AttributeContext_Request{Http: httpRequest},
		}}
		response, err := check(ctx, pool, request)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body, err := decisionForm(response, httpRequest.Path)
		if err != nil || ctx.Err() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", formContentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = io.WriteString(w, body)
	})
}

func readCheckRequest(w http.ResponseWriter, r *http.Request) (*auth.AttributeContext_HttpRequest, error) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || len(r.Header.Values("Content-Type")) != 1 {
		return nil, errInvalidForm
	}
	size := int64(-1)
	formSize := int64(-1)
	var formReader io.Reader
	switch contentType {
	case formContentType:
		formReader = http.MaxBytesReader(w, r.Body, maxFormSize)
	case bodyContentType:
		// The private body frame starts with the legacy form and ends with
		// the original bytes. A fixed HTTP length delimits the whole frame.
		lengths := r.Header.Values(formLengthHeader)
		if len(lengths) != 1 || len(r.TransferEncoding) != 0 {
			return nil, errInvalidForm
		}
		length, err := strconv.ParseUint(lengths[0], 10, 32)
		if err != nil || length == 0 || length > maxFormSize || r.ContentLength < int64(length) {
			return nil, errInvalidForm
		}
		formSize = int64(length)
		size = r.ContentLength - formSize
		if size > maxForwardBodySize {
			return nil, errInvalidForm
		}
		formReader = io.LimitReader(r.Body, formSize)
	default:
		return nil, errInvalidForm
	}
	body, err := io.ReadAll(formReader)
	if err != nil || (formSize >= 0 && int64(len(body)) != formSize) {
		return nil, errInvalidForm
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, errInvalidForm
	}
	httpRequest := &auth.AttributeContext_HttpRequest{Size: size}
	for field, target := range map[string]*string{
		"method": &httpRequest.Method, "path": &httpRequest.Path, "host": &httpRequest.Host,
		"scheme": &httpRequest.Scheme, "protocol": &httpRequest.Protocol,
	} {
		values := form[field]
		if len(values) != 1 || !httpguts.ValidHeaderFieldValue(values[0]) {
			return nil, errInvalidForm
		}
		*target = strings.ToValidUTF8(values[0], "!")
		delete(form, field)
	}
	if !httpguts.ValidHeaderFieldName(httpRequest.Method) || httpRequest.Path == "" ||
		httpRequest.Scheme == "" || httpRequest.Protocol == "" {
		return nil, errInvalidForm
	}
	if len(form) > 0 {
		httpRequest.Headers = make(map[string]string, len(form))
	}
	for field, values := range form {
		name, ok := strings.CutPrefix(field, "h.")
		authority := name == ":authority" && httpRequest.Protocol == "HTTP/2" &&
			len(values) == 1 && values[0] == httpRequest.Host
		if !ok || (!authority && !httpguts.ValidHeaderFieldName(name)) || name != strings.ToLower(name) {
			return nil, errInvalidForm
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return nil, errInvalidForm
			}
		}
		// Envoy's HttpRequest.headers map combines duplicate fields with commas.
		httpRequest.Headers[name] = strings.ToValidUTF8(strings.Join(values, ","), "!")
	}
	return httpRequest, nil
}
