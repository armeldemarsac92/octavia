// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	httpStatus "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const testPool = "b2414b7f-56ba-430f-b636-51b681e66a33"

type testAuthorizer struct {
	auth.UnimplementedAuthorizationServer
	requests chan *auth.AttributeContext_HttpRequest
}

func (a *testAuthorizer) Check(ctx context.Context, request *auth.CheckRequest) (*auth.CheckResponse, error) {
	httpRequest := request.GetAttributes().GetRequest().GetHttp()
	a.requests <- httpRequest
	switch httpRequest.GetPath() {
	case "/products?drop=x&tone=old&tone=older&keep=a%20b&keep=two":
		return &auth.CheckResponse{
			Status: status.New(codes.OK, "").Proto(),
			HttpResponse: &auth.CheckResponse_OkResponse{OkResponse: &auth.OkHttpResponse{
				HeadersToRemove: []string{"Authorization", ":authority"},
				Headers: []*core.HeaderValueOption{
					{Header: &core.HeaderValue{Key: "x-user", Value: "synthetic"}},
					{Header: &core.HeaderValue{Key: "x-user", Value: "reader"}, Append: wrapperspb.Bool(true)},
					{Header: &core.HeaderValue{Key: "x-feature", Value: "enabled"}, AppendAction: core.HeaderValueOption_ADD_IF_ABSENT},
					{Header: &core.HeaderValue{Key: "x-tag", Value: "read"}, AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS},
				},
				QueryParametersToSet:    []*core.QueryParameter{{Key: "tone", Value: "blue%20green"}, {Key: "new", Value: "yes"}},
				QueryParametersToRemove: []string{"drop"},
				ResponseHeadersToAdd: []*core.HeaderValueOption{
					{Header: &core.HeaderValue{Key: "x-session", Value: "checked"}, AppendAction: core.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD},
					{Header: &core.HeaderValue{Key: "set-cookie", Value: "sample=a"}},
					{Header: &core.HeaderValue{Key: "set-cookie", Value: "another=b"}, Append: wrapperspb.Bool(true)},
				},
			}},
			DynamicMetadata: &structpb.Struct{Fields: map[string]*structpb.Value{"fixture": structpb.NewBoolValue(true)}},
		}, nil
	case "/restricted":
		return &auth.CheckResponse{
			Status: status.New(codes.PermissionDenied, "").Proto(),
			HttpResponse: &auth.CheckResponse_DeniedResponse{DeniedResponse: &auth.DeniedHttpResponse{
				Status: &httpStatus.HttpStatus{Code: httpStatus.StatusCode_Unauthorized},
				Body:   "Log in to continue.",
				Headers: []*core.HeaderValueOption{
					{Header: &core.HeaderValue{Key: "www-authenticate", Value: "Probe"}},
					{Header: &core.HeaderValue{Key: "set-cookie", Value: "sample=a"}},
					{Header: &core.HeaderValue{Key: "set-cookie", Value: "another=b"}},
				},
			}},
		}, nil
	case "/auth-error":
		return &auth.CheckResponse{
			Status: status.New(codes.Internal, "").Proto(),
			HttpResponse: &auth.CheckResponse_ErrorResponse{ErrorResponse: &auth.DeniedHttpResponse{
				Status:  &httpStatus.HttpStatus{Code: httpStatus.StatusCode_ServiceUnavailable},
				Body:    "Please retry.",
				Headers: []*core.HeaderValueOption{{Header: &core.HeaderValue{Key: "retry-after", Value: "30"}}},
			}},
		}, nil
	case "/slow":
		<-ctx.Done()
		return nil, ctx.Err()
	case "/binary", "/empty":
		return &auth.CheckResponse{Status: status.New(codes.OK, "").Proto()}, nil
	default:
		return nil, status.Error(codes.Unavailable, "fixture unavailable")
	}
}

func TestUnixCheckRawBody(t *testing.T) {
	root := t.TempDir() + string(filepath.Separator)
	listener, err := net.Listen("unix", root+testPool+".sock")
	if err != nil {
		t.Fatal(err)
	}
	// A 4 MiB body plus the protobuf metadata exceeds gRPC's default
	// receive limit. The authorizer must configure room for the envelope.
	server := grpc.NewServer(grpc.MaxRecvMsgSize(8 * 1024 * 1024))
	authorizer := &testAuthorizer{requests: make(chan *auth.AttributeContext_HttpRequest, 1)}
	auth.RegisterAuthorizationServer(server, authorizer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	handler := newHandler(unixCheck(root))

	for _, tc := range []struct {
		path string
		body []byte
	}{
		{path: "/binary", body: bytes.Repeat([]byte{0, 0xff, '&', '='}, 1024*1024)},
		{path: "/empty"},
	} {
		form := validForm(tc.path) + "&h.x-selected=header"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, rawBodyRequest(form, tc.body))
		assertDecision(t, response, "decision=allow")
		got := <-authorizer.requests
		if got.GetSize() != int64(len(tc.body)) || !bytes.Equal(got.GetRawBody(), tc.body) || got.GetBody() != "" ||
			got.GetPath() != tc.path || got.GetHeaders()["x-selected"] != "header" {
			t.Fatalf("unexpected Check for %s: Size=%d, %d raw bytes, %d string bytes",
				tc.path, got.GetSize(), len(got.GetRawBody()), len(got.GetBody()))
		}
	}
}

func TestRawBodyLeavesRoomForProtobuf(t *testing.T) {
	const largestBody = 2146435071
	form := validForm("/upload")
	frame := rawBodyRequest(form, nil)
	frame.ContentLength += largestBody
	metadata, err := readCheckRequest(httptest.NewRecorder(), frame)
	if err != nil || metadata.GetSize() != largestBody {
		t.Fatal("expected the largest supported declared body to fit")
	}
	frame = rawBodyRequest(form, nil)
	frame.ContentLength += largestBody + 1
	if _, err = readCheckRequest(httptest.NewRecorder(), frame); err == nil {
		t.Fatal("accepted a body without room for a protobuf envelope")
	}
}

func TestInvalidRawBodyFrame(t *testing.T) {
	handler := newHandler(func(context.Context, string, *auth.CheckRequest) (*auth.CheckResponse, error) {
		t.Fatal("called the authorizer with an invalid body frame")
		return nil, nil
	})
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"missing length", func(r *http.Request) { r.ContentLength = -1 }},
		{"chunked frame", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }},
		{"short form", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("method=POST")) }},
		{"short body", func(r *http.Request) { r.ContentLength++ }},
		{"oversized metadata", func(r *http.Request) { r.Header.Set(formLengthHeader, strconv.Itoa(maxFormSize+1)) }},
		{"oversized declared body", func(r *http.Request) { r.ContentLength += maxForwardBodySize }},
		{"duplicate metadata length", func(r *http.Request) { r.Header.Add(formLengthHeader, "1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := rawBodyRequest(validForm("/binary"), []byte{0, 0xff})
			tc.change(request)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
				t.Fatalf("expected an empty 503 response, got %d", response.Code)
			}
		})
	}
}

func TestUnixCheck(t *testing.T) {
	root := t.TempDir() + string(filepath.Separator)
	listener, err := net.Listen("unix", root+testPool+".sock")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	authorizer := &testAuthorizer{requests: make(chan *auth.AttributeContext_HttpRequest, 3)}
	auth.RegisterAuthorizationServer(server, authorizer)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	handler := newHandler(unixCheck(root))

	path := "/products?drop=x&tone=old&tone=older&keep=a%20b&keep=two"
	response := postCheck(handler, validForm(path)+"&h.x-test=first&h.x-test=second&h.%3Aauthority=catalogue.example%3A443")
	want := "decision=allow&remove=authorization&set.x-user=synthetic&add.x-user=reader" +
		"&ifabsent.x-feature=enabled&ifpresent.x-tag=read&query=" +
		url.QueryEscape("tone=blue%20green&keep=a%20b&keep=two&new=yes") +
		"&response.set.x-session=checked&response.add.set-cookie=sample%3Da&response.add.set-cookie=another%3Db"
	assertDecision(t, response, want)
	got := <-authorizer.requests
	wantRequest := &auth.AttributeContext_HttpRequest{
		Method: "POST", Path: path, Host: "catalogue.example:443", Scheme: "https", Protocol: "HTTP/2", Size: -1,
		Headers: map[string]string{"x-test": "first,second", ":authority": "catalogue.example:443"},
	}
	if !proto.Equal(got, wantRequest) {
		t.Fatalf("unexpected typed Check: %v", got)
	}

	response = postCheck(handler, validForm("/restricted"))
	assertDecision(t, response, "decision=deny&status=401&body=Log+in+to+continue."+
		"&set.www-authenticate=Probe&set.set-cookie=sample%3Da&add.set-cookie=another%3Db")

	response = postCheck(handler, validForm("/auth-error"))
	assertDecision(t, response, "decision=deny&status=503&body=Please+retry.&set.retry-after=30")

	response = postCheck(handler, validForm("/unavailable"))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("expected an empty 503 response on gRPC transport failure, got %d", response.Code)
	}

	deadline := time.Now().Add(400 * time.Millisecond)
	ctx := context.WithValue(t.Context(), socketDeadlineKey{}, deadline)
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/v1/check/"+testPool, strings.NewReader(validForm("/slow")))
	request.Header.Set("Content-Type", formContentType)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("expected an empty 503 response on deadline expiry, got %d", response.Code)
	}
}

func TestFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		form   string
		result *auth.CheckResponse
	}{
		{name: "ambiguous request", form: validForm("/products") + "&path=%2Fother"},
		{name: "oversized request", form: validForm("/products") + "&h.x-test=" + strings.Repeat("a", maxFormSize)},
		{
			name: "inconsistent successful status and error result", form: validForm("/products"),
			result: &auth.CheckResponse{
				Status: status.New(codes.OK, "").Proto(),
				HttpResponse: &auth.CheckResponse_ErrorResponse{ErrorResponse: &auth.DeniedHttpResponse{
					Body: "private diagnostic",
				}},
			},
		},
		{
			name: "unrepresentable decision", form: validForm("/products"),
			result: &auth.CheckResponse{
				Status: status.New(codes.OK, "").Proto(),
				HttpResponse: &auth.CheckResponse_OkResponse{OkResponse: &auth.OkHttpResponse{
					ResponseHeadersToAdd: []*core.HeaderValueOption{{
						Header: &core.HeaderValue{Key: "x-test", Value: "value"}, AppendAction: core.HeaderValueOption_HeaderAppendAction(9),
					}},
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := newHandler(func(context.Context, string, *auth.CheckRequest) (*auth.CheckResponse, error) {
				if tc.result == nil {
					t.Fatal("called the authorizer with an invalid request")
				}
				return tc.result, nil
			})
			response := postCheck(handler, tc.form)
			if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
				t.Fatalf("expected an empty 503 response, got %d", response.Code)
			}
		})
	}
}

func TestDefaultDenialAndReplyLimit(t *testing.T) {
	body := strings.Repeat("*", 32*1024)
	denied := &auth.DeniedHttpResponse{Body: body}
	handler := newHandler(func(context.Context, string, *auth.CheckRequest) (*auth.CheckResponse, error) {
		return &auth.CheckResponse{
			Status:       status.New(codes.PermissionDenied, "").Proto(),
			HttpResponse: &auth.CheckResponse_DeniedResponse{DeniedResponse: denied},
		}, nil
	})
	assertDecision(t, postCheck(handler, validForm("/products")), "decision=deny&status=403&body="+url.QueryEscape(body))
	denied.Body = strings.Repeat("*", maxFormSize/2)
	response := postCheck(handler, validForm("/products"))
	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("expected an empty 503 response when the form exceeds the reply limit, got %d", response.Code)
	}
}

func validForm(path string) string {
	return "method=POST&path=" + url.QueryEscape(path) + "&host=catalogue.example%3A443&scheme=https&protocol=HTTP%2F2"
}

func postCheck(handler http.Handler, form string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/v1/check/"+testPool, strings.NewReader(form))
	request.Header.Set("Content-Type", formContentType)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func rawBodyRequest(form string, body []byte) *http.Request {
	frame := io.MultiReader(strings.NewReader(form), bytes.NewReader(body))
	request := httptest.NewRequest(http.MethodPost, "/v1/check/"+testPool, frame)
	request.ContentLength = int64(len(form)) + int64(len(body))
	request.Header.Set("Content-Type", bodyContentType)
	request.Header.Set(formLengthHeader, strconv.Itoa(len(form)))
	return request
}

func assertDecision(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != formContentType ||
		response.Header().Get("Content-Length") != strconv.Itoa(len(want)) || response.Body.String() != want {
		t.Fatalf("expected HTTP 200 with the ordered decision form (%d bytes), got %d with %d bytes and headers %v",
			len(want), response.Code, response.Body.Len(), response.Header())
	}
}
