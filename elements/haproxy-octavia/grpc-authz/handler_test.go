// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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
	default:
		return nil, status.Error(codes.Unavailable, "fixture unavailable")
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

func assertDecision(t *testing.T, response *httptest.ResponseRecorder, want string) {
	t.Helper()
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != formContentType ||
		response.Header().Get("Content-Length") != strconv.Itoa(len(want)) || response.Body.String() != want {
		t.Fatalf("expected HTTP 200 with the ordered decision form (%d bytes), got %d with %d bytes and headers %v",
			len(want), response.Code, response.Body.Len(), response.Header())
	}
}
