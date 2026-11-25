// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"golang.org/x/net/netutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	httpSocket     = "/run/octavia/grpc-authz.sock"
	authSocketRoot = "/run/octavia/grpc-auth/"
	checkTimeout   = 3 * time.Second
	maxFormSize    = 256 * 1024
)

type socketDeadlineKey struct{}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Println("octavia-grpc-authz 1")
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--capabilities" {
		fmt.Println("grpc_external_auth_forward_body_v1")
		return
	}
	if len(os.Args) != 1 {
		log.Fatal("usage: octavia-grpc-authz [--version|--capabilities]")
	}
	listener, err := activatedListener()
	if err != nil {
		log.Fatal(err)
	}
	server := http.Server{
		Handler:           newHandler(unixCheck(authSocketRoot)),
		ReadHeaderTimeout: time.Second,
		ReadTimeout:       checkTimeout,
		WriteTimeout:      checkTimeout,
		MaxHeaderBytes:    8 * 1024,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, socketDeadlineKey{}, time.Now().Add(checkTimeout))
		},
	}
	server.SetKeepAlivesEnabled(false)
	if err := server.Serve(netutil.LimitListener(listener, 128)); err != nil {
		log.Fatal("could not serve the grpc-authz socket")
	}
}

func activatedListener() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) ||
		os.Getenv("LISTEN_FDS") != "1" || os.Getenv("LISTEN_FDNAMES") != "grpc-authz" {
		return nil, errors.New("expected one systemd socket named grpc-authz")
	}
	const fd = 3
	file := os.NewFile(fd, "grpc-authz")
	defer file.Close()
	accepts, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
	if err != nil || accepts != 1 {
		return nil, errors.New("grpc-authz file descriptor must be a listening socket")
	}
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, errors.New("could not open the grpc-authz listener")
	}
	if unix, ok := listener.(*net.UnixListener); ok && unix.Addr().Network() == "unix" && unix.Addr().String() == httpSocket {
		return unix, nil
	}
	listener.Close()
	return nil, errors.New("systemd socket must listen on the grpc-authz Unix stream path")
}

func unixCheck(socketRoot string) checkFunc {
	return func(ctx context.Context, pool string, request *auth.CheckRequest) (*auth.CheckResponse, error) {
		conn, err := grpc.NewClient("unix://"+socketRoot+pool+".sock",
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithNoProxy(),
			grpc.WithDisableServiceConfig(),
			grpc.WithDisableRetry(),
			grpc.WithMaxHeaderListSize(16*1024),
			grpc.WithDefaultCallOptions(
				grpc.MaxCallRecvMsgSize(maxFormSize),
				grpc.MaxCallSendMsgSize(maxFormSize),
				// Commit when the Check payload is sent so it cannot be replayed.
				grpc.MaxRetryRPCBufferSize(0),
			),
		)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		var options []grpc.CallOption
		if request.GetAttributes().GetRequest().GetHttp().GetSize() >= 0 {
			// The peer's receive limit must cover the raw body and the protobuf
			// envelope. The local decision and legacy send limits stay small.
			options = append(options, grpc.MaxCallSendMsgSize(math.MaxInt32))
		}
		return auth.NewAuthorizationClient(conn).Check(ctx, request, options...)
	}
}
