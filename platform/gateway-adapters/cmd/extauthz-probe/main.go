// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Command extauthz-probe issues ONE Envoy ext_authz Check against a running
// gateway-adapters listener and prints what came back.
//
// # WHY THIS EXISTS
//
// runtime-e2e/2860_client_version_telemetry has to drive a REAL governed
// request through the adapter before it can assert that the adapter identified
// itself to the engine. The seam is gRPC, and the three alternatives were all
// worse:
//
//   - curl cannot speak it.
//   - grpcurl needs either server reflection (which this listener does not
//     enable, deliberately: it serves governed traffic) or .proto files, which
//     reach this repo only as compiled Go packages.
//   - A shell-driven Envoy in front of the adapter is a second moving part to
//     boot, configure and diagnose in a suite that is about a counter.
//
// It is a DIAGNOSTIC, not a product surface: it is not in any image, not in
// build.yml, and an operator debugging a seam is its other legitimate user.
//
// Exit codes: 0 = the Check completed and its verdict is on stdout as JSON;
// 1 = the call itself failed. A DENY is exit 0 with "status":"denied" — the
// caller decides whether a deny is the expected answer, because for the
// counting question it is not the interesting axis.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9090", "gateway-adapters gRPC listen address")
	path := flag.String("path", "/probe", ":path pseudo-header of the probed request")
	method := flag.String("method", "GET", ":method pseudo-header")
	body := flag.String("body", "", "request body (empty = a bodyless request, gated on the request line)")
	stage := flag.String("stage", "", "override the adapter's default stage via the gateway context extension")
	timeout := flag.Duration("timeout", 20*time.Second, "overall deadline")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fail("dial %s: %v", *addr, err)
	}
	// The close error is discarded EXPLICITLY rather than by a bare `defer
	// conn.Close()`. This is a probe: the connection is closed as the process
	// exits, and there is no caller for a close failure to be reported to. The
	// explicit discard says that was decided rather than overlooked, which is
	// what errcheck is asking.
	//
	// Pre-existing on main and found by #3704 only because this directory is
	// OUTSIDE the five CI lints: the workflow lints platform/{agent,orchestrator,
	// connectors,shared,decision}, and platform/gateway-adapters has no go.mod
	// of its own, so it belongs to the `platform` module, which nothing lints.
	defer func() { _ = conn.Close() }()

	ext := map[string]string{}
	if *stage != "" {
		ext["axonflow-stage"] = *stage
	}

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			ContextExtensions: ext,
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: *method,
					Path:   *path,
					Headers: map[string]string{
						":method":      *method,
						":path":        *path,
						"content-type": "application/json",
					},
					Body: *body,
				},
			},
		},
	}

	resp, err := authv3.NewAuthorizationClient(conn).Check(ctx, req)
	if err != nil {
		fail("Check: %v", err)
	}

	out := map[string]any{"status": "allowed", "code": resp.GetStatus().GetCode()}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		out["status"] = "denied"
		out["http_status"] = int32(resp.GetDeniedResponse().GetStatus().GetCode())
		out["body"] = resp.GetDeniedResponse().GetBody()
	}
	// The response headers the adapter stamps carry the decision id, which is
	// what makes a failed run diagnosable rather than merely red.
	hdrs := map[string]string{}
	for _, h := range resp.GetOkResponse().GetHeaders() {
		hdrs[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	for _, h := range resp.GetDeniedResponse().GetHeaders() {
		hdrs[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	out["headers"] = hdrs

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "extauthz-probe: "+format+"\n", args...)
	os.Exit(1)
}
