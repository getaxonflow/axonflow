// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
)

// startServer runs the full Server (all three services + health) on a
// bufconn listener and returns a connected client.
func startServer(t *testing.T, cfg Config) *grpc.ClientConn {
	t.Helper()
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.GracefulStop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func openExtProcStream(t *testing.T, conn *grpc.ClientConn) extprocv3.ExternalProcessor_ProcessClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	return stream
}

func requestHeadersMsg(endOfStream bool, extra ...*corev3.HeaderValue) *extprocv3.ProcessingRequest {
	headers := []*corev3.HeaderValue{
		{Key: ":method", RawValue: []byte("POST")},
		{Key: ":path", RawValue: []byte("/v1/chat/completions")},
		{Key: "authorization", RawValue: []byte("Bearer jwt-proc")},
		{Key: "x-user-email", RawValue: []byte("dev@example.com")},
	}
	headers = append(headers, extra...)
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{
			Headers:     &corev3.HeaderMap{Headers: headers},
			EndOfStream: endOfStream,
		},
	}}
}

func requestBodyMsg(body string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: eos},
	}}
}

func responseHeadersMsg() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: &corev3.HeaderMap{}},
	}}
}

func responseBodyMsg(body string, eos bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: eos},
	}}
}

// roundTrip sends one message and reads one response.
func roundTrip(t *testing.T, stream extprocv3.ExternalProcessor_ProcessClient, msg *extprocv3.ProcessingRequest) *extprocv3.ProcessingResponse {
	t.Helper()
	if err := stream.Send(msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	return resp
}

func TestExtProcFullConversationAllow(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	// This test asserts the identity-header PLUMBING, so it opts in to
	// trusting them; the safe-by-default behavior (headers dropped) is
	// pinned by TestExtProcForgedIdentityHeadersDroppedByDefault.
	cfg.TrustIdentityHeaders = true
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	if resp := roundTrip(t, stream, requestHeadersMsg(false)); resp.GetRequestHeaders() == nil {
		t.Fatalf("expected HeadersResponse, got %+v", resp)
	}
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	rb := resp.GetRequestBody()
	if rb == nil {
		t.Fatalf("expected BodyResponse, got %+v", resp)
	}
	if rb.GetResponse().GetBodyMutation() != nil {
		t.Fatalf("clean allow must not mutate the body: %+v", rb)
	}
	// Decision headers ride the body response under BUFFERED mode.
	var foundDecision bool
	for _, h := range rb.GetResponse().GetHeaderMutation().GetSetHeaders() {
		if h.GetHeader().GetKey() == "x-axonflow-decision-id" {
			foundDecision = true
		}
	}
	if !foundDecision {
		t.Fatalf("decision header not stamped: %+v", rb.GetResponse().GetHeaderMutation())
	}

	if resp := roundTrip(t, stream, responseHeadersMsg()); resp.GetResponseHeaders() == nil {
		t.Fatalf("expected response HeadersResponse, got %+v", resp)
	}
	respBody := roundTrip(t, stream, responseBodyMsg(`{"choices":[{"message":{"content":"hi"}}]}`, true))
	if respBody.GetResponseBody() == nil || respBody.GetResponseBody().GetResponse().GetBodyMutation() != nil {
		t.Fatalf("clean response must pass unmutated: %+v", respBody)
	}

	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["user_token"] != "jwt-proc" {
		t.Fatalf("bearer not propagated: %v", decide["user_token"])
	}
	co := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput })
	if co["user_token"] != "jwt-proc" {
		t.Fatalf("check-output user_token not propagated: %v", co)
	}
	hdrs := func() map[string][]string {
		pdp.mu.Lock()
		defer pdp.mu.Unlock()
		return pdp.lastCheckOutputHdrs
	}()
	if got := hdrs["X-User-Email"]; len(got) == 0 || got[0] != "dev@example.com" {
		t.Fatalf("X-User-Email not propagated to check-output: %v", hdrs)
	}
}

func TestExtProcForgedIdentityHeadersDroppedByDefault(t *testing.T) {
	// A governed client forges X-User-Email/X-Session-Id. Under the default
	// config (TrustIdentityHeaders=false) neither may reach the engine —
	// agentgateway cannot strip them pre-callout (route header modifiers run
	// AFTER ext_proc), so the adapter is the enforcement point.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	if cfg.TrustIdentityHeaders {
		t.Fatal("test config must use the default untrusted posture")
	}
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	// Build the headers WITHOUT the helper's default x-user-email so the
	// forged value below is the only identity candidate — the assertion
	// then discriminates this exact fix, not the helper's base header.
	forgedHeaders := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestHeaders{
		RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte("POST")},
				{Key: ":path", RawValue: []byte("/v1/chat/completions")},
				{Key: "authorization", RawValue: []byte("Bearer jwt-proc")},
				{Key: "x-user-email", RawValue: []byte("forged@victim.example")},
				{Key: "x-session-id", RawValue: []byte("forged-session")},
			}},
		},
	}}
	roundTrip(t, stream, forgedHeaders)
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	roundTrip(t, stream, responseHeadersMsg())
	roundTrip(t, stream, responseBodyMsg(`{"choices":[{"message":{"content":"hi"}}]}`, true))

	pdp.mu.Lock()
	hdrs := pdp.lastCheckOutputHdrs
	co := pdp.lastCheckOutput
	pdp.mu.Unlock()
	if got := hdrs.Get("X-User-Email"); got != "" {
		t.Fatalf("forged X-User-Email reached the engine: %q", got)
	}
	if got := hdrs.Get("X-Session-Id"); got != "" {
		t.Fatalf("forged X-Session-Id reached the engine: %q", got)
	}
	// The PDP-validated identity channel still flows.
	if co["user_token"] != "jwt-proc" {
		t.Fatalf("bearer user_token must still flow: %v", co["user_token"])
	}
}

func TestExtProcRequestPDPDownFailClosed(t *testing.T) {
	// Request-body plane, PDP unreachable, default FailModeClosed → the
	// request must be blocked with a 503, never forwarded (the ExtMcp and
	// ext_authz analogues are covered in their own tests; this pins the
	// ext_proc branch).
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	pdp.srv.Close() // engine dies before the body-phase decision
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("expected 503 fail-closed immediate response, got %+v", resp)
	}
	if im.GetDetails() != "pdp_unavailable" {
		t.Fatalf("expected pdp_unavailable details, got %q", im.GetDetails())
	}
	if !strings.Contains(string(im.GetBody()), "fail-closed") {
		t.Fatalf("deny body should state fail-closed: %s", im.GetBody())
	}
}

func TestExtProcRequestDeny(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("deny", "policy says no")
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 immediate response, got %+v", resp)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(im.GetBody(), &payload); err != nil {
		t.Fatalf("deny body not JSON: %v", err)
	}
	if payload["decision_id"] != "dec-deny" {
		t.Fatalf("decision_id missing: %v", payload)
	}
}

func TestExtProcRequestRedactionMutatesBody(t *testing.T) {
	pdp := newFakePDP(t)
	redacted := `{"model":"gpt-x","messages":[{"role":"user","content":"summarize account [REDACTED]"}]}`
	pdp.setDecideRedactionObligation(redacted)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	bm := resp.GetRequestBody().GetResponse().GetBodyMutation()
	if bm == nil || string(bm.GetBody()) != redacted {
		t.Fatalf("expected engine-redacted body mutation, got %+v", resp)
	}
	if resp.GetRequestBody().GetResponse().GetStatus() != extprocv3.CommonResponse_CONTINUE_AND_REPLACE {
		t.Fatalf("expected CONTINUE_AND_REPLACE, got %v", resp.GetRequestBody().GetResponse().GetStatus())
	}
	// Fulfillment ran on the FULL body.
	ci := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckInput })
	if ci["statement"] != openAIBody {
		t.Fatalf("check-input statement should be the full body, got %v", ci["statement"])
	}
}

func TestExtProcRequestUnforwardableRedactionFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("corrupted {{{")
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected fail-closed 403 on unparseable redaction, got %+v", resp)
	}
}

func TestExtProcResponseRedactionMutates(t *testing.T) {
	pdp := newFakePDP(t)
	redacted := `{"choices":[{"message":{"content":"[REDACTED-NIK]"}}]}`
	pdp.set(func(f *fakePDP) {
		f.checkOutputBody = map[string]interface{}{
			"allowed": true, "redacted_data": redacted,
			"redaction_evaluated": true, "decision_id": "dec-out",
		}
	})
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	roundTrip(t, stream, responseHeadersMsg())
	resp := roundTrip(t, stream, responseBodyMsg(`{"choices":[{"message":{"content":"3175064209870001"}}]}`, true))
	bm := resp.GetResponseBody().GetResponse().GetBodyMutation()
	if bm == nil || string(bm.GetBody()) != redacted {
		t.Fatalf("expected engine-redacted response mutation, got %+v", resp)
	}
}

func TestExtProcResponseBlocked(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) {
		f.checkOutputStatus = 403
		f.checkOutputBody = map[string]interface{}{
			"allowed": false, "block_reason": "critical PII", "decision_id": "dec-block",
		}
	})
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	roundTrip(t, stream, responseHeadersMsg())
	resp := roundTrip(t, stream, responseBodyMsg(`{"secret":"data"}`, true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 withhold, got %+v", resp)
	}
	if !strings.Contains(string(im.GetBody()), "dec-block") {
		t.Fatalf("decision_id missing from block body: %s", im.GetBody())
	}
}

func TestExtProcResponsePlaneAlwaysFailsClosed(t *testing.T) {
	// Even under request-plane fail-open, an unreachable engine on the
	// response plane withholds the response.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	pdp.srv.Close() // engine dies after the request-plane decision
	// Request plane fails open...
	resp := roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	if resp.GetRequestBody() == nil {
		t.Fatalf("expected fail-open continue on request plane, got %+v", resp)
	}
	roundTrip(t, stream, responseHeadersMsg())
	// ...but the response plane must not.
	respBody := roundTrip(t, stream, responseBodyMsg(`{"data":"x"}`, true))
	im := respBody.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("response plane must fail closed, got %+v", respBody)
	}
}

func TestExtProcStreamedBodyModeRejected(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	// protocol_config announcing full-duplex streaming arrives with the first
	// message — the adapter cannot govern partial bodies and must fail closed.
	first := requestHeadersMsg(false)
	first.ProtocolConfig = &extprocv3.ProtocolConfiguration{
		RequestBodyMode:  extprocfilterv3.ProcessingMode_FULL_DUPLEX_STREAMED,
		ResponseBodyMode: extprocfilterv3.ProcessingMode_FULL_DUPLEX_STREAMED,
	}
	resp := roundTrip(t, stream, first)
	im := resp.GetImmediateResponse()
	if im == nil || !strings.Contains(string(im.GetBody()), "buffered") {
		t.Fatalf("expected fail-closed config error pointing at buffered mode, got %+v", resp)
	}
}

func TestExtProcPartialBodyChunkRejected(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	resp := roundTrip(t, stream, requestBodyMsg("partial...", false))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("expected fail-closed on streamed chunk, got %+v", resp)
	}
}

func TestExtProcOversizedRequestBodyRejected(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.MaxBodyBytes = 16
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	resp := roundTrip(t, stream, requestBodyMsg(strings.Repeat("a", 64), true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_PayloadTooLarge {
		t.Fatalf("expected 413, got %+v", resp)
	}
}

func TestExtProcBodylessRequestDecidedAtHeaders(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	resp := roundTrip(t, stream, requestHeadersMsg(true))
	if resp.GetRequestHeaders() == nil {
		t.Fatalf("expected HeadersResponse continue, got %+v", resp)
	}
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["query"] != "POST /v1/chat/completions" {
		t.Fatalf("bodyless decide should gate the request line, got %v", decide["query"])
	}
}

func TestExtProcBodylessDenyImmediate(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("deny", "path forbidden")
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	resp := roundTrip(t, stream, requestHeadersMsg(true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403, got %+v", resp)
	}
}

func TestExtProcStageOverrideViaGatewayMetadataOnly(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	// A client-sent x-axonflow-stage header must be IGNORED (the governed
	// party cannot pick its policy layer)...
	hdrs := requestHeadersMsg(false,
		&corev3.HeaderValue{Key: "x-axonflow-stage", RawValue: []byte("agent")})
	// ...while the gateway-config metadataContext override is honored.
	hdrs.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		"axonflow": {Fields: map[string]*structpb.Value{
			"stage": structpb.NewStringValue("tool"),
		}},
	}}
	roundTrip(t, stream, hdrs)
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["stage"] != "tool" {
		t.Fatalf("gateway metadata stage override not honored (or client header trusted): %v", decide["stage"])
	}
}

func TestExtProcClientStageHeaderIgnored(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false,
		&corev3.HeaderValue{Key: "x-axonflow-stage", RawValue: []byte("agent")}))
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["stage"] != "llm" {
		t.Fatalf("client header must not select the stage; want default llm, got %v", decide["stage"])
	}
}

func TestExtProcInvalidGatewayStageRejected(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	hdrs := requestHeadersMsg(false)
	hdrs.MetadataContext = &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		"axonflow": {Fields: map[string]*structpb.Value{
			"stage": structpb.NewStringValue("bogus"),
		}},
	}}
	resp := roundTrip(t, stream, hdrs)
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
		t.Fatalf("expected 500 on invalid gateway-configured stage, got %+v", resp)
	}
}

// #2958: the BODYLESS ext_proc path is headers-only — the only content is
// :path/:method, which Envoy ext_proc cannot rewrite. It therefore declares
// headers-only, and the PDP owns what happens to a redaction it must suppress.
// These three tests replace TestExtProcBodylessRedactionObligationDenies, which
// pinned the old behavior: the adapter locally 403'd a PDP `allow`, the same
// defect this epic removes from ext_authz.

func TestExtProcBodylessAdvertisesHeadersOnly(t *testing.T) {
	// The load-bearing assertion. This path shares GateRequest with the
	// body-capable request-BODY path, so over-declaring here is a one-word
	// mistake that silently reinstates the allow→403.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(true))

	got := pdp.lastDecideCapabilities()
	for _, c := range got {
		if c == "request_body_redaction" {
			t.Fatalf("the bodyless path must NEVER advertise request_body_redaction — it cannot rewrite :path/:method, so the PDP would hand it a redaction it can only answer with a local 403: %v", got)
		}
	}
	if len(got) != 1 || got[0] != "request_header_mutation" {
		t.Fatalf("capabilities = %v, want exactly [request_header_mutation]", got)
	}
}

func TestExtProcBodylessRedactionSuppressedByPDPForwards(t *testing.T) {
	// A conforming PDP suppresses the request-line redaction and applies the org
	// posture. Under the default (log) that is an allow — so the request is
	// FORWARDED, not 403'd.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("GET /users/[REDACTED]")
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	resp := roundTrip(t, stream, requestHeadersMsg(true))
	if im := resp.GetImmediateResponse(); im != nil {
		t.Fatalf("a PDP-suppressed obligation must NOT become a local deny: %s", im.GetBody())
	}
	if resp.GetRequestHeaders() == nil {
		t.Fatalf("expected the allow to be forwarded, got %+v", resp)
	}
}

func TestExtProcBodylessStalePDPBackstopBlocks(t *testing.T) {
	// Version skew: a <=9.10.0 PDP ignores the advertisement and emits the
	// obligation anyway. We hold a request line a policy wanted masked and
	// cannot mask it, so we block — the one local block still allowed here.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("GET /users/[REDACTED]")
	pdp.set(func(f *fakePDP) { f.seamCapabilityAware = false })
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	resp := roundTrip(t, stream, requestHeadersMsg(true))
	im := resp.GetImmediateResponse()
	if im == nil || im.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("a stale PDP handing over an unfulfillable obligation must fail closed, got %+v", resp)
	}
	if !strings.Contains(string(im.GetBody()), "version mismatch") {
		t.Fatalf("deny body should name the version mismatch so it is diagnosable: %s", im.GetBody())
	}
}

func TestExtProcEmptyResponseBodyPasses(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))
	roundTrip(t, stream, responseHeadersMsg())
	resp := roundTrip(t, stream, responseBodyMsg("", true))
	if resp.GetResponseBody() == nil {
		t.Fatalf("empty response body should continue, got %+v", resp)
	}
}

// TestServerHealthAndExtMcpOverWire exercises the full Server wiring: gRPC
// health plus the vendored ExtMcp service over a real (bufconn) connection.
func TestServerHealthAndExtMcpOverWire(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)

	hres, err := healthv1.NewHealthClient(conn).Check(context.Background(), &healthv1.HealthCheckRequest{})
	if err != nil || hres.GetStatus() != healthv1.HealthCheckResponse_SERVING {
		t.Fatalf("health: %v %v", hres, err)
	}

	res, err := agwapi.NewExtMcpClient(conn).CheckRequest(context.Background(), toolsCallRequest("jwt-wire"))
	if err != nil {
		t.Fatalf("ExtMcp over wire: %v", err)
	}
	if res.GetPass() == nil {
		t.Fatalf("expected Pass over the wire, got %+v", res)
	}
}

func TestExtProcRequestBodyAdvertisesBodyCapability(t *testing.T) {
	// The symmetric guard to TestExtProcBodylessAdvertisesHeadersOnly. This path
	// CAN rewrite the body, so it must say so — UNDER-declaring here would make
	// the PDP withhold a redaction this seam can actually perform, silently
	// degrading a governed LLM leg to the org's fallback posture (detect-and-log)
	// while everything still looks green.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	conn := startServer(t, cfg)
	stream := openExtProcStream(t, conn)

	roundTrip(t, stream, requestHeadersMsg(false))
	roundTrip(t, stream, requestBodyMsg(openAIBody, true))

	got := pdp.lastDecideCapabilities()
	if len(got) != 1 || got[0] != "request_body_redaction" {
		t.Fatalf("capabilities = %v, want exactly [request_body_redaction] — the request-BODY path can mask, so it must declare it", got)
	}
}
