// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
	"axonflow/platform/shared/pep"
)

func toolsCallRequest(bearer string) *agwapi.McpRequest {
	headers := []*agwapi.McpHeader{
		{Key: "x-user-email", Value: []byte("dev@example.com")},
		{Key: "traceparent", Value: []byte("00-abc-def-01")},
	}
	if bearer != "" {
		headers = append(headers, &agwapi.McpHeader{Key: "authorization", Value: []byte("Bearer " + bearer)})
	}
	return &agwapi.McpRequest{
		ServiceNames: []string{"payments"},
		Method:       "tools/call",
		McpRequest:   []byte(`{"name":"refund","arguments":{"account":"12345","note":"NIK 3175064209870001"}}`),
		Headers:      headers,
	}
}

func TestExtMcpCheckRequestAllow(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, err := s.CheckRequest(context.Background(), toolsCallRequest("jwt-1"))
	if err != nil {
		t.Fatalf("CheckRequest: %v", err)
	}
	if res.GetPass() == nil {
		t.Fatalf("expected Pass, got %+v", res)
	}
	// Decision identifiers must ride the upstream headers + CEL metadata.
	hm := res.GetHeaderMutation()
	if hm == nil || len(hm.GetSet()) != 2 || hm.GetSet()[0].GetKey() != "x-axonflow-decision-id" {
		t.Fatalf("decision header mutation missing: %+v", hm)
	}
	if res.GetMetadata().GetFields()["axonflow_decision_id"].GetStringValue() != "dec-allow" {
		t.Fatalf("decision metadata missing: %+v", res.GetMetadata())
	}

	// The decide call must carry the tool target, the arguments as query, the
	// gateway identity, and the end-user token.
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["stage"] != "tool" {
		t.Fatalf("stage = %v, want tool", decide["stage"])
	}
	target := decide["target"].(map[string]interface{})
	if target["tool"] != "refund" {
		t.Fatalf("target.tool = %v, want refund", target["tool"])
	}
	// #3717: the TYPE and the SERVER, on the wire, from the producer's side.
	//
	// This block asserted only target.tool for three releases, which is exactly
	// why the seam could send Type "mcp_tool" against a platform gate reading
	// "tool" with both packages' suites green. The check is on the marshalled
	// body rather than on the Go value on purpose: the defect was a STRING
	// crossing a process boundary, and a claim about a Go constant is not a
	// claim about the wire.
	if target["type"] != pep.TargetTypeTool {
		t.Fatalf("target.type = %v, want %q — a type the platform's tool-attribution gate does not "+
			"recognise empties tool_server/tool_name on every audit row this seam produces, with "+
			"nothing failing (#3717)", target["type"], pep.TargetTypeTool)
	}
	if target["server"] != "payments" {
		t.Fatalf("target.server = %v, want payments (the single service_names entry for this "+
			"single-target method)", target["server"])
	}
	if !strings.Contains(decide["query"].(string), "12345") {
		t.Fatalf("query should be the tool arguments, got %v", decide["query"])
	}
	if decide["user_token"] != "jwt-1" {
		t.Fatalf("user_token not propagated from Authorization bearer: %v", decide["user_token"])
	}
	caller := decide["caller_identity"].(map[string]interface{})
	if caller["gateway_id"] != "agw-test" {
		t.Fatalf("gateway_id not stamped: %v", caller)
	}
	ctxMap := decide["context"].(map[string]interface{})
	if ctxMap["mcp_method"] != "tools/call" {
		t.Fatalf("mcp_method context missing: %v", ctxMap)
	}
}

func TestExtMcpCheckRequestDeny(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("deny", "SQL injection pattern")
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, err := s.CheckRequest(context.Background(), toolsCallRequest(""))
	if err != nil {
		t.Fatalf("CheckRequest: %v", err)
	}
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("expected PERMISSION_DENIED error, got %+v", res)
	}
	if !strings.Contains(e.GetReason(), "SQL injection") {
		t.Fatalf("reason lost: %q", e.GetReason())
	}
	var data map[string]interface{}
	if err := json.Unmarshal(e.GetMcpError(), &data); err != nil {
		t.Fatalf("mcp_error not JSON: %v", err)
	}
	if data["decision_id"] != "dec-deny" || data["verdict"] != "deny" {
		t.Fatalf("decision context missing from mcp_error: %v", data)
	}
}

func TestExtMcpCheckRequestNeedsApprovalBlocks(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("needs_approval")
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("needs_approval must block synchronously, got %+v", res)
	}
}

func TestExtMcpCheckRequestRedactionMutates(t *testing.T) {
	pdp := newFakePDP(t)
	redacted := `{"name":"refund","arguments":{"account":"12345","note":"NIK [REDACTED-NIK]"}}`
	pdp.setDecideRedactionObligation(redacted)
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	req := toolsCallRequest("jwt-1")
	res, err := s.CheckRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("CheckRequest: %v", err)
	}
	if string(res.GetMutated()) != redacted {
		t.Fatalf("Mutated must carry the ENGINE-redacted params verbatim, got %s", res.GetMutated())
	}
	// Fulfillment must have run against the FULL params payload, not just the
	// extracted arguments — PII in sibling fields must reach the engine.
	ci := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckInput })
	if ci["statement"] != string(req.GetMcpRequest()) {
		t.Fatalf("check-input statement = %v, want full params", ci["statement"])
	}
}

func TestExtMcpCheckRequestUnforwardableRedactionFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation(`not-json {{{`)
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	e := res.GetError()
	if e == nil || !strings.Contains(e.GetReason(), "not forwardable JSON") {
		t.Fatalf("expected fail-closed on unparseable engine redaction, got %+v", res)
	}
}

func TestExtMcpCheckRequestRedactorNotRunFailsClosed(t *testing.T) {
	// Obligation present but check-input reports redaction_evaluated=false —
	// the pep client refuses and the adapter must block.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	pdp.set(func(f *fakePDP) {
		f.checkInputBody = map[string]interface{}{"allowed": true, "redaction_evaluated": false}
	})
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	e := res.GetError()
	if e == nil || !strings.Contains(e.GetReason(), "policy decision unavailable") {
		t.Fatalf("expected fail-closed when the redactor did not run, got %+v", res)
	}
}

func TestExtMcpCheckRequestPDPDownFailClosed(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	pdp.srv.Close() // engine unreachable
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_UNKNOWN {
		t.Fatalf("expected UNKNOWN fail-closed error, got %+v", res)
	}
	if !strings.Contains(e.GetReason(), "fail-closed") {
		t.Fatalf("reason should state fail-closed: %q", e.GetReason())
	}
}

func TestExtMcpCheckRequestPDPDownFailOpen(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	pdp.srv.Close()
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	if res.GetPass() == nil {
		t.Fatalf("expected fail-open Pass, got %+v", res)
	}
}

func TestExtMcpCheckRequestAuthRejectionBlocksEvenFailOpen(t *testing.T) {
	// A PDP 4xx is NOT transient — fail-open must not apply.
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) { f.decideStatus = http.StatusUnauthorized })
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	if res.GetError() == nil {
		t.Fatalf("a rejected decide call must block even under fail-open, got %+v", res)
	}
}

func TestExtMcpCheckRequestOversizedParamsFailClosed(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.MaxBodyBytes = 16
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckRequest(context.Background(), toolsCallRequest(""))
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_RESOURCE_EXHAUSTED {
		t.Fatalf("expected RESOURCE_EXHAUSTED, got %+v", res)
	}
}

func TestExtMcpCheckRequestGenericMethod(t *testing.T) {
	// Non-tools/call methods are gated generically on their params.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, err := s.CheckRequest(context.Background(), &agwapi.McpRequest{
		ServiceNames: []string{"docs"},
		Method:       "resources/read",
		McpRequest:   []byte(`{"uri":"file:///etc/passwd"}`),
	})
	if err != nil || res.GetPass() == nil {
		t.Fatalf("expected Pass, got %+v err=%v", res, err)
	}
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	target := decide["target"].(map[string]interface{})
	if target["tool"] != "resources/read" {
		t.Fatalf("generic method should gate on the method name, got %v", target)
	}
}

func TestExtMcpCheckResponseCleanPass(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, err := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		ServiceNames: []string{"payments"},
		Method:       "tools/call",
		McpResponse:  []byte(`{"content":[{"type":"text","text":"ok"}]}`),
	})
	if err != nil || res.GetPass() == nil {
		t.Fatalf("expected Pass, got %+v err=%v", res, err)
	}
	co := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastCheckOutput })
	if !strings.Contains(co["message"].(string), "ok") {
		t.Fatalf("check-output must receive the serialized result: %v", co)
	}
}

func TestExtMcpCheckResponseRedactedMutates(t *testing.T) {
	pdp := newFakePDP(t)
	redacted := `{"content":[{"type":"text","text":"[REDACTED-NIK]"}]}`
	pdp.set(func(f *fakePDP) {
		f.checkOutputBody = map[string]interface{}{
			"allowed": true, "redacted_data": redacted,
			"redaction_evaluated": true, "decision_id": "dec-out",
		}
	})
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":[{"type":"text","text":"3175064209870001"}]}`),
	})
	if string(res.GetMutated()) != redacted {
		t.Fatalf("Mutated must carry engine-redacted result, got %s", res.GetMutated())
	}
}

func TestExtMcpCheckResponseBlocked(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) {
		f.checkOutputStatus = http.StatusForbidden
		f.checkOutputBody = map[string]interface{}{
			"allowed": false, "block_reason": "exfiltration detected", "decision_id": "dec-block",
		}
	})
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":[]}`),
	})
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_PERMISSION_DENIED {
		t.Fatalf("expected PERMISSION_DENIED, got %+v", res)
	}
	var data map[string]interface{}
	_ = json.Unmarshal(e.GetMcpError(), &data)
	if data["decision_id"] != "dec-block" {
		t.Fatalf("decision_id missing from block data: %v", data)
	}
}

func TestExtMcpCheckResponseEngineDownAlwaysFailsClosed(t *testing.T) {
	// The response plane ignores the fail-open posture entirely.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	pdp.srv.Close()
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":[]}`),
	})
	e := res.GetError()
	if e == nil || !strings.Contains(e.GetReason(), "fail-closed") {
		t.Fatalf("response plane must fail closed even under fail-open, got %+v", res)
	}
}

func TestExtMcpCheckResponseRedactorNotRunFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) {
		f.checkOutputBody = map[string]interface{}{"allowed": true, "policies_evaluated": 0}
	})
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":[]}`),
	})
	if res.GetError() == nil {
		t.Fatalf("expected fail-closed when response redactor did not run, got %+v", res)
	}
}

func TestExtMcpCheckResponseUnforwardableRedactionFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) {
		f.checkOutputBody = map[string]interface{}{
			"allowed": true, "redacted_data": "corrupted {{{",
			"redaction_evaluated": true,
		}
	})
	cfg := testConfig(pdp)
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":[]}`),
	})
	e := res.GetError()
	if e == nil || !strings.Contains(e.GetReason(), "not forwardable JSON") {
		t.Fatalf("expected fail-closed on unparseable engine redaction, got %+v", res)
	}
}

func TestExtMcpCheckResponseOversizedFailsClosed(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.MaxBodyBytes = 8
	s := NewExtMcpServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.CheckResponse(context.Background(), &agwapi.McpResponse{
		Method: "tools/call", McpResponse: []byte(`{"content":"large payload"}`),
	})
	e := res.GetError()
	if e == nil || e.GetCode() != agwapi.AuthorizationError_RESOURCE_EXHAUSTED {
		t.Fatalf("expected RESOURCE_EXHAUSTED, got %+v", res)
	}
}
