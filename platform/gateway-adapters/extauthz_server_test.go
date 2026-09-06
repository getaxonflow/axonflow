// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
)

func authzCheckRequest(body string, ctxExt map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "POST",
					Path:   "/v1/chat/completions",
					Host:   "llm.internal",
					Headers: map[string]string{
						"authorization": "Bearer jwt-authz",
						"traceparent":   "00-abc-def-01",
					},
					Body: body,
				},
			},
			ContextExtensions: ctxExt,
		},
	}
}

const openAIBody = `{"model":"gpt-x","messages":[{"role":"system","content":"be nice"},{"role":"user","content":"summarize account 12345"}]}`

func TestExtAuthzAllow(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if res.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected OK, got %+v", res)
	}
	ok := res.GetOkResponse()
	if ok == nil {
		t.Fatalf("expected OkHttpResponse, got %+v", res)
	}
	found := false
	for _, h := range ok.GetHeaders() {
		if h.GetHeader().GetKey() == "x-axonflow-decision-id" && h.GetHeader().GetValue() == "dec-allow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("decision id header not stamped upstream: %+v", ok.GetHeaders())
	}
	if res.GetDynamicMetadata().GetFields()["axonflow_verdict"].GetStringValue() != "allow" {
		t.Fatalf("dynamic metadata missing: %+v", res.GetDynamicMetadata())
	}

	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["stage"] != "llm" {
		t.Fatalf("default stage should be llm, got %v", decide["stage"])
	}
	if decide["query"] != "summarize account 12345" {
		t.Fatalf("query should be the last user message, got %v", decide["query"])
	}
	if decide["target"].(map[string]interface{})["model"] != "gpt-x" {
		t.Fatalf("model not extracted: %v", decide["target"])
	}
	if decide["user_token"] != "jwt-authz" {
		t.Fatalf("bearer not propagated: %v", decide["user_token"])
	}
}

func TestExtAuthzDeny(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("deny", "prompt injection")
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if res.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("expected PermissionDenied, got %+v", res.GetStatus())
	}
	denied := res.GetDeniedResponse()
	if denied == nil || denied.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403 direct response, got %+v", denied)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(denied.GetBody()), &payload); err != nil {
		t.Fatalf("deny body not JSON: %v", err)
	}
	if payload["decision_id"] != "dec-deny" || payload["verdict"] != "deny" {
		t.Fatalf("decision context missing from deny body: %v", payload)
	}
}

func TestExtAuthzNeedsApprovalDenies(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.setDecideVerdict("needs_approval")
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if res.GetDeniedResponse() == nil {
		t.Fatalf("needs_approval must deny synchronously, got %+v", res)
	}
}

// #2958: ext_authz declares what it can do, so the PDP owns what happens to
// content it cannot redact. These four tests replace TestExtAuthzRedactionObligationDenies,
// which pinned the old behavior: the adapter converted the PDP's allow into a
// local 403 on every PII-bearing request, which is the outage this fixed.

func TestExtAuthzAdvertisesHeadersOnlyCapabilities(t *testing.T) {
	// The declaration is the whole mechanism: if ext_authz ever advertised
	// request_body_redaction, the PDP would hand it an obligation it cannot
	// discharge and the backstop would 403 every PII request again.
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	if _, err := s.Check(context.Background(), authzCheckRequest(openAIBody, nil)); err != nil {
		t.Fatalf("Check: %v", err)
	}
	got := pdp.lastDecideCapabilities()
	if len(got) == 0 {
		t.Fatal("ext_authz advertised NO capabilities — an empty set is indistinguishable from a legacy caller on the wire, so the PDP would emit the obligation and the seam would 403")
	}
	for _, c := range got {
		if c == "request_body_redaction" {
			t.Fatalf("ext_authz must NEVER advertise request_body_redaction (it cannot rewrite bodies): %v", got)
		}
	}
	if got[0] != "request_header_mutation" || len(got) != 1 {
		t.Fatalf("capabilities = %v, want exactly [request_header_mutation]", got)
	}
}

func TestExtAuthzRedactionSuppressedByPDPAllows(t *testing.T) {
	// The reported outage: a PII prompt on a headers-only LLM leg. A conforming
	// PDP suppresses the obligation and applies the log posture, so the request
	// is FORWARDED — chat keeps working — with the audit trail on the PDP side.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if res.GetDeniedResponse() != nil {
		t.Fatalf("a PDP-suppressed obligation must NOT be turned into a local deny: %+v", res.GetDeniedResponse())
	}
	if res.GetOkResponse() == nil {
		t.Fatalf("expected the allow to be forwarded, got %+v", res)
	}
}

func TestExtAuthzRedactionFallbackBlockDenies(t *testing.T) {
	// Same request, org posture = block: the PDP returns deny and the adapter
	// enforces it. The deny is the PDP's decision, not the adapter's.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	pdp.set(func(f *fakePDP) { f.fallbackVerdict = "deny" })
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	denied := res.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("expected the PDP's fallback deny to be enforced, got %+v", res)
	}
	if !strings.Contains(denied.GetBody(), "obligation-fallback") {
		t.Fatalf("deny body should carry the PDP's fallback reason: %s", denied.GetBody())
	}
}

func TestExtAuthzStalePDPObligationBackstopBlocks(t *testing.T) {
	// Version skew: a >=9.11.0 adapter against a <=9.10.0 PDP, which ignores
	// fulfillment_capabilities and emits the obligation regardless. The adapter
	// holds content a policy wanted masked and cannot mask it, so it blocks —
	// this is the ONE local block the seam is still allowed to make.
	pdp := newFakePDP(t)
	pdp.setDecideRedactionObligation("ignored")
	pdp.set(func(f *fakePDP) { f.seamCapabilityAware = false })
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	denied := res.GetDeniedResponse()
	if denied == nil {
		t.Fatalf("stale PDP handing over an unfulfillable obligation must fail closed, got %+v", res)
	}
	if denied.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403, got %+v", denied.GetStatus())
	}
	if !strings.Contains(denied.GetBody(), "version mismatch") {
		t.Fatalf("deny body should name the version mismatch so it is diagnosable: %s", denied.GetBody())
	}
}

func TestExtAuthzPDPDownFailClosed(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	pdp.srv.Close()
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	denied := res.GetDeniedResponse()
	if denied == nil || denied.GetStatus().GetCode() != typev3.StatusCode_ServiceUnavailable {
		t.Fatalf("expected 503 fail-closed deny, got %+v", res)
	}
}

func TestExtAuthzPDPDownFailOpen(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	pdp.srv.Close()
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if res.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("expected fail-open allow, got %+v", res)
	}
}

func TestExtAuthzAuthRejectionDeniesEvenFailOpen(t *testing.T) {
	pdp := newFakePDP(t)
	pdp.set(func(f *fakePDP) { f.decideStatus = http.StatusUnauthorized })
	cfg := testConfig(pdp)
	cfg.FailMode = FailModeOpen
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	if res.GetDeniedResponse() == nil {
		t.Fatalf("a rejected decide call must deny even under fail-open, got %+v", res)
	}
}

func TestExtAuthzStageOverrideViaContextExtension(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	_, _ = s.Check(context.Background(), authzCheckRequest(openAIBody,
		map[string]string{stageContextExtension: "agent"}))
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["stage"] != "agent" {
		t.Fatalf("stage override not honored: %v", decide["stage"])
	}
}

func TestExtAuthzInvalidStageDenies(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody,
		map[string]string{stageContextExtension: "bogus"}))
	denied := res.GetDeniedResponse()
	if denied == nil || denied.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
		t.Fatalf("expected 500 deny on invalid stage, got %+v", res)
	}
}

func TestExtAuthzOversizedBodyDenies(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	cfg.MaxBodyBytes = 8
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	res, _ := s.Check(context.Background(), authzCheckRequest(openAIBody, nil))
	denied := res.GetDeniedResponse()
	if denied == nil || denied.GetStatus().GetCode() != typev3.StatusCode_PayloadTooLarge {
		t.Fatalf("expected 413 deny, got %+v", res)
	}
}

func TestExtAuthzBodylessGatesOnRequestLine(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	_, _ = s.Check(context.Background(), authzCheckRequest("", nil))
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["query"] != "POST /v1/chat/completions" {
		t.Fatalf("bodyless query should be the request line, got %v", decide["query"])
	}
}

func TestExtAuthzNonOpenAIBodyGatesWholeBody(t *testing.T) {
	pdp := newFakePDP(t)
	cfg := testConfig(pdp)
	s := NewExtAuthzServer(newTestPDPFacade(t, cfg), cfg)

	_, _ = s.Check(context.Background(), authzCheckRequest(`{"prompt":"hello"}`, nil))
	decide := pdp.last(func(f *fakePDP) map[string]interface{} { return f.lastDecide })
	if decide["query"] != `{"prompt":"hello"}` {
		t.Fatalf("non-OpenAI body should gate whole body, got %v", decide["query"])
	}
}
