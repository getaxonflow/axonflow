// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pep

import (
	"encoding/json"
	"testing"
)

// platformCheckOutputResponseSample is a byte-for-byte sample of what
// platform/agent/mcp_handler.go emits from mcpCheckOutputHandler on the
// message-path allow branch (json.NewEncoder(w).Encode(MCPCheckOutputResponse{...})
// with redacted_data carrying the redacted message string and
// redaction_evaluated from the #2865/#2866 response-plane mirror). This pins
// the wire contract so checkOutputWireResponse cannot silently drift from the
// platform handler.
const platformCheckOutputResponseSample = `{
  "allowed": true,
  "redacted_data": "order for [REDACTED-NIK] confirmed",
  "policies_evaluated": 3,
  "decision_id": "66666666-7777-8888-9999-000000000000",
  "redaction_evaluated": true
}`

// platformCheckOutputBlockSample mirrors the 403 block branch
// (sendMCPBlockedResponse-style body: allowed:false + block_reason +
// decision_id; policies_evaluated is 0 on block paths).
const platformCheckOutputBlockSample = `{
  "allowed": false,
  "block_reason": "Response blocked: critical PII (NIK) cannot be redacted",
  "policies_evaluated": 0,
  "decision_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}`

func TestCheckOutputWireContractAllow(t *testing.T) {
	var parsed checkOutputWireResponse
	if err := json.Unmarshal([]byte(platformCheckOutputResponseSample), &parsed); err != nil {
		t.Fatalf("decode platform sample: %v", err)
	}
	if !parsed.Allowed {
		t.Fatal("allowed lost in decode")
	}
	if !parsed.RedactionEvaluated {
		t.Fatal("redaction_evaluated lost in decode — the fail-closed gate would misfire")
	}
	if parsed.PoliciesEvaluated != 3 {
		t.Fatalf("policies_evaluated lost: %d", parsed.PoliciesEvaluated)
	}
	if parsed.DecisionID != "66666666-7777-8888-9999-000000000000" {
		t.Fatalf("decision_id lost: %q", parsed.DecisionID)
	}
	res, err := buildCheckOutputResult(parsed)
	if err != nil {
		t.Fatalf("buildCheckOutputResult: %v", err)
	}
	if !res.Redacted || res.RedactedMessage != "order for [REDACTED-NIK] confirmed" {
		t.Fatalf("redacted message lost: %+v", res)
	}
}

func TestCheckOutputWireContractBlock(t *testing.T) {
	var parsed checkOutputWireResponse
	if err := json.Unmarshal([]byte(platformCheckOutputBlockSample), &parsed); err != nil {
		t.Fatalf("decode platform block sample: %v", err)
	}
	if parsed.Allowed {
		t.Fatal("allowed:false lost in decode")
	}
	if parsed.BlockReason == "" || parsed.DecisionID == "" {
		t.Fatalf("block context lost: %+v", parsed)
	}
}

// TestCheckOutputWireRequestShape pins the request bytes this client sends —
// the platform's MCPCheckOutputRequest decoder reads exactly these keys
// (client_id, user_token, tenant_id, connector_type, message).
func TestCheckOutputWireRequestShape(t *testing.T) {
	b, err := json.Marshal(checkOutputWireRequest{
		ClientID:      "org-1",
		UserToken:     "jwt",
		TenantID:      "tenant-1",
		ConnectorType: "agentgateway",
		Message:       "hello",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	for _, key := range []string{"client_id", "user_token", "tenant_id", "connector_type", "message"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("wire request missing %q: %s", key, b)
		}
	}
	if len(m) != 5 {
		t.Fatalf("unexpected extra wire keys (contract drift?): %s", b)
	}
}
