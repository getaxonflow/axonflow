// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pep

import (
	"encoding/json"
	"testing"
)

// platformDecideResponseSample is a byte-for-byte sample of what
// platform/agent/decision_handler.go emits for an allow verdict carrying a
// self-describing redact_pii obligation (writeDecideResponse +
// newRedactPIIObligation). This pins the wire contract so the DTOs re-declared
// in pep.go cannot silently drift from the platform handler: if the platform
// renames a field or drops the fulfillment block, this decode loses data and
// the assertions below fail.
const platformDecideResponseSample = `{
  "verdict": "allow",
  "decision_id": "11111111-2222-3333-4444-555555555555",
  "trace_id": "0af7651916cd43dd8448eb211c80319c",
  "obligations": [
    {
      "type": "redact_pii",
      "detail": "RBI India PII detected: Aadhaar",
      "fulfillment": {
        "endpoint": "/api/v1/mcp/check-input",
        "method": "POST",
        "phase": "request",
        "content_types": ["text/plain"]
      }
    }
  ],
  "evaluated_policies": ["pii-india"],
  "stage": "llm",
  "expires_at": "2026-06-09T00:00:00Z"
}`

func TestContract_DecodePlatformDecideResponse(t *testing.T) {
	var dr DecideResponse
	if err := json.Unmarshal([]byte(platformDecideResponseSample), &dr); err != nil {
		t.Fatalf("decode platform sample: %v", err)
	}
	if dr.Verdict != VerdictAllow {
		t.Fatalf("verdict=%q", dr.Verdict)
	}
	if len(dr.Obligations) != 1 {
		t.Fatalf("obligations=%d want 1", len(dr.Obligations))
	}
	ob := dr.Obligations[0]
	if ob.Type != ObligationRedactPII {
		t.Fatalf("obligation type=%q", ob.Type)
	}
	if ob.Fulfillment == nil {
		t.Fatal("fulfillment block lost on decode — DTO drift")
	}
	if ob.Fulfillment.Endpoint != requestRedactionPath {
		t.Fatalf("fulfillment endpoint=%q want %q", ob.Fulfillment.Endpoint, requestRedactionPath)
	}
	if ob.Fulfillment.Phase != PhaseRequest {
		t.Fatalf("fulfillment phase=%q want request", ob.Fulfillment.Phase)
	}
	// content_types is always emitted by the platform (newRedactPIIObligation);
	// pin it so the PEP's content-type fail-closed logic can't drift.
	if len(ob.Fulfillment.ContentTypes) != 1 || ob.Fulfillment.ContentTypes[0] != ContentTypeText {
		t.Fatalf("fulfillment content_types=%v want [%s]", ob.Fulfillment.ContentTypes, ContentTypeText)
	}
	// And the helper must accept this exact endpoint for fulfillment.
	if !isAllowedFulfillmentEndpoint(ob.Fulfillment.Endpoint, requestRedactionPath) {
		t.Fatal("helper rejects the endpoint the platform actually emits")
	}
}

// platformCheckInputRedactedSample mirrors what mcpCheckInputHandler returns on
// the allow-with-redaction path (Redacted + RedactedStatement). Pins that the
// client reads back the field names the platform writes.
const platformCheckInputRedactedSample = `{
  "allowed": true,
  "policies_evaluated": 3,
  "decision_id": "abc",
  "redacted": true,
  "redacted_statement": "my id is [REDACTED]",
  "redaction_evaluated": true
}`

func TestContract_DecodeCheckInputRedaction(t *testing.T) {
	var cir checkInputResponse
	if err := json.Unmarshal([]byte(platformCheckInputRedactedSample), &cir); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !cir.Allowed || !cir.Redacted || cir.RedactedStatement != "my id is [REDACTED]" {
		t.Fatalf("check-input redaction fields not read: %+v", cir)
	}
	if !cir.RedactionEvaluated {
		t.Fatalf("redaction_evaluated must decode true (drives PEP fail-closed): %+v", cir)
	}
}
