// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Cross-package wire-contract test (#2563 M2): marshal the REAL platform
// Decision-Mode obligation type and decode it into the pep client's DTO. Unlike
// a hand-written JSON literal, this fails the moment the platform reshapes the
// obligation (renamed field, dropped fulfillment block, changed json tag) — the
// decoded pep value would lose data and the assertions below would catch it. It
// is the authoritative pin for the obligation contract the PEP client depends
// on.

import (
	"encoding/json"
	"testing"
	"time"

	"axonflow/platform/shared/pep"
)

func TestWireContract_PlatformObligationDecodesIntoPEPClient(t *testing.T) {
	// Build the obligation exactly as /decide emits it.
	platformResp := DecideResponse{
		Verdict:           VerdictAllow,
		DecisionID:        "11111111-2222-3333-4444-555555555555",
		TraceID:           "0af7651916cd43dd8448eb211c80319c",
		Stage:             DecisionStageLLM,
		Obligations:       []DecisionObligation{newRedactPIIObligation("RBI India PII detected: Aadhaar")},
		EvaluatedPolicies: []string{"pii-india"},
		ExpiresAt:         time.Unix(0, 0).UTC(),
	}

	wire, err := json.Marshal(platformResp)
	if err != nil {
		t.Fatalf("marshal platform response: %v", err)
	}

	// Decode into the PEP client's independently-declared DTO.
	var clientResp pep.DecideResponse
	if err := json.Unmarshal(wire, &clientResp); err != nil {
		t.Fatalf("PEP client cannot decode platform response: %v", err)
	}

	if clientResp.Verdict != pep.VerdictAllow {
		t.Fatalf("verdict drift: %q", clientResp.Verdict)
	}
	if len(clientResp.Obligations) != 1 {
		t.Fatalf("obligations lost in transit: %d", len(clientResp.Obligations))
	}
	ob := clientResp.Obligations[0]
	if ob.Type != pep.ObligationRedactPII {
		t.Fatalf("obligation type drift: %q", ob.Type)
	}
	if ob.Fulfillment == nil {
		t.Fatal("fulfillment block lost — platform/client DTO drift")
	}
	if ob.Fulfillment.Phase != pep.PhaseRequest {
		t.Fatalf("phase drift: %q", ob.Fulfillment.Phase)
	}
	// The endpoint the platform emits must be the one the client will call.
	if ob.Fulfillment.Endpoint != requestRedactionEndpoint {
		t.Fatalf("endpoint drift: platform=%q", ob.Fulfillment.Endpoint)
	}
	// content_types must round-trip so the client's content-type fail-closed
	// logic sees the same modalities the platform advertises.
	if len(ob.Fulfillment.ContentTypes) != 1 || ob.Fulfillment.ContentTypes[0] != pep.ContentTypeText {
		t.Fatalf("content_types drift: %v", ob.Fulfillment.ContentTypes)
	}
}
