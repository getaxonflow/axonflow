// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

func TestDecideEvaluatesTypedRefundAmountThroughTheRealHandler(t *testing.T) {
	enfSetup(t)
	content, err := os.ReadFile(filepath.Join("..", "..", "ee", "examples", "payment-exception-shadow", "fixtures", "refund-policy-example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc pdp.Document
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	fixture := authoring.Fixture{
		Name: "USD refund of 949 dollars",
		Attributes: contract.AttributeSet{
			pdp.ActionIDPath:           contract.Known("Action::"+authoringcatalog.ActionToolCall, contract.ProvPlatform, 1, now),
			pdp.ActionTagsPath:         contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, now),
			"args.refund.operation":    contract.Known("issue_refund", contract.ProvCaller, 1, now),
			"args.refund.currency":     contract.Known("USD", contract.ProvCaller, 1, now),
			"args.refund.amount_minor": contract.Known(float64(94900), contract.ProvCaller, 1, now),
		},
		Expect: map[string]pdp.Verdict{"support.refund.usd.review": pdp.VerdictMatch},
	}
	docs := enfPublishPolicyDocumentAs(t, authoring.EditionEnterprise, enfSnapshot(t), doc, []authoring.Fixture{fixture})
	enfInstallSeam(t, docs)
	probe := func(amount any) enfResponse {
		request := DecideRequest{
			Stage:  DecisionStageTool,
			Target: DecisionTarget{Type: "tool", Server: "support-ops", Tool: "support-ops.issue_refund"},
			Query:  "Review support refund", UserToken: enfMintUserToken(t, enfOrgPublished, enfUser),
			Context: map[string]interface{}{"refund_action": map[string]interface{}{"amount_minor": amount, "currency": "USD"}},
		}
		req := decideEnterpriseReq(t, request, enfOrgPublished, enfOrgPublished)
		rr := httptest.NewRecorder()
		handleDecide(rr, req)
		out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
		if err := json.Unmarshal(out.raw, &out.body); err != nil {
			t.Fatal(err)
		}
		return out
	}
	below := probe(float64(49900))
	if below.str(t, "verdict") != VerdictAllow {
		t.Fatalf("below threshold: %s", below.raw)
	}
	above := probe(float64(94900))
	if above.str(t, "verdict") == VerdictAllow {
		t.Fatalf("above threshold escaped approval: %s", above.raw)
	}
	if !slices.Contains(above.strings(t, "evaluated_policies"), "support.refund.usd.review") {
		t.Fatalf("above threshold did not name the typed refund requirement: %s", above.raw)
	}
	malformed := probe("94900")
	if malformed.str(t, "verdict") == VerdictAllow {
		t.Fatalf("string amount escaped typed policy: %s", malformed.raw)
	}
}
