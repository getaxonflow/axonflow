// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

func TestDecideRefundMoneyFactsAreTypedAndActionScoped(t *testing.T) {
	target := DecisionTarget{Type: "tool", Server: "support-ops", Tool: "support-ops.issue_refund"}
	facts := refundMoneyFacts(DecisionStageTool, target, map[string]interface{}{
		"refund_action": map[string]interface{}{"amount_minor": float64(94900), "currency": "USD"},
	})
	for path, want := range map[string]any{"args.refund.amount_minor": float64(94900), "args.refund.currency": "USD", "args.refund.operation": "issue_refund"} {
		got := facts[path]
		if got.State != contract.StateKnown || got.Value != want || got.Source != contract.ProvCaller {
			t.Errorf("%s = %+v, want known caller value %v", path, got, want)
		}
	}
	if got := refundMoneyFacts(DecisionStageTool, DecisionTarget{Type: "tool", Server: "support-ops", Tool: "support-ops.lookup"},
		map[string]interface{}{"refund_action": map[string]interface{}{"amount_minor": 94900}}); got != nil {
		t.Fatalf("read-only support tool stated refund money facts: %+v", got)
	}
	for _, bad := range []any{"94900", float64(94900.5), float64(9007199254740992)} {
		got := refundMoneyFacts(DecisionStageTool, target, map[string]interface{}{
			"refund_action": map[string]interface{}{"amount_minor": bad, "currency": "USD"},
		})
		if got["args.refund.amount_minor"].State != contract.StateUnknown {
			t.Errorf("malformed amount %v was not unknown: %+v", bad, got)
		}
	}
}
