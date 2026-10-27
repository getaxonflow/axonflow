// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/moneyfacts"
)

// refundMoneyFacts reads only the typed refund money fields asserted by the
// authenticated enforcement point for this exact tool. The fact is caller
// sourced. It cannot establish provider status or permission to execute.
func refundMoneyFacts(stage string, target DecisionTarget, context map[string]interface{}) contract.AttributeSet {
	if stage != DecisionStageTool || target.Type != "tool" || target.Server != "support-ops" || target.Tool != "support-ops.issue_refund" {
		return nil
	}
	now := time.Now().UTC()
	facts := contract.AttributeSet{}
	facts["args.refund.operation"] = contract.Known("issue_refund", contract.ProvCaller, 1, now)
	values, ok := context["refund_action"].(map[string]interface{})
	if !ok {
		facts["args.refund.amount_minor"] = contract.Absent(contract.ProvCaller, 1, now)
		facts["args.refund.currency"] = contract.Absent(contract.ProvCaller, 1, now)
		return facts
	}
	if amount, valid := moneyfacts.Minor(values["amount_minor"]); valid {
		facts["args.refund.amount_minor"] = contract.Known(amount, contract.ProvCaller, 1, now)
	} else {
		facts["args.refund.amount_minor"] = contract.Unknown(contract.ReasonMalformedValue, contract.ProvCaller, 1, now)
	}
	if currency, valid := moneyfacts.Currency(values["currency"]); valid {
		facts["args.refund.currency"] = contract.Known(currency, contract.ProvCaller, 1, now)
	} else {
		facts["args.refund.currency"] = contract.Unknown(contract.ReasonMalformedValue, contract.ProvCaller, 1, now)
	}
	return facts
}
