// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// FinCrime seam integration (ADR-061 / #3328/#3329): the lift of the documented
// fincrime context objects into /decide's evaluation. The anchored engine
// authors /decide's verdict (PRD v11 §1.1), and no FinCrime engine remains to
// consult: the legacy Engine A was deleted once the MCP request pass's cutover
// left it without a caller (PRD v11 §5.8). The HITLBridge adapter that lived
// here went with the last agent path that raised an approval entry, and the
// bridge itself with it (#4253).

package agent

import (
	"axonflow/platform/agent/fincrime"
)

// finCrimeParametersFromContext lifts the documented fincrime context objects
// out of DecideRequest.Context for the typed FinCrime fact evaluator. The
// target and admitted identity determine whether that evaluator applies.
//
// Returns nil when the caller sent neither key. A covered payment action then
// gets an invalid-context fact, while unrelated traffic stays outside the pack.
// Only the two documented keys are lifted; the rest of the request context
// remains audit-only (canonicalizeRequestContext), never evaluated.
func finCrimeParametersFromContext(reqContext map[string]interface{}) map[string]interface{} {
	if len(reqContext) == 0 {
		return nil
	}
	var out map[string]interface{}
	if v, ok := reqContext[fincrime.TransactionContextKey]; ok {
		out = map[string]interface{}{fincrime.TransactionContextKey: v}
	}
	if v, ok := reqContext[fincrime.CohortContextKey]; ok {
		if out == nil {
			out = map[string]interface{}{}
		}
		out[fincrime.CohortContextKey] = v
	}
	return out
}
