// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// The circuit breaker's exemption switch itself, by reason code (#4246): every
// refusal the caller did not cause is exempt, and a refusal the caller did
// cause still feeds it. The evaluation_error case reaches no gated recording
// site observably - an engine evaluation_error names no policy, and those
// sites record only against one - so it is pinned here. (/api/request's
// segment fail-closed deny was judged under its class until #4253 removed the
// route's segment gate.)
func TestViolationFeedsCircuitBreakerByReasonCode(t *testing.T) {
	for code, feeds := range map[contract.ReasonCode]bool{
		contract.ReasonExplicitConstraint:    true,
		contract.ReasonNoMatchingPermission:  true,
		contract.ReasonUnsupportedObligation: false,
		contract.ReasonUnknownConstraint:     false,
		contract.ReasonUnknownRequirement:    false,
		contract.ReasonApprovalRequired:      false,
		contract.ReasonObligationConflict:    false,
		contract.ReasonEvaluationError:       false,
	} {
		if got := violationFeedsCircuitBreaker(string(code)); got != feeds {
			t.Errorf("violationFeedsCircuitBreaker(%s) = %v, want %v", code, got, feeds)
		}
	}
}
