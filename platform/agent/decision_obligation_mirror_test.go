// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/shared/pep"
)

// TestRequiresRequestBodyRedactionMirrorsPEP is a DRIFT GUARD across a package
// boundary (#2958 R3 follow-up, folded in by #2959).
//
// Two functions encode the same question — "does this obligation need the seam
// to rewrite the request payload?" — on either side of the contract:
//
//   - requiresRequestBodyRedaction (this package) decides whether to SUPPRESS
//     the obligation for a seam that did not advertise the capability.
//   - pep.HasRequestRedaction (platform/shared/pep) is what a PEP branches on
//     to decide whether the verdict carries work for it.
//
// They are separate code with no compiler link, and they must agree. If the PDP
// side got NARROWER, it would emit an obligation the PEP then tries and fails
// to discharge — the exact allow→403 that #2958 removed. If the PDP side got
// WIDER, it would suppress an obligation the PEP could have fulfilled, silently
// degrading a governed leg to the org's fallback posture. Either drift is
// invisible until a partner's traffic finds it.
//
// The matrix is exhaustive over everything either predicate reads: the
// obligation type, the presence of the fulfillment block, and the phase.
func TestRequiresRequestBodyRedactionMirrorsPEP(t *testing.T) {
	types := []string{ObligationRedactPII, "log_only", "require_approval", ""}
	phases := []string{ObligationPhaseRequest, ObligationPhaseResponse, "", "bogus"}

	// Constants must be spelled identically on both sides before comparing the
	// predicates, otherwise the matrix below would compare two different
	// questions and agree for the wrong reason.
	if ObligationRedactPII != pep.ObligationRedactPII {
		t.Fatalf("obligation type constant drift: agent %q vs pep %q", ObligationRedactPII, pep.ObligationRedactPII)
	}
	if ObligationPhaseRequest != pep.PhaseRequest || ObligationPhaseResponse != pep.PhaseResponse {
		t.Fatalf("phase constant drift: agent %q/%q vs pep %q/%q",
			ObligationPhaseRequest, ObligationPhaseResponse, pep.PhaseRequest, pep.PhaseResponse)
	}

	for _, typ := range types {
		for _, withFulfillment := range []bool{true, false} {
			for _, phase := range phases {
				if !withFulfillment && phase != ObligationPhaseRequest {
					continue // phase is unreachable without a fulfillment block
				}

				agentObl := DecisionObligation{Type: typ}
				pepObl := pep.Obligation{Type: typ}
				if withFulfillment {
					agentObl.Fulfillment = &ObligationFulfillment{
						Endpoint: requestRedactionEndpoint, Method: "POST", Phase: phase,
					}
					pepObl.Fulfillment = &pep.ObligationFulfillment{
						Endpoint: requestRedactionEndpoint, Method: "POST", Phase: phase,
					}
				}

				gotPDP := requiresRequestBodyRedaction(agentObl)
				gotPEP := pep.HasRequestRedaction([]pep.Obligation{pepObl})
				if gotPDP != gotPEP {
					t.Errorf("drift for type=%q fulfillment=%v phase=%q: requiresRequestBodyRedaction=%v but pep.HasRequestRedaction=%v — the PDP's suppression gate and the PEP's fulfillment branch must answer the same question",
						typ, withFulfillment, phase, gotPDP, gotPEP)
				}
			}
		}
	}

	// Non-vacuity: a matrix where nothing is ever true would pass while both
	// predicates returned constant false.
	redacting := DecisionObligation{
		Type:        ObligationRedactPII,
		Fulfillment: &ObligationFulfillment{Phase: ObligationPhaseRequest},
	}
	if !requiresRequestBodyRedaction(redacting) {
		t.Fatal("positive control failed: a request-phase redact_pii obligation must require body redaction, so the agreement above is not vacuous")
	}
}
