// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import "axonflow/platform/decision/contract"

// Class is which of the six shapes a Verdict has. The orchestrator's three
// request-side seams (the route requests, the workflow step gate and the
// multi-agent checker) answer a verdict by its class first and in their own
// terms after: which classes hold, how an expired approval is counted, how the
// blocking policy is named. Those arms stay in each seam; only the
// classification is shared (#4249 row 5674229604), so those three cannot
// disagree about which shape a verdict is. The orchestrator's response seam
// and the agent's seams still classify with their own switches.
type Class int

const (
	// ClassUnavailable: the plane could not reach a verdict (v.Unavailable
	// names the cause).
	ClassUnavailable Class = iota + 1
	// ClassRefusal: the identity plane refused the subject (v.Refusal).
	ClassRefusal
	// ClassNoDecision: nothing refused and no decision was returned.
	ClassNoDecision
	// ClassAllow: the decision permits.
	ClassAllow
	// ClassChallenge: the decision requires an approval.
	ClassChallenge
	// ClassWithhold: the decision denies, or errored on input it could not
	// evaluate, or is in any other state. Unknown input is never an admission
	// (ADR-065 invariant 4).
	ClassWithhold
)

// Classify returns v's class, checked in the order the three seams checked it:
// an unavailable cause first, then a refusal, then an absent decision, then
// the decision's state. A verdict carrying a cause or a refusal beside a decision
// is classed by the cause or the refusal.
func Classify(v Verdict) Class {
	switch {
	case v.Unavailable != "":
		return ClassUnavailable
	case v.Refusal != nil:
		return ClassRefusal
	case v.Decision == nil:
		return ClassNoDecision
	}
	switch v.Decision.State {
	case contract.StateAllow:
		return ClassAllow
	case contract.StateChallenge:
		return ClassChallenge
	default:
		return ClassWithhold
	}
}

// ClassifyDecision classes a decision alone, ignoring any cause or refusal
// beside it: ClassNoDecision for nil, otherwise its state's class. A seam's
// decision half, reached only after the seam has answered the cause and the
// refusal, reads it.
func ClassifyDecision(dec *contract.Decision) Class {
	return Classify(Verdict{Decision: dec})
}
