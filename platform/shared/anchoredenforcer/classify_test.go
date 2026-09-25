// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"testing"

	"axonflow/platform/decision/contract"
	sharedidentity "axonflow/platform/shared/identity"
)

func TestClassifyNamesEachShapeInTheSeamsOrder(t *testing.T) {
	refusal := &sharedidentity.Admission{State: sharedidentity.AdmissionDeny, Reason: sharedidentity.ReasonUnknownRealm}
	dec := func(s contract.OperationalState) *contract.Decision { return &contract.Decision{State: s} }
	for _, c := range []struct {
		name string
		v    Verdict
		want Class
	}{
		{"a cause", Verdict{Unavailable: CauseEvaluation}, ClassUnavailable},
		{"a refusal", Verdict{Refusal: refusal}, ClassRefusal},
		{"no decision", Verdict{}, ClassNoDecision},
		{"allow", Verdict{Decision: dec(contract.StateAllow)}, ClassAllow},
		{"challenge", Verdict{Decision: dec(contract.StateChallenge)}, ClassChallenge},
		{"deny", Verdict{Decision: dec(contract.StateDeny)}, ClassWithhold},
		{"error", Verdict{Decision: dec(contract.StateError)}, ClassWithhold},
		{"an unrecognised state", Verdict{Decision: dec(contract.OperationalState("SOMETHING_NEW"))}, ClassWithhold},
		// The orderings that matter: a cause or a refusal beside a decision is
		// classed by the cause or the refusal, never by the decision.
		{"a cause beside an allow", Verdict{Unavailable: CauseEvaluation, Decision: dec(contract.StateAllow)}, ClassUnavailable},
		{"a refusal beside an allow", Verdict{Refusal: refusal, Decision: dec(contract.StateAllow)}, ClassRefusal},
		{"a cause beside a refusal", Verdict{Unavailable: CauseEvaluation, Refusal: refusal}, ClassUnavailable},
	} {
		if got := Classify(c.v); got != c.want {
			t.Errorf("%s: Classify = %d, want %d", c.name, got, c.want)
		}
	}
	if got := ClassifyDecision(nil); got != ClassNoDecision {
		t.Errorf("ClassifyDecision(nil) = %d, want ClassNoDecision", got)
	}
	if got := ClassifyDecision(dec(contract.StateChallenge)); got != ClassChallenge {
		t.Errorf("ClassifyDecision(challenge) = %d, want ClassChallenge", got)
	}
}
