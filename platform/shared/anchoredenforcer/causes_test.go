// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"errors"
	"fmt"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
)

// TestAnEditionRefusalIsNotReportedAsAGenericActivationFailure is about what an
// operator can DO with the counter.
//
// Every failure between "this organization owns an anchored verdict" and "the
// engine answered" lands on axonflow_decision_enforce_decisions_total with a
// reason label, per organization. Before this routing existed, an activation
// refused because the active document spends a construct the deployment's
// edition no longer carries was labelled `activation_failed` - the same label
// as an unreadable bundle, a signature that does not verify and an anchor that
// does not match. Those have nothing in common from an operator's chair: three
// are incidents, and this one is an upgrade conversation about a document that
// is exactly as valid as it was yesterday.
//
// The status is deliberately unchanged. A caller still gets the 503 the seam
// gives every enforce-mode failure; the per-organization observability is the
// metric and the audit row, and that is where the distinction has to live.
func TestAnEditionRefusalIsNotReportedAsAGenericActivationFailure(t *testing.T) {
	refusal := &activation.CapabilityRefusal{
		Code:    activation.CodeCapabilityRequiresUpgrade,
		Edition: string(authoring.EditionCommunity),
	}

	if got := CauseForActivation(refusal); got != CauseCapability {
		t.Errorf("a bare CapabilityRefusal mapped to %q, want %q", got, CauseCapability)
	}

	// WRAPPED, which is how it actually arrives. ActivationFor wraps what
	// Activate returns, so a check that only handled the bare value would pass
	// this test's first case and still label every real refusal
	// `activation_failed`.
	wrapped := fmt.Errorf("loading the active document: %w", refusal)
	if got := CauseForActivation(wrapped); got != CauseCapability {
		t.Errorf("a WRAPPED CapabilityRefusal mapped to %q, want %q - errors.As is required, not a type assertion",
			got, CauseCapability)
	}

	// THE NEGATIVE TWIN. Without it, a helper that returned the capability
	// cause unconditionally would satisfy both assertions above, and every
	// corrupt bundle would be reported to an operator as a licence problem -
	// the same collapse as before, pointing the other way.
	for _, other := range []error{
		errors.New("the bundle digest does not match the artifact"),
		fmt.Errorf("verifying the organization signature: %w", errors.New("signature mismatch")),
	} {
		if got := CauseForActivation(other); got != CauseActivation {
			t.Errorf("a non-capability activation error mapped to %q, want %q: %v", got, CauseActivation, other)
		}
	}

	// The cause must carry an operator-facing sentence, like every other cause
	// in the vocabulary. A reason with no message reaches the caller as an
	// empty string.
	if msg := CauseMessages[CauseCapability]; msg == "" {
		t.Errorf("%q has no entry in CauseMessages", CauseCapability)
	}
}
