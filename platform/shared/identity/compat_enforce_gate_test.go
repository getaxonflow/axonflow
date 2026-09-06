// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"strings"
	"testing"
)

// record drives the real recorder, so these tests exercise the same increments
// production takes rather than writing the counters directly. A test that set
// the metrics by hand would pass against a recorder that stopped incrementing.
func record(t *testing.T, component, org string, synthetic bool, d CompatDivergence) {
	t.Helper()
	PrometheusCounterfactualRecorder{}.RecordCounterfactual(context.Background(), Counterfactual{
		Component:  component,
		OrgID:      org,
		Synthetic:  synthetic,
		Divergence: d,
	})
}

// TestEnforcePreconditionRequiresAnOrganicDenominator is rule 1 and the
// canary trap in one: a probe exists to give the window a denominator, so if
// its own comparisons satisfied that denominator the gate would be unlockable
// by the thing built to feed it.
func TestEnforcePreconditionRequiresAnOrganicDenominator(t *testing.T) {
	const comp, org = "agent", "gate-denominator-org"

	got := EvaluateEnforcePrecondition(comp, org)
	if got.OK {
		t.Fatal("an organization with no comparisons at all satisfied the precondition; there is no shadow window behind it")
	}
	if got.Reason != EnforceReasonNotMeasured {
		t.Errorf("reason = %q, want %q", got.Reason, EnforceReasonNotMeasured)
	}

	// SYNTHETIC ONLY. The canary ran; nobody else did.
	for i := 0; i < 50; i++ {
		record(t, comp, org, true, DivergenceNone)
	}
	got = EvaluateEnforcePrecondition(comp, org)
	if got.OK {
		t.Fatalf("50 SYNTHETIC comparisons satisfied the denominator (read %.0f). A canary exists to give the "+
			"window a denominator; letting it satisfy the enforce gate would unlock enforcement for traffic "+
			"nobody has served.", got.Denominator)
	}
	if got.Reason != EnforceReasonNotMeasured {
		t.Errorf("reason = %q, want %q", got.Reason, EnforceReasonNotMeasured)
	}

	// One organic comparison, and it is measured.
	record(t, comp, org, false, DivergenceNone)
	got = EvaluateEnforcePrecondition(comp, org)
	if !got.OK {
		t.Fatalf("an organization with an organic comparison and no divergence was refused: %s / %s", got.Reason, got.Detail)
	}
	if got.Denominator != 1 {
		t.Errorf("denominator = %v, want 1 (synthetic comparisons must not be counted)", got.Denominator)
	}
}

// TestEnforcePreconditionReadsAnAbsentDivergenceSeriesAsZeroOnlyWhenMeasured
// is rule 2, and it is the ordering that makes the whole gate sound.
//
// A CounterVec with no children exports no series, so "no divergence series
// for this org" is equally consistent with "nothing diverged" and "nothing
// ran". If the divergence read came first, an organization nobody had measured
// would present as perfectly clean - the most dangerous possible answer.
func TestEnforcePreconditionReadsAnAbsentDivergenceSeriesAsZeroOnlyWhenMeasured(t *testing.T) {
	const comp = "agent"

	// Never measured: no comparison series, and no divergence series either.
	unmeasured := EvaluateEnforcePrecondition(comp, "gate-never-measured-org")
	if unmeasured.OK {
		t.Fatal("an unmeasured organization passed. Its divergence series is absent, but so is its denominator, " +
			"and absence of a divergence series proves nothing on its own.")
	}
	if unmeasured.Reason != EnforceReasonNotMeasured {
		t.Errorf("reason = %q, want %q - the refusal must name the missing denominator, not a clean divergence read",
			unmeasured.Reason, EnforceReasonNotMeasured)
	}
	if unmeasured.Divergences != 0 {
		t.Errorf("divergences = %v; the unmeasured case must not have read the divergence series at all", unmeasured.Divergences)
	}

	// Measured and clean: the same absent divergence series, now readable.
	const clean = "gate-measured-clean-org"
	record(t, comp, clean, false, DivergenceNone)
	if got := EvaluateEnforcePrecondition(comp, clean); !got.OK {
		t.Fatalf("a measured, non-diverging organization was refused: %s / %s", got.Reason, got.Detail)
	}
}

// TestEnforcePreconditionRefusesAnOrganizationStillDiverging pins that a real
// divergence blocks, and that the refusal names the CLASS - an operator who is
// told only "diverging" cannot act.
func TestEnforcePreconditionRefusesAnOrganizationStillDiverging(t *testing.T) {
	const comp, org = "agent", "gate-diverging-org"
	record(t, comp, org, false, DivergenceNone)
	record(t, comp, org, false, DivergenceIdentityRefused)

	got := EvaluateEnforcePrecondition(comp, org)
	if got.OK {
		t.Fatal("an organization with an unexplained divergence was granted enforce; enforcement would refuse exactly that traffic")
	}
	if got.Reason != EnforceReasonDiverging {
		t.Errorf("reason = %q, want %q", got.Reason, EnforceReasonDiverging)
	}
	if !strings.Contains(got.Detail, string(DivergenceIdentityRefused)) {
		t.Errorf("the refusal does not name the divergence class, so an operator cannot act on it.\ngot: %s", got.Detail)
	}

	// NOT_EVALUATED IS NOT A DIVERGENCE. A record the adapter never evaluated
	// is not evidence of disagreement, and counting it would block an
	// organization for traffic the plane deliberately skipped.
	const skipped = "gate-not-evaluated-org"
	record(t, comp, skipped, false, DivergenceNone)
	record(t, comp, skipped, false, DivergenceNotEvaluated)
	if got := EvaluateEnforcePrecondition(comp, skipped); !got.OK {
		t.Errorf("a not_evaluated record blocked enforcement: %s / %s", got.Reason, got.Detail)
	}
}

// TestEnforcePreconditionRefusesTheSharedBuckets is rule 3: the overflow and
// unattributed labels are shared by many organizations, so a reading taken
// from them is a statement about a crowd, never about the org in hand.
func TestEnforcePreconditionRefusesTheSharedBuckets(t *testing.T) {
	// The unattributed bucket is reachable by name: an empty org id.
	record(t, "agent", "", false, DivergenceNone)
	got := EvaluateEnforcePrecondition("agent", "")
	if got.OK {
		t.Fatal("the unattributed bucket satisfied the gate. Every record with no organization lands there, so a " +
			"reading from it is not about any organization in particular.")
	}
	if got.Reason != EnforceReasonUnnamedOrgLabel {
		t.Errorf("reason = %q, want %q", got.Reason, EnforceReasonUnnamedOrgLabel)
	}
}
