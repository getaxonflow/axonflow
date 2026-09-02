// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	"axonflow/platform/shared/identity"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// dispositionCount reads one disposition counter for one plane.
//
// Read from the REGISTRY rather than from a field, because the counter is what
// an operator sees and a field is not: a test asserting on an internal tally
// would pass for a change that stopped exporting the series.
func dispositionCount(t *testing.T, plane, disposition string) float64 {
	t.Helper()
	return testutil.ToFloat64(shadowObservations.WithLabelValues(plane, disposition))
}

// TestTheContentTargetIsNormalizedOnBothSidesOfTheDiff is the R3 round-2
// finding-1 regression, and it is the SAME CLASS as the action-identity defect
// one statement earlier in the same function.
//
// Compile normalizes Options internally; the observer kept its own copy and read
// ContentTarget back off it to build the LEGACY side. Un-normalized, the legacy
// redaction effect targeted "" while the compiled ADR-065 effect targeted
// response.content, so every static redaction classified UNEXPLAINED - on every
// plane, on every deployment that had not set
// AXONFLOW_DECISION_SHADOW_CONTENT_TARGET, which is all of them.
//
// The assertion is on the CLASSIFICATION rather than on the field, because the
// field being equal is a means and a readable window is the end.
func TestTheContentTargetIsNormalizedOnBothSidesOfTheDiff(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts legacycompile.Options
	}{
		// The production default: nothing set, so Compile's own default has to
		// reach both sides.
		{"content target unset", legacycompile.Options{}},
		// And an explicitly configured one, so the test is not merely asserting
		// that a constant equals itself.
		{"content target set explicitly", legacycompile.Options{ContentTarget: "response.body"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			rec := newCapturingRecorder(1)
			o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec,
				WithCompileOptions(tc.opts))

			obs := fixtureObservation(true, true)
			// THE RESPONSE PHASE OF THE FIXTURE ROW, whose stored
			// action_response IS "redact". The action is taken from the row
			// rather than overridden on the observation: overriding it would
			// make the observation claim the plane resolved a redaction while
			// the COMPILED row still said block, and the resulting UNEXPLAINED
			// would be about the fixture rather than about the content target.
			//
			// A redaction is the only action whose target is supplied from the
			// compilation options rather than stored on the row, which is what
			// makes it the shape this finding lives in.
			obs.Plane = legacycompile.PlaneOrchestratorResponse
			obs.Phase = legacycompile.PhaseResponse
			obs.Rows[0].Action = "redact"
			obs.Rows[0].Target = ""
			o.Observe(context.Background(), obs)

			got := rec.wait(t)
			if len(got) != 1 {
				t.Fatalf("want 1 comparison, got %d", len(got))
			}
			c := got[0].Record
			if c.Class == shadow.ClassUnexplained {
				t.Fatalf("a matched static REDACTION classified UNEXPLAINED with %s.\n"+
					"That is the whole window: every static redaction on every plane would "+
					"land in gate 18's numerator for a reason the migration did not cause.\n"+
					"detail: %s", tc.name, c.Detail)
			}
		})
	}
}

// TestAShadowedRowKeepsItsDetectorVerdictAndLeavesTheDeterminingSet is the
// round-2 finding-4 regression.
//
// A row the plane's combiner discarded has TWO facts that must not be
// collapsed: its detector fired (which the ADR-065 side needs, or
// EC6_PROXY_TIER_FIRST_MATCH_SHADOWING can never fire) and it determined
// nothing (which the legacy side needs, or the determining sets disagree for a
// reason the running system did not produce).
//
// The proxy-tier site expressed "shadowed" by setting Matched back to false,
// which is a fail-open in BOTH directions at once.
func TestAShadowedRowKeepsItsDetectorVerdictAndLeavesTheDeterminingSet(t *testing.T) {
	obs := fixtureObservation(true, true)
	obs.Rows[0].Shadowed = true
	obs.Rows[0].Action = ""

	// The LEGACY side must not claim it.
	v := legacyVerdictFor(obs, legacycompile.DefaultContentTarget)
	for _, d := range v.Determining {
		if strings.Contains(d, fixturePolicy) {
			t.Fatalf("a SHADOWED row reached the legacy determining set (%v). The plane's "+
				"combiner discarded it, so the running system rested nothing on it, and "+
				"claiming it here manufactures a disagreement with the ADR-065 side.", v.Determining)
		}
	}
	if len(v.Effects) != 0 {
		t.Fatalf("a shadowed row produced legacy effect(s) %v; the running system applied none", v.Effects)
	}

	// The ADR-065 side MUST still see the detector as having fired.
	c := caseFor(obs, "shadowed-case", legacycompile.Options{}.Normalized())
	if !c.DetectorVerdicts[fixturePolicy] {
		t.Fatalf("a shadowed row's detector verdict is %v, want true.\n"+
			"EC6_PROXY_TIER_FIRST_MATCH_SHADOWING's evidence predicate requires the denying "+
			"constraint's detector verdict to be TRUE, so a false here makes the one "+
			"plane-specific divergence this harness declares UNREACHABLE - and the real "+
			"tightening records as a confident `match`.", c.DetectorVerdicts[fixturePolicy])
	}

	// ANTI-VACUITY, in both directions: an UNSHADOWED matched row must do the
	// opposite, or the assertions above would hold for a translator that
	// ignored every row.
	plain := fixtureObservation(true, true)
	pv := legacyVerdictFor(plain, legacycompile.DefaultContentTarget)
	if len(pv.Determining) == 0 {
		t.Fatal("an ordinary MATCHED row produced an empty determining set, so the " +
			"shadowed-row assertion above would pass for a translator that dropped everything")
	}
	pc := caseFor(plain, "plain-case", legacycompile.Options{}.Normalized())
	if !pc.DetectorVerdicts[fixturePolicy] {
		t.Fatal("an ordinary matched row's detector verdict is false; the fixture is wrong")
	}
}

// TestTheSnapshotDigestDoesNotVaryWithTheNUMBEROfSiblingFacts is the round-2
// finding-15 regression.
//
// A dynamic row whose actions JSONB is an array becomes N sibling RowFacts
// sharing a row key - which the effect MULTISET needs and the policy-SET
// identity must not see. Without de-duplication sha256("k") != sha256("k\nk"),
// so the digest documented as identifying "the policy set this plane evaluated
// against" varied with request CONTENT: each shape bought a fresh compile,
// bundle build-sign-verify and OPA engine against a 256-entry cache, and two
// comparisons of one policy set were attributed to two different sets.
func TestTheSnapshotDigestDoesNotVaryWithTheNUMBEROfSiblingFacts(t *testing.T) {
	row := RowFact{
		Table: "dynamic_policies", PolicyID: "p-multi",
		UpdatedAt: fixtureStamp, Ran: true, Matched: true,
	}
	one := Observation{Rows: []RowFact{row}}

	// The same row, having produced three instructions - block, log, and a
	// redaction naming a field. Sibling facts share Table/PolicyID/UpdatedAt.
	blockAct, logAct, redactAct := row, row, row
	blockAct.Action, logAct.Action = "block", "log"
	redactAct.Action, redactAct.Target = "redact", "response.ssn"
	three := Observation{Rows: []RowFact{blockAct, logAct, redactAct}}

	if one.Snapshot() != three.Snapshot() {
		t.Fatalf("the policy-set digest changed with the number of INSTRUCTIONS one row "+
			"produced:\n  1 fact:  %s\n  3 facts: %s\n"+
			"These are the same policy set. A digest that varies with request content is "+
			"not the identity of a policy set, and every distinct value is a separate "+
			"worldKey and reportKey - a fresh compile, bundle and OPA engine per shape.",
			one.Snapshot(), three.Snapshot())
	}

	// ANTI-VACUITY: a genuinely DIFFERENT set must still digest differently, or
	// the assertion above would hold for a function returning a constant.
	other := RowFact{Table: "dynamic_policies", PolicyID: "p-other", UpdatedAt: fixtureStamp}
	if (Observation{Rows: []RowFact{row, other}}).Snapshot() == one.Snapshot() {
		t.Fatal("two DIFFERENT policy sets produced the same digest; the de-duplication " +
			"above collapsed more than the siblings it was meant to")
	}
	// And an updated_at change must still move it: staleness is what the digest
	// exists to detect.
	edited := row
	edited.UpdatedAt = "2026-09-01T00:00:00Z"
	if (Observation{Rows: []RowFact{edited}}).Snapshot() == one.Snapshot() {
		t.Fatal("editing a row's updated_at did not change the digest, so a bundle built " +
			"from a stale read would be reused as if it were current")
	}
}

// TestAnObservationWithAnOrgScopeAndNoOrgIDIsRefusedAndCounted is the round-2
// finding-3 regression.
//
// effectiveMode falls back to the PROCESS mode when OrgID is empty. That is
// right for a plane with no organization and wrong for a site that has one and
// did not pass it - and three shipped that way, including the only
// cowork_ingest evaluation. The failure was silent in both directions: a
// per-org enablement never reached them, a per-org exemption never released
// them, and no series moved either way.
func TestAnObservationWithAnOrgScopeAndNoOrgIDIsRefusedAndCounted(t *testing.T) {
	rec := newCapturingRecorder(1)
	// A per-org source IS wired and the process mode is OFF: the documented
	// rollout shape, and the only shape in which this is a defect.
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeOff), rec,
		WithOrgModes(fixtureOrgModes{modes: map[string]identity.CompatMode{fixtureOrg: identity.CompatModeShadow}}))

	before := dispositionCount(t, string(legacycompile.PlaneGatewayRequest), dispositionRefused)

	obs := fixtureObservation(true, true)
	obs.OrgID = "" // the defect: a scope, and no id to resolve the mode from
	o.Observe(context.Background(), obs)

	after := dispositionCount(t, string(legacycompile.PlaneGatewayRequest), dispositionRefused)
	if after <= before {
		t.Fatalf("an observation with an org scope and NO org id did not move the `refused` "+
			"counter (%v -> %v).\nThe per-organization mode cannot be resolved for it, so "+
			"the process mode silently decides - and on the documented rollout (process off, "+
			"one org on) the plane records nothing while reading exactly like no traffic.",
			before, after)
	}

	// ANTI-VACUITY: the same observation WITH an org id must be accepted, or
	// this test would pass against an observer that refused everything.
	o.Observe(context.Background(), fixtureObservation(true, true))
	if got := rec.wait(t); len(got) != 1 {
		t.Fatalf("the well-formed observation was not compared (%d comparisons); the "+
			"assertion above would then hold for an observer that refused everything", len(got))
	}
}
