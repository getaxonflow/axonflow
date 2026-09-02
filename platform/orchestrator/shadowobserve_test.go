// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"sort"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
	"axonflow/platform/shared/planeshadow"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
)

// TestAMovedConditionFieldIsNotComparable pins R3 round 1, finding 8.
//
// The dynamic engine's risk_score is MUTABLE mid-loop: a matched policy's
// modify_risk raises result.RiskScore, and a later policy's condition reads the
// raised value. So one evaluation can read one field at 0 for the first row and
// at 50 for the third.
//
// The ADR-065 request carries ONE value per attribute and the PDP evaluates
// every compiled row against it, so whichever value were sent, some row would
// be judged against a number the legacy engine never showed it - and the
// determining sets would differ on EVERY request of that shape, in the
// numerator ADR-065 gate 18 is read from. That is a difference the harness
// manufactured, not one the migration caused.
func TestAMovedConditionFieldIsNotComparable(t *testing.T) {
	t.Run("a field read at one value is comparable", func(t *testing.T) {
		tr := &dynamicShadowTrace{fields: map[string]any{}}
		tr.noteField("risk_score", 0.0)
		tr.noteField("risk_score", 0.0)
		tr.noteField("user.role", "developer")
		if len(tr.movedFields) != 0 {
			t.Fatalf("a field read twice at the SAME value was reported as moved: %v", tr.movedFields)
		}
	})

	t.Run("a field read at two values is reported", func(t *testing.T) {
		tr := &dynamicShadowTrace{fields: map[string]any{}}
		tr.noteField("risk_score", 0.0)
		tr.noteField("user.role", "developer")
		tr.noteField("risk_score", 50.0) // modify_risk raised it mid-loop
		if !tr.movedFields["risk_score"] {
			t.Fatal("risk_score was read at 0 and then at 50 in one evaluation and was not " +
				"reported as moved. One request carries one value per attribute, so the PDP " +
				"would judge the first row against 50 - a number the legacy engine never " +
				"showed it - and the determining sets would differ on every request of this " +
				"shape, in gate 18's numerator.")
		}
		if tr.movedFields["user.role"] {
			t.Fatal("a field read once was reported as moved")
		}
	})

	t.Run("a nil trace and an unfamiliar type do not panic", func(t *testing.T) {
		var nilTrace *dynamicShadowTrace
		nilTrace.noteField("x", 1)

		tr := &dynamicShadowTrace{fields: map[string]any{}}
		// getFieldValue returns scalars today. A future field returning a slice
		// must degrade to "assume it moved" rather than panic on the REQUEST
		// PATH, which a bare == would do.
		tr.noteField("weird", []string{"a"})
		tr.noteField("weird", []string{"a"})
		if !tr.movedFields["weird"] {
			t.Fatal("an uncomparable type was treated as unchanged; the conservative reading " +
				"is that it moved, because the alternative is comparing a pair whose inputs " +
				"cannot be shown to be the same")
		}
	})
}

// TestEmitRefusesToCompareAMovedField is the BEHAVIOURAL half of the test
// above: it asserts that emit actually TAKES the branch, not merely that
// noteField detects the condition.
//
// A detector and a branch are two properties, and a test of only the first
// leaves the second free to be deleted - which is exactly what a mutant on
// emit's guard does. The branch's only observable effect is the counter, so
// that is what this reads.
func TestEmitRefusesToCompareAMovedField(t *testing.T) {
	// AN OBSERVER MUST BE INSTALLED, because the counter is now gated on the
	// organization PARTICIPATING in the window.
	//
	// R3 round 2, finding 11: NoteNotComparable incremented unconditionally
	// from a call site reached before Observe, so on a deployment with the
	// process mode off and an org source wired, every modify_risk evaluation
	// contributed `not_comparable` forever for tenants that were not in the
	// window - into the five counters presented as the window's denominator.
	// It now resolves the mode first, which is what this fixture supplies.
	//
	// NO WORKERS, AND THAT IS WHAT MAKES THIS TEST DETERMINISTIC.
	//
	// NotComparableCounter is `shadowObservations{plane,not_comparable}`, and
	// the observer's WORKER increments that same series whenever a comparison
	// comes back ErrNotComparable. The anti-vacuity leg below emits a CLEAN
	// trace, which is precisely the leg that reaches Observe and gets enqueued -
	// and shadowTestRowSource serves no rows, so the worker classifies it
	// not-comparable and moves the counter. With a worker running, that
	// increment races the very next line of this test, and the leg then reports
	// the clean trace as having taken the call-site branch. It did not; a
	// different writer moved the number. Measured as a real intermittent failure
	// on the -race job, which widens the window.
	//
	// The property under test is a CALL-SITE property and is synchronous, so the
	// asynchronous writer is noise rather than signal. Starting no workers
	// removes it without weakening anything: the guard still runs, still counts,
	// and a mutant that fires it on every input still moves the counter here.
	shadowTestObserverWithWorkers(t, 0)

	plane := legacycompile.PlaneWCP
	before := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane))

	tr := &dynamicShadowTrace{
		rows:   []planeshadow.RowFact{{Table: "dynamic_policies", PolicyID: "p", UpdatedAt: "x", Ran: true}},
		index:  map[string]int{"p": 0},
		fields: map[string]any{},
	}
	tr.noteField("risk_score", 0.0)
	tr.noteField("risk_score", 50.0)

	req := OrchestratorRequest{ShadowPlane: plane}
	tr.emit(context.Background(), req, "org", nil, &PolicyEvaluationResult{Allowed: true})

	// EXACTLY one, not merely more than none. With no worker there is no second
	// writer of this series, so the precise count is assertable - and a call
	// site that counted twice would be a double-counted denominator, which the
	// looser reading admitted.
	if got := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane)); got != before+1 {
		t.Fatalf("emit did not count the observation as not-comparable exactly once (%v -> %v). A field read "+
			"at two values in one evaluation cannot be asked of a request that carries one "+
			"value per attribute; comparing it puts a difference the harness manufactured into "+
			"gate 18's numerator on every request of that shape.", before, got)
	}

	// ANTI-VACUITY: an observation with NO moved field must not take the
	// branch, or the assertion above would pass for any input.
	clean := &dynamicShadowTrace{
		rows:   []planeshadow.RowFact{{Table: "dynamic_policies", PolicyID: "p", UpdatedAt: "x", Ran: true}},
		index:  map[string]int{"p": 0},
		fields: map[string]any{},
	}
	clean.noteField("risk_score", 0.0)
	mid := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane))
	clean.emit(context.Background(), req, "org", nil, &PolicyEvaluationResult{Allowed: true})
	if got := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane)); got != mid {
		t.Fatalf("an observation with no moved field was ALSO counted not-comparable (%v -> %v); "+
			"the branch fires on everything and proves nothing", mid, got)
	}
}

// TestTheDynamicSiteRefusesAPlaneThatIsNotDynamic pins the guard AND the fact
// that a refusal is COUNTED (R3 round 1, finding 5).
//
// The site used to log and return before Observe was ever called, so no metric
// moved. A sixth dynamic call site that forgot ShadowPlane - it is json:"-",
// so its zero value is the empty plane - would then contribute nothing while
// every other plane's series looked healthy.
func TestTheDynamicSiteRefusesAPlaneThatIsNotDynamic(t *testing.T) {
	for name, plane := range map[string]legacycompile.Plane{
		"no plane at all":  "",
		"a static plane":   legacycompile.PlaneGatewayRequest,
		"an unknown plane": legacycompile.Plane("gateway"),
	} {
		if shadowPlaneIsDynamic(plane) {
			t.Errorf("%s (%q) was accepted as a dynamic plane; its rows would be attributed to "+
				"a surface that never reads the dynamic substrate", name, plane)
		}
	}
	for _, plane := range legacycompile.PlanesFor(legacycompile.SubstrateDynamic) {
		if !shadowPlaneIsDynamic(plane) {
			t.Errorf("%q evaluates the dynamic substrate and was refused", plane)
		}
	}
	// ANTI-VACUITY: without this a predicate returning false for everything
	// would satisfy the first loop.
	if len(legacycompile.PlanesFor(legacycompile.SubstrateDynamic)) == 0 {
		t.Fatal("no plane evaluates the dynamic substrate; the second loop asserted nothing")
	}
}

// shadowTestObserverOn installs a process observer for the duration of a test,
// so newDynamicShadowTrace returns a trace rather than nil.
//
// Without it every assertion about the trace's CONTENTS is vacuous: a nil trace
// has no rows, so "another tenant's row is absent" holds trivially. The helper
// therefore fails loudly rather than skipping.
func shadowTestObserverOn(t *testing.T) {
	t.Helper()
	shadowTestObserverWithWorkers(t, 1)
}

// shadowTestObserverWithWorkers is shadowTestObserverOn with the worker count
// stated.
//
// Pass 0 in a test that READS a shadowObservations counter. Those series are
// written from two places - the synchronous call-site Note helpers and the
// worker's own classification - and a test asserting on a call site's effect
// cannot tell the two apart once a worker is draining the queue. Every other
// test here asserts on the TRACE the site builds and wants the ordinary
// one-worker fixture.
func shadowTestObserverWithWorkers(t *testing.T, workers int) {
	t.Helper()
	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })

	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: identity.CompatModeShadow, SampleRate: 1, QueueDepth: 16, Workers: workers},
		shadowTestRowSource{}, planeshadow.MetricsRecorder{},
		planeshadow.WithComponent("orchestrator-shadow-test"),
	)
	if err != nil {
		t.Fatalf("building the test observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	planeshadow.SetProcessObserver(o)
	if !planeshadow.Enabled() {
		t.Fatal("the shadow is not enabled after installing an observer; every assertion " +
			"about a trace's contents would be vacuous against a nil trace")
	}
}

// testOrgModes answers the per-organization decision-shadow mode from a map.
type testOrgModes map[string]identity.CompatMode

func (m testOrgModes) OrgDecisionShadowMode(_ context.Context, orgID string) (identity.CompatMode, bool, error) {
	mode, ok := m[orgID]
	if !ok {
		return identity.CompatModeUnspecified, false, nil
	}
	return mode, true, nil
}

func orgModesFor(m map[string]identity.CompatMode) planeshadow.OrgModeSource { return testOrgModes(m) }

// shadowTestRowSource satisfies the observer's row source. These tests assert
// on the TRACE the site builds, never on a comparison, so it serves nothing.
type shadowTestRowSource struct{}

func (shadowTestRowSource) RawRows(context.Context, string) ([]legacycompile.RawRow, error) {
	return nil, nil
}

// dynEntry builds one cache entry belonging to one organization.
func dynEntry(cacheKey, policyID, orgID string) dynamicPolicyCacheEntry {
	return dynamicPolicyCacheEntry{
		cacheKey: cacheKey,
		policyMap: map[string]interface{}{
			"policy_id":  policyID,
			"category":   "pii-us",
			"updated_at": "2026-01-01T00:00:00Z",
			"_metadata":  map[string]interface{}{"org_id": orgID},
		},
	}
}

// TestTheDynamicTraceCarriesOnlyTheRequestingTenantsRows is the R3 round-2
// finding-2 regression.
//
// e.policies is an explicitly ALL-TENANTS cache - loaded on the BYPASSRLS
// refresh pool with no org predicate - and the trace enumerated it whole. Two
// consequences, both permanent on any deployment with two organizations holding
// dynamic policies, which is both of ours:
//
//   - dbRowSource.RawRows reads only `org_id = orgScope` plus 'global' and
//     coversPlaneRows is a one-directional cover, so every OTHER tenant's row is
//     reported MISSING and every observation from all four dynamic planes
//     returns ErrNotComparable, blaming a deletion that never happened.
//   - one tenant's policy_ids ride into another tenant's Observation.Rows, its
//     Comparison.PolicySnapshot and its "not comparable" log line.
func TestTheDynamicTraceCarriesOnlyTheRequestingTenantsRows(t *testing.T) {
	shadowTestObserverOn(t)

	entries := []dynamicPolicyCacheEntry{
		dynEntry("k-mine", "p-mine", "org-a"),
		dynEntry("k-theirs", "p-theirs", "org-b"),
		dynEntry("k-global", "p-global", "global"),
	}

	tr := newDynamicShadowTrace(entries, "org-a")
	if tr == nil {
		t.Fatal("no trace was built; the shadow is not enabled in this fixture and every " +
			"assertion below would be vacuous")
	}

	got := map[string]bool{}
	for _, r := range tr.rows {
		got[r.PolicyID] = true
	}
	if got["p-theirs"] {
		t.Fatalf("ANOTHER TENANT'S POLICY reached org-a's trace: %v.\n"+
			"The row source reads only org-a's rows plus 'global', so coversPlaneRows "+
			"reports p-theirs MISSING and every observation on all four dynamic planes "+
			"becomes permanently not_comparable - and p-theirs would ride into org-a's "+
			"policy snapshot and log lines.", sortedPolicyIDs(tr.rows))
	}

	// ANTI-VACUITY IN BOTH DIRECTIONS. The tenant's OWN row and the shared
	// baseline must both survive, or a trace that dropped everything would pass
	// the assertion above - and a version digest missing the tenant's own rows
	// is not the identity of what the plane evaluated.
	if !got["p-mine"] {
		t.Fatalf("the requesting tenant's OWN policy is missing from its trace: %v",
			sortedPolicyIDs(tr.rows))
	}
	if !got["p-global"] {
		t.Fatalf("the 'global' baseline is missing from the trace: %v. It applies to every "+
			"org and the row source reads it, so dropping it here would leave the compiled "+
			"side carrying a row the observation does not claim.", sortedPolicyIDs(tr.rows))
	}
}

// TestASegmentScopedRowStaysInTheVersionEvenWhenTheCallerIsNotInIt pins the
// reason the trace filters on the ORG half of the applicability gate and not
// the whole gate.
//
// A segment-scoped row the caller is not in did not RUN, which the tri-state
// records as unknown - but it is still part of the tenant's policy VERSION, and
// the digest that identifies that version has to contain it. Filtering with the
// full gate (nil segments) would drop every segment-scoped row from the version.
func TestASegmentScopedRowStaysInTheVersionEvenWhenTheCallerIsNotInIt(t *testing.T) {
	shadowTestObserverOn(t)

	seg := dynEntry("k-seg", "p-seg", "org-a")
	seg.policyMap["_metadata"].(map[string]interface{})["segment_id"] = "seg-finance"

	tr := newDynamicShadowTrace([]dynamicPolicyCacheEntry{seg}, "org-a")
	if tr == nil {
		t.Fatal("no trace was built; this assertion would be vacuous")
	}
	if len(tr.rows) != 1 || tr.rows[0].PolicyID != "p-seg" {
		t.Fatalf("a segment-scoped row belonging to this tenant was dropped from the policy "+
			"version: %v.\nIt did not RUN for a caller outside the segment - which the "+
			"tri-state records as unknown - but the digest identifying what the plane "+
			"evaluated against must still contain it.", sortedPolicyIDs(tr.rows))
	}
	// And it must be reported as NOT having run, or the tri-state would be told
	// a condition positively did not hold when nothing evaluated it.
	if tr.rows[0].Ran {
		t.Fatal("a segment-scoped row the caller is not in is marked Ran; nothing evaluated it")
	}
}

func sortedPolicyIDs(rows []planeshadow.RowFact) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.PolicyID)
	}
	sort.Strings(out)
	return out
}

// TestANonParticipatingOrgDoesNotMoveTheDenominator is the R3 round-2
// finding-11 regression.
//
// Observe argues at length that an organization whose resolved mode does not
// record is not in the window at all and must not appear in these series - and
// then the two Note helpers incremented them unconditionally, from call sites
// reached BEFORE Observe. On a deployment with the process mode off, an org
// source wired and no organization opted in, every dynamic evaluation using
// modify_risk incremented `not_comparable` forever, for tenants that are not in
// the window, in the counters an operator reads to size it.
func TestANonParticipatingOrgDoesNotMoveTheDenominator(t *testing.T) {
	plane := legacycompile.PlaneWCP

	// The process mode is OFF and a per-org source IS wired - the documented
	// rollout shape, and the only shape in which this is a defect.
	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })
	// No workers, for the reason shadowTestObserverWithWorkers gives: this test
	// READS a shadowObservations counter, and the worker writes the same series.
	// Both legs below return before Observe today, so nothing is enqueued - but
	// that is a property of the branch under test, and a test must not depend on
	// the thing it is checking to stay deterministic.
	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: identity.CompatModeOff, SampleRate: 1, QueueDepth: 16, Workers: 0},
		shadowTestRowSource{}, planeshadow.MetricsRecorder{},
		planeshadow.WithComponent("orchestrator-nonparticipant-test"),
		planeshadow.WithOrgModes(orgModesFor(map[string]identity.CompatMode{
			"org-shadowing": identity.CompatModeShadow,
		})),
	)
	if err != nil {
		t.Fatalf("building the observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	planeshadow.SetProcessObserver(o)

	moved := func() *dynamicShadowTrace {
		tr := &dynamicShadowTrace{
			rows:   []planeshadow.RowFact{{Table: "dynamic_policies", PolicyID: "p", UpdatedAt: "x", Ran: true}},
			index:  map[string]int{"p": 0},
			fields: map[string]any{},
		}
		tr.noteField("risk_score", 0.0)
		tr.noteField("risk_score", 50.0)
		return tr
	}
	req := OrchestratorRequest{ShadowPlane: plane}

	before := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane))
	moved().emit(context.Background(), req, "org-not-in-the-window", nil,
		&PolicyEvaluationResult{Allowed: true})
	if got := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane)); got != before {
		t.Fatalf("an organization that is NOT in the window moved the not_comparable counter "+
			"(%v -> %v). Every modify_risk evaluation for every non-participating tenant "+
			"would accumulate there forever, in the series an operator reads as the "+
			"window's denominator.", before, got)
	}

	// ANTI-VACUITY: the SAME input for a PARTICIPATING organization must still
	// be counted, or this test would pass for a change that stopped counting
	// anything at all - which is the opposite defect and just as blinding.
	mid := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane))
	moved().emit(context.Background(), req, "org-shadowing", nil,
		&PolicyEvaluationResult{Allowed: true})
	if got := promtestutil.ToFloat64(planeshadow.NotComparableCounter(plane)); got <= mid {
		t.Fatalf("a PARTICIPATING organization's not-comparable observation was not counted "+
			"(%v -> %v); the gate above is refusing everything rather than refusing "+
			"non-participants", mid, got)
	}
}

// TestAMalformedPlaneIsRefusedEvenWhenAFieldAlsoMoved pins the ORDER of emit's
// two guards (R3 round 2, finding 5's side effect).
//
// The movedFields branch used to run first, so a call site that named NO plane
// - the likely new-site mistake, since ShadowPlane is json:"-" and its zero
// value is the empty plane - was reported as `not_comparable` whenever the
// request also happened to use modify_risk. That reads as ordinary operation. A
// malformed call site is a DEFECT and must be reported as one on every request,
// not on the subset that avoids an unrelated branch.
func TestAMalformedPlaneIsRefusedEvenWhenAFieldAlsoMoved(t *testing.T) {
	// Reads two counters, so no workers - see shadowTestObserverWithWorkers.
	shadowTestObserverWithWorkers(t, 0)

	beforeRefused := promtestutil.ToFloat64(planeshadow.RefusedCounter(""))
	beforeNC := promtestutil.ToFloat64(planeshadow.NotComparableCounter(""))

	tr := &dynamicShadowTrace{
		rows:   []planeshadow.RowFact{{Table: "dynamic_policies", PolicyID: "p", UpdatedAt: "x", Ran: true}},
		index:  map[string]int{"p": 0},
		fields: map[string]any{},
	}
	tr.noteField("risk_score", 0.0)
	tr.noteField("risk_score", 50.0)

	// No plane AND a moved field: both guards would fire, and the defect must win.
	tr.emit(context.Background(), OrchestratorRequest{}, "org", nil,
		&PolicyEvaluationResult{Allowed: true})

	if got := promtestutil.ToFloat64(planeshadow.RefusedCounter("")); got <= beforeRefused {
		t.Fatalf("a call site that named NO plane was not counted as refused (%v -> %v); "+
			"a malformed site must be reported as a defect on every request", beforeRefused, got)
	}
	if got := promtestutil.ToFloat64(planeshadow.NotComparableCounter("")); got != beforeNC {
		t.Fatalf("the malformed call site was ALSO counted not-comparable (%v -> %v), which "+
			"is the ordinary-operation disposition; a reader would see a plane quietly "+
			"contributing nothing rather than a site to fix", beforeNC, got)
	}
}
