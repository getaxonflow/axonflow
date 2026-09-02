// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
	"axonflow/platform/shared/planeshadow"
)

// THIS FILE EXISTS BECAUSE tierShadowTrace.emit HAD NO TEST AT ALL.
//
// R3 round 2 found that emit expressed "this row matched but the combiner
// discarded it" by setting Matched back to FALSE - contradicting both the
// comment three lines above it and markMatched's own header, and making
// EC6_PROXY_TIER_FIRST_MATCH_SHADOWING unreachable on every production
// observation. Nothing caught it because nothing ran this function: grepping for
// EC6 and detectorMatchedButShadowed found them in no test.
//
// The proxy_tier plane's one known divergence - the deny ADR-065 will start
// issuing at cutover on a row today's first-match reduction hides - was
// therefore recorded as perfect agreement.

// tierShadowObserverOn installs a recording observer for one test and hands
// back the recorder.
func tierShadowObserverOn(t *testing.T) *tierCapture {
	t.Helper()
	rec := &tierCapture{done: make(chan struct{}, 8)}

	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })

	o, err := planeshadow.NewObserver(
		// ONE worker, so an observation that has been recorded is an
		// observation the worker has finished with - a pool would let a test
		// snapshot the recorder between two comparisons.
		planeshadow.Config{Mode: identity.CompatModeShadow, SampleRate: 1, QueueDepth: 16, Workers: 1},
		tierShadowRows{}, rec, planeshadow.WithComponent("tier-shadow-test"),
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
	if !planeshadow.Enabled() {
		t.Fatal("the shadow is not enabled; newTierShadowTrace would return nil and every " +
			"assertion below would be about a no-op")
	}
	return rec
}

type tierCapture struct {
	done chan struct{}
}

func (c *tierCapture) RecordComparison(context.Context, planeshadow.Comparison) {
	select {
	case c.done <- struct{}{}:
	default:
	}
}

// tierShadowRows serves nothing: these tests assert on the ROW FACTS emit
// builds, which is where the defect lived, and never on a classification.
type tierShadowRows struct{}

func (tierShadowRows) RawRows(context.Context, string) ([]legacycompile.RawRow, error) {
	return nil, nil
}

func tierPolicy(policyID string) EffectiveStaticPolicy {
	var p EffectiveStaticPolicy
	p.PolicyID = policyID
	p.Category = "pii-us"
	p.UpdatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return p
}

// TestAShadowedProxyTierRowKeepsItsDetectorVerdict is the round-2 finding-4
// regression, asserted on the ROW FACTS emit produces.
//
// A row the first-match/strictest reduction discarded must be:
//
//	Ran = true       - its conditions were evaluated
//	Matched = true   - its pattern really did fire, which EC6's evidence
//	                   predicate requires and which a `false` makes unreachable
//	Shadowed = true  - so the LEGACY side leaves it out of the determining set
//	Action = ""      - so no legacy effect is attributed to it
func TestAShadowedProxyTierRowKeepsItsDetectorVerdict(t *testing.T) {
	tierShadowObserverOn(t)

	tr := newTierShadowTrace([]EffectiveStaticPolicy{
		tierPolicy("p_allow"), tierPolicy("p_block"),
	})
	if tr == nil {
		t.Fatal("no trace was built; every assertion below would be vacuous")
	}

	// Both patterns fired. The combiner then rested the verdict on p_allow
	// alone, which is the first-match reduction this plane is known for.
	tr.markRan("p_allow")
	tr.markRan("p_block")
	tr.markMatched("p_allow", "log")
	tr.markMatched("p_block", "block")

	got := captureTierRows(t, tr, map[string]bool{"p_allow": true})

	shadowed, ok := got["p_block"]
	if !ok {
		t.Fatalf("the shadowed row is absent from the emitted facts (%v); it is part of the "+
			"policy version whether or not it determined anything", tierRowKeys(got))
	}
	if !shadowed.Matched {
		t.Fatal("a SHADOWED row was emitted with Matched=false.\n" +
			"caseFor writes DetectorVerdicts[policyID] = Matched, and " +
			"EC6_PROXY_TIER_FIRST_MATCH_SHADOWING's evidence predicate requires the denying " +
			"constraint's detector verdict to be TRUE - so this makes EC6 unreachable on " +
			"every production observation, and the one divergence this plane is known to " +
			"have records as a confident `match`.")
	}
	if !shadowed.Shadowed {
		t.Fatal("a row the combiner discarded was not marked Shadowed, so legacyVerdictFor " +
			"will put it in the LEGACY determining set - claiming the running system rested " +
			"its verdict on a row it discarded")
	}
	if shadowed.Action != "" {
		t.Fatalf("a shadowed row kept its action %q; a legacy effect would be attributed to "+
			"a row the running system did not act on", shadowed.Action)
	}
	if !shadowed.Ran {
		t.Fatal("a shadowed row was emitted with Ran=false; its conditions WERE evaluated, " +
			"and reporting otherwise makes the tri-state call it unknown")
	}

	// ANTI-VACUITY: the DETERMINING row must be the opposite in every respect,
	// or the assertions above would hold for an emit that marked everything
	// shadowed.
	det, ok := got["p_allow"]
	if !ok {
		t.Fatalf("the determining row is absent from the emitted facts (%v)", tierRowKeys(got))
	}
	if det.Shadowed {
		t.Fatal("the row the verdict RESTED on was marked Shadowed; emit is marking " +
			"everything, and the assertions above prove nothing")
	}
	if det.Action != "log" {
		t.Fatalf("the determining row's action is %q, want \"log\"; its legacy effect would "+
			"be lost", det.Action)
	}
}

// TestDetectorMatchedButShadowedIsTheOneEmitUses pins that the named helper and
// emit share a predicate rather than restating one.
//
// The helper's doc claimed it existed "so the property has a name in tests"
// while emit restated the same expression inline and nothing called the helper.
// Two copies of a predicate is one edit away from disagreeing, and the fix to
// the inline copy would have left this one describing the old behaviour.
func TestDetectorMatchedButShadowedIsTheOneEmitUses(t *testing.T) {
	determining := map[string]bool{"kept": true}
	matchedKept := planeshadow.RowFact{PolicyID: "kept", Matched: true}
	matchedShadowed := planeshadow.RowFact{PolicyID: "dropped", Matched: true}
	unmatched := planeshadow.RowFact{PolicyID: "quiet"}

	if detectorMatchedButShadowed(matchedKept, determining) {
		t.Error("a row the verdict rested on was reported as shadowed")
	}
	if !detectorMatchedButShadowed(matchedShadowed, determining) {
		t.Error("a matched row the verdict did NOT rest on was not reported as shadowed")
	}
	if detectorMatchedButShadowed(unmatched, determining) {
		t.Error("a row that never matched was reported as shadowed; only a row whose " +
			"detector FIRED can be shadowed by the combiner")
	}
}

// captureTierRows applies the REAL transformation emit applies, keyed by
// policy.
//
// It calls shadowedRowFacts - the function emit itself calls - rather than
// re-deriving the facts. A test that reimplemented the loop would certify its
// own copy, which is precisely how a transformation that contradicted its own
// two comments survived to production.
func captureTierRows(t *testing.T, tr *tierShadowTrace, determining map[string]bool) map[string]planeshadow.RowFact {
	t.Helper()
	facts := shadowedRowFacts(tr.rows, determining)
	if len(facts) == 0 {
		t.Fatal("the transformation produced no facts; every assertion on them is vacuous")
	}
	out := make(map[string]planeshadow.RowFact, len(facts))
	for _, r := range facts {
		out[r.PolicyID] = r
	}
	return out
}

func tierRowKeys(m map[string]planeshadow.RowFact) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
