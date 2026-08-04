// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"math/rand"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// ADR-060 (#2989 P3, issue #3051) Decision 1 combiner tests — the
// additive, restriction-only combiner ("segment can only tighten, never
// loosen") is the security-critical core of this phase and is required to
// be property-tested (DoD): (a) adding a segment never loosens any
// category's outcome, and (b) non-segment orgs are byte-identical to
// pre-P3 behavior. These tests operate directly on the pure combiner
// functions (evaluateFirstMatch / evaluateStrictestMatch /
// combineTierAndSegmentResults / splitBySegment), independent of the
// database — the DB-facing selection contract (WHERE segment_id ...) is
// covered separately by the real-Postgres GetEffective tests and the
// runtime-e2e harness.

// newTestEngine returns a TierAwarePolicyEngine usable for direct calls to
// its unexported evaluation methods (getCompiledPattern, evaluateFirstMatch,
// evaluateStrictestMatch) without ever touching the database — those
// methods only need the engine's in-memory pattern cache.
func newTestEngine(t *testing.T) *TierAwarePolicyEngine {
	t.Helper()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewTierAwarePolicyEngine(db, nil)
}

// matchPattern / noMatchPattern are fixed regex fixtures: matchPattern
// matches any non-empty input, noMatchPattern matches nothing the property
// test's fixed input string could ever contain.
const (
	testInput      = "the quick brown fox"
	matchPattern   = `.*`
	noMatchPattern = `zzz_never_present_in_test_input_zzz`
)

func segPolicy(id, action string, matches bool, enabled bool) EffectiveStaticPolicy {
	pattern := noMatchPattern
	if matches {
		pattern = matchPattern
	}
	sid := "seg-x"
	return EffectiveStaticPolicy{
		StaticPolicy: StaticPolicy{
			PolicyID:  id,
			Category:  "pii-global",
			Tier:      TierTenant,
			Pattern:   pattern,
			Action:    action,
			Enabled:   enabled,
			Severity:  "high",
			SegmentID: &sid,
		},
	}
}

func tierPolicyFixture(id, action, tier string, matches bool, enabled bool) EffectiveStaticPolicy {
	pattern := noMatchPattern
	if matches {
		pattern = matchPattern
	}
	return EffectiveStaticPolicy{
		StaticPolicy: StaticPolicy{
			PolicyID: id,
			Category: "pii-global",
			Tier:     PolicyTier(tier),
			Pattern:  pattern,
			Action:   action,
			Enabled:  enabled,
			Severity: "high",
		},
	}
}

// --- Direct combiner unit tests ---

func TestCombineTierAndSegmentResults_NoSegmentMatch_ReturnsTierVerbatim(t *testing.T) {
	tier := &PolicyEvaluationResult{Matched: true, PolicyID: "t1", Action: "warn"}
	seg := &PolicyEvaluationResult{Matched: false}
	got := combineTierAndSegmentResults(tier, seg)
	if got != tier {
		t.Fatalf("expected the exact tier result pointer back (byte-identical), got %+v", got)
	}
}

func TestCombineTierAndSegmentResults_NoTierMatch_SegmentAlone(t *testing.T) {
	tier := &PolicyEvaluationResult{Matched: false}
	seg := &PolicyEvaluationResult{Matched: true, PolicyID: "s1", Action: "block"}
	got := combineTierAndSegmentResults(tier, seg)
	if got != seg {
		t.Fatalf("expected the segment result alone when tier has no match, got %+v", got)
	}
}

func TestCombineTierAndSegmentResults_SegmentStricterWins(t *testing.T) {
	tier := &PolicyEvaluationResult{Matched: true, PolicyID: "t1", Action: "warn"}
	seg := &PolicyEvaluationResult{Matched: true, PolicyID: "s1", Action: "block"}
	got := combineTierAndSegmentResults(tier, seg)
	if got != seg || got.Action != "block" {
		t.Fatalf("segment (block) must win over tier (warn), got %+v", got)
	}
}

func TestCombineTierAndSegmentResults_SegmentNeverLoosens(t *testing.T) {
	// Tier says block; segment (independently) only says warn. The combined
	// outcome must remain block — a weaker segment policy must never
	// override a stronger tier result.
	tier := &PolicyEvaluationResult{Matched: true, PolicyID: "t1", Action: "block"}
	seg := &PolicyEvaluationResult{Matched: true, PolicyID: "s1", Action: "warn"}
	got := combineTierAndSegmentResults(tier, seg)
	if got.Action != "block" {
		t.Fatalf("a weaker segment match must never loosen a stronger tier result: got action=%s", got.Action)
	}
}

func TestCombineTierAndSegmentResults_Tie_PrefersTier(t *testing.T) {
	tier := &PolicyEvaluationResult{Matched: true, PolicyID: "t1", Action: "redact"}
	seg := &PolicyEvaluationResult{Matched: true, PolicyID: "s1", Action: "redact"}
	got := combineTierAndSegmentResults(tier, seg)
	if got != tier {
		t.Fatalf("a tie must deterministically prefer the tier result, got %+v", got)
	}
}

func TestCombineTierAndSegmentResults_BothNilOrUnmatched(t *testing.T) {
	got := combineTierAndSegmentResults(&PolicyEvaluationResult{Matched: false}, &PolicyEvaluationResult{Matched: false})
	if got.Matched {
		t.Fatalf("expected no match, got %+v", got)
	}
}

// --- splitBySegment ---

func TestSplitBySegment(t *testing.T) {
	sid := "finance"
	policies := []EffectiveStaticPolicy{
		{StaticPolicy: StaticPolicy{PolicyID: "tier-1"}},
		{StaticPolicy: StaticPolicy{PolicyID: "seg-1", SegmentID: &sid}},
		{StaticPolicy: StaticPolicy{PolicyID: "tier-2"}},
		{StaticPolicy: StaticPolicy{PolicyID: "seg-2", SegmentID: &sid}},
	}
	tierP, segP := splitBySegment(policies)
	if len(tierP) != 2 || tierP[0].PolicyID != "tier-1" || tierP[1].PolicyID != "tier-2" {
		t.Fatalf("tier split wrong: %+v", tierP)
	}
	if len(segP) != 2 || segP[0].PolicyID != "seg-1" || segP[1].PolicyID != "seg-2" {
		t.Fatalf("segment split wrong: %+v", segP)
	}
}

func TestSplitBySegment_EmptySegmentIDStringTreatedAsTier(t *testing.T) {
	empty := ""
	policies := []EffectiveStaticPolicy{
		{StaticPolicy: StaticPolicy{PolicyID: "p1", SegmentID: &empty}},
	}
	tierP, segP := splitBySegment(policies)
	if len(tierP) != 1 || len(segP) != 0 {
		t.Fatalf("an empty-string SegmentID must be treated as tier-scoped, got tier=%d seg=%d", len(tierP), len(segP))
	}
}

// --- normalizeSegmentIDs ---

func TestNormalizeSegmentIDs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, nil},
		{"dedupe+sort", []string{"b", "a", "b"}, []string{"a", "b"}},
		{"drops empty strings", []string{"b", "", "a"}, []string{"a", "b"}},
		{"all empty collapses to nil", []string{"", ""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSegmentIDs(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("normalizeSegmentIDs(%v) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("normalizeSegmentIDs(%v) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

// --- Property tests (DoD gate) ---

// TestProperty_AddingSegmentNeverLoosens is THE required DoD property test:
// for any randomized tier-policy set and any randomized segment-policy set,
// combining them can never produce an outcome LESS restrictive than the
// tier-only outcome. Runs many randomized trials with a fixed seed for
// reproducibility.
func TestProperty_AddingSegmentNeverLoosens(t *testing.T) {
	engine := newTestEngine(t)
	actions := []string{"log", "warn", "redact", "require_approval", "block"}
	rng := rand.New(rand.NewSource(42))

	for trial := 0; trial < 2000; trial++ {
		numTier := rng.Intn(4)
		numSeg := rng.Intn(4)

		var tierPolicies, segPolicies []EffectiveStaticPolicy
		for i := 0; i < numTier; i++ {
			action := actions[rng.Intn(len(actions))]
			matches := rng.Intn(2) == 0
			enabled := rng.Intn(10) != 0 // mostly enabled
			tierPolicies = append(tierPolicies, tierPolicyFixture("t", action, "tenant", matches, enabled))
		}
		for i := 0; i < numSeg; i++ {
			action := actions[rng.Intn(len(actions))]
			matches := rng.Intn(2) == 0
			enabled := rng.Intn(10) != 0
			segPolicies = append(segPolicies, segPolicy("s", action, matches, enabled))
		}

		tierOnly := engine.evaluateFirstMatch(tierPolicies, testInput)
		segResult := engine.evaluateStrictestMatch(segPolicies, testInput)
		combined := combineTierAndSegmentResults(tierOnly, segResult)

		tierRestrictiveness := ActionRestrictiveness(OverrideAction(tierOnly.Action))
		combinedRestrictiveness := ActionRestrictiveness(OverrideAction(combined.Action))

		if combinedRestrictiveness < tierRestrictiveness {
			t.Fatalf("trial %d: combined result is LESS restrictive than tier-only — a segment loosened the outcome. tierOnly=%+v combined=%+v",
				trial, tierOnly, combined)
		}

		// Property (b): when there are no MATCHING segment policies, the
		// combined result must be byte-identical (same pointer) to the
		// tier-only result.
		if !segResult.Matched && combined != tierOnly {
			t.Fatalf("trial %d: no segment match but combined result is not byte-identical to tier-only: tierOnly=%+v combined=%+v",
				trial, tierOnly, combined)
		}
	}
}

// TestProperty_NonSegmentOrgByteIdentical is the second required DoD
// property: an org with ZERO segment-scoped policies must see EXACTLY the
// pre-P3 result regardless of what segment set is (incorrectly, or
// correctly) passed through — because GetEffectivePolicies never returns
// segment-scoped rows for such an org in the first place, splitBySegment's
// segment sublist is always empty, so the combiner is a structural no-op.
// This test simulates that shape directly: an all-tier policy list run
// through the full EvaluatePolicy pipeline (evaluateFirstMatch +
// evaluateStrictestMatch-of-nothing + combine) must equal the single-pass
// legacy walk exactly.
func TestProperty_NonSegmentOrgByteIdentical(t *testing.T) {
	engine := newTestEngine(t)
	actions := []string{"log", "warn", "redact", "require_approval", "block"}
	rng := rand.New(rand.NewSource(7))

	for trial := 0; trial < 500; trial++ {
		numTier := 1 + rng.Intn(5)
		var tierPolicies []EffectiveStaticPolicy
		for i := 0; i < numTier; i++ {
			action := actions[rng.Intn(len(actions))]
			matches := rng.Intn(2) == 0
			tierPolicies = append(tierPolicies, tierPolicyFixture("t", action, "tenant", matches, true))
		}

		// Simulate GetEffectivePolicies returning ONLY tier rows (the
		// zero-segment-scoped-policies shape) and split it exactly like
		// EvaluatePolicy does.
		splitTier, splitSeg := splitBySegment(tierPolicies)
		if len(splitSeg) != 0 {
			t.Fatalf("trial %d: an all-tier input must split with zero segment policies, got %d", trial, len(splitSeg))
		}

		legacy := engine.evaluateFirstMatch(tierPolicies, testInput)
		viaPipeline := combineTierAndSegmentResults(
			engine.evaluateFirstMatch(splitTier, testInput),
			engine.evaluateStrictestMatch(splitSeg, testInput),
		)

		if legacy.Matched != viaPipeline.Matched || legacy.Action != viaPipeline.Action || legacy.PolicyID != viaPipeline.PolicyID {
			t.Fatalf("trial %d: non-segment-org result diverged from legacy: legacy=%+v via=%+v", trial, legacy, viaPipeline)
		}
	}
}

// TestEvaluateStrictestMatch_IgnoresOverrideFields_DefenseInDepth pins the
// belt-and-suspenders guarantee described on evaluateStrictestMatch: even if
// a segment-scoped EffectiveStaticPolicy somehow carries HasOverride=true /
// OverrideEnabled=false (which GetEffective should never produce, but a
// defect elsewhere might), the engine must still use the RAW action/enabled
// state, never the Effective* override-aware accessors — an override must
// never be able to silently disable, or downgrade, a segment policy.
func TestEvaluateStrictestMatch_IgnoresOverrideFields_DefenseInDepth(t *testing.T) {
	engine := newTestEngine(t)
	sid := "finance"
	disabledOverride := false
	weakerAction := ActionLog

	policy := EffectiveStaticPolicy{
		StaticPolicy: StaticPolicy{
			PolicyID:  "seg-block",
			Category:  "pii-global",
			Tier:      TierTenant,
			Pattern:   matchPattern,
			Action:    "block",
			Enabled:   true,
			Severity:  "critical",
			SegmentID: &sid,
		},
		// A defect elsewhere hypothetically leaves override fields set on a
		// segment row: this must have ZERO effect on the outcome.
		HasOverride:     true,
		OverrideAction:  &weakerAction,
		OverrideEnabled: &disabledOverride,
	}

	result := engine.evaluateStrictestMatch([]EffectiveStaticPolicy{policy}, testInput)
	if !result.Matched {
		t.Fatal("segment policy must still match — an override must never be able to silently disable it")
	}
	if result.Action != "block" {
		t.Fatalf("segment policy action must be the RAW action (block), got %q — override leaked through", result.Action)
	}
}
