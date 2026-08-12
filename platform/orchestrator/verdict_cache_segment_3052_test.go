// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3052 (ADR-060 #2989 P3b) — the DynamicPolicyEngine verdict cache
// (verdictCacheKey / generateCacheKey, #3142) must include the request's
// resolved governance-segment set. getApplicablePolicies now selects a
// DIFFERENT policy set depending on the caller's resolved segments
// (memPolicyAppliesToTenant folds segment membership into the same choke
// point that selects the tenant-scoped set), so two evaluations of the
// SAME OrchestratorRequest — same org, tenant, email, query, everything —
// can legitimately produce different verdicts if the caller resolves to
// different segments between calls. Omitting Segments from the cache key
// would let the second call be served the first call's verdict.
//
// Every test here is written so it FAILS on a version of the code with the
// Segments field (or its population in generateCacheKey) removed — see each
// test's comment for the specific failure mode it reproduces.

import (
	"context"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// segmentBlockPolicyFor returns an org-agnostic policy scoped to segmentID
// that blocks any query containing "kyc".
func segmentBlockPolicyFor(segmentID string) DynamicPolicy {
	return DynamicPolicy{
		ID:         "pol-segment-block-" + segmentID,
		Name:       "segment KYC block (" + segmentID + ")",
		Type:       "content",
		Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "kyc"}},
		Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "kyc exfiltration"}}},
		Enabled:    true,
		SegmentID:  segmentID,
		RiskLevel:  "medium",
	}
}

// segReqFor builds the SAME request shape every call in this file uses:
// only the wired segment resolver's answer differs between calls, never
// anything in the request itself.
func segReqFor(email string) OrchestratorRequest {
	return OrchestratorRequest{
		RequestType: "query",
		Query:       "export all kyc records",
		User: UserContext{
			OrgID: "org-shared",
			Email: email,
		},
	}
}

func resolverReturning(ids ...string) *fakeOrchestratorSegmentResolver {
	segs := make([]sharedidentity.Segment, len(ids))
	for i, id := range ids {
		segs[i] = sharedidentity.Segment{ID: sharedidentity.SegmentID(id)}
	}
	return &fakeOrchestratorSegmentResolver{resolved: sharedidentity.ResolvedIdentity{Segments: segs}}
}

// TestVerdictCacheKey_SegmentsAreLoadBearing is the #3142/#3052 collision
// test: the identical OrchestratorRequest, evaluated three times, resolving
// to seg-finance, then seg-engineering, then seg-finance again. A
// segment-scoped block policy targets ONLY seg-finance.
//
// If verdictCacheKey ever loses its Segments field (or generateCacheKey
// stops populating it from the resolved set), call 2 would hit the cache
// entry call 1 wrote — for a DIFFERENT, non-matching segment — and this
// test fails at the res2 assertion. Call 3 additionally proves the two
// segment sets land on genuinely DIFFERENT keys (not merely "last write
// wins"): if they collided, call 2 would have overwritten call 1's entry
// and call 3 would incorrectly come back allowed.
func TestVerdictCacheKey_SegmentsAreLoadBearing(t *testing.T) {
	e := newVerdictCacheTestEngine(t, []DynamicPolicy{segmentBlockPolicyFor("seg-finance")})
	ctx := context.Background()
	req := segReqFor("alice@example.com")

	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))
	res1 := e.EvaluateDynamicPolicies(ctx, req)
	if res1.Allowed {
		t.Fatalf("vacuity control failed: a seg-finance member was not blocked by the segment-scoped policy (result %+v)", res1)
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-engineering"))
	res2 := e.EvaluateDynamicPolicies(ctx, req)
	if !res2.Allowed {
		t.Fatal("CACHE COLLISION (#3142/#3052): a caller resolved to seg-engineering (not seg-finance) was blocked — " +
			"the verdict cache served seg-finance's cached verdict because the cache key does not distinguish the two resolved segment sets")
	}

	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))
	res3 := e.EvaluateDynamicPolicies(ctx, req)
	if res3.Allowed {
		t.Fatal("CACHE COLLISION (#3142/#3052): seg-finance's own cache entry was corrupted by the seg-engineering evaluation — " +
			"the two segment sets did not get distinct cache keys")
	}
}

// TestVerdictCacheKey_NoSegments_UnaffectedByPriorSegmentEvaluation is the
// zero-behavior-change half: an org with no segment-scoped policies must
// see byte-identical results regardless of what the caller's resolved
// segment set happens to be, INCLUDING when a differently-segmented
// evaluation of the identical request already populated the cache.
func TestVerdictCacheKey_NoSegments_UnaffectedByPriorSegmentEvaluation(t *testing.T) {
	e := newVerdictCacheTestEngine(t, []DynamicPolicy{
		{
			ID:         "pol-tier-only",
			Name:       "tier-only allow-through",
			Type:       "content",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "kyc"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Enabled:    true,
			RiskLevel:  "low",
		},
	})
	ctx := context.Background()
	req := segReqFor("alice@example.com")

	withOrchestratorSegmentResolver(t, resolverReturning("seg-finance"))
	res1 := e.EvaluateDynamicPolicies(ctx, req)

	withOrchestratorSegmentResolver(t, resolverReturning("seg-engineering"))
	res2 := e.EvaluateDynamicPolicies(ctx, req)

	if res1.Allowed != res2.Allowed {
		t.Fatalf("org with zero segment-scoped policies must be unaffected by which segment the caller resolves to: res1.Allowed=%v res2.Allowed=%v", res1.Allowed, res2.Allowed)
	}
	if !res1.Allowed || !res2.Allowed {
		t.Fatalf("vacuity control: expected both evaluations to be allowed (only a log-only tier policy matches), got res1=%+v res2=%+v", res1, res2)
	}
}

// TestGenerateCacheKey_DifferentNormalizedSegmentsProduceDifferentKeys pins
// generateCacheKey directly (the P3 `.WithArgs`-style regression shape): the
// struct's Segments field must differ for different normalized segment
// sets, and must be stable (order-insensitive) once normalizeSegmentIDs has
// run — two callers resolving to the same logical set in a different order
// must hit the SAME cache entry, never a distinct one.
func TestGenerateCacheKey_DifferentNormalizedSegmentsProduceDifferentKeys(t *testing.T) {
	e := newVerdictCacheTestEngine(t, nil)
	req := segReqFor("alice@example.com")

	keyNone := e.generateCacheKey(req, nil)
	keyFinance := e.generateCacheKey(req, normalizeSegmentIDs([]string{"seg-finance"}))
	keyEng := e.generateCacheKey(req, normalizeSegmentIDs([]string{"seg-engineering"}))

	if keyNone == keyFinance {
		t.Fatalf("no-segment key must differ from a segment-scoped key: %+v", keyNone)
	}
	if keyNone == keyEng {
		t.Fatalf("no-segment key must differ from a segment-scoped key: %+v", keyNone)
	}
	if keyFinance == keyEng {
		t.Fatalf("two different segment sets must produce different cache keys, both got %+v", keyFinance)
	}

	// Order-insensitivity: the SAME logical set, differently ordered before
	// normalization, must land on the identical key after normalization.
	keyBothA := e.generateCacheKey(req, normalizeSegmentIDs([]string{"seg-engineering", "seg-finance"}))
	keyBothB := e.generateCacheKey(req, normalizeSegmentIDs([]string{"seg-finance", "seg-engineering"}))
	if keyBothA != keyBothB {
		t.Fatalf("generateCacheKey must be order-insensitive once segments are normalized: %+v vs %+v", keyBothA, keyBothB)
	}
	if keyBothA == keyFinance || keyBothA == keyEng {
		t.Fatalf("a two-segment set must not collide with either of its single-segment subsets: %+v", keyBothA)
	}
}
