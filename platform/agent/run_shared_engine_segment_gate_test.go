// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #3266 end-to-end tests for clientRequestHandler's Phase 1 (the shared
// UnifiedPolicyEngine, run.go): a segment-scoped static_policies row must
// block a MEMBER of its segment and must NOT block a NON-member, closing the
// cross-segment enforcement leak the shared engine had (it never threaded
// EvalOptions.Segments before this fix). Complements
// run_segment_policy_test.go, which covers the same member/non-member
// contract for Phase 2 (the tier-aware engine) — this file exercises Phase 1
// specifically, reusing that file's segmentPolicyTestSetup/
// doSegmentPolicyRequest scaffolding. The live-stack proof lives in
// runtime-e2e/3266_shared_engine_segment_gate/.

// installSharedEngineWithSegmentScopedPolicy swaps the global shared-policy
// engine for one backed by sqlmock that serves ONE segment-scoped BLOCK
// policy (SegmentID = segmentID, matching pattern literally) plus the
// mandatory system-tier row (#3048 — a load with zero system-tier policies
// fails closed), on every load.
func installSharedEngineWithSegmentScopedPolicy(t *testing.T, segmentID, tenantID, pattern string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	// Category compliance-rbi: it is in the Phase-1 Categories whitelist
	// (proxyPolicyCategories, run.go) and — unlike security-sqli / pii /
	// sensitive-data / dangerous — is NOT rewritten by
	// ModeDetectionConfig.BuildActionOverrides, so the seeded "block" action
	// survives the handler's detection-posture overrides (mirrors
	// seedGlobalEngineWithMarkerPolicy in gateway_precheck_no_data_on_block_test.go).
	for i := 0; i < 8; i++ { // headroom: two scoped passes per load (#3048)
		rows := policytest.SegmentScopedPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
			"seg-policy-1", "seg_finance_ledger_block", tenantID, segmentID,
			"compliance-rbi", pattern, "critical", "request", "block", 100)
		rows = policytest.SystemPolicyRow(rows,
			"sys-never-matches", "sys_test_never_matches",
			"security-sqli", "ZZ_NEVER_MATCHES_ZZ", "low", "request", "block", 1)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 8)

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

// TestClientRequestHandler_Phase1SegmentGate_MemberBlocked proves a caller
// who IS a member of the policy's segment is blocked by Phase 1 (the shared
// engine) alone — Phase 2 (tier-aware) never runs because Phase 1 already
// blocked, so tierDB has zero expectations registered.
func TestClientRequestHandler_Phase1SegmentGate_MemberBlocked(t *testing.T) {
	tierDB, tierMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer tierDB.Close()

	tenantID, orgID, email := "seg-p1-mem-tenant", "seg-p1-mem-org", "carol@corp.example"
	userToken := segmentPolicyTestSetup(t, tierDB, tenantID, orgID, email)
	installSharedEngineWithSegmentScopedPolicy(t, "finance", tenantID, "confidential_ledger")

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey, "please read the confidential_ledger for Q3")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (Phase-1 shared-engine segment block), got %d: %s", w.Code, w.Body.String())
	}
	var resp ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Blocked {
		t.Fatalf("expected Blocked=true from the Phase-1 segment-scoped policy, got response=%+v", resp)
	}
	// Phase 2 (GetEffective) must NOT have been reached — Phase 1 blocked first.
	if err := tierMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("tier-aware GetEffective must not have been queried once Phase 1 blocked: %v", err)
	}
}

// TestClientRequestHandler_Phase1SegmentGate_NonMemberNotBlocked is the
// #3266 regression proof: a caller who resolves to a DIFFERENT segment must
// NOT be blocked by Phase 1's segment-scoped policy — before this fix, the
// shared engine had no segment awareness at all and would have blocked (and
// reported) this policy for every caller regardless of membership. Phase 2
// is mocked to return an empty effective set so the assertion isolates
// Phase 1's behavior.
func TestClientRequestHandler_Phase1SegmentGate_NonMemberNotBlocked(t *testing.T) {
	tierDB, tierMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer tierDB.Close()

	tenantID, orgID, email := "seg-p1-nonmem-tenant", "seg-p1-nonmem-org", "dave@corp.example"
	userToken := segmentPolicyTestSetup(t, tierDB, tenantID, orgID, email)
	installSharedEngineWithSegmentScopedPolicy(t, "finance", tenantID, "confidential_ledger")

	// Caller resolves to segment "engineering" — NOT a member of "finance".
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "engineering", DisplayName: "Engineering"}},
	}}
	withFleetSegmentResolver(t, fake)

	// Phase 1 must not block, so Phase 2 runs next: mock its GetEffective
	// call with an empty effective set (no tier-level policy matches either),
	// pinned to the resolved "engineering" segment so this is also a proof
	// the resolved segments reach the tier-aware query unchanged.
	tenantRows := sqlmock.NewRows(effectiveCols())
	globalRows := sqlmock.NewRows(effectiveCols())
	expectEffectiveTwoPass(tierMock, orgID, tenantRows, emptyOverrideRows(), globalRows, []string{"engineering"})

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey, "please read the confidential_ledger for Q3")

	if w.Code != http.StatusOK {
		t.Fatalf("#3266: expected 200 (non-member must not be blocked by the segment-scoped policy), got %d: %s", w.Code, w.Body.String())
	}
	var resp ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Blocked {
		t.Fatalf("#3266: non-member must NOT be blocked by a segment-scoped policy outside their segment, got response=%+v", resp)
	}
	if err := tierMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet tier-aware mock expectations: %v", err)
	}
}

// policyTestPreviewResponse is the subset of policyTestHandler's JSON body
// these tests assert on.
type policyTestPreviewResponse struct {
	Blocked           bool     `json:"blocked"`
	Reason            string   `json:"reason"`
	TriggeredPolicies []string `json:"triggered_policies"`
	SegmentsResolved  bool     `json:"segments_resolved"`
}

// doPolicyTestPreviewRequest drives policyTestHandler directly (it is an
// internal admin API with no client/JWT auth, unlike clientRequestHandler),
// stamping the tenant/org context the way apiAuthMiddleware does.
func doPolicyTestPreviewRequest(t *testing.T, tenantID, orgID, userEmail, query string) policyTestPreviewResponse {
	t.Helper()
	body, _ := json.Marshal(map[string]interface{}{
		"query":      query,
		"user_email": userEmail,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/policies/test", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyTenantID, tenantID)
	ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	policyTestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var resp policyTestPreviewResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// TestPolicyTestHandler_SegmentScopedPolicy_NotReportedForNonMember is the
// literal #3266 bug report (GH issue symptom 1): a segment-scoped policy's
// identifier must NOT appear in the preview's triggered_policies for a
// caller who is not a member of that segment — before this fix the shared
// engine reported it regardless of membership, disclosing the existence and
// identifier of a policy scoped to a segment the caller cannot see, even
// though the verdict was (coincidentally, via Phase 2 only) correct.
// tierAwarePolicyEngine runs on a nil DB here so Phase 2 contributes nothing
// (it errors and is skipped) — the assertion isolates Phase 1 (the shared
// engine) alone. #3293: the preview's Phase-1 is now fully converged with
// clientRequestHandler's (Segments: segmentIDs, resolved fail-closed), so
// this is real coverage again, not a deferred stub.
func TestPolicyTestHandler_SegmentScopedPolicy_NotReportedForNonMember(t *testing.T) {
	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

	const orgID = "seg-preview-nonmem-org"
	installSharedEngineWithSegmentScopedPolicy(t, "finance", orgID, "confidential_ledger")

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "engineering", DisplayName: "Engineering"}},
	}}
	withFleetSegmentResolver(t, fake)

	resp := doPolicyTestPreviewRequest(t, orgID, orgID, "nonmember@example.com",
		"please read the confidential_ledger for Q3")

	if resp.Blocked {
		t.Fatalf("#3266: non-member preview must report blocked=false, got %+v", resp)
	}
	for _, id := range resp.TriggeredPolicies {
		if id == "seg_finance_ledger_block" {
			t.Fatalf("#3266: segment-scoped policy leaked into triggered_policies for a non-member: %+v", resp.TriggeredPolicies)
		}
	}
}

// TestPolicyTestHandler_SegmentScopedPolicy_ReportedForMember is the positive
// counterpart: a member's preview reports blocked=true AND the segment-scoped
// policy's identifier in triggered_policies, so the preview's own output
// agrees with its verdict.
func TestPolicyTestHandler_SegmentScopedPolicy_ReportedForMember(t *testing.T) {
	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

	const orgID = "seg-preview-mem-org"
	installSharedEngineWithSegmentScopedPolicy(t, "finance", orgID, "confidential_ledger")

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	resp := doPolicyTestPreviewRequest(t, orgID, orgID, "member@example.com",
		"please read the confidential_ledger for Q3")

	if !resp.Blocked {
		t.Fatalf("expected a member's preview to report blocked=true, got %+v", resp)
	}
	found := false
	for _, id := range resp.TriggeredPolicies {
		if id == "seg_finance_ledger_block" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the segment-scoped policy in triggered_policies for a member, got %+v", resp.TriggeredPolicies)
	}
}

// installCanarySharedEngine swaps the global shared-policy engine for one
// backed by a sqlmock DB with ZERO registered query expectations, and
// returns it (so the caller can defer db.Close()). If clientRequestHandler's
// Phase 1 ever calls EvaluateRequest against this engine, the loader's query
// hits an unexpected-call error, and the engine fails closed with its OWN
// distinct BlockReason ("Policy engine unavailable") — DIFFERENT from the
// resolution-site deny's reason. This is the trap that makes
// TestClientRequestHandler_SegmentResolutionFailure_DeniesBeforePhase1's
// exact-string BlockReason assertion a real proof that Phase 1 never ran,
// not just an inference from the response shape.
func installCanarySharedEngine(t *testing.T) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	// Deliberately NO mockSQL.ExpectQuery(...) registered.

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	old := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(old) })
}

// TestClientRequestHandler_SegmentResolutionFailure_DeniesBeforePhase1 is the
// #3293 locked-invariant regression test: a segment-resolution FAILURE must
// be handled at the resolution SITE — before Phase 1 (the shared engine)
// ever runs — and must never be propagated downstream as a nil/empty
// Segments set for Phase 1 or Phase 2 to independently discover and act on.
//
// tierAwarePolicyEngine is nil here, so Phase 2 structurally CANNOT be the
// source of the deny (its whole block is gated on `tierAwarePolicyEngine !=
// nil`). The shared engine (Phase 1) is wired to installCanarySharedEngine's
// zero-expectation mock DB: if Phase 1 ran, it would hit an unexpected-query
// error and fail closed with BlockReason="Policy engine unavailable" — a
// DIFFERENT string from the resolution-site deny's reason. Asserting the
// EXACT resolution-site BlockReason therefore proves Phase 1 never ran, not
// merely that SOME block occurred.
func TestClientRequestHandler_SegmentResolutionFailure_DeniesBeforePhase1(t *testing.T) {
	// This DB backs segmentPolicyTestSetup's tierAwarePolicyEngine wiring,
	// but that engine is immediately replaced with nil below — Phase 2 is
	// structurally absent for this test, not merely unqueried.
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID, orgID, email := "seg-p1-fc-tenant", "seg-p1-fc-org", "erin@corp.example"
	userToken := segmentPolicyTestSetup(t, db, tenantID, orgID, email)

	// #3293: prove the deny does NOT depend on Phase 2 existing at all.
	originalTierEngine := tierAwarePolicyEngine
	tierAwarePolicyEngine = nil
	t.Cleanup(func() { tierAwarePolicyEngine = originalTierEngine })

	installCanarySharedEngine(t)

	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey, "SELECT * FROM widgets")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (fail-closed deny at the resolution site, independent of Phase 1/Phase 2), got %d: %s", w.Code, w.Body.String())
	}
	var resp ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Blocked {
		t.Fatalf("expected Blocked=true, got response=%+v", resp)
	}
	const wantReason = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"
	if resp.BlockReason != wantReason {
		t.Fatalf("#3293: BlockReason = %q, want the resolution-site reason %q — a different reason means the deny came from somewhere else (e.g. Phase 1 hitting the canary DB and failing closed on its own), which would mean the resolution failure reached the engine as a nil Segments set instead of being denied at the source",
			resp.BlockReason, wantReason)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected segment resolver to be called exactly once, got %d", fake.callCount())
	}
}

// TestPolicyTestHandler_SegmentResolutionFailure_SimulatesDenyBeforeEitherEngine
// is the preview's companion to
// TestClientRequestHandler_SegmentResolutionFailure_DeniesBeforePhase1: on
// segOK=false the preview must simulate the fail-closed deny BEFORE calling
// either engine, never handing a nil-on-failure segment set to Phase 1 or
// Phase 2 (#3293). tierAwarePolicyEngine is nil (Phase 2 structurally
// absent) and the shared engine is wired to installCanarySharedEngine's
// zero-expectation mock DB — if Phase 1 ran anyway, it would hit an
// unexpected-query error and fail closed with a DIFFERENT reason ("Policy
// engine unavailable") instead of the resolution-site simulated-deny reason
// this test pins exactly. Unlike the enforcement-path test, the expected
// HTTP status is 200 (the preview is a dry-run — it reports a simulated
// verdict, never a real HTTP error), with blocked=true in the body.
func TestPolicyTestHandler_SegmentResolutionFailure_SimulatesDenyBeforeEitherEngine(t *testing.T) {
	originalTierEngine := tierAwarePolicyEngine
	tierAwarePolicyEngine = nil
	t.Cleanup(func() { tierAwarePolicyEngine = originalTierEngine })

	installCanarySharedEngine(t)

	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	const orgID = "seg-preview-fc-org"
	resp := doPolicyTestPreviewRequest(t, orgID, orgID, "erin@corp.example", "SELECT * FROM widgets")

	if !resp.Blocked {
		t.Fatalf("#3293: expected the preview to simulate a fail-closed deny, got %+v", resp)
	}
	const wantReason = "segment resolution unavailable — a real request would be denied (fail-closed, ADR-060 #2989)"
	if resp.Reason != wantReason {
		t.Fatalf("#3293: reason = %q, want the resolution-site simulated-deny reason %q — a different reason means the deny came from somewhere else (e.g. Phase 1 hitting the canary DB and failing closed on its own), which would mean the resolution failure reached an engine as a nil Segments set instead of being simulated at the source",
			resp.Reason, wantReason)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected segment resolver to be called exactly once, got %d", fake.callCount())
	}
}

// TestPolicyTestHandler_SegmentsResolvedSignal proves the #3239 M4
// segments_resolved informational flag (Signal B), ported here as part of
// the same #3298 consolidation that already carries the fail-closed
// convergence and Phase-1 segment-awareness: it is true ONLY when
// resolution succeeded AND returned a non-empty segment set that actually
// factored into the verdict, and false for a legitimate org-only case (zero
// group memberships) — a case distinct from, and not to be confused with,
// the fail-closed DENY path (segOK=false), which is covered separately by
// TestPolicyTestHandler_SegmentResolutionFailure_SimulatesDenyBeforeEitherEngine.
func TestPolicyTestHandler_SegmentsResolvedSignal(t *testing.T) {
	t.Run("member with a non-empty resolved segment set", func(t *testing.T) {
		originalEngine := tierAwarePolicyEngine
		t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
		tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

		const orgID = "seg-resolved-mem-org"
		installSharedEngineWithSegmentScopedPolicy(t, "finance", orgID, "confidential_ledger")

		fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
		}}
		withFleetSegmentResolver(t, fake)

		resp := doPolicyTestPreviewRequest(t, orgID, orgID, "member@example.com", "a totally benign query")

		if !resp.SegmentsResolved {
			t.Fatalf("expected segments_resolved=true for a member with a non-empty resolved segment set, got %+v", resp)
		}
	})

	t.Run("org-only: zero group memberships", func(t *testing.T) {
		originalEngine := tierAwarePolicyEngine
		t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
		tierAwarePolicyEngine = NewTierAwarePolicyEngine(nil, nil)

		const orgID = "seg-resolved-orgonly-org"
		installSharedEngineWithSegmentScopedPolicy(t, "finance", orgID, "confidential_ledger")

		// Zero-value fakeSegmentResolver: resolution SUCCEEDS (no err) with an
		// empty Segments slice — the "legitimate org-only" outcome per
		// resolveUserSegments's contract, distinct from a resolver error.
		fake := &fakeSegmentResolver{}
		withFleetSegmentResolver(t, fake)

		resp := doPolicyTestPreviewRequest(t, orgID, orgID, "orgonly@example.com", "a totally benign query")

		if resp.SegmentsResolved {
			t.Fatalf("expected segments_resolved=false for zero group memberships (org-only), got %+v", resp)
		}
		if resp.Blocked {
			t.Fatalf("sanity: org-only case must not be blocked (query does not match the non-segment-scoped system marker), got %+v", resp)
		}
	})
}
