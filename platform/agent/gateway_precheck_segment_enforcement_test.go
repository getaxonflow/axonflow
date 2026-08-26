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
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/indonesia"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #3312 (ADR-060 Slice 3, #18): handlePolicyPreCheck now resolves the
// caller's governance-segment set and passes it into the shared engine
// instead of the hardcoded Segments: nil that #3266 left as a deliberate
// restriction-only deferral. These tests prove real enforcement: a segment
// MEMBER is blocked by a segment-scoped policy, a NON-member is not, a
// resolution FAILURE denies fail-closed and is audited, and a nil
// resolver / no-identity case proceeds org-only WITHOUT suppressing a
// non-segment-scoped (org-tier) policy. Mirrors
// run_shared_engine_segment_gate_test.go's Phase-1 coverage for
// clientRequestHandler; the live-stack proof is
// runtime-e2e/3312_gateway_segment_enforcement/.

// orgTierControlPolicyRow appends an ENABLED tenant-tier policy row with
// segment_id = NULL — an org-wide control policy that must enforce
// regardless of the caller's segment membership. Used to prove the segment
// gate is restriction-only: it must never suppress a non-segment-scoped
// policy for a non-member (the R3 "over-enforcement regression" hunt item).
func orgTierControlPolicyRow(rows *sqlmock.Rows, id, policyID, tenantID, category, pattern, severity, phase, actionRequest string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		id, policyID, "Test policy "+policyID, category, "tenant", pattern, severity,
		nil, phase, actionRequest, nil,
		true, priority, tenantID, nil, []byte(`{}`),
		time.Now().UTC(),
	)
}

// installSharedEngineWithSegmentAndOrgPolicy seeds BOTH a segment-scoped
// BLOCK policy (segPattern, gated to segmentID) and an org-tier
// (segment_id IS NULL) BLOCK control policy (orgPattern) on every load.
func installSharedEngineWithSegmentAndOrgPolicy(t *testing.T, segmentID, tenantID, segPattern, orgPattern string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)

	for i := 0; i < 8; i++ {
		rows := policytest.SegmentScopedPolicyRow(sqlmock.NewRows(policytest.LoaderCols()),
			"seg-policy-1", "seg_finance_ledger_block", tenantID, segmentID,
			"compliance-rbi", segPattern, "critical", "request", "block", 100)
		rows = orgTierControlPolicyRow(rows,
			"org-policy-1", "org_control_block", tenantID,
			"compliance-rbi", orgPattern, "critical", "request", "block", 90)
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

// setupGatewaySegmentPreCheckTest wires DEPLOYMENT_MODE=enterprise (so a real
// org/email pair can be asserted from a JWT rather than the community
// synthetic user), a signed-JWT-capable jwtSecret, a sqlmock usageDB for the
// canonical audit row, and nils out the optional DB-backed services so the
// only DB traffic is the policy-engine load (installed separately per test)
// and the canonical audit_logs write.
func setupGatewaySegmentPreCheckTest(t *testing.T) (sqlmock.Sqlmock, func()) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)

	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}

	origUsageDB := usageDB
	origAuthDB := authDB
	origCB := circuitBreakerInstance
	origCost := costService
	origIndo := indonesiaPIIDetector

	usageDB = mockDB
	authDB = nil // gateway_contexts satellite write no-ops
	circuitBreakerInstance = nil
	costService = nil
	indonesiaPIIDetector = indonesia.NewIndonesiaPIIDetector(indonesia.DefaultIndonesiaPIIDetectorConfig())
	ResetDetectionConfigCache()

	return mock, func() {
		jwtSecret = origSecret
		usageDB = origUsageDB
		authDB = origAuthDB
		circuitBreakerInstance = origCB
		costService = origCost
		indonesiaPIIDetector = origIndo
		mockDB.Close()
		ResetDetectionConfigCache()
	}
}

// doGatewayPreCheckSegmentRequest signs a JWT carrying tenantID/orgID/email,
// stamps the auth context the way apiAuthMiddleware would for an Enterprise
// caller, and drives handlePolicyPreCheck directly.
func doGatewayPreCheckSegmentRequest(t *testing.T, tenantID, orgID, email, query string) *httptest.ResponseRecorder {
	t.Helper()
	token := generateTestJWTWithOrgEmail(1, tenantID, orgID, email, []string{"query", "llm"}, "developer")
	body, _ := json.Marshal(PreCheckRequest{ClientID: "seg-gw-client", Query: query, UserToken: token})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "seg-gw-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, tenantID)
	ctx = context.WithValue(ctx, ContextKeyOrgID, orgID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)
	return rr
}

// TestHandlePolicyPreCheck_SegmentMember_PolicyEnforced is the headline
// #3312 proof: a member of the policy's segment is BLOCKED by the gateway
// pre-check — before this fix, Segments: nil excluded this row for every
// caller including a member, so a finance-segment member blocked on
// /api/request could re-route the identical query through the gateway
// pre-check unblocked.
func TestHandlePolicyPreCheck_SegmentMember_PolicyEnforced(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()

	const tenantID, orgID, email = "seg-gw-mem-tenant", "seg-gw-mem-org", "carol@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, "confidential_ledger", "ZZ_ORG_CONTROL_NEVER_MATCHES_ZZ")

	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	rr := doGatewayPreCheckSegmentRequest(t, tenantID, orgID, email, "please read the confidential_ledger for Q3")

	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Approved {
		t.Fatalf("#3312: expected a segment MEMBER to be blocked by the segment-scoped policy, got approved=true response=%+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet audit expectations: %v", err)
	}
}

// TestHandlePolicyPreCheck_SegmentNonMember_NotBlocked is the #3266
// restriction-only regression proof carried into #3312: a caller who
// resolves to a DIFFERENT segment must NOT be blocked by the segment-scoped
// policy.
func TestHandlePolicyPreCheck_SegmentNonMember_NotBlocked(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()

	const tenantID, orgID, email = "seg-gw-nonmem-tenant", "seg-gw-nonmem-org", "dave@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, "confidential_ledger", "ZZ_ORG_CONTROL_NEVER_MATCHES_ZZ")

	// Caller resolves to segment "engineering" — NOT a member of "finance".
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "engineering", DisplayName: "Engineering"}},
	}}
	withFleetSegmentResolver(t, fake)

	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	rr := doGatewayPreCheckSegmentRequest(t, tenantID, orgID, email, "please read the confidential_ledger for Q3")

	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Approved {
		t.Fatalf("#3266/#3312: expected a non-member NOT to be blocked by a segment-scoped policy outside their segment, got response=%+v", resp)
	}
	for _, p := range resp.Policies {
		if p == "seg_finance_ledger_block" {
			t.Fatalf("segment-scoped policy leaked into a non-member's triggered policies: %+v", resp.Policies)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet audit expectations: %v", err)
	}
}

// TestHandlePolicyPreCheck_SegmentResolutionError_FailsClosedAndAudited pins
// the #3293 locked invariant on THIS surface: a genuine resolver error must
// deny the WHOLE request before the shared engine ever runs, and that deny
// must be observable via the canonical audit_logs row (not merely a silent
// fail-closed). installCanarySharedEngine (run_shared_engine_segment_gate_test.go)
// has ZERO query expectations registered — if Phase evaluation ran anyway it
// would hit an unexpected-query error, so reaching a clean 200-with-decode
// response here proves the deny happened at the resolution site.
func TestHandlePolicyPreCheck_SegmentResolutionError_FailsClosedAndAudited(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()

	installCanarySharedEngine(t)

	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	const tenantID, orgID, email = "seg-gw-fc-tenant", "seg-gw-fc-org", "erin@corp.example"
	rr := doGatewayPreCheckSegmentRequest(t, tenantID, orgID, email, "hello, totally benign query")

	var resp PreCheckResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Approved {
		t.Fatalf("#3293: a segment-resolution failure must deny the whole request, got approved=true response=%+v", resp)
	}
	const wantReason = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"
	if resp.BlockReason != wantReason {
		t.Fatalf("BlockReason = %q, want the resolution-site reason %q — a different reason means the deny came from somewhere else (e.g. the canary engine failing closed on its own), meaning the failure reached the engine as a nil Segments set instead of being denied at the source",
			resp.BlockReason, wantReason)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected the segment resolver to be called exactly once, got %d", fake.callCount())
	}
	// The audit row IS the observability requirement (Real-World-Path clause):
	// the fail-closed deny must be visible on the canonical audit_logs surface,
	// not just enforced silently.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("fail-closed deny did not emit the canonical audit_logs row: %v", err)
	}
}

// TestHandlePolicyPreCheck_NilResolver_OrgOnlyDoesNotSuppressOrgTierPolicy
// covers the nil-resolver / no-SCIM-configured case: resolution must
// legitimately proceed org-only (never a failure), the segment-scoped
// policy must NOT enforce (no resolved segments to match against), and —
// the over-enforcement regression R3 is told to hunt for — a
// NON-segment-scoped (org-tier, segment_id IS NULL) policy must still
// enforce normally. Segment gating is restriction-only; it must never
// suppress an org-tier policy for anyone.
func TestHandlePolicyPreCheck_NilResolver_OrgOnlyDoesNotSuppressOrgTierPolicy(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()
	ResetFleetSegmentResolverForTest()

	const tenantID, orgID, email = "seg-gw-orgonly-tenant", "seg-gw-orgonly-org", "frank@corp.example"
	installSharedEngineWithSegmentAndOrgPolicy(t, "finance", tenantID, "confidential_ledger", "org_wide_secret")

	t.Run("segment-scoped policy does not enforce (no resolver)", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
		rr := doGatewayPreCheckSegmentRequest(t, tenantID, orgID, email, "please read the confidential_ledger for Q3")
		var resp PreCheckResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if !resp.Approved {
			t.Fatalf("expected org-only (no resolver) NOT to enforce a segment-scoped policy, got response=%+v", resp)
		}
	})

	t.Run("org-tier control policy still enforces", func(t *testing.T) {
		mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))
		rr := doGatewayPreCheckSegmentRequest(t, tenantID, orgID, email, "this query contains org_wide_secret data")
		var resp PreCheckResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		if resp.Approved {
			t.Fatalf("over-enforcement regression: a non-segment-scoped org-tier policy must still enforce when Segments is nil, got approved=true response=%+v", resp)
		}
	})

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet audit expectations: %v", err)
	}
}

// TestHandlePolicyPreCheck_IdentityAbsent_MalformedToken is the mandatory
// Real-World-Path unhappy-path case: an Enterprise-mode caller presenting a
// malformed/absent user token must be refused, and the refusal must be
// OBSERVABLE (the canonical audit_logs row), not merely a silent deny —
// mirrors TestGatewayPreCheck_InvalidUserTokenEmitsCanonicalAuditRow
// (#2642) but asserted here as part of the #3312 segment-enforcement
// surface's own coverage.
func TestHandlePolicyPreCheck_IdentityAbsent_MalformedToken(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()

	expectGatewayAuditRow(mock, gatewayAuditBlocked)

	body, _ := json.Marshal(PreCheckRequest{ClientID: "seg-gw-badtoken-client", Query: "hello", UserToken: "not-a-valid-jwt"})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "seg-gw-badtoken-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "seg-gw-badtoken-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "seg-gw-badtoken-org")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)

	if rr.Code == http.StatusOK {
		t.Fatalf("expected a non-200 refusal for a malformed user token, got %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("malformed-token refusal must be observable via the canonical audit_logs row: %v", err)
	}
}

// TestHandlePolicyPreCheck_SegmentResolution_UsesJWTOrgID_NotContextOrg is
// the R3 round-2 LOW-6 guard: every OTHER test in this file sets the JWT's
// org_id claim and the auth-context org to the SAME value (both ultimately
// derived from the same tenantID/orgID params), so a future accidental
// swap from user.OrgID (the validated JWT claim
// resolveUserSegments(ctx, user.OrgID, user.Email) actually resolves
// against — matching run.go's clientRequestHandler and the
// EvalOptions.OrganizationID scoping two lines below in
// gateway_handlers.go) to client.OrgID (the auth-context/license org — see
// db_auth.go's validateViaOrganizations) would be COMPLETELY SILENT to
// every other test here. That swap would let a caller select which org's
// SCIM directory their membership resolves from — the same class of defect
// as the B-1 finding that dropped this PR's OpenAI-compat half. This test
// sets the two orgs to DIFFERENT values and pins resolution to the
// JWT-derived one specifically. Reuses orgCapturingSegmentResolver
// (run_policy_test_org_binding_test.go, the #3255 policyTestHandler
// counterpart of this exact same org-binding contract) rather than a
// second copy of the same double.
func TestHandlePolicyPreCheck_SegmentResolution_UsesJWTOrgID_NotContextOrg(t *testing.T) {
	mock, cleanup := setupGatewaySegmentPreCheckTest(t)
	defer cleanup()

	const (
		contextOrgID = "seg-gw-context-org-should-be-ignored"
		jwtOrgID     = "seg-gw-jwt-org-should-be-used"
		tenantID     = "seg-gw-orgmismatch-tenant"
		email        = "orgmismatch@corp.example"
	)

	// Phase 1 (shared engine) does not need to matter for this test — a
	// zero-expectation canary means if resolveUserSegments is EVER
	// reached with a segment set (regardless of which org it came from),
	// EvaluateRequest still runs against it; the assertions below are on
	// the resolver call itself, not on the final HTTP verdict.
	installCanarySharedEngine(t)

	capture := &orgCapturingSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, capture)

	mock.ExpectExec("INSERT INTO audit_logs").WillReturnResult(sqlmock.NewResult(0, 1))

	token := generateTestJWTWithOrgEmail(1, tenantID, jwtOrgID, email, []string{"query", "llm"}, "developer")
	body, _ := json.Marshal(PreCheckRequest{ClientID: "seg-gw-orgmismatch-client", Query: "hello, totally benign query", UserToken: token})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "seg-gw-orgmismatch-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, tenantID)
	// Deliberately DIFFERENT from the JWT's org_id claim above.
	ctx = context.WithValue(ctx, ContextKeyOrgID, contextOrgID)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)

	orgs := capture.capturedOrgs()
	if len(orgs) != 1 {
		t.Fatalf("expected the segment resolver to be called exactly once, got %d calls: %v", len(orgs), orgs)
	}
	if orgs[0] != jwtOrgID {
		t.Fatalf("resolveUserSegments resolved against org %q, want the JWT-derived user.OrgID %q (NOT the context/license org %q) — a silent swap to client.OrgID would let a caller select which org's SCIM directory their membership resolves from",
			orgs[0], jwtOrgID, contextOrgID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet audit expectations: %v", err)
	}
}
