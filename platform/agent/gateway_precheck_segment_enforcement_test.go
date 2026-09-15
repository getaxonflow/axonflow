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

// #3312 (ADR-060 Slice 3, #18) made handlePolicyPreCheck resolve the caller's
// governance-segment set, and refuse the request when that failed. v11 retired
// it: the pre-check is decided by the anchored engine, which reads no segments,
// and a legacy static_policies row - segment-scoped or org-tier - authors no
// verdict there (PRD v11 §1.1, §1.2). What these tests prove now is that the
// handler never consults the segment resolver, and that an absent identity is
// still refused.

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
		rows := policytest.SegmentScopedPolicyRow(appendShippedGlobalRows(t, sqlmock.NewRows(policytest.LoaderCols()), nil, nil),
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

// TestHandlePolicyPreCheck_ReadsNoSegments: the pre-check is decided by the
// anchored engine, which reads no segments, so the handler never consults the
// segment resolver and a resolver that would fail changes nothing. The gate that
// stood here refused the request on a resolution failure (#3293), on behalf of
// an organization's segment-scoped static rows, which no longer decide.
func TestHandlePolicyPreCheck_ReadsNoSegments(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resolver *fakeSegmentResolver
	}{
		{"a resolver that fails", &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}},
		{"a resolver that would answer a membership", &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
			Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock, cleanup := setupGatewaySegmentPreCheckTest(t)
			defer cleanup()
			withFleetSegmentResolver(t, tc.resolver)
			expectGatewayAuditRow(mock, gatewayAuditAllowed)

			rr := doGatewayPreCheckSegmentRequest(t, "seg-gw-tenant", "seg-gw-org", "erin@corp.example", "hello, totally benign query")
			var resp PreCheckResponse
			if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if !resp.Approved || resp.Engine != decisionEngineAnchored {
				t.Fatalf("approved=%v engine=%q, want an anchored approval: %+v", resp.Approved, resp.Engine, resp)
			}
			if c := tc.resolver.callCount(); c != 0 {
				t.Fatalf("the pre-check consulted the segment resolver %d time(s); it reads no segments", c)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the approved pre-check did not write its canonical audit row: %v", err)
			}
		})
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
