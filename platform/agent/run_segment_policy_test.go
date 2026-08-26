// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989 P3, issue #3051) end-to-end tests for clientRequestHandler:
// segment resolution promoted from observability-only to POLICY-AFFECTING on
// the agent static-policy proxy plane. Covers the two DoD-required runtime
// behaviors at the HTTP-handler level (the live-stack proof lives in
// runtime-e2e/2989_segment_policy_targeting/):
//   - fail-closed: a segment resolution ERROR denies the request outright.
//   - a segment-scoped policy can independently block a request the
//     tier-effective (org-only) evaluation would otherwise allow.

var errAssertSegmentResolutionFailed = errors.New("segment query failed (test)")

// generateTestJWTWithOrgEmail mirrors generateTestJWT (same signing
// approach, same testJWTSecret) but additionally sets the "org_id" and
// "email" claims validateUserToken reads (run.go) — generateTestJWT itself
// carries neither, so resolveUserSegments would otherwise be called
// with an empty email/an org_id that merely falls back to tenantID.
func generateTestJWTWithOrgEmail(userID interface{}, tenantID, orgID, email string, permissions []string, role string) string {
	jwtSecret = []byte(testJWTSecret)

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"user_id":     userID,
		"tenant_id":   tenantID,
		"org_id":      orgID,
		"email":       email,
		"permissions": permissions,
		"role":        role,
		"iat":         now,
		"exp":         now + 86400,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	h := hmac.New(sha256.New, []byte(testJWTSecret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature
}

// segmentPolicyTestSetup wires DEPLOYMENT_MODE=enterprise, a known client, a
// mock orchestrator (in case the request is — unexpectedly — allowed
// through), and a tierAwarePolicyEngine bound to db; returns the signed user
// token. Common scaffolding shared by both tests below.
func segmentPolicyTestSetup(t *testing.T, db *sql.DB, tenantID, orgID, email string) (userToken string) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}

	originalEngine := tierAwarePolicyEngine
	t.Cleanup(func() { tierAwarePolicyEngine = originalEngine })
	tierAwarePolicyEngine = NewTierAwarePolicyEngine(db, nil)

	mockOrch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": "should not be reached"})
	}))
	t.Cleanup(mockOrch.Close)
	oldOrchURL := orchestratorURL
	t.Cleanup(func() { orchestratorURL = oldOrchURL })
	orchestratorURL = mockOrch.URL

	testLicenseKey := generateTestLicenseKey(orgID, "Enterprise", "20351231")
	clientID := "test-client-seg-" + tenantID
	knownClients[clientID] = &ClientAuth{
		ClientID:   clientID,
		LicenseKey: testLicenseKey,
		Name:       "Segment Policy Test Client",
		TenantID:   tenantID,
		Enabled:    true,
	}
	t.Cleanup(func() { delete(knownClients, clientID) })

	return generateTestJWTWithOrgEmail(1, tenantID, orgID, email, []string{"query", "llm"}, "developer")
}

func doSegmentPolicyRequest(t *testing.T, clientID, userToken, licenseKey, query string) *httptest.ResponseRecorder {
	t.Helper()
	reqBody := ClientRequest{
		ClientID:    clientID,
		RequestType: "sql",
		Query:       query,
		UserToken:   userToken,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	setOAuth2BasicAuth(req, clientID, licenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)
	return w
}

// TestClientRequestHandler_SegmentResolutionError_FailsClosed is the DoD
// fail-closed gate: a genuine segment-resolution error must DENY the whole
// request — never silently proceed org-only — even though the tier-effective
// (segment_id IS NULL) policy set alone contains nothing that would block
// this query.
func TestClientRequestHandler_SegmentResolutionError_FailsClosed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID, orgID, email := "seg-fc-tenant", "seg-fc-org", "alice@corp.example"
	userToken := segmentPolicyTestSetup(t, db, tenantID, orgID, email)

	// GetEffective must NOT even be reached (mock has zero expectations
	// registered) — a fail-closed deny happens before EvaluatePolicy runs.
	fake := &fakeSegmentResolver{err: errAssertSegmentResolutionFailed}
	withFleetSegmentResolver(t, fake)

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey, "SELECT * FROM widgets")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (fail-closed deny), got %d: %s", w.Code, w.Body.String())
	}
	var resp ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Blocked {
		t.Fatalf("expected Blocked=true, got response=%+v", resp)
	}
	if fake.callCount() != 1 {
		t.Fatalf("expected segment resolver to be called exactly once, got %d", fake.callCount())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("GetEffective must not have been queried on a fail-closed deny: %v", err)
	}
}

// TestClientRequestHandler_SegmentOnlyPolicy_BlocksWhenTierWouldAllow proves
// a segment-scoped block policy independently blocks a request even though
// no tier (segment_id IS NULL) policy matches — the "member of segment X
// with a segment-X block policy is blocked" DoD/runtime-e2e requirement,
// exercised here at the unit level via the real HTTP handler + a mocked DB
// that simulates the SQL WHERE segment-selection outcome (GetEffective
// itself is not executed against real Postgres here — see
// TestGetEffective_SegmentScoped and the runtime-e2e harness for that leg).
func TestClientRequestHandler_SegmentOnlyPolicy_BlocksWhenTierWouldAllow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID, orgID, email := "seg-block-tenant", "seg-block-org", "bob@corp.example"
	userToken := segmentPolicyTestSetup(t, db, tenantID, orgID, email)

	// The caller resolves to segment "finance", which has a block policy on
	// "confidential_ledger". There is no tier-level (segment_id IS NULL)
	// policy matching this query at all — a pre-P3 evaluation would ALLOW.
	fake := &fakeSegmentResolver{resolved: sharedidentity.ResolvedIdentity{
		Segments: []sharedidentity.Segment{{ID: "finance", DisplayName: "Finance"}},
	}}
	withFleetSegmentResolver(t, fake)

	// #3048: GetEffective runs two scoped passes (org scope: tenant/org rows
	// + overrides; 'global' scope: system rows). EvaluatePolicy's caller
	// (clientRequestHandler) passes orgID=nil, so the pass-A GUC scope key
	// falls back to OrgIDFromContext — populated here by stampAuthContext
	// from client.OrgID, which validateClientCredentials derives from the
	// Enterprise license (generateTestLicenseKey(orgID, ...) above) — i.e.
	// scopeOrg is orgID, NOT tenantID (the two differ in this fixture).
	now := time.Now()
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"seg-policy-1", "finance_ledger_block", "Finance Ledger Block", "sensitive-data",
		"confidential_ledger", "critical",
		"Segment-scoped block on the finance ledger keyword", "block", "tenant", 50, true,
		tenantID, nil, "finance",
		"[]", "{}", 1,
		now, now, "admin", "admin",
	)
	globalRows := sqlmock.NewRows(effectiveCols())
	// No override — and none would apply to a segment row regardless.
	expectEffectiveTwoPass(mock, orgID, tenantRows, emptyOverrideRows(), globalRows, []string{"finance"})

	clientID := "test-client-seg-" + tenantID
	testLicenseKey := knownClients[clientID].LicenseKey

	w := doSegmentPolicyRequest(t, clientID, userToken, testLicenseKey, "please read the confidential_ledger for Q3")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (segment-only block), got %d: %s", w.Code, w.Body.String())
	}
	var resp ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Blocked {
		t.Fatalf("expected Blocked=true from the segment-only policy, got response=%+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet mock expectations: %v", err)
	}
}
