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
	"github.com/golang-jwt/jwt/v5"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// #2867: a handler-level guard for the fetch site (gateway_handlers.go, the
// shouldPrefetchApprovedData gate). The pure-predicate test does NOT protect the
// wiring — reverting the gate to a bare `else` would leave it green. These tests
// drive the REAL handlePolicyPreCheck end-to-end with a row-returning connector
// registered and the user permitted for it, so if a blocked (or HITL-pending)
// pre-check ever reaches fetchApprovedData again, approved_data is populated and
// the assertion fails.

// seedGlobalEngineWithMarkerPolicy installs a real policy engine over a sqlmock
// that returns a single request-phase policy with the given action. Category is
// compliance-rbi: it is in the pre-check Categories whitelist, has no semantic
// validator (so a bare regex match fires), and — unlike security-sqli / pii /
// sensitive-data / dangerous — is NOT rewritten by ModeDetectionConfig.Build-
// ActionOverrides, so the seeded action ("block" / "require_approval") survives
// the handler's detection-posture overrides regardless of env.
func seedGlobalEngineWithMarkerPolicy(t *testing.T, actionRequest, pattern string) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	cols := policytest.LoaderCols() // #3048: includes created_at
	for i := 0; i < 8; i++ { // headroom: two scoped passes per load (#3048)
		mockSQL.ExpectQuery("SELECT").WillReturnRows(
			sqlmock.NewRows(cols).AddRow(
				"p1", "test_marker_policy", "Test Marker", "compliance-rbi", "system",
				pattern, "critical", "test marker", "request", actionRequest, nil,
				true, 100, "global", nil, []byte("{}"), time.Now().UTC(),
			))
	}
	policytest.ScopedTxPlumbing(mockSQL, 8)
	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	t.Cleanup(engine.Stop)
	orig := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(orig) })
}

// registerLeakConnector registers a row-returning connector named "leakdb" so a
// leaked fetch would produce non-nil approved_data (the failure signal).
func registerLeakConnector(t *testing.T) {
	t.Helper()
	orig := mcpRegistry
	t.Cleanup(func() { mcpRegistry = orig })
	mcpRegistry = registry.NewRegistry()
	conn := &testMockConnector{
		name:     "leakdb",
		connType: "postgres",
		queryRows: []map[string]interface{}{
			{"secret": "row-that-must-not-leak-on-a-denied-request"},
		},
	}
	if err := mcpRegistry.Register("leakdb", conn,
		&base.ConnectorConfig{Name: "leakdb", Type: "postgres", Timeout: 5 * time.Second}); err != nil {
		t.Fatalf("register leak connector: %v", err)
	}
}

// entPreCheck drives handlePolicyPreCheck in enterprise mode with a valid user
// token (tenant matches the injected credential) that grants mcp_query — so the
// only thing standing between a denied request and the connector data is the
// fetch gate under test.
func entPreCheck(t *testing.T, query string) PreCheckResponse {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	origSecret := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = origSecret })
	// Disable the circuit breaker: every handler CB call is guarded by
	// `circuitBreakerInstance != nil`, so nil is a clean no-op. (A stub over a
	// nil-DB repo would be a no-op under the community build but nil-deref in
	// the Enterprise circuit breaker's RecordPolicyViolation DB write, which the
	// block path triggers.)
	origCB := circuitBreakerInstance
	circuitBreakerInstance = nil
	t.Cleanup(func() { circuitBreakerInstance = origCB })
	origDB := usageDB
	usageDB = nil // audit writes are best-effort; skip them here
	t.Cleanup(func() { usageDB = origDB })

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":     float64(7),
		"tenant_id":   "ent-tenant",
		"email":       "user@example.com",
		"role":        "user",
		"permissions": []string{"mcp_query"},
	}).SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	body, _ := json.Marshal(PreCheckRequest{
		ClientID:    "ent-client",
		Query:       query,
		UserToken:   signed,
		DataSources: []string{"leakdb"},
	})
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyAuthKind, AuthKindEnterprise)
	ctx = context.WithValue(ctx, ContextKeyClientID, "ent-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "ent-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "ent-org")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 from pre-check, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp PreCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse pre-check response: %v", err)
	}
	return resp
}

// A BLOCKED pre-check must be denied AND must not execute the connector query /
// return approved_data. Reverting the fetch gate to a bare `else` populates
// approved_data on this denied response — this test catches that.
func TestPreCheck_BlockedRequestReturnsNoApprovedData(t *testing.T) {
	seedGlobalEngineWithMarkerPolicy(t, "block", "BLOCKME_MARKER_XYZ")
	registerLeakConnector(t)

	resp := entPreCheck(t, "SELECT note FROM ledger WHERE note = 'BLOCKME_MARKER_XYZ'")

	if resp.Approved {
		t.Fatal("a policy-blocked pre-check must not be approved")
	}
	if resp.BlockReason == "" {
		t.Error("a blocked pre-check must carry a block reason")
	}
	if resp.ApprovedData != nil {
		t.Errorf("a BLOCKED pre-check must NOT return approved_data (connector was executed on a deny): %v", resp.ApprovedData)
	}
}

// A HITL/needs_approval pre-check (enterprise) must be un-approved AND must not
// prefetch connector data before a human approves. Same guard, HITL branch.
func TestPreCheck_HITLPendingRequestReturnsNoApprovedData(t *testing.T) {
	seedGlobalEngineWithMarkerPolicy(t, "require_approval", "APPROVEME_MARKER_XYZ")
	registerLeakConnector(t)

	resp := entPreCheck(t, "SELECT note FROM ledger WHERE note = 'APPROVEME_MARKER_XYZ'")

	if resp.Approved {
		t.Fatal("a needs-approval pre-check must not be approved (awaiting human approval)")
	}
	if resp.BlockReason != "require_approval" {
		t.Errorf("HITL pre-check must carry the require_approval sentinel, got %q", resp.BlockReason)
	}
	if resp.ApprovedData != nil {
		t.Errorf("a HITL-pending pre-check must NOT prefetch approved_data before approval: %v", resp.ApprovedData)
	}
}

// Control: a clean-approved request with the same connector + data source DOES
// prefetch — proving the assertions above fail for the RIGHT reason (the gate),
// not because the fetch never runs in this harness.
func TestPreCheck_CleanApprovedRequestDoesPrefetch(t *testing.T) {
	seedGlobalEngineWithMarkerPolicy(t, "block", "PATTERN_THAT_WONT_MATCH_ANYTHING_ZZZ")
	registerLeakConnector(t)

	resp := entPreCheck(t, "SELECT note FROM ledger WHERE note = 'totally benign'")

	if !resp.Approved {
		t.Fatalf("a clean request must be approved, got blocked: %s", resp.BlockReason)
	}
	if resp.ApprovedData == nil {
		t.Fatal("a clean-approved request with a permitted data source must prefetch approved_data (control)")
	}
}
