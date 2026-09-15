// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/decision/contract"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// #2867: a handler-level guard for the fetch site (gateway_handlers.go, the
// shouldPrefetchApprovedData gate). The pure-predicate test does NOT protect the
// wiring — reverting the gate to a bare `else` would leave it green. These tests
// drive the REAL handlePolicyPreCheck end-to-end with a row-returning connector
// registered and the user permitted for it, so if a blocked pre-check ever
// reaches fetchApprovedData again, approved_data is populated and the assertion
// fails. A HITL-pending pre-check is not reachable on this plane: the gateway
// pre-check has no approval hold, so the anchored engine's CHALLENGE is a deny
// with approval_required here (mapAnchoredDecision, PRD v11 §1.13).

// seedGlobalEngineWithMarkerControl installs the shared engine over the shipped
// rows with the first constraint the gateway pre-check's organization template
// binds on a row carrying no semantic validator matching pattern, and returns
// that constraint's policy id: a request carrying pattern is denied by it, as a
// shipped constraint denies what its detector matches while the organization
// has published nothing. The template also binds requirements here, which allow
// with an obligation rather than deny, and a validated row confirms its
// pattern's match against the content it detects, so a bare marker would not
// fire it.
func seedGlobalEngineWithMarkerControl(t *testing.T, pattern string) string {
	t.Helper()
	controls, err := templateControls(gatewayRequestSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range controls {
		if c.policy.Authority == contract.AuthorityConstraint &&
			sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category)) == nil {
			enfInstallDetectors(t, map[string]string{c.row.PolicyID: regexp.QuoteMeta(pattern)}, nil)
			return c.policy.ID
		}
	}
	t.Fatal("the gateway pre-check's organization template binds no constraint on a row a bare marker fires")
	return ""
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
		"iss":         sharedidentity.UserTokenIssuer,
		"sub":         "user@example.com",
		"user_id":     float64(7),
		"tenant_id":   "ent-tenant",
		"org_id":      "ent-org",
		"jti":         "jti-ent-precheck",
		"email":       "user@example.com",
		"role":        "user",
		"permissions": []string{"mcp_query"},
		"exp":         time.Now().Add(time.Hour).Unix(),
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
	control := seedGlobalEngineWithMarkerControl(t, "BLOCKME_MARKER_XYZ")
	registerLeakConnector(t)

	resp := entPreCheck(t, "SELECT note FROM ledger WHERE note = 'BLOCKME_MARKER_XYZ'")

	if resp.Approved {
		t.Fatal("a policy-blocked pre-check must not be approved")
	}
	if resp.BlockReason == "" {
		t.Error("a blocked pre-check must carry a block reason")
	}
	if !slices.Contains(resp.Policies, control) {
		t.Errorf("the deny must name the control that matched, %s; got policies %v", control, resp.Policies)
	}
	if resp.ApprovedData != nil {
		t.Errorf("a BLOCKED pre-check must NOT return approved_data (connector was executed on a deny): %v", resp.ApprovedData)
	}
}

// Control: a clean-approved request with the same connector + data source DOES
// prefetch — proving the assertions above fail for the RIGHT reason (the gate),
// not because the fetch never runs in this harness.
func TestPreCheck_CleanApprovedRequestDoesPrefetch(t *testing.T) {
	seedGlobalEngineWithMarkerControl(t, "PATTERN_THAT_WONT_MATCH_ANYTHING_ZZZ")
	registerLeakConnector(t)

	resp := entPreCheck(t, "SELECT note FROM ledger WHERE note = 'totally benign'")

	if !resp.Approved {
		t.Fatalf("a clean request must be approved, got blocked: %s", resp.BlockReason)
	}
	if resp.ApprovedData == nil {
		t.Fatal("a clean-approved request with a permitted data source must prefetch approved_data (control)")
	}
}
