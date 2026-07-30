// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// v9 Follow-up A residual tests (Epic #2230). Each test asserts the
// post-fix behavior for one of the 5 fixes in the residual PR. The fix
// is mutation-tested in tandem (revert the SUT line, re-run the test,
// confirm it fails) so the assertions can't be tautological.

// --- Fix 2: BasicAuth must use session.clientID, not session.tenantID ---

func decodeBasicAuth(t *testing.T, r *http.Request) (user, pass string) {
	t.Helper()
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		t.Fatalf("missing/invalid Authorization header: %q", h)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		t.Fatalf("malformed Basic creds: %q", raw)
	}
	return parts[0], parts[1]
}

// TestMCPProxyToOrchestrator_BasicAuth_UsesClientID asserts that the
// /api/v1/* forwarder (mcpProxyToOrchestrator at line ~1801) sends the
// caller's clientID as the BasicAuth username, NOT the tenantID. Legacy
// whitelist callers (healthcare-demo etc.) have clientID != tenantID;
// the orchestrator must see the credential identity (clientID).
//
// Mutation test: revert the fix (SetBasicAuth(session.tenantID, ...)) in
// the SUT and this test fails — it asserts the literal string "client-X".
func TestMCPProxyToOrchestrator_BasicAuth_UsesClientID(t *testing.T) {
	var capturedUser string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, _ = decodeBasicAuth(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer stub.Close()

	original := orchestratorURL
	orchestratorURL = stub.URL
	defer func() { orchestratorURL = original }()

	// Distinct values so we can tell which one the SUT used.
	session := &mcpSession{
		tenantID: "tenant-healthcare",
		clientID: "client-healthcare-demo",
		orgID:    "org-healthcare",
	}
	if _, err := mcpProxyToOrchestrator(session, "GET", "/api/v1/decisions", nil); err != nil {
		t.Fatalf("mcpProxyToOrchestrator: %v", err)
	}
	if capturedUser != "client-healthcare-demo" {
		t.Errorf("BasicAuth user: got %q, want %q (clientID, per ADR-052 §5)", capturedUser, "client-healthcare-demo")
	}
	if capturedUser == "tenant-healthcare" {
		t.Errorf("BasicAuth user is tenantID (%q) — Fix 2 was reverted", capturedUser)
	}
}

// TestMCPListRecentDecisions_BasicAuth_UsesClientID asserts the same
// invariant for the second touched site (mcpToolListRecentDecisions
// at line ~1694), which has its own SetBasicAuth call rather than
// going through mcpProxyToOrchestrator.
func TestMCPListRecentDecisions_BasicAuth_UsesClientID(t *testing.T) {
	var capturedUser string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, _ = decodeBasicAuth(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"decisions":[]}`))
	}))
	defer stub.Close()

	original := orchestratorURL
	orchestratorURL = stub.URL
	defer func() { orchestratorURL = original }()

	session := &mcpSession{
		tenantID: "tenant-healthcare",
		clientID: "client-healthcare-demo",
		orgID:    "org-healthcare",
		tier:     "Pro",
	}
	if _, err := mcpToolListRecentDecisions(session, map[string]interface{}{"limit": float64(5)}); err != nil {
		t.Fatalf("mcpToolListRecentDecisions: %v", err)
	}
	if capturedUser != "client-healthcare-demo" {
		t.Errorf("BasicAuth user: got %q, want %q (clientID)", capturedUser, "client-healthcare-demo")
	}
}

// TestMCPProxyToAgent_BasicAuth_UsesClientID covers the third forwarder
// (mcpProxyToAgent at line ~1497) — already correct pre-PR but pinned
// here to lock in the sibling-parity invariant: ALL three orchestrator
// forwarders agree that the BasicAuth username is clientID.
func TestMCPProxyToAgent_BasicAuth_UsesClientID(t *testing.T) {
	var capturedUser string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser, _ = decodeBasicAuth(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer stub.Close()

	session := &mcpSession{
		tenantID: "tenant-healthcare",
		clientID: "client-healthcare-demo",
		orgID:    "org-healthcare",
	}
	if _, err := mcpProxyToAgent(session, "POST", stub.URL+"/v1/audit", map[string]interface{}{"k": "v"}); err != nil {
		t.Fatalf("mcpProxyToAgent: %v", err)
	}
	if capturedUser != "client-healthcare-demo" {
		t.Errorf("BasicAuth user: got %q, want %q (clientID)", capturedUser, "client-healthcare-demo")
	}
}

// --- Fix 5: authenticateMCPServerRequest must NOT fabricate userRole="admin" ---

// TestAuthenticateMCPServerRequest_UserRoleNotFabricated asserts that
// authenticateMCPServerRequest never fabricates an elevated userRole when no
// validated per-user token is present. The original v9 Fix 5 stamped
// "unknown"; RBAC-1 (#2920) replaces that sentinel with least-privilege
// RoleNone ("") — the fail-closed authz default that read-scoping (RBAC-3)
// gates on. The anti-fabrication invariant is preserved: a shared-credential /
// header-only caller must NEVER resolve to "admin".
//
// Mutation test: change the least-privilege return to "admin" — this test
// fails. It also rejects the old "unknown" sentinel so a partial revert is
// caught.
func TestAuthenticateMCPServerRequest_UserRoleNotFabricated(t *testing.T) {
	// Community mode: Authenticate succeeds without DB and no per-user token
	// is presented, so the caller takes the least-privilege path.
	// #3096: this said AXONFLOW_MODE, which nothing reads — the test worked
	// only because an unset DEPLOYMENT_MODE meant community. Name the real one.
	t.Setenv("DEPLOYMENT_MODE", "community")

	req := httptest.NewRequest("POST", "/", nil)
	req.Header.Set("X-User-Email", "alice@example.com")

	_, _, _, _, userRole, _, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("authenticateMCPServerRequest: %v", err)
	}
	if userRole == "admin" {
		t.Errorf("userRole is fabricated 'admin' — the RBAC-1 least-privilege default was reverted")
	}
	if userRole != "" {
		t.Errorf("userRole: got %q, want least-privilege \"\" (RBAC-1 #2920)", userRole)
	}
}

// --- Fix 4: db_auth Client.ClientID is the api_key_id, not OrganizationID ---

// TestValidateViaAPIKeys_ClientIDIsCredentialIdentity asserts ADR-052 §5
// alignment: Client.ClientID = apiKey.APIKeyID (the credential identity),
// NOT customer.OrganizationID (which would collapse all api_keys of one
// org into the same ClientID and break post-v10 unique-index lookups
// keyed on client_id).
//
// Mutation test: revert the SUT to ClientID: customer.OrganizationID
// in db_auth.go and this test fails because client.ClientID is then
// the org_id ("v9-followup-a-org") rather than the api_key_id
// ("api-key-v9-fix4"). The assertions reference DIFFERENT literal
// values for the two fields so a copy-paste swap of either field
// cannot fake the result.
func TestValidateViaAPIKeys_ClientIDIsCredentialIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		wantAPIKeyID = "api-key-v9-fix4"
		wantOrgID    = "v9-followup-a-org"
	)

	testLicenseKey := generateTestLicenseKey(wantOrgID, "Enterprise", "20351231")

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		wantAPIKeyID, "customer-v9", testLicenseKey, "Fix4 Key", "production",
		time.Now().Add(365*24*time.Hour), 30, []byte(`["query","llm"]`), nil,
		true, nil, time.Now().Add(-1*time.Hour), 1,
		"customer-v9", "V9 Org", wantOrgID, "saas",
		"Enterprise", "tenant-v9", "active", true, 100,
	)

	mock.ExpectQuery("FROM auth_lookup_api_key").
		WillReturnRows(rows)

	ctx := context.Background()
	client, err := validateViaAPIKeys(ctx, db, "irrelevant-basic-auth-user", testLicenseKey)
	if err != nil {
		t.Fatalf("validateViaAPIKeys: %v", err)
	}
	if client == nil {
		t.Fatal("expected client, got nil")
	}

	if client.ClientID == wantOrgID {
		t.Errorf("Client.ClientID was collapsed to OrganizationID (%q) — Fix 4 was reverted", client.ClientID)
	}
	if client.ClientID != wantAPIKeyID {
		t.Errorf("Client.ClientID: got %q, want %q (api_key_id per ADR-052 §5)", client.ClientID, wantAPIKeyID)
	}
	// ID retains OrganizationID for the legacy compat window — pin this so
	// nobody "cleans up" by swapping both fields to api_key_id (which would
	// silently break callers that read .ID as the org boundary).
	if client.ID != wantOrgID {
		t.Errorf("Client.ID: got %q, want %q (org_id retained for compat)", client.ID, wantOrgID)
	}
}

// TestAuthenticate_EnterpriseAPIKey_ClientIDIsCredentialIdentity walks the
// FULL Enterprise auth path (Authenticate → validateClientCredentialsDB →
// validateViaAPIKeys → AuthResult propagation) and asserts the F1 fix:
// auth.ClientID surfaces apiKey.APIKeyID (the credential identity), NOT
// customer.OrganizationID. Without this propagation, Fix 2 (BasicAuth)
// + Fix 4 (db_auth) are operationally no-ops for API-keyed callers
// because every downstream consumer (mcpSession.clientID, X-Client-ID
// header, rate-limiter buckets, audit_logs.client_id) reads from
// auth.ClientID — not client.ClientID directly.
//
// Mutation test: revert authenticator.go:211 or :260 from `client.ClientID`
// to `client.ID` and this test fails — auth.ClientID then collapses to
// the org_id and the != assertion fires.
//
// Tautology guard: wantAPIKeyID and wantOrgID are distinct string
// literals AND distinct from any default the SUT might fabricate.
func TestAuthenticate_EnterpriseAPIKey_ClientIDIsCredentialIdentity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		wantAPIKeyID   = "api-key-credential-f1"
		wantOrgID      = "org-from-customer-table-f1"
		wantLicenseOrg = "org-from-license-f1"
		wantTenantID   = "tenant-f1"
	)

	testLicenseKey := generateTestLicenseKey(wantLicenseOrg, "Enterprise", "20351231")

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		wantAPIKeyID, "customer-f1", testLicenseKey, "F1 Key", "production",
		time.Now().Add(365*24*time.Hour), 30, []byte(`["query","llm"]`), nil,
		true, nil, time.Now().Add(-1*time.Hour), 1,
		"customer-f1", "F1 Org", wantOrgID, "saas",
		"Enterprise", wantTenantID, "active", true, 100,
	)

	mock.ExpectQuery("FROM auth_lookup_api_key").
		WillReturnRows(rows)

	// Wire the package-level authDB to our sqlmock + force enterprise mode.
	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	// Configure the internal-service HMAC secret so the validator init
	// path doesn't degrade behavior, but no hints are passed so the path
	// falls through to step 4 (Enterprise Basic auth).
	t.Setenv("AXONFLOW_INTERNAL_SERVICE_SECRET", "test-secret-not-used-here-only-prevents-degraded-warnings")

	req := httptest.NewRequest("POST", "/api/v1/query", nil)
	// Basic auth: clientID slot is irrelevant (the SQL lookup is keyed on
	// the secret hash); we use "irrelevant" deliberately so the test
	// cannot accidentally pin clientID to that value.
	req.SetBasicAuth("irrelevant-basic-auth-user", testLicenseKey)

	auth, authErr := Authenticate(req, nil)
	if authErr != nil {
		t.Fatalf("Authenticate: %s (%s)", authErr.Message, authErr.Code)
	}
	if auth == nil {
		t.Fatal("expected non-nil AuthResult")
	}

	if auth.ClientID == wantOrgID {
		t.Errorf("auth.ClientID collapsed to customer.OrganizationID (%q) — F1 fix reverted in authenticator.go", auth.ClientID)
	}
	if auth.ClientID != wantAPIKeyID {
		t.Errorf("auth.ClientID: got %q, want %q (must propagate apiKey.APIKeyID through Authenticate per ADR-052 §5)",
			auth.ClientID, wantAPIKeyID)
	}
	// Spot-check siblings on AuthResult to catch a "swap both fields" cleanup
	// that would silently change the org boundary too.
	if auth.OrgID != wantLicenseOrg {
		t.Errorf("auth.OrgID: got %q, want %q (from license)", auth.OrgID, wantLicenseOrg)
	}
	if auth.TenantID != wantTenantID {
		t.Errorf("auth.TenantID: got %q, want %q", auth.TenantID, wantTenantID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations: %v", err)
	}
}

// --- Fix 1: setMigrationSessionVars issues set_config('app.deployment_org_id') ---

// TestSetMigrationSessionVars_IssuesDeploymentOrgIDConfig asserts that the
// migration-setup helper executes BOTH set_config calls before migrations
// run. Without the app.deployment_org_id call, migration 094 would default
// the GUC and silently stamp historical empty-org_id rows with
// 'local-dev-org' on first prod run (Epic #2230 Phase 3 forward-only
// backfill).
//
// Mutation test: revert run.go's helper to omit the second db.Exec call
// and this test fails with "expected sql.Exec for app.deployment_org_id".
// Tautology guard: the test asserts BOTH expected Exec calls with their
// specific argument values; a missing or differently-named call breaks
// sqlmock.ExpectationsWereMet().
func TestSetMigrationSessionVars_IssuesDeploymentOrgIDConfig(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	const (
		wantPassword = "dbpass-fix1"
		wantOrgID    = "prod-customer-xyz"
		wantKind     = "production"
	)

	mock.ExpectExec(`SELECT set_config\('app\.db_password',\s*\$1,\s*false\)`).
		WithArgs(wantPassword).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app\.deployment_org_id',\s*\$1,\s*false\)`).
		WithArgs(wantOrgID).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// #2320: helper must also seed app.deployment_kind so migration 094's
	// prod-safety precondition can fire EXCEPTION on prod-forgot-ORG_ID.
	mock.ExpectExec(`SELECT set_config\('app\.deployment_kind',\s*\$1,\s*false\)`).
		WithArgs(wantKind).
		WillReturnResult(sqlmock.NewResult(0, 0))

	setMigrationSessionVars(db, wantPassword, wantOrgID, wantKind)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled sqlmock expectations (Fix 1 reverted?): %v", err)
	}
}

// TestGetDeploymentOrgID_PropagatesEnv pins the ORG_ID env → migration
// session-var chain. setMigrationSessionVars is called with whatever
// getDeploymentOrgID() returns at boot time; if this chain breaks,
// migration 094's GUC ends up at the 'local-dev-org' default.
func TestGetDeploymentOrgID_PropagatesEnv(t *testing.T) {
	t.Setenv("ORG_ID", "prod-acme-corp")
	if got := getDeploymentOrgID(); got != "prod-acme-corp" {
		t.Errorf("getDeploymentOrgID with ORG_ID=prod-acme-corp: got %q, want %q", got, "prod-acme-corp")
	}
}

// TestGetDeploymentKind_PropagatesEnv pins the DEPLOYMENT_KIND env →
// migration session-var chain (#2320). Unset → "dev" (matches the
// docker-compose default); explicit "production" round-trips so the CFN
// task-def value reaches the migration 094 precondition.
func TestGetDeploymentKind_PropagatesEnv(t *testing.T) {
	t.Run("unset_defaults_to_dev", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_KIND", "")
		if got := getDeploymentKind(); got != "dev" {
			t.Errorf("getDeploymentKind with DEPLOYMENT_KIND unset: got %q, want %q", got, "dev")
		}
	})
	t.Run("production_round_trips", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_KIND", "production")
		if got := getDeploymentKind(); got != "production" {
			t.Errorf("getDeploymentKind with DEPLOYMENT_KIND=production: got %q, want %q", got, "production")
		}
	})
}

// TestSetMigrationSessionVars_NonFatalOnError verifies the helper doesn't
// panic or short-circuit when the db.Exec fails — pre-fix inline form
// logged and continued, and the migration runner's own per-migration
// error handling owns the failure surface. This test is a behavior pin
// against future "improvements" that might turn the helper into a
// log.Fatalf without an ADR-level discussion.
func TestSetMigrationSessionVars_NonFatalOnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectExec(`SELECT set_config\('app\.db_password',\s*\$1,\s*false\)`).
		WithArgs("p").
		WillReturnError(errExecMock())
	mock.ExpectExec(`SELECT set_config\('app\.deployment_org_id',\s*\$1,\s*false\)`).
		WithArgs("o").
		WillReturnError(errExecMock())
	mock.ExpectExec(`SELECT set_config\('app\.deployment_kind',\s*\$1,\s*false\)`).
		WithArgs("k").
		WillReturnError(errExecMock())

	// Must not panic / fatal.
	setMigrationSessionVars(db, "p", "o", "k")
}

func errExecMock() error { return errMock{} }

type errMock struct{}

func (errMock) Error() string { return "sqlmock: forced exec error" }
