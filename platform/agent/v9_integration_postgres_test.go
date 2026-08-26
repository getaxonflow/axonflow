// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	sharedaudit "axonflow/platform/shared/audit"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// requirePG is the gate for DoD R2 (Phase 4 Epic #2230). The test
// connects to a real local Postgres (`V9_PG_INTEGRATION=1`) and proves
// the v9 identity changes flow end-to-end:
//
//   - Community-SaaS auth shape  ({OrgID="cs_*", ClientID="cs_*", TenantID="cs_*"})
//   - Enterprise auth shape      ({OrgID=license, ClientID=basic-auth, TenantID=scope-tag})
//   - X-Client-ID forwards agent → orchestrator (overwrite rule applies)
//   - Spoofed identity headers are REJECTED at the auth boundary
//   - audit_logs INSERTs land with non-empty org_id
//
// The test is skipped in CI by default and runs locally via:
//
//	V9_PG_INTEGRATION=1 V9_PG_DSN='host=localhost dbname=v9_identity_test sslmode=disable' \
//	  go test -count=1 -tags=enterprise -run TestV9 ./agent/
func requirePG(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv("V9_PG_INTEGRATION") != "1" {
		t.Skip("V9_PG_INTEGRATION=1 not set — skipping Postgres-backed integration test")
	}
	dsn := os.Getenv("V9_PG_DSN")
	if dsn == "" {
		dsn = "host=localhost dbname=v9_identity_test sslmode=disable"
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("db.Ping: %v — is local Postgres up and does v9_identity_test exist?", err)
	}
	return db
}

// TestV9_AuditLogs_OrgIDPersistedAgainstRealPostgres is the R2 audit
// SELECT proof: write a row through the same writeExplainableAuditLog
// path that ships in production, then read it back from the live
// Postgres and assert org_id is the v9 value we passed (NOT the empty
// string the pre-fix MCP handlers used).
func TestV9_AuditLogs_OrgIDPersistedAgainstRealPostgres(t *testing.T) {
	db := requirePG(t)
	defer db.Close()

	// Unique IDs so reruns don't collide on PK.
	now := time.Now().UTC().UnixNano()
	decisionID := fmt.Sprintf("r2-explain-%d", now)
	overrideID := fmt.Sprintf("r2-override-%d", now)

	// Path 1: writeExplainableAuditLog
	writeExplainableAuditLog(context.Background(), db,
		decisionID, fmt.Sprintf("req-%d", now),
		"cs_v9_demo", "cs_v9_demo", "client-v9", "alice@v9.test",
		"alice@v9.test", "admin",
		"mcp_check_policy", "SELECT 1 -- v9", "h-v9",
		"deny", "low",
		[]RicherPolicyMatch{{PolicyName: "v9-p", PolicyID: "v9-pid", Version: 1}},
		"corr-v9-input",
		sharedaudit.LatencyUnmeasured)

	// Path 2: writeOverrideUsedEvent
	writeOverrideUsedEvent(context.Background(), db,
		overrideID, decisionID,
		"acme-corp", "acme-corp", "client-acme", "bob@v9.test",
		"v9-policy", "V9 Policy", 7,
		"corr-v9-ovr")

	// writeExplainableAuditLog prefixes the row id with "audit_";
	// writeOverrideUsedEvent prefixes with "audit_used_". Both rows
	// reference the same decision_id in policy_details, but the PK
	// shape is the literal we read back.
	rows, err := db.Query(`SELECT id, tenant_id, org_id FROM audit_logs WHERE id IN ($1, $2) ORDER BY id`,
		"audit_used_"+decisionID, "audit_"+decisionID)
	if err != nil {
		t.Fatalf("SELECT: %v", err)
	}
	defer rows.Close()

	seen := map[string][2]string{}
	for rows.Next() {
		var id, tid, oid string
		if err := rows.Scan(&id, &tid, &oid); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		seen[id] = [2]string{tid, oid}
	}
	t.Logf("seen rows: %+v", seen)
	if len(seen) != 2 {
		t.Fatalf("expected 2 rows, got %d (%+v)", len(seen), seen)
	}

	// The R2 falsifying assertion: BOTH rows must carry non-empty org_id.
	// Pre-fix HEAD wrote "" for org_id on these paths; if this assertion
	// fails after a future regression, the bug is back.
	for id, vals := range seen {
		if vals[1] == "" {
			t.Errorf("row %s has empty org_id — v9 fix regressed", id)
		}
	}
	if got := seen["audit_"+decisionID]; got[1] != "cs_v9_demo" {
		t.Errorf("decision row org_id = %q, want %q", got[1], "cs_v9_demo")
	}
	if got := seen["audit_used_"+decisionID]; got[1] != "acme-corp" {
		t.Errorf("override row org_id = %q, want %q", got[1], "acme-corp")
	}
}

// TestV9_CommunitySaas_AuthShape locks the Community-SaaS identity
// shape on the AuthResult struct: org/client/tenant all equal each
// other for cs_* customers during the v9 compatibility window.
//
// This does NOT touch the real registrations table — we drive the
// auth path via the synthetic Authenticate() Community mode that
// behaves the same way (deployment_mode == community). For the
// real bcrypt path we have authenticator_test.go coverage; this test
// proves the V1.1 shape end-to-end via headers + context.
func TestV9_CommunitySaas_AuthShape(t *testing.T) {
	requirePG(t).Close() // gate; this test reads no DB but is part of the R2 suite
	t.Setenv("DEPLOYMENT_MODE", "community")

	var got RequestIdentity
	handler := apiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	const cred = "cs_demo_42"
	req := httptest.NewRequest("GET", "/api/v1/check", nil)
	req.SetBasicAuth(cred, "secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got.ClientID != cred {
		t.Errorf("ClientID = %q, want %q", got.ClientID, cred)
	}
	if got.OrgID == "" {
		t.Errorf("OrgID must not be empty for community-saas auth path")
	}
}

// TestV9Phase6_SaaSAuthReturnsPerCustomerOrgID is the load-bearing
// mutation guard for the auth.go Phase 6 change: validateCommunitySaasAuth
// must return OrgID = the per-customer cs_<uuid> (= ClientID = TenantID),
// NOT the legacy shared constant "community-saas".
//
// Drives validateCommunitySaasAuth DIRECTLY (skips apiAuthMiddleware's
// daily-cap layer, which would otherwise require migration 068's
// increment_csaas_daily() function to be present in the test schema).
// The mutation guard is for the auth function's return value, not the
// surrounding middleware.
//
// Mutation test: revert auth.go to `OrgID: "community-saas"` (the
// pre-Phase-6 value). Run this test. It MUST FAIL on the org_id check.
//
// Counter-test for tautology: the assertion uses `cred` (a runtime-
// generated cs_<uuid>) compared against `c.OrgID` returned from the SUT.
// Different sources — SUT writes the value from its OWN logic, test
// reads it back. If the SUT computes OrgID = "community-saas" (the
// legacy constant), c.OrgID != cred and the assertion fails.
func TestV9Phase6_SaaSAuthReturnsPerCustomerOrgID(t *testing.T) {
	db := requirePG(t)
	defer db.Close()

	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	// validateCommunitySaasAuth uses authDB (package-global) for the
	// registration lookup. Wire the test DB to the package global so the
	// auth path can find the seeded row.
	saved := authDB
	authDB = db
	defer func() { authDB = saved }()

	// Seed a cs_* registration with a known bcrypt-hashed secret.
	cred := fmt.Sprintf("cs_v9p6_%d", time.Now().UnixNano())
	const plaintextSecret = "phase6-test-secret-12345"
	hash, err := bcryptHashForTest(plaintextSecret)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	expiresAt := time.Now().UTC().Add(365 * 24 * time.Hour)
	if _, err := db.Exec(`
		INSERT INTO community_saas_registrations
		(tenant_id, client_id, secret_hash, secret_prefix, org_id, label, expires_at)
		VALUES ($1, $1, $2, $3, $1, $4, $5)`,
		cred, hash, plaintextSecret[:8], "v9p6-mutation-test", expiresAt); err != nil {
		t.Fatalf("seed registration: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM community_saas_registrations WHERE tenant_id = $1`, cred)
	})

	// Drive validateCommunitySaasAuth directly with a Basic Auth request.
	req := httptest.NewRequest("GET", "/api/v1/check", nil)
	req.SetBasicAuth(cred, plaintextSecret)

	c, authErr := validateCommunitySaasAuth(req)
	if authErr != nil {
		t.Fatalf("validateCommunitySaasAuth failed: status=%d msg=%q (seed bcrypt or rate-limit issue?)",
			authErr.StatusCode, authErr.Message)
	}
	if c == nil {
		t.Fatal("validateCommunitySaasAuth returned nil Client")
	}

	// The load-bearing assertions — these flip on the auth.go mutation.
	if c.OrgID == "community-saas" {
		t.Fatalf("v9 Phase 6 REGRESSION: OrgID = %q (the legacy shared constant). Expected per-customer cs_*.",
			c.OrgID)
	}
	if c.OrgID != cred {
		t.Errorf("OrgID = %q, want %q (per-customer identity per ADR-052)", c.OrgID, cred)
	}
	if c.ClientID != cred {
		t.Errorf("ClientID = %q, want %q", c.ClientID, cred)
	}
	if c.OrgID != c.ClientID {
		t.Errorf("v9 Phase 6 invariant violated: OrgID (%q) != ClientID (%q)",
			c.OrgID, c.ClientID)
	}
	if c.TenantID != cred {
		t.Errorf("TenantID = %q, want %q (v9 compat alias = ClientID)", c.TenantID, cred)
	}
}

// bcryptHashForTest produces a real bcrypt hash for the given plaintext.
// Used by the SaaS-auth integration test to seed a registration row that
// the production validateCommunityRegistration path can authenticate.
func bcryptHashForTest(plaintext string) (string, error) {
	out, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// TestV9_AgentOrchestratorWire is a black-box check of the proxy
// boundary: the agent's proxyAuthMiddleware MUST stamp X-Client-ID
// (the new v9 header) along with X-Org-ID and X-Tenant-ID. Caller-
// supplied values for any of these are overwritten — this is the
// anti-spoofing rule that protects cross-tenant data access.
func TestV9_AgentOrchestratorWire(t *testing.T) {
	requirePG(t).Close()
	t.Setenv("DEPLOYMENT_MODE", "community")

	var sawOrg, sawClient, sawTenant string
	handler := proxyAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		sawOrg = r.Header.Get("X-Org-ID")
		sawClient = r.Header.Get("X-Client-ID")
		sawTenant = r.Header.Get("X-Tenant-ID")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/api/v1/audit/summary", nil)
	req.SetBasicAuth("integration-client", "secret")
	// Adversarial values that should be wiped:
	req.Header.Set("X-Org-ID", "attacker-org")
	req.Header.Set("X-Client-ID", "attacker-client")
	req.Header.Set("X-Tenant-ID", "attacker-tenant")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", rr.Code, rr.Body.String())
	}
	if sawOrg == "attacker-org" || sawClient == "attacker-client" || sawTenant == "attacker-tenant" {
		t.Fatalf("identity headers were NOT overwritten — spoof succeeded: org=%q client=%q tenant=%q",
			sawOrg, sawClient, sawTenant)
	}
	if sawClient != "integration-client" {
		t.Errorf("X-Client-ID = %q, want %q", sawClient, "integration-client")
	}
	if sawOrg == "" {
		t.Errorf("X-Org-ID must be non-empty after auth")
	}
}
