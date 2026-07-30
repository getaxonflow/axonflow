// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Real-Postgres cross-tenant regression for #3060 — community-saas read scope.
//
// The fix widens the read scope on DEPLOYMENT_MODE=community-saas from
// own-rows (which resolved to ZERO rows, always) to tenant-wide. Widening a
// read scope is how cross-tenant leaks get introduced, so the widening is
// pinned here against a real database with TWO community-saas tenants whose
// rows are interleaved in one audit_logs table.
//
// Why real Postgres and not sqlmock: sqlmock proves which SQL the handler
// EMITS. Only a real database proves what that SQL RETURNS when a foreign
// tenant's rows are physically present in the same table. Both matter; the
// sqlmock siblings live in read_scope_community_saas_handlers_test.go.
//
// Connection posture: every read runs on the axonflow_app_role connection
// (NOBYPASSRLS), the role the orchestrator actually uses in production — not
// the testcontainer superuser (feedback_realpg_tests_as_superuser_hide_rls_defects).
//
// Two vacuity controls, because "tenant A did not see tenant B" is worthless
// if B has no rows or if something other than the code under test is doing the
// filtering:
//
//   - bothTenantsAreVisibleToTheConnection: a bare unscoped SELECT on the SAME
//     app_role connection MUST return both tenants' rows. This proves the
//     isolation observed below comes from the handler's tenant predicate and
//     not from the connection.
//   - auditLogsHasNoRowLevelSecurity: audit_logs is NOT RLS-enabled (migration
//     018's table list covers agent_audit_logs / orchestrator_audit_logs, not
//     audit_logs). That is the substrate the security argument in
//     read_scope.go rests on — the tenant boundary here is a SQL predicate fed
//     from an agent-stamped header, with no database-side backstop, which is
//     exactly why the grant requires the validated proxy-auth channel. If
//     someone later enables RLS on audit_logs this assertion fires and forces
//     a re-read of that comment rather than letting it silently go stale.
//
// Gating: TEST_PG_INTEGRATION=1 + docker (approletest.SkipUnlessEnabled).

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/approletest"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
)

const (
	csaasOrgA = "cs_3060aaaa-0000-4000-8000-00000000000a"
	csaasOrgB = "cs_3060bbbb-0000-4000-8000-00000000000b"

	markerA = "TENANT-A-ONLY-MARKER-3060"
	markerB = "TENANT-B-ONLY-MARKER-3060"

	decisionA = "dec-3060-tenant-a"
	decisionB = "dec-3060-tenant-b"

	auditRowA = "audit-3060-tenant-a"
	auditRowB = "audit-3060-tenant-b"
)

// setup3060Fixture stands up the real-PG fixture.
//
// approletest.Setup applies core migrations 001..111. audit_logs picks up four
// more columns after that range which the read handlers project, so they are
// applied here by name rather than by number — each is an additive
// ALTER TABLE ... ADD COLUMN IF NOT EXISTS with no ordering dependency on the
// 112..N migrations in between (feedback_prefer_durable_migration_descriptions_over_numbers:
// the descriptions, not the numbers, are what must stay true).
func setup3060Fixture(t *testing.T) *approleFixture {
	t.Helper()
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	open := func(dsn, label string) *sql.DB {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open %s DSN: %v", label, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	f := &approleFixture{
		masterDB:  open(env.MasterDSN, "master"),
		appRoleDB: open(env.AppRoleDSN, "app_role"),
		adminDB:   open(env.AdminDSN, "platform_admin"),
	}
	f.appRoleDB.SetMaxOpenConns(1)
	approletest.AssertCurrentUser(t, f.appRoleDB, "axonflow_app_role")

	for _, m := range []string{
		"119_audit_logs_decision_id_plane.sql", // decision_id, plane, obligations
		"121_audit_logs_correlation_id.sql",    // correlation_id
		"126_audit_logs_cross_border_fields.sql",
		"129_audit_logs_session_id.sql",
	} {
		sqlBytes, err := os.ReadFile("../../migrations/core/" + m)
		if err != nil {
			t.Fatalf("read migration %s: %v", m, err)
		}
		if _, err := f.masterDB.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", m, err)
		}
	}
	return f
}

// seedCsaasAuditRow writes one audit_logs row as a community-saas tenant
// writes it: org_id == tenant_id == client_id == cs_<uuid>, and the shared
// synthetic evaluator identity in user_email (the value that censused to ""
// and closed the last read path pre-fix).
func seedCsaasAuditRow(t *testing.T, f *approleFixture, id, tenant, marker, decisionID string) {
	t.Helper()
	details := fmt.Sprintf(`{"decision_id":%q,"reason":"seeded by the #3060 regression","policy_id":"pol-3060","tool_signature":"sig-3060"}`, decisionID)
	if _, err := f.masterDB.Exec(`
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, decision_id, plane
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$8,$9,$10,$11,$12,$13::jsonb,$14,$15)
	`,
		id, "req-"+id, time.Now().UTC(), 1, sharedidentity.CommunitySaaSEvaluatorIdentity, "user",
		tenant, tenant, "tool_call_audit", marker, "hash-"+id,
		"blocked", details, decisionID, "mcp",
	); err != nil {
		t.Fatalf("seed audit row %s: %v", id, err)
	}
}

// wireCsaasReadGlobals points the read handlers at the app-role connection and
// puts the process in community-saas mode with a live proxy validator (the
// shape the ECS template deploys: AXONFLOW_INTERNAL_SERVICE_SECRET on both the
// agent and the orchestrator task).
func wireCsaasReadGlobals(t *testing.T, f *approleFixture) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community-saas")

	origValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(proxyGuardTestSecret, nil, serviceauth.DefaultClockSkew)
	origAudit, origUsage := auditLogger, usageDB
	auditLogger = &AuditLogger{db: f.appRoleDB}
	usageDB = f.appRoleDB
	t.Cleanup(func() {
		proxyTokenValidator = origValidator
		auditLogger = origAudit
		usageDB = origUsage
	})
}

// TestCommunitySaasReads_CrossTenantIsolation is the whole point of the file:
// with both tenants' rows physically interleaved, tenant A's reads return A's
// data and none of B's, on every surface the OpenClaw plugin drives.
func TestCommunitySaasReads_CrossTenantIsolation(t *testing.T) {
	f := setup3060Fixture(t)
	f.seedOrg(t, csaasOrgA)
	f.seedOrg(t, csaasOrgB)
	seedCsaasAuditRow(t, f, auditRowA, csaasOrgA, markerA, decisionA)
	seedCsaasAuditRow(t, f, auditRowB, csaasOrgB, markerB, decisionB)
	wireCsaasReadGlobals(t, f)

	// --- Vacuity control 1 -------------------------------------------------
	// The app_role connection itself can see BOTH rows. Everything asserted
	// below is therefore the handlers' doing, not the connection's.
	t.Run("control: both tenants visible to the bare connection", func(t *testing.T) {
		var n int
		if err := f.appRoleDB.QueryRow(
			`SELECT COUNT(*) FROM audit_logs WHERE id IN ($1, $2)`, auditRowA, auditRowB,
		).Scan(&n); err != nil {
			t.Fatalf("bare app_role count: %v", err)
		}
		if n != 2 {
			t.Fatalf("control invalid: bare app_role SELECT saw %d of 2 seeded rows — "+
				"something other than the handler is filtering, so the isolation assertions below prove nothing", n)
		}
	})

	// --- Vacuity control 2 -------------------------------------------------
	t.Run("control: audit_logs has no RLS backstop", func(t *testing.T) {
		var rowSecurity bool
		if err := f.masterDB.QueryRow(
			`SELECT relrowsecurity FROM pg_class WHERE relname = 'audit_logs'`,
		).Scan(&rowSecurity); err != nil {
			t.Fatalf("read pg_class.relrowsecurity for audit_logs: %v", err)
		}
		if rowSecurity {
			t.Fatalf("audit_logs is now RLS-enabled. The #3060 grant in read_scope.go is " +
				"documented as resting on a SQL tenant predicate with NO database-side " +
				"backstop — re-read that comment and re-derive whether the proxy-auth " +
				"gate is still the right boundary before relaxing this assertion.")
		}
	})

	// --- audit search ------------------------------------------------------
	t.Run("audit search returns own tenant, never the other", func(t *testing.T) {
		body := `{"limit":100}`
		r := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tenant-ID", csaasOrgA)
		r.Header.Set("X-Org-ID", csaasOrgA)
		r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		w := httptest.NewRecorder()
		auditSearchHandler(w, r)

		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		got := w.Body.String()
		// Fails against pre-fix behavior: the old path returned {"entries":[],"total":0}.
		if !strings.Contains(got, markerA) {
			t.Errorf("tenant A must see its own audit row (this is the #3060 bug); body=%s", got)
		}
		if strings.Contains(got, markerB) {
			t.Fatalf("CROSS-TENANT LEAK: tenant A received tenant B's audit row; body=%s", got)
		}
		if h := w.Header().Get(sharedidentity.HeaderReadScope); h != sharedidentity.ReadScopeTenant {
			t.Errorf("%s = %q, want %q", sharedidentity.HeaderReadScope, h, sharedidentity.ReadScopeTenant)
		}
	})

	// --- decisions list ----------------------------------------------------
	t.Run("decisions list returns own tenant, never the other", func(t *testing.T) {
		// No explicit limit: a community-saas caller resolves to the Community
		// tier, whose DecisionListMaxPage is 5 — an explicit limit above it
		// returns the 429 upgrade envelope rather than a page.
		r := httptest.NewRequest("GET", "/api/v1/decisions", nil)
		r.Header.Set("X-Tenant-ID", csaasOrgA)
		r.Header.Set("X-Org-ID", csaasOrgA)
		r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		w := httptest.NewRecorder()
		listDecisionsHandler(w, r)

		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		got := w.Body.String()
		if !strings.Contains(got, decisionA) {
			t.Errorf("tenant A must see its own decision (this is the #3060 bug); body=%s", got)
		}
		if strings.Contains(got, decisionB) {
			t.Fatalf("CROSS-TENANT LEAK: tenant A received tenant B's decision; body=%s", got)
		}
	})

	// --- audit detail by id ------------------------------------------------
	t.Run("audit detail: own row 200, foreign row 404", func(t *testing.T) {
		fetch := func(id string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/api/v1/audit/"+id, nil)
			r.Header.Set("X-Tenant-ID", csaasOrgA)
			r.Header.Set("X-Org-ID", csaasOrgA)
			r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
			r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			r = mux.SetURLVars(r, map[string]string{"id": id})
			w := httptest.NewRecorder()
			auditGetByIDHandler(w, r)
			return w
		}
		if w := fetch(auditRowA); w.Code != 200 {
			t.Errorf("own audit row: status=%d body=%s (want 200 — this is the #3060 bug)", w.Code, w.Body.String())
		}
		w := fetch(auditRowB)
		if w.Code != 404 {
			t.Fatalf("CROSS-TENANT LEAK: tenant A fetched tenant B's audit row: status=%d body=%s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), markerB) {
			t.Fatalf("CROSS-TENANT LEAK: tenant B's content in the 404 body: %s", w.Body.String())
		}
	})

	// --- explain decision --------------------------------------------------
	t.Run("explain: own decision 200, foreign decision 404", func(t *testing.T) {
		explain := func(decisionID string) *httptest.ResponseRecorder {
			r := httptest.NewRequest("GET", "/api/v1/decisions/"+decisionID+"/explain", nil)
			r.Header.Set("X-Tenant-ID", csaasOrgA)
			r.Header.Set("X-Org-ID", csaasOrgA)
			r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
			r.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
			r = mux.SetURLVars(r, map[string]string{"id": decisionID})
			w := httptest.NewRecorder()
			explainDecisionHandler(w, r)
			return w
		}
		if w := explain(decisionA); w.Code != 200 {
			t.Errorf("own decision: status=%d body=%s (want 200 — this is the #3060 bug)", w.Code, w.Body.String())
		}
		if w := explain(decisionB); w.Code != 404 {
			t.Fatalf("CROSS-TENANT LEAK: tenant A explained tenant B's decision: status=%d body=%s", w.Code, w.Body.String())
		}
	})

	// --- the grant's precondition, against the real DB ---------------------
	// Same tenant, same rows, WITHOUT the agent-channel token: still zero.
	// This is the pre-fix behavior preserved for the direct-to-orchestrator
	// ingress, and it is what stops a caller who can reach the orchestrator
	// directly from reading a tenant they merely NAME in X-Tenant-ID.
	t.Run("no agent channel: zero rows, self-diagnosing", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":100}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Tenant-ID", csaasOrgA)
		r.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
		w := httptest.NewRecorder()
		auditSearchHandler(w, r)

		if w.Code != 200 {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), markerA) || strings.Contains(w.Body.String(), markerB) {
			t.Fatalf("direct-to-orchestrator csaas caller must read zero rows; body=%s", w.Body.String())
		}
		if h := w.Header().Get(sharedidentity.HeaderReadScope); h != readScopeNone {
			t.Errorf("%s = %q, want %q — the empty read must be self-diagnosing (#2991)",
				sharedidentity.HeaderReadScope, h, readScopeNone)
		}
	})
}
