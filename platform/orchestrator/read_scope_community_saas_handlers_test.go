// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3060 handler-level coverage. Two claims, both asserted on the SQL the real
// handlers emit rather than on a stubbed scope:
//
//  1. On community-saas over the agent channel the read reaches the database
//     with a TENANT predicate and NO own-rows predicate — i.e. it can return
//     rows at all, which is the bug. Pre-fix these handlers short-circuited to
//     an empty page without ever querying, so the ExpectQuery below is exactly
//     the assertion that fails against the old behavior.
//
//  2. The tenant predicate is still there, keyed on the header the agent
//     stamps — the widening moves the boundary from per-user to per-tenant and
//     NOT past the tenant. Every test asserts the tenant arg by value.
//
// Plus the #2991 observability gap closure: X-Axonflow-Read-Scope on the
// handlers that used to answer a fail-closed empty with a bare 200.

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
)

// withCommunitySaasProxyValidator puts the process in community-saas mode with
// a live proxy-token validator — the shape of a real csaas deployment (the
// ECS template wires AXONFLOW_INTERNAL_SERVICE_SECRET into both the agent and
// the orchestrator task).
func withCommunitySaasProxyValidator(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "community-saas")
	orig := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(proxyGuardTestSecret, nil, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { proxyTokenValidator = orig })
}

const (
	csaasTenantA = "cs_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	csaasTenantB = "cs_bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
)

// The reported bug: audit search on csaas returned a silent empty page. Post-
// fix the handler queries with the tenant arg ONLY — no own-rows predicate,
// so the evaluator's own rows come back.
func TestAuditSearch_CommunitySaas_TenantScopedNotOwnRows(t *testing.T) {
	withCommunitySaasProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	// Exactly one arg — the tenant. A query still carrying
	// LOWER(user_email) = $1 would need two and fail this expectation.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) tenant_id = \\$1").
		WithArgs(csaasTenantA).
		WillReturnRows(auditSearchRows())

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", csaasTenantA)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	// The csaas write path stamps this; pre-fix it censused to "" and zeroed
	// the read. It must now be irrelevant to the outcome.
	req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != sharedidentity.ReadScopeTenant {
		t.Errorf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, sharedidentity.ReadScopeTenant)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// Cross-tenant control. Tenant A's credential, with tenant B's id asserted in
// the BODY (auditSearchCriteria has a TenantID field) — the handler must
// force-inject the header tenant and never query for B. Sqlmock's WithArgs is
// the enforcement: a query carrying csaasTenantB fails the expectation.
func TestAuditSearch_CommunitySaas_BodyTenantCannotCrossTenants(t *testing.T) {
	withCommunitySaasProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) tenant_id = \\$1").
		WithArgs(csaasTenantA).
		WillReturnRows(auditSearchRows())

	body := `{"limit":50,"tenant_id":"` + csaasTenantB + `"}`
	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", csaasTenantA)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: the search must be pinned to the header tenant: %v", err)
	}
}

// Direct-to-orchestrator csaas caller (no proxy token) claiming tenant B: the
// grant does not apply, the evaluator identity censuses to "", and the handler
// short-circuits to an empty page WITHOUT querying. No ExpectQuery is
// registered, so any SQL at all fails this test.
func TestAuditSearch_CommunitySaas_NoAgentChannel_NoQueryRuns(t *testing.T) {
	withCommunitySaasProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", csaasTenantB)
	req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != readScopeNone {
		t.Errorf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, readScopeNone)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock (no query should have run): %v", err)
	}
}

// GET /api/v1/decisions — the second dead plugin tool. Post-fix the handler
// queries with the tenant arg and an EMPTY scope-email arg ($6), which the SQL
// short-circuits to "no user filter". Pre-fix it returned {"decisions":[]}
// without touching the DB.
func TestListDecisions_CommunitySaas_QueriesTenantWide(t *testing.T) {
	withCommunitySaasProxyValidator(t)
	oldUsageDB := usageDB
	defer func() { usageDB = oldUsageDB }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	usageDB = db

	rows := sqlmock.NewRows([]string{
		"decision_id", "timestamp", "decision", "policy_id",
		"tool_signature", "context", "transfer_basis", "data_residency",
	})
	// $1 tenant, $6 scope email — asserted empty (tenant-wide), and the tenant
	// asserted by value so a cross-tenant read would fail here.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE tenant_id = \\$1").
		WithArgs(csaasTenantA, sqlmock.AnyArg(), sqlmock.AnyArg(), "", "", "", sqlmock.AnyArg()).
		WillReturnRows(rows)

	req := httptest.NewRequest("GET", "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", csaasTenantA)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set("X-User-Email", sharedidentity.CommunitySaaSEvaluatorIdentity)
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != sharedidentity.ReadScopeTenant {
		t.Errorf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, sharedidentity.ReadScopeTenant)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// #2991 coverage gap, decisions half: the fail-closed empty list must now
// carry the scope header + the diagnostic log line instead of a bare 200.
func TestListDecisions_ScopedEmpty_StampsNoneHeader(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldUsageDB := usageDB
	defer func() { usageDB = oldUsageDB }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	usageDB = db
	// No ExpectQuery — the fail-closed arm must not reach the DB.

	req := httptest.NewRequest("GET", "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // valid hop, no role, no identity
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != readScopeNone {
		t.Fatalf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, readScopeNone)
	}
	var resp DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Decisions) != 0 {
		t.Fatalf("expected fail-closed empty list, got %d", len(resp.Decisions))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock (no query should have run): %v", err)
	}
}

// #2991 coverage gap, audit-detail half. The 404 body is deliberately a
// non-oracle, so the header is the only channel that distinguishes "scoped
// out" from "no such record" — and it must be present on BOTH.
func TestAuditGetByID_StampsReadScopeHeaderOnEveryOutcome(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	// Row exists and belongs to another user; the caller has no identity at
	// all, so it is hidden — with the header explaining why.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE id = (.+)").
		WithArgs("rec-1", "tenant-1").
		WillReturnRows(auditGetByIDRow("someone-else@acme.com"))

	req := httptest.NewRequest("GET", "/api/v1/audit/rec-1", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req = mux.SetURLVars(req, map[string]string{"id": "rec-1"})
	w := httptest.NewRecorder()
	auditGetByIDHandler(w, req)

	if w.Code != 404 {
		t.Fatalf("status=%d body=%s (want 404 non-oracle)", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != readScopeNone {
		t.Fatalf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, readScopeNone)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// The same record IS returned to an agent-proxied csaas caller for the same
// tenant — and the tenant arg is asserted by value, so the lookup can never
// straddle tenants.
func TestAuditGetByID_CommunitySaas_ReturnsTenantRow(t *testing.T) {
	withCommunitySaasProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE id = (.+)").
		WithArgs("rec-1", csaasTenantA).
		WillReturnRows(auditGetByIDRow(sharedidentity.CommunitySaaSEvaluatorIdentity))

	req := httptest.NewRequest("GET", "/api/v1/audit/rec-1", nil)
	req.Header.Set("X-Tenant-ID", csaasTenantA)
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req = mux.SetURLVars(req, map[string]string{"id": "rec-1"})
	w := httptest.NewRecorder()
	auditGetByIDHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get(sharedidentity.HeaderReadScope); got != sharedidentity.ReadScopeTenant {
		t.Errorf("%s = %q, want %q", sharedidentity.HeaderReadScope, got, sharedidentity.ReadScopeTenant)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// GET /api/v1/audit/search must answer 405 naming POST — not the greedy
// {id} route's 404 "audit record not found", which described the wrong
// resource and sent operators hunting for missing data.
func TestAuditSearchGET_405NamesTheCorrectMethod(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/audit/search", nil)
	w := httptest.NewRecorder()
	auditSearchMethodNotAllowedHandler(w, req)

	if w.Code != 405 {
		t.Fatalf("status=%d, want 405", w.Code)
	}
	if got := w.Header().Get("Allow"); !strings.Contains(got, "POST") {
		t.Fatalf("Allow = %q, must advertise POST", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, "POST") {
		t.Errorf("body must name the correct method, got %s", body)
	}
	if strings.Contains(strings.ToLower(body), "not found") {
		t.Errorf("body must not claim the resource is missing, got %s", body)
	}
}

// Route-level proof that a literal /audit/search GET registration wins over
// the greedy /audit/{id} — i.e. the chosen fix actually works under gorilla/mux
// matching order. This reconstructs the three registrations rather than
// importing Run() (which boots servers), so it pins the MECHANISM, not the
// production wiring; the production route is exercised end-to-end by
// runtime-e2e/3060_community_saas_reads/.
func TestAuditSearchGET_RouterPrefersLiteralOverGreedyID(t *testing.T) {
	r := mux.NewRouter()
	r.HandleFunc("/api/v1/audit/search", auditSearchHandler).Methods("POST")
	r.HandleFunc("/api/v1/audit/search", auditSearchMethodNotAllowedHandler).Methods("GET", "HEAD")
	r.HandleFunc("/api/v1/audit/{id}", auditGetByIDHandler).Methods("GET")

	req := httptest.NewRequest("GET", "/api/v1/audit/search", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != 405 {
		t.Fatalf("status=%d body=%s — the greedy {id} route must not win", w.Code, w.Body.String())
	}
}
