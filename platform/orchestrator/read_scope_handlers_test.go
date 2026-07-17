// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
)

// #2922 handler-level enforcement tests. Each drives the REAL handler with a
// REAL request (direct-endpoint / non-MCP ingress — the reported exploit path)
// and asserts the SQL the handler emits: a non-admin caller's query MUST carry
// the exact-canonical own-rows predicate; an admin over the trusted channel
// MUST NOT; a caller-supplied user_email arg MUST NOT widen a non-admin.

func withEnterpriseProxyValidator(t *testing.T) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	orig := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(proxyGuardTestSecret, nil, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { proxyTokenValidator = orig })
}

func auditSearchRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
		"client_id", "tenant_id", "request_type", "query", "policy_decision",
		"policy_details", "provider", "model", "response_time_ms", "tokens_used",
		"cost", "redacted_fields", "error_message", "compliance_flags",
		"response_sample", "session_id", "total_count",
	})
}

// Non-admin developer, direct curl to /api/v1/audit/search: the SQL MUST carry
// the LOWER(user_email) = <canonical caller> predicate. WithArgs is the real
// assertion — it fails unless the handler injected the own-rows scope.
func TestAuditSearch_NonAdmin_ScopedToOwnRows(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	// tenant ($1), scope email ($2). The scope predicate lands FIRST so it can
	// never be displaced by a caller filter.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) LOWER\\(user_email\\) = (.+) tenant_id = (.+)").
		WithArgs("dev@acme.com", "tenant-1").
		WillReturnRows(auditSearchRows())

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	req.Header.Set("X-User-Email", "Dev@Acme.com") // mixed case → canonicalized
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// A non-admin who supplies a user_email arg for ANOTHER user must NOT widen:
// the enforced scope predicate is on the CALLER's canonical email; the caller
// arg is AND'ed as a (harmless, narrowing-only) ILIKE. Both predicates present,
// scope first.
func TestAuditSearch_NonAdmin_UserEmailArgCannotWiden(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	// $1 = enforced scope (caller), $2 = the ILIKE filter arg (victim), $3 = tenant.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) LOWER\\(user_email\\) = (.+) user_email ILIKE (.+) tenant_id = (.+)").
		WithArgs("dev@acme.com", "victim@acme.com", "tenant-1").
		WillReturnRows(auditSearchRows())

	body := `{"limit":50,"user_email":"victim@acme.com"}`
	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	req.Header.Set("X-User-Email", "dev@acme.com")
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// Admin over the trusted channel: NO scope predicate — full tenant read. The
// query must NOT contain LOWER(user_email) = ... . We assert by expecting a
// query WITHOUT the scope arg (only tenant).
func TestAuditSearch_Admin_FullTenant(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	// Only the tenant arg — no scope email. QueryMatcherRegexp: a query that
	// contained LOWER(user_email) would need a second arg and fail.
	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) tenant_id = \\$1").
		WithArgs("tenant-1").
		WillReturnRows(auditSearchRows())

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// Shared-credential / forged-header caller with NO validated identity: the
// handler short-circuits to an empty page WITHOUT ever hitting the DB
// (fail-closed). No ExpectQuery is registered, so any query would fail the mock.
func TestAuditSearch_NoIdentity_EmptyNoQuery(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}
	// Deliberately register NO expected query.

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // valid hop, but no role + no user identity
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []json.RawMessage `json:"entries"`
		Total   int               `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Entries) != 0 || resp.Total != 0 {
		t.Fatalf("expected empty fail-closed page, got %d entries total=%d", len(resp.Entries), resp.Total)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock (no query should have run): %v", err)
	}
}

// A forged admin role WITHOUT proxy-auth reaching the orchestrator directly is
// scoped to own-rows (the header is ignored). We assert the scope predicate is
// present keyed on the self-claimed identity — never tenant-wide.
func TestAuditSearch_ForgedAdminNoProxyAuth_ScopedToOwnRows(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	auditLogger = &AuditLogger{db: db}

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE (.+) LOWER\\(user_email\\) = (.+) tenant_id = (.+)").
		WithArgs("attacker@acme.com", "tenant-1").
		WillReturnRows(auditSearchRows())

	req := httptest.NewRequest("POST", "/api/v1/audit/search", strings.NewReader(`{"limit":50}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	// No proxy-auth token — the role header is forged and must be ignored.
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	req.Header.Set("X-User-Email", "attacker@acme.com")
	w := httptest.NewRecorder()
	auditSearchHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// listDecisionsHandler: a developer's list is scoped to their own decisions
// ($6 = canonical caller email); admin's $6 is empty (tenant-wide).
func TestListDecisions_NonAdmin_ScopedToOwnRows(t *testing.T) {
	withEnterpriseProxyValidator(t)
	origDB := usageDB
	usageDB, _ = nil, 0
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	usageDB = db
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(), // since
			sqlmock.AnyArg(), // decision vals
			"",               // policy_id
			"",               // tool_signature
			"dev@acme.com",   // #2922 own-rows scope (canonical)
			sqlmock.AnyArg(), // limit
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context", "transfer_basis", "data_residency"},
		))

	req := httptest.NewRequest("GET", "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "developer")
	req.Header.Set("X-User-Email", "DEV@acme.com")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

func TestListDecisions_Admin_FullTenant(t *testing.T) {
	withEnterpriseProxyValidator(t)
	origDB := usageDB
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	usageDB = db
	defer func() { usageDB = origDB }()

	mock.ExpectQuery(`FROM audit_logs[\s\S]*?WHERE tenant_id = \$1`).
		WithArgs(
			"tenant-a",
			sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			"",
			"",
			"", // empty scope → tenant-wide
			sqlmock.AnyArg(),
		).
		WillReturnRows(sqlmock.NewRows(
			[]string{"decision_id", "timestamp", "decision", "policy_id", "tool_signature", "context", "transfer_basis", "data_residency"},
		))

	req := httptest.NewRequest("GET", "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	req.Header.Set(sharedidentity.HeaderUserRole, "admin")
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock: %v", err)
	}
}

// listDecisions: no per-user identity ⇒ empty list, no query.
func TestListDecisions_NoIdentity_EmptyNoQuery(t *testing.T) {
	withEnterpriseProxyValidator(t)
	origDB := usageDB
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()
	usageDB = db
	defer func() { usageDB = origDB }()
	// No ExpectQuery registered.

	req := httptest.NewRequest("GET", "/api/v1/decisions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	listDecisionsHandler(w, req)

	if w.Code != 200 {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp DecisionListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Decisions) != 0 {
		t.Fatalf("expected empty list, got %d", len(resp.Decisions))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock (no query should run): %v", err)
	}
}

var _ = time.Now
