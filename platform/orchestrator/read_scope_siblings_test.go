// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	sharedidentity "axonflow/platform/shared/identity"
)

// #2922 census-sibling scope tests: every cross-user read surface enumerated in
// #2923 is exercised for the non-admin (own-rows) and the fail-closed
// (no-identity) case. These are the direct-endpoint (non-MCP) ingress.

// --- listOverridesHandler: non-admin scoped to created_by ---

func TestListOverrides_NonAdmin_ScopedToCreatedBy(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		})
		// tenant ($1), created_by scope ($2). No policy filter.
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND LOWER\\(created_by\\) = .+").
			WithArgs("tenant-x", "dev@acme.com").
			WillReturnRows(rows)

		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "DEV@acme.com")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestListOverrides_Admin_FullTenant(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		})
		// Only the tenant arg — no created_by scope predicate.
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = \\$1 AND revoked_at IS NULL").
			WithArgs("tenant-x").
			WillReturnRows(rows)

		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "admin")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

func TestListOverrides_NoIdentity_EmptyNoQuery(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// No ExpectQuery — fail-closed short-circuit must not hit the DB.
		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // no role, no identity
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"count":0`) {
			t.Fatalf("expected empty list, got %s", rr.Body.String())
		}
	})
}

// --- getOverrideHandler: non-admin may fetch only own; 404 otherwise ---

func TestGetOverride_NonAdmin_OtherUsersOverrideIs404(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id", "organization_id",
			"tool_signature", "override_reason", "expires_at",
			"created_by", "created_at", "revoked_at", "revoked_by",
		}).AddRow("ov-1", "pol-1", "static", "tenant-x", nil, nil,
			"reason", time.Now().Add(time.Hour), "someone-else@acme.com", time.Now(), nil, nil)
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE id = .+ AND tenant_id").
			WithArgs("ov-1", "tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides/ov-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)
		if rr.Code != 404 {
			t.Fatalf("expected 404 for another user's override, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestGetOverride_NonAdmin_OwnOverrideIs200(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id", "organization_id",
			"tool_signature", "override_reason", "expires_at",
			"created_by", "created_at", "revoked_at", "revoked_by",
		}).AddRow("ov-1", "pol-1", "static", "tenant-x", nil, nil,
			"reason", time.Now().Add(time.Hour), "Dev@Acme.com", time.Now(), nil, nil)
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE id = .+ AND tenant_id").
			WithArgs("ov-1", "tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides/ov-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com") // canonical match to created_by
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("expected 200 for own override, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- revokeOverrideHandler: non-admin cannot revoke a colleague's override ---

func TestRevokeOverride_NonAdmin_OtherUsersOverrideIs404(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT policy_id, created_by FROM policy_overrides").
			WithArgs("ov-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "created_by"}).
				AddRow("pol-1", "someone-else@acme.com"))
		mock.ExpectCommit()
		// No UPDATE expected — the scope guard rejects before any write.

		req := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, req)
		if rr.Code != 404 {
			t.Fatalf("expected 404 when revoking another user's override, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- explainDecisionHandler: non-admin explaining another user's decision ---

func TestExplainDecision_NonAdmin_OtherUsersDecisionIs404(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// entry belongs to someone else.
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"user_email", "tenant_id", "timestamp", "policy_decision", "policy_details"}).
				AddRow("boss@acme.com", "tenant-x", time.Now(), "blocked", `{"decision_id":"dec-1"}`))

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)
		if rr.Code != 404 {
			t.Fatalf("expected 404 explaining another user's decision, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// --- auditGetByIDHandler: non-admin fetching another user's row ---

func TestAuditGetByID_NonAdmin_OtherUsersRowIs404(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		auditLogger = &AuditLogger{db: usageDB}
		mock.ExpectQuery("SELECT .+ FROM audit_logs\\s+WHERE id = .+ AND tenant_id").
			WithArgs("a-1", "tenant-x").
			WillReturnRows(auditGetByIDRow("boss@acme.com"))

		req := httptest.NewRequest("GET", "/api/v1/audit/a-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "a-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != 404 {
			t.Fatalf("expected 404 fetching another user's audit row, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestAuditGetByID_NonAdmin_OwnRowIs200(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		auditLogger = &AuditLogger{db: usageDB}
		mock.ExpectQuery("SELECT .+ FROM audit_logs\\s+WHERE id = .+ AND tenant_id").
			WithArgs("a-1", "tenant-x").
			WillReturnRows(auditGetByIDRow("Dev@Acme.com"))

		req := httptest.NewRequest("GET", "/api/v1/audit/a-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "a-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		auditGetByIDHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("expected 200 fetching own audit row, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// auditGetByIDRow builds the 26-column row GetAuditLogByID scans.
func auditGetByIDRow(userEmail string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "request_id", "timestamp", "user_id", "user_email", "user_role",
		"client_id", "tenant_id", "org_id", "request_type", "query",
		"policy_decision", "policy_details", "provider", "model", "response_time_ms",
		"tokens_used", "cost", "redacted_fields", "error_message", "response_sample",
		"compliance_flags", "correlation_id", "decision_id", "plane", "session_id",
	}).AddRow(
		"a-1", "req-1", time.Now(), "5", userEmail, "developer",
		"c1", "tenant-x", "org-x", "tool_call_audit", "q",
		"allowed", []byte(`{}`), "openai", "gpt-4", 10,
		5, 0.001, []byte(`[]`), "", "",
		[]byte(`[]`), "corr-1", "dec-1", "decision", "sess-1",
	)
}

// --- auditReportHandler: non-admin with no identity ⇒ empty report ---

func TestAuditReport_NonAdmin_NoIdentity_EmptyReport(t *testing.T) {
	withEnterpriseProxyValidator(t)
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		auditLogger = &AuditLogger{db: usageDB}
		// No ExpectQuery — fail-closed empty report short-circuits the DB.
		body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-02-01T00:00:00Z"}`
		req := httptest.NewRequest("POST", "/api/v1/audit/report", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // no identity
		rr := httptest.NewRecorder()
		auditReportHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"total":0`) {
			t.Fatalf("expected empty report, got %s", rr.Body.String())
		}
	})
}

// --- auditSummary (get_policy_stats): non-admin scoped ---

func TestAuditSummary_NonAdmin_ScopedToOwnRows(t *testing.T) {
	withEnterpriseProxyValidator(t)
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		auditSummaryHandler = NewAuditSummaryHandler(usageDB)
		defer func() { auditSummaryHandler = nil }()
		// action query carries the scope predicate ($4 = canonical email).
		mock.ExpectQuery("SELECT request_type, policy_decision, COUNT.+FROM audit_logs\\s+WHERE tenant_id = .+ LOWER\\(user_email\\) = \\$4").
			WithArgs("tenant-x", sqlmock.AnyArg(), sqlmock.AnyArg(), "dev@acme.com").
			WillReturnRows(sqlmock.NewRows([]string{"request_type", "policy_decision", "cnt"}))
		mock.ExpectQuery("SELECT COALESCE\\(AVG").
			WithArgs("tenant-x", sqlmock.AnyArg(), sqlmock.AnyArg(), "dev@acme.com").
			WillReturnRows(sqlmock.NewRows([]string{"avg"}).AddRow(0.0))
		mock.ExpectQuery("policy_details->>'policy_name'.+trigger_count").
			WithArgs("tenant-x", sqlmock.AnyArg(), sqlmock.AnyArg(), "dev@acme.com", sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"policy_name", "trigger_count", "block_count"}))

		body := `{"start_time":"2026-01-01T00:00:00Z","end_time":"2026-02-01T00:00:00Z"}`
		req := httptest.NewRequest("POST", "/api/v1/audit/summary", strings.NewReader(body))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "dev@acme.com")
		rr := httptest.NewRecorder()
		auditSummaryRequestHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
	})
}

// --- auditExportHandler: non-admin scoped; no-identity ⇒ empty export ---

func TestAuditExport_NonAdmin_ScopedToOwnRows(t *testing.T) {
	withEnterpriseProxyValidator(t)
	al, mock, done := newMockAuditLogger(t)
	defer done()
	ts := time.Now().UTC()
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"aud-s", "req-s", ts, 1, "dev@acme.com", "developer", "acme", "acme",
		"org", "llm_call", "q", "allowed", []byte(`{}`), "", "",
		int64(3), 0, 0.0, []byte(`[]`), "", "", "corr-s", "sess-42")
	// tenant ($1), scope email ($2) — exact canonical predicate first.
	mock.ExpectQuery("SELECT id, request_id, timestamp(.+)LOWER\\(user_email\\) = ").
		WithArgs("acme", "dev@acme.com").
		WillReturnRows(rows)

	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest("POST", "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
		req.Header.Set(sharedidentity.HeaderUserRole, "developer")
		req.Header.Set("X-User-Email", "DEV@acme.com")
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("unmet: %v", err)
		}
	})
}

func TestAuditExport_NoIdentity_EmptyNoQuery(t *testing.T) {
	withEnterpriseProxyValidator(t)
	al, mock, done := newMockAuditLogger(t)
	defer done()
	// No ExpectQuery — the fail-closed path must return empty without a query.
	withGlobalAuditLogger(al, func() {
		req := httptest.NewRequest("POST", "/api/v1/audit/export?format=json", strings.NewReader(`{}`))
		req.Header.Set("X-Tenant-ID", "acme")
		req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t)) // no identity
		rr := httptest.NewRecorder()
		auditExportHandler(rr, req)
		if rr.Code != 200 {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"count":0`) {
			t.Fatalf("expected empty export, got %s", rr.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("no query should have run: %v", err)
		}
	})
}
