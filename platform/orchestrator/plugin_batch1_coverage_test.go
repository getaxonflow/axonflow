// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// --- Small helpers to hoist the usageDB global for each test ---

func withUsageDB(t *testing.T, fn func(mock sqlmock.Sqlmock)) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	prev := usageDB
	usageDB = db
	t.Cleanup(func() {
		usageDB = prev
		_ = db.Close()
	})
	fn(mock)
}

// --- listOverridesHandler: no tenant header → 400 ---

func TestListOverridesHandler_RequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
	rr := httptest.NewRecorder()
	listOverridesHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// --- listOverridesHandler: tenant-scoped happy path ---

func TestListOverridesHandler_TenantScoped(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := overrideViewMockRow(t, "ov-1", "pol-1", "tenant-x")

		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id").
			WithArgs("tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var body struct {
			Count int `json:"count"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Count != 1 {
			t.Errorf("count = %d, want 1", body.Count)
		}
	})
}

// --- listOverridesHandler: policy_id filter path + include_revoked ---

func TestListOverridesHandler_PolicyAndRevokedFilters(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := overrideViewMockEmptyRows()
		// resolvePolicyUUID runs FIRST when a policy_id filter is present, and
		// it has its own WithOrgScope transaction - so this fixture declares
		// TWO. Before #3944's scoping fix the list query was bare, so the
		// resolve transaction was the only one and this test tolerated its
		// failure silently (the handler falls back to the raw param and logs).
		// Same shape as TestListOverridesHandler_PolicyAndTenantScope below.
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config").WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id::text FROM static_policies").
			WithArgs("pol-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).
				AddRow("00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+").
			WithArgs("tenant-x", "00000000-0000-0000-0000-000000000001").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET",
			"/api/v1/overrides?policy_id=pol-1&include_revoked=true", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})
}

// --- getOverrideHandler: tenant + id happy path ---

func TestGetOverrideHandler_TenantScopedLookup(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := overrideViewMockRowAs(t, "ov-1", "pol-1", "tenant-x", "user@x.com")

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE id = \\$1 AND tenant_id = \\$2").
			WithArgs("ov-1", "tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides/ov-1", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
	})
}

func TestGetOverrideHandler_NotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT .+ FROM policy_overrides").
			WithArgs("ov-missing", "tenant-x").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		req := httptest.NewRequest("GET", "/api/v1/overrides/ov-missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-missing"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rr.Code)
		}
	})
}

// --- explainDecisionHandler: missing id / 404 ---

func TestExplainDecisionHandler_RequiresID(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/decisions//explain", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	rr := httptest.NewRecorder()
	explainDecisionHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestExplainDecisionHandler_NotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// SELECT now binds (decisionID, callerTenant) — see #1623 retro fix.
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-missing", "tenant-x").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-missing/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-missing"})
		req.Header.Set("X-User-Email", "dev@x.com")
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rr.Code)
		}
	})
}

// --- explainDecisionHandler: happy path ---

func TestExplainDecisionHandler_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		ts := time.Now().UTC()
		details := `{"policy_matches":[{"policy_id":"p-1","policy_name":"Test","risk_level":"medium","allow_override":true}],"tool_signature":"Bash"}`
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{
				"user_email", "tenant_id", "timestamp", "policy_decision", "policy_details",
			}).AddRow("dev@x.com", "tenant-x", ts, "blocked", details))
		// historical hit count
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
		// No override lookup follows (#4252): explain reads no session
		// override. The match above is medium-risk with allow_override=true,
		// the exact input on which the deleted lookup answered
		// override_available=true, so a regression that restores it reaches
		// an unexpected query here and reports true.

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
		req.Header.Set("X-User-Email", "dev@x.com")
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
		}
		var body struct {
			DecisionID                string `json:"decision_id"`
			HistoricalHitCountSession int    `json:"historical_hit_count_session"`
			OverrideAvailable         bool   `json:"override_available"`
			OverrideExistingID        string `json:"override_existing_id"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.DecisionID != "dec-1" {
			t.Errorf("decision_id = %q, want dec-1", body.DecisionID)
		}
		if body.HistoricalHitCountSession != 2 {
			t.Errorf("historical_hit_count_session = %d, want 2", body.HistoricalHitCountSession)
		}
		if body.OverrideAvailable {
			t.Error("override_available must be false: session overrides are retired in v11 (#4252), so explain never offers one")
		}
		if body.OverrideExistingID != "" {
			t.Errorf("override_existing_id = %q, want empty: explain offers no override in v11", body.OverrideExistingID)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("explain made reads beyond the audit row and the hit count: %v", err)
		}
	})
}

// TestExplainDecisionHandler_CrossTenantReturnsNoOracle is the post-fix
// equivalent of the old _CrossTenantForbidden test. With tenant_id baked into
// the SELECT, an attacker in tenant-x simply cannot SELECT a row from
// tenant-other — the SQL returns ErrNoRows and the handler responds 404 so
// the existence of dec-1 in another tenant cannot be inferred from the
// response code.
func TestExplainDecisionHandler_CrossTenantReturnsNoOracle(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-1", "tenant-x").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
		req.Header.Set("X-User-Email", "attacker@x.com")
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404 (no enumeration oracle)", rr.Code)
		}
	})
}

// --- queryHistoricalHitCount: returns 0 paths ---

func TestQueryHistoricalHitCount_EmptyUserReturnsZero(t *testing.T) {
	got := queryHistoricalHitCount("", []ExplainPolicy{{PolicyID: "p-1"}}, time.Now())
	if got != 0 {
		t.Errorf("got %d, want 0 for empty user", got)
	}
}

func TestQueryHistoricalHitCount_NoMatchesReturnsZero(t *testing.T) {
	got := queryHistoricalHitCount("u@x.com", nil, time.Now())
	if got != 0 {
		t.Errorf("got %d, want 0 for nil matches", got)
	}
}

func TestQueryHistoricalHitCount_EmptyPolicyIDReturnsZero(t *testing.T) {
	got := queryHistoricalHitCount("u@x.com", []ExplainPolicy{{PolicyID: ""}}, time.Now())
	if got != 0 {
		t.Errorf("got %d, want 0 for empty policy id", got)
	}
}

func TestQueryHistoricalHitCount_DBError(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
			WillReturnError(sql.ErrConnDone)
		got := queryHistoricalHitCount("u@x.com",
			[]ExplainPolicy{{PolicyID: "p-1"}}, time.Now())
		if got != 0 {
			t.Errorf("got %d, want 0 on DB error", got)
		}
	})
}

func TestQueryHistoricalHitCount_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs").
			WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))
		got := queryHistoricalHitCount("u@x.com",
			[]ExplainPolicy{{PolicyID: "p-1"}}, time.Now())
		if got != 7 {
			t.Errorf("got %d, want 7", got)
		}
	})
}

// TestGetOverrideHandler_HappyPath exercises the 200 OK path. The SELECT
// pulls 12 columns to match the overrideRow struct, including
// organization_id, revoked_at, revoked_by.
func TestGetOverrideHandler_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := overrideViewMockRow(t, "ov-1", "pol-1", "tenant-x")

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
		rr := httptest.NewRecorder()
		getOverrideHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestListOverridesHandler_PolicyAndTenantScope exercises the (policy_id +
// tenant + !include_revoked) branch — the narrowest list filter.
func TestListOverridesHandler_PolicyAndTenantScope(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {

		// resolvePolicyUUID lookup chain: static first, then dynamic if
		// static misses. For this fixture we answer static with a UUID
		// that the handler will use as the actual WHERE value.
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id::text FROM static_policies").
			WithArgs("pol-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).
				AddRow("00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		rows := overrideViewMockRow(t, "ov-1", "00000000-0000-0000-0000-000000000001", "tenant-x")

		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+ AND revoked_at IS NULL").
			WithArgs("tenant-x", "00000000-0000-0000-0000-000000000001").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides?policy_id=pol-1", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestListOverridesHandler_PolicyAndTenantScope_IncludeRevoked exercises
// the include_revoked=true branch for the (policy + tenant) filter.
func TestListOverridesHandler_PolicyAndTenantScope_IncludeRevoked(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id::text FROM static_policies").
			WithArgs("pol-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).
				AddRow("00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		rows := overrideViewMockRow(t, "ov-1", "00000000-0000-0000-0000-000000000001", "tenant-x")

		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+ ORDER BY created_at").
			WithArgs("tenant-x", "00000000-0000-0000-0000-000000000001").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides?policy_id=pol-1&include_revoked=true", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestListOverridesHandler_TenantOnlyIncludeRevoked exercises the
// (tenant + include_revoked=true) branch.
func TestListOverridesHandler_TenantOnlyIncludeRevoked(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := overrideViewMockEmptyRows()
		expectListOverridesScope(mock, "tenant-x")
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ ORDER BY created_at").
			WithArgs("tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		req := httptest.NewRequest("GET", "/api/v1/overrides?include_revoked=true", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestListOverridesHandler_QueryError covers the 500 path when the list
// SELECT returns a driver error.
func TestListOverridesHandler_QueryError(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT .+ FROM policy_overrides").
			WithArgs("tenant-x").
			WillReturnError(sql.ErrConnDone)

		req := httptest.NewRequest("GET", "/api/v1/overrides", nil)
		req.Header.Set("X-Tenant-ID", "tenant-x")
		rr := httptest.NewRecorder()
		listOverridesHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestExplainDecisionHandler_LookupError covers the 500 path when the
// audit_logs SELECT fails with a non-ErrNoRows error.
func TestExplainDecisionHandler_LookupError(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-1", "tenant-x").
			WillReturnError(sql.ErrConnDone)

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)

		if rr.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want 500; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestExplainDecisionHandler_CrossTenantReturns404 locks in the access
// control: a caller from tenant-b who asks about a decision that lives in
// tenant-a gets 404 (not 403). The fix moved tenant filtering into the SELECT
// (was previously a post-fetch comparison), so cross-tenant requests return
// no rows and surface as 404 — denying an enumeration oracle that 403 would
// otherwise leak ("this ID exists, but not for you").
func TestExplainDecisionHandler_CrossTenantReturns404(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// SELECT now takes (decisionID, callerTenant). Caller is tenant-b, so
		// tenant-a's row is structurally unreachable — sqlmock returns ErrNoRows.
		mock.ExpectQuery("SELECT user_email.+FROM audit_logs WHERE").
			WithArgs("dec-1", "tenant-b").
			WillReturnError(sql.ErrNoRows)

		req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
		req.Header.Set("X-Tenant-ID", "tenant-b")   // different tenant
		req.Header.Set("X-User-Email", "bob@b.com") // different caller
		rr := httptest.NewRecorder()
		explainDecisionHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404; body=%s", rr.Code, rr.Body.String())
		}
	})
}
