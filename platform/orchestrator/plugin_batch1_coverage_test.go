// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// --- nullableString ---

func TestNullableString(t *testing.T) {
	if got := nullableString(""); got.Valid {
		t.Errorf("empty string should produce invalid NullString, got %+v", got)
	}
	got := nullableString("abc")
	if !got.Valid || got.String != "abc" {
		t.Errorf("non-empty string: got %+v, want {abc true}", got)
	}
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
		expiresAt := time.Now().Add(time.Hour)
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		}).AddRow("ov-1", "pol-1", "static", "tenant-x",
			"debugging", expiresAt, nil, time.Now())

		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id").
			WithArgs("tenant-x").
			WillReturnRows(rows)

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
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		})
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+").
			WithArgs("tenant-x", "pol-1").
			WillReturnRows(rows)

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
		expiresAt := time.Now().Add(time.Hour)
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id", "organization_id",
			"tool_signature", "override_reason", "expires_at",
			"created_by", "created_at", "revoked_at", "revoked_by",
		}).AddRow("ov-1", "pol-1", "static", "tenant-x", nil, nil,
			"reason", expiresAt, "user@x.com", time.Now(), nil, nil)

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

// --- policyRiskAndOverride ---

func TestPolicyRiskAndOverride_InvalidType(t *testing.T) {
	_, _, _, err := policyRiskAndOverride(context.Background(), nil, "tenant-1", "pol-1", "invalid")
	if err == nil || !strings.Contains(err.Error(), "invalid policy_type") {
		t.Errorf("expected invalid type error, got %v", err)
	}
}

func TestPolicyRiskAndOverride_StaticHappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// #3039: lookup runs org-scoped (BEGIN + set_config + SELECT + COMMIT).
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-1", "tenant-1").
			WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
				AddRow("high", true, "00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()
		risk, ao, uuid, err := policyRiskAndOverride(context.Background(), usageDB, "tenant-1", "pol-1", "static")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if risk != "high" || !ao {
			t.Errorf("got (%q, %v), want (high, true)", risk, ao)
		}
		if uuid != "00000000-0000-0000-0000-000000000001" {
			t.Errorf("canonical uuid = %q, want fixture uuid", uuid)
		}
	})
}

func TestPolicyRiskAndOverride_DynamicNotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		// #3039: tenant-scope pass misses, then the 'global'-scope pass
		// misses too — ErrNoRows must surface unchanged.
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-1").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT COALESCE\\(risk_level").
			WithArgs("pol-x", "tenant-1").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT COALESCE\\(risk_level").
			WithArgs("pol-x", "tenant-1").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		_, _, _, err := policyRiskAndOverride(context.Background(), usageDB, "tenant-1", "pol-x", "dynamic")
		if err != sql.ErrNoRows {
			t.Errorf("error = %v, want sql.ErrNoRows", err)
		}
	})
}

// --- createOverrideHandler: critical-risk rejection ---

func TestCreateOverrideHandler_RejectsCriticalRisk(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-crit", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
				AddRow("critical", false, "00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID: "pol-crit", PolicyType: "static", OverrideReason: "test",
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@x.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rr.Code)
		}
	})
}

func TestCreateOverrideHandler_RejectsAllowOverrideFalse(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT COALESCE\\(risk_level").
			WithArgs("pol-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
				AddRow("medium", false, "00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID: "pol-1", PolicyType: "dynamic", OverrideReason: "test",
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@x.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rr.Code)
		}
	})
}

func TestCreateOverrideHandler_PolicyNotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-missing", "tenant-x").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("global").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-missing", "tenant-x").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID: "pol-missing", PolicyType: "static", OverrideReason: "test",
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@x.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("status = %d, want 404", rr.Code)
		}
	})
}

// --- revokeOverrideHandler: not found / happy path ---

func TestRevokeOverrideHandler_NotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT policy_id, created_by FROM policy_overrides").
			WithArgs("ov-missing", "tenant-x").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		req := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-missing", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-missing"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@x.com")
		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, req)

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
		// override availability check
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id FROM policy_overrides").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

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
		if !body.OverrideAvailable {
			t.Error("override_available should be true (medium risk + allow_override)")
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

// --- checkOverrideAvailability: DB-hit paths ---

func TestCheckOverrideAvailability_WithActiveOverride(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id FROM policy_overrides").
			WithArgs("p-1", "dev@x.com", "tenant-x", "").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-existing"))
		mock.ExpectCommit()

		ok, id := checkOverrideAvailability("tenant-x", "tenant-x", "dev@x.com", "",
			[]ExplainPolicy{{PolicyID: "p-1", RiskLevel: "medium", AllowOverride: true}})
		if !ok {
			t.Error("expected available=true")
		}
		if id != "ov-existing" {
			t.Errorf("id = %q, want 'ov-existing'", id)
		}
	})
}

func TestCheckOverrideAvailability_NoActiveOverride(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id FROM policy_overrides").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		ok, id := checkOverrideAvailability("tenant-x", "tenant-x", "dev@x.com", "",
			[]ExplainPolicy{{PolicyID: "p-1", RiskLevel: "medium", AllowOverride: true}})
		if !ok {
			t.Error("expected available=true (policy is overridable, no existing override)")
		}
		if id != "" {
			t.Errorf("id = %q, want empty", id)
		}
	})
}

// --- ApplyOverrideToResult: skip critical, pick second match ---

func TestApplyOverrideToResult_SkipsCriticalAndUsesNonCritical(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		expiresAt := time.Now().Add(time.Hour)
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id, policy_id, policy_type.+FROM policy_overrides").
			WithArgs("p-medium", "dev@x.com", "tenant-x", "").
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at",
			}).AddRow("ov-1", "p-medium", "dynamic", "", "reason", expiresAt))
		mock.ExpectCommit()

		result := &PolicyEvaluationResult{
			Allowed: false,
			AppliedPoliciesDetail: []AppliedPolicyDetail{
				{PolicyID: "p-critical", RiskLevel: "critical", AllowOverride: true},
				{PolicyID: "p-medium", RiskLevel: "medium", AllowOverride: true},
			},
		}
		applied, _ := ApplyOverrideToResult(context.Background(), usageDB, nil, result,
			"tenant-x", "", "dev@x.com", "")
		if !applied {
			t.Fatal("expected applied=true (medium-risk policy overridable)")
		}
	})
}

// --- FindActiveOverride: happy path via mock ---

func TestFindActiveOverride_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		expiresAt := time.Now().Add(time.Hour)
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at",
		}).AddRow("ov-1", "pol-1", "static", "", "test reason", expiresAt)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id, policy_id, policy_type.+FROM policy_overrides").
			WithArgs("pol-1", "dev@x.com", "tenant-x", "").
			WillReturnRows(rows)
		mock.ExpectCommit()

		ov, err := FindActiveOverride(context.Background(), usageDB, "tenant-x", "tenant-x", "dev@x.com", "pol-1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ov == nil {
			t.Fatal("expected override, got nil")
		}
		if ov.ID != "ov-1" {
			t.Errorf("ID = %q, want 'ov-1'", ov.ID)
		}
	})
}

func TestFindActiveOverride_NotFound(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id, policy_id, policy_type.+FROM policy_overrides").
			WillReturnError(sql.ErrNoRows)
		mock.ExpectRollback()

		ov, err := FindActiveOverride(context.Background(), usageDB, "tenant-x", "tenant-x", "dev@x.com", "pol-1", "")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if ov != nil {
			t.Errorf("expected nil override, got %+v", ov)
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

// --- ApplyOverrideToResult: real flip-to-allow path ---

func TestApplyOverrideToResult_FlipsOnActiveOverride(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		expiresAt := time.Now().Add(time.Hour)
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at",
		}).AddRow("ov-1", "pol-1", "dynamic", "", "test reason", expiresAt)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("org-y"). // scope key = the passed org (R3 HIGH-3)
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id, policy_id, policy_type.+FROM policy_overrides").
			WillReturnRows(rows)
		mock.ExpectCommit()

		result := &PolicyEvaluationResult{
			Allowed: false,
			AppliedPoliciesDetail: []AppliedPolicyDetail{
				{PolicyID: "pol-1", RiskLevel: "medium", AllowOverride: true},
			},
		}

		applied, ov := ApplyOverrideToResult(context.Background(), usageDB, nil, result,
			"tenant-x", "org-y", "dev@x.com", "")
		if !applied {
			t.Fatal("expected applied=true")
		}
		if ov == nil {
			t.Fatal("expected non-nil override")
		}
		if !result.Allowed {
			t.Error("result.Allowed should now be true")
		}
		if !result.OverrideApplied || result.OverrideID != "ov-1" {
			t.Errorf("OverrideApplied=%v, OverrideID=%q; want (true, 'ov-1')",
				result.OverrideApplied, result.OverrideID)
		}
	})
}

// TestCreateOverrideHandler_InvalidBody covers the 400 path when the request
// body is unparseable JSON — rejects before touching validation or the DB.
func TestCreateOverrideHandler_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader("not json"))
	req.Header.Set("X-Tenant-ID", "tenant-x")
	req.Header.Set("X-User-Email", "dev@example.com")
	rr := httptest.NewRecorder()
	createOverrideHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestCreateOverrideHandler_CriticalPolicyForbidden covers the ADR-044
// invariant rejection: a critical-risk policy cannot be overridden.
func TestCreateOverrideHandler_CriticalPolicyForbidden(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
			AddRow("critical", false, "00000000-0000-0000-0000-000000000001")
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-critical", "tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID:       "pol-critical",
			PolicyType:     "static",
			OverrideReason: "trying to override critical",
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestCreateOverrideHandler_AllowOverrideFalse covers the 403 path for a
// non-critical policy that opts out of override via allow_override=false.
func TestCreateOverrideHandler_AllowOverrideFalse(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
			AddRow("high", false, "00000000-0000-0000-0000-000000000001")
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-no-override", "tenant-x").
			WillReturnRows(rows)
		mock.ExpectCommit()

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID:       "pol-no-override",
			PolicyType:     "static",
			OverrideReason: "policy blocks override",
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// TestCreateOverrideHandler_HappyPath exercises the 201 Created path,
// covering policy lookup, INSERT, cache invalidation, and audit event emit.
// This is the biggest coverage lever on createOverrideHandler.
func TestCreateOverrideHandler_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		riskRows := sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
			AddRow("medium", true, "00000000-0000-0000-0000-000000000001")
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-ok", "tenant-x").
			WillReturnRows(riskRows)
		mock.ExpectCommit()
		// v9 Phase 8 PR-C2 (#2384): INSERT wrapped in rls.WithOrgScope; scope
		// is X-Org-ID if set, else X-Tenant-ID (tenant-x in this test).
		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO policy_overrides").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		mock.ExpectExec("DELETE FROM workflow_steps").
			WithArgs("tenant-x", "dev@example.com", "pol-ok").
			WillReturnResult(sqlmock.NewResult(0, 0))

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID:       "pol-ok",
			PolicyType:     "static",
			OverrideReason: "need this to debug a thing",
			TTLSeconds:     1800,
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
		}
		var resp CreateOverrideResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.PolicyID != "pol-ok" {
			t.Errorf("PolicyID: got %q, want pol-ok", resp.PolicyID)
		}
		if resp.TTLSeconds != 1800 {
			t.Errorf("TTLSeconds: got %d, want 1800", resp.TTLSeconds)
		}
		if resp.Clamped {
			t.Error("expected Clamped=false for TTL within bounds")
		}
	})
}

// TestCreateOverrideHandler_TTLClamped exercises the clamping branch of the
// happy path — a TTL over the hard cap produces a clamped response.
func TestCreateOverrideHandler_TTLClamped(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		riskRows := sqlmock.NewRows([]string{"risk_level", "allow_override", "id"}).
			AddRow("low", true, "00000000-0000-0000-0000-000000000001")
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT risk_level, allow_override, id::text").
			WithArgs("pol-ok", "tenant-x").
			WillReturnRows(riskRows)
		mock.ExpectCommit()
		// v9 Phase 8 PR-C2 (#2384): wrapped INSERT.
		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO policy_overrides").
			WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit()
		mock.ExpectExec("DELETE FROM workflow_steps").
			WithArgs("tenant-x", "dev@example.com", "pol-ok").
			WillReturnResult(sqlmock.NewResult(0, 0))

		body, _ := json.Marshal(CreateOverrideRequest{
			PolicyID:       "pol-ok",
			PolicyType:     "static",
			OverrideReason: "long-running debug",
			TTLSeconds:     int64((30 * time.Hour).Seconds()),
		})
		req := httptest.NewRequest("POST", "/api/v1/overrides", strings.NewReader(string(body)))
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		createOverrideHandler(rr, req)

		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
		}
		var resp CreateOverrideResponse
		_ = json.NewDecoder(rr.Body).Decode(&resp)
		if !resp.Clamped {
			t.Error("expected Clamped=true for TTL above hard cap")
		}
		if resp.ClampedReason != "exceeds_hard_cap" {
			t.Errorf("ClampedReason = %q, want exceeds_hard_cap", resp.ClampedReason)
		}
	})
}

// TestRevokeOverrideHandler_HappyPath exercises the full 200 OK path.
func TestRevokeOverrideHandler_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT policy_id, created_by FROM policy_overrides").
			WithArgs("ov-live", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "created_by"}).AddRow("pol-1", "dev@example.com"))
		mock.ExpectCommit()
		// v9 Phase 8 PR-C2 (#2384): UPDATE wrapped in rls.WithOrgScope.
		mock.ExpectBegin()
		mock.ExpectExec("set_config").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("UPDATE policy_overrides SET revoked_at").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		req := httptest.NewRequest("DELETE", "/api/v1/overrides/ov-live", nil)
		req = mux.SetURLVars(req, map[string]string{"id": "ov-live"})
		req.Header.Set("X-Tenant-ID", "tenant-x")
		req.Header.Set("X-User-Email", "dev@example.com")
		rr := httptest.NewRecorder()
		revokeOverrideHandler(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		_ = json.NewDecoder(rr.Body).Decode(&resp)
		if resp["id"] != "ov-live" {
			t.Errorf("id: got %v, want ov-live", resp["id"])
		}
	})
}

// TestRevokeOverrideHandler_EmptyID covers the 400 guard against empty id.
func TestRevokeOverrideHandler_EmptyID(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/api/v1/overrides/", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req.Header.Set("X-Tenant-ID", "tenant-x")
	req.Header.Set("X-User-Email", "dev@example.com")
	rr := httptest.NewRecorder()
	revokeOverrideHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

// TestGetOverrideHandler_HappyPath exercises the 200 OK path. The SELECT
// pulls 12 columns to match the overrideRow struct, including
// organization_id, revoked_at, revoked_by.
func TestGetOverrideHandler_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		expiresAt := time.Now().Add(time.Hour)
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id", "organization_id",
			"tool_signature", "override_reason", "expires_at", "created_by",
			"created_at", "revoked_at", "revoked_by",
		}).AddRow("ov-1", "pol-1", "static", "tenant-x", nil,
			nil, "debugging", expiresAt, "dev@example.com",
			time.Now(), nil, nil)

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
		expiresAt := time.Now().Add(time.Hour)

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

		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		}).AddRow("ov-1", "00000000-0000-0000-0000-000000000001", "static", "tenant-x",
			"debug", expiresAt, nil, time.Now())

		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+ AND revoked_at IS NULL").
			WithArgs("tenant-x", "00000000-0000-0000-0000-000000000001").
			WillReturnRows(rows)

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
		revokedAt := time.Now().Add(-time.Minute)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").WithArgs("tenant-x").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id::text FROM static_policies").
			WithArgs("pol-1", "tenant-x").
			WillReturnRows(sqlmock.NewRows([]string{"id"}).
				AddRow("00000000-0000-0000-0000-000000000001"))
		mock.ExpectCommit()

		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		}).AddRow("ov-1", "00000000-0000-0000-0000-000000000001", "static", "tenant-x",
			"debug", nil, revokedAt, time.Now().Add(-time.Hour))

		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ AND policy_id::text = .+ ORDER BY created_at").
			WithArgs("tenant-x", "00000000-0000-0000-0000-000000000001").
			WillReturnRows(rows)

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
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tenant_id",
			"override_reason", "expires_at", "revoked_at", "created_at",
		})
		mock.ExpectQuery("SELECT .+ FROM policy_overrides WHERE tenant_id = .+ ORDER BY created_at").
			WithArgs("tenant-x").
			WillReturnRows(rows)

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

// TestApplyOverrideToResult_HappyPath covers the branch where an overridable
// policy's denial is flipped via an active override. Requires withUsageDB
// because FindActiveOverride queries policy_overrides.
func TestApplyOverrideToResult_HappyPath(t *testing.T) {
	withUsageDB(t, func(mock sqlmock.Sqlmock) {
		rows := sqlmock.NewRows([]string{
			"id", "policy_id", "policy_type", "tool_signature", "override_reason", "expires_at",
		}).AddRow("ov-1", "pol-med", "static", "", "debugging", nil)

		mock.ExpectBegin()
		mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
			WithArgs("tenant-x").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery("SELECT id, policy_id, policy_type.+FROM policy_overrides").
			WithArgs("pol-med", "dev@example.com", "tenant-x", "").
			WillReturnRows(rows)
		mock.ExpectCommit()

		result := &PolicyEvaluationResult{
			Allowed: false,
			AppliedPoliciesDetail: []AppliedPolicyDetail{
				{PolicyID: "pol-med", RiskLevel: "medium", AllowOverride: true},
			},
		}

		applied, ov := ApplyOverrideToResult(context.Background(), usageDB, nil,
			result, "tenant-x", "", "dev@example.com", "")
		if !applied {
			t.Fatal("expected applied=true")
		}
		if ov == nil || ov.ID != "ov-1" {
			t.Errorf("override: got %+v, want ov-1", ov)
		}
		if !result.Allowed {
			t.Error("result.Allowed should be true after apply")
		}
		if !result.OverrideApplied || result.OverrideID != "ov-1" {
			t.Errorf("OverrideApplied/ID: got %v/%s", result.OverrideApplied, result.OverrideID)
		}
	})
}
