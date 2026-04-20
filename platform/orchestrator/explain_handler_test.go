// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

func TestBuildExplanation_EmptyDetails(t *testing.T) {
	ts := time.Now().UTC()
	exp := buildExplanation("dec-1", ts, "deny", "some reason", nil)

	if exp.DecisionID != "dec-1" {
		t.Errorf("DecisionID = %q, want 'dec-1'", exp.DecisionID)
	}
	if exp.Decision != "deny" {
		t.Errorf("Decision = %q, want 'deny'", exp.Decision)
	}
	if exp.Reason != "some reason" {
		t.Errorf("Reason = %q, want 'some reason'", exp.Reason)
	}
	if len(exp.PolicyMatches) != 0 {
		t.Errorf("PolicyMatches length = %d, want 0", len(exp.PolicyMatches))
	}
}

func TestBuildExplanation_StructuredMatches(t *testing.T) {
	ts := time.Now().UTC()
	details := map[string]interface{}{
		"tool_signature": "Bash",
		"risk_level":     "high",
		"policy_matches": []interface{}{
			map[string]interface{}{
				"policy_id":          "pol-sqli",
				"policy_name":        "SQL Injection Detector",
				"action":             "deny",
				"risk_level":         "high",
				"allow_override":     true,
				"policy_description": "Blocks SQL injection patterns",
			},
			map[string]interface{}{
				"policy_id":      "pol-secret",
				"policy_name":    "Secret Detector",
				"action":         "deny",
				"risk_level":     "critical",
				"allow_override": false,
			},
		},
	}

	exp := buildExplanation("dec-2", ts, "deny", "blocked", details)

	if exp.ToolSignature != "Bash" {
		t.Errorf("ToolSignature = %q, want 'Bash'", exp.ToolSignature)
	}
	if exp.RiskLevel != "high" {
		t.Errorf("RiskLevel = %q, want 'high'", exp.RiskLevel)
	}
	if len(exp.PolicyMatches) != 2 {
		t.Fatalf("PolicyMatches length = %d, want 2", len(exp.PolicyMatches))
	}

	m0 := exp.PolicyMatches[0]
	if m0.PolicyID != "pol-sqli" {
		t.Errorf("PolicyMatches[0].PolicyID = %q, want 'pol-sqli'", m0.PolicyID)
	}
	if m0.PolicyName != "SQL Injection Detector" {
		t.Errorf("PolicyMatches[0].PolicyName = %q", m0.PolicyName)
	}
	if !m0.AllowOverride {
		t.Error("PolicyMatches[0].AllowOverride = false, want true")
	}
	if m0.RiskLevel != "high" {
		t.Errorf("PolicyMatches[0].RiskLevel = %q, want 'high'", m0.RiskLevel)
	}

	m1 := exp.PolicyMatches[1]
	if m1.RiskLevel != "critical" {
		t.Errorf("PolicyMatches[1].RiskLevel = %q, want 'critical'", m1.RiskLevel)
	}
	if m1.AllowOverride {
		t.Error("PolicyMatches[1].AllowOverride = true, want false")
	}
}

func TestBuildExplanation_FallsBackToPolicyIDs(t *testing.T) {
	ts := time.Now().UTC()
	details := map[string]interface{}{
		"policy_ids": []interface{}{"pol-a", "pol-b"},
	}

	exp := buildExplanation("dec-3", ts, "deny", "blocked", details)

	if len(exp.PolicyMatches) != 2 {
		t.Fatalf("PolicyMatches length = %d, want 2", len(exp.PolicyMatches))
	}
	if exp.PolicyMatches[0].PolicyID != "pol-a" {
		t.Errorf("PolicyMatches[0].PolicyID = %q", exp.PolicyMatches[0].PolicyID)
	}
	if exp.PolicyMatches[1].PolicyID != "pol-b" {
		t.Errorf("PolicyMatches[1].PolicyID = %q", exp.PolicyMatches[1].PolicyID)
	}
}

func TestCheckOverrideAvailability_NoUserReturnsFalse(t *testing.T) {
	ok, id := checkOverrideAvailability("tenant-x", "", "", []ExplainPolicy{
		{PolicyID: "p-1", AllowOverride: true, RiskLevel: "medium"},
	})
	if ok {
		t.Error("expected false for empty user")
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestCheckOverrideAvailability_NoMatchesReturnsFalse(t *testing.T) {
	ok, id := checkOverrideAvailability("tenant-x", "user@example.com", "", nil)
	if ok {
		t.Error("expected false for no matches")
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

// Logical check: when all matches are critical OR allow_override=false,
// the function should return false without even trying the DB.
// We avoid DB dependencies in this unit test by keeping matches in a
// configuration that short-circuits the DB query.
func TestCheckOverrideAvailability_AllCriticalReturnsFalse(t *testing.T) {
	matches := []ExplainPolicy{
		{PolicyID: "p-1", AllowOverride: true, RiskLevel: "critical"},
		{PolicyID: "p-2", AllowOverride: false, RiskLevel: "high"},
	}
	ok, id := checkOverrideAvailability("tenant-x", "user@example.com", "", matches)
	if ok {
		t.Error("expected false when all matches are critical or non-overridable")
	}
	if id != "" {
		t.Errorf("expected empty id, got %q", id)
	}
}

func TestBuildExplanation_ExtractsReason(t *testing.T) {
	exp := buildExplanation("dec-4", time.Now().UTC(), "require_approval", "manual review required", nil)
	if exp.Reason != "manual review required" {
		t.Errorf("Reason = %q", exp.Reason)
	}
	if exp.Decision != "require_approval" {
		t.Errorf("Decision = %q", exp.Decision)
	}
}

func TestExplainDecision_RequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
	// Deliberately no X-Tenant-ID
	req.Header.Set("X-User-Email", "alice@example.com")
	w := httptest.NewRecorder()

	explainDecisionHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when X-Tenant-ID missing, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExplainDecision_RequiresDecisionID(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/decisions//explain", nil)
	req = mux.SetURLVars(req, map[string]string{"id": ""})
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-User-Email", "alice@example.com")
	w := httptest.NewRecorder()

	explainDecisionHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when decision_id missing, got %d", w.Code)
	}
}

func TestExplainDecision_CrossTenantReturns404(t *testing.T) {
	// Setup mock DB. The explain handler uses the package-level usageDB; swap it
	// for a sqlmock instance for the duration of this test.
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer mockDB.Close()

	origDB := usageDB
	usageDB = mockDB
	defer func() { usageDB = origDB }()

	// The fix: tenant_id filter is in the SELECT. A request for decision dec-1
	// from tenant-b must not return rows that belong to tenant-a — the SQL must
	// receive both decisionID and tenantID as positional args, and the mock
	// responds with ErrNoRows. The handler must surface that as 404 (not 403)
	// so attackers cannot enumerate decision_id existence across tenants.
	mock.ExpectQuery(`SELECT user_email, tenant_id, timestamp, policy_decision, policy_details`).
		WithArgs("dec-1", "tenant-b").
		WillReturnError(sql.ErrNoRows)

	req := httptest.NewRequest("GET", "/api/v1/decisions/dec-1/explain", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "dec-1"})
	req.Header.Set("X-Tenant-ID", "tenant-b")
	req.Header.Set("X-User-Email", "bob@example.com")
	w := httptest.NewRecorder()

	explainDecisionHandler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when decision belongs to different tenant, got %d: %s",
			w.Code, w.Body.String())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}
