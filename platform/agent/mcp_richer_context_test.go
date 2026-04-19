// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/agent/sqli"
)

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

// TestLookupPolicyRiskOverride_HappyPath covers the common case: a matching
// policy row returns its risk_level + allow_override.
func TestLookupPolicyRiskOverride_HappyPath(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override"}).
			AddRow("high", true))

	risk, ao, err := lookupPolicyRiskOverride(context.Background(), db, "pol-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if risk != "high" || !ao {
		t.Errorf("got (%q, %v), want (high, true)", risk, ao)
	}
}

// TestLookupPolicyRiskOverride_NotFoundReturnsEmpty asserts ErrNoRows maps
// to ("", false, nil) — dynamic policies aren't in static_policies so the
// caller can fall through gracefully.
func TestLookupPolicyRiskOverride_NotFoundReturnsEmpty(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-missing").
		WillReturnError(sql.ErrNoRows)

	risk, ao, err := lookupPolicyRiskOverride(context.Background(), db, "pol-missing")
	if err != nil || risk != "" || ao {
		t.Errorf("not-found should return (\"\", false, nil); got (%q, %v, %v)", risk, ao, err)
	}
}

// TestLookupActiveOverride_HappyPath — override exists for tenant+user+policy.
// lookupActiveOverride joins via static_policies so both slug and UUID resolve
// to the same override row.
func TestLookupActiveOverride_HappyPath(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT po\\.id FROM policy_overrides po").
		WithArgs("pol-slug", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-1"))

	id, found, err := lookupActiveOverride(context.Background(), db,
		"tenant-x", "dev@example.com", "pol-slug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !found || id != "ov-1" {
		t.Errorf("got (%q, %v); want (ov-1, true)", id, found)
	}
}

func TestLookupActiveOverride_NotFound(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT po\\.id FROM policy_overrides po").
		WithArgs("pol-x", "dev@example.com", "tenant-x").
		WillReturnError(sql.ErrNoRows)

	_, found, err := lookupActiveOverride(context.Background(), db,
		"tenant-x", "dev@example.com", "pol-x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Error("ErrNoRows should map to found=false")
	}
}

// TestBuildRicherCheckInputBlock_NoOverride covers the path where a matched
// policy is overridable but the caller hasn't created an override yet.
// override_available must still be true (user CAN create one), but
// override_existing_id empty.
func TestBuildRicherCheckInputBlock_NoOverride(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override"}).
			AddRow("high", true))
	mock.ExpectQuery("SELECT po\\.id FROM policy_overrides po").
		WithArgs("pol-1", "dev@example.com", "tenant-x").
		WillReturnError(sql.ErrNoRows)

	matches := []sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "Bypass"}}
	m, topRisk, overrideAvail, overrideID := buildRicherCheckInputBlock(
		context.Background(), db, "tenant-x", "dev@example.com", matches)

	if len(m) != 1 || m[0].PolicyID != "pol-1" || !m[0].AllowOverride {
		t.Errorf("matches not populated correctly: %+v", m)
	}
	if topRisk != "high" {
		t.Errorf("top risk = %q, want high", topRisk)
	}
	if overrideAvail == nil || !*overrideAvail {
		t.Errorf("override_available should be true when policy is overridable")
	}
	if overrideID != "" {
		t.Errorf("override_existing_id should be empty; got %q", overrideID)
	}
}

// TestBuildRicherCheckInputBlock_ExistingOverride — same shape but an
// override already exists, so override_existing_id is populated.
func TestBuildRicherCheckInputBlock_ExistingOverride(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override"}).
			AddRow("medium", true))
	mock.ExpectQuery("SELECT po\\.id FROM policy_overrides po").
		WithArgs("pol-1", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-42"))

	matches := []sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "Bypass"}}
	_, _, _, overrideID := buildRicherCheckInputBlock(
		context.Background(), db, "tenant-x", "dev@example.com", matches)

	if overrideID != "ov-42" {
		t.Errorf("override_existing_id = %q, want ov-42", overrideID)
	}
}

// TestBuildRicherCheckInputBlock_Critical_NotOverridable — critical-risk
// policies never surface as overridable, even if allow_override=true.
func TestBuildRicherCheckInputBlock_Critical_NotOverridable(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-crit").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override"}).
			AddRow("critical", false))

	matches := []sharedpolicy.PolicyMatch{{PolicyID: "pol-crit", PolicyName: "Catastrophic"}}
	m, topRisk, overrideAvail, _ := buildRicherCheckInputBlock(
		context.Background(), db, "tenant-x", "dev@example.com", matches)

	if m[0].RiskLevel != "critical" || m[0].AllowOverride {
		t.Errorf("critical match shape wrong: %+v", m[0])
	}
	if topRisk != "critical" {
		t.Errorf("top risk = %q, want critical", topRisk)
	}
	if overrideAvail != nil {
		t.Errorf("override_available should be unset (nil) for critical-only match; got %v", *overrideAvail)
	}
}

// TestBuildRicherCheckInputBlock_NilDBOrEmpty — guard rails return empty
// without panicking.
func TestBuildRicherCheckInputBlock_NilDBOrEmpty(t *testing.T) {
	ctx := context.Background()

	m, r, av, oid := buildRicherCheckInputBlock(ctx, nil, "t", "u", nil)
	if m != nil || r != "" || av != nil || oid != "" {
		t.Errorf("nil db should return zero values")
	}

	db, _ := newMockDB(t)
	m, r, av, oid = buildRicherCheckInputBlock(ctx, db, "t", "u", nil)
	if m != nil || r != "" || av != nil || oid != "" {
		t.Errorf("empty matches should return zero values")
	}
}

// TestApplyOverrideToCheckInputBlock_Flip — RICH-path override returns the
// override id and signals apply=true when an overridable match has an
// active override.
func TestApplyOverrideToCheckInputBlock_Flip(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT po\\.id FROM policy_overrides po").
		WithArgs("pol-1", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-7"))

	matches := []RicherPolicyMatch{
		{PolicyID: "pol-1", PolicyName: "Bypass", RiskLevel: "medium", AllowOverride: true},
	}
	id, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "dev@example.com", matches)
	if !applied || id != "ov-7" {
		t.Errorf("expected applied=(true, ov-7); got (%v, %q)", applied, id)
	}
}

// TestApplyOverrideToCheckInputBlock_CriticalNoFlip — critical-risk matches
// are skipped entirely; no DB lookup fires.
func TestApplyOverrideToCheckInputBlock_CriticalNoFlip(t *testing.T) {
	db, _ := newMockDB(t) // no ExpectQuery — lookup must not fire
	matches := []RicherPolicyMatch{
		{PolicyID: "pol-crit", PolicyName: "Catastrophic", RiskLevel: "critical", AllowOverride: false},
	}
	_, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "dev@example.com", matches)
	if applied {
		t.Error("critical-risk match must never trigger override apply")
	}
}

// TestApplyOverrideToCheckInputBlock_NoUserEmail — without a user identity
// we can't scope the lookup, so apply=false without consulting DB.
func TestApplyOverrideToCheckInputBlock_NoUserEmail(t *testing.T) {
	db, _ := newMockDB(t)
	matches := []RicherPolicyMatch{
		{PolicyID: "pol-1", RiskLevel: "medium", AllowOverride: true},
	}
	_, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "", matches)
	if applied {
		t.Error("empty userEmail must not apply any override")
	}
}

// TestWriteExplainableAuditLog_Inserts verifies the audit dual-write hits
// the right columns in the right order. explainDecision(id) relies on this
// row existing.
func TestWriteExplainableAuditLog_Inserts(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			"req-1",           // request_id
			sqlmock.AnyArg(), // timestamp
			0,                 // user_id (email is not numeric → 0)
			"u@e.com",         // user_email
			"user",            // user_role
			"c1",              // client_id
			"t1",              // tenant_id
			"o1",              // org_id
			"mcp_check_input", // request_type
			"SELECT 1",        // query
			"h1",              // query_hash
			"deny",            // policy_decision
			sqlmock.AnyArg(), // policy_details JSON
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"dec-1", "req-1",
		"t1", "o1", "c1", "u@e.com",
		"", "user",
		"mcp_check_input", "SELECT 1", "h1",
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "Name"}},
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestWriteExplainableAuditLog_NilDBOrEmptyDecisionID — guards against
// writes without a usable scope.
func TestWriteExplainableAuditLog_NilDBOrEmptyDecisionID(t *testing.T) {
	writeExplainableAuditLog(context.Background(), nil,
		"dec-1", "req-1", "t1", "o1", "c1", "u", "0", "user",
		"t", "q", "h", "r", "high", nil)

	db, mock := newMockDB(t)
	writeExplainableAuditLog(context.Background(), db,
		"", "req-1", "t1", "o1", "c1", "u", "0", "user",
		"t", "q", "h", "r", "high", nil)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("empty decision_id should be a no-op; got: %v", err)
	}
}

// TestWriteOverrideUsedEvent_Inserts — audit trail for override use fires
// an insert with policy_decision=allow + event_type=override_used.
func TestWriteOverrideUsedEvent_Inserts(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeOverrideUsedEvent(context.Background(), db,
		"ov-1", "dec-1", "t1", "o1", "c1", "u@e.com")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestWriteOverrideUsedEvent_NilDBOrEmptyOverride — guards against writes
// without a usable override id.
func TestWriteOverrideUsedEvent_NilDBOrEmptyOverride(t *testing.T) {
	writeOverrideUsedEvent(context.Background(), nil,
		"ov-1", "dec-1", "t1", "o1", "c1", "u@e.com")

	db, mock := newMockDB(t)
	writeOverrideUsedEvent(context.Background(), db,
		"", "dec-1", "t1", "o1", "c1", "u@e.com")
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("empty override_id should be a no-op; got: %v", err)
	}
}

// TestWriteOverrideUsedEvent_FallbackPlaceholders — covers the NOT NULL
// fallback branches when userEmail/clientID/tenantID are empty.
func TestWriteOverrideUsedEvent_FallbackPlaceholders(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			"dec-1",           // request_id = decisionID
			sqlmock.AnyArg(), // timestamp
			0,                 // user_id
			"unknown@axonflow.local", // user_email fallback
			"user",                   // user_role
			"unknown",                // client_id fallback
			"unknown",                // tenant_id fallback
			"",                        // org_id (no fallback)
			"override_used",           // request_type
			"override applied",        // query
			"none",                    // query_hash
			"allow",                   // policy_decision
			sqlmock.AnyArg(),          // policy_details JSON
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeOverrideUsedEvent(context.Background(), db,
		"ov-1", "dec-1", "", "", "", "")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestWriteExplainableAuditLog_FallbackPlaceholders — covers the NOT NULL
// fallback branches for explainable audit writes.
func TestWriteExplainableAuditLog_FallbackPlaceholders(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			"req-1",           // request_id
			sqlmock.AnyArg(), // timestamp
			42,                // user_id parsed from numeric string
			"unknown@axonflow.local", // user_email fallback
			"user",                   // user_role fallback
			"unknown",                // client_id fallback
			"unknown",                // tenant_id fallback
			"",                        // org_id (no fallback)
			"mcp_check_input",
			"q",
			"h",
			"deny",
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"dec-1", "req-1",
		"", "", "", "",
		"42", "",
		"mcp_check_input", "q", "h",
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "n1"}},
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestMcpToolExplainDecision_MissingArg — argument validation branch.
func TestMcpToolExplainDecision_MissingArg(t *testing.T) {
	_, err := mcpToolExplainDecision(&mcpSession{}, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing decision_id, got nil")
	}
}

// TestMcpToolCreateOverride_MissingArgs — every missing field fails fast.
func TestMcpToolCreateOverride_MissingArgs(t *testing.T) {
	cases := []map[string]interface{}{
		{},
		{"policy_id": "p1"},
		{"policy_id": "p1", "policy_type": "static"},
		{"policy_type": "static", "override_reason": "r"},
	}
	for i, args := range cases {
		if _, err := mcpToolCreateOverride(&mcpSession{}, args); err == nil {
			t.Errorf("case %d expected error, got nil", i)
		}
	}
}

// TestMcpToolDeleteOverride_MissingArg — argument validation branch.
func TestMcpToolDeleteOverride_MissingArg(t *testing.T) {
	_, err := mcpToolDeleteOverride(&mcpSession{}, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error for missing override_id, got nil")
	}
}

// TestMcpToolCheckPolicy_MissingArgs — connector_type + statement required.
func TestMcpToolCheckPolicy_MissingArgs(t *testing.T) {
	ctx := context.Background()
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{}); err == nil {
		t.Error("expected error when both args missing")
	}
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{
		"connector_type": "postgresql",
	}); err == nil {
		t.Error("expected error when statement missing")
	}
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{
		"statement": "SELECT 1",
	}); err == nil {
		t.Error("expected error when connector_type missing")
	}
}

// TestMcpToolCheckOutput_MissingArgs — connector_type required.
func TestMcpToolCheckOutput_MissingArgs(t *testing.T) {
	if _, err := mcpToolCheckOutput(context.Background(), &mcpSession{}, map[string]interface{}{}); err == nil {
		t.Error("expected error when connector_type missing")
	}
}

// TestMcpToolCheckPolicy_AllowedPath — happy path. Dynamic evaluator returns
// allowed; no block path, no richer-context fields required.
func TestMcpToolCheckPolicy_AllowedPath(t *testing.T) {
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           true,
		PoliciesEvaluated: 2,
	})
	defer server.Close()
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", userID: "u1", userRole: "admin", clientID: "c1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"statement":      "SELECT 1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Errorf("expected allowed=true, got %v", m["allowed"])
	}
	if _, set := m["decision_id"]; set {
		t.Error("allowed path must not emit decision_id")
	}
}

// TestMcpToolCheckPolicy_DynamicBlocked — exercises block-path branches:
// decision_id minted, block_reason from dynamic, no static MatchedPolicies
// so richer-context lookups are skipped but allowed=false is set.
func TestMcpToolCheckPolicy_DynamicBlocked(t *testing.T) {
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:     false,
		BlockReason: "Budget exceeded",
	})
	defer server.Close()
	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", userID: "u1", userRole: "admin", clientID: "c1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"statement":      "SELECT 1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	if allowed, _ := m["allowed"].(bool); allowed {
		t.Error("expected allowed=false")
	}
	if _, hasID := m["decision_id"]; !hasID {
		t.Error("block path must emit decision_id")
	}
	if reason, _ := m["block_reason"].(string); reason != "Budget exceeded" {
		t.Errorf("block_reason = %q, want 'Budget exceeded'", reason)
	}
}

// TestMcpToolCheckPolicy_DefaultOperation — verifies default `operation=execute`.
func TestMcpToolCheckPolicy_DefaultOperation(t *testing.T) {
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"statement":      "SELECT 1",
		// operation intentionally omitted → defaults to "execute"
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("expected non-nil response")
	}
}

// TestMcpToolCheckOutput_AllowedPath — verifies response-data parsing + the
// short-circuit when no policies fire.
func TestMcpToolCheckOutput_AllowedPath(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "t1", userID: "u1", userRole: "admin", clientID: "c1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"message":        "result",
		"response_data": []interface{}{
			map[string]interface{}{"id": 1, "email": "a@b.c"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	m, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	if allowed, _ := m["allowed"].(bool); !allowed {
		t.Errorf("expected allowed=true, got %v", m["allowed"])
	}
}

// TestMcpToolCheckOutput_SQLiBlocked — block-path branch: SQLi middleware
// flags an exfil-style response; mcpToolCheckOutput must surface allowed=false
// + decision_id + block_reason. No static matches, so the richer-context
// + audit dual-write branch stays disabled.
func TestMcpToolCheckOutput_SQLiBlocked(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	originalSQLi := sqli.GetGlobalMiddleware()
	defer sqli.SetGlobalMiddleware(originalSQLi)

	// Block-on-detection middleware so ScanQueryResponse reports Blocked=true.
	cfg := sqli.DefaultConfig().WithBlockOnDetection(true)
	m, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(cfg))
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(m)

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "t1", userID: "u1", userRole: "admin", clientID: "c1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"response_data": []interface{}{
			map[string]interface{}{
				"id":   1,
				"data": "admin' UNION SELECT password FROM users--",
			},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mp, ok := resp.(map[string]interface{})
	if !ok {
		t.Fatalf("resp not a map: %T", resp)
	}
	if allowed, _ := mp["allowed"].(bool); allowed {
		t.Error("expected allowed=false for SQLi-blocked response")
	}
	if _, set := mp["decision_id"]; !set {
		t.Error("block path must emit decision_id")
	}
	if reason, _ := mp["block_reason"].(string); reason == "" {
		t.Error("block path must emit block_reason")
	}
}

// TestMcpToolCheckOutput_SQLiBlocked_MessageMode — same block path, but via
// the message branch (rows=nil, non-empty message) exercising the other
// SQLi scan entry point in evaluateOutputPolicies.
func TestMcpToolCheckOutput_SQLiBlocked_MessageMode(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	originalSQLi := sqli.GetGlobalMiddleware()
	defer sqli.SetGlobalMiddleware(originalSQLi)

	cfg := sqli.DefaultConfig().WithBlockOnDetection(true)
	m, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(cfg))
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(m)

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "t1", userID: "u1", userRole: "admin", clientID: "c1",
	}, map[string]interface{}{
		"connector_type": "postgres",
		"message":        "admin' UNION SELECT password FROM users--",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mp, _ := resp.(map[string]interface{})
	if allowed, _ := mp["allowed"].(bool); allowed {
		t.Error("expected allowed=false for SQLi-blocked message")
	}
}

// TestCommunitySaasAuthError_Error — Error() returns the Message field.
func TestCommunitySaasAuthError_Error(t *testing.T) {
	e := &CommunitySaasAuthError{StatusCode: 401, Message: "nope"}
	if e.Error() != "nope" {
		t.Errorf("Error() = %q, want %q", e.Error(), "nope")
	}
}

// TestLookupPolicyRiskOverride_DBError — error branch returns the SQL error.
func TestLookupPolicyRiskOverride_DBError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override FROM static_policies").
		WithArgs("pol-err").
		WillReturnError(fmt.Errorf("db broken"))
	_, _, err := lookupPolicyRiskOverride(context.Background(), db, "pol-err")
	if err == nil || err.Error() != "db broken" {
		t.Errorf("want 'db broken', got %v", err)
	}
}

// TestLookupActiveOverride_DBError — error branch returns the SQL error.
func TestLookupActiveOverride_DBError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("FROM policy_overrides").
		WithArgs("pol-1", "u@e.com", "t1").
		WillReturnError(fmt.Errorf("db broken"))
	_, _, err := lookupActiveOverride(context.Background(), db, "t1", "u@e.com", "pol-1")
	if err == nil || err.Error() != "db broken" {
		t.Errorf("want 'db broken', got %v", err)
	}
}

// TestBuildRicherCheckInputBlock_RiskLookupError — lookupPolicyRiskOverride
// error path: stub entry is emitted instead of dropping the match.
func TestBuildRicherCheckInputBlock_RiskLookupError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnError(fmt.Errorf("db down"))

	matches, topRisk, avail, _ := buildRicherCheckInputBlock(
		context.Background(), db, "t1", "u@e.com",
		[]sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "P1"}},
	)
	if len(matches) != 1 {
		t.Fatalf("expected stub entry, got %d matches", len(matches))
	}
	if matches[0].RiskLevel != "" || matches[0].AllowOverride {
		t.Errorf("stub entry should have empty risk/allowOverride: %+v", matches[0])
	}
	if topRisk != "" || avail != nil {
		t.Errorf("no overridable policy -> topRisk=%q avail=%v", topRisk, avail)
	}
}

// TestBuildRicherCheckInputBlock_ActiveLookupError — lookupActiveOverride
// error does not fail the block; overrideAvailable stays true with no id.
func TestBuildRicherCheckInputBlock_ActiveLookupError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override"}).
			AddRow("high", true))
	mock.ExpectQuery("FROM policy_overrides").
		WithArgs("pol-1", "u@e.com", "t1").
		WillReturnError(fmt.Errorf("active lookup broken"))

	_, _, avail, id := buildRicherCheckInputBlock(
		context.Background(), db, "t1", "u@e.com",
		[]sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "P1"}},
	)
	if avail == nil || *avail != false {
		t.Errorf("avail after err should be pointer to false, got %v", avail)
	}
	if id != "" {
		t.Errorf("overrideID should be empty on lookup error, got %q", id)
	}
}
