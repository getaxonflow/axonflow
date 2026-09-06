// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	sharedaudit "axonflow/platform/shared/audit"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"axonflow/platform/agent/sqli"
	sharedpolicy "axonflow/platform/shared/policy"
	"github.com/DATA-DOG/go-sqlmock"
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

// expectScopedTx registers the BEGIN + SET LOCAL prologue of one
// rls.WithOrgScope transaction (#3048 — the richer-context lookups now run
// org-scoped). Follow with the in-tx query expectation(s) and then
// mock.ExpectCommit() (or ExpectRollback() when the closure errors).
func expectScopedTx(mock sqlmock.Sqlmock, org string) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app\.current_org_id'`).
		WithArgs(org).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// TestLookupPolicyMeta_HappyPath covers the common case: a matching
// policy row returns its risk_level + allow_override + version.
func TestLookupPolicyMeta_HappyPath(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("high", true, 7))

	risk, ao, version, err := lookupPolicyMeta(context.Background(), db, "", "pol-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if risk != "high" || !ao || version != 7 {
		t.Errorf("got (%q, %v, %d), want (high, true, 7)", risk, ao, version)
	}
}

// TestLookupPolicyMeta_NotFoundReturnsEmpty asserts ErrNoRows maps
// to ("", false, 0, nil) — dynamic policies aren't in static_policies so the
// caller can fall through gracefully.
func TestLookupPolicyMeta_NotFoundReturnsEmpty(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-missing").
		WillReturnError(sql.ErrNoRows)

	risk, ao, version, err := lookupPolicyMeta(context.Background(), db, "", "pol-missing")
	if err != nil || risk != "" || ao || version != 0 {
		t.Errorf("not-found should return (\"\", false, 0, nil); got (%q, %v, %d, %v)", risk, ao, version, err)
	}
}

// TestLookupPolicyMeta_ScopedFallsBackToGlobal — #3048: with a caller org
// scope, a miss in the org scope retries in the 'global' scope so system-tier
// policy metadata stays resolvable under app-role RLS.
func TestLookupPolicyMeta_ScopedFallsBackToGlobal(t *testing.T) {
	db, mock := newMockDB(t)
	// Org-scope pass: no row (tenant scope can't see the global system row).
	expectScopedTx(mock, "org-1")
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("sys_pol").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	// Global-scope pass: hit.
	expectScopedTx(mock, GlobalOrgSentinel)
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("sys_pol").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("high", true, 7))
	mock.ExpectCommit()

	risk, ao, version, err := lookupPolicyMeta(context.Background(), db, "org-1", "sys_pol")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if risk != "high" || !ao || version != 7 {
		t.Errorf("got (%q, %v, %d), want (high, true, 7)", risk, ao, version)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestLookupActiveOverride_HappyPath — override exists for tenant+user+policy.
// lookupActiveOverride joins via static_policies so both slug and UUID resolve
// to the same override row.
func TestLookupActiveOverride_HappyPath(t *testing.T) {
	db, mock := newMockDB(t)
	// #3048 scoped shape: resolve the policy UUID in the caller org scope,
	// then read the override row in the same scope.
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-slug").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-pol-slug"))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT po\\.id\\s+FROM policy_overrides po").
		WithArgs("uuid-pol-slug", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-1"))
	mock.ExpectCommit()

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
	// Resolve misses in the org scope AND the 'global' scope → not found,
	// without ever consulting policy_overrides.
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-x").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()
	expectScopedTx(mock, GlobalOrgSentinel)
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-x").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

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
// override_existing_id empty. Version is propagated through to the
// RicherPolicyMatch (#1983 / α1).
func TestBuildRicherCheckInputBlock_NoOverride(t *testing.T) {
	db, mock := newMockDB(t)
	// #3048 scoped shape: meta lookup, then override lookup (resolve UUID +
	// override read), each in its own org-scoped transaction.
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("high", true, 3))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-pol-1"))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT po\\.id\\s+FROM policy_overrides po").
		WithArgs("uuid-pol-1", "dev@example.com", "tenant-x").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	matches := []sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "Bypass"}}
	m, topRisk, overrideAvail, overrideID := buildRicherCheckInputBlock(
		context.Background(), db, "tenant-x", "dev@example.com", matches)

	if len(m) != 1 || m[0].PolicyID != "pol-1" || !m[0].AllowOverride {
		t.Errorf("matches not populated correctly: %+v", m)
	}
	if m[0].Version != 3 {
		t.Errorf("Version = %d, want 3 (#1983: must propagate live policy version)", m[0].Version)
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
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("medium", true, 1))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-pol-1"))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT po\\.id\\s+FROM policy_overrides po").
		WithArgs("uuid-pol-1", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-42"))
	mock.ExpectCommit()

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
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-crit").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("critical", false, 9))
	mock.ExpectCommit()

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
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-pol-1"))
	mock.ExpectCommit()
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT po\\.id\\s+FROM policy_overrides po").
		WithArgs("uuid-pol-1", "dev@example.com", "tenant-x").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("ov-7"))
	mock.ExpectCommit()

	matches := []RicherPolicyMatch{
		{PolicyID: "pol-1", PolicyName: "Bypass", RiskLevel: "medium", AllowOverride: true, Version: 4},
	}
	id, overridden, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "dev@example.com", matches)
	if !applied || id != "ov-7" {
		t.Errorf("expected applied=(true, ov-7); got (%v, %q)", applied, id)
	}
	if overridden == nil || overridden.PolicyID != "pol-1" || overridden.Version != 4 {
		t.Errorf("overridden match wrong: %+v (want PolicyID=pol-1, Version=4)", overridden)
	}
}

// TestApplyOverrideToCheckInputBlock_CriticalNoFlip — critical-risk matches
// are skipped entirely; no DB lookup fires.
func TestApplyOverrideToCheckInputBlock_CriticalNoFlip(t *testing.T) {
	db, _ := newMockDB(t) // no ExpectQuery — lookup must not fire
	matches := []RicherPolicyMatch{
		{PolicyID: "pol-crit", PolicyName: "Catastrophic", RiskLevel: "critical", AllowOverride: false},
	}
	_, _, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "dev@example.com", matches)
	if applied {
		t.Error("critical-risk match must never trigger override apply")
	}
}

// TestApplyOverrideToCheckInputBlock_LookupError — DB error on
// lookupActiveOverride is logged and the loop continues to the next
// match. Returns ("", nil, false) when no match yields a usable override.
func TestApplyOverrideToCheckInputBlock_LookupError(t *testing.T) {
	db, mock := newMockDB(t)
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT sp\\.id FROM static_policies sp").
		WithArgs("pol-1").
		WillReturnError(fmt.Errorf("db down"))
	mock.ExpectRollback()

	matches := []RicherPolicyMatch{
		{PolicyID: "pol-1", PolicyName: "Bypass", RiskLevel: "medium", AllowOverride: true, Version: 4},
	}
	id, overridden, applied := applyOverrideToCheckInputBlock(context.Background(), db,
		"tenant-x", "dev@example.com", matches)
	if applied || overridden != nil || id != "" {
		t.Errorf("DB-error must not flip applied; got (%q, %v, %v)", id, overridden, applied)
	}
}

// TestApplyOverrideToCheckInputBlock_NoUserEmail — without a user identity
// we can't scope the lookup, so apply=false without consulting DB.
func TestApplyOverrideToCheckInputBlock_NoUserEmail(t *testing.T) {
	db, _ := newMockDB(t)
	matches := []RicherPolicyMatch{
		{PolicyID: "pol-1", RiskLevel: "medium", AllowOverride: true},
	}
	_, _, applied := applyOverrideToCheckInputBlock(context.Background(), db,
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
			sqlmock.AnyArg(),  // id
			"req-1",           // request_id
			sqlmock.AnyArg(),  // timestamp
			0,                 // user_id (email is not numeric → 0)
			"u@e.com",         // user_email
			"user",            // user_role
			"c1",              // client_id
			"t1",              // tenant_id
			"o1",              // org_id
			"mcp_check_input", // request_type
			"SELECT 1",        // query
			"h1",              // query_hash
			"blocked",         // policy_decision (#2641/#2638)
			sqlmock.AnyArg(),  // policy_details JSON
			"dec-1",           // decision_id (first-class column; #2592)
			PlaneMCP,          // plane — MCP check-input surface
			"corr-trace-1",    // correlation_id (#2598)
			nil,               // session_id (#2753)
			sqlmock.AnyArg(),  // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"dec-1", "req-1",
		"t1", "o1", "c1", "u@e.com",
		"", "user",
		"mcp_check_input", "SELECT 1", "h1",
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "Name"}},
		"corr-trace-1",
		sharedaudit.LatencyUnmeasured,
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
		"t", "q", "h", "r", "high", nil, "", sharedaudit.LatencyUnmeasured)

	db, mock := newMockDB(t)
	writeExplainableAuditLog(context.Background(), db,
		"", "req-1", "t1", "o1", "c1", "u", "0", "user",
		"t", "q", "h", "r", "high", nil, "", sharedaudit.LatencyUnmeasured)
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
		"ov-1", "dec-1", "t1", "o1", "c1", "u@e.com",
		"pol-1", "Policy 1", 5, "")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestWriteOverrideUsedEvent_NilDBOrEmptyOverride — guards against writes
// without a usable override id.
func TestWriteOverrideUsedEvent_NilDBOrEmptyOverride(t *testing.T) {
	writeOverrideUsedEvent(context.Background(), nil,
		"ov-1", "dec-1", "t1", "o1", "c1", "u@e.com",
		"pol-1", "Policy 1", 5, "")

	db, mock := newMockDB(t)
	writeOverrideUsedEvent(context.Background(), db,
		"", "dec-1", "t1", "o1", "c1", "u@e.com",
		"pol-1", "Policy 1", 5, "")
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
			sqlmock.AnyArg(),         // id
			"dec-1",                  // request_id = decisionID
			sqlmock.AnyArg(),         // timestamp
			0,                        // user_id
			"unknown@axonflow.local", // user_email fallback
			"user",                   // user_role
			"unknown",                // client_id fallback
			"unknown",                // tenant_id fallback
			"",                       // org_id (no fallback)
			"override_used",          // request_type
			"override applied",       // query
			"none",                   // query_hash
			"allowed",                // policy_decision (#2641/#2638)
			sqlmock.AnyArg(),         // policy_details JSON
			"dec-1",                  // decision_id (first-class column; #2592)
			PlaneMCP,                 // plane — MCP check-input override surface
			"corr-fb-ovr",            // correlation_id (#2598)
			nil,                      // session_id (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeOverrideUsedEvent(context.Background(), db,
		"ov-1", "dec-1", "", "", "", "",
		"", "", 0, "corr-fb-ovr")

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
			sqlmock.AnyArg(),         // id
			"req-1",                  // request_id
			sqlmock.AnyArg(),         // timestamp
			42,                       // user_id parsed from numeric string
			"unknown@axonflow.local", // user_email fallback
			"unknown",                // user_role fallback — honest label for an unresolved role (RBAC-1 #2920)
			"unknown",                // client_id fallback
			"unknown",                // tenant_id fallback
			"",                       // org_id (no fallback)
			"mcp_check_input",
			"q",
			"h",
			"blocked",
			sqlmock.AnyArg(),
			"dec-1",          // decision_id (first-class column; #2592)
			PlaneMCP,         // plane - MCP check-input surface
			"corr-fb-exp",    // correlation_id (#2598)
			nil,              // session_id (#2753)
			sqlmock.AnyArg(), // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"dec-1", "req-1",
		"", "", "", "",
		"42", "",
		"mcp_check_input", "q", "h",
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "n1"}},
		"corr-fb-exp",
		sharedaudit.LatencyUnmeasured,
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
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{}, pepHandshakeResolution{}); err == nil {
		t.Error("expected error when both args missing")
	}
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{
		"connector_type": "postgresql",
	}, pepHandshakeResolution{}); err == nil {
		t.Error("expected error when statement missing")
	}
	if _, err := mcpToolCheckPolicy(ctx, &mcpSession{}, map[string]interface{}{
		"statement": "SELECT 1",
	}, pepHandshakeResolution{}); err == nil {
		t.Error("expected error when connector_type missing")
	}
}

// TestMcpToolCheckOutput_MissingArgs — connector_type required.
func TestMcpToolCheckOutput_MissingArgs(t *testing.T) {
	if _, err := mcpToolCheckOutput(context.Background(), &mcpSession{}, map[string]interface{}{}, pepHandshakeResolution{}); err == nil {
		t.Error("expected error when connector_type missing")
	}
}

// TestMcpToolCheckPolicy_AllowedPath — happy path. Dynamic evaluator returns
// allowed; richer-context fields aren't applicable, but `decision_id` IS
// emitted (Plugin Batch 1 / ADR-042 / ADR-043: every governance decision
// surfaces decision_id, allow paths included, so callers can correlate
// the decision via /explain/{id} without an extra round-trip).
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
	}, pepHandshakeResolution{})
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
	id, hasID := m["decision_id"].(string)
	if !hasID {
		t.Error("allowed path must emit decision_id (Plugin Batch 1 / ADR-042)")
	}
	if id == "" {
		t.Error("allowed path emitted decision_id but it was empty")
	}
	// No richer-context fields on the allow path — those only fire when
	// the engine matched a blocking policy.
	for _, k := range []string{"block_reason", "blocked_by", "risk_level", "policy_matches", "override_available"} {
		if _, set := m[k]; set {
			t.Errorf("allowed path leaked %q field: %v", k, m[k])
		}
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
	}, pepHandshakeResolution{})
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
	}, pepHandshakeResolution{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("expected non-nil response")
	}
}

// TestMcpToolCheckOutput_AllowedPath — verifies response-data parsing + the
// short-circuit when no policies fire. Allow paths emit decision_id too
// (Plugin Batch 1 / ADR-042 / ADR-043 — every governance decision is
// addressable via /explain/{id}).
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
	}, pepHandshakeResolution{})
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
	id, hasID := m["decision_id"].(string)
	if !hasID {
		t.Error("allowed path must emit decision_id (Plugin Batch 1 / ADR-042)")
	}
	if id == "" {
		t.Error("allowed path emitted decision_id but it was empty")
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
	}, pepHandshakeResolution{})
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
	}, pepHandshakeResolution{})
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

// TestLookupPolicyMeta_DBError — error branch returns the SQL error.
func TestLookupPolicyMeta_DBError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-err").
		WillReturnError(fmt.Errorf("db broken"))
	_, _, _, err := lookupPolicyMeta(context.Background(), db, "", "pol-err")
	if err == nil || err.Error() != "db broken" {
		t.Errorf("want 'db broken', got %v", err)
	}
}

// TestLookupActiveOverride_DBError — error branch returns the SQL error.
func TestLookupActiveOverride_DBError(t *testing.T) {
	db, mock := newMockDB(t)
	expectScopedTx(mock, "t1")
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnError(fmt.Errorf("db broken"))
	mock.ExpectRollback()
	_, _, err := lookupActiveOverride(context.Background(), db, "t1", "u@e.com", "pol-1")
	if err == nil || err.Error() != "db broken" {
		t.Errorf("want 'db broken', got %v", err)
	}
}

// TestBuildRicherCheckInputBlock_RiskLookupError — lookupPolicyMeta
// error path: stub entry is emitted instead of dropping the match.
func TestBuildRicherCheckInputBlock_RiskLookupError(t *testing.T) {
	db, mock := newMockDB(t)
	expectScopedTx(mock, "t1")
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnError(fmt.Errorf("db down"))
	mock.ExpectRollback()

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
	expectScopedTx(mock, "t1")
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("high", true, 2))
	mock.ExpectCommit()
	expectScopedTx(mock, "t1")
	mock.ExpectQuery("FROM static_policies").
		WithArgs("pol-1").
		WillReturnError(fmt.Errorf("active lookup broken"))
	mock.ExpectRollback()

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

// jsonCaptureArg is a sqlmock matcher that captures a []byte argument
// (typically marshaled JSON) into a target slice for later assertion.
type jsonCaptureArg struct {
	dst *[]byte
}

func (j jsonCaptureArg) Match(value driver.Value) bool {
	switch v := value.(type) {
	case []byte:
		*j.dst = append([]byte(nil), v...)
	case string:
		*j.dst = []byte(v)
	default:
		return true // accept any shape — we just want the capture
	}
	return true
}

// TestCollectPolicyVersions — α1: builds { policy_id → version } map from
// RicherPolicyMatch slice. Empty / no-version matches map to nil so JSONB
// emits omitempty rather than "{}".
func TestCollectPolicyVersions(t *testing.T) {
	if got := collectPolicyVersions(nil); got != nil {
		t.Errorf("nil matches: want nil, got %v", got)
	}
	if got := collectPolicyVersions([]RicherPolicyMatch{}); got != nil {
		t.Errorf("empty matches: want nil, got %v", got)
	}
	if got := collectPolicyVersions([]RicherPolicyMatch{{PolicyID: "p", Version: 0}}); got != nil {
		t.Errorf("zero-version match: want nil (omitempty), got %v", got)
	}
	got := collectPolicyVersions([]RicherPolicyMatch{
		{PolicyID: "pol-a", Version: 3},
		{PolicyID: "pol-b", Version: 5},
		{PolicyID: "pol-c", Version: 0}, // dynamic / unknown — skipped
		{PolicyID: "", Version: 9},      // no id — skipped
	})
	want := map[string]int{"pol-a": 3, "pol-b": 5}
	if len(got) != len(want) || got["pol-a"] != 3 || got["pol-b"] != 5 {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestWriteExplainableAuditLog_PolicyVersionsInJSONB — α1: when matches carry
// a non-zero Version, the JSONB blob must include both per-match
// "policy_version" (inline, via RicherPolicyMatch.Version) AND a top-level
// "policy_versions" map keyed by policy_id. Forward-only — pre-α1 matches
// with Version=0 must surface no policy_versions key (omitempty preserves
// byte-for-byte legacy shape).
func TestWriteExplainableAuditLog_PolicyVersionsInJSONB(t *testing.T) {
	cases := []struct {
		name       string
		matches    []RicherPolicyMatch
		wantTopMap map[string]int // expected top-level policy_versions map
		wantInline map[string]int // expected inline match[i].policy_version
	}{
		{
			name: "with versions",
			matches: []RicherPolicyMatch{
				{PolicyID: "pol-a", PolicyName: "A", Version: 3},
				{PolicyID: "pol-b", PolicyName: "B", Version: 5},
			},
			wantTopMap: map[string]int{"pol-a": 3, "pol-b": 5},
			wantInline: map[string]int{"pol-a": 3, "pol-b": 5},
		},
		{
			name: "no versions (pre-α1 / dynamic-only)",
			matches: []RicherPolicyMatch{
				{PolicyID: "pol-a", PolicyName: "A"},
			},
			wantTopMap: nil,
			wantInline: nil,
		},
		{
			name: "mixed — only versioned matches surface in map",
			matches: []RicherPolicyMatch{
				{PolicyID: "pol-a", PolicyName: "A", Version: 7},
				{PolicyID: "pol-b", PolicyName: "B"},
			},
			wantTopMap: map[string]int{"pol-a": 7},
			wantInline: map[string]int{"pol-a": 7},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock := newMockDB(t)

			var capturedJSON []byte
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					sqlmock.AnyArg(), "req-1", sqlmock.AnyArg(), 0,
					"u@e.com", "user", "c1", "t1", "o1",
					"mcp_check_input", "SELECT 1", "h1", "blocked",
					jsonCaptureArg{dst: &capturedJSON},
					"dec-1",          // decision_id (first-class column; #2592)
					PlaneMCP,         // plane - MCP check-input surface
					"corr-tc",        // correlation_id (#2598)
					nil,              // session_id (#2753)
					sqlmock.AnyArg(), // response_time_ms (#3424)
				).
				WillReturnResult(sqlmock.NewResult(1, 1))

			writeExplainableAuditLog(context.Background(), db,
				"dec-1", "req-1",
				"t1", "o1", "c1", "u@e.com",
				"", "user",
				"mcp_check_input", "SELECT 1", "h1",
				"blocked", "high",
				tc.matches,
				"corr-tc",
				sharedaudit.LatencyUnmeasured,
			)

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("unmet expectations: %v", err)
			}
			if len(capturedJSON) == 0 {
				t.Fatal("policy_details JSON was not captured")
			}
			var details struct {
				DecisionID     string           `json:"decision_id"`
				PolicyVersions map[string]int   `json:"policy_versions,omitempty"`
				PolicyMatches  []map[string]any `json:"policy_matches"`
			}
			if err := json.Unmarshal(capturedJSON, &details); err != nil {
				t.Fatalf("unmarshal policy_details JSON: %v", err)
			}
			if details.DecisionID != "dec-1" {
				t.Errorf("decision_id = %q, want dec-1", details.DecisionID)
			}

			// Top-level policy_versions map.
			if len(tc.wantTopMap) == 0 {
				if details.PolicyVersions != nil {
					t.Errorf("expected omitempty policy_versions, got %v", details.PolicyVersions)
				}
			} else {
				if len(details.PolicyVersions) != len(tc.wantTopMap) {
					t.Errorf("policy_versions size = %d, want %d (got %v)",
						len(details.PolicyVersions), len(tc.wantTopMap), details.PolicyVersions)
				}
				for k, v := range tc.wantTopMap {
					if details.PolicyVersions[k] != v {
						t.Errorf("policy_versions[%q] = %d, want %d", k, details.PolicyVersions[k], v)
					}
				}
			}

			// Inline per-match policy_version.
			for _, m := range details.PolicyMatches {
				pid, _ := m["policy_id"].(string)
				if want, ok := tc.wantInline[pid]; ok {
					got, _ := m["policy_version"].(float64) // JSON numbers
					if int(got) != want {
						t.Errorf("inline policy_matches[%q].policy_version = %v, want %d",
							pid, m["policy_version"], want)
					}
				} else if _, has := m["policy_version"]; has {
					t.Errorf("policy_matches[%q] should not carry policy_version (Version=0 was omitempty), got %v",
						pid, m["policy_version"])
				}
			}
		})
	}
}

// TestWriteOverrideUsedEvent_PolicyVersionInJSONB — α1: override_used events
// stamp the overridden policy's id + version into the JSONB so explain can
// surface "which version of which policy was overridden". policyID="" or
// policyVersion=0 are simply omitted (forward-only / no error path).
func TestWriteOverrideUsedEvent_PolicyVersionInJSONB(t *testing.T) {
	db, mock := newMockDB(t)
	var capturedJSON []byte
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), "dec-1", sqlmock.AnyArg(), 0,
			"u@e.com", "user", "c1", "t1", "o1",
			"override_used", "override applied", "none", "allowed",
			jsonCaptureArg{dst: &capturedJSON},
			"dec-1",   // decision_id (first-class column; #2592)
			PlaneMCP,  // plane - MCP check-input override surface
			"corr-pv", // correlation_id (#2598)
			nil,       // session_id (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeOverrideUsedEvent(context.Background(), db,
		"ov-1", "dec-1", "t1", "o1", "c1", "u@e.com",
		"pol-1", "Policy 1", 4,
		"corr-pv",
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
	var details map[string]any
	if err := json.Unmarshal(capturedJSON, &details); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, _ := details["policy_id"].(string); v != "pol-1" {
		t.Errorf("policy_id = %v, want pol-1", details["policy_id"])
	}
	if v, _ := details["policy_version"].(float64); int(v) != 4 {
		t.Errorf("policy_version = %v, want 4", details["policy_version"])
	}
}

// TestLookupPolicyVersionsByID_HappyPath — α1: batch lookup returns map for
// the policy_ids that exist; missing IDs simply don't appear.
func TestLookupPolicyVersionsByID_HappyPath(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT policy_id, version FROM static_policies").
		WillReturnRows(sqlmock.NewRows([]string{"policy_id", "version"}).
			AddRow("pol-a", 2).
			AddRow("pol-b", 11))

	got := lookupPolicyVersionsByID(context.Background(), db,
		[]string{"pol-a", "pol-b", "pol-missing"})
	if len(got) != 2 || got["pol-a"] != 2 || got["pol-b"] != 11 {
		t.Errorf("got %v, want pol-a=2 pol-b=11", got)
	}
	if _, ok := got["pol-missing"]; ok {
		t.Error("missing policy must not appear in result map")
	}
}

func TestLookupPolicyVersionsByID_NilOrEmpty(t *testing.T) {
	if got := lookupPolicyVersionsByID(context.Background(), nil, []string{"x"}); got != nil {
		t.Errorf("nil db: want nil, got %v", got)
	}
	db, _ := newMockDB(t)
	if got := lookupPolicyVersionsByID(context.Background(), db, nil); got != nil {
		t.Errorf("nil ids: want nil, got %v", got)
	}
}

func TestLookupPolicyVersionsByID_DBError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery("SELECT policy_id, version FROM static_policies").
		WillReturnError(fmt.Errorf("db down"))
	got := lookupPolicyVersionsByID(context.Background(), db, []string{"pol-a"})
	if got != nil {
		t.Errorf("DB error must return nil map, got %v", got)
	}
}

// TestLookupPolicyVersionsByID_RowScanError — α1: a malformed row
// (e.g. NULL policy_id) is logged + skipped; surviving rows still map.
func TestLookupPolicyVersionsByID_RowScanError(t *testing.T) {
	db, mock := newMockDB(t)
	// First row: scan-incompatible (string in int column simulated by
	// returning a row with a non-numeric value). Second row: well-formed.
	rows := sqlmock.NewRows([]string{"policy_id", "version"}).
		AddRow("pol-a", "not-an-int"). // Scan into NullInt64 will fail.
		AddRow("pol-b", 4)
	mock.ExpectQuery("SELECT policy_id, version FROM static_policies").
		WillReturnRows(rows)

	got := lookupPolicyVersionsByID(context.Background(), db, []string{"pol-a", "pol-b"})
	// pol-a's scan failed → skipped; pol-b ok.
	if got["pol-a"] != 0 || got["pol-b"] != 4 {
		t.Errorf("scan-error survivor map = %v, want {pol-b: 4} only", got)
	}
}

// TestWriteExplainableAuditLog_EmptyStatementFallback — covers the
// statement / statementHash placeholder fallback branches that fire when
// the upstream (e.g. mcp_check_output where there's no canonical
// statement) passes empty strings.
func TestWriteExplainableAuditLog_EmptyStatementFallback(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), "req-1", sqlmock.AnyArg(), 0,
			"u@e.com", "user", "c1", "t1", "o1",
			"mcp_check_output",
			"(empty statement)", // statement fallback
			"none",              // statementHash fallback
			"blocked",
			sqlmock.AnyArg(),
			"dec-1",          // decision_id (first-class column; #2592)
			PlaneMCP,         // plane - MCP check-input surface
			"corr-out",       // correlation_id (#2598)
			nil,              // session_id (#2753)
			sqlmock.AnyArg(), // response_time_ms (#3424)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"dec-1", "req-1",
		"t1", "o1", "c1", "u@e.com",
		"", "user",
		"mcp_check_output", "", "", // empty statement + hash
		"blocked", "high",
		[]RicherPolicyMatch{{PolicyID: "p1", PolicyName: "n", Version: 1}},
		"corr-out",
		sharedaudit.LatencyUnmeasured,
	)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestLookupPolicyVersionsByID_AllRowsHaveNullVersion — α1: when all
// rows return NULL version, the function returns nil (not empty map)
// so audit consumers see omitempty.
func TestLookupPolicyVersionsByID_AllRowsHaveNullVersion(t *testing.T) {
	db, mock := newMockDB(t)
	rows := sqlmock.NewRows([]string{"policy_id", "version"}).
		AddRow("pol-a", nil)
	mock.ExpectQuery("SELECT policy_id, version FROM static_policies").
		WillReturnRows(rows)

	got := lookupPolicyVersionsByID(context.Background(), db, []string{"pol-a"})
	if got != nil {
		t.Errorf("all-null versions: want nil, got %v", got)
	}
}
