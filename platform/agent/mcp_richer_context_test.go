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
	"strings"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
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

// TestBuildRicherCheckInputBlock_NoOverrideOffered is #4252's check on the MCP
// check-input block: a matched policy that is overridable (high risk,
// allow_override=true) is still reported with its metadata, but no session
// override is offered or looked up, because the write answers the v11 freeze.
// The block reads the policy metadata and nothing else, so the deleted override
// lookup restored would reach an unqueued query and report override_available.
func TestBuildRicherCheckInputBlock_NoOverrideOffered(t *testing.T) {
	db, mock := newMockDB(t)
	expectScopedTx(mock, "tenant-x")
	mock.ExpectQuery("SELECT risk_level, allow_override, version FROM static_policies").
		WithArgs("pol-1").
		WillReturnRows(sqlmock.NewRows([]string{"risk_level", "allow_override", "version"}).
			AddRow("high", true, 3))
	mock.ExpectCommit()
	matches := []sharedpolicy.PolicyMatch{{PolicyID: "pol-1", PolicyName: "Bypass"}}
	m, topRisk, overrideAvail, overrideID := buildRicherCheckInputBlock(
		context.Background(), db, "tenant-x", "dev@example.com", matches)
	if len(m) != 1 || m[0].PolicyID != "pol-1" || !m[0].AllowOverride || m[0].Version != 3 {
		t.Errorf("matches not populated correctly: %+v", m)
	}
	if topRisk != "high" {
		t.Errorf("top risk = %q, want high", topRisk)
	}
	if overrideAvail != nil {
		t.Errorf("override_available = %v, want unset: no session override is offered in v11 (#4252)", *overrideAvail)
	}
	if overrideID != "" {
		t.Errorf("override_existing_id = %q, want empty", overrideID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the block made reads beyond the policy metadata: %v", err)
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

// TestMcpToolCheckPolicy_AllowedPath — happy path. The anchored engine permits
// a statement nothing detects; richer-context fields aren't applicable, but `decision_id` IS
// emitted (Plugin Batch 1 / ADR-042 / ADR-043: every governance decision
// surfaces decision_id, allow paths included, so callers can correlate
// the decision via /explain/{id} without an extra round-trip).
func TestMcpToolCheckPolicy_AllowedPath(t *testing.T) {
	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1", userID: "u1", userRole: "admin", clientID: "c1",
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

// TestMcpToolCheckPolicy_DefaultOperation — verifies default `operation=execute`.
func TestMcpToolCheckPolicy_DefaultOperation(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	sharedpolicy.SetGlobalEngine(nil)

	resp, err := mcpToolCheckPolicy(context.Background(), &mcpSession{
		tenantID: "t1", orgID: "o1",
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
	session := &mcpSession{tenantID: "t1", orgID: "o1", userID: "u1", userRole: "admin", clientID: "c1"}
	resp, err := mcpToolCheckOutput(authenticatedToolContext(session), session, map[string]interface{}{
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

// TestMcpToolCreateOverride_AnswersTheFreeze: from v11 the tool writes nothing
// (#4252). A session with a real per-user identity is answered the freeze's code
// and remedy, and a session attributed to the client-shared
// pseudo-identity is refused for its identity first, so the #3077 diagnostic
// stays the answer that applies to it.
func TestMcpToolCreateOverride_AnswersTheFreeze(t *testing.T) {
	_, err := mcpToolCreateOverride(&mcpSession{userEmail: "dev@corp.example"}, map[string]interface{}{})
	if err == nil || !strings.HasPrefix(err.Error(), legacyfreeze.ErrCode+": ") || !strings.Contains(err.Error(), "system_controls") {
		t.Fatalf("create_override with a real identity: err = %v, want the freeze code and remedy", err)
	}
	_, err = mcpToolCreateOverride(&mcpSession{userEmail: "mcp-client:client-1"}, map[string]interface{}{})
	if err == nil || strings.Contains(err.Error(), legacyfreeze.ErrCode) || !strings.Contains(err.Error(), "scoped to an individual user") {
		t.Fatalf("create_override on the shared identity: err = %v, want the identity refusal and not the freeze", err)
	}
}

// TestMcpToolDeleteOverride_AnswersTheFreeze: delete answers the freeze for every
// caller, including the shared identity create refuses for its identity.
func TestMcpToolDeleteOverride_AnswersTheFreeze(t *testing.T) {
	for _, email := range []string{"dev@corp.example", "mcp-client:client-1"} {
		_, err := mcpToolDeleteOverride(&mcpSession{userEmail: email}, map[string]interface{}{"override_id": "ov-1"})
		if err == nil || !strings.HasPrefix(err.Error(), legacyfreeze.ErrCode+": ") {
			t.Errorf("delete_override as %q: err = %v, want the freeze", email, err)
		}
	}
}
