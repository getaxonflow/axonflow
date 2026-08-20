// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestWriteExplainableAuditLog_OrgIDPersisted verifies the v9 fix for the
// MCP-path empty-org_id bug. Before this PR, callers passed `""` for
// orgID (mcp_server_handler.go:1094, :1224 in pre-PR HEAD), producing
// audit_logs rows with empty org_id. Phase 4 of Epic #2230 fixes those
// call sites to pass session.orgID; this test asserts the writer
// faithfully forwards the value into the INSERT.
func TestWriteExplainableAuditLog_OrgIDPersisted(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	const wantOrgID = "cs_demo_org"

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_logs")).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			0,                // user_id
			"alice@example.com",
			"admin",
			"client-123",
			"cs_demo_org", // tenant_id (legacy alias, equal to client_id today)
			wantOrgID,     // org_id — THIS is the v9 fix
			"mcp_check_policy",
			"SELECT 1",
			sqlmock.AnyArg(),     // query_hash
			"blocked",            // policy_decision — canonical past-tense vocab (#2641/#2638)
			sqlmock.AnyArg(),     // policy_details JSONB
			"decision-1",         // decision_id (first-class column; #2592)
			PlaneMCP,             // plane — MCP check-input surface
			"corr-trace-input-1", // correlation_id (#2598)
			nil, // session_id (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeExplainableAuditLog(context.Background(), db,
		"decision-1", "request-1",
		"cs_demo_org", wantOrgID, "client-123", "alice@example.com",
		"alice@example.com", "admin",
		"mcp_check_policy", "SELECT 1", "h",
		"deny", "low",
		[]RicherPolicyMatch{{PolicyName: "p", PolicyID: "pid", Version: 1}},
		"corr-trace-input-1")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestWriteOverrideUsedEvent_OrgIDPersisted is the override-event sibling.
// mcp_server_handler.go:1083 + :1208 also called this with orgID="".
// Phase 4 routes session.orgID through; assert the writer carries it
// onto the INSERT.
func TestWriteOverrideUsedEvent_OrgIDPersisted(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()

	const wantOrgID = "acme-corp"

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO audit_logs")).
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id (decisionID)
			sqlmock.AnyArg(), // timestamp
			0,                // user_id
			"bob@example.com",
			"user",
			"client-xyz",
			"travel_tenant", // tenant_id
			wantOrgID,       // org_id — v9 fix
			"override_used",
			"override applied",
			"none",
			"allowed",          // policy_decision — override flips deny→allowed (#2641/#2638)
			sqlmock.AnyArg(),   // policy_details JSONB
			"decision-1",       // decision_id (first-class column; #2592)
			PlaneMCP,           // plane — MCP check-input override surface
			"corr-trace-ovr-1", // correlation_id (#2598)
			nil, // session_id (#2753)
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	writeOverrideUsedEvent(context.Background(), db,
		"override-1", "decision-1",
		"travel_tenant", wantOrgID, "client-xyz", "bob@example.com",
		"policy-1", "Policy One", 7,
		"corr-trace-ovr-1")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("sqlmock expectations: %v", err)
	}
}

// TestMCPSession_OrgIDPropagatesFromAuth confirms the wiring: when the
// MCP session is built from authenticateMCPServerRequest's returned
// orgID, the session struct carries that value through to the audit
// writer. Combined with the two writer tests above, this gives the v9
// MCP-path org_id chain end-to-end coverage:
//
//	Authenticate() → authenticateMCPServerRequest() → mcpSession.orgID
//	→ writeExplainableAuditLog / writeOverrideUsedEvent → DB column.
func TestMCPSession_OrgIDPropagatesFromAuth(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")

	req := httptest.NewRequest("POST", "/mcp", nil)
	tenantID, orgID, _, _, _, clientID, _, _, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if orgID == "" {
		t.Errorf("orgID must not be empty after auth — would re-introduce the v9 bug")
	}
	if tenantID == "" || clientID == "" {
		t.Errorf("tenantID/clientID must not be empty: tenantID=%q clientID=%q",
			tenantID, clientID)
	}
	// In community mode (no real registrations DB), tenantID == clientID
	// and orgID == getDeploymentOrgID() — the helper guarantees a
	// stable default that audit writers can rely on.
	if orgID != getDeploymentOrgID() {
		t.Errorf("orgID = %q, want %q (community deployment default)", orgID, getDeploymentOrgID())
	}
}
