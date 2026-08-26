// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Response-plane capability scoping (#2955, sub-issue of epic #2905): the
// check-output plane must key capability scoping off the caller-sent (server,
// tool) split — MCPCheckOutputRequest.ConnectorType is the SERVER axis and the
// new MCPCheckOutputRequest.Tool is the sub-tool — exactly as check-input does
// since #2916. Before #2955 the handler duplicated ConnectorType into
// evaluateOutputPolicies' toolIdentity param, so a text-document tool's output
// was scored against the bare server name (never a text-document tool) and the
// execution-class response scanners ran again on documentation — reintroducing
// the #2802 documentation-FP class for the langgraph de-concat SDKs.
//
// These tests prove, deterministically:
//   1. Tool present + text-document → the execution-class response SQLi scan is
//      scoped OUT (capability relaxation keys off req.Tool).
//   2. Tool absent → FULL (fail-closed) evaluation; the scan runs. No silent
//      widen, no fallback from ConnectorType.
//   3. The SERVER axis must never relax scoping: a text-document-looking
//      connector_type with an empty tool still gets full evaluation. This case
//      is the direct regression guard against the pre-#2955 duplication bug —
//      it PASSES only when the handler passes req.Tool (not req.ConnectorType).
//   4. Both identity axes land on the canonical audit row as
//      policy_details.tool_server / policy_details.tool_name.

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/sqli"
	sharedpolicy "axonflow/platform/shared/policy"
)

// installBlockingSQLiResponseMiddleware swaps the global SQLi middleware for one
// in response=basic + block mode, and restores the prior instance after the
// test. The serving agent never wires block mode by default (the global
// middleware is lazily DefaultConfig, BlockOnDetection=false), so the test
// installs it explicitly to make the execution-class response scan an OBSERVABLE
// allow/block signal — the only response-plane detector gated by tool identity.
func installBlockingSQLiResponseMiddleware(t *testing.T) {
	t.Helper()
	old := sqli.GetGlobalMiddleware()
	cfg := sqli.DefaultConfig().WithBlockOnDetection(true) // ResponseMode defaults to basic
	if err := sqli.InitGlobalMiddleware(cfg); err != nil {
		t.Fatalf("InitGlobalMiddleware: %v", err)
	}
	t.Cleanup(func() { sqli.SetGlobalMiddleware(old) })
}

// checkOutputScan drives POST /api/v1/mcp/check-output with the given
// (connector_type, tool) and a message the SQLi response scanner detects,
// returning the HTTP status. A 403 => the execution-class scan RAN (full
// evaluation); a 200 => it was scoped out (text-document relaxation).
func checkOutputScan(t *testing.T, connectorType, tool string) int {
	t.Helper()
	// Proven-detected response SQLi artifact (sqli/middleware_test.go).
	const sqliMessage = "Error: syntax near ' UNION SELECT * FROM admin_passwords--"
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: connectorType,
		Tool:          tool,
		Message:       sqliMessage,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)
	return w.Code
}

func TestCheckOutput_ToolIdentity_ScopesExecutionClassResponseScan(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	// Isolate the SQLi-middleware discriminator: disable the MCP static/PII
	// response pass so detectionGate is false and steps 2-3 of
	// evaluateOutputPolicies never run. The execution-class SQLi scan (step 1)
	// is independent of that gate and is the only detector tool identity scopes
	// on the response plane.
	t.Setenv("MCP_STATIC_POLICIES_ENABLED", "false")
	// A non-nil global engine is required for IsTextDocumentTool classification
	// (it consults the built-in text-document registry, no DB load). Reuse the
	// proven engine installer; its request-phase policy is never loaded here
	// because the response static pass is disabled above.
	installSharedEngineWithPolicyRows(t)
	installBlockingSQLiResponseMiddleware(t)
	installUsageDBMock(t) // best-effort audit writes; unmatched inserts are logged + ignored

	// connector_type is a SERVER name that is NOT a text-document tool.
	const server = "atlassian_remote"

	// 1. Tool present + text-document: the execution-class scan is scoped out.
	//    Under the pre-#2955 bug (connector_type duplicated into toolIdentity)
	//    IsTextDocumentTool("atlassian_remote") is false and this would 403.
	if code := checkOutputScan(t, server, "getConfluencePage"); code != http.StatusOK {
		t.Errorf("text-document tool: expected 200 (execution-class scan scoped out), got %d — scoping is not keying off req.Tool", code)
	}

	// 2. Tool absent: FULL (fail-closed) evaluation; the scan runs and blocks.
	if code := checkOutputScan(t, server, ""); code != http.StatusForbidden {
		t.Errorf("absent tool: expected 403 (full fail-closed evaluation), got %d — a missing tool must NOT silently widen", code)
	}

	// 3. SERVER axis must not relax scoping: a text-document-looking
	//    connector_type with an empty tool still gets full evaluation. This is
	//    the regression guard — it 200s (wrongly) only if the handler feeds
	//    req.ConnectorType into toolIdentity (the pre-#2955 duplication bug).
	if code := checkOutputScan(t, "getConfluencePage", ""); code != http.StatusForbidden {
		t.Errorf("server axis relaxed scoping: expected 403 with a text-document-looking connector_type but empty tool, got %d — the server name must never classify a tool", code)
	}
}

// toolIdentityDetails is a sqlmock argument matcher over the writeDecisionAuditLog
// policy_details JSON column, asserting it carries the split (tool_server,
// tool_name) identity for the check-output decision row.
type toolIdentityDetails struct {
	wantServer string
	wantTool   string
}

func (m toolIdentityDetails) Match(v driver.Value) bool {
	var raw []byte
	switch t := v.(type) {
	case []byte:
		raw = t
	case string:
		raw = []byte(t)
	default:
		return false
	}
	var details map[string]interface{}
	if err := json.Unmarshal(raw, &details); err != nil {
		return false
	}
	return details["tool_server"] == m.wantServer && details["tool_name"] == m.wantTool
}

func TestCheckOutput_ToolIdentity_PersistedOnAuditRow(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	disablePolicyEngines(t)
	disableOutputCheckers(t)
	mock := installUsageDBMock(t)

	// The canonical allow row goes through recordDecideDecision ->
	// writeDecisionAuditLog. Pin policy_details (14th arg, per
	// expectDecideWriterRow's column layout) to the split identity; every other
	// column is free.
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), // id
			sqlmock.AnyArg(), // request_id
			sqlmock.AnyArg(), // timestamp
			sqlmock.AnyArg(), // user_id
			sqlmock.AnyArg(), // user_email
			sqlmock.AnyArg(), // user_role
			sqlmock.AnyArg(), // client_id
			sqlmock.AnyArg(), // tenant_id
			sqlmock.AnyArg(), // org_id
			sqlmock.AnyArg(), // request_type
			sqlmock.AnyArg(), // query
			sqlmock.AnyArg(), // query_hash
			sqlmock.AnyArg(), // policy_decision
			toolIdentityDetails{wantServer: "postgres", wantTool: "query"}, // policy_details
			sqlmock.AnyArg(), // decision_id
			sqlmock.AnyArg(), // plane
			sqlmock.AnyArg(), // obligations
			sqlmock.AnyArg(), // correlation_id
			sqlmock.AnyArg(), // redacted_fields
			sqlmock.AnyArg(), // session_id
			sqlmock.AnyArg(), // response_time_ms (#3424): handler elapsed time
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Tool:          "query",
		Message:       "1 row affected",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (allow), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("check-output allow row did not persist policy_details.tool_server/tool_name: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Sibling plane: the MCP-server stdio `check_output` JSON-RPC tool
// (mcpToolCheckOutput). #2916 fixed BOTH the REST check-input handler AND the
// stdio check_policy tool; #2955 must mirror it on BOTH the REST check-output
// handler (above) AND this stdio check_output tool — otherwise the exact
// connector_type→toolIdentity duplication survives on the plane the Claude Code
// plugin's PostToolUse hook actually calls over the wire.
// ---------------------------------------------------------------------------

func TestMcpToolCheckOutput_ToolIdentity_ScopesExecutionClassResponseScan(t *testing.T) {
	// Same isolation as the REST scoping test: disable the static/PII pass so the
	// SQLi middleware scan is the sole tool-identity-gated discriminator, and
	// install a non-nil engine for IsTextDocumentTool classification.
	t.Setenv("MCP_STATIC_POLICIES_ENABLED", "false")
	installSharedEngineWithPolicyRows(t)
	installBlockingSQLiResponseMiddleware(t)
	installUsageDBMock(t) // best-effort block audit writes; unmatched inserts logged + ignored

	const sqliMessage = "Error: syntax near ' UNION SELECT * FROM admin_passwords--"
	allowed := func(connectorType, tool string) bool {
		t.Helper()
		resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
			tenantID: "t-1", orgID: "o-1", clientID: "c-1", userID: "u-1", userRole: "admin", userEmail: "u@e.com",
		}, map[string]interface{}{
			"connector_type": connectorType,
			"tool":           tool,
			"message":        sqliMessage,
		})
		if err != nil {
			t.Fatalf("mcpToolCheckOutput(%q,%q): %v", connectorType, tool, err)
		}
		m, _ := resp.(map[string]interface{})
		v, _ := m["allowed"].(bool)
		return v
	}

	const server = "atlassian_remote" // a server name that is NOT a text-document tool

	// Text-document tool → execution-class scan scoped out → allowed. Under the
	// pre-#2955 bug (connector_type duplicated into toolIdentity) this would block.
	if !allowed(server, "getConfluencePage") {
		t.Error("text-document tool: expected allowed=true (execution-class scan scoped out) — stdio scoping is not keying off args[\"tool\"]")
	}
	// Absent tool → full (fail-closed) evaluation → the scan runs and blocks.
	if allowed(server, "") {
		t.Error("absent tool: expected allowed=false (full fail-closed evaluation) — a missing tool must NOT silently widen on the stdio plane")
	}
	// Server axis must not relax scoping: a text-document-looking connector_type
	// with an empty tool still gets full evaluation (regression guard for the
	// pre-#2955 duplication).
	if allowed("getConfluencePage", "") {
		t.Error("server axis relaxed scoping: expected allowed=false with a text-document-looking connector_type but empty tool")
	}
}

func TestMcpToolCheckOutput_ToolIdentity_PersistedOnAuditRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	origDB := usageDB
	usageDB = db
	defer func() { usageDB = origDB }()

	// SQLi block on the stdio plane routes through writeMCPDecisionAudit (the
	// #2641 canonical "blocked" row). Nil the engine so only the SQLi scan runs,
	// and install it in block mode.
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(origEngine)
	origSQLi := sqli.GetGlobalMiddleware()
	defer sqli.SetGlobalMiddleware(origSQLi)
	mw, err := sqli.NewScanningMiddleware(sqli.WithMiddlewareConfig(sqli.DefaultConfig().WithBlockOnDetection(true)))
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}
	sqli.SetGlobalMiddleware(mw)

	// policy_details is the 14th arg of the writeMCPDecisionAudit INSERT
	// (mcp_richer_context.go:568-574). Pin it to the split identity; every other
	// column is free.
	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // id, request_id, timestamp, user_id
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // user_email, user_role, client_id, tenant_id, org_id
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // request_type, query, query_hash
			sqlmock.AnyArg(), // policy_decision
			toolIdentityDetails{wantServer: "claude_code", wantTool: "Bash"}, // policy_details (14th)
			sqlmock.AnyArg(), sqlmock.AnyArg(), // decision_id, plane
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), // correlation_id, redacted_fields, session_id
			sqlmock.AnyArg(), // response_time_ms (#3424): mcpToolCheckOutput's own elapsed time
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := mcpToolCheckOutput(context.Background(), &mcpSession{
		tenantID: "t-1", orgID: "o-1", clientID: "c-1", userID: "u-1", userRole: "admin", userEmail: "u@e.com",
	}, map[string]interface{}{
		"connector_type": "claude_code",
		"tool":           "Bash",
		"response_data": []interface{}{
			map[string]interface{}{"id": 1, "data": "admin' UNION SELECT password FROM users--"},
		},
	})
	if err != nil {
		t.Fatalf("mcpToolCheckOutput: %v", err)
	}
	if m, _ := resp.(map[string]interface{}); m["allowed"] != false {
		t.Fatalf("expected allowed=false on SQLi block, got %v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("stdio check_output block row did not persist policy_details.tool_server/tool_name: %v", err)
	}
}
