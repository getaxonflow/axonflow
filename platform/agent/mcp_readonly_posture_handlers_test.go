// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// errExecMustNotRun is wired into the mock connector for the execute block test:
// the read-only posture must refuse a write BEFORE connector.Execute, so if the
// gate were removed and execution were reached, the handler would surface this
// error (500) instead of the posture's 403.
var errExecMustNotRun = errors.New("connector.Execute must not run under read-only posture")

// =============================================================================
// Read-only posture on the EXECUTE + CHECK-INPUT planes (#2720, epic #2716).
//
// The mcp_server_handler check_policy gate is covered by
// mcp_readonly_posture_gate_test.go. Master R3 (round 3) flagged that the
// real side-effect plane (POST /mcp/tools/execute → connector.Execute) and the
// SDK / Decision-Mode PEP gate (POST /api/v1/mcp/check-input) bypassed the
// posture. These red-on-revert tests pin the block on both: removing either
// gate flips the assertion (a write is allowed through).
// =============================================================================

// TestMCPExecuteHandler_ReadOnlyPosture_BlocksWrite: with MCP_READ_ONLY=true a
// write-path /mcp/tools/execute is refused BEFORE connector.Execute, with a
// canonical 'blocked' audit row. The connector is registered with an error so
// that, if the gate were removed and execution were reached, the response would
// be 500, the 403 proves the side effect never ran.
func TestMCPExecuteHandler_ReadOnlyPosture_BlocksWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{executeError: errExecMustNotRun})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_tools_execute", mcpVerdictBlocked)

	w := postExecute(MCPExecuteRequest{Connector: "files.create_note", Action: "INSERT", Statement: "hello"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (read-only posture block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("write-path execute block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPExecuteHandler_ReadOnlyPosture_OffAllowsWrite: with the posture off, a
// write-path execute reaches the connector and succeeds (default for every
// deployment that does not opt in).
func TestMCPExecuteHandler_ReadOnlyPosture_OffAllowsWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "false")
	registerExecConnector(t, &mockConnector{})
	quietPolicyEngines(t)

	w := postExecute(MCPExecuteRequest{Connector: "test-db", Action: "INSERT", Statement: "INSERT INTO t VALUES (1)"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with posture off, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMCPQueryHandler_ReadOnlyPosture_BlocksWriteStatement: with MCP_READ_ONLY=true
// a write DML on /mcp/resources/query is refused BEFORE connector.Query (which
// would execute it verbatim on a SQL connector), with a canonical 'blocked' row.
// The connector is wired to error so reaching Query would surface 500, the 403
// proves the statement never executed.
func TestMCPQueryHandler_ReadOnlyPosture_BlocksWriteStatement(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{queryError: errExecMustNotRun})
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_resources_query", mcpVerdictBlocked)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "DELETE FROM t WHERE 1=1"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (read-only posture block), got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("write statement block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPQueryHandler_ReadOnlyPosture_AllowsSelect: a SELECT is read-path and
// reaches the connector (allowed).
func TestMCPQueryHandler_ReadOnlyPosture_AllowsSelect(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	registerExecConnector(t, &mockConnector{})
	quietPolicyEngines(t)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "SELECT id FROM t"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for read-path SELECT under read-only posture, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMCPQueryHandler_ReadOnlyPosture_OffAllowsWrite: posture off, a write DML
// reaches the connector (default).
func TestMCPQueryHandler_ReadOnlyPosture_OffAllowsWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "false")
	registerExecConnector(t, &mockConnector{})
	quietPolicyEngines(t)

	w := postQuery(MCPQueryRequest{Connector: "test-db", Statement: "DELETE FROM t WHERE 1=1"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with posture off, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFetchApprovedData_ReadOnlyPosture_BlocksWrite: the gateway pre-check data
// fetch (gateway_handlers.go) runs the caller query through connector.Query. With
// MCP_READ_ONLY=true a write/stacked query must be refused before connector.Query.
// The connector is wired to error so reaching Query would be observable; the gate
// returns (nil, error) before the loop, so the canonical 'blocked' row is the
// proof the fetch was refused.
func TestFetchApprovedData_ReadOnlyPosture_BlocksWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	mock, restore := setUsageDBMock(t)
	defer restore()
	registerExecConnector(t, &mockConnector{queryError: errExecMustNotRun})

	expectCanonicalDecisionRow(mock, "policy_precheck_query", mcpVerdictBlocked)

	user := &User{ID: 1, Email: "u@e.com", Role: "service", TenantID: "default", OrgID: "org-1", Permissions: []string{"*"}}
	client := &Client{ID: "client-1", TenantID: "default", OrgID: "org-1"}
	res, err := fetchApprovedData(context.Background(), []string{"test-db"}, "DELETE FROM t WHERE 1=1", user, client)
	if err == nil {
		t.Fatalf("expected error (read-only posture block), got nil with res=%v", res)
	}
	if res != nil {
		t.Errorf("expected nil result on block, got %v", res)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("pre-check write block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestFetchApprovedData_ReadOnlyPosture_AllowsRead: a SELECT pre-check fetch is
// allowed and reaches the connector under read-only.
func TestFetchApprovedData_ReadOnlyPosture_AllowsRead(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	registerExecConnector(t, &mockConnector{})

	user := &User{ID: 1, Email: "u@e.com", Role: "service", TenantID: "default", OrgID: "org-1", Permissions: []string{"*"}}
	client := &Client{ID: "client-1", TenantID: "default", OrgID: "org-1"}
	res, err := fetchApprovedData(context.Background(), []string{"test-db"}, "SELECT id FROM t", user, client)
	if err != nil {
		t.Fatalf("expected SELECT pre-check fetch to succeed under read-only, got %v", err)
	}
	if _, ok := res["test-db"]; !ok {
		t.Errorf("expected approved data for test-db, got %v", res)
	}
}

// postCheckInput drives the SDK / Decision-Mode PEP request gate.
func postCheckInput(req MCPCheckInputRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, r)
	return w
}

// TestMCPCheckInputHandler_ReadOnlyPosture_BlocksWrite: with MCP_READ_ONLY=true a
// write-path check-input returns allowed=false (so a PEP never forwards the
// call) with a canonical 'blocked' audit row.
func TestMCPCheckInputHandler_ReadOnlyPosture_BlocksWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	mock, restore := setUsageDBMock(t)
	defer restore()
	quietPolicyEngines(t)

	expectCanonicalDecisionRow(mock, "mcp_check_input", mcpVerdictBlocked)

	w := postCheckInput(MCPCheckInputRequest{ConnectorType: "files.create_note", Statement: "hello", TenantID: "default"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (read-only posture block), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Allowed {
		t.Errorf("expected allowed=false on write-path under read-only posture, got true")
	}
	if resp.DecisionID == "" {
		t.Error("block must emit decision_id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("write-path check-input block did not emit a canonical 'blocked' audit row: %v", err)
	}
}

// TestMCPCheckInputHandler_ReadOnlyPosture_AllowsRead: a read-path check-input is
// NOT blocked by the posture and falls through to normal evaluation (allowed
// with engines nil).
func TestMCPCheckInputHandler_ReadOnlyPosture_AllowsRead(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "true")
	quietPolicyEngines(t)

	w := postCheckInput(MCPCheckInputRequest{ConnectorType: "files.read_note", Statement: "note-1", TenantID: "default"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on read-path under read-only posture, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true on read-path, got false (block_reason=%q)", resp.BlockReason)
	}
}

// TestMCPCheckInputHandler_ReadOnlyPosture_OffAllowsWrite: posture off, a
// write-path check-input is allowed (default).
func TestMCPCheckInputHandler_ReadOnlyPosture_OffAllowsWrite(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()
	t.Setenv(EnvMCPReadOnly, "false")
	quietPolicyEngines(t)

	w := postCheckInput(MCPCheckInputRequest{ConnectorType: "files.create_note", Statement: "hello", TenantID: "default"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with posture off, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true with posture off, got false (block_reason=%q)", resp.BlockReason)
	}
}
