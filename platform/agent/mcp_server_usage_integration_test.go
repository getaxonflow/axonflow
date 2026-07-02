// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package agent

// WS-4 #2758 — write-side proof: the MCP-server governance path (the endpoint
// Claude Code's PreToolUse hook calls: POST /api/v1/mcp-server tools/call
// check_policy) emits an api_call usage_events row, RLS-scoped to the session's
// license org, under the v9 app_role connection.
//
// Before the fix this path wrote audit_logs but NEVER a usage_events row, so
// usage_daily (rolled up from usage_events) stayed empty and the portal Usage
// page read 0 for live Claude Code traffic.
//
// Boots a throwaway postgres:15 as axonflow_app_role (real RLS, NOBYPASSRLS),
// points the package usageDB at it, drives recordMCPToolCallUsage exactly as
// handleMCPToolsCall does, then polls (the write is async, non-blocking) for
// the row and asserts its identity + governance metrics.
//
// Gating: TEST_PG_INTEGRATION=1 + docker.

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/rls"
)

func TestRecordMCPToolCallUsage_WritesScopedUsageEvent(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	masterDB, err := sql.Open("postgres", env.MasterDSN)
	if err != nil {
		t.Fatalf("open master DSN: %v", err)
	}
	defer func() { _ = masterDB.Close() }()

	const org = "ws4-mcp-usage-org"
	if _, err := masterDB.Exec(`
		INSERT INTO organizations (org_id, name, license_key, tier)
		VALUES ($1, $2, $3, 'ENTERPRISE') ON CONFLICT (org_id) DO NOTHING
	`, org, org+"-name", "test-license-"+org); err != nil {
		t.Fatalf("seed organizations row: %v", err)
	}

	appRoleDB, err := sql.Open("postgres", env.AppRoleDSN)
	if err != nil {
		t.Fatalf("open app_role DSN: %v", err)
	}
	defer func() { _ = appRoleDB.Close() }()
	appRoleDB.SetMaxOpenConns(3)
	approletest.AssertCurrentUser(t, appRoleDB, "axonflow_app_role")

	// Point the package-global usage DB (read by recordMCPToolCallUsage) at the
	// app_role pool for this test, then restore.
	prev := usageDB
	usageDB = appRoleDB
	t.Cleanup(func() { usageDB = prev })

	// A blocked check_policy decision: 3 policies evaluated, one violation.
	session := &mcpSession{orgID: org, tenantID: org, clientID: "cs_plugin_key"}
	result := map[string]interface{}{"allowed": false, "policies_evaluated": 3}
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", nil)

	// Drive exactly what handleMCPToolsCall does after a served governance call.
	recordMCPToolCallUsage(req, session, "check_policy", result, nil, time.Now().Add(-8*time.Millisecond))

	// The recorder runs on a goroutine; poll the RLS-scoped read until the row
	// lands (bounded).
	ctx := context.Background()
	var (
		count    int
		evType   string
		httpPath string
		pe, pv   int
		latency  int
		clientID sql.NullString
	)
	deadline := time.Now().Add(5 * time.Second)
	for {
		scanErr := rls.WithOrgScope(ctx, appRoleDB, org, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `
				SELECT COUNT(*),
				       COALESCE(MAX(event_type), ''),
				       COALESCE(MAX(http_path), ''),
				       COALESCE(MAX(policies_evaluated), 0),
				       COALESCE(MAX(policy_violations), 0),
				       COALESCE(MAX(latency_ms), 0),
				       MAX(client_id)
				FROM usage_events
				WHERE org_id = $1 AND event_type = 'api_call'
			`, org).Scan(&count, &evType, &httpPath, &pe, &pv, &latency, &clientID)
		})
		if scanErr != nil {
			t.Fatalf("scoped usage_events read: %v", scanErr)
		}
		if count >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if count != 1 {
		t.Fatalf("usage_events api_call count = %d, want 1 (the governance path must emit exactly one row)", count)
	}
	if evType != "api_call" {
		t.Errorf("event_type = %q, want api_call", evType)
	}
	if httpPath != "/api/v1/mcp-server" {
		t.Errorf("http_path = %q, want /api/v1/mcp-server", httpPath)
	}
	if pe != 3 {
		t.Errorf("policies_evaluated = %d, want 3", pe)
	}
	if pv != 1 {
		t.Errorf("policy_violations = %d, want 1 (blocked decision)", pv)
	}
	if !clientID.Valid || clientID.String != "cs_plugin_key" {
		t.Errorf("client_id = %v, want cs_plugin_key", clientID)
	}
	if latency < 0 {
		t.Errorf("latency_ms = %d, want >= 0", latency)
	}
	t.Logf("MCP governance path wrote usage_events: count=%d type=%s path=%s policies=%d violations=%d latency=%dms client=%s",
		count, evType, httpPath, pe, pv, latency, clientID.String)
}
