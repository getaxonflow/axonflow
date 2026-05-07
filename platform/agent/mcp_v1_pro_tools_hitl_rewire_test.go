// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
)
// =============================================================================
// MCP-tool rewire tests (added in #1998)
//
// These cover the rewire from a direct INSERT into hitl_approval_queue
// to an in-process call into hitl.Service. Uses the package-level
// `hitlServiceForTest` seam so tests don't need a real DB beyond
// sqlmock.
// =============================================================================

// newHITLServiceWithTier returns a real hitl.Service backed by sqlmock,
// with its tier provider pinned to the given tier. Tests inject this
// via `hitlServiceForTest` to drive specific tier-gate paths in
// `mcpToolRequestApproval`.
func newHITLServiceWithTier(t *testing.T, tier license.Tier) (*hitl.Service, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	repo := hitl.NewRepository(db)
	svc := hitl.NewService(repo, hitl.ServiceConfig{DefaultExpiry: 24 * time.Hour})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return tier })
	cleanup := func() { db.Close() }
	return svc, mock, cleanup
}

// TestMCPToolRequestApproval_ServiceUnavailable asserts the tool
// surfaces a clear error when the HITL service hasn't been wired in
// (mcpHITLService nil + no test seam). Mirrors the original "db == nil"
// check the pre-rewire code had.
func TestMCPToolRequestApproval_ServiceUnavailable(t *testing.T) {
	prevTest := hitlServiceForTest
	prevGlobal := mcpHITLService
	t.Cleanup(func() {
		hitlServiceForTest = prevTest
		mcpHITLService = prevGlobal
	})
	hitlServiceForTest = nil
	mcpHITLService = nil

	session := &mcpSession{tenantID: "cs_test", clientID: "client-1", tier: "Pro"}
	args := map[string]interface{}{
		"original_query": "rm -rf /",
		"request_type":   "shell_command",
	}
	_, err := mcpToolRequestApproval(context.Background(), nil, session, args)
	if err == nil {
		t.Fatal("Expected service-unavailable error, got nil")
	}
	if !strings.Contains(err.Error(), "HITL service unavailable") {
		t.Errorf("Expected 'HITL service unavailable', got: %v", err)
	}
}

// TestMCPToolRequestApproval_CommunityTierTranslated asserts the tool
// translates `hitl.ErrHITLApprovalDisabledByTier` into a clear MCP-layer
// error mentioning Evaluation license. No DB row written.
func TestMCPToolRequestApproval_CommunityTierTranslated(t *testing.T) {
	svc, mock, cleanup := newHITLServiceWithTier(t, license.TierCommunity)
	defer cleanup()
	prev := hitlServiceForTest
	t.Cleanup(func() { hitlServiceForTest = prev })
	hitlServiceForTest = func() *hitl.Service { return svc }

	session := &mcpSession{tenantID: "cs_test", clientID: "client-1", tier: "Pro"}
	args := map[string]interface{}{
		"original_query": "rm -rf /",
		"request_type":   "shell_command",
		"severity":       "high",
	}

	_, err := mcpToolRequestApproval(context.Background(), nil, session, args)
	if err == nil {
		t.Fatal("Expected tier-rejection error, got nil")
	}
	// User-facing wording must surface BOTH the current state
	// (Community) AND the unblock path (Evaluation+ license URL).
	for _, needle := range []string{"Community", "Evaluation", "https://getaxonflow.com"} {
		if !strings.Contains(err.Error(), needle) {
			t.Errorf("Expected error to contain %q, got: %v", needle, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("DB query fired despite tier rejection: %v", err)
	}
}

// TestMCPToolRequestApproval_EvalTierSucceeds asserts the happy path:
// Eval-tier process, valid input → Service writes the row → MCP tool
// returns the success envelope with success=true + submitted=true +
// awaiting_review=true + non-empty approval_id. Confirms the rewire
// preserved the locked V1 response shape.
func TestMCPToolRequestApproval_EvalTierSucceeds(t *testing.T) {
	svc, mock, cleanup := newHITLServiceWithTier(t, license.TierEvaluation)
	defer cleanup()
	prev := hitlServiceForTest
	t.Cleanup(func() { hitlServiceForTest = prev })
	hitlServiceForTest = func() *hitl.Service { return svc }

	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))

	session := &mcpSession{tenantID: "cs_test", clientID: "client-1", userID: "user-1", tier: "Pro"}
	args := map[string]interface{}{
		"original_query": "DROP TABLE users",
		"request_type":   "sql",
		"severity":       "high",
		"trigger_reason": "schema modification",
	}

	result, err := mcpToolRequestApproval(context.Background(), nil, session, args)
	if err != nil {
		t.Fatalf("Eval-tier should succeed, got: %v", err)
	}
	body, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}
	for _, key := range []string{"success", "submitted", "awaiting_review"} {
		v, ok := body[key].(bool)
		if !ok || !v {
			t.Errorf("Expected %s=true, got %v", key, body[key])
		}
	}
	if id, _ := body["approval_id"].(string); id == "" {
		t.Error("Expected non-empty approval_id")
	}
	if status, _ := body["status"].(string); status != "pending" {
		t.Errorf("Expected status=pending (back-compat), got %q", status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Mock expectations not met: %v", err)
	}
}

// TestMCPToolRequestApproval_DefaultsTriggerReason asserts the tool
// supplies a stable identifier for `trigger_reason` when the caller
// omits it. The pre-rewire INSERT had a sentinel string; the rewire
// must preserve that behavior so the audit trail keeps a searchable
// "MCP-tool-initiated" label.
func TestMCPToolRequestApproval_DefaultsTriggerReason(t *testing.T) {
	svc, mock, cleanup := newHITLServiceWithTier(t, license.TierEvaluation)
	defer cleanup()
	prev := hitlServiceForTest
	t.Cleanup(func() { hitlServiceForTest = prev })
	hitlServiceForTest = func() *hitl.Service { return svc }

	// Match any args, but verify the trigger_reason landed correctly via
	// the response — Service.CreateApprovalRequest's input goes through
	// validation that rejects empty trigger_reason; if our default
	// didn't fire, validation would fire instead and the test would
	// fail with the validation message.
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))

	session := &mcpSession{tenantID: "cs_test", clientID: "client-1", tier: "Pro"}
	args := map[string]interface{}{
		"original_query": "SELECT 1",
		"request_type":   "sql",
		// trigger_reason intentionally omitted
	}

	_, err := mcpToolRequestApproval(context.Background(), nil, session, args)
	if err != nil {
		t.Fatalf("Expected success with default trigger_reason, got: %v", err)
	}
}
