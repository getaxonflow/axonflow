//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Tests for Community + Evaluation WCP HITL wiring.
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/license"
)

func TestInitializeWCPHITL_Community(t *testing.T) {
	// Without AXONFLOW_LICENSE_KEY, should be a no-op (community mode)
	err := InitializeWCPHITL(nil, nil)
	if err != nil {
		t.Errorf("InitializeWCPHITL() in community mode returned error: %v", err)
	}
}

func TestInitializeWCPHITL_CommunityWithAdapter(t *testing.T) {
	// Even with a real adapter, community mode (no license) should be a no-op
	adapter := &WCPPolicyAdapter{}
	err := InitializeWCPHITL(nil, adapter)
	if err != nil {
		t.Errorf("InitializeWCPHITL() with adapter in community mode returned error: %v", err)
	}
}

func TestInitializeWCPHITL_NilAdapter(t *testing.T) {
	// nil adapter should return nil regardless of tier
	err := InitializeWCPHITL(nil, nil)
	if err != nil {
		t.Errorf("InitializeWCPHITL(nil, nil) returned error: %v", err)
	}
}

// Valid-format eval license key used by the InitializeWCPHITL tests below.
//
// NOTE (#3408 sibling): this key EXPIRED on 2026-05-30, so
// license.IsEvaluationOrHigher is false for it today and the two tests below
// exercise the community (disabled) branch, not the eval branch their names
// claim. They still assert the only thing they ever asserted - that
// InitializeWCPHITL returns nil - so they are not wrong, they are weaker than
// they read. Left as-is rather than silently re-minted: replacing a fixture
// key changes which branch a pre-existing test covers, which is a decision for
// whoever owns the tier-fixture story (#3416), not a drive-by in this diff.
// The write path's own tier coverage does not depend on it - see
// TestTierGateRefusesBeforeTouchingTheDatabase in hitl_wcp_adapter_test.go,
// which injects the tier directly.
const testEvalLicenseKey = "AXON-eyJ0aWVyIjoiRXZhbHVhdGlvbiIsInRlbmFudF9pZCI6InRlc3Qtb3JnIiwic2VydmljZV9uYW1lIjoicGxhdGZvcm0iLCJzZXJ2aWNlX3R5cGUiOiJiYWNrZW5kLXNlcnZpY2UiLCJwZXJtaXNzaW9ucyI6WyJtY3A6KjoqIiwibGxtOio6KiJdLCJpc3N1ZWRfYXQiOiIyMDI2MDMwMSIsImV4cGlyZXNfYXQiOiIyMDI2MDUzMCJ9.x1bQuE-j3MDvuhIsUZ8vEDo8Z3FRhCAH9X9BsqMoRsOWrLAnnbrM7n2CKTcCWwIgXG7W4qwUeUPT-jOF-cgADQ"

func TestInitializeWCPHITL_EvalTierNilDB(t *testing.T) {
	// Set eval license key → InitializeWCPHITL should enter eval branch
	// but return nil because db is nil
	t.Setenv("AXONFLOW_LICENSE_KEY", testEvalLicenseKey)

	adapter := &WCPPolicyAdapter{}
	err := InitializeWCPHITL(nil, adapter)
	if err != nil {
		t.Errorf("InitializeWCPHITL with eval key + nil DB returned error: %v", err)
	}
}

func TestInitializeWCPHITL_EvalTierWithDB(t *testing.T) {
	t.Setenv("AXONFLOW_LICENSE_KEY", testEvalLicenseKey)

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &WCPPolicyAdapter{}
	err = InitializeWCPHITL(db, adapter)
	if err != nil {
		t.Errorf("InitializeWCPHITL with eval key + mock DB returned error: %v", err)
	}
}

func TestExpireEvalApprovals_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// RETURNING query returns expired approval rows with request_context containing workflow/step IDs
	mock.ExpectQuery("UPDATE hitl_approval_queue").WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}).
			AddRow("req-1", "tenant-1", "step-a", `{"workflow_id":"wf-1","step_id":"s-1"}`).
			AddRow("req-2", "tenant-1", "step-b", `{"workflow_id":"wf-2","step_id":"s-2"}`),
	)
	// For each expired approval: precise update workflow_steps by (workflow_id, step_id) + abort specific workflow
	mock.ExpectExec("UPDATE workflow_steps").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE workflows").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE workflow_steps").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("UPDATE workflows").WillReturnResult(sqlmock.NewResult(0, 1))

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestExpireEvalApprovals_FallbackWithoutContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// Approval without workflow_id/step_id in context — uses fallback (tenant + step_name) matching
	mock.ExpectQuery("UPDATE hitl_approval_queue").WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}).
			AddRow("req-legacy", "tenant-1", "step-a", `{}`),
	)
	// Fallback: broader workflow_steps update via tenant + step_name join
	mock.ExpectExec("UPDATE workflow_steps").WillReturnResult(sqlmock.NewResult(0, 1))
	// Fallback: broader workflow abort via step_name subquery
	mock.ExpectExec("UPDATE workflows").WillReturnResult(sqlmock.NewResult(0, 1))

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestExpireEvalApprovals_NoExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// RETURNING query returns no rows
	mock.ExpectQuery("UPDATE hitl_approval_queue").WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}),
	)

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

func TestExpireEvalApprovals_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery("UPDATE hitl_approval_queue").WillReturnError(err)

	// Should not panic, just log the error
	expireEvalApprovals(db)
}

func TestExpireEvalApprovals_WorkflowAbortError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// One expired approval with workflow context
	mock.ExpectQuery("UPDATE hitl_approval_queue").WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}).
			AddRow("req-1", "tenant-1", "step-a", `{"workflow_id":"wf-1","step_id":"s-1"}`),
	)
	// workflow_steps update succeeds (precise path)
	mock.ExpectExec("UPDATE workflow_steps").WillReturnResult(sqlmock.NewResult(0, 1))
	// workflow abort fails — should not panic
	mock.ExpectExec("UPDATE workflows").WillReturnError(fmt.Errorf("connection lost"))

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations: %v", err)
	}
}

// TestExpireEvalApprovals_WritesExpiredNotRejected is the red-on-revert guard for
// #2654: the auto-timeout path MUST write status='expired' to hitl_approval_queue
// and approval_status='expired' to workflow_steps — never 'rejected'. A timeout is
// not a human rejection, and mislabeling it as 'rejected' inflates the
// eu_ai_act_hitl_metrics rejected_count. Reverting either SET clause back to
// 'rejected' breaks the regex matchers below and fails this test.
func TestExpireEvalApprovals_WritesExpiredNotRejected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	// Queue UPDATE must set status='expired' (precise path: context has IDs).
	mock.ExpectQuery(`(?s)UPDATE hitl_approval_queue.*status = 'expired'`).WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}).
			AddRow("req-1", "tenant-1", "step-a", `{"workflow_id":"wf-1","step_id":"s-1"}`),
	)
	// Precise workflow_steps UPDATE must set approval_status='expired'.
	mock.ExpectExec(`(?s)UPDATE workflow_steps.*approval_status = 'expired'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE workflows.*status = 'aborted'`).WillReturnResult(sqlmock.NewResult(0, 1))

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations (expired-status writes regressed to 'rejected'?): %v", err)
	}
}

// TestExpireEvalApprovals_FallbackWritesExpired is the red-on-revert guard for the
// legacy fallback path (approval created before workflow_id/step_id were stored in
// context): it too must write approval_status='expired', not 'rejected' (#2654).
func TestExpireEvalApprovals_FallbackWritesExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`(?s)UPDATE hitl_approval_queue.*status = 'expired'`).WillReturnRows(
		sqlmock.NewRows([]string{"request_id", "tenant_id", "original_query", "request_context"}).
			AddRow("req-legacy", "tenant-1", "step-a", `{}`),
	)
	// Fallback workflow_steps UPDATE (tenant + step_name join) must set 'expired'.
	mock.ExpectExec(`(?s)UPDATE workflow_steps ws.*approval_status = 'expired'`).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(`(?s)UPDATE workflows.*status = 'aborted'`).WillReturnResult(sqlmock.NewResult(0, 1))

	expireEvalApprovals(db)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet expectations (fallback expired-status regressed?): %v", err)
	}
}

// hitlContains checks if s contains substr.
func hitlContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestUnentitledTierStillWiresTheAdapter is R3 round 2's pin for the blocker
// the entitlement change created on THIS build.
//
// InitializeWCPHITL used to `return nil` before SetHITLApproval when the tier
// was unentitled, leaving WCPPolicyAdapter.hitlApproval nil. The enqueue block
// in wcp_policy_adapter.go is guarded `if ... && a.hitlApproval != nil`, so a
// require_approval gate on an unentitled tier was held with ApprovalEnqueue
// left "" - and that field is `omitempty`, whose documented meaning is "no
// enqueue was attempted, the ordinary case for an allow/block decision".
//
// The refusal was therefore INDISTINGUISHABLE ON THE WIRE from an ordinary
// gate, which is the exact ambiguity approval_enqueue exists to remove. It was
// promised anyway by this file's own boot log, by the approval_enqueue enum in
// docs/api/orchestrator-api.yaml, and by two docs pages - all of which were
// describing the ENTERPRISE build, because round 1 made that build wire
// unconditionally and did not carry the change here. The edition that
// disagreed with the published contract is the one an unentitled licensee
// actually runs.
//
// No licence key is set, so the resolved tier is Community: unentitled, and
// the case a Free/Pro/Premium or Evaluation deployment now lands in.
func TestUnentitledTierStillWiresTheAdapter(t *testing.T) {
	t.Setenv("AXONFLOW_LICENSE_KEY", "")

	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &WCPPolicyAdapter{}
	if err := InitializeWCPHITL(db, adapter); err != nil {
		t.Fatalf("InitializeWCPHITL returned error: %v", err)
	}

	// Guard the premise. If the tier ever resolves as entitled here the
	// assertion below still passes but stops testing the unentitled path.
	if license.IsHITLApprovalEntitled(license.GetCurrentTier(context.Background())) {
		t.Fatal("resolved tier is entitled; this test no longer covers the unentitled path")
	}

	if adapter.hitlApproval == nil {
		t.Error("no HITL adapter was wired on an unentitled tier: the gate will be held " +
			"with approval_enqueue absent instead of \"tier_disabled\", which is " +
			"indistinguishable on the wire from an ordinary allow/block decision")
	}
}
