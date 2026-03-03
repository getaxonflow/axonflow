//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0
//
// Tests for Community + Evaluation WCP HITL wiring.
// Issue #1082: Wire WCP require_approval action to HITL queue

package orchestrator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
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

func TestEvalWCPHITLAdapter_Fields(t *testing.T) {
	adapter := &evalWCPHITLAdapter{
		db:                  nil,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	if adapter.expiryDuration != 24*time.Hour {
		t.Errorf("Expected 24h expiry, got %v", adapter.expiryDuration)
	}
	if adapter.maxPendingPerTenant != 100 {
		t.Errorf("Expected 100 max pending, got %d", adapter.maxPendingPerTenant)
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_NilDB(t *testing.T) {
	adapter := &evalWCPHITLAdapter{
		db:                  nil,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	req := &HITLApprovalRequest{
		TenantID:      "test-tenant",
		OrgID:         "test-org",
		ClientID:      "test-client",
		UserID:        "test-user",
		StepName:      "review-step",
		PolicyID:      "pol-1",
		PolicyName:    "test-policy",
		TriggerReason: "manual review required",
		Severity:      "high",
	}

	resp, err := adapter.CreateApproval(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for nil db, got nil")
	}
	if resp != nil {
		t.Error("Expected nil response for nil db")
	}
	if err.Error() != "database connection not available" {
		t.Errorf("Expected 'database connection not available', got %q", err.Error())
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &evalWCPHITLAdapter{
		db:                  db,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	// Expect count query returning 5 (under limit)
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"count"}).AddRow(5),
	)
	// Expect INSERT
	mock.ExpectExec("INSERT INTO hitl_approval_queue").WillReturnResult(sqlmock.NewResult(1, 1))

	req := &HITLApprovalRequest{
		TenantID:       "test-tenant",
		OrgID:          "test-org",
		ClientID:       "test-client",
		UserID:         "test-user",
		StepName:       "review-step",
		PolicyID:       "pol-1",
		PolicyName:     "test-policy",
		TriggerReason:  "high risk detected",
		Severity:       "high",
		RequestContext: map[string]interface{}{"source": "test"},
	}

	resp, err := adapter.CreateApproval(context.Background(), req)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if resp == nil {
		t.Fatal("Expected non-nil response")
	}
	if resp.Status != "pending" {
		t.Errorf("Expected status 'pending', got %q", resp.Status)
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("Expected expires_at to be in the future")
	}
	if resp.ExpiresAt.After(time.Now().Add(25 * time.Hour)) {
		t.Error("Expected expires_at within ~24h")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet sqlmock expectations: %v", err)
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_PendingLimitExceeded(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &evalWCPHITLAdapter{
		db:                  db,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	// Return count at limit
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"count"}).AddRow(100),
	)

	req := &HITLApprovalRequest{
		TenantID: "test-tenant",
		StepName: "step-1",
		PolicyID: "pol-1",
		Severity: "medium",
	}

	resp, err := adapter.CreateApproval(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error for pending limit exceeded")
	}
	if resp != nil {
		t.Error("Expected nil response when limit exceeded")
	}
	if !hitlContains(err.Error(), "pending approval limit exceeded") {
		t.Errorf("Expected 'pending approval limit exceeded' error, got %q", err.Error())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet sqlmock expectations: %v", err)
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_CountQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &evalWCPHITLAdapter{
		db:                  db,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	mock.ExpectQuery("SELECT COUNT").WillReturnError(err)

	req := &HITLApprovalRequest{
		TenantID: "test-tenant",
		StepName: "step-1",
		PolicyID: "pol-1",
		Severity: "medium",
	}

	resp, createErr := adapter.CreateApproval(context.Background(), req)
	if createErr == nil {
		t.Fatal("Expected error for count query failure")
	}
	if resp != nil {
		t.Error("Expected nil response on count query failure")
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_InsertError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	adapter := &evalWCPHITLAdapter{
		db:                  db,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	// Count OK
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(
		sqlmock.NewRows([]string{"count"}).AddRow(0),
	)
	// Insert fails
	mock.ExpectExec("INSERT INTO hitl_approval_queue").WillReturnError(err)

	req := &HITLApprovalRequest{
		TenantID: "test-tenant",
		StepName: "step-1",
		PolicyID: "pol-1",
		Severity: "low",
	}

	resp, createErr := adapter.CreateApproval(context.Background(), req)
	if createErr == nil {
		t.Fatal("Expected error for INSERT failure")
	}
	if resp != nil {
		t.Error("Expected nil response on INSERT failure")
	}
}

func TestEvalWCPHITLAdapter_CreateApproval_NilContext(t *testing.T) {
	adapter := &evalWCPHITLAdapter{
		db:                  nil,
		expiryDuration:      24 * time.Hour,
		maxPendingPerTenant: 100,
	}

	req := &HITLApprovalRequest{
		TenantID: "test-tenant",
		StepName: "step-1",
	}

	_, err := adapter.CreateApproval(context.Background(), req)
	if err == nil {
		t.Fatal("Expected error")
	}
}

// Valid eval license key for testing (test-org, expires 2026-05-30).
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

// hitlContains checks if s contains substr.
func hitlContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
