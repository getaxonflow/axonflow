// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue Repository Tests

//go:build enterprise

package hitl

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()

	// v9 Phase 8 #2384 PR-C1: Create wraps the INSERT in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WithArgs(
			requestID, "org-1", "tenant-1", "client-1", sql.NullString{},
			"SELECT * FROM users", "sql", sqlmock.AnyArg(),
			"policy-1", "PII Detection", "Contains PII", "high",
			sql.NullString{String: "14", Valid: true},
			sql.NullString{String: "EU_AI_Act", Valid: true},
			sql.NullString{String: "high-risk", Valid: true},
			"pending", sqlmock.AnyArg(),
			sql.NullString{}, // notify_url (omitted in this test)
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, now, now))
	mock.ExpectCommit()

	req := &ApprovalRequest{
		RequestID:           requestID,
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Contains PII",
		Severity:            "high",
		EUAIActArticle:      "14",
		ComplianceFramework: "EU_AI_Act",
		RiskClassification:  "high-risk",
		Status:              "pending",
		ExpiresAt:           time.Now().Add(24 * time.Hour),
	}

	err = repo.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if req.ID != 1 {
		t.Errorf("Expected ID=1, got %d", req.ID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_Create_WithContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()

	contextData := map[string]interface{}{
		"user_role": "admin",
		"ip":        "192.168.1.1",
	}

	contextJSON, _ := json.Marshal(contextData)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WithArgs(
			requestID, "org-1", "tenant-1", "client-1", sql.NullString{},
			"SELECT * FROM users", "sql", contextJSON,
			"policy-1", "PII Detection", "Contains PII", "high",
			sql.NullString{}, sql.NullString{}, sql.NullString{},
			"pending", sqlmock.AnyArg(),
			sql.NullString{}, // notify_url
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, now, now))
	mock.ExpectCommit()

	req := &ApprovalRequest{
		RequestID:           requestID,
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		RequestContext:      contextData,
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Contains PII",
		Severity:            "high",
		Status:              "pending",
		ExpiresAt:           time.Now().Add(24 * time.Hour),
	}

	err = repo.Create(ctx, req)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetByRequestID_Found(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()
	reviewedAt := now.Add(1 * time.Hour)

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", "user-1",
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk",
			"approved", "reviewer-1", "reviewer@example.com", "admin", "Looks good", reviewedAt,
			nil, nil, nil,
			now.Add(24*time.Hour), now, now,
		))

	req, err := repo.GetByRequestID(ctx, requestID)
	if err != nil {
		t.Fatalf("GetByRequestID failed: %v", err)
	}

	if req == nil {
		t.Fatal("Expected request, got nil")
	}

	if req.RequestID != requestID {
		t.Errorf("Expected RequestID=%s, got %s", requestID, req.RequestID)
	}
	if req.Status != "approved" {
		t.Errorf("Expected status=approved, got %s", req.Status)
	}
	if req.ReviewerID != "reviewer-1" {
		t.Errorf("Expected ReviewerID=reviewer-1, got %s", req.ReviewerID)
	}
	if req.ReviewedAt == nil {
		t.Error("Expected ReviewedAt to be set")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetByRequestID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnError(sql.ErrNoRows)

	req, err := repo.GetByRequestID(ctx, requestID)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if req != nil {
		t.Errorf("Expected nil request, got %+v", req)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	// Mock count query
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	// Mock list query
	requestID1 := uuid.New()
	requestID2 := uuid.New()
	now := time.Now()

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).
			AddRow(1, requestID1, "org-1", "tenant-1", "client-1", nil,
				"SELECT * FROM users", "sql", nil,
				"policy-1", "PII Detection", "Contains PII", "high",
				nil, nil, nil,
				"pending", nil, nil, nil, nil, nil,
				nil, nil, nil,
				now.Add(24*time.Hour), now, now).
			AddRow(2, requestID2, "org-1", "tenant-1", "client-2", nil,
				"SELECT * FROM orders", "sql", nil,
				"policy-1", "PII Detection", "Contains PII", "critical",
				nil, nil, nil,
				"pending", nil, nil, nil, nil, nil,
				nil, nil, nil,
				now.Add(24*time.Hour), now, now))

	filter := ListFilter{
		Status:   []string{"pending"},
		Severity: []string{"high", "critical"},
		PolicyID: "policy-1",
		Limit:    10,
		Offset:   0,
		OrderBy:  "severity",
		OrderDir: "DESC",
	}

	requests, total, err := repo.List(ctx, filter)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if total != 3 {
		t.Errorf("Expected total=3, got %d", total)
	}
	if len(requests) != 2 {
		t.Errorf("Expected 2 requests, got %d", len(requests))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_List_OrderByASC(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}))

	filter := ListFilter{
		OrderBy:  "created_at",
		OrderDir: "ASC",
		Limit:    20,
	}

	_, total, err := repo.List(ctx, filter)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}

	if total != 0 {
		t.Errorf("Expected total=0, got %d", total)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_UpdateStatus_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
		Role:  "admin",
	}

	// v9 Phase 8 #2384 PR-C1: WithOrgScope wraps the UPDATE in BEGIN/SET-CONFIG/QUERY/COMMIT.
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("test-org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WithArgs("approved", "reviewer-1", "reviewer@example.com", "admin", "Looks good", requestID).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectCommit()

	err = repo.UpdateStatus(ctx, "test-org", requestID, "approved", reviewer, "Looks good")
	if err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_UpdateStatus_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("test-org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WithArgs("approved", "reviewer-1", "reviewer@example.com", sql.NullString{}, sql.NullString{}, requestID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repo.UpdateStatus(ctx, "test-org", requestID, "approved", reviewer, "")
	if err == nil {
		t.Error("Expected error for not found, got nil")
	}
	// After R3 R1 HIGH #2 fix: sql.ErrNoRows from the UPDATE collapses
	// "row missing" + "lost race to another reviewer" into the same
	// sentinel because the WHERE-status='pending' guard returns zero
	// rows in either case. The caller (Service.ApproveRequest) translates
	// to "cannot approve request: ..." via the existing 409 path.
	if !errors.Is(err, ErrApprovalLostRace) {
		t.Errorf("Unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_Override_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("test-org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WithArgs("Emergency override", "admin-1", requestID).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectCommit()

	err = repo.Override(ctx, "test-org", requestID, "Emergency override", "admin-1")
	if err != nil {
		t.Fatalf("Override failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_Override_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()

	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs("test-org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WithArgs("Emergency override", "admin-1", requestID).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err = repo.Override(ctx, "test-org", requestID, "Emergency override", "admin-1")
	if err == nil {
		t.Error("Expected error for not found, got nil")
	}
	// See TestRepository_UpdateStatus_NotFound — same lost-race / not-found
	// collapse after the R3 R1 HIGH #2 fix.
	if !errors.Is(err, ErrApprovalLostRace) {
		t.Errorf("Unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetPendingStats_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	oldestHours := 5.5
	mock.ExpectQuery("SELECT \\* FROM get_hitl_pending_count").
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total_pending", "high_priority", "critical_priority", "oldest_pending_hours",
		}).AddRow(10, 5, 2, oldestHours))

	stats, err := repo.GetPendingStats(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetPendingStats failed: %v", err)
	}

	if stats.TotalPending != 10 {
		t.Errorf("Expected TotalPending=10, got %d", stats.TotalPending)
	}
	if stats.HighPriority != 5 {
		t.Errorf("Expected HighPriority=5, got %d", stats.HighPriority)
	}
	if stats.CriticalPriority != 2 {
		t.Errorf("Expected CriticalPriority=2, got %d", stats.CriticalPriority)
	}
	if stats.OldestPendingHours == nil || *stats.OldestPendingHours != oldestHours {
		t.Errorf("Expected OldestPendingHours=5.5, got %v", stats.OldestPendingHours)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetPendingStats_NullOldest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT \\* FROM get_hitl_pending_count").
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total_pending", "high_priority", "critical_priority", "oldest_pending_hours",
		}).AddRow(0, 0, 0, nil))

	stats, err := repo.GetPendingStats(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetPendingStats failed: %v", err)
	}

	if stats.OldestPendingHours != nil {
		t.Errorf("Expected OldestPendingHours=nil, got %v", stats.OldestPendingHours)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_ExpireStale_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT expire_hitl_requests").
		WillReturnRows(sqlmock.NewRows([]string{"expire_hitl_requests"}).AddRow(3))

	count, err := repo.ExpireStale(ctx)
	if err != nil {
		t.Fatalf("ExpireStale failed: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected count=3, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_AddHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()

	// v9 Phase 8 #2384 PR-C1: AddHistory wraps INSERT in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WithArgs(
			requestID, "org-1", "tenant-1", "approved",
			"reviewer-1", "reviewer@example.com", "admin", "192.168.1.1",
			"Looks good", sql.NullString{},
			"pending", "approved",
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, now))
	mock.ExpectCommit()

	entry := &ApprovalHistory{
		RequestID:      requestID,
		OrgID:          "org-1",
		TenantID:       "tenant-1",
		Action:         "approved",
		ActorID:        "reviewer-1",
		ActorEmail:     "reviewer@example.com",
		ActorRole:      "admin",
		ActorIP:        "192.168.1.1",
		Comment:        "Looks good",
		PreviousStatus: "pending",
		NewStatus:      "approved",
	}

	err = repo.AddHistory(ctx, entry)
	if err != nil {
		t.Fatalf("AddHistory failed: %v", err)
	}

	if entry.ID != 1 {
		t.Errorf("Expected ID=1, got %d", entry.ID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_AddHistory_WithJustification(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WithArgs(
			requestID, "org-1", "tenant-1", "overridden",
			"admin-1", "admin@example.com", sql.NullString{}, sql.NullString{},
			sql.NullString{}, "Emergency bypass needed",
			"pending", "overridden",
		).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, now))
	mock.ExpectCommit()

	entry := &ApprovalHistory{
		RequestID:      requestID,
		OrgID:          "org-1",
		TenantID:       "tenant-1",
		Action:         "overridden",
		ActorID:        "admin-1",
		ActorEmail:     "admin@example.com",
		Justification:  "Emergency bypass needed",
		PreviousStatus: "pending",
		NewStatus:      "overridden",
	}

	err = repo.AddHistory(ctx, entry)
	if err != nil {
		t.Fatalf("AddHistory failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetHistory_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()
	now := time.Now()

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "action",
			"actor_id", "actor_email", "actor_role", "actor_ip",
			"comment", "justification",
			"previous_status", "new_status", "created_at",
		}).
			AddRow(1, requestID, "org-1", "tenant-1", "created",
				nil, nil, nil, nil,
				nil, nil,
				nil, "pending", now).
			AddRow(2, requestID, "org-1", "tenant-1", "approved",
				"reviewer-1", "reviewer@example.com", "admin", "192.168.1.1",
				"Looks good", nil,
				"pending", "approved", now.Add(1*time.Hour)))

	history, err := repo.GetHistory(ctx, requestID)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	if len(history) != 2 {
		t.Fatalf("Expected 2 history entries, got %d", len(history))
	}

	if history[0].Action != "created" {
		t.Errorf("Expected action=created, got %s", history[0].Action)
	}
	if history[1].Action != "approved" {
		t.Errorf("Expected action=approved, got %s", history[1].Action)
	}
	if history[1].ActorID != "reviewer-1" {
		t.Errorf("Expected ActorID=reviewer-1, got %s", history[1].ActorID)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRepository_GetHistory_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	ctx := context.Background()

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "action",
			"actor_id", "actor_email", "actor_role", "actor_ip",
			"comment", "justification",
			"previous_status", "new_status", "created_at",
		}))

	history, err := repo.GetHistory(ctx, requestID)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}

	if len(history) != 0 {
		t.Errorf("Expected empty history, got %d entries", len(history))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestNullString(t *testing.T) {
	tests := []struct {
		input    string
		expected sql.NullString
	}{
		{"", sql.NullString{String: "", Valid: false}},
		{"test", sql.NullString{String: "test", Valid: true}},
		{"   ", sql.NullString{String: "   ", Valid: true}},
	}

	for _, tt := range tests {
		result := nullString(tt.input)
		if result.String != tt.expected.String || result.Valid != tt.expected.Valid {
			t.Errorf("nullString(%q) = %+v, expected %+v", tt.input, result, tt.expected)
		}
	}
}
