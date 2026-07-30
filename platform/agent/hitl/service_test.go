// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue Service Tests

//go:build enterprise

package hitl

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"axonflow/platform/agent/license"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// newEvalTierService returns a Service whose tier provider is pinned to
// Evaluation (tier gate passes). Used by every test in this file that
// exercises the happy path; tier-gate tests construct the Service
// directly with the desired tier.
func newEvalTierService(t *testing.T, repo *Repository, cfg ServiceConfig) *Service {
	t.Helper()
	svc := NewService(repo, cfg)
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierEvaluation })
	return svc
}

func TestNewService(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)

	// Test default config
	svc := newEvalTierService(t, repo, ServiceConfig{})
	if svc.defaultExpiry != 24*time.Hour {
		t.Errorf("Expected default expiry 24h, got %v", svc.defaultExpiry)
	}
	if svc.maxExpiry != 168*time.Hour {
		t.Errorf("Expected max expiry 168h, got %v", svc.maxExpiry)
	}

	// Test custom config
	svc = NewService(repo, ServiceConfig{
		DefaultExpiry: 48 * time.Hour,
		MaxExpiry:     336 * time.Hour,
	})
	if svc.defaultExpiry != 48*time.Hour {
		t.Errorf("Expected custom default expiry 48h, got %v", svc.defaultExpiry)
	}
	if svc.maxExpiry != 336*time.Hour {
		t.Errorf("Expected custom max expiry 336h, got %v", svc.maxExpiry)
	}
}

func TestCreateApprovalRequest_Validation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	tests := []struct {
		name    string
		input   CreateApprovalInput
		wantErr string
	}{
		{
			name:    "missing org_id",
			input:   CreateApprovalInput{},
			wantErr: "org_id is required",
		},
		{
			name: "missing tenant_id",
			input: CreateApprovalInput{
				OrgID: "org-1",
			},
			wantErr: "tenant_id is required",
		},
		{
			name: "missing client_id",
			input: CreateApprovalInput{
				OrgID:    "org-1",
				TenantID: "tenant-1",
			},
			wantErr: "client_id is required",
		},
		{
			name: "missing original_query",
			input: CreateApprovalInput{
				OrgID:    "org-1",
				TenantID: "tenant-1",
				ClientID: "client-1",
			},
			wantErr: "original_query is required",
		},
		{
			name: "missing request_type",
			input: CreateApprovalInput{
				OrgID:         "org-1",
				TenantID:      "tenant-1",
				ClientID:      "client-1",
				OriginalQuery: "SELECT * FROM users",
			},
			wantErr: "request_type is required",
		},
		{
			name: "missing triggered_policy_id",
			input: CreateApprovalInput{
				OrgID:         "org-1",
				TenantID:      "tenant-1",
				ClientID:      "client-1",
				OriginalQuery: "SELECT * FROM users",
				RequestType:   "sql",
			},
			wantErr: "triggered_policy_id is required",
		},
		{
			name: "missing triggered_policy_name",
			input: CreateApprovalInput{
				OrgID:             "org-1",
				TenantID:          "tenant-1",
				ClientID:          "client-1",
				OriginalQuery:     "SELECT * FROM users",
				RequestType:       "sql",
				TriggeredPolicyID: "policy-1",
			},
			wantErr: "triggered_policy_name is required",
		},
		{
			name: "missing trigger_reason",
			input: CreateApprovalInput{
				OrgID:               "org-1",
				TenantID:            "tenant-1",
				ClientID:            "client-1",
				OriginalQuery:       "SELECT * FROM users",
				RequestType:         "sql",
				TriggeredPolicyID:   "policy-1",
				TriggeredPolicyName: "PII Detection",
			},
			wantErr: "trigger_reason is required",
		},
		{
			name: "invalid severity",
			input: CreateApprovalInput{
				OrgID:               "org-1",
				TenantID:            "tenant-1",
				ClientID:            "client-1",
				OriginalQuery:       "SELECT * FROM users",
				RequestType:         "sql",
				TriggeredPolicyID:   "policy-1",
				TriggeredPolicyName: "PII Detection",
				TriggerReason:       "Contains PII data",
				Severity:            "invalid",
			},
			wantErr: "invalid severity: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := svc.CreateApprovalRequest(ctx, tt.input)
			if err == nil {
				t.Error("Expected error, got nil")
				return
			}
			if err.Error() != tt.wantErr {
				t.Errorf("Expected error %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

func TestCreateApprovalRequest_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{
		DefaultExpiry: 24 * time.Hour,
	})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	// v9 Phase 8 #2384 PR-C1: Create + AddHistory wrap their INSERTs in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectCommit()

	// Mock the history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))
	mock.ExpectCommit()

	input := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Query accesses PII table",
		Severity:            "high",
		EUAIActArticle:      "14",
	}

	req, err := svc.CreateApprovalRequest(ctx, input)
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}

	if req.Status != "pending" {
		t.Errorf("Expected status 'pending', got %q", req.Status)
	}
	if req.Severity != "high" {
		t.Errorf("Expected severity 'high', got %q", req.Severity)
	}
	if req.RequestID == uuid.Nil {
		t.Error("Expected non-nil request ID")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestCreateApprovalRequest_DefaultSeverity(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	// v9 Phase 8 #2384 PR-C1: Create + AddHistory wrap their INSERTs in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectCommit()

	// Mock the history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))
	mock.ExpectCommit()

	input := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Query accesses PII table",
		// No severity - should default to "high"
	}

	req, err := svc.CreateApprovalRequest(ctx, input)
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}

	if req.Severity != "high" {
		t.Errorf("Expected default severity 'high', got %q", req.Severity)
	}
}

func TestCreateApprovalRequest_ExpiryLimiting(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{
		DefaultExpiry: 24 * time.Hour,
		MaxExpiry:     48 * time.Hour,
	})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	// v9 Phase 8 #2384 PR-C1: Create + AddHistory wrap their INSERTs in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectCommit()

	// Mock the history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))
	mock.ExpectCommit()

	input := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT * FROM users",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "PII Detection",
		TriggerReason:       "Query accesses PII table",
		ExpiresIn:           100 * time.Hour, // Exceeds max
	}

	req, err := svc.CreateApprovalRequest(ctx, input)
	if err != nil {
		t.Fatalf("CreateApprovalRequest failed: %v", err)
	}

	// Check that expiry was capped to max
	expectedExpiry := time.Now().Add(48 * time.Hour)
	if req.ExpiresAt.Before(expectedExpiry.Add(-time.Minute)) || req.ExpiresAt.After(expectedExpiry.Add(time.Minute)) {
		t.Errorf("Expected expiry around %v, got %v", expectedExpiry, req.ExpiresAt)
	}
}

func TestApproveRequest_InvalidStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID returning an already approved request
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"approved", "reviewer-1", "reviewer@example.com", "admin", "LGTM", time.Now(),
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	reviewer := &Reviewer{
		ID:    "reviewer-2",
		Email: "reviewer2@example.com",
	}

	err = svc.ApproveRequest(ctx, requestID, reviewer, "")
	if err == nil {
		t.Error("Expected error for already approved request")
		return
	}
	if err.Error() != "cannot approve request with status: approved" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestApproveRequest_Expired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID returning an expired pending request
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(-1*time.Hour), // Expired 1 hour ago
			time.Now().Add(-25*time.Hour), time.Now().Add(-25*time.Hour),
		))

	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	err = svc.ApproveRequest(ctx, requestID, reviewer, "")
	if err == nil {
		t.Error("Expected error for expired request")
		return
	}
	if err.Error() != "request has expired" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestOverrideRequest_RequiresJustification(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	authorizedBy := &Reviewer{
		ID:    "admin-1",
		Email: "admin@example.com",
	}

	err = svc.OverrideRequest(ctx, requestID, "", authorizedBy)
	if err == nil {
		t.Error("Expected error for missing justification")
		return
	}
	if err.Error() != "justification is required for override" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestOverrideRequest_RequiresAuthorizedBy(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	err = svc.OverrideRequest(ctx, requestID, "Emergency bypass needed", nil)
	if err == nil {
		t.Error("Expected error for missing authorized_by")
		return
	}
	if err.Error() != "authorized_by is required for override" {
		t.Errorf("Unexpected error: %v", err)
	}

	err = svc.OverrideRequest(ctx, requestID, "Emergency bypass needed", &Reviewer{})
	if err == nil {
		t.Error("Expected error for empty authorized_by.ID")
		return
	}
	if err.Error() != "authorized_by is required for override" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestOverrideRequest_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock Override. v9 Phase 8 #2384 PR-C1: WithOrgScope wraps UPDATE in BEGIN/SET-CONFIG/QUERY/COMMIT.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectCommit()

	// Mock history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))
	mock.ExpectCommit()

	authorizedBy := &Reviewer{
		ID:    "admin-1",
		Email: "admin@example.com",
	}

	err = svc.OverrideRequest(ctx, requestID, "Emergency override", authorizedBy)
	if err != nil {
		t.Fatalf("OverrideRequest failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestOverrideRequest_NonPendingStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID returning an approved request
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"approved", "reviewer-1", "reviewer@example.com", "admin", "Done", time.Now(),
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	authorizedBy := &Reviewer{
		ID:    "admin-1",
		Email: "admin@example.com",
	}

	err = svc.OverrideRequest(ctx, requestID, "Emergency override", authorizedBy)
	if err == nil {
		t.Error("Expected error for non-pending status")
		return
	}
	if err.Error() != "cannot override request with status: approved" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRejectRequest_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock UpdateStatus. v9 Phase 8 #2384 PR-C1: WithOrgScope wraps UPDATE in BEGIN/SET-CONFIG/QUERY/COMMIT.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectCommit()

	// Mock history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))
	mock.ExpectCommit()

	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	err = svc.RejectRequest(ctx, requestID, reviewer, "Not acceptable")
	if err != nil {
		t.Fatalf("RejectRequest failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestRejectRequest_NotFoundService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrNoRows)

	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	err = svc.RejectRequest(ctx, requestID, reviewer, "Not acceptable")
	if err == nil {
		t.Error("Expected error for not found")
		return
	}
}

func TestApproveRequest_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// Mock GetByRequestID
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			"14", "EU_AI_Act", "high-risk_ai_system",
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	// Mock UpdateStatus. v9 Phase 8 #2384 PR-C1: WithOrgScope wraps UPDATE in BEGIN/SET-CONFIG/QUERY/COMMIT.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("UPDATE hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))
	mock.ExpectCommit()

	// Mock history INSERT
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(1, time.Now()))
	mock.ExpectCommit()

	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	err = svc.ApproveRequest(ctx, requestID, reviewer, "Looks good")
	if err != nil {
		t.Fatalf("ApproveRequest failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestApproveRequest_NotFoundService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	mock.ExpectQuery("SELECT").
		WillReturnError(sql.ErrNoRows)

	reviewer := &Reviewer{
		ID:    "reviewer-1",
		Email: "reviewer@example.com",
	}

	err = svc.ApproveRequest(ctx, requestID, reviewer, "Looks good")
	if err == nil {
		t.Error("Expected error for not found")
		return
	}
}

func TestGetApprovalRequest_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

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

	req, err := svc.GetApprovalRequest(ctx, requestID)
	if err == nil {
		t.Error("Expected error for not found")
		return
	}
	if req != nil {
		t.Errorf("Expected nil request, got %+v", req)
	}
}

func TestListApprovalRequests(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	requestID := uuid.New()
	mock.ExpectQuery("SELECT").
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "client_id", "user_id",
			"original_query", "request_type", "request_context",
			"triggered_policy_id", "triggered_policy_name", "trigger_reason", "severity",
			"eu_ai_act_article", "compliance_framework", "risk_classification",
			"status", "reviewer_id", "reviewer_email", "reviewer_role", "review_comment", "reviewed_at",
			"override_justification", "override_authorized_by", "notify_url",
			"expires_at", "created_at", "updated_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "client-1", nil,
			"SELECT * FROM users", "sql", nil,
			"policy-1", "PII Detection", "Contains PII", "high",
			nil, nil, nil,
			"pending", nil, nil, nil, nil, nil,
			nil, nil, nil,
			time.Now().Add(24*time.Hour), time.Now(), time.Now(),
		))

	filter := ListFilter{
		OrgID:  "org-1",
		Status: []string{"pending"},
		Limit:  10,
	}

	requests, total, err := svc.ListApprovalRequests(ctx, filter)
	if err != nil {
		t.Fatalf("ListApprovalRequests failed: %v", err)
	}

	if total != 1 {
		t.Errorf("Expected total=1, got %d", total)
	}
	if len(requests) != 1 {
		t.Errorf("Expected 1 request, got %d", len(requests))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestGetPendingStats(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	// #3048: GetPendingStats runs org-scoped.
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total_pending", "high_priority", "critical_priority", "oldest_pending_hours",
		}).AddRow(10, 5, 2, 3.5))
	mock.ExpectCommit()

	stats, err := svc.GetPendingStats(ctx, "org-1")
	if err != nil {
		t.Fatalf("GetPendingStats failed: %v", err)
	}

	if stats.TotalPending != 10 {
		t.Errorf("Expected TotalPending=10, got %d", stats.TotalPending)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestGetRequestHistoryService(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	requestID := uuid.New()

	// #3048 R3 BLOCKER-2: GetRequestHistory resolves + org-checks the parent
	// request before reading history.
	expectApprovalLookup(mock, requestID, "org-1")

	mock.ExpectQuery("SELECT").
		WithArgs(requestID).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "request_id", "org_id", "tenant_id", "action",
			"actor_id", "actor_email", "actor_role", "actor_ip",
			"comment", "justification",
			"previous_status", "new_status", "created_at",
		}).AddRow(
			1, requestID, "org-1", "tenant-1", "created",
			nil, nil, nil, nil,
			nil, nil,
			nil, "pending", time.Now(),
		))

	history, err := svc.GetRequestHistory(ctx, requestID)
	if err != nil {
		t.Fatalf("GetRequestHistory failed: %v", err)
	}

	if len(history) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(history))
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

func TestExpireStaleRequests(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := newEvalTierService(t, repo, ServiceConfig{})
	// #3065 (F5): rejectCrossOrg fails closed on an empty caller org, so
	// the service context must carry the authenticated org — the same
	// value the handler passes via WithCallerOrg(r.Context(), X-Org-ID).
	ctx := WithCallerOrg(context.Background(), "org-1")

	mock.ExpectQuery("SELECT expire_hitl_requests").
		WillReturnRows(sqlmock.NewRows([]string{"expire_hitl_requests"}).AddRow(5))

	count, err := svc.ExpireStaleRequests(ctx)
	if err != nil {
		t.Fatalf("ExpireStaleRequests failed: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected count=5, got %d", count)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// =============================================================================
// Tier-gate tests (added in #1998)
//
// These tests exercise the license-tier gate added at the top of
// CreateApprovalRequest. The gate is the single chokepoint that both the
// HTTP handler path AND the in-process MCP-tool path inherit.
// =============================================================================

// TestCreateApprovalRequest_CommunityTierRejected asserts that a
// Community-tier process refuses HITL-approval creation BEFORE any DB
// write occurs.
func TestCreateApprovalRequest_CommunityTierRejected(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{DefaultExpiry: 24 * time.Hour})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierCommunity })

	input := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "rm -rf /",
		RequestType:         "shell_command",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "Destructive command",
		TriggerReason:       "deletion attempt",
		Severity:            "high",
	}

	_, err = svc.CreateApprovalRequest(context.Background(), input)
	if err == nil {
		t.Fatal("Expected ErrHITLApprovalDisabledByTier, got nil")
	}
	if !errors.Is(err, ErrHITLApprovalDisabledByTier) {
		t.Fatalf("Expected ErrHITLApprovalDisabledByTier, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unexpected query (gate should have short-circuited before DB): %v", err)
	}
}

// TestCreateApprovalRequest_EvaluationOrHigherAllowed asserts every
// non-Community tier passes the gate.
func TestCreateApprovalRequest_EvaluationOrHigherAllowed(t *testing.T) {
	tierCases := []license.Tier{
		license.TierEvaluation,
		license.TierProfessional,
		license.TierEnterprise,
		license.TierEnterprisePlus,
	}
	for _, tier := range tierCases {
		t.Run(string(tier), func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("Failed to create sqlmock: %v", err)
			}
			defer db.Close()

			repo := NewRepository(db)
			svc := NewService(repo, ServiceConfig{DefaultExpiry: 24 * time.Hour})
			svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return tier })

			// v9 Phase 8 #2384 PR-C1: Create + AddHistory wrap their INSERTs in WithOrgScope txn.
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
				WithArgs("org-1").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("INSERT INTO hitl_approval_queue").
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
					AddRow(1, time.Now(), time.Now()))
			mock.ExpectCommit()
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
				WithArgs("org-1").
				WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("INSERT INTO hitl_approval_history").
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
					AddRow(1, time.Now()))
			mock.ExpectCommit()

			input := CreateApprovalInput{
				OrgID:               "org-1",
				TenantID:            "tenant-1",
				ClientID:            "client-1",
				OriginalQuery:       "SELECT 1",
				RequestType:         "sql",
				TriggeredPolicyID:   "policy-1",
				TriggeredPolicyName: "Smoke",
				TriggerReason:       "smoke",
				Severity:            "high",
			}

			_, err = svc.CreateApprovalRequest(context.Background(), input)
			if err != nil {
				t.Fatalf("Tier %s rejected unexpectedly: %v", tier, err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Mock expectations not met: %v", err)
			}
		})
	}
}

// TestCreateApprovalRequest_TierGateOrderVsValidation confirms that
// validation errors fire BEFORE the tier gate (input-shape problems
// surface as the more informative error to the caller). On valid input
// + Community tier the tier-gate error fires.
func TestCreateApprovalRequest_TierGateOrderVsValidation(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{})
	svc.SetTierProviderForTest(func(_ context.Context) license.Tier { return license.TierCommunity })

	// Valid shape, Community tier → tier-gate error.
	validInput := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT 1",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "Smoke",
		TriggerReason:       "smoke",
	}
	_, err = svc.CreateApprovalRequest(context.Background(), validInput)
	if !errors.Is(err, ErrHITLApprovalDisabledByTier) {
		t.Fatalf("Expected tier-gate error on Community + valid input, got %v", err)
	}

	// Invalid shape, Community tier → validation error fires first.
	invalidInput := CreateApprovalInput{}
	_, err = svc.CreateApprovalRequest(context.Background(), invalidInput)
	if err == nil {
		t.Fatal("Expected validation error on empty input")
	}
	if errors.Is(err, ErrHITLApprovalDisabledByTier) {
		t.Fatalf("Tier gate fired on invalid input; expected validation error first, got %v", err)
	}
}

// TestCreateApprovalRequest_NilTierProviderFallsThrough confirms that
// a Service whose tier provider has been explicitly nilled out does not
// fire the gate. Defensive coverage for the `s.currentTier != nil`
// guard.
func TestCreateApprovalRequest_NilTierProviderFallsThrough(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	repo := NewRepository(db)
	svc := NewService(repo, ServiceConfig{DefaultExpiry: 24 * time.Hour})
	svc.SetTierProviderForTest(nil)

	// v9 Phase 8 #2384 PR-C1: Create + AddHistory wrap their INSERTs in WithOrgScope txn.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_queue").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(1, time.Now(), time.Now()))
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO hitl_approval_history").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).
			AddRow(1, time.Now()))
	mock.ExpectCommit()

	input := CreateApprovalInput{
		OrgID:               "org-1",
		TenantID:            "tenant-1",
		ClientID:            "client-1",
		OriginalQuery:       "SELECT 1",
		RequestType:         "sql",
		TriggeredPolicyID:   "policy-1",
		TriggeredPolicyName: "Smoke",
		TriggerReason:       "smoke",
		Severity:            "high",
	}

	_, err = svc.CreateApprovalRequest(context.Background(), input)
	if err != nil {
		t.Fatalf("Nil tier provider should not block: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Mock expectations not met: %v", err)
	}
}
