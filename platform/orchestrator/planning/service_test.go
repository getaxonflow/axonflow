// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// MockRepository is defined in mock.go for use by other packages' tests.
// service_test.go uses the same MockRepository via the shared mock.go file.

// Test helper to create a valid workflow definition
func validWorkflowJSON() json.RawMessage {
	return json.RawMessage(`{
		"metadata": {"name": "test-workflow"},
		"spec": {"steps": [{"name": "step1", "type": "llm"}]}
	}`)
}

func TestService_StorePlan(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreatePlanRequest
		repoErr error
		wantErr error
	}{
		{
			name: "successful store",
			req: &CreatePlanRequest{
				PlanID:             "plan_123",
				Query:              "Test query",
				Domain:             "generic",
				ExecutionMode:      "auto",
				WorkflowDefinition: validWorkflowJSON(),
				StepCount:          1,
				OrgID:              "org_1",
			},
			wantErr: nil,
		},
		{
			name: "empty plan ID",
			req: &CreatePlanRequest{
				PlanID:             "",
				Query:              "Test query",
				WorkflowDefinition: validWorkflowJSON(),
			},
			wantErr: ErrInvalidPlanID,
		},
		{
			name: "empty workflow definition",
			req: &CreatePlanRequest{
				PlanID:             "plan_123",
				Query:              "Test query",
				WorkflowDefinition: nil,
			},
			wantErr: ErrInvalidWorkflow,
		},
		{
			name: "repository error",
			req: &CreatePlanRequest{
				PlanID:             "plan_123",
				Query:              "Test query",
				WorkflowDefinition: validWorkflowJSON(),
			},
			repoErr: errors.New("database error"),
			wantErr: errors.New("failed to store plan"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockRepository()
			if tt.repoErr != nil {
				repo.SetError(tt.repoErr)
			}
			svc := NewService(repo)

			plan, err := svc.StorePlan(context.Background(), tt.req)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if plan.PlanID != tt.req.PlanID {
				t.Errorf("expected plan ID %s, got %s", tt.req.PlanID, plan.PlanID)
			}
			if plan.Status != PlanStatusPending {
				t.Errorf("expected status %s, got %s", PlanStatusPending, plan.Status)
			}
			if plan.ExpiresAt.Before(time.Now()) {
				t.Error("expected expiration to be in the future")
			}
		})
	}
}

func TestService_GetPlanForExecution(t *testing.T) {
	tests := []struct {
		name      string
		planID    string
		orgID     string // Requesting org
		setupPlan *Plan
		wantErr   error
	}{
		{
			name:   "successful retrieval",
			planID: "plan_123",
			orgID:  "org_1",
			setupPlan: &Plan{
				PlanID:             "plan_123",
				OrgID:              "org_1",
				Status:             PlanStatusPending,
				WorkflowDefinition: validWorkflowJSON(),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
			},
			wantErr: nil,
		},
		{
			name:   "successful retrieval - empty orgID (community mode)",
			planID: "plan_community",
			orgID:  "", // No org restriction in community mode
			setupPlan: &Plan{
				PlanID:             "plan_community",
				OrgID:              "", // No org set
				Status:             PlanStatusPending,
				WorkflowDefinition: validWorkflowJSON(),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
			},
			wantErr: nil,
		},
		{
			name:    "plan not found",
			planID:  "nonexistent",
			orgID:   "org_1",
			wantErr: ErrPlanNotFound,
		},
		{
			name:   "expired plan",
			planID: "plan_expired",
			orgID:  "org_1",
			setupPlan: &Plan{
				PlanID:             "plan_expired",
				OrgID:              "org_1",
				Status:             PlanStatusPending,
				WorkflowDefinition: validWorkflowJSON(),
				ExpiresAt:          time.Now().Add(-1 * time.Hour), // Already expired
			},
			wantErr: ErrPlanExpired,
		},
		{
			name:   "already executed plan",
			planID: "plan_completed",
			orgID:  "org_1",
			setupPlan: &Plan{
				PlanID:             "plan_completed",
				OrgID:              "org_1",
				Status:             PlanStatusCompleted,
				WorkflowDefinition: validWorkflowJSON(),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrPlanAlreadyRun,
		},
		{
			name:   "cross-tenant execution blocked",
			planID: "plan_other_org",
			orgID:  "org_2", // Different org trying to execute
			setupPlan: &Plan{
				PlanID:             "plan_other_org",
				OrgID:              "org_1", // Plan belongs to org_1
				Status:             PlanStatusPending,
				WorkflowDefinition: validWorkflowJSON(),
				ExpiresAt:          time.Now().Add(1 * time.Hour),
			},
			wantErr: ErrPlanNotFound, // Returns not found to avoid leaking plan existence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := NewMockRepository()
			if tt.setupPlan != nil {
				repo.plans[tt.setupPlan.PlanID] = tt.setupPlan
			}
			svc := NewService(repo)

			plan, err := svc.GetPlanForExecution(context.Background(), tt.planID, tt.orgID)

			if tt.wantErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.wantErr)
				} else if !errors.Is(err, tt.wantErr) && err.Error() != tt.wantErr.Error() {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			// Plan should be marked as executing
			if repo.plans[tt.planID].Status != PlanStatusExecuting {
				t.Errorf("expected status %s, got %s", PlanStatusExecuting, repo.plans[tt.planID].Status)
			}

			if plan.PlanID != tt.planID {
				t.Errorf("expected plan ID %s, got %s", tt.planID, plan.PlanID)
			}
		})
	}
}

func TestService_MarkPlanCompleted(t *testing.T) {
	repo := NewMockRepository()
	repo.plans["plan_123"] = &Plan{
		PlanID:             "plan_123",
		Status:             PlanStatusExecuting,
		WorkflowDefinition: validWorkflowJSON(),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}
	svc := NewService(repo)

	result := map[string]interface{}{"output": "success"}
	err := svc.MarkPlanCompleted(context.Background(), "plan_123", result)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	plan := repo.plans["plan_123"]
	if plan.Status != PlanStatusCompleted {
		t.Errorf("expected status %s, got %s", PlanStatusCompleted, plan.Status)
	}
	if plan.ExecutedAt == nil {
		t.Error("expected ExecutedAt to be set")
	}
}

func TestService_MarkPlanFailed(t *testing.T) {
	repo := NewMockRepository()
	repo.plans["plan_123"] = &Plan{
		PlanID:             "plan_123",
		Status:             PlanStatusExecuting,
		WorkflowDefinition: validWorkflowJSON(),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}
	svc := NewService(repo)

	err := svc.MarkPlanFailed(context.Background(), "plan_123", "execution failed")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	plan := repo.plans["plan_123"]
	if plan.Status != PlanStatusFailed {
		t.Errorf("expected status %s, got %s", PlanStatusFailed, plan.Status)
	}
	if plan.ErrorMessage != "execution failed" {
		t.Errorf("expected error message 'execution failed', got '%s'", plan.ErrorMessage)
	}
}

func TestService_CleanupExpiredPlans(t *testing.T) {
	repo := NewMockRepository()

	// Add expired pending plan (should be cleaned)
	repo.plans["expired_pending"] = &Plan{
		PlanID:    "expired_pending",
		Status:    PlanStatusPending,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	// Add expired completed plan (should NOT be cleaned - already executed)
	repo.plans["expired_completed"] = &Plan{
		PlanID:    "expired_completed",
		Status:    PlanStatusCompleted,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	// Add valid pending plan (should NOT be cleaned)
	repo.plans["valid_pending"] = &Plan{
		PlanID:    "valid_pending",
		Status:    PlanStatusPending,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	svc := NewService(repo)
	count, err := svc.CleanupExpiredPlans(context.Background())

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 plan cleaned, got %d", count)
	}

	// Verify correct plans remain
	if _, ok := repo.plans["expired_pending"]; ok {
		t.Error("expired_pending should have been cleaned")
	}
	if _, ok := repo.plans["expired_completed"]; !ok {
		t.Error("expired_completed should NOT have been cleaned")
	}
	if _, ok := repo.plans["valid_pending"]; !ok {
		t.Error("valid_pending should NOT have been cleaned")
	}
}

func TestPlan_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := &Plan{ExpiresAt: tt.expiresAt}
			if got := plan.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPlan_CanExecute(t *testing.T) {
	tests := []struct {
		name string
		plan *Plan
		want bool
	}{
		{
			name: "can execute - pending and not expired",
			plan: &Plan{
				Status:    PlanStatusPending,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			want: true,
		},
		{
			name: "cannot execute - already completed",
			plan: &Plan{
				Status:    PlanStatusCompleted,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			want: false,
		},
		{
			name: "cannot execute - expired",
			plan: &Plan{
				Status:    PlanStatusPending,
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			want: false,
		},
		{
			name: "cannot execute - executing",
			plan: &Plan{
				Status:    PlanStatusExecuting,
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.plan.CanExecute(); got != tt.want {
				t.Errorf("CanExecute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GetPlan(t *testing.T) {
	repo := NewMockRepository()
	repo.plans["plan_123"] = &Plan{
		PlanID:             "plan_123",
		Status:             PlanStatusPending,
		Query:              "test query",
		Domain:             "generic",
		WorkflowDefinition: validWorkflowJSON(),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}
	svc := NewService(repo)

	t.Run("successful retrieval", func(t *testing.T) {
		plan, err := svc.GetPlan(context.Background(), "plan_123")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if plan.PlanID != "plan_123" {
			t.Errorf("expected plan ID 'plan_123', got '%s'", plan.PlanID)
		}
	})

	t.Run("plan not found", func(t *testing.T) {
		_, err := svc.GetPlan(context.Background(), "nonexistent")
		if !errors.Is(err, ErrPlanNotFound) {
			t.Errorf("expected ErrPlanNotFound, got %v", err)
		}
	})
}

func TestService_StorePlan_WithCustomTTL(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	customTTL := 30 * time.Minute
	req := &CreatePlanRequest{
		PlanID:             "plan_custom_ttl",
		Query:              "Test query",
		Domain:             "generic",
		ExecutionMode:      "auto",
		WorkflowDefinition: validWorkflowJSON(),
		StepCount:          1,
		TTL:                customTTL,
	}

	plan, err := svc.StorePlan(context.Background(), req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Check TTL was applied (with some tolerance)
	expectedExpiry := time.Now().Add(customTTL)
	if plan.ExpiresAt.Before(expectedExpiry.Add(-1*time.Second)) || plan.ExpiresAt.After(expectedExpiry.Add(1*time.Second)) {
		t.Errorf("expected expiry around %v, got %v", expectedExpiry, plan.ExpiresAt)
	}
}

func TestService_GetPlanForExecution_FailedPlan(t *testing.T) {
	repo := NewMockRepository()
	repo.plans["plan_failed"] = &Plan{
		PlanID:             "plan_failed",
		OrgID:              "org_1",
		Status:             PlanStatusFailed,
		WorkflowDefinition: validWorkflowJSON(),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}
	svc := NewService(repo)

	_, err := svc.GetPlanForExecution(context.Background(), "plan_failed", "org_1")
	if !errors.Is(err, ErrPlanAlreadyRun) {
		t.Errorf("expected ErrPlanAlreadyRun, got %v", err)
	}
}

func TestService_GetPlanForExecution_ExecutingPlan(t *testing.T) {
	repo := NewMockRepository()
	repo.plans["plan_executing"] = &Plan{
		PlanID:             "plan_executing",
		OrgID:              "org_1",
		Status:             PlanStatusExecuting,
		WorkflowDefinition: validWorkflowJSON(),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}
	svc := NewService(repo)

	_, err := svc.GetPlanForExecution(context.Background(), "plan_executing", "org_1")
	if err == nil {
		t.Error("expected error for executing plan")
	}
	// Executing plan should return ErrPlanAlreadyRun
	if !errors.Is(err, ErrPlanAlreadyRun) {
		t.Errorf("expected ErrPlanAlreadyRun for executing plan, got %v", err)
	}
}

func TestService_MarkPlanCompleted_NotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	err := svc.MarkPlanCompleted(context.Background(), "nonexistent", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for nonexistent plan")
	}
}

func TestService_MarkPlanFailed_NotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	err := svc.MarkPlanFailed(context.Background(), "nonexistent", "error")
	if err == nil {
		t.Error("expected error for nonexistent plan")
	}
}

func TestService_CleanupExpiredPlans_RepoError(t *testing.T) {
	repo := NewMockRepository()
	repo.SetError(errors.New("database error"))
	svc := NewService(repo)

	_, err := svc.CleanupExpiredPlans(context.Background())
	if err == nil {
		t.Error("expected error from repository")
	}
}

func TestService_StartCleanupWorker(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	// Create a context that will be cancelled
	ctx, cancel := context.WithCancel(context.Background())

	// Start cleanup worker with short interval
	svc.StartCleanupWorker(ctx, 10*time.Millisecond)

	// Add an expired plan
	repo.plans["expired"] = &Plan{
		PlanID:    "expired",
		Status:    PlanStatusPending,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	// Wait for cleanup to run
	time.Sleep(50 * time.Millisecond)

	// Cancel context to stop worker
	cancel()

	// Wait for worker to stop
	time.Sleep(20 * time.Millisecond)

	// Verify expired plan was cleaned up
	if _, ok := repo.plans["expired"]; ok {
		t.Error("expected expired plan to be cleaned up")
	}
}

func TestService_StartCleanupWorker_DefaultInterval(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start with zero interval (should use default)
	svc.StartCleanupWorker(ctx, 0)

	// Just verify it doesn't panic
	time.Sleep(10 * time.Millisecond)
}

func TestCreatePlanRequest_AllFields(t *testing.T) {
	req := &CreatePlanRequest{
		PlanID:             "plan_full",
		Query:              "full query",
		Domain:             "travel",
		ExecutionMode:      "parallel",
		WorkflowDefinition: validWorkflowJSON(),
		Complexity:         3,
		Parallel:           true,
		EstimatedDuration:  "30s",
		StepCount:          5,
		OrgID:              "org_1",
		TenantID:           "tenant_1",
		UserID:             "user_1",
		ClientID:           "client_1",
		TTL:                2 * time.Hour,
	}

	repo := NewMockRepository()
	svc := NewService(repo)

	plan, err := svc.StorePlan(context.Background(), req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify all fields were stored correctly
	if plan.Query != req.Query {
		t.Errorf("expected Query %s, got %s", req.Query, plan.Query)
	}
	if plan.Domain != req.Domain {
		t.Errorf("expected Domain %s, got %s", req.Domain, plan.Domain)
	}
	if plan.ExecutionMode != req.ExecutionMode {
		t.Errorf("expected ExecutionMode %s, got %s", req.ExecutionMode, plan.ExecutionMode)
	}
	if plan.Complexity != req.Complexity {
		t.Errorf("expected Complexity %d, got %d", req.Complexity, plan.Complexity)
	}
	if plan.Parallel != req.Parallel {
		t.Errorf("expected Parallel %v, got %v", req.Parallel, plan.Parallel)
	}
	if plan.EstimatedDuration != req.EstimatedDuration {
		t.Errorf("expected EstimatedDuration %s, got %s", req.EstimatedDuration, plan.EstimatedDuration)
	}
	if plan.StepCount != req.StepCount {
		t.Errorf("expected StepCount %d, got %d", req.StepCount, plan.StepCount)
	}
	if plan.OrgID != req.OrgID {
		t.Errorf("expected OrgID %s, got %s", req.OrgID, plan.OrgID)
	}
	if plan.TenantID != req.TenantID {
		t.Errorf("expected TenantID %s, got %s", req.TenantID, plan.TenantID)
	}
	if plan.UserID != req.UserID {
		t.Errorf("expected UserID %s, got %s", req.UserID, plan.UserID)
	}
	if plan.ClientID != req.ClientID {
		t.Errorf("expected ClientID %s, got %s", req.ClientID, plan.ClientID)
	}
}

func TestPlanStatus_Constants(t *testing.T) {
	// Verify status constants
	statuses := []PlanStatus{
		PlanStatusPending,
		PlanStatusExecuting,
		PlanStatusCompleted,
		PlanStatusFailed,
		PlanStatusExpired,
		PlanStatusCancelled,
	}

	expectedValues := []string{
		"pending",
		"executing",
		"completed",
		"failed",
		"expired",
		"cancelled",
	}

	for i, status := range statuses {
		if string(status) != expectedValues[i] {
			t.Errorf("expected status %s, got %s", expectedValues[i], status)
		}
	}
}

func TestDefaultPlanTTL(t *testing.T) {
	if DefaultPlanTTL != 1*time.Hour {
		t.Errorf("expected DefaultPlanTTL to be 1 hour, got %v", DefaultPlanTTL)
	}
}

func TestErrors(t *testing.T) {
	// Test error strings
	if ErrPlanNotFound.Error() != "plan not found" {
		t.Errorf("unexpected error message: %s", ErrPlanNotFound.Error())
	}
	if ErrPlanExpired.Error() != "plan has expired" {
		t.Errorf("unexpected error message: %s", ErrPlanExpired.Error())
	}
	if ErrPlanAlreadyRun.Error() != "plan has already been executed" {
		t.Errorf("unexpected error message: %s", ErrPlanAlreadyRun.Error())
	}
	if ErrInvalidPlanID.Error() != "invalid plan ID" {
		t.Errorf("unexpected error message: %s", ErrInvalidPlanID.Error())
	}
	if ErrInvalidWorkflow.Error() != "invalid workflow definition" {
		t.Errorf("unexpected error message: %s", ErrInvalidWorkflow.Error())
	}
}

// NoOpRepository tests

func TestNoOpRepository_Implements_Interface(t *testing.T) {
	var _ Repository = (*NoOpRepository)(nil)
}

func TestNoOpRepository_NewNoOpRepository(t *testing.T) {
	repo := NewNoOpRepository()
	if repo == nil {
		t.Error("expected non-nil repository")
	}
}

func TestNoOpRepository_SavePlan(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	err := repo.SavePlan(ctx, &Plan{PlanID: "test"})
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_GetPlan(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	plan, err := repo.GetPlan(ctx, "test")
	if err != ErrPlanNotFound {
		t.Errorf("expected ErrPlanNotFound, got %v", err)
	}
	if plan != nil {
		t.Error("expected nil plan")
	}
}

func TestService_CancelPlan(t *testing.T) {
	t.Run("cancel pending plan", func(t *testing.T) {
		repo := NewMockRepository()
		svc := NewService(repo)

		// Store a plan
		plan, err := svc.StorePlan(context.Background(), &CreatePlanRequest{
			PlanID:             "plan_cancel_1",
			Query:              "Test query",
			Domain:             "generic",
			WorkflowDefinition: validWorkflowJSON(),
			StepCount:          1,
		})
		if err != nil {
			t.Fatalf("StorePlan failed: %v", err)
		}
		if plan.Status != PlanStatusPending {
			t.Fatalf("Plan status = %s, want pending", plan.Status)
		}

		// Cancel it
		err = svc.CancelPlan(context.Background(), "plan_cancel_1", "user requested")
		if err != nil {
			t.Fatalf("CancelPlan failed: %v", err)
		}

		// Verify cancelled
		got, err := svc.GetPlan(context.Background(), "plan_cancel_1")
		if err != nil {
			t.Fatalf("GetPlan failed: %v", err)
		}
		if got.Status != PlanStatusCancelled {
			t.Errorf("Status = %s, want cancelled", got.Status)
		}
		if got.ErrorMessage != "user requested" {
			t.Errorf("ErrorMessage = %q, want %q", got.ErrorMessage, "user requested")
		}
	})

	t.Run("cancel executing plan", func(t *testing.T) {
		repo := NewMockRepository()
		svc := NewService(repo)

		// Store and start executing
		_, _ = svc.StorePlan(context.Background(), &CreatePlanRequest{
			PlanID:             "plan_cancel_2",
			Query:              "Test query",
			Domain:             "generic",
			WorkflowDefinition: validWorkflowJSON(),
			StepCount:          1,
		})
		_, _ = svc.GetPlanForExecution(context.Background(), "plan_cancel_2", "")

		// Cancel it
		err := svc.CancelPlan(context.Background(), "plan_cancel_2", "timeout")
		if err != nil {
			t.Fatalf("CancelPlan failed: %v", err)
		}

		got, _ := svc.GetPlan(context.Background(), "plan_cancel_2")
		if got.Status != PlanStatusCancelled {
			t.Errorf("Status = %s, want cancelled", got.Status)
		}
	})

	t.Run("cancel completed plan fails", func(t *testing.T) {
		repo := NewMockRepository()
		svc := NewService(repo)

		_, _ = svc.StorePlan(context.Background(), &CreatePlanRequest{
			PlanID:             "plan_cancel_3",
			Query:              "Test query",
			Domain:             "generic",
			WorkflowDefinition: validWorkflowJSON(),
			StepCount:          1,
		})
		_ = svc.MarkPlanCompleted(context.Background(), "plan_cancel_3", nil)

		err := svc.CancelPlan(context.Background(), "plan_cancel_3", "too late")
		if err == nil {
			t.Error("CancelPlan should fail for completed plan")
		}
	})

	t.Run("cancel already cancelled plan fails", func(t *testing.T) {
		repo := NewMockRepository()
		svc := NewService(repo)

		_, _ = svc.StorePlan(context.Background(), &CreatePlanRequest{
			PlanID:             "plan_cancel_4",
			Query:              "Test query",
			Domain:             "generic",
			WorkflowDefinition: validWorkflowJSON(),
			StepCount:          1,
		})
		_ = svc.CancelPlan(context.Background(), "plan_cancel_4", "first cancel")

		err := svc.CancelPlan(context.Background(), "plan_cancel_4", "second cancel")
		if err == nil {
			t.Error("CancelPlan should fail for already cancelled plan")
		}
	})

	t.Run("cancel nonexistent plan fails", func(t *testing.T) {
		repo := NewMockRepository()
		svc := NewService(repo)

		err := svc.CancelPlan(context.Background(), "nonexistent", "reason")
		if err == nil {
			t.Error("CancelPlan should fail for nonexistent plan")
		}
	})
}

func TestPlanStatus_Cancelled(t *testing.T) {
	if PlanStatusCancelled != "cancelled" {
		t.Errorf("PlanStatusCancelled = %q, want %q", PlanStatusCancelled, "cancelled")
	}
}

func TestNoOpRepository_UpdatePlanStatus(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	err := repo.UpdatePlanStatus(ctx, "test", PlanStatusCompleted, nil, "")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_UpdatePlanStatusAtomic(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	err := repo.UpdatePlanStatusAtomic(ctx, "test", PlanStatusPending, PlanStatusExecuting)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_DeletePlan(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	err := repo.DeletePlan(ctx, "test")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNoOpRepository_CleanupExpiredPlans(t *testing.T) {
	repo := NewNoOpRepository()
	ctx := context.Background()

	count, err := repo.CleanupExpiredPlans(ctx)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 count, got %d", count)
	}
}
