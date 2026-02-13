// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/execution"
)

// MockMAPRepository implements execution.ExecutionRepository for testing
type MockMAPRepository struct {
	mu         sync.Mutex
	executions map[string]*execution.ExecutionStatus
}

func NewMockMAPRepository() *MockMAPRepository {
	return &MockMAPRepository{
		executions: make(map[string]*execution.ExecutionStatus),
	}
}

func (m *MockMAPRepository) Create(ctx context.Context, exec *execution.ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := *exec
	copy.Steps = append([]execution.StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &copy
	return nil
}

func (m *MockMAPRepository) Get(ctx context.Context, executionID string) (*execution.ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return nil, execution.ErrExecutionNotFound
	}
	copy := *exec
	copy.Steps = append([]execution.StepStatus{}, exec.Steps...)
	return &copy, nil
}

func (m *MockMAPRepository) Update(ctx context.Context, exec *execution.ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.executions[exec.ExecutionID]; !ok {
		return execution.ErrExecutionNotFound
	}
	copy := *exec
	copy.Steps = append([]execution.StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &copy
	return nil
}

func (m *MockMAPRepository) List(ctx context.Context, req execution.ListExecutionsRequest) ([]execution.ExecutionStatus, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var results []execution.ExecutionStatus
	for _, exec := range m.executions {
		if req.ExecutionType != nil && exec.ExecutionType != *req.ExecutionType {
			continue
		}
		results = append(results, *exec)
	}
	return results, len(results), nil
}

func (m *MockMAPRepository) Delete(ctx context.Context, executionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.executions, executionID)
	return nil
}

func (m *MockMAPRepository) UpdateStatus(ctx context.Context, executionID string, status execution.ExecutionStatusValue, completedAt *time.Time, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	exec.Status = status
	exec.CompletedAt = completedAt
	exec.Error = errorMsg
	return nil
}

func (m *MockMAPRepository) UpdateSteps(ctx context.Context, executionID string, steps []execution.StepStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	exec.Steps = append([]execution.StepStatus{}, steps...)
	exec.TotalSteps = len(steps)
	return nil
}

func (m *MockMAPRepository) UpdateCost(ctx context.Context, executionID string, estimatedCost, actualCost *float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	if estimatedCost != nil {
		exec.EstimatedCostUSD = estimatedCost
	}
	if actualCost != nil {
		exec.ActualCostUSD = actualCost
	}
	return nil
}

func (m *MockMAPRepository) CountActive(_ context.Context, tenantID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, exec := range m.executions {
		if exec.TenantID == tenantID && (exec.Status == execution.StatusRunning || exec.Status == execution.StatusPending) {
			count++
		}
	}
	return count, nil
}

func (m *MockMAPRepository) GetByPlanID(ctx context.Context, planID string) (*execution.ExecutionStatus, error) {
	return m.GetByMetadata(ctx, "plan_id", planID)
}

func (m *MockMAPRepository) GetByMetadata(ctx context.Context, key, value string) (*execution.ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, exec := range m.executions {
		if exec.Metadata != nil {
			if v, ok := exec.Metadata[key].(string); ok && v == value {
				copy := *exec
				copy.Steps = append([]execution.StepStatus{}, exec.Steps...)
				return &copy, nil
			}
		}
	}
	return nil, execution.ErrExecutionNotFound
}

func (m *MockMAPRepository) ExpireExecution(ctx context.Context, executionID string, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return execution.ErrExecutionNotFound
	}
	exec.Status = execution.StatusExpired
	now := time.Now()
	exec.CompletedAt = &now
	exec.UpdatedAt = now
	return nil
}

func (m *MockMAPRepository) PurgeOldest(_ context.Context, _ string, _ int) (int64, error) {
	return 0, nil
}

// MockPlanService implements a minimal planning.Service for testing
type MockPlanService struct {
	plans map[string]*planning.Plan
}

func (m *MockPlanService) GetPlan(ctx context.Context, planID string) (*planning.Plan, error) {
	plan, ok := m.plans[planID]
	if !ok {
		return nil, planning.ErrPlanNotFound
	}
	return plan, nil
}

func TestMapStepType(t *testing.T) {
	tests := []struct {
		input    string
		expected execution.StepType
	}{
		{"llm-call", execution.StepTypeLLMCall},
		{"tool-call", execution.StepTypeToolCall},
		{"function", execution.StepTypeToolCall},
		{"connector-call", execution.StepTypeConnectorCall},
		{"human-task", execution.StepTypeHumanTask},
		{"human", execution.StepTypeHumanTask},
		{"synthesis", execution.StepTypeSynthesis},
		{"unknown", execution.StepTypeAction},
		{"", execution.StepTypeAction},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapStepType(tt.input)
			if got != tt.expected {
				t.Errorf("mapStepType(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestMapPlanStatus(t *testing.T) {
	tests := []struct {
		input    planning.PlanStatus
		expected execution.ExecutionStatusValue
	}{
		{planning.PlanStatusPending, execution.StatusPending},
		{planning.PlanStatusExecuting, execution.StatusRunning},
		{planning.PlanStatusCompleted, execution.StatusCompleted},
		{planning.PlanStatusFailed, execution.StatusFailed},
		{planning.PlanStatusExpired, execution.StatusExpired},
		{planning.PlanStatus("unknown"), execution.StatusPending},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := mapPlanStatus(tt.input)
			if got != tt.expected {
				t.Errorf("mapPlanStatus(%v) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func TestPlanToExecutionStatus(t *testing.T) {
	now := time.Now()

	// Create a sample workflow definition
	workflow := Workflow{
		APIVersion: "v1",
		Kind:       "workflow",
		Metadata: WorkflowMetadata{
			Name:        "test-workflow",
			Description: "Test workflow",
		},
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call", Provider: "openai", Model: "gpt-4"},
				{Name: "step2", Type: "connector-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	t.Run("pending plan", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:             "plan_123",
			Query:              "Test query",
			Domain:             "general",
			Status:             planning.PlanStatusPending,
			StepCount:          2,
			Complexity:         1,
			Parallel:           false,
			EstimatedDuration:  "5s",
			ExecutionMode:      "sequential",
			WorkflowDefinition: workflowJSON,
			TenantID:           "tenant-1",
			OrgID:              "org-1",
			UserID:             "user-1",
			ClientID:           "client-1",
			CreatedAt:          now,
			UpdatedAt:          now,
			ExpiresAt:          now.Add(1 * time.Hour),
		}

		exec := planToExecutionStatus(plan)

		if exec.ExecutionID != "plan_123" {
			t.Errorf("ExecutionID = %v, want plan_123", exec.ExecutionID)
		}
		if exec.ExecutionType != execution.ExecutionTypeMAP {
			t.Errorf("ExecutionType = %v, want MAP", exec.ExecutionType)
		}
		if exec.Status != execution.StatusPending {
			t.Errorf("Status = %v, want pending", exec.Status)
		}
		if exec.TotalSteps != 2 {
			t.Errorf("TotalSteps = %v, want 2", exec.TotalSteps)
		}
		if exec.ProgressPercent != 0 {
			t.Errorf("ProgressPercent = %v, want 0", exec.ProgressPercent)
		}
		if len(exec.Steps) != 2 {
			t.Errorf("len(Steps) = %v, want 2", len(exec.Steps))
		}
		if exec.Steps[0].StepType != execution.StepTypeLLMCall {
			t.Errorf("Steps[0].StepType = %v, want llm_call", exec.Steps[0].StepType)
		}
		if exec.Steps[0].Status != execution.StepStatusPending {
			t.Errorf("Steps[0].Status = %v, want pending", exec.Steps[0].Status)
		}
	})

	t.Run("completed plan", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:             "plan_456",
			Query:              "Completed query",
			Domain:             "general",
			Status:             planning.PlanStatusCompleted,
			StepCount:          2,
			WorkflowDefinition: workflowJSON,
			CreatedAt:          now.Add(-1 * time.Hour),
			UpdatedAt:          now,
		}

		exec := planToExecutionStatus(plan)

		if exec.Status != execution.StatusCompleted {
			t.Errorf("Status = %v, want completed", exec.Status)
		}
		if exec.CompletedAt == nil {
			t.Error("CompletedAt should be set for completed plans")
		}
		if exec.ProgressPercent != 100 {
			t.Errorf("ProgressPercent = %v, want 100", exec.ProgressPercent)
		}
		if exec.Steps[0].Status != execution.StepStatusCompleted {
			t.Errorf("Steps[0].Status = %v, want completed", exec.Steps[0].Status)
		}
	})

	t.Run("failed plan with error", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:             "plan_789",
			Query:              "Failed query",
			Status:             planning.PlanStatusFailed,
			StepCount:          2,
			ErrorMessage:       "Step 1 failed: API timeout",
			WorkflowDefinition: workflowJSON,
			CreatedAt:          now,
			UpdatedAt:          now,
		}

		exec := planToExecutionStatus(plan)

		if exec.Status != execution.StatusFailed {
			t.Errorf("Status = %v, want failed", exec.Status)
		}
		if exec.Error != "Step 1 failed: API timeout" {
			t.Errorf("Error = %v, want 'Step 1 failed: API timeout'", exec.Error)
		}
	})

	t.Run("expired plan", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:    "plan_exp",
			Query:     "Expired query",
			Status:    planning.PlanStatusExpired,
			StepCount: 2,
			CreatedAt: now.Add(-2 * time.Hour),
			UpdatedAt: now.Add(-1 * time.Hour),
			ExpiresAt: now.Add(-1 * time.Hour),
		}

		exec := planToExecutionStatus(plan)

		if exec.Status != execution.StatusExpired {
			t.Errorf("Status = %v, want expired", exec.Status)
		}
	})

	t.Run("plan without workflow definition", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:    "plan_no_wf",
			Query:     "Query without workflow",
			Status:    planning.PlanStatusPending,
			StepCount: 3,
			CreatedAt: now,
			UpdatedAt: now,
		}

		exec := planToExecutionStatus(plan)

		if len(exec.Steps) != 0 {
			t.Errorf("len(Steps) = %v, want 0 (no workflow definition)", len(exec.Steps))
		}
		if exec.TotalSteps != 3 {
			t.Errorf("TotalSteps = %v, want 3", exec.TotalSteps)
		}
	})

	t.Run("metadata is populated", func(t *testing.T) {
		plan := &planning.Plan{
			PlanID:            "plan_meta",
			Query:             "Metadata test",
			Status:            planning.PlanStatusPending,
			StepCount:         1,
			Complexity:        3,
			Parallel:          true,
			EstimatedDuration: "10s",
			ExecutionMode:     "parallel",
			ExpiresAt:         now.Add(1 * time.Hour),
			CreatedAt:         now,
			UpdatedAt:         now,
		}

		exec := planToExecutionStatus(plan)

		if exec.Metadata["plan_id"] != "plan_meta" {
			t.Errorf("Metadata[plan_id] = %v, want plan_meta", exec.Metadata["plan_id"])
		}
		if exec.Metadata["complexity"] != 3 {
			t.Errorf("Metadata[complexity] = %v, want 3", exec.Metadata["complexity"])
		}
		if exec.Metadata["parallel"] != true {
			t.Errorf("Metadata[parallel] = %v, want true", exec.Metadata["parallel"])
		}
		if exec.Metadata["execution_mode"] != "parallel" {
			t.Errorf("Metadata[execution_mode] = %v, want parallel", exec.Metadata["execution_mode"])
		}
	})
}

func TestNewMAPExecutionTracker(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)

	if tracker == nil {
		t.Fatal("NewMAPExecutionTracker returned nil")
	}
	if tracker.BaseExecutionTracker == nil {
		t.Error("BaseExecutionTracker should not be nil")
	}
}

func TestMAPExecutionTracker_StartPlanExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call", Provider: "openai", Model: "gpt-4"},
				{Name: "step2", Type: "connector-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	plan := &planning.Plan{
		PlanID:             "plan_test",
		Query:              "Test query",
		Domain:             "general",
		StepCount:          2,
		WorkflowDefinition: workflowJSON,
		TenantID:           "tenant-1",
		OrgID:              "org-1",
		UserID:             "user-1",
		ClientID:           "client-1",
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
	}

	exec, err := tracker.StartPlanExecution(ctx, plan)
	if err != nil {
		t.Fatalf("StartPlanExecution() error = %v", err)
	}

	if exec.ExecutionType != execution.ExecutionTypeMAP {
		t.Errorf("ExecutionType = %v, want MAP", exec.ExecutionType)
	}
	if exec.Name != "Test query" {
		t.Errorf("Name = %v, want 'Test query'", exec.Name)
	}
	if exec.TotalSteps != 2 {
		t.Errorf("TotalSteps = %v, want 2", exec.TotalSteps)
	}
	if len(exec.Steps) != 2 {
		t.Errorf("len(Steps) = %v, want 2", len(exec.Steps))
	}
	if exec.Steps[0].StepType != execution.StepTypeLLMCall {
		t.Errorf("Steps[0].StepType = %v, want llm_call", exec.Steps[0].StepType)
	}

	// Verify metadata contains plan_id
	if exec.Metadata["plan_id"] != "plan_test" {
		t.Errorf("Metadata[plan_id] = %v, want 'plan_test'", exec.Metadata["plan_id"])
	}
}

func TestMAPExecutionTracker_StartPlanExecution_InvalidWorkflow(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	plan := &planning.Plan{
		PlanID:             "plan_invalid",
		WorkflowDefinition: []byte("invalid json"),
	}

	_, err := tracker.StartPlanExecution(ctx, plan)
	if err == nil {
		t.Error("Expected error for invalid workflow definition")
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FromUnifiedExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Create workflow definition
	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	// Start a plan execution
	plan := &planning.Plan{
		PlanID:             "plan_status_test",
		Query:              "Status test query",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
		TenantID:           "tenant-1",
	}

	exec, err := tracker.StartPlanExecution(ctx, plan)
	if err != nil {
		t.Fatalf("StartPlanExecution() error = %v", err)
	}

	// Get status by plan ID
	status, err := tracker.GetPlanStatus(ctx, "plan_status_test")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.ExecutionID != exec.ExecutionID {
		t.Errorf("ExecutionID = %v, want %v", status.ExecutionID, exec.ExecutionID)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_NilPlanService(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Since planService is nil and no unified execution exists,
	// it should return an error
	_, err := tracker.GetPlanStatus(ctx, "nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent plan with nil plan service")
	}
}

func TestMAPExecutionTracker_SyncPlanStatus(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Create workflow
	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	// Start an execution
	plan := &planning.Plan{
		PlanID:             "plan_sync_test",
		Query:              "Sync test",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
	}

	_, err := tracker.StartPlanExecution(ctx, plan)
	if err != nil {
		t.Fatalf("StartPlanExecution() error = %v", err)
	}

	// Sync to completed status
	err = tracker.SyncPlanStatus(ctx, "plan_sync_test", planning.PlanStatusCompleted, "")
	if err != nil {
		t.Errorf("SyncPlanStatus(completed) error = %v", err)
	}

	// Verify status changed
	status, _ := tracker.GetPlanStatus(ctx, "plan_sync_test")
	if status.Status != execution.StatusCompleted {
		t.Errorf("Status = %v, want completed", status.Status)
	}
}

func TestMAPExecutionTracker_SyncPlanStatus_Failed(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	plan := &planning.Plan{
		PlanID:             "plan_fail_test",
		Query:              "Fail test",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
	}

	tracker.StartPlanExecution(ctx, plan)

	err := tracker.SyncPlanStatus(ctx, "plan_fail_test", planning.PlanStatusFailed, "Step failed: timeout")
	if err != nil {
		t.Errorf("SyncPlanStatus(failed) error = %v", err)
	}

	status, _ := tracker.GetPlanStatus(ctx, "plan_fail_test")
	if status.Status != execution.StatusFailed {
		t.Errorf("Status = %v, want failed", status.Status)
	}
}

func TestMAPExecutionTracker_SyncPlanStatus_Expired(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	plan := &planning.Plan{
		PlanID:             "plan_expire_test",
		Query:              "Expire test",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
	}

	tracker.StartPlanExecution(ctx, plan)

	err := tracker.SyncPlanStatus(ctx, "plan_expire_test", planning.PlanStatusExpired, "TTL exceeded")
	if err != nil {
		t.Errorf("SyncPlanStatus(expired) error = %v", err)
	}

	status, _ := tracker.GetPlanStatus(ctx, "plan_expire_test")
	if status.Status != execution.StatusExpired {
		t.Errorf("Status = %v, want expired", status.Status)
	}
}

func TestMAPExecutionTracker_SyncPlanStatus_Cancelled(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	plan := &planning.Plan{
		PlanID:             "plan_cancel_test",
		Query:              "Cancel test",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
	}

	tracker.StartPlanExecution(ctx, plan)

	err := tracker.SyncPlanStatus(ctx, "plan_cancel_test", planning.PlanStatusCancelled, "user cancelled")
	if err != nil {
		t.Errorf("SyncPlanStatus(cancelled) error = %v", err)
	}

	status, _ := tracker.GetPlanStatus(ctx, "plan_cancel_test")
	if status.Status != execution.StatusCancelled {
		t.Errorf("Status = %v, want cancelled", status.Status)
	}
}

func TestMAPExecutionTracker_SyncPlanStatus_CancelledDefaultReason(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	workflow := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{{Name: "step1", Type: "llm-call"}},
		},
	}
	workflowJSON, _ := json.Marshal(workflow)

	plan := &planning.Plan{
		PlanID:             "plan_cancel_default",
		Query:              "Cancel default reason",
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
	}

	tracker.StartPlanExecution(ctx, plan)

	// Empty reason should use default "plan cancelled"
	err := tracker.SyncPlanStatus(ctx, "plan_cancel_default", planning.PlanStatusCancelled, "")
	if err != nil {
		t.Errorf("SyncPlanStatus(cancelled) error = %v", err)
	}
}

func TestMAPExecutionTracker_SyncPlanStatus_NoExecution(t *testing.T) {
	repo := NewMockMAPRepository()
	tracker := NewMAPExecutionTracker(repo, nil)
	ctx := context.Background()

	// Sync for a plan that doesn't have a unified execution
	err := tracker.SyncPlanStatus(ctx, "nonexistent_plan", planning.PlanStatusCompleted, "")
	if err != nil {
		t.Errorf("SyncPlanStatus() should not error for missing execution: %v", err)
	}
}

func TestPtrExecutionType(t *testing.T) {
	mapType := ptrExecutionType(execution.ExecutionTypeMAP)
	if mapType == nil {
		t.Fatal("ptrExecutionType returned nil")
	}
	if *mapType != execution.ExecutionTypeMAP {
		t.Errorf("*ptrExecutionType(MAP) = %v, want MAP", *mapType)
	}

	wcpType := ptrExecutionType(execution.ExecutionTypeWCP)
	if wcpType == nil {
		t.Fatal("ptrExecutionType returned nil")
	}
	if *wcpType != execution.ExecutionTypeWCP {
		t.Errorf("*ptrExecutionType(WCP) = %v, want WCP", *wcpType)
	}
}

// =============================================================================
// GetPlanStatus Coverage Tests — plan service fallback path
// =============================================================================

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_WithWorkflow(t *testing.T) {
	// Test: plan is NOT in unified execution store but available via plan service,
	// with WorkflowDefinition populated. This covers the planService.GetPlan branch
	// and the planToExecutionStatus conversion with workflow parsing.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	// Store a plan in the planning repository
	workflowDef := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "analyze", Type: "llm-call", Provider: "openai", Model: "gpt-4"},
				{Name: "fetch", Type: "connector-call"},
				{Name: "synthesize", Type: "synthesis"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflowDef)

	now := time.Now()
	plan := &planning.Plan{
		PlanID:             "plan_svc_wf",
		Query:              "Analyze data trends",
		Domain:             "analytics",
		Status:             planning.PlanStatusPending,
		StepCount:          3,
		Complexity:         2,
		Parallel:           false,
		EstimatedDuration:  "15s",
		ExecutionMode:      "sequential",
		WorkflowDefinition: workflowJSON,
		TenantID:           "tenant-abc",
		OrgID:              "org-abc",
		UserID:             "user-abc",
		ClientID:           "client-abc",
		ExpiresAt:          now.Add(1 * time.Hour),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	// GetPlanStatus should fall back to plan service since repo has no metadata match
	status, err := tracker.GetPlanStatus(ctx, "plan_svc_wf")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.ExecutionID != "plan_svc_wf" {
		t.Errorf("ExecutionID = %v, want plan_svc_wf", status.ExecutionID)
	}
	if status.ExecutionType != execution.ExecutionTypeMAP {
		t.Errorf("ExecutionType = %v, want MAP", status.ExecutionType)
	}
	if status.Status != execution.StatusPending {
		t.Errorf("Status = %v, want pending", status.Status)
	}
	if status.Name != "Analyze data trends" {
		t.Errorf("Name = %v, want 'Analyze data trends'", status.Name)
	}
	if status.Source != "analytics" {
		t.Errorf("Source = %v, want 'analytics'", status.Source)
	}
	if status.TotalSteps != 3 {
		t.Errorf("TotalSteps = %v, want 3", status.TotalSteps)
	}
	if len(status.Steps) != 3 {
		t.Fatalf("len(Steps) = %v, want 3", len(status.Steps))
	}
	// Verify step types were mapped correctly
	if status.Steps[0].StepType != execution.StepTypeLLMCall {
		t.Errorf("Steps[0].StepType = %v, want llm_call", status.Steps[0].StepType)
	}
	if status.Steps[1].StepType != execution.StepTypeConnectorCall {
		t.Errorf("Steps[1].StepType = %v, want connector_call", status.Steps[1].StepType)
	}
	if status.Steps[2].StepType != execution.StepTypeSynthesis {
		t.Errorf("Steps[2].StepType = %v, want synthesis", status.Steps[2].StepType)
	}
	// All steps should be pending for a pending plan
	for i, step := range status.Steps {
		if step.Status != execution.StepStatusPending {
			t.Errorf("Steps[%d].Status = %v, want pending", i, step.Status)
		}
	}
	// Metadata should be populated
	if status.Metadata["plan_id"] != "plan_svc_wf" {
		t.Errorf("Metadata[plan_id] = %v, want plan_svc_wf", status.Metadata["plan_id"])
	}
	if status.Metadata["complexity"] != 2 {
		t.Errorf("Metadata[complexity] = %v, want 2", status.Metadata["complexity"])
	}
	if status.TenantID != "tenant-abc" {
		t.Errorf("TenantID = %v, want tenant-abc", status.TenantID)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_NoWorkflow(t *testing.T) {
	// Test: plan available via plan service but has NO WorkflowDefinition.
	// This covers the branch where len(plan.WorkflowDefinition) == 0.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	now := time.Now()
	plan := &planning.Plan{
		PlanID:            "plan_no_workflow",
		Query:             "Simple query",
		Domain:            "general",
		Status:            planning.PlanStatusExecuting,
		StepCount:         5,
		Complexity:        1,
		EstimatedDuration: "3s",
		ExecutionMode:     "sequential",
		TenantID:          "tenant-nw",
		ExpiresAt:         now.Add(1 * time.Hour),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	status, err := tracker.GetPlanStatus(ctx, "plan_no_workflow")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.Status != execution.StatusRunning {
		t.Errorf("Status = %v, want running", status.Status)
	}
	if len(status.Steps) != 0 {
		t.Errorf("len(Steps) = %v, want 0 (no workflow definition)", len(status.Steps))
	}
	if status.TotalSteps != 5 {
		t.Errorf("TotalSteps = %v, want 5", status.TotalSteps)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_CompletedPlan(t *testing.T) {
	// Test: completed plan via plan service — all steps should show completed status.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	workflowDef := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
				{Name: "step2", Type: "tool-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflowDef)

	now := time.Now()
	plan := &planning.Plan{
		PlanID:             "plan_completed_svc",
		Query:              "Completed plan query",
		Domain:             "finance",
		Status:             planning.PlanStatusCompleted,
		StepCount:          2,
		WorkflowDefinition: workflowJSON,
		ExecutionResult:    json.RawMessage(`{"summary":"done"}`),
		ExpiresAt:          now.Add(1 * time.Hour),
		CreatedAt:          now.Add(-10 * time.Minute),
		UpdatedAt:          now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	status, err := tracker.GetPlanStatus(ctx, "plan_completed_svc")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.Status != execution.StatusCompleted {
		t.Errorf("Status = %v, want completed", status.Status)
	}
	if status.CompletedAt == nil {
		t.Error("CompletedAt should be set for completed plan")
	}
	if status.ProgressPercent != 100 {
		t.Errorf("ProgressPercent = %v, want 100", status.ProgressPercent)
	}
	// All steps should be completed for a completed plan
	for i, step := range status.Steps {
		if step.Status != execution.StepStatusCompleted {
			t.Errorf("Steps[%d].Status = %v, want completed", i, step.Status)
		}
	}
	// execution_result should be in metadata
	if status.Metadata["execution_result"] == nil {
		t.Error("Metadata should contain execution_result")
	}
	// workflow_definition should be in metadata
	if status.Metadata["workflow_definition"] == nil {
		t.Error("Metadata should contain workflow_definition")
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_PlanNotFound(t *testing.T) {
	// Test: plan service also returns ErrPlanNotFound.
	// Should return execution.ErrExecutionNotFound.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()
	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	_, err := tracker.GetPlanStatus(ctx, "nonexistent_plan_id")
	if err == nil {
		t.Fatal("Expected error for nonexistent plan")
	}
	// The error should wrap execution.ErrExecutionNotFound
	if !mapTrackerContains(err.Error(), "execution not found") {
		t.Errorf("Expected error to contain 'execution not found', got: %v", err)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_RepoError(t *testing.T) {
	// Test: plan service repository returns a non-ErrPlanNotFound error.
	// This covers the branch: errors.Is(err, planning.ErrPlanNotFound) == false.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()
	planRepo.SetError(context.DeadlineExceeded) // Force a non-PlanNotFound error

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	_, err := tracker.GetPlanStatus(ctx, "plan_repo_error")
	if err == nil {
		t.Fatal("Expected error for plan service failure")
	}
	// Should contain "lookup failed" since it's not ErrPlanNotFound
	if !mapTrackerContains(err.Error(), "lookup failed") {
		t.Errorf("Expected error to contain 'lookup failed', got: %v", err)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_UnifiedWins_OverPlanService(t *testing.T) {
	// Test: when both unified execution store AND plan service have data,
	// the unified execution store should win (it's checked first).
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	workflowDef := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "step1", Type: "llm-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflowDef)

	now := time.Now()
	// Store plan in planning repository
	plan := &planning.Plan{
		PlanID:             "plan_both_exist",
		Query:              "Both exist query",
		Domain:             "general",
		Status:             planning.PlanStatusPending, // Plan says pending
		StepCount:          1,
		WorkflowDefinition: workflowJSON,
		ExpiresAt:          now.Add(1 * time.Hour),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	// Start a plan execution in the unified store — this creates a unified record
	execStatus, err := tracker.StartPlanExecution(ctx, plan)
	if err != nil {
		t.Fatalf("StartPlanExecution() error = %v", err)
	}

	// Mark the unified execution as completed
	err = tracker.CompleteExecution(ctx, execStatus.ExecutionID, nil)
	if err != nil {
		t.Fatalf("CompleteExecution() error = %v", err)
	}

	// Now query by plan ID — should return the unified execution (completed),
	// NOT the plan service result (pending).
	status, err := tracker.GetPlanStatus(ctx, "plan_both_exist")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	// Unified execution was completed; plan service would return pending.
	// Unified should win.
	if status.Status != execution.StatusCompleted {
		t.Errorf("Status = %v, want completed (unified should win over plan service pending)", status.Status)
	}
	if status.ExecutionID != execStatus.ExecutionID {
		t.Errorf("ExecutionID = %v, want %v (should come from unified store)", status.ExecutionID, execStatus.ExecutionID)
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_CancelledPlan(t *testing.T) {
	// Test: cancelled plan via plan service.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	now := time.Now()
	plan := &planning.Plan{
		PlanID:            "plan_cancelled_svc",
		Query:             "Cancelled query",
		Domain:            "ops",
		Status:            planning.PlanStatusCancelled,
		StepCount:         2,
		EstimatedDuration: "10s",
		ExpiresAt:         now.Add(1 * time.Hour),
		CreatedAt:         now.Add(-5 * time.Minute),
		UpdatedAt:         now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	status, err := tracker.GetPlanStatus(ctx, "plan_cancelled_svc")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.Status != execution.StatusCancelled {
		t.Errorf("Status = %v, want cancelled", status.Status)
	}
	if status.CompletedAt == nil {
		t.Error("CompletedAt should be set for cancelled plan")
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_FailedWithError(t *testing.T) {
	// Test: failed plan with error message via plan service.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	workflowDef := Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "analyze", Type: "llm-call"},
			},
		},
	}
	workflowJSON, _ := json.Marshal(workflowDef)

	now := time.Now()
	plan := &planning.Plan{
		PlanID:             "plan_failed_svc",
		Query:              "Failed query",
		Domain:             "research",
		Status:             planning.PlanStatusFailed,
		StepCount:          1,
		ErrorMessage:       "LLM provider returned 429: rate limited",
		WorkflowDefinition: workflowJSON,
		ExpiresAt:          now.Add(1 * time.Hour),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	status, err := tracker.GetPlanStatus(ctx, "plan_failed_svc")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.Status != execution.StatusFailed {
		t.Errorf("Status = %v, want failed", status.Status)
	}
	if status.Error != "LLM provider returned 429: rate limited" {
		t.Errorf("Error = %v, want 'LLM provider returned 429: rate limited'", status.Error)
	}
	if status.CompletedAt == nil {
		t.Error("CompletedAt should be set for failed plan")
	}
}

func TestMAPExecutionTracker_GetPlanStatus_FallbackToPlanService_ZeroStepCount(t *testing.T) {
	// Test: plan with zero step count to cover progressPercent = 0 branch.
	repo := NewMockMAPRepository()
	planRepo := planning.NewMockRepository()

	now := time.Now()
	plan := &planning.Plan{
		PlanID:    "plan_zero_steps",
		Query:     "Zero steps",
		Status:    planning.PlanStatusPending,
		StepCount: 0,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
		UpdatedAt: now,
	}
	planRepo.SavePlan(context.Background(), plan)

	planService := planning.NewService(planRepo)
	tracker := NewMAPExecutionTracker(repo, planService)
	ctx := context.Background()

	status, err := tracker.GetPlanStatus(ctx, "plan_zero_steps")
	if err != nil {
		t.Fatalf("GetPlanStatus() error = %v", err)
	}

	if status.ProgressPercent != 0 {
		t.Errorf("ProgressPercent = %v, want 0 for zero step count", status.ProgressPercent)
	}
	if status.TotalSteps != 0 {
		t.Errorf("TotalSteps = %v, want 0", status.TotalSteps)
	}
}

// mapTrackerContains checks if s contains substr (helper for error message assertions).
func mapTrackerContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
