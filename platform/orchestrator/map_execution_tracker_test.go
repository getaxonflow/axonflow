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
