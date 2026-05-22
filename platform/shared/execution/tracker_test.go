// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// MockClock provides controllable time for testing
type MockClock struct {
	now time.Time
}

func (m *MockClock) Now() time.Time {
	return m.now
}

func (m *MockClock) Advance(d time.Duration) {
	m.now = m.now.Add(d)
}

// MockRepository implements ExecutionRepository for testing
type MockRepository struct {
	mu         sync.Mutex
	executions map[string]*ExecutionStatus
	createErr  error
	getErr     error
	updateErr  error
	listErr    error
	deleteErr  error
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		executions: make(map[string]*ExecutionStatus),
	}
}

func (m *MockRepository) Create(ctx context.Context, exec *ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return m.createErr
	}
	if exec == nil {
		return ErrInvalidExecution
	}
	// Deep copy to avoid mutation issues
	copy := *exec
	copy.Steps = append([]StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &copy
	return nil
}

func (m *MockRepository) Get(ctx context.Context, executionID string) (*ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.getErr != nil {
		return nil, m.getErr
	}
	exec, ok := m.executions[executionID]
	if !ok {
		return nil, ErrExecutionNotFound
	}
	// Deep copy to avoid mutation issues
	copy := *exec
	copy.Steps = append([]StepStatus{}, exec.Steps...)
	return &copy, nil
}

func (m *MockRepository) Update(ctx context.Context, exec *ExecutionStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	if exec == nil {
		return ErrInvalidExecution
	}
	if _, ok := m.executions[exec.ExecutionID]; !ok {
		return ErrExecutionNotFound
	}
	// Deep copy
	copy := *exec
	copy.Steps = append([]StepStatus{}, exec.Steps...)
	m.executions[exec.ExecutionID] = &copy
	return nil
}

func (m *MockRepository) List(ctx context.Context, req ListExecutionsRequest) ([]ExecutionStatus, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, 0, m.listErr
	}

	var results []ExecutionStatus
	for _, exec := range m.executions {
		// Apply filters
		if req.ExecutionType != nil && exec.ExecutionType != *req.ExecutionType {
			continue
		}
		if req.Status != nil && exec.Status != *req.Status {
			continue
		}
		if req.TenantID != "" && exec.TenantID != req.TenantID {
			continue
		}
		if req.OrgID != "" && exec.OrgID != req.OrgID {
			continue
		}
		results = append(results, *exec)
	}

	total := len(results)

	// Apply pagination
	if req.Offset > 0 && req.Offset < len(results) {
		results = results[req.Offset:]
	} else if req.Offset >= len(results) {
		results = []ExecutionStatus{}
	}
	if req.Limit > 0 && req.Limit < len(results) {
		results = results[:req.Limit]
	}

	return results, total, nil
}

// v9 Phase 8 #2384 PR-C1: Delete/Update*/Expire signatures gained
// orgID + tenantID for RLS scoping; the mock ignores them (in-memory store
// doesn't enforce RLS).
func (m *MockRepository) Delete(ctx context.Context, _, _, executionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if _, ok := m.executions[executionID]; !ok {
		return ErrExecutionNotFound
	}
	delete(m.executions, executionID)
	return nil
}

func (m *MockRepository) UpdateStatus(ctx context.Context, _, _, executionID string, status ExecutionStatusValue, completedAt *time.Time, errorMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	exec, ok := m.executions[executionID]
	if !ok {
		return ErrExecutionNotFound
	}
	exec.Status = status
	exec.CompletedAt = completedAt
	exec.Error = errorMsg
	exec.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) UpdateSteps(ctx context.Context, _, _, executionID string, steps []StepStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	exec, ok := m.executions[executionID]
	if !ok {
		return ErrExecutionNotFound
	}
	exec.Steps = append([]StepStatus{}, steps...)
	exec.TotalSteps = len(steps)
	exec.UpdatedAt = time.Now()
	return nil
}

func (m *MockRepository) UpdateCost(ctx context.Context, _, _, executionID string, estimatedCost, actualCost *float64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return m.updateErr
	}
	exec, ok := m.executions[executionID]
	if !ok {
		return ErrExecutionNotFound
	}
	if estimatedCost != nil {
		exec.EstimatedCostUSD = estimatedCost
	}
	if actualCost != nil {
		exec.ActualCostUSD = actualCost
	}
	exec.UpdatedAt = time.Now()
	return nil
}

// SetError helpers for testing error paths
func (m *MockRepository) CountActive(ctx context.Context, tenantID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, exec := range m.executions {
		if exec.TenantID == tenantID && (exec.Status == StatusRunning || exec.Status == StatusPending) {
			count++
		}
	}
	return count, nil
}

func (m *MockRepository) PurgeOldest(ctx context.Context, orgID, tenantID string, keepCount int) (int64, error) {
	// Simplified mock: just return 0
	return 0, nil
}

func (m *MockRepository) GetByPlanID(ctx context.Context, planID string) (*ExecutionStatus, error) {
	return m.GetByMetadata(ctx, "plan_id", planID)
}

func (m *MockRepository) GetByMetadata(ctx context.Context, key, value string) (*ExecutionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, exec := range m.executions {
		if exec.Metadata != nil {
			if v, ok := exec.Metadata[key].(string); ok && v == value {
				copy := *exec
				copy.Steps = append([]StepStatus{}, exec.Steps...)
				return &copy, nil
			}
		}
	}
	return nil, ErrExecutionNotFound
}

func (m *MockRepository) ExpireExecution(ctx context.Context, _, _, executionID string, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	exec, ok := m.executions[executionID]
	if !ok {
		return ErrExecutionNotFound
	}
	exec.Status = StatusExpired
	now := time.Now()
	exec.CompletedAt = &now
	exec.UpdatedAt = now
	return nil
}

func (m *MockRepository) SetCreateError(err error)  { m.createErr = err }
func (m *MockRepository) SetGetError(err error)     { m.getErr = err }
func (m *MockRepository) SetUpdateError(err error)  { m.updateErr = err }
func (m *MockRepository) SetListError(err error)    { m.listErr = err }
func (m *MockRepository) SetDeleteError(err error)  { m.deleteErr = err }
func (m *MockRepository) ClearErrors() {
	m.createErr = nil
	m.getErr = nil
	m.updateErr = nil
	m.listErr = nil
	m.deleteErr = nil
}

// --- Tests ---

func TestBaseExecutionTracker_StartExecution(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	tests := []struct {
		name      string
		req       CreateExecutionRequest
		setupErr  error
		wantErr   bool
		checkFunc func(*testing.T, *ExecutionStatus)
	}{
		{
			name: "create MAP execution",
			req: CreateExecutionRequest{
				ExecutionType: ExecutionTypeMAP,
				Name:          "Test Plan",
				TotalSteps:    3,
				TenantID:      "tenant-123",
				UserID:        "user-456",
				Metadata:      map[string]interface{}{"key": "value"},
			},
			wantErr: false,
			checkFunc: func(t *testing.T, exec *ExecutionStatus) {
				if exec.ExecutionType != ExecutionTypeMAP {
					t.Errorf("ExecutionType = %v, want %v", exec.ExecutionType, ExecutionTypeMAP)
				}
				if exec.Name != "Test Plan" {
					t.Errorf("Name = %v, want %v", exec.Name, "Test Plan")
				}
				if exec.Status != StatusPending {
					t.Errorf("Status = %v, want %v", exec.Status, StatusPending)
				}
				if exec.TotalSteps != 3 {
					t.Errorf("TotalSteps = %v, want %v", exec.TotalSteps, 3)
				}
				if exec.TenantID != "tenant-123" {
					t.Errorf("TenantID = %v, want %v", exec.TenantID, "tenant-123")
				}
				if !exec.StartedAt.Equal(clock.now) {
					t.Errorf("StartedAt = %v, want %v", exec.StartedAt, clock.now)
				}
				if len(exec.ExecutionID) < 5 {
					t.Errorf("ExecutionID too short: %v", exec.ExecutionID)
				}
				if exec.ExecutionID[:5] != "plan_" {
					t.Errorf("ExecutionID should start with plan_, got %v", exec.ExecutionID)
				}
			},
		},
		{
			name: "create WCP execution",
			req: CreateExecutionRequest{
				ExecutionType: ExecutionTypeWCP,
				Name:          "LangChain Workflow",
				Source:        "langchain",
				TotalSteps:    5,
			},
			wantErr: false,
			checkFunc: func(t *testing.T, exec *ExecutionStatus) {
				if exec.ExecutionType != ExecutionTypeWCP {
					t.Errorf("ExecutionType = %v, want %v", exec.ExecutionType, ExecutionTypeWCP)
				}
				if exec.Source != "langchain" {
					t.Errorf("Source = %v, want %v", exec.Source, "langchain")
				}
				if exec.ExecutionID[:3] != "wf_" {
					t.Errorf("ExecutionID should start with wf_, got %v", exec.ExecutionID)
				}
			},
		},
		{
			name: "repository error",
			req: CreateExecutionRequest{
				ExecutionType: ExecutionTypeMAP,
				Name:          "Test Plan",
			},
			setupErr: errors.New("database connection failed"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo.ClearErrors()
			if tt.setupErr != nil {
				repo.SetCreateError(tt.setupErr)
			}

			exec, err := tracker.StartExecution(context.Background(), tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("StartExecution() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.checkFunc != nil {
				tt.checkFunc(t, exec)
			}
		})
	}
}

func TestBaseExecutionTracker_ConcurrentExecutionLimit(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)
	tracker.MaxConcurrentExecutions = 2

	tenantID := "tenant-limit-test"

	// Start 2 executions — should succeed
	for i := 0; i < 2; i++ {
		_, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
			ExecutionType: ExecutionTypeMAP,
			Name:          fmt.Sprintf("Exec %d", i),
			TenantID:      tenantID,
		})
		if err != nil {
			t.Fatalf("StartExecution %d error = %v", i, err)
		}
	}

	// Third should fail with concurrent limit error
	_, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Exec overflow",
		TenantID:      tenantID,
	})
	if !errors.Is(err, ErrConcurrentExecutionLimit) {
		t.Fatalf("expected ErrConcurrentExecutionLimit, got %v", err)
	}

	// Different tenant should succeed (limit is per-tenant)
	_, err = tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Other Tenant Exec",
		TenantID:      "other-tenant",
	})
	if err != nil {
		t.Fatalf("different tenant should succeed, got error: %v", err)
	}
}

func TestBaseExecutionTracker_ConcurrentExecutionLimit_Unlimited(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)
	tracker.MaxConcurrentExecutions = -1 // unlimited (Enterprise)

	// Should be able to start many executions
	for i := 0; i < 10; i++ {
		_, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
			ExecutionType: ExecutionTypeMAP,
			Name:          fmt.Sprintf("Exec %d", i),
			TenantID:      "tenant-unlimited",
		})
		if err != nil {
			t.Fatalf("StartExecution %d error = %v", i, err)
		}
	}
}

func TestBaseExecutionTracker_GetStatus(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	// Create an execution first
	exec, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
		TotalSteps:    3,
	})
	if err != nil {
		t.Fatalf("Failed to create execution: %v", err)
	}

	tests := []struct {
		name        string
		executionID string
		setupErr    error
		wantErr     bool
		wantErrType error
	}{
		{
			name:        "get existing execution",
			executionID: exec.ExecutionID,
			wantErr:     false,
		},
		{
			name:        "get non-existent execution",
			executionID: "nonexistent",
			wantErr:     true,
			wantErrType: ErrExecutionNotFound,
		},
		{
			name:        "repository error",
			executionID: exec.ExecutionID,
			setupErr:    errors.New("database error"),
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo.ClearErrors()
			if tt.setupErr != nil {
				repo.SetGetError(tt.setupErr)
			}

			result, err := tracker.GetStatus(context.Background(), tt.executionID)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErrType != nil && !errors.Is(err, tt.wantErrType) {
				t.Errorf("GetStatus() error = %v, wantErrType %v", err, tt.wantErrType)
			}

			if !tt.wantErr {
				if result.ExecutionID != tt.executionID {
					t.Errorf("ExecutionID = %v, want %v", result.ExecutionID, tt.executionID)
				}
			}
		})
	}
}

func TestBaseExecutionTracker_ListExecutions(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	// Create multiple executions
	for i := 0; i < 5; i++ {
		execType := ExecutionTypeMAP
		if i%2 == 0 {
			execType = ExecutionTypeWCP
		}
		_, err := tracker.StartExecution(context.Background(), CreateExecutionRequest{
			ExecutionType: execType,
			Name:          "Test Execution",
			TenantID:      "tenant-1",
		})
		if err != nil {
			t.Fatalf("Failed to create execution: %v", err)
		}
	}

	mapType := ExecutionTypeMAP
	wcpType := ExecutionTypeWCP

	tests := []struct {
		name      string
		req       ListExecutionsRequest
		wantCount int
		wantTotal int
		setupErr  error
		wantErr   bool
	}{
		{
			name:      "list all",
			req:       ListExecutionsRequest{Limit: 100},
			wantCount: 5,
			wantTotal: 5,
		},
		{
			name:      "filter by MAP type",
			req:       ListExecutionsRequest{ExecutionType: &mapType, Limit: 100},
			wantCount: 2,
			wantTotal: 2,
		},
		{
			name:      "filter by WCP type",
			req:       ListExecutionsRequest{ExecutionType: &wcpType, Limit: 100},
			wantCount: 3,
			wantTotal: 3,
		},
		{
			name:      "with pagination",
			req:       ListExecutionsRequest{Limit: 2, Offset: 0},
			wantCount: 2,
			wantTotal: 5,
		},
		{
			name:      "default limit applied",
			req:       ListExecutionsRequest{},
			wantCount: 5, // all fit in default limit of 20
			wantTotal: 5,
		},
		{
			name:      "limit capped at 100",
			req:       ListExecutionsRequest{Limit: 500},
			wantCount: 5, // only 5 exist
			wantTotal: 5,
		},
		{
			name:     "repository error",
			req:      ListExecutionsRequest{},
			setupErr: errors.New("database error"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo.ClearErrors()
			if tt.setupErr != nil {
				repo.SetListError(tt.setupErr)
			}

			result, err := tracker.ListExecutions(context.Background(), tt.req)

			if (err != nil) != tt.wantErr {
				t.Errorf("ListExecutions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(result.Executions) != tt.wantCount {
					t.Errorf("Executions count = %v, want %v", len(result.Executions), tt.wantCount)
				}
				if result.Total != tt.wantTotal {
					t.Errorf("Total = %v, want %v", result.Total, tt.wantTotal)
				}
			}
		})
	}
}

func TestBaseExecutionTracker_CompleteExecution(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	clock.Advance(5 * time.Minute)

	err := tracker.CompleteExecution(context.Background(), exec.ExecutionID, map[string]string{"result": "success"})
	if err != nil {
		t.Errorf("CompleteExecution() error = %v", err)
	}

	// Verify status changed
	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Status != StatusCompleted {
		t.Errorf("Status = %v, want %v", updated.Status, StatusCompleted)
	}
	if updated.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}
}

func TestBaseExecutionTracker_FailExecution(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	testErr := errors.New("step 2 failed: API timeout")
	err := tracker.FailExecution(context.Background(), exec.ExecutionID, testErr)
	if err != nil {
		t.Errorf("FailExecution() error = %v", err)
	}

	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Status != StatusFailed {
		t.Errorf("Status = %v, want %v", updated.Status, StatusFailed)
	}
	if updated.Error != testErr.Error() {
		t.Errorf("Error = %v, want %v", updated.Error, testErr.Error())
	}
}

func TestBaseExecutionTracker_CancelExecution(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	reason := "User requested cancellation"
	err := tracker.CancelExecution(context.Background(), exec.ExecutionID, reason)
	if err != nil {
		t.Errorf("CancelExecution() error = %v", err)
	}

	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Status != StatusCancelled {
		t.Errorf("Status = %v, want %v", updated.Status, StatusCancelled)
	}
	if updated.Error != reason {
		t.Errorf("Error = %v, want %v", updated.Error, reason)
	}
}

func TestBaseExecutionTracker_StepLifecycle(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
		TotalSteps:    0, // Will be updated as we add steps
	})

	// Add step
	step := StepStatus{
		StepID:    "step-1",
		StepIndex: 0,
		StepName:  "Initialize",
		StepType:  StepTypeAction,
	}
	err := tracker.AddStep(context.Background(), exec.ExecutionID, step)
	if err != nil {
		t.Fatalf("AddStep() error = %v", err)
	}

	// Verify step added
	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if len(updated.Steps) != 1 {
		t.Fatalf("Steps count = %v, want 1", len(updated.Steps))
	}
	if updated.Steps[0].Status != StepStatusPending {
		t.Errorf("Step status = %v, want %v", updated.Steps[0].Status, StepStatusPending)
	}

	// Start step
	clock.Advance(1 * time.Second)
	err = tracker.StartStep(context.Background(), exec.ExecutionID, "step-1")
	if err != nil {
		t.Fatalf("StartStep() error = %v", err)
	}

	updated, _ = tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Steps[0].Status != StepStatusRunning {
		t.Errorf("Step status = %v, want %v", updated.Steps[0].Status, StepStatusRunning)
	}
	if updated.Status != StatusRunning {
		t.Errorf("Execution status = %v, want %v", updated.Status, StatusRunning)
	}

	// Complete step
	clock.Advance(5 * time.Second)
	err = tracker.CompleteStep(context.Background(), exec.ExecutionID, "step-1", nil)
	if err != nil {
		t.Fatalf("CompleteStep() error = %v", err)
	}

	updated, _ = tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Steps[0].Status != StepStatusCompleted {
		t.Errorf("Step status = %v, want %v", updated.Steps[0].Status, StepStatusCompleted)
	}
	if updated.Steps[0].EndedAt == nil {
		t.Error("EndedAt should be set")
	}
}

func TestBaseExecutionTracker_FailStep(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	step := StepStatus{
		StepID:    "step-1",
		StepIndex: 0,
		StepName:  "Initialize",
		StepType:  StepTypeAction,
	}
	tracker.AddStep(context.Background(), exec.ExecutionID, step)
	tracker.StartStep(context.Background(), exec.ExecutionID, "step-1")

	stepErr := errors.New("connection refused")
	err := tracker.FailStep(context.Background(), exec.ExecutionID, "step-1", stepErr)
	if err != nil {
		t.Fatalf("FailStep() error = %v", err)
	}

	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.Steps[0].Status != StepStatusFailed {
		t.Errorf("Step status = %v, want %v", updated.Steps[0].Status, StepStatusFailed)
	}
	if updated.Steps[0].Error != stepErr.Error() {
		t.Errorf("Step error = %v, want %v", updated.Steps[0].Error, stepErr.Error())
	}
}

func TestBaseExecutionTracker_UpdateStepDecision(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeWCP,
		Name:          "Test Workflow",
	})

	step := StepStatus{
		StepID:    "step-1",
		StepIndex: 0,
		StepName:  "Risk Assessment",
		StepType:  StepTypeGate,
	}
	tracker.AddStep(context.Background(), exec.ExecutionID, step)

	tests := []struct {
		name           string
		decision       GateDecision
		reason         string
		policies       []string
		expectedStatus StepStatusValue
	}{
		{
			name:           "allow decision",
			decision:       GateDecisionAllow,
			reason:         "Within risk tolerance",
			policies:       []string{"policy-1"},
			expectedStatus: StepStatusPending, // Allow doesn't change status
		},
		{
			name:           "block decision",
			decision:       GateDecisionBlock,
			reason:         "Exceeds budget limit",
			policies:       []string{"budget-policy"},
			expectedStatus: StepStatusBlocked,
		},
		{
			name:           "require approval",
			decision:       GateDecisionRequireApproval,
			reason:         "High-risk operation",
			policies:       []string{"approval-policy"},
			expectedStatus: StepStatusApproval,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset step status
			exec, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
			exec.Steps[0].Status = StepStatusPending
			repo.Update(context.Background(), exec)

			err := tracker.UpdateStepDecision(context.Background(), exec.ExecutionID, "step-1", tt.decision, tt.reason, tt.policies)
			if err != nil {
				t.Fatalf("UpdateStepDecision() error = %v", err)
			}

			updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
			if updated.Steps[0].Decision != tt.decision {
				t.Errorf("Decision = %v, want %v", updated.Steps[0].Decision, tt.decision)
			}
			if updated.Steps[0].DecisionReason != tt.reason {
				t.Errorf("DecisionReason = %v, want %v", updated.Steps[0].DecisionReason, tt.reason)
			}
			if tt.decision != GateDecisionAllow && updated.Steps[0].Status != tt.expectedStatus {
				t.Errorf("Status = %v, want %v", updated.Steps[0].Status, tt.expectedStatus)
			}
		})
	}
}

func TestBaseExecutionTracker_CostTracking(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	// Add steps with costs
	for i := 0; i < 3; i++ {
		step := StepStatus{
			StepID:    string(rune('a' + i)),
			StepIndex: i,
			StepName:  "Step",
			StepType:  StepTypeAction,
		}
		tracker.AddStep(context.Background(), exec.ExecutionID, step)
	}

	// Set estimated cost
	err := tracker.SetEstimatedCost(context.Background(), exec.ExecutionID, 0.05)
	if err != nil {
		t.Fatalf("SetEstimatedCost() error = %v", err)
	}

	// Record step costs
	tracker.RecordStepCost(context.Background(), exec.ExecutionID, "a", 0.01)
	tracker.RecordStepCost(context.Background(), exec.ExecutionID, "b", 0.02)
	tracker.RecordStepCost(context.Background(), exec.ExecutionID, "c", 0.005)

	updated, _ := tracker.GetStatus(context.Background(), exec.ExecutionID)
	if updated.EstimatedCostUSD == nil || *updated.EstimatedCostUSD != 0.05 {
		t.Errorf("EstimatedCostUSD = %v, want 0.05", updated.EstimatedCostUSD)
	}
	if updated.ActualCostUSD == nil {
		t.Fatal("ActualCostUSD should be set")
	}
	// Use approximate comparison for floating point
	diff := *updated.ActualCostUSD - 0.035
	if diff < 0 {
		diff = -diff
	}
	if diff > 0.0001 {
		t.Errorf("ActualCostUSD = %v, want ~0.035", *updated.ActualCostUSD)
	}
}

func TestBaseExecutionTracker_ErrorPaths(t *testing.T) {
	repo := NewMockRepository()
	clock := &MockClock{now: time.Date(2026, 1, 23, 10, 0, 0, 0, time.UTC)}
	tracker := NewBaseExecutionTrackerWithClock(repo, clock)

	// Create a valid execution first
	exec, _ := tracker.StartExecution(context.Background(), CreateExecutionRequest{
		ExecutionType: ExecutionTypeMAP,
		Name:          "Test Plan",
	})

	t.Run("AddStep with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.AddStep(context.Background(), exec.ExecutionID, StepStatus{StepID: "step-1"})
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})

	t.Run("StartStep with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.StartStep(context.Background(), exec.ExecutionID, "step-1")
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})

	t.Run("CompleteStep with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.CompleteStep(context.Background(), exec.ExecutionID, "step-1", nil)
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})

	t.Run("FailStep with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.FailStep(context.Background(), exec.ExecutionID, "step-1", errors.New("test"))
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})

	t.Run("UpdateStepDecision with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.UpdateStepDecision(context.Background(), exec.ExecutionID, "step-1", GateDecisionAllow, "", nil)
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})

	t.Run("RecordStepCost with get error", func(t *testing.T) {
		repo.SetGetError(errors.New("database error"))
		err := tracker.RecordStepCost(context.Background(), exec.ExecutionID, "step-1", 0.01)
		if err == nil {
			t.Error("Expected error")
		}
		repo.ClearErrors()
	})
}

func TestNewBaseExecutionTracker(t *testing.T) {
	repo := NewMockRepository()
	tracker := NewBaseExecutionTracker(repo)

	if tracker == nil {
		t.Fatal("NewBaseExecutionTracker returned nil")
	}

	// Should use RealClock by default
	if _, ok := tracker.clock.(RealClock); !ok {
		t.Error("Default clock should be RealClock")
	}
}

func TestRealClock(t *testing.T) {
	clock := RealClock{}
	before := time.Now()
	clockTime := clock.Now()
	after := time.Now()

	if clockTime.Before(before) || clockTime.After(after) {
		t.Error("RealClock.Now() should return current time")
	}
}
