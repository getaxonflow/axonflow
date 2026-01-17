// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// MockRepository is an in-memory implementation of Repository for testing
type MockRepository struct {
	mu        sync.RWMutex
	workflows map[string]*Workflow
	steps     map[string]map[string]*WorkflowStep // workflowID -> stepID -> step
}

// NewMockRepository creates a new in-memory mock repository
func NewMockRepository() *MockRepository {
	return &MockRepository{
		workflows: make(map[string]*Workflow),
		steps:     make(map[string]map[string]*WorkflowStep),
	}
}

// Create stores a new workflow
func (m *MockRepository) Create(ctx context.Context, workflow *Workflow) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if workflow.WorkflowID == "" {
		workflow.WorkflowID = fmt.Sprintf("wf_mock_%d", len(m.workflows)+1)
	}

	if workflow.Source == "" {
		workflow.Source = WorkflowSourceExternal
	}

	if workflow.Status == "" {
		workflow.Status = WorkflowStatusInProgress
	}

	now := time.Now()
	workflow.StartedAt = now
	workflow.CreatedAt = now
	workflow.UpdatedAt = now

	m.workflows[workflow.WorkflowID] = workflow
	m.steps[workflow.WorkflowID] = make(map[string]*WorkflowStep)

	return nil
}

// GetByID retrieves a workflow by ID
func (m *MockRepository) GetByID(ctx context.Context, workflowID string) (*Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}

	// Deep copy to avoid race conditions
	copy := *workflow
	copy.Steps = make([]WorkflowStep, 0)

	if steps, ok := m.steps[workflowID]; ok {
		for _, step := range steps {
			copy.Steps = append(copy.Steps, *step)
		}
	}

	return &copy, nil
}

// UpdateStatus updates a workflow's status
func (m *MockRepository) UpdateStatus(ctx context.Context, workflowID string, status WorkflowStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow not found: %s", workflowID)
	}

	workflow.Status = status
	workflow.UpdatedAt = time.Now()

	return nil
}

// Complete marks a workflow as completed
func (m *MockRepository) Complete(ctx context.Context, workflowID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow not found: %s", workflowID)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusCompleted
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now

	return nil
}

// Abort marks a workflow as aborted
func (m *MockRepository) Abort(ctx context.Context, workflowID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow not found: %s", workflowID)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusAborted
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now

	return nil
}

// Fail marks a workflow as failed
func (m *MockRepository) Fail(ctx context.Context, workflowID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow not found: %s", workflowID)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusFailed
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now

	return nil
}

// List retrieves workflows with optional filters
func (m *MockRepository) List(ctx context.Context, opts ListWorkflowsOptions) ([]Workflow, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []Workflow

	for _, w := range m.workflows {
		// Apply filters
		if opts.TenantID != "" && w.TenantID != opts.TenantID {
			continue
		}
		if opts.OrgID != "" && w.OrgID != opts.OrgID {
			continue
		}
		if opts.Status != nil && w.Status != *opts.Status {
			continue
		}
		if opts.Source != nil && w.Source != *opts.Source {
			continue
		}

		result = append(result, *w)
	}

	total := len(result)

	// Apply pagination
	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}
	offset := opts.Offset
	if offset >= len(result) {
		return []Workflow{}, total, nil
	}

	end := offset + limit
	if end > len(result) {
		end = len(result)
	}

	return result[offset:end], total, nil
}

// AddStep records a new step
func (m *MockRepository) AddStep(ctx context.Context, step *WorkflowStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.workflows[step.WorkflowID]; !ok {
		return fmt.Errorf("workflow not found: %s", step.WorkflowID)
	}

	if m.steps[step.WorkflowID] == nil {
		m.steps[step.WorkflowID] = make(map[string]*WorkflowStep)
	}

	step.ID = len(m.steps[step.WorkflowID]) + 1
	step.GateCheckedAt = time.Now()

	m.steps[step.WorkflowID][step.StepID] = step

	// Update workflow's current step index
	if workflow, ok := m.workflows[step.WorkflowID]; ok {
		if step.StepIndex > workflow.CurrentStepIndex {
			workflow.CurrentStepIndex = step.StepIndex
			workflow.UpdatedAt = time.Now()
		}
	}

	return nil
}

// GetStep retrieves a specific step
func (m *MockRepository) GetStep(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			copy := *step
			return &copy, nil
		}
	}

	return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
}

// UpdateStepApproval updates a step's approval status
func (m *MockRepository) UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			step.ApprovalStatus = &status
			step.ApprovedBy = approvedBy
			now := time.Now()
			step.ApprovedAt = &now
			return nil
		}
	}

	return fmt.Errorf("step not found: %s/%s", workflowID, stepID)
}

// MarkStepCompleted marks a step as completed
func (m *MockRepository) MarkStepCompleted(ctx context.Context, workflowID, stepID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			now := time.Now()
			step.StepCompletedAt = &now
			return nil
		}
	}

	return fmt.Errorf("step not found: %s/%s", workflowID, stepID)
}

// GetStepsForWorkflow retrieves all steps for a workflow
func (m *MockRepository) GetStepsForWorkflow(ctx context.Context, workflowID string) ([]WorkflowStep, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []WorkflowStep

	if steps, ok := m.steps[workflowID]; ok {
		for _, step := range steps {
			result = append(result, *step)
		}
	}

	return result, nil
}

// GetPendingApprovals retrieves steps awaiting approval
func (m *MockRepository) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]WorkflowStep, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []WorkflowStep

	for workflowID, steps := range m.steps {
		workflow, ok := m.workflows[workflowID]
		if !ok || (tenantID != "" && workflow.TenantID != tenantID) {
			continue
		}

		for _, step := range steps {
			if step.ApprovalStatus != nil && *step.ApprovalStatus == ApprovalStatusPending {
				result = append(result, *step)
				if limit > 0 && len(result) >= limit {
					return result, nil
				}
			}
		}
	}

	return result, nil
}
