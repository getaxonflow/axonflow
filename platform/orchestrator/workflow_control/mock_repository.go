// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// MockRepository is an in-memory implementation of Repository for testing
type MockRepository struct {
	mu          sync.RWMutex
	workflows   map[string]*Workflow
	steps       map[string]map[string]*WorkflowStep // workflowID -> stepID -> step
	checkpoints map[string]map[string]*Checkpoint   // workflowID -> stepID -> checkpoint
	cpNextID    int64
}

// NewMockRepository creates a new in-memory mock repository
func NewMockRepository() *MockRepository {
	return &MockRepository{
		workflows:   make(map[string]*Workflow),
		steps:       make(map[string]map[string]*WorkflowStep),
		checkpoints: make(map[string]map[string]*Checkpoint),
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

// Delete removes a workflow by ID
func (m *MockRepository) Delete(ctx context.Context, workflowID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.workflows, workflowID)
	delete(m.steps, workflowID)
	return nil
}

// GetByID retrieves a workflow by ID
func (m *MockRepository) GetByID(ctx context.Context, workflowID string) (*Workflow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
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
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	workflow.Status = status
	workflow.UpdatedAt = time.Now()

	return nil
}

// Complete marks a workflow as completed.
// If TotalSteps was not declared upfront, it is finalised to CurrentStepIndex.
func (m *MockRepository) Complete(ctx context.Context, workflowID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusCompleted
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now
	if workflow.TotalSteps == nil {
		idx := workflow.CurrentStepIndex
		workflow.TotalSteps = &idx
	}

	return nil
}

// Abort marks a workflow as aborted.
// If TotalSteps was not declared upfront, it is finalised to CurrentStepIndex.
func (m *MockRepository) Abort(ctx context.Context, workflowID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusAborted
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now
	if workflow.TotalSteps == nil {
		idx := workflow.CurrentStepIndex
		workflow.TotalSteps = &idx
	}

	return nil
}

// Fail marks a workflow as failed.
// If TotalSteps was not declared upfront, it is finalised to CurrentStepIndex.
func (m *MockRepository) Fail(ctx context.Context, workflowID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	workflow, ok := m.workflows[workflowID]
	if !ok {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	now := time.Now()
	workflow.Status = WorkflowStatusFailed
	workflow.CompletedAt = &now
	workflow.UpdatedAt = now
	if workflow.TotalSteps == nil {
		idx := workflow.CurrentStepIndex
		workflow.TotalSteps = &idx
	}

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
		if opts.TraceID != "" && w.TraceID != opts.TraceID {
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

// AddStep records a new step gate decision. Issue #1673: also maintains
// gate_count / completion_count / last_decision / first_attempt_at /
// idempotency_key so tests exercise the same invariants as the Postgres
// implementation. Semantics:
//   - First-time insert: gate_count=1, completion_count=0, last_decision=decision,
//     first_attempt_at=now, idempotency_key=step.IdempotencyKey.
//   - Re-gate (existing row): gate_count++, last_decision=OLD decision
//     (snapshot before overwrite), first_attempt_at preserved,
//     idempotency_key preserved (immutable once set; caller-supplied value
//     only used when the existing key is nil).
func (m *MockRepository) AddStep(ctx context.Context, step *WorkflowStep) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.workflows[step.WorkflowID]; !ok {
		return fmt.Errorf("workflow not found: %s", step.WorkflowID)
	}

	if m.steps[step.WorkflowID] == nil {
		m.steps[step.WorkflowID] = make(map[string]*WorkflowStep)
	}

	now := time.Now()
	step.GateCheckedAt = now

	existing := m.steps[step.WorkflowID][step.StepID]
	if existing == nil {
		// First-call insert
		step.ID = len(m.steps[step.WorkflowID]) + 1
		step.GateCount = 1
		step.CompletionCount = 0
		step.LastDecision = step.Decision
		first := now
		step.FirstAttemptAt = &first
		// step.IdempotencyKey already set by caller; keep as-is
		m.steps[step.WorkflowID][step.StepID] = step
	} else {
		// Re-gate UPSERT: preserve immutable fields, bump counter, snapshot OLD decision
		step.ID = existing.ID
		step.GateCount = existing.GateCount + 1
		step.CompletionCount = existing.CompletionCount
		step.LastDecision = existing.Decision // OLD decision becomes last_decision
		step.FirstAttemptAt = existing.FirstAttemptAt
		// idempotency_key is immutable once set: keep existing, else take new
		if existing.IdempotencyKey != nil {
			step.IdempotencyKey = existing.IdempotencyKey
		}
		m.steps[step.WorkflowID][step.StepID] = step
	}

	// Update workflow's current step index
	if workflow, ok := m.workflows[step.WorkflowID]; ok {
		if step.StepIndex > workflow.CurrentStepIndex {
			workflow.CurrentStepIndex = step.StepIndex
			workflow.UpdatedAt = now
		}
	}

	return nil
}

// BumpGateCountCached increments gate_count and snapshots last_decision without
// changing decision. Used by the cached-hit path of StepGate (Issue #1673).
func (m *MockRepository) BumpGateCountCached(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	steps, ok := m.steps[workflowID]
	if !ok {
		return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}
	step, ok := steps[stepID]
	if !ok {
		return nil, fmt.Errorf("step not found: %s/%s", workflowID, stepID)
	}

	step.GateCount++
	// last_decision = decision snapshots the current (cached) decision so the
	// NEXT call's retry_context.last_decision reflects this call's outcome.
	step.LastDecision = step.Decision
	step.GateCheckedAt = time.Now()

	copy := *step
	return &copy, nil
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

// GetStepDecision retrieves a step's cached decision for idempotent retry support (#1414).
// Returns nil (not error) when the step has not been evaluated yet.
func (m *MockRepository) GetStepDecision(ctx context.Context, workflowID, stepID string) (*WorkflowStep, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			copy := *step
			return &copy, nil
		}
	}

	return nil, nil
}

// UpdateStepApproval updates a step's approval status
func (m *MockRepository) UpdateStepApproval(ctx context.Context, workflowID, stepID string, status ApprovalStatus, approvedBy string, comment string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			step.ApprovalStatus = &status
			step.ApprovedBy = approvedBy
			step.ApprovalComment = comment
			now := time.Now()
			step.ApprovedAt = &now
			return nil
		}
	}

	return fmt.Errorf("step not found: %s/%s", workflowID, stepID)
}

// MarkStepCompleted marks a step as completed, optionally applying post-execution metrics.
// Issue #1673: also increments completion_count so retry_context on subsequent
// gate calls reflects that a prior /complete landed.
func (m *MockRepository) MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *StepCompleteRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if steps, ok := m.steps[workflowID]; ok {
		if step, ok := steps[stepID]; ok {
			now := time.Now()
			step.StepCompletedAt = &now
			step.CompletionCount++
			if req != nil {
				if req.TokensIn != nil {
					step.TokensIn = req.TokensIn
				}
				if req.TokensOut != nil {
					step.TokensOut = req.TokensOut
				}
				if req.CostUSD != nil {
					step.CostUSD = req.CostUSD
				}
				if req.Output != nil {
					data, _ := json.Marshal(req.Output)
					step.StepOutput = data
				}
			}
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

// GetPendingApprovals retrieves steps awaiting approval with workflow context
func (m *MockRepository) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]PendingApprovalResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []PendingApprovalResponse

	for workflowID, steps := range m.steps {
		workflow, ok := m.workflows[workflowID]
		if !ok || (tenantID != "" && workflow.TenantID != tenantID) {
			continue
		}

		for _, step := range steps {
			if step.ApprovalStatus != nil && *step.ApprovalStatus == ApprovalStatusPending {
				result = append(result, PendingApprovalResponse{
					WorkflowID:      step.WorkflowID,
					WorkflowName:    workflow.WorkflowName,
					StepID:          step.StepID,
					StepIndex:       step.StepIndex,
					StepName:        step.StepName,
					StepType:        step.StepType,
					Decision:        step.Decision,
					DecisionReason:  step.DecisionReason,
					PoliciesMatched: step.PoliciesMatched,
					StepInput:       step.StepInput,
					ApprovalStatus:  step.ApprovalStatus,
					CreatedAt:       step.GateCheckedAt,
				})
				if limit > 0 && len(result) >= limit {
					return result, nil
				}
			}
		}
	}

	return result, nil
}

// CountPendingApprovals returns the total number of pending approvals for a tenant.
func (m *MockRepository) CountPendingApprovals(ctx context.Context, tenantID string) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for workflowID, steps := range m.steps {
		workflow, ok := m.workflows[workflowID]
		if !ok || (tenantID != "" && workflow.TenantID != tenantID) {
			continue
		}
		for _, step := range steps {
			if step.ApprovalStatus != nil && *step.ApprovalStatus == ApprovalStatusPending {
				count++
			}
		}
	}

	return count, nil
}

// --- Checkpoint mock implementations ---

// CreateCheckpoint stores a checkpoint, upserting on workflow_id+step_id conflict.
func (m *MockRepository) CreateCheckpoint(ctx context.Context, cp *Checkpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.checkpoints[cp.WorkflowID] == nil {
		m.checkpoints[cp.WorkflowID] = make(map[string]*Checkpoint)
	}

	// Check if exists (upsert)
	if existing, ok := m.checkpoints[cp.WorkflowID][cp.StepID]; ok {
		existing.StepIndex = cp.StepIndex
		existing.CheckpointType = cp.CheckpointType
		existing.GateDecision = cp.GateDecision
		existing.GateReason = cp.GateReason
		existing.PoliciesEvaluated = cp.PoliciesEvaluated
		existing.PoliciesMatched = cp.PoliciesMatched
		existing.StepInput = cp.StepInput
		existing.IsResumable = cp.IsResumable
		cp.ID = existing.ID
		cp.CreatedAt = existing.CreatedAt
		return nil
	}

	m.cpNextID++
	cp.ID = m.cpNextID
	cp.CreatedAt = time.Now()
	copy := *cp
	m.checkpoints[cp.WorkflowID][cp.StepID] = &copy
	return nil
}

// ListCheckpoints returns all checkpoints for a workflow, sorted by step_index.
func (m *MockRepository) ListCheckpoints(ctx context.Context, workflowID string) ([]Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cps, ok := m.checkpoints[workflowID]
	if !ok {
		return []Checkpoint{}, nil
	}

	result := make([]Checkpoint, 0, len(cps))
	for _, cp := range cps {
		result = append(result, *cp)
	}

	// Sort by step_index
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].StepIndex < result[i].StepIndex {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result, nil
}

// GetLastResumableCheckpoint returns the checkpoint with the highest step_index that is resumable.
func (m *MockRepository) GetLastResumableCheckpoint(ctx context.Context, workflowID string) (*Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cps, ok := m.checkpoints[workflowID]
	if !ok {
		return nil, nil
	}

	var best *Checkpoint
	for _, cp := range cps {
		if cp.IsResumable {
			if best == nil || cp.StepIndex > best.StepIndex {
				copy := *cp
				best = &copy
			}
		}
	}

	return best, nil
}

// GetCheckpointByID returns a checkpoint by its database ID.
func (m *MockRepository) GetCheckpointByID(ctx context.Context, id int64) (*Checkpoint, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, cps := range m.checkpoints {
		for _, cp := range cps {
			if cp.ID == id {
				copy := *cp
				return &copy, nil
			}
		}
	}

	return nil, nil
}

// IncrementResumeCount increments the resume counter and sets last_resumed_at.
func (m *MockRepository) IncrementResumeCount(ctx context.Context, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, cps := range m.checkpoints {
		for _, cp := range cps {
			if cp.ID == id {
				cp.ResumeCount++
				now := time.Now()
				cp.LastResumedAt = &now
				return nil
			}
		}
	}

	return nil
}
