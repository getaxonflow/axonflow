// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// ExecutionTracker defines the interface for tracking execution status.
// Both MAP and WCP implement this interface with their specific logic.
type ExecutionTracker interface {
	// Lifecycle management
	StartExecution(ctx context.Context, req CreateExecutionRequest) (*ExecutionStatus, error)
	CompleteExecution(ctx context.Context, executionID string, result interface{}) error
	FailExecution(ctx context.Context, executionID string, err error) error
	CancelExecution(ctx context.Context, executionID string, reason string) error

	// Step management
	AddStep(ctx context.Context, executionID string, step StepStatus) error
	StartStep(ctx context.Context, executionID, stepID string) error
	CompleteStep(ctx context.Context, executionID, stepID string, result interface{}) error
	FailStep(ctx context.Context, executionID, stepID string, err error) error
	UpdateStepDecision(ctx context.Context, executionID, stepID string, decision GateDecision, reason string, policies []string) error

	// Status retrieval
	GetStatus(ctx context.Context, executionID string) (*ExecutionStatus, error)
	ListExecutions(ctx context.Context, req ListExecutionsRequest) (*ListExecutionsResponse, error)

	// Cost tracking
	RecordStepCost(ctx context.Context, executionID, stepID string, costUSD float64) error
	SetEstimatedCost(ctx context.Context, executionID string, costUSD float64) error
}

// ExecutionRepository defines the database operations for execution tracking.
type ExecutionRepository interface {
	// Create a new execution record
	Create(ctx context.Context, exec *ExecutionStatus) error

	// Get an execution by ID
	Get(ctx context.Context, executionID string) (*ExecutionStatus, error)

	// Update an execution
	Update(ctx context.Context, exec *ExecutionStatus) error

	// List executions with filters
	List(ctx context.Context, req ListExecutionsRequest) ([]ExecutionStatus, int, error)

	// Delete an execution (for cleanup).
	//
	// v9 Phase 8 #2384 PR-C1: orgID + tenantID are required so the
	// PostgresRepository can wrap the DELETE in WithOrgAndTenantScope —
	// execution_history's mig 042 USING/WITH CHECK predicate is keyed on
	// app.current_tenant_id. The caller has both from a prior Get.
	Delete(ctx context.Context, orgID, tenantID, executionID string) error

	// Update specific fields. See Delete for the orgID/tenantID rationale.
	UpdateStatus(ctx context.Context, orgID, tenantID, executionID string, status ExecutionStatusValue, completedAt *time.Time, errorMsg string) error
	UpdateSteps(ctx context.Context, orgID, tenantID, executionID string, steps []StepStatus) error
	UpdateCost(ctx context.Context, orgID, tenantID, executionID string, estimatedCost, actualCost *float64) error

	// GetByPlanID looks up a single execution by plan_id in metadata.
	// Uses the expression index on metadata->>'plan_id' for efficient lookup.
	GetByPlanID(ctx context.Context, planID string) (*ExecutionStatus, error)

	// GetByMetadata looks up a single execution by a metadata key-value pair.
	GetByMetadata(ctx context.Context, key, value string) (*ExecutionStatus, error)

	// ExpireExecution marks an execution as expired (MAP-specific: plan expired before execution).
	ExpireExecution(ctx context.Context, orgID, tenantID, executionID string, metadata map[string]interface{}) error

	// CountActive returns the number of executions with running/pending status for a tenant.
	CountActive(ctx context.Context, tenantID string) (int, error)

	// PurgeOldest removes the oldest execution records beyond keepCount for a tenant.
	// v9 Phase 8 #2384 PR-C1 DoD D-4: orgID + tenantID required so the
	// postgres impl can wrap the DELETE in WithOrgAndTenantScope (mig 042
	// app.current_tenant_id-keyed USING).
	PurgeOldest(ctx context.Context, orgID, tenantID string, keepCount int) (int64, error)
}

// ErrConcurrentExecutionLimit is returned when the concurrent execution limit is reached.
var ErrConcurrentExecutionLimit = errors.New("concurrent execution limit reached")

// BaseExecutionTracker provides common functionality for execution tracking.
// MAP and WCP trackers embed this and add their specific logic.
type BaseExecutionTracker struct {
	repo                   ExecutionRepository
	clock                  Clock // For testing
	eventHub               *EventHub
	MaxConcurrentExecutions int  // 0 or negative = unlimited
}

// Clock interface for time operations (enables testing)
type Clock interface {
	Now() time.Time
}

// RealClock implements Clock using actual time
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// NewBaseExecutionTracker creates a new base tracker.
func NewBaseExecutionTracker(repo ExecutionRepository) *BaseExecutionTracker {
	return &BaseExecutionTracker{
		repo:  repo,
		clock: RealClock{},
	}
}

// NewBaseExecutionTrackerWithClock creates a tracker with a custom clock (for testing).
func NewBaseExecutionTrackerWithClock(repo ExecutionRepository, clock Clock) *BaseExecutionTracker {
	return &BaseExecutionTracker{
		repo:  repo,
		clock: clock,
	}
}

// GetRepo returns the underlying repository.
func (t *BaseExecutionTracker) GetRepo() ExecutionRepository {
	return t.repo
}

// SetEventHub sets the event hub for publishing execution state changes.
func (t *BaseExecutionTracker) SetEventHub(hub *EventHub) {
	t.eventHub = hub
}

// GetEventHub returns the event hub, or nil if not set.
func (t *BaseExecutionTracker) GetEventHub() *EventHub {
	return t.eventHub
}

// publishEvent publishes an execution event to the event hub.
// No-op if the event hub is not set.
func (t *BaseExecutionTracker) publishEvent(ctx context.Context, eventType string, executionID string) {
	if t.eventHub == nil {
		return
	}
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return
	}
	t.eventHub.Publish(ExecutionEvent{
		EventType:   eventType,
		ExecutionID: executionID,
		Data:        exec,
	})
}

// StartExecution creates a new execution record.
func (t *BaseExecutionTracker) StartExecution(ctx context.Context, req CreateExecutionRequest) (*ExecutionStatus, error) {
	// Check concurrent execution limit
	if t.MaxConcurrentExecutions > 0 && req.TenantID != "" {
		active, err := t.repo.CountActive(ctx, req.TenantID)
		if err == nil && active >= t.MaxConcurrentExecutions {
			return nil, ErrConcurrentExecutionLimit
		}
	}

	now := t.clock.Now()

	// #3442: a subsystem that already owns the run's identity supplies it;
	// everyone else gets one minted. The empty check is not defensive
	// decoration - an empty ExecutionID would be written as the PRIMARY KEY of
	// execution_history, so falling back to a generated id is what keeps a
	// caller that forgot to set it from writing an unaddressable row (or, on
	// the second such row, failing a unique violation).
	executionID := req.ExecutionID
	if executionID == "" {
		executionID = generateExecutionID(req.ExecutionType)
	}
	externalID := req.ExternalID
	if externalID == "" {
		externalID = executionID
	}

	exec := &ExecutionStatus{
		ExecutionID:      executionID,
		ExternalID:       externalID,
		ExecutionType:    req.ExecutionType,
		Name:             req.Name,
		Source:           req.Source,
		Status:           StatusPending,
		CurrentStepIndex: 0,
		TotalSteps:       req.TotalSteps,
		ProgressPercent:  0,
		StartedAt:        now,
		TenantID:         req.TenantID,
		OrgID:            req.OrgID,
		UserID:           req.UserID,
		ClientID:         req.ClientID,
		Metadata:         req.Metadata,
		Steps:            []StepStatus{},
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := t.repo.Create(ctx, exec); err != nil {
		return nil, err
	}

	t.publishEvent(ctx, EventExecutionStarted, exec.ExecutionID)
	return exec, nil
}

// GetStatus retrieves the current execution status.
func (t *BaseExecutionTracker) GetStatus(ctx context.Context, executionID string) (*ExecutionStatus, error) {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return nil, err
	}

	// Calculate derived fields
	exec.ProgressPercent = exec.CalculateProgress()
	exec.Duration = exec.CalculateDuration()
	if exec.ActualCostUSD == nil {
		cost := exec.TotalCost()
		if cost > 0 {
			exec.ActualCostUSD = &cost
		}
	}

	return exec, nil
}

// ListExecutions returns a paginated list of executions.
func (t *BaseExecutionTracker) ListExecutions(ctx context.Context, req ListExecutionsRequest) (*ListExecutionsResponse, error) {
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	executions, total, err := t.repo.List(ctx, req)
	if err != nil {
		return nil, err
	}

	// Calculate derived fields for each execution
	for i := range executions {
		executions[i].ProgressPercent = executions[i].CalculateProgress()
		executions[i].Duration = executions[i].CalculateDuration()
		if executions[i].ActualCostUSD == nil {
			cost := executions[i].TotalCost()
			if cost > 0 {
				executions[i].ActualCostUSD = &cost
			}
		}
	}

	return &ListExecutionsResponse{
		Executions: executions,
		Total:      total,
		Limit:      req.Limit,
		Offset:     req.Offset,
		HasMore:    req.Offset+len(executions) < total,
	}, nil
}

// CompleteExecution marks an execution as completed.
//
// v9 Phase 8 #2384 PR-C1: fetches orgID + tenantID via the prior Get so
// the repo can scope the UPDATE.
func (t *BaseExecutionTracker) CompleteExecution(ctx context.Context, executionID string, result interface{}) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}
	now := t.clock.Now()
	if err := t.repo.UpdateStatus(ctx, exec.OrgID, exec.TenantID, executionID, StatusCompleted, &now, ""); err != nil {
		return err
	}
	t.publishEvent(ctx, EventExecutionCompleted, executionID)
	return nil
}

// FailExecution marks an execution as failed.
func (t *BaseExecutionTracker) FailExecution(ctx context.Context, executionID string, err error) error {
	exec, getErr := t.repo.Get(ctx, executionID)
	if getErr != nil {
		return getErr
	}
	now := t.clock.Now()
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	if updateErr := t.repo.UpdateStatus(ctx, exec.OrgID, exec.TenantID, executionID, StatusFailed, &now, errMsg); updateErr != nil {
		return updateErr
	}
	t.publishEvent(ctx, EventExecutionFailed, executionID)
	return nil
}

// CancelExecution marks an execution as cancelled.
func (t *BaseExecutionTracker) CancelExecution(ctx context.Context, executionID string, reason string) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}
	now := t.clock.Now()
	if err := t.repo.UpdateStatus(ctx, exec.OrgID, exec.TenantID, executionID, StatusCancelled, &now, reason); err != nil {
		return err
	}
	t.publishEvent(ctx, EventExecutionCancelled, executionID)
	return nil
}

// AddStep adds a new step to the execution.
func (t *BaseExecutionTracker) AddStep(ctx context.Context, executionID string, step StepStatus) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}

	if step.Status == "" {
		step.Status = StepStatusPending
	}
	exec.Steps = append(exec.Steps, step)
	exec.TotalSteps = len(exec.Steps)
	exec.UpdatedAt = t.clock.Now()

	return t.repo.UpdateSteps(ctx, exec.OrgID, exec.TenantID, executionID, exec.Steps)
}

// StartStep marks a step as running.
func (t *BaseExecutionTracker) StartStep(ctx context.Context, executionID, stepID string) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}

	now := t.clock.Now()
	for i := range exec.Steps {
		if exec.Steps[i].StepID == stepID {
			exec.Steps[i].Status = StepStatusRunning
			exec.Steps[i].StartedAt = &now
			exec.CurrentStepIndex = exec.Steps[i].StepIndex
			break
		}
	}

	// Update execution status to running if pending
	if exec.Status == StatusPending {
		exec.Status = StatusRunning
	}

	exec.UpdatedAt = now
	if err := t.repo.Update(ctx, exec); err != nil {
		return err
	}
	t.publishEvent(ctx, EventStepStarted, executionID)
	return nil
}

// CompleteStep marks a step as completed.
// If result is a map[string]interface{} containing tokens_in, tokens_out, or cost_usd,
// those values override the step's existing metrics (set at gate time).
func (t *BaseExecutionTracker) CompleteStep(ctx context.Context, executionID, stepID string, result interface{}) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}

	now := t.clock.Now()
	for i := range exec.Steps {
		if exec.Steps[i].StepID == stepID {
			exec.Steps[i].Status = StepStatusCompleted
			exec.Steps[i].EndedAt = &now
			exec.Steps[i].Duration = exec.Steps[i].CalculateDuration()

			// Apply post-execution metrics from result if provided
			if m, ok := result.(map[string]interface{}); ok {
				if v, ok := m["tokens_in"].(int); ok {
					exec.Steps[i].TokensIn = &v
				}
				if v, ok := m["tokens_out"].(int); ok {
					exec.Steps[i].TokensOut = &v
				}
				if v, ok := m["cost_usd"].(float64); ok {
					exec.Steps[i].CostUSD = &v
				}
			}
			break
		}
	}

	exec.UpdatedAt = now
	if err := t.repo.UpdateSteps(ctx, exec.OrgID, exec.TenantID, executionID, exec.Steps); err != nil {
		return err
	}
	t.publishEvent(ctx, EventStepCompleted, executionID)
	return nil
}

// FailStep marks a step as failed.
func (t *BaseExecutionTracker) FailStep(ctx context.Context, executionID, stepID string, err error) error {
	exec, getErr := t.repo.Get(ctx, executionID)
	if getErr != nil {
		return getErr
	}

	now := t.clock.Now()
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}

	for i := range exec.Steps {
		if exec.Steps[i].StepID == stepID {
			exec.Steps[i].Status = StepStatusFailed
			exec.Steps[i].EndedAt = &now
			exec.Steps[i].Duration = exec.Steps[i].CalculateDuration()
			exec.Steps[i].Error = errMsg
			break
		}
	}

	exec.UpdatedAt = now
	if err := t.repo.UpdateSteps(ctx, exec.OrgID, exec.TenantID, executionID, exec.Steps); err != nil {
		return err
	}
	t.publishEvent(ctx, EventStepFailed, executionID)
	return nil
}

// UpdateStepDecision updates the policy decision for a step (WCP use case).
func (t *BaseExecutionTracker) UpdateStepDecision(ctx context.Context, executionID, stepID string, decision GateDecision, reason string, policies []string) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}

	for i := range exec.Steps {
		if exec.Steps[i].StepID == stepID {
			exec.Steps[i].Decision = decision
			exec.Steps[i].DecisionReason = reason
			exec.Steps[i].PoliciesMatched = policies

			// Update step status based on decision
			switch decision {
			case GateDecisionBlock:
				exec.Steps[i].Status = StepStatusBlocked
			case GateDecisionRequireApproval:
				exec.Steps[i].Status = StepStatusApproval
				pending := ApprovalStatusPending
				exec.Steps[i].ApprovalStatus = &pending
			}
			break
		}
	}

	exec.UpdatedAt = t.clock.Now()
	if err := t.repo.UpdateSteps(ctx, exec.OrgID, exec.TenantID, executionID, exec.Steps); err != nil {
		return err
	}
	t.publishEvent(ctx, EventStepDecision, executionID)
	return nil
}

// RecordStepCost records the cost for a step.
func (t *BaseExecutionTracker) RecordStepCost(ctx context.Context, executionID, stepID string, costUSD float64) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}

	for i := range exec.Steps {
		if exec.Steps[i].StepID == stepID {
			exec.Steps[i].CostUSD = &costUSD
			break
		}
	}

	// Update total actual cost
	totalCost := exec.TotalCost()
	exec.ActualCostUSD = &totalCost
	exec.UpdatedAt = t.clock.Now()

	return t.repo.Update(ctx, exec)
}

// SetEstimatedCost sets the estimated cost for the execution.
func (t *BaseExecutionTracker) SetEstimatedCost(ctx context.Context, executionID string, costUSD float64) error {
	exec, err := t.repo.Get(ctx, executionID)
	if err != nil {
		return err
	}
	return t.repo.UpdateCost(ctx, exec.OrgID, exec.TenantID, executionID, &costUSD, nil)
}

// --- ID Generation ---

// generateExecutionID generates a unique execution ID with type prefix.
//
// ENTROPY: 96 random bits (12 crypto/rand bytes, hex-encoded to 24
// characters). That is far past any birthday bound a deployment can reach.
//
// #3442 removed a `wf_<UnixNano>` fallback that this function returned when
// rand.Read reported an error. It was not merely an untested failure path, it
// was UNREACHABLE: since Go 1.24 `crypto/rand.Read` "never returns an error,
// and always fills b entirely" - on an operating-system RNG failure it
// crashes the program irrecoverably rather than returning. The branch could
// therefore never run, and what it would have produced was a guessable,
// clock-derived id that is not even unique under concurrency on a coarse
// clock. Deleting it removes a fallback that could only ever have been a
// liability, with no behaviour change, and the errcheck-silenced discard
// below records why the error is not handled.
//
// The `wf` case is now reached only if a WCP caller fails to supply the
// control-plane workflow id; the WCP tracker always supplies it (see
// CreateExecutionRequest.ExecutionID).
func generateExecutionID(execType ExecutionType) string {
	prefix := "exec"
	switch execType {
	case ExecutionTypeMAP:
		prefix = "plan"
	case ExecutionTypeWCP:
		prefix = "wf"
	}

	bytes := make([]byte, 12)
	// crypto/rand.Read cannot fail; see the entropy note above.
	_, _ = rand.Read(bytes)

	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(bytes))
}
