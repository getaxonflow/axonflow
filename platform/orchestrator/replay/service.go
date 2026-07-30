// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// Service provides execution replay and debugging capabilities
type Service struct {
	repo   Repository
	mu     sync.RWMutex
	logger *log.Logger

	// In-flight executions cache for fast updates
	executions map[string]*ExecutionSummary
}

// NewService creates a new replay service
func NewService(repo Repository) *Service {
	return &Service{
		repo:       repo,
		logger:     log.Default(),
		executions: make(map[string]*ExecutionSummary),
	}
}

// NewServiceWithLogger creates a new replay service with a custom logger
func NewServiceWithLogger(repo Repository, logger *log.Logger) *Service {
	if logger == nil {
		logger = log.Default()
	}
	return &Service{
		repo:       repo,
		logger:     logger,
		executions: make(map[string]*ExecutionSummary),
	}
}

// StartExecution initializes a new execution tracking session
func (s *Service) StartExecution(ctx context.Context, requestID, workflowName string, totalSteps int, orgID, tenantID, userID string) error {
	summary := &ExecutionSummary{
		RequestID:    requestID,
		WorkflowName: workflowName,
		Status:       ExecutionStatusRunning,
		TotalSteps:   totalSteps,
		StartedAt:    time.Now().UTC(),
		OrgID:        orgID,
		TenantID:     tenantID,
		UserID:       userID,
	}

	// Save to database
	if err := s.repo.SaveSummary(ctx, summary); err != nil {
		s.logger.Printf("[Replay] Failed to save execution summary: %v", err)
		return fmt.Errorf("failed to start execution: %w", err)
	}

	// Cache in memory for fast updates
	s.mu.Lock()
	s.executions[requestID] = summary
	s.mu.Unlock()

	s.logger.Printf("[Replay] Started execution tracking: %s (workflow=%s, steps=%d)", requestID, workflowName, totalSteps)
	return nil
}

// RecordStep records a step execution snapshot
func (s *Service) RecordStep(ctx context.Context, snapshot *ExecutionSnapshot) error {
	if snapshot == nil {
		return ErrInvalidInput
	}

	// Save snapshot to database
	if err := s.repo.SaveSnapshot(ctx, snapshot); err != nil {
		s.logger.Printf("[Replay] Failed to save snapshot for %s step %d: %v", snapshot.RequestID, snapshot.StepIndex, err)
		return fmt.Errorf("failed to record step: %w", err)
	}

	// Update execution summary if step completed
	if snapshot.Status == StepStatusCompleted || snapshot.Status == StepStatusFailed {
		s.updateExecutionProgress(ctx, snapshot)
	}

	s.logger.Printf("[Replay] Recorded step %d (%s) for %s: status=%s",
		snapshot.StepIndex, snapshot.StepName, snapshot.RequestID, snapshot.Status)
	return nil
}

// updateExecutionProgress updates the execution summary based on step completion
func (s *Service) updateExecutionProgress(ctx context.Context, snapshot *ExecutionSnapshot) {
	s.mu.Lock()
	summary, exists := s.executions[snapshot.RequestID]
	if !exists {
		s.mu.Unlock()
		// Try to load from database
		var err error
		summary, err = s.repo.GetSummary(ctx, snapshot.RequestID)
		if err != nil {
			s.logger.Printf("[Replay] Failed to get summary for progress update: %v", err)
			return
		}
		s.mu.Lock()
		s.executions[snapshot.RequestID] = summary
	}
	defer s.mu.Unlock()

	// Update progress
	if snapshot.Status == StepStatusCompleted {
		summary.CompletedSteps++
		summary.TotalTokens += snapshot.TokensIn + snapshot.TokensOut
		summary.TotalCostUSD += snapshot.CostUSD
	}

	// Check if execution is complete
	if summary.CompletedSteps >= summary.TotalSteps {
		now := time.Now().UTC()
		summary.Status = ExecutionStatusCompleted
		summary.CompletedAt = &now
		duration := int(now.Sub(summary.StartedAt).Milliseconds())
		summary.DurationMs = &duration
	}

	// Update in database (non-blocking)
	// Create a copy to avoid data race with concurrent modifications
	summaryCopy := *summary
	if summary.CompletedAt != nil {
		completedAt := *summary.CompletedAt
		summaryCopy.CompletedAt = &completedAt
	}
	if summary.DurationMs != nil {
		durationMs := *summary.DurationMs
		summaryCopy.DurationMs = &durationMs
	}
	go func(sum ExecutionSummary) {
		if err := s.repo.UpdateSummary(context.Background(), &sum); err != nil {
			s.logger.Printf("[Replay] Failed to update execution summary: %v", err)
		}
	}(summaryCopy)
}

// CompleteExecution marks an execution as completed
func (s *Service) CompleteExecution(ctx context.Context, requestID string, outputSummary json.RawMessage) error {
	s.mu.Lock()
	summary, exists := s.executions[requestID]
	if !exists {
		s.mu.Unlock()
		var err error
		summary, err = s.repo.GetSummary(ctx, requestID)
		if err != nil {
			return err
		}
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	now := time.Now().UTC()
	summary.Status = ExecutionStatusCompleted
	summary.CompletedAt = &now
	duration := int(now.Sub(summary.StartedAt).Milliseconds())
	summary.DurationMs = &duration
	summary.OutputSummary = outputSummary

	if err := s.repo.UpdateSummary(ctx, summary); err != nil {
		return fmt.Errorf("failed to complete execution: %w", err)
	}

	// Remove from cache
	delete(s.executions, requestID)

	s.logger.Printf("[Replay] Completed execution: %s (duration=%dms, tokens=%d, cost=$%.6f)",
		requestID, duration, summary.TotalTokens, summary.TotalCostUSD)
	return nil
}

// FailExecution marks an execution as failed
func (s *Service) FailExecution(ctx context.Context, requestID string, errorMessage string) error {
	s.mu.Lock()
	summary, exists := s.executions[requestID]
	if !exists {
		s.mu.Unlock()
		var err error
		summary, err = s.repo.GetSummary(ctx, requestID)
		if err != nil {
			return err
		}
		s.mu.Lock()
	}
	defer s.mu.Unlock()

	now := time.Now().UTC()
	summary.Status = ExecutionStatusFailed
	summary.CompletedAt = &now
	duration := int(now.Sub(summary.StartedAt).Milliseconds())
	summary.DurationMs = &duration
	summary.ErrorMessage = errorMessage

	if err := s.repo.UpdateSummary(ctx, summary); err != nil {
		return fmt.Errorf("failed to mark execution as failed: %w", err)
	}

	// Remove from cache
	delete(s.executions, requestID)

	s.logger.Printf("[Replay] Execution failed: %s (error=%s)", requestID, errorMessage)
	return nil
}

// Every by-id read below takes the caller's AccessScope (#2934) and anchors
// on an org/tenant-scoped summary fetch: execution_snapshots has no org
// column, so the scoped summary row IS the SQL-enforced authorization for the
// execution's steps. A request id outside the caller's scope is ErrNotFound —
// indistinguishable from a nonexistent execution, so the routes don't oracle
// other tenants' request ids.

// GetExecution retrieves a full execution with summary and all steps
func (s *Service) GetExecution(ctx context.Context, requestID string, scope AccessScope) (*Execution, error) {
	summary, err := s.repo.GetSummaryScoped(ctx, requestID, scope)
	if err != nil {
		return nil, err
	}
	steps, err := s.repo.GetSnapshots(ctx, requestID)
	if err != nil {
		return nil, err
	}
	return &Execution{Summary: summary, Steps: steps}, nil
}

// ListExecutions lists execution summaries with filtering and pagination.
//
// #3065: the tenancy filters are mandatory. Both the Postgres repository and
// the mock append the org/tenant conditions only when non-empty, so an
// unscoped call listed every tenant's executions. The guard lives here as
// well as in the repository so a future in-memory or cached implementation
// inherits it.
func (s *Service) ListExecutions(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error) {
	if err := (AccessScope{OrgID: opts.OrgID, TenantID: opts.TenantID}).Validate(); err != nil {
		return nil, 0, err
	}
	return s.repo.ListSummaries(ctx, opts)
}

// GetStep retrieves a specific step snapshot
func (s *Service) GetStep(ctx context.Context, requestID string, stepIndex int, scope AccessScope) (*ExecutionSnapshot, error) {
	if _, err := s.repo.GetSummaryScoped(ctx, requestID, scope); err != nil {
		return nil, err
	}
	return s.repo.GetSnapshot(ctx, requestID, stepIndex)
}

// GetSteps retrieves all steps for an execution
func (s *Service) GetSteps(ctx context.Context, requestID string, scope AccessScope) ([]ExecutionSnapshot, error) {
	if _, err := s.repo.GetSummaryScoped(ctx, requestID, scope); err != nil {
		return nil, err
	}
	return s.repo.GetSnapshots(ctx, requestID)
}

// ExportExecution exports a full execution record for compliance
func (s *Service) ExportExecution(ctx context.Context, requestID string, opts ExportOptions, scope AccessScope) (json.RawMessage, error) {
	exec, err := s.GetExecution(ctx, requestID, scope)
	if err != nil {
		return nil, err
	}

	// Build export based on options
	export := struct {
		ExportedAt time.Time    `json:"exported_at"`
		Format     ExportFormat `json:"format"`
		Execution  *Execution   `json:"execution"`
	}{
		ExportedAt: time.Now().UTC(),
		Format:     opts.Format,
		Execution:  exec,
	}

	// Optionally redact input/output
	if !opts.IncludeInput {
		export.Execution.Summary.InputSummary = nil
		for i := range export.Execution.Steps {
			export.Execution.Steps[i].Input = nil
		}
	}
	if !opts.IncludeOutput {
		export.Execution.Summary.OutputSummary = nil
		for i := range export.Execution.Steps {
			export.Execution.Steps[i].Output = nil
		}
	}
	if !opts.IncludePolicies {
		for i := range export.Execution.Steps {
			export.Execution.Steps[i].PoliciesChecked = nil
			export.Execution.Steps[i].PoliciesTriggered = nil
		}
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal export: %w", err)
	}

	s.logger.Printf("[Replay] Exported execution: %s", requestID)
	return data, nil
}

// GetTimeline retrieves a timeline view of execution steps
func (s *Service) GetTimeline(ctx context.Context, requestID string, scope AccessScope) ([]TimelineEntry, error) {
	steps, err := s.GetSteps(ctx, requestID, scope)
	if err != nil {
		return nil, err
	}

	timeline := make([]TimelineEntry, len(steps))
	for i, step := range steps {
		timeline[i] = TimelineEntry{
			StepIndex:   step.StepIndex,
			StepName:    step.StepName,
			Status:      step.Status,
			StartedAt:   step.StartedAt,
			CompletedAt: step.CompletedAt,
			DurationMs:  step.DurationMs,
			HasError:    step.ErrorMessage != "",
			HasApproval: step.Status == StepStatusPaused,
		}
	}

	return timeline, nil
}

// DeleteExecution removes an execution and all its data. The delete is
// org/tenant-scoped in SQL: a cross-org request id is ErrNotFound and nothing
// is removed (#2934 — a shared-credential caller must not be able to destroy
// another org's execution trail).
func (s *Service) DeleteExecution(ctx context.Context, requestID string, scope AccessScope) error {
	if err := s.repo.DeleteExecutionScoped(ctx, requestID, scope); err != nil {
		return err
	}

	s.mu.Lock()
	delete(s.executions, requestID)
	s.mu.Unlock()

	return nil
}

// IsHealthy checks if the service is healthy
func (s *Service) IsHealthy(ctx context.Context) bool {
	return s.repo.Ping(ctx) == nil
}

// GetExecutionCount returns the count of executions matching the filter
func (s *Service) GetExecutionCount(ctx context.Context, opts ListOptions) (int, error) {
	if err := (AccessScope{OrgID: opts.OrgID, TenantID: opts.TenantID}).Validate(); err != nil {
		return 0, err
	}
	_, total, err := s.repo.ListSummaries(ctx, ListOptions{
		OrgID:      opts.OrgID,
		TenantID:   opts.TenantID,
		Status:     opts.Status,
		StartTime:  opts.StartTime,
		EndTime:    opts.EndTime,
		WorkflowID: opts.WorkflowID,
		Limit:      1, // Just need count
	})
	return total, err
}
