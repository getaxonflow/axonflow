// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
	"sync"
)

// MockRepository is a mock implementation of Repository for testing
type MockRepository struct {
	mu         sync.RWMutex
	snapshots  map[string][]ExecutionSnapshot
	summaries  map[string]*ExecutionSummary
	executions map[string]*Execution

	// Error injection for testing
	SaveSnapshotErr   error
	UpdateSnapshotErr error
	GetSnapshotErr    error
	GetSnapshotsErr   error
	SaveSummaryErr    error
	UpdateSummaryErr  error
	GetSummaryErr     error
	ListSummariesErr  error
	GetExecutionErr   error
	DeleteErr         error
	PingErr           error
}

// NewMockRepository creates a new mock repository
func NewMockRepository() *MockRepository {
	return &MockRepository{
		snapshots:  make(map[string][]ExecutionSnapshot),
		summaries:  make(map[string]*ExecutionSummary),
		executions: make(map[string]*Execution),
	}
}

// Ensure MockRepository implements Repository
var _ Repository = (*MockRepository)(nil)

func (r *MockRepository) SaveSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	if r.SaveSnapshotErr != nil {
		return r.SaveSnapshotErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.snapshots[snapshot.RequestID] == nil {
		r.snapshots[snapshot.RequestID] = []ExecutionSnapshot{}
	}
	r.snapshots[snapshot.RequestID] = append(r.snapshots[snapshot.RequestID], *snapshot)
	return nil
}

func (r *MockRepository) UpdateSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	if r.UpdateSnapshotErr != nil {
		return r.UpdateSnapshotErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if snapshots, ok := r.snapshots[snapshot.RequestID]; ok {
		for i, s := range snapshots {
			if s.StepIndex == snapshot.StepIndex {
				r.snapshots[snapshot.RequestID][i] = *snapshot
				return nil
			}
		}
	}
	return nil
}

func (r *MockRepository) GetSnapshot(ctx context.Context, requestID string, stepIndex int) (*ExecutionSnapshot, error) {
	if r.GetSnapshotErr != nil {
		return nil, r.GetSnapshotErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if snapshots, ok := r.snapshots[requestID]; ok {
		for _, s := range snapshots {
			if s.StepIndex == stepIndex {
				return &s, nil
			}
		}
	}
	return nil, ErrNotFound
}

func (r *MockRepository) GetSnapshots(ctx context.Context, requestID string) ([]ExecutionSnapshot, error) {
	if r.GetSnapshotsErr != nil {
		return nil, r.GetSnapshotsErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if snapshots, ok := r.snapshots[requestID]; ok {
		return snapshots, nil
	}
	return []ExecutionSnapshot{}, nil
}

func (r *MockRepository) DeleteSnapshots(ctx context.Context, requestID string) error {
	if r.DeleteErr != nil {
		return r.DeleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.snapshots, requestID)
	return nil
}

func (r *MockRepository) SaveSummary(ctx context.Context, summary *ExecutionSummary) error {
	if r.SaveSummaryErr != nil {
		return r.SaveSummaryErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.summaries[summary.RequestID] = summary
	return nil
}

func (r *MockRepository) UpdateSummary(ctx context.Context, summary *ExecutionSummary) error {
	if r.UpdateSummaryErr != nil {
		return r.UpdateSummaryErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.summaries[summary.RequestID] = summary
	return nil
}

func (r *MockRepository) GetSummary(ctx context.Context, requestID string) (*ExecutionSummary, error) {
	if r.GetSummaryErr != nil {
		return nil, r.GetSummaryErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	if summary, ok := r.summaries[requestID]; ok {
		return summary, nil
	}
	return nil, ErrNotFound
}

func (r *MockRepository) ListSummaries(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error) {
	if r.ListSummariesErr != nil {
		return nil, 0, r.ListSummariesErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []ExecutionSummary
	for _, summary := range r.summaries {
		// Apply filters
		if opts.Status != "" && string(summary.Status) != opts.Status {
			continue
		}
		if opts.OrgID != "" && summary.OrgID != opts.OrgID {
			continue
		}
		if opts.TenantID != "" && summary.TenantID != opts.TenantID {
			continue
		}
		if opts.WorkflowID != "" && summary.WorkflowName != opts.WorkflowID {
			continue
		}
		result = append(result, *summary)
	}

	total := len(result)

	// Apply pagination
	if opts.Offset > 0 && opts.Offset < len(result) {
		result = result[opts.Offset:]
	} else if opts.Offset >= len(result) {
		result = []ExecutionSummary{}
	}
	if opts.Limit > 0 && opts.Limit < len(result) {
		result = result[:opts.Limit]
	}

	return result, total, nil
}

func (r *MockRepository) DeleteSummary(ctx context.Context, requestID string) error {
	if r.DeleteErr != nil {
		return r.DeleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.summaries, requestID)
	return nil
}

func (r *MockRepository) GetExecution(ctx context.Context, requestID string) (*Execution, error) {
	if r.GetExecutionErr != nil {
		return nil, r.GetExecutionErr
	}
	r.mu.RLock()
	defer r.mu.RUnlock()

	summary, ok := r.summaries[requestID]
	if !ok {
		return nil, ErrNotFound
	}

	steps := r.snapshots[requestID]
	if steps == nil {
		steps = []ExecutionSnapshot{}
	}

	return &Execution{
		Summary: summary,
		Steps:   steps,
	}, nil
}

func (r *MockRepository) DeleteExecution(ctx context.Context, requestID string) error {
	if r.DeleteErr != nil {
		return r.DeleteErr
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.snapshots, requestID)
	delete(r.summaries, requestID)
	return nil
}

func (r *MockRepository) Ping(ctx context.Context) error {
	return r.PingErr
}

// Helper methods for test setup

// AddSnapshot adds a snapshot directly for testing
func (r *MockRepository) AddSnapshot(snapshot *ExecutionSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.snapshots[snapshot.RequestID] == nil {
		r.snapshots[snapshot.RequestID] = []ExecutionSnapshot{}
	}
	r.snapshots[snapshot.RequestID] = append(r.snapshots[snapshot.RequestID], *snapshot)
}

// AddSummary adds a summary directly for testing
func (r *MockRepository) AddSummary(summary *ExecutionSummary) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.summaries[summary.RequestID] = summary
}

// GetSummaryCount returns the number of summaries
func (r *MockRepository) GetSummaryCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.summaries)
}

// GetSnapshotCount returns the number of snapshots for a request
func (r *MockRepository) GetSnapshotCount(requestID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.snapshots[requestID])
}
