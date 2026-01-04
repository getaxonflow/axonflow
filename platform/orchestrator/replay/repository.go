// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"
)

// Repository defines the interface for execution replay data persistence
type Repository interface {
	// Snapshot operations
	SaveSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error
	UpdateSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error
	GetSnapshot(ctx context.Context, requestID string, stepIndex int) (*ExecutionSnapshot, error)
	GetSnapshots(ctx context.Context, requestID string) ([]ExecutionSnapshot, error)
	DeleteSnapshots(ctx context.Context, requestID string) error

	// Summary operations
	SaveSummary(ctx context.Context, summary *ExecutionSummary) error
	UpdateSummary(ctx context.Context, summary *ExecutionSummary) error
	GetSummary(ctx context.Context, requestID string) (*ExecutionSummary, error)
	ListSummaries(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error)
	DeleteSummary(ctx context.Context, requestID string) error

	// Bulk operations
	GetExecution(ctx context.Context, requestID string) (*Execution, error)
	DeleteExecution(ctx context.Context, requestID string) error

	// Health check
	Ping(ctx context.Context) error
}

// NoOpRepository is a no-op implementation for when the database is unavailable
type NoOpRepository struct{}

// Ensure NoOpRepository implements Repository
var _ Repository = (*NoOpRepository)(nil)

func (r *NoOpRepository) SaveSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	return nil
}

func (r *NoOpRepository) UpdateSnapshot(ctx context.Context, snapshot *ExecutionSnapshot) error {
	return nil
}

func (r *NoOpRepository) GetSnapshot(ctx context.Context, requestID string, stepIndex int) (*ExecutionSnapshot, error) {
	return nil, ErrNotFound
}

func (r *NoOpRepository) GetSnapshots(ctx context.Context, requestID string) ([]ExecutionSnapshot, error) {
	return []ExecutionSnapshot{}, nil
}

func (r *NoOpRepository) DeleteSnapshots(ctx context.Context, requestID string) error {
	return nil
}

func (r *NoOpRepository) SaveSummary(ctx context.Context, summary *ExecutionSummary) error {
	return nil
}

func (r *NoOpRepository) UpdateSummary(ctx context.Context, summary *ExecutionSummary) error {
	return nil
}

func (r *NoOpRepository) GetSummary(ctx context.Context, requestID string) (*ExecutionSummary, error) {
	return nil, ErrNotFound
}

func (r *NoOpRepository) ListSummaries(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error) {
	return []ExecutionSummary{}, 0, nil
}

func (r *NoOpRepository) DeleteSummary(ctx context.Context, requestID string) error {
	return nil
}

func (r *NoOpRepository) GetExecution(ctx context.Context, requestID string) (*Execution, error) {
	return nil, ErrNotFound
}

func (r *NoOpRepository) DeleteExecution(ctx context.Context, requestID string) error {
	return nil
}

func (r *NoOpRepository) Ping(ctx context.Context) error {
	return nil
}
