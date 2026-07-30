// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"context"

	"axonflow/platform/shared/tenantscope"
)

// AccessScope is the caller's org/tenant read scope for the by-id execution
// routes (#2934). Behind the agent gateway both values come from the
// cryptographically validated license headers, so a governed caller cannot
// pick another org.
//
// #3065: an empty value used to leave that dimension UNFILTERED — the
// docstring called it "single-tenant Community deployments and the internal
// write path", but in practice it meant a caller who omitted X-Org-ID read,
// exported and DELETED any tenant's execution trail. Both dimensions are now
// mandatory and enforced against the shared choke point; the SQL predicate is
// strict equality.
type AccessScope struct {
	OrgID    string
	TenantID string
}

// scope converts an AccessScope to the shared fail-closed authorization
// primitive (#3065). Keeping AccessScope as the package's public shape avoids
// churning every handler signature while routing the actual decision through
// the single choke point.
func (a AccessScope) scope() tenantscope.Scope {
	return tenantscope.Scope{OrgID: a.OrgID, TenantID: a.TenantID}
}

// Validate reports whether the scope is usable for a by-id read or write.
// An unbound scope is a denial, surfaced as ErrNotFound so the by-id routes
// never become a cross-tenant existence oracle.
func (a AccessScope) Validate() error {
	if !a.scope().Bound() {
		return ErrNotFound
	}
	return nil
}

// Authorize is the fail-closed row check: both the caller's and the row's
// org/tenant must be present and equal.
func (a AccessScope) Authorize(rowOrg, rowTenant string) error {
	if a.scope().Authorize(rowOrg, rowTenant) != nil {
		return ErrNotFound
	}
	return nil
}

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
	// GetSummaryScoped is the org/tenant-isolated variant used by the HTTP
	// read path (#2934): a request id outside the caller's scope is
	// ErrNotFound. Snapshots carry no org column, so every scoped read is
	// anchored on this summary fetch.
	GetSummaryScoped(ctx context.Context, requestID string, scope AccessScope) (*ExecutionSummary, error)
	ListSummaries(ctx context.Context, opts ListOptions) ([]ExecutionSummary, int, error)
	DeleteSummary(ctx context.Context, requestID string) error

	// Bulk operations
	GetExecution(ctx context.Context, requestID string) (*Execution, error)
	DeleteExecution(ctx context.Context, requestID string) error
	// DeleteExecutionScoped deletes summary + snapshots only when the
	// execution's summary row is inside the caller's org/tenant scope; a
	// cross-org id is ErrNotFound and nothing is deleted (#2934).
	DeleteExecutionScoped(ctx context.Context, requestID string, scope AccessScope) error

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

func (r *NoOpRepository) GetSummaryScoped(ctx context.Context, requestID string, scope AccessScope) (*ExecutionSummary, error) {
	return nil, ErrNotFound
}

func (r *NoOpRepository) DeleteExecutionScoped(ctx context.Context, requestID string, scope AccessScope) error {
	return ErrNotFound
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
