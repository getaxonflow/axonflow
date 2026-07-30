// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"time"

	"axonflow/platform/shared/tenantscope"
)

// MockRepository implements Repository for testing.
// This is exported so it can be used by tests in other packages.
type MockRepository struct {
	plans    map[string]*Plan
	versions map[string][]PlanVersion // planID -> versions
	err      error
}

// NewMockRepository creates a new mock repository for testing
func NewMockRepository() *MockRepository {
	return &MockRepository{
		plans:    make(map[string]*Plan),
		versions: make(map[string][]PlanVersion),
	}
}

// SavePlan saves a plan to the mock storage
func (m *MockRepository) SavePlan(ctx context.Context, plan *Plan) error {
	if m.err != nil {
		return m.err
	}
	if plan == nil || plan.PlanID == "" {
		return ErrInvalidPlanID
	}
	// #3065: the mock mirrors the fixed Postgres write contract. Without this
	// a test could seed an org-less plan — the exact row that used to belong
	// to every tenant — and then "prove" the by-id routes work on it.
	if err := tenantscope.ValidateRowKeys(plan.OrgID, plan.TenantID); err != nil {
		return err
	}
	m.plans[plan.PlanID] = plan
	return nil
}

// GetPlan retrieves a plan from mock storage
func (m *MockRepository) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	if m.err != nil {
		return nil, m.err
	}
	if planID == "" {
		return nil, ErrInvalidPlanID
	}
	plan, ok := m.plans[planID]
	if !ok {
		return nil, ErrPlanNotFound
	}
	return plan, nil
}

// UpdatePlanStatus updates a plan's status in mock storage
func (m *MockRepository) UpdatePlanStatus(ctx context.Context, planID string, status PlanStatus, result json.RawMessage, errorMsg string) error {
	if m.err != nil {
		return m.err
	}
	if planID == "" {
		return ErrInvalidPlanID
	}
	plan, ok := m.plans[planID]
	if !ok {
		return ErrPlanNotFound
	}
	plan.Status = status
	if len(result) > 0 {
		plan.ExecutionResult = result
	}
	if errorMsg != "" {
		plan.ErrorMessage = errorMsg
	}
	if status == PlanStatusCompleted || status == PlanStatusFailed {
		now := time.Now()
		plan.ExecutedAt = &now
	}
	return nil
}

// DeletePlan removes a plan from mock storage
func (m *MockRepository) DeletePlan(ctx context.Context, planID string) error {
	if m.err != nil {
		return m.err
	}
	if planID == "" {
		return ErrInvalidPlanID
	}
	delete(m.plans, planID)
	return nil
}

// UpdatePlanStatusAtomic atomically updates plan status
func (m *MockRepository) UpdatePlanStatusAtomic(ctx context.Context, planID string, expectedStatus, newStatus PlanStatus) error {
	if m.err != nil {
		return m.err
	}
	if planID == "" {
		return ErrInvalidPlanID
	}
	plan, ok := m.plans[planID]
	if !ok {
		return ErrPlanAlreadyRun // Not found treated as already run for atomic update
	}
	if plan.Status != expectedStatus {
		return ErrPlanAlreadyRun // Status mismatch = race condition
	}
	plan.Status = newStatus
	return nil
}

// CleanupExpiredPlans removes expired plans from mock storage
func (m *MockRepository) CleanupExpiredPlans(ctx context.Context) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	count := 0
	for id, plan := range m.plans {
		if plan.IsExpired() && (plan.Status == PlanStatusPending || plan.Status == PlanStatusExpired) {
			delete(m.plans, id)
			count++
		}
	}
	return count, nil
}

// SetError configures the mock to return an error on all operations
func (m *MockRepository) SetError(err error) {
	m.err = err
}

// UpdatePlanWithVersion updates a plan with optimistic locking
func (m *MockRepository) UpdatePlanWithVersion(ctx context.Context, planID string, expectedVersion int, updates map[string]interface{}) (*Plan, error) {
	if m.err != nil {
		return nil, m.err
	}
	if planID == "" {
		return nil, ErrInvalidPlanID
	}
	plan, ok := m.plans[planID]
	if !ok {
		return nil, ErrPlanNotFound
	}
	if plan.Version != expectedVersion {
		return nil, ErrVersionConflict
	}

	// Apply updates
	if mode, ok := updates["execution_mode"]; ok {
		plan.ExecutionMode = mode.(string)
	}
	if domain, ok := updates["domain"]; ok {
		plan.Domain = domain.(string)
	}

	plan.Version++
	plan.UpdatedAt = time.Now()
	return plan, nil
}

// SavePlanVersion saves a version snapshot
func (m *MockRepository) SavePlanVersion(ctx context.Context, version *PlanVersion) error {
	if m.err != nil {
		return m.err
	}
	m.versions[version.PlanID] = append(m.versions[version.PlanID], *version)
	return nil
}

// GetPlanVersions retrieves versions for a plan
func (m *MockRepository) GetPlanVersions(ctx context.Context, planID string) ([]PlanVersion, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.versions[planID], nil
}

// CountPlansWithVersioning returns the count of plans with version > 1
func (m *MockRepository) CountPlansWithVersioning(ctx context.Context, orgID string) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	count := 0
	for _, plan := range m.plans {
		if plan.OrgID == orgID && plan.Version > 1 {
			count++
		}
	}
	return count, nil
}

// CountVersions returns the number of versions for a plan
func (m *MockRepository) CountVersions(ctx context.Context, planID string) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	return len(m.versions[planID]), nil
}

// GetPlanVersion retrieves a specific version snapshot for a plan
func (m *MockRepository) GetPlanVersion(ctx context.Context, planID string, version int) (*PlanVersion, error) {
	if m.err != nil {
		return nil, m.err
	}
	versions := m.versions[planID]
	for _, v := range versions {
		if v.Version == version {
			return &v, nil
		}
	}
	return nil, ErrVersionNotFound
}

// RollbackPlan restores a plan from a snapshot, incrementing the version
func (m *MockRepository) RollbackPlan(ctx context.Context, planID string, expectedVersion int, snapshot json.RawMessage) (*Plan, error) {
	if m.err != nil {
		return nil, m.err
	}
	plan, ok := m.plans[planID]
	if !ok {
		return nil, ErrPlanNotFound
	}
	if plan.Version != expectedVersion {
		return nil, ErrVersionConflict
	}

	// Parse snapshot and restore fields
	var snap struct {
		ExecutionMode      string          `json:"execution_mode"`
		Domain             string          `json:"domain"`
		WorkflowDefinition json.RawMessage `json:"workflow_definition"`
	}
	if err := json.Unmarshal(snapshot, &snap); err != nil {
		return nil, err
	}

	plan.ExecutionMode = snap.ExecutionMode
	plan.Domain = snap.Domain
	if len(snap.WorkflowDefinition) > 0 {
		plan.WorkflowDefinition = snap.WorkflowDefinition
	}
	plan.Version++
	plan.UpdatedAt = time.Now()
	return plan, nil
}

// GetPlans returns all plans in the mock storage (for test assertions)
func (m *MockRepository) GetPlans() map[string]*Plan {
	return m.plans
}

// GetVersions returns all versions in the mock storage (for test assertions)
func (m *MockRepository) GetVersions() map[string][]PlanVersion {
	return m.versions
}
