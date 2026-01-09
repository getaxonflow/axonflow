// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"time"
)

// MockRepository implements Repository for testing.
// This is exported so it can be used by tests in other packages.
type MockRepository struct {
	plans map[string]*Plan
	err   error
}

// NewMockRepository creates a new mock repository for testing
func NewMockRepository() *MockRepository {
	return &MockRepository{
		plans: make(map[string]*Plan),
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

// GetPlans returns all plans in the mock storage (for test assertions)
func (m *MockRepository) GetPlans() map[string]*Plan {
	return m.plans
}
