// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planning

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// setupPendingPlan inserts a pending plan into the mock repository and returns it.
func setupPendingPlan(repo *MockRepository) *Plan {
	plan := &Plan{
		PlanID:             "test-plan-123",
		Query:              "test query",
		Domain:             "test",
		Status:             PlanStatusPending,
		ExecutionMode:      "auto",
		Version:            1,
		OrgID:              "org-1",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	repo.plans[plan.PlanID] = plan
	return plan
}

// ---------------------------------------------------------------------------
// UpdatePlan tests
// ---------------------------------------------------------------------------

func TestService_UpdatePlan_Success(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
		ChangedBy:       "user-a",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if updated.Version != 2 {
		t.Errorf("expected version 2 after update, got %d", updated.Version)
	}
	if updated.ExecutionMode != "manual" {
		t.Errorf("expected execution_mode 'manual', got %q", updated.ExecutionMode)
	}

	// Verify a version snapshot was saved
	versions := repo.GetVersions()
	planVersions := versions[plan.PlanID]
	if len(planVersions) != 1 {
		t.Fatalf("expected 1 version snapshot, got %d", len(planVersions))
	}
	if planVersions[0].Version != 1 {
		t.Errorf("expected snapshot version 1, got %d", planVersions[0].Version)
	}
	if planVersions[0].ChangeType != "update" {
		t.Errorf("expected change_type 'update', got %q", planVersions[0].ChangeType)
	}
	if planVersions[0].ChangedBy != "user-a" {
		t.Errorf("expected changed_by 'user-a', got %q", planVersions[0].ChangedBy)
	}
	if !strings.Contains(planVersions[0].ChangeSummary, "execution_mode") {
		t.Errorf("expected change summary to mention execution_mode, got %q", planVersions[0].ChangeSummary)
	}
}

func TestService_UpdatePlan_VersionConflict(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewService(repo)

	// Plan is at version 1, but we claim to expect version 5
	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 5,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected ErrVersionConflict, got nil")
	}
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("expected ErrVersionConflict, got %v", err)
	}
}

func TestService_UpdatePlan_NonPendingPlan(t *testing.T) {
	statuses := []PlanStatus{
		PlanStatusCompleted,
		PlanStatusFailed,
		PlanStatusExecuting,
		PlanStatusExpired,
		PlanStatusCancelled,
	}

	for _, status := range statuses {
		t.Run(string(status), func(t *testing.T) {
			repo := NewMockRepository()
			plan := setupPendingPlan(repo)
			plan.Status = status
			svc := NewService(repo)

			req := &UpdatePlanRequest{
				PlanID:          plan.PlanID,
				ExpectedVersion: 1,
				ExecutionMode:   "manual",
				OrgID:           "org-1",
			}

			_, err := svc.UpdatePlan(context.Background(), req)
			if err == nil {
				t.Fatalf("expected error for %s plan, got nil", status)
			}
			if !strings.Contains(err.Error(), string(status)) {
				t.Errorf("expected error to mention status %q, got %q", status, err.Error())
			}
		})
	}
}

func TestService_UpdatePlan_PlanNotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          "nonexistent-plan",
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for nonexistent plan, got nil")
	}
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound, got %v", err)
	}
}

func TestService_UpdatePlan_CommunityLimits_MaxVersions(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 100,
		MaxVersionsPerPlan:     3,
	})

	// Pre-populate 3 version snapshots (at the limit)
	for i := 0; i < 3; i++ {
		_ = repo.SavePlanVersion(context.Background(), &PlanVersion{
			PlanID:     plan.PlanID,
			Version:    i + 1,
			Snapshot:   json.RawMessage(`{}`),
			ChangeType: "update",
		})
	}

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected ErrMaxVersions, got nil")
	}
	if !errors.Is(err, ErrMaxVersions) {
		t.Errorf("expected ErrMaxVersions, got %v", err)
	}
}

func TestService_UpdatePlan_CommunityLimits_MaxPlans(t *testing.T) {
	repo := NewMockRepository()
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 2,
		MaxVersionsPerPlan:     100,
	})

	// Create 2 plans that already have versioning (version > 1)
	for i := 0; i < 2; i++ {
		repo.plans[string(rune('A'+i))] = &Plan{
			PlanID:  string(rune('A' + i)),
			OrgID:   "org-1",
			Status:  PlanStatusPending,
			Version: 2, // Already versioned
		}
	}

	// Create a new plan at version 1 (first update would push it to versioned)
	plan := setupPendingPlan(repo) // version 1, org-1

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected ErrMaxPlans, got nil")
	}
	if !errors.Is(err, ErrMaxPlans) {
		t.Errorf("expected ErrMaxPlans, got %v", err)
	}
}

func TestService_UpdatePlan_ExecutionModeChange(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.ExecutionMode = "auto"
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "parallel",
		OrgID:           "org-1",
		ChangedBy:       "admin",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.ExecutionMode != "parallel" {
		t.Errorf("expected execution_mode 'parallel', got %q", updated.ExecutionMode)
	}

	// Domain should remain unchanged
	if updated.Domain != "test" {
		t.Errorf("expected domain to remain 'test', got %q", updated.Domain)
	}

	// Verify change summary references execution_mode
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) == 0 {
		t.Fatal("expected at least 1 version snapshot")
	}
	if !strings.Contains(versions[0].ChangeSummary, "execution_mode: auto") {
		t.Errorf("expected change summary to reference old execution_mode, got %q", versions[0].ChangeSummary)
	}
	if !strings.Contains(versions[0].ChangeSummary, "parallel") {
		t.Errorf("expected change summary to reference new execution_mode, got %q", versions[0].ChangeSummary)
	}
}

func TestService_UpdatePlan_DomainChange(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.Domain = "finance"
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		Domain:          "healthcare",
		OrgID:           "org-1",
		ChangedBy:       "admin",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.Domain != "healthcare" {
		t.Errorf("expected domain 'healthcare', got %q", updated.Domain)
	}

	// ExecutionMode should remain unchanged
	if updated.ExecutionMode != "auto" {
		t.Errorf("expected execution_mode to remain 'auto', got %q", updated.ExecutionMode)
	}

	// Verify change summary references domain
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) == 0 {
		t.Fatal("expected at least 1 version snapshot")
	}
	if !strings.Contains(versions[0].ChangeSummary, "domain: finance") {
		t.Errorf("expected change summary to reference old domain, got %q", versions[0].ChangeSummary)
	}
}

func TestService_UpdatePlan_NoChanges(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewService(repo)

	// Request with same values as current plan (no actual change)
	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   plan.ExecutionMode, // same
		Domain:          plan.Domain,        // same
		OrgID:           "org-1",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Version should NOT be incremented when there are no changes
	if updated.Version != 1 {
		t.Errorf("expected version to remain 1 with no changes, got %d", updated.Version)
	}

	// No version snapshot should be saved
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) != 0 {
		t.Errorf("expected 0 version snapshots when no changes, got %d", len(versions))
	}
}

func TestService_UpdatePlan_EmptyPlanID(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          "",
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for empty plan ID, got nil")
	}
	if !errors.Is(err, ErrInvalidPlanID) {
		t.Errorf("expected ErrInvalidPlanID, got %v", err)
	}
}

func TestService_UpdatePlan_InvalidExpectedVersion(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          "test-plan-123",
		ExpectedVersion: 0,
		ExecutionMode:   "manual",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for expected_version 0, got nil")
	}
	if !strings.Contains(err.Error(), "expected_version must be >= 1") {
		t.Errorf("expected error about expected_version, got %q", err.Error())
	}
}

func TestService_UpdatePlan_CrossTenantBlocked(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.OrgID = "org-1"
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-2", // Different org
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for cross-tenant update, got nil")
	}
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound (to avoid leaking plan existence), got %v", err)
	}
}

func TestService_UpdatePlan_BothFieldsChanged(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.ExecutionMode = "auto"
	plan.Domain = "finance"
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "parallel",
		Domain:          "healthcare",
		OrgID:           "org-1",
		ChangedBy:       "admin",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if updated.ExecutionMode != "parallel" {
		t.Errorf("expected execution_mode 'parallel', got %q", updated.ExecutionMode)
	}
	if updated.Domain != "healthcare" {
		t.Errorf("expected domain 'healthcare', got %q", updated.Domain)
	}
	if updated.Version != 2 {
		t.Errorf("expected version 2, got %d", updated.Version)
	}

	// Change summary should mention both fields
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) == 0 {
		t.Fatal("expected at least 1 version snapshot")
	}
	summary := versions[0].ChangeSummary
	if !strings.Contains(summary, "execution_mode") {
		t.Errorf("expected change summary to mention execution_mode, got %q", summary)
	}
	if !strings.Contains(summary, "domain") {
		t.Errorf("expected change summary to mention domain, got %q", summary)
	}
}

func TestService_UpdatePlan_SnapshotContainsPreviousState(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.ExecutionMode = "auto"
	plan.Domain = "finance"
	plan.Query = "original query"
	svc := NewService(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// The snapshot should contain the previous state of the plan
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) == 0 {
		t.Fatal("expected at least 1 version snapshot")
	}

	var snapshotPlan Plan
	if err := json.Unmarshal(versions[0].Snapshot, &snapshotPlan); err != nil {
		t.Fatalf("failed to unmarshal snapshot: %v", err)
	}

	// Snapshot should reflect the state BEFORE the update
	if snapshotPlan.ExecutionMode != "auto" {
		t.Errorf("expected snapshot execution_mode 'auto', got %q", snapshotPlan.ExecutionMode)
	}
	if snapshotPlan.Domain != "finance" {
		t.Errorf("expected snapshot domain 'finance', got %q", snapshotPlan.Domain)
	}
	if snapshotPlan.Query != "original query" {
		t.Errorf("expected snapshot query 'original query', got %q", snapshotPlan.Query)
	}
}

func TestService_UpdatePlan_SuccessiveUpdates(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.ExecutionMode = "auto"
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 100,
		MaxVersionsPerPlan:     100,
	})

	// First update: v1 -> v2
	req1 := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
		ChangedBy:       "user-a",
	}
	updated1, err := svc.UpdatePlan(context.Background(), req1)
	if err != nil {
		t.Fatalf("first update failed: %v", err)
	}
	if updated1.Version != 2 {
		t.Fatalf("expected version 2, got %d", updated1.Version)
	}

	// Second update: v2 -> v3
	req2 := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 2,
		Domain:          "healthcare",
		OrgID:           "org-1",
		ChangedBy:       "user-b",
	}
	updated2, err := svc.UpdatePlan(context.Background(), req2)
	if err != nil {
		t.Fatalf("second update failed: %v", err)
	}
	if updated2.Version != 3 {
		t.Errorf("expected version 3, got %d", updated2.Version)
	}
	if updated2.Domain != "healthcare" {
		t.Errorf("expected domain 'healthcare', got %q", updated2.Domain)
	}
	if updated2.ExecutionMode != "manual" {
		t.Errorf("expected execution_mode to remain 'manual' from first update, got %q", updated2.ExecutionMode)
	}

	// Verify 2 version snapshots exist
	versions := repo.GetVersions()[plan.PlanID]
	if len(versions) != 2 {
		t.Fatalf("expected 2 version snapshots, got %d", len(versions))
	}
	if versions[0].Version != 1 {
		t.Errorf("first snapshot version = %d, want 1", versions[0].Version)
	}
	if versions[0].ChangedBy != "user-a" {
		t.Errorf("first snapshot changed_by = %q, want 'user-a'", versions[0].ChangedBy)
	}
	if versions[1].Version != 2 {
		t.Errorf("second snapshot version = %d, want 2", versions[1].Version)
	}
	if versions[1].ChangedBy != "user-b" {
		t.Errorf("second snapshot changed_by = %q, want 'user-b'", versions[1].ChangedBy)
	}
}

func TestService_UpdatePlan_CustomConfig(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 5,
		MaxVersionsPerPlan:     3,
	})

	// Verify custom limits are applied (should succeed within limits)
	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	updated, err := svc.UpdatePlan(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error with custom config, got %v", err)
	}
	if updated.Version != 2 {
		t.Errorf("expected version 2, got %d", updated.Version)
	}
}

func TestService_UpdatePlan_RepositoryError(t *testing.T) {
	repo := NewMockRepository()
	setupPendingPlan(repo)

	// Set error after plan is already stored (GetPlan succeeds because plan
	// is in memory, but UpdatePlanWithVersion will fail)
	svc := NewService(repo)

	// To trigger a repo error on UpdatePlanWithVersion specifically, we need
	// a plan with the right version but set error before the update call.
	// Since SetError affects all operations, we need to test the propagation
	// from GetPlan.
	repo.SetError(errors.New("database connection lost"))

	req := &UpdatePlanRequest{
		PlanID:          "test-plan-123",
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected error from repository, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetPlanVersions tests
// ---------------------------------------------------------------------------

func TestService_GetPlanVersions_Success(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewService(repo)

	// Add version history
	now := time.Now()
	repo.versions[plan.PlanID] = []PlanVersion{
		{
			ID:            "v-1",
			PlanID:        plan.PlanID,
			Version:       1,
			Snapshot:      json.RawMessage(`{"execution_mode":"auto"}`),
			ChangedBy:     "user-a",
			ChangedAt:     now.Add(-2 * time.Minute),
			ChangeType:    "update",
			ChangeSummary: "execution_mode: auto -> manual",
		},
		{
			ID:            "v-2",
			PlanID:        plan.PlanID,
			Version:       2,
			Snapshot:      json.RawMessage(`{"execution_mode":"manual"}`),
			ChangedBy:     "user-b",
			ChangedAt:     now.Add(-1 * time.Minute),
			ChangeType:    "update",
			ChangeSummary: "domain: test -> healthcare",
		},
	}

	versions, err := svc.GetPlanVersions(context.Background(), plan.PlanID, "org-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}

	if versions[0].ID != "v-1" {
		t.Errorf("first version ID = %q, want 'v-1'", versions[0].ID)
	}
	if versions[0].Version != 1 {
		t.Errorf("first version number = %d, want 1", versions[0].Version)
	}
	if versions[0].ChangedBy != "user-a" {
		t.Errorf("first version changed_by = %q, want 'user-a'", versions[0].ChangedBy)
	}
	if versions[1].ID != "v-2" {
		t.Errorf("second version ID = %q, want 'v-2'", versions[1].ID)
	}
	if versions[1].Version != 2 {
		t.Errorf("second version number = %d, want 2", versions[1].Version)
	}
}

func TestService_GetPlanVersions_Empty(t *testing.T) {
	repo := NewMockRepository()
	setupPendingPlan(repo)
	svc := NewService(repo)

	versions, err := svc.GetPlanVersions(context.Background(), "test-plan-123", "org-1")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// MockRepository.GetPlanVersions returns nil for missing keys, which is
	// acceptable as an empty result.
	if versions != nil && len(versions) != 0 {
		t.Errorf("expected empty/nil versions, got %d entries", len(versions))
	}
}

func TestService_GetPlanVersions_RepositoryError(t *testing.T) {
	repo := NewMockRepository()
	setupPendingPlan(repo)
	svc := NewService(repo)

	repo.SetError(errors.New("database timeout"))

	_, err := svc.GetPlanVersions(context.Background(), "test-plan-123", "org-1")
	if err == nil {
		t.Fatal("expected error from repository, got nil")
	}
}

func TestService_GetPlanVersions_PlanNotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	_, err := svc.GetPlanVersions(context.Background(), "nonexistent", "org-1")
	if err == nil {
		t.Fatal("expected error for nonexistent plan, got nil")
	}
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound, got %v", err)
	}
}

func TestService_GetPlanVersions_CrossTenantBlocked(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	plan.OrgID = "org-1"
	svc := NewService(repo)

	_, err := svc.GetPlanVersions(context.Background(), plan.PlanID, "org-2")
	if err == nil {
		t.Fatal("expected error for cross-tenant access, got nil")
	}
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound (to avoid leaking plan existence), got %v", err)
	}
}

func TestService_GetPlanVersions_EmptyOrgID(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)

	// Add a version so we can verify retrieval
	repo.versions[plan.PlanID] = []PlanVersion{
		{
			ID:         "v-1",
			PlanID:     plan.PlanID,
			Version:    1,
			Snapshot:   json.RawMessage(`{}`),
			ChangeType: "update",
		},
	}

	svc := NewService(repo)

	// Empty orgID should skip authorization check (community mode)
	versions, err := svc.GetPlanVersions(context.Background(), plan.PlanID, "")
	if err != nil {
		t.Fatalf("expected no error with empty orgID, got %v", err)
	}
	if len(versions) != 1 {
		t.Errorf("expected 1 version, got %d", len(versions))
	}
}

// --- RollbackPlan tests ---

func TestRollbackPlan_Success(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	// Create a plan at version 2 (updated once from version 1)
	plan := &Plan{
		PlanID:             "plan-rollback-ok",
		Query:              "test query",
		Domain:             "travel",
		ExecutionMode:      "parallel",
		Status:             PlanStatusPending,
		Version:            2,
		OrgID:              "org-1",
		WorkflowDefinition: json.RawMessage(`{"steps":["updated"]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	// Save version 1 snapshot (the state before first update)
	v1Snapshot := json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":["original"]}}`)
	_ = repo.SavePlanVersion(context.Background(), &PlanVersion{
		PlanID:     plan.PlanID,
		Version:    1,
		Snapshot:   v1Snapshot,
		ChangeType: "update",
	})

	result, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 1,
		OrgID:         "org-1",
		RolledBackBy:  "user-1",
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Version should increment
	if result.Version != 3 {
		t.Errorf("version = %d, want 3", result.Version)
	}
	// Fields restored from v1 snapshot
	if result.ExecutionMode != "sequential" {
		t.Errorf("execution_mode = %q, want %q", result.ExecutionMode, "sequential")
	}
	if result.Domain != "generic" {
		t.Errorf("domain = %q, want %q", result.Domain, "generic")
	}

	// Pre-rollback snapshot should be saved
	versions := repo.versions[plan.PlanID]
	found := false
	for _, v := range versions {
		if v.ChangeType == "rollback" && v.Version == 2 {
			found = true
		}
	}
	if !found {
		t.Error("expected pre-rollback snapshot at version 2")
	}
}

func TestRollbackPlan_VersionConflict(t *testing.T) {
	// Use a custom mock that simulates a concurrent version change
	// between GetPlan and RollbackPlan calls
	repo := &conflictMockRepository{
		MockRepository:   NewMockRepository(),
		conflictOnPlanID: "plan-rollback-conflict",
	}
	svc := NewService(repo)

	plan := &Plan{
		PlanID:             "plan-rollback-conflict",
		Status:             PlanStatusPending,
		Version:            3,
		OrgID:              "org-1",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	// Save v1 snapshot
	_ = repo.SavePlanVersion(context.Background(), &PlanVersion{
		PlanID:   plan.PlanID,
		Version:  1,
		Snapshot: json.RawMessage(`{"execution_mode":"auto","domain":"test"}`),
	})

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 1,
		OrgID:         "org-1",
	})
	if !errors.Is(err, ErrVersionConflict) {
		t.Errorf("expected ErrVersionConflict, got %v", err)
	}
}

// conflictMockRepository wraps MockRepository and forces ErrVersionConflict on RollbackPlan
type conflictMockRepository struct {
	*MockRepository
	conflictOnPlanID string
}

func (r *conflictMockRepository) RollbackPlan(ctx context.Context, planID string, expectedVersion int, snapshot json.RawMessage) (*Plan, error) {
	if planID == r.conflictOnPlanID {
		return nil, ErrVersionConflict
	}
	return r.MockRepository.RollbackPlan(ctx, planID, expectedVersion, snapshot)
}

func TestRollbackPlan_NonPendingPlan(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	plan := &Plan{
		PlanID:    "plan-rollback-completed",
		Status:    PlanStatusCompleted,
		Version:   2,
		OrgID:     "org-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 1,
		OrgID:         "org-1",
	})
	if err == nil {
		t.Fatal("expected error for non-pending plan")
	}
	if !strings.Contains(err.Error(), "only pending plans") {
		t.Errorf("error = %q, want substring 'only pending plans'", err.Error())
	}
}

func TestRollbackPlan_VersionNotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	plan := &Plan{
		PlanID:    "plan-rollback-no-version",
		Status:    PlanStatusPending,
		Version:   2,
		OrgID:     "org-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 1, // No snapshot saved for v1
		OrgID:         "org-1",
	})
	if !errors.Is(err, ErrVersionNotFound) {
		t.Errorf("expected ErrVersionNotFound, got %v", err)
	}
}

func TestRollbackPlan_CrossTenantRejected(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	plan := &Plan{
		PlanID:    "plan-rollback-cross-tenant",
		Status:    PlanStatusPending,
		Version:   2,
		OrgID:     "org-owner",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 1,
		OrgID:         "org-attacker",
	})
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound (hides existence), got %v", err)
	}
}

func TestRollbackPlan_CannotRollbackToCurrentVersion(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	plan := &Plan{
		PlanID:    "plan-rollback-same-version",
		Status:    PlanStatusPending,
		Version:   2,
		OrgID:     "org-1",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		CreatedAt: time.Now(),
	}
	repo.plans[plan.PlanID] = plan

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        plan.PlanID,
		TargetVersion: 2, // Same as current version
		OrgID:         "org-1",
	})
	if err == nil {
		t.Fatal("expected error for rollback to current version")
	}
	if !strings.Contains(err.Error(), "must be less than") {
		t.Errorf("error = %q, want substring 'must be less than'", err.Error())
	}
}

func TestRollbackPlan_PlanNotFound(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        "nonexistent",
		TargetVersion: 1,
		OrgID:         "org-1",
	})
	if !errors.Is(err, ErrPlanNotFound) {
		t.Errorf("expected ErrPlanNotFound, got %v", err)
	}
}

func TestRollbackPlan_InvalidPlanID(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo)

	_, err := svc.RollbackPlan(context.Background(), &RollbackPlanRequest{
		PlanID:        "",
		TargetVersion: 1,
	})
	if !errors.Is(err, ErrInvalidPlanID) {
		t.Errorf("expected ErrInvalidPlanID, got %v", err)
	}
}

func TestRollbackPlan_MaxVersionsEnforced(t *testing.T) {
	repo := NewMockRepository()
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 100,
		MaxVersionsPerPlan:     3,
	})

	ctx := context.Background()

	// Create plan at version 4
	plan := &Plan{
		PlanID:             "plan-rollback-limit",
		OrgID:              "org-1",
		Status:             PlanStatusPending,
		Version:            4,
		ExecutionMode:      "parallel",
		Domain:             "test",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := repo.SavePlan(ctx, plan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}

	// Save 3 versions (= the limit)
	for v := 1; v <= 3; v++ {
		_ = repo.SavePlanVersion(ctx, &PlanVersion{
			PlanID:     "plan-rollback-limit",
			Version:    v,
			Snapshot:   json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":[]}}`),
			ChangeType: "update",
		})
	}

	// Attempt rollback - should fail with ErrMaxVersions since we have 3 versions (= limit)
	_, err := svc.RollbackPlan(ctx, &RollbackPlanRequest{
		PlanID:        "plan-rollback-limit",
		TargetVersion: 1,
		OrgID:         "org-1",
		RolledBackBy:  "user-1",
	})
	if err == nil {
		t.Fatal("expected ErrMaxVersions, got nil")
	}
	if !errors.Is(err, ErrMaxVersions) {
		t.Errorf("expected ErrMaxVersions, got %v", err)
	}
}

func TestRollbackPlan_WithinVersionLimit(t *testing.T) {
	repo := NewMockRepository()
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 100,
		MaxVersionsPerPlan:     10,
	})

	ctx := context.Background()

	// Create plan at version 3
	plan := &Plan{
		PlanID:             "plan-rollback-ok",
		OrgID:              "org-1",
		Status:             PlanStatusPending,
		Version:            3,
		ExecutionMode:      "parallel",
		Domain:             "test",
		WorkflowDefinition: json.RawMessage(`{"steps":[]}`),
		ExpiresAt:          time.Now().Add(1 * time.Hour),
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}
	if err := repo.SavePlan(ctx, plan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}

	// Save 2 versions (under the limit of 10)
	for v := 1; v <= 2; v++ {
		_ = repo.SavePlanVersion(ctx, &PlanVersion{
			PlanID:     "plan-rollback-ok",
			Version:    v,
			Snapshot:   json.RawMessage(`{"execution_mode":"sequential","domain":"generic","workflow_definition":{"steps":[]}}`),
			ChangeType: "update",
		})
	}

	// Rollback should succeed
	result, err := svc.RollbackPlan(ctx, &RollbackPlanRequest{
		PlanID:        "plan-rollback-ok",
		TargetVersion: 1,
		OrgID:         "org-1",
		RolledBackBy:  "user-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Version != 4 {
		t.Errorf("expected version 4 after rollback, got %d", result.Version)
	}
}

func TestPlanLimitConstants(t *testing.T) {
	// Verify Community limits
	if MaxCommunityPlans != 25 {
		t.Errorf("MaxCommunityPlans = %d, want 25", MaxCommunityPlans)
	}
	if MaxCommunityVersionsPerPlan != 10 {
		t.Errorf("MaxCommunityVersionsPerPlan = %d, want 10", MaxCommunityVersionsPerPlan)
	}

	// Verify Evaluation limits
	if MaxEvaluationPlans != 100 {
		t.Errorf("MaxEvaluationPlans = %d, want 100", MaxEvaluationPlans)
	}
	if MaxEvaluationVersionsPerPlan != 25 {
		t.Errorf("MaxEvaluationVersionsPerPlan = %d, want 25", MaxEvaluationVersionsPerPlan)
	}

	// Evaluation limits must be higher than Community
	if MaxEvaluationPlans <= MaxCommunityPlans {
		t.Errorf("Evaluation plan limit (%d) should exceed Community (%d)", MaxEvaluationPlans, MaxCommunityPlans)
	}
	if MaxEvaluationVersionsPerPlan <= MaxCommunityVersionsPerPlan {
		t.Errorf("Evaluation versions limit (%d) should exceed Community (%d)", MaxEvaluationVersionsPerPlan, MaxCommunityVersionsPerPlan)
	}
}

func TestService_UpdatePlan_EvaluationLimits_MaxVersions(t *testing.T) {
	repo := NewMockRepository()
	plan := setupPendingPlan(repo)
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: MaxEvaluationPlans,
		MaxVersionsPerPlan:     MaxEvaluationVersionsPerPlan,
	})

	// Pre-populate at the Evaluation version limit
	for i := 0; i < MaxEvaluationVersionsPerPlan; i++ {
		_ = repo.SavePlanVersion(context.Background(), &PlanVersion{
			PlanID:     plan.PlanID,
			Version:    i + 1,
			Snapshot:   json.RawMessage(`{}`),
			ChangeType: "update",
		})
	}

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected ErrMaxVersions at Evaluation limit, got nil")
	}
	if !errors.Is(err, ErrMaxVersions) {
		t.Errorf("expected ErrMaxVersions, got %v", err)
	}
}

func TestService_UpdatePlan_EvaluationLimits_MaxPlans(t *testing.T) {
	repo := NewMockRepository()
	svc := NewServiceWithConfig(repo, ServiceConfig{
		MaxPlansWithVersioning: 3, // use small number for test (mirrors Evaluation pattern)
		MaxVersionsPerPlan:     MaxEvaluationVersionsPerPlan,
	})

	// Create 3 plans that already have versioning
	for i := 0; i < 3; i++ {
		repo.plans[string(rune('A'+i))] = &Plan{
			PlanID:  string(rune('A' + i)),
			OrgID:   "org-1",
			Status:  PlanStatusPending,
			Version: 2,
		}
	}

	// Create a new plan at version 1
	plan := setupPendingPlan(repo)

	req := &UpdatePlanRequest{
		PlanID:          plan.PlanID,
		ExpectedVersion: 1,
		ExecutionMode:   "manual",
		OrgID:           "org-1",
	}

	_, err := svc.UpdatePlan(context.Background(), req)
	if err == nil {
		t.Fatal("expected ErrMaxPlans, got nil")
	}
	if !errors.Is(err, ErrMaxPlans) {
		t.Errorf("expected ErrMaxPlans, got %v", err)
	}
}
