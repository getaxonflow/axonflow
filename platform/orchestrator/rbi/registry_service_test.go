// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"errors"
	"testing"
	"time"
)

// MockAISystemRepository is a mock implementation of AISystemRepository for testing.
type MockAISystemRepository struct {
	systems map[string]map[string]*AISystem // orgID -> id -> system
	err     error
}

// NewMockAISystemRepository creates a new mock repository.
func NewMockAISystemRepository() *MockAISystemRepository {
	return &MockAISystemRepository{
		systems: make(map[string]map[string]*AISystem),
	}
}

func (m *MockAISystemRepository) Create(ctx context.Context, system *AISystem) error {
	if m.err != nil {
		return m.err
	}
	if m.systems[system.OrgID] == nil {
		m.systems[system.OrgID] = make(map[string]*AISystem)
	}
	// Check for duplicate system_id
	for _, s := range m.systems[system.OrgID] {
		if s.SystemID == system.SystemID {
			return ErrSystemAlreadyExists
		}
	}

	// Simulate what the real repository does - set ID and defaults
	if system.ID == "" {
		system.ID = "mock-id-" + system.SystemID
	}
	if system.CreatedAt.IsZero() {
		system.CreatedAt = time.Now().UTC()
	}
	system.UpdatedAt = system.CreatedAt
	if system.DeploymentStatus == "" {
		system.DeploymentStatus = DeploymentStatusDevelopment
	}
	// Set board approval based on risk
	if system.RiskCategory == RiskCategoryHigh {
		system.BoardApprovalRequired = true
		if system.BoardApprovalStatus == "" {
			system.BoardApprovalStatus = BoardApprovalPending
		}
	} else if system.BoardApprovalStatus == "" {
		system.BoardApprovalStatus = BoardApprovalNotRequired
	}

	m.systems[system.OrgID][system.ID] = system
	return nil
}

func (m *MockAISystemRepository) Get(ctx context.Context, orgID, id string) (*AISystem, error) {
	if m.err != nil {
		return nil, m.err
	}
	if orgSystems, ok := m.systems[orgID]; ok {
		if system, ok := orgSystems[id]; ok {
			return system, nil
		}
	}
	return nil, ErrSystemNotFound
}

func (m *MockAISystemRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystem, error) {
	if m.err != nil {
		return nil, m.err
	}
	if orgSystems, ok := m.systems[orgID]; ok {
		for _, system := range orgSystems {
			if system.SystemID == systemID {
				return system, nil
			}
		}
	}
	return nil, ErrSystemNotFound
}

func (m *MockAISystemRepository) List(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	var result []*AISystem
	if orgSystems, ok := m.systems[orgID]; ok {
		for _, system := range orgSystems {
			// Apply filters
			if params != nil {
				if params.RiskCategory != "" && string(system.RiskCategory) != params.RiskCategory {
					continue
				}
				if params.DeploymentStatus != "" && string(system.DeploymentStatus) != params.DeploymentStatus {
					continue
				}
				if params.BoardApprovalStatus != "" && string(system.BoardApprovalStatus) != params.BoardApprovalStatus {
					continue
				}
			}
			result = append(result, system)
		}
	}
	return result, len(result), nil
}

func (m *MockAISystemRepository) Update(ctx context.Context, system *AISystem) error {
	if m.err != nil {
		return m.err
	}
	if orgSystems, ok := m.systems[system.OrgID]; ok {
		if _, ok := orgSystems[system.ID]; ok {
			m.systems[system.OrgID][system.ID] = system
			return nil
		}
	}
	return ErrSystemNotFound
}

func (m *MockAISystemRepository) Delete(ctx context.Context, orgID, id string) error {
	if m.err != nil {
		return m.err
	}
	if orgSystems, ok := m.systems[orgID]; ok {
		if system, ok := orgSystems[id]; ok {
			now := time.Now().UTC()
			system.DeploymentStatus = DeploymentStatusDeprecated
			system.DeprecatedAt = &now
			return nil
		}
	}
	return ErrSystemNotFound
}

func (m *MockAISystemRepository) GetSummary(ctx context.Context, orgID string) (*AISystemSummary, error) {
	if m.err != nil {
		return nil, m.err
	}
	summary := &AISystemSummary{
		SystemsByRisk:   make(map[string]int),
		SystemsByStatus: make(map[string]int),
	}
	if orgSystems, ok := m.systems[orgID]; ok {
		summary.TotalSystems = len(orgSystems)
		for _, system := range orgSystems {
			summary.SystemsByRisk[string(system.RiskCategory)]++
			summary.SystemsByStatus[string(system.DeploymentStatus)]++
			if system.BoardApprovalStatus == BoardApprovalPending {
				summary.SystemsPendingApproval++
			}
		}
	}
	return summary, nil
}

func TestAISystemRegistryService_CreateSystem(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	t.Run("create low risk system", func(t *testing.T) {
		req := &CreateAISystemRequest{
			SystemID:     "chatbot-v1",
			SystemName:   "Customer Support Chatbot",
			RiskCategory: "low",
			Description:  "AI chatbot for FAQ",
		}

		system, err := service.CreateSystem(ctx, "org-1", req)
		if err != nil {
			t.Fatalf("CreateSystem failed: %v", err)
		}

		if system.ID == "" {
			t.Error("Expected system ID to be set")
		}
		if system.OrgID != "org-1" {
			t.Errorf("OrgID = %v, want org-1", system.OrgID)
		}
		if system.SystemID != "chatbot-v1" {
			t.Errorf("SystemID = %v, want chatbot-v1", system.SystemID)
		}
		if system.RiskCategory != RiskCategoryLow {
			t.Errorf("RiskCategory = %v, want low", system.RiskCategory)
		}
		if system.BoardApprovalRequired {
			t.Error("Low risk system should not require board approval")
		}
		if system.BoardApprovalStatus != BoardApprovalNotRequired {
			t.Errorf("BoardApprovalStatus = %v, want not_required", system.BoardApprovalStatus)
		}
	})

	t.Run("create high risk system requires board approval", func(t *testing.T) {
		req := &CreateAISystemRequest{
			SystemID:     "loan-approval-v1",
			SystemName:   "Loan Approval System",
			RiskCategory: "high",
			Description:  "AI for automated loan decisions",
		}

		system, err := service.CreateSystem(ctx, "org-1", req)
		if err != nil {
			t.Fatalf("CreateSystem failed: %v", err)
		}

		if !system.BoardApprovalRequired {
			t.Error("High risk system should require board approval")
		}
		if system.BoardApprovalStatus != BoardApprovalPending {
			t.Errorf("BoardApprovalStatus = %v, want pending", system.BoardApprovalStatus)
		}
	})

	t.Run("duplicate system ID fails", func(t *testing.T) {
		req := &CreateAISystemRequest{
			SystemID:     "chatbot-v1", // Already exists
			SystemName:   "Another Chatbot",
			RiskCategory: "low",
		}

		_, err := service.CreateSystem(ctx, "org-1", req)
		if !errors.Is(err, ErrSystemAlreadyExists) {
			t.Errorf("Expected ErrSystemAlreadyExists, got %v", err)
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *CreateAISystemRequest
		}{
			{"nil request", nil},
			{"missing system_id", &CreateAISystemRequest{SystemName: "Test", RiskCategory: "low"}},
			{"missing system_name", &CreateAISystemRequest{SystemID: "test", RiskCategory: "low"}},
			{"missing risk_category", &CreateAISystemRequest{SystemID: "test", SystemName: "Test"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateSystem(ctx, "org-1", tc.req)
				if err == nil {
					t.Error("Expected error for invalid input")
				}
			})
		}
	})

	t.Run("invalid risk category", func(t *testing.T) {
		req := &CreateAISystemRequest{
			SystemID:     "test-invalid",
			SystemName:   "Test System",
			RiskCategory: "invalid",
		}

		_, err := service.CreateSystem(ctx, "org-1", req)
		if err == nil {
			t.Error("Expected error for invalid risk category")
		}
	})

	t.Run("validation frequency sets next due date", func(t *testing.T) {
		req := &CreateAISystemRequest{
			SystemID:                "test-validation",
			SystemName:              "Test Validation System",
			RiskCategory:            "medium",
			ValidationFrequencyDays: 90,
		}

		system, err := service.CreateSystem(ctx, "org-1", req)
		if err != nil {
			t.Fatalf("CreateSystem failed: %v", err)
		}

		if system.NextValidationDue == nil {
			t.Error("Expected NextValidationDue to be set")
		}
	})
}

func TestAISystemRegistryService_GetSystem(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create a system first
	req := &CreateAISystemRequest{
		SystemID:     "get-test-v1",
		SystemName:   "Get Test System",
		RiskCategory: "low",
	}
	created, _ := service.CreateSystem(ctx, "org-1", req)

	t.Run("get existing system", func(t *testing.T) {
		system, err := service.GetSystem(ctx, "org-1", created.ID)
		if err != nil {
			t.Fatalf("GetSystem failed: %v", err)
		}
		if system.ID != created.ID {
			t.Errorf("ID = %v, want %v", system.ID, created.ID)
		}
	})

	t.Run("get non-existent system", func(t *testing.T) {
		_, err := service.GetSystem(ctx, "org-1", "non-existent")
		if !errors.Is(err, ErrSystemNotFound) {
			t.Errorf("Expected ErrSystemNotFound, got %v", err)
		}
	})
}

func TestAISystemRegistryService_UpdateSystem(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create a system first
	req := &CreateAISystemRequest{
		SystemID:     "update-test-v1",
		SystemName:   "Update Test System",
		RiskCategory: "low",
	}
	created, _ := service.CreateSystem(ctx, "org-1", req)

	t.Run("update system name", func(t *testing.T) {
		newName := "Updated System Name"
		updateReq := &UpdateAISystemRequest{
			SystemName: &newName,
		}

		updated, err := service.UpdateSystem(ctx, "org-1", created.ID, updateReq)
		if err != nil {
			t.Fatalf("UpdateSystem failed: %v", err)
		}
		if updated.SystemName != newName {
			t.Errorf("SystemName = %v, want %v", updated.SystemName, newName)
		}
	})

	t.Run("upgrade to high risk triggers board approval", func(t *testing.T) {
		highRisk := "high"
		updateReq := &UpdateAISystemRequest{
			RiskCategory: &highRisk,
		}

		updated, err := service.UpdateSystem(ctx, "org-1", created.ID, updateReq)
		if err != nil {
			t.Fatalf("UpdateSystem failed: %v", err)
		}
		if !updated.BoardApprovalRequired {
			t.Error("High risk should require board approval")
		}
		if updated.BoardApprovalStatus != BoardApprovalPending {
			t.Errorf("BoardApprovalStatus = %v, want pending", updated.BoardApprovalStatus)
		}
	})

	t.Run("production deployment requires board approval for high risk", func(t *testing.T) {
		production := "production"
		updateReq := &UpdateAISystemRequest{
			DeploymentStatus: &production,
		}

		_, err := service.UpdateSystem(ctx, "org-1", created.ID, updateReq)
		if err == nil {
			t.Error("Expected error when moving to production without board approval")
		}
	})

	t.Run("nil request fails", func(t *testing.T) {
		_, err := service.UpdateSystem(ctx, "org-1", created.ID, nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
	})
}

func TestAISystemRegistryService_ProcessBoardApproval(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create a high-risk system
	req := &CreateAISystemRequest{
		SystemID:     "approval-test-v1",
		SystemName:   "Approval Test System",
		RiskCategory: "high",
	}
	created, _ := service.CreateSystem(ctx, "org-1", req)

	t.Run("approve system", func(t *testing.T) {
		approvalReq := &BoardApprovalRequest{
			Action:    "approve",
			Reference: "BOARD-2025-001",
			Approver:  "CRO",
			Notes:     "Approved after risk review",
		}

		approved, err := service.ProcessBoardApproval(ctx, "org-1", created.ID, approvalReq)
		if err != nil {
			t.Fatalf("ProcessBoardApproval failed: %v", err)
		}
		if approved.BoardApprovalStatus != BoardApprovalApproved {
			t.Errorf("BoardApprovalStatus = %v, want approved", approved.BoardApprovalStatus)
		}
		if approved.BoardApproverName != "CRO" {
			t.Errorf("BoardApproverName = %v, want CRO", approved.BoardApproverName)
		}
		if approved.BoardApprovalDate == nil {
			t.Error("Expected BoardApprovalDate to be set")
		}
	})

	t.Run("invalid action fails", func(t *testing.T) {
		approvalReq := &BoardApprovalRequest{
			Action:   "invalid",
			Approver: "CRO",
		}

		_, err := service.ProcessBoardApproval(ctx, "org-1", created.ID, approvalReq)
		if err == nil {
			t.Error("Expected error for invalid action")
		}
	})

	t.Run("nil request fails", func(t *testing.T) {
		_, err := service.ProcessBoardApproval(ctx, "org-1", created.ID, nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
	})
}

func TestAISystemRegistryService_DeleteSystem(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create a system first
	req := &CreateAISystemRequest{
		SystemID:     "delete-test-v1",
		SystemName:   "Delete Test System",
		RiskCategory: "low",
	}
	created, _ := service.CreateSystem(ctx, "org-1", req)

	t.Run("delete existing system", func(t *testing.T) {
		err := service.DeleteSystem(ctx, "org-1", created.ID)
		if err != nil {
			t.Fatalf("DeleteSystem failed: %v", err)
		}

		// Verify it's marked as deprecated
		system, err := service.GetSystem(ctx, "org-1", created.ID)
		if err != nil {
			t.Fatalf("GetSystem failed: %v", err)
		}
		if system.DeploymentStatus != DeploymentStatusDeprecated {
			t.Errorf("DeploymentStatus = %v, want deprecated", system.DeploymentStatus)
		}
	})

	t.Run("delete non-existent system", func(t *testing.T) {
		err := service.DeleteSystem(ctx, "org-1", "non-existent")
		if !errors.Is(err, ErrSystemNotFound) {
			t.Errorf("Expected ErrSystemNotFound, got %v", err)
		}
	})
}

func TestAISystemRegistryService_ListSystems(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create multiple systems
	systems := []CreateAISystemRequest{
		{SystemID: "sys-1", SystemName: "System 1", RiskCategory: "low"},
		{SystemID: "sys-2", SystemName: "System 2", RiskCategory: "medium"},
		{SystemID: "sys-3", SystemName: "System 3", RiskCategory: "high"},
	}
	for _, req := range systems {
		service.CreateSystem(ctx, "org-1", &req)
	}

	t.Run("list all systems", func(t *testing.T) {
		result, total, err := service.ListSystems(ctx, "org-1", nil)
		if err != nil {
			t.Fatalf("ListSystems failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Total = %v, want 3", total)
		}
		if len(result) != 3 {
			t.Errorf("Result length = %v, want 3", len(result))
		}
	})

	t.Run("filter by risk category", func(t *testing.T) {
		params := &ListAISystemsParams{
			RiskCategory: "high",
		}
		result, total, err := service.ListSystems(ctx, "org-1", params)
		if err != nil {
			t.Fatalf("ListSystems failed: %v", err)
		}
		if total != 1 {
			t.Errorf("Total = %v, want 1", total)
		}
		if len(result) != 1 {
			t.Errorf("Result length = %v, want 1", len(result))
		}
	})
}

func TestAISystemRegistryService_GetSummary(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create multiple systems
	systems := []CreateAISystemRequest{
		{SystemID: "sum-1", SystemName: "System 1", RiskCategory: "low"},
		{SystemID: "sum-2", SystemName: "System 2", RiskCategory: "medium"},
		{SystemID: "sum-3", SystemName: "System 3", RiskCategory: "high"},
	}
	for _, req := range systems {
		service.CreateSystem(ctx, "org-2", &req)
	}

	t.Run("get summary", func(t *testing.T) {
		summary, err := service.GetSystemSummary(ctx, "org-2")
		if err != nil {
			t.Fatalf("GetSystemSummary failed: %v", err)
		}
		if summary.TotalSystems != 3 {
			t.Errorf("TotalSystems = %v, want 3", summary.TotalSystems)
		}
		if summary.SystemsByRisk["low"] != 1 {
			t.Errorf("SystemsByRisk[low] = %v, want 1", summary.SystemsByRisk["low"])
		}
		if summary.SystemsPendingApproval != 1 {
			t.Errorf("SystemsPendingApproval = %v, want 1", summary.SystemsPendingApproval)
		}
	})
}

func TestAISystemRegistryService_ScheduleValidation(t *testing.T) {
	repo := NewMockAISystemRepository()
	service := NewAISystemRegistryService(repo)
	ctx := context.Background()

	// Create a system with validation frequency
	req := &CreateAISystemRequest{
		SystemID:                "val-test-v1",
		SystemName:              "Validation Test System",
		RiskCategory:            "medium",
		ValidationFrequencyDays: 90,
	}
	created, _ := service.CreateSystem(ctx, "org-1", req)

	t.Run("schedule validation", func(t *testing.T) {
		validationDate := time.Now().UTC()
		updated, err := service.ScheduleValidation(ctx, "org-1", created.ID, validationDate)
		if err != nil {
			t.Fatalf("ScheduleValidation failed: %v", err)
		}
		if updated.LastValidationDate == nil {
			t.Error("Expected LastValidationDate to be set")
		}
		if updated.NextValidationDue == nil {
			t.Error("Expected NextValidationDue to be set")
		}
		// Next validation should be 90 days from validation date
		expectedNext := validationDate.Add(90 * 24 * time.Hour)
		if updated.NextValidationDue.Sub(expectedNext) > time.Minute {
			t.Errorf("NextValidationDue = %v, want ~%v", updated.NextValidationDue, expectedNext)
		}
	})
}
