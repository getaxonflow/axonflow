// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// mockRegistryRepository is a mock implementation of RegistryRepository for testing.
type mockRegistryRepository struct {
	systems  map[string]*AISystemRegistry
	createFn func(ctx context.Context, system *AISystemRegistry) error
	getByIDFn func(ctx context.Context, orgID, id string) (*AISystemRegistry, error)
}

func newMockRegistryRepository() *mockRegistryRepository {
	return &mockRegistryRepository{
		systems: make(map[string]*AISystemRegistry),
	}
}

func (m *mockRegistryRepository) Create(ctx context.Context, system *AISystemRegistry) error {
	if m.createFn != nil {
		return m.createFn(ctx, system)
	}
	// Generate ID if not set (simulating database auto-generation)
	if system.ID == "" {
		system.ID = fmt.Sprintf("reg-%d", len(m.systems)+1)
	}
	m.systems[system.ID] = system
	return nil
}

func (m *mockRegistryRepository) GetByID(ctx context.Context, orgID, id string) (*AISystemRegistry, error) {
	if m.getByIDFn != nil {
		return m.getByIDFn(ctx, orgID, id)
	}
	for _, sys := range m.systems {
		if sys.OrgID == orgID && sys.ID == id {
			return sys, nil
		}
	}
	return nil, nil
}

func (m *mockRegistryRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystemRegistry, error) {
	for _, sys := range m.systems {
		if sys.OrgID == orgID && sys.SystemID == systemID {
			return sys, nil
		}
	}
	return nil, nil
}

func (m *mockRegistryRepository) List(ctx context.Context, orgID string, params ListParams) ([]*AISystemRegistry, error) {
	var result []*AISystemRegistry
	for _, sys := range m.systems {
		if sys.OrgID == orgID {
			if params.Status != "" && string(sys.Status) != params.Status {
				continue
			}
			result = append(result, sys)
		}
	}
	return result, nil
}

func (m *mockRegistryRepository) Update(ctx context.Context, system *AISystemRegistry) error {
	m.systems[system.ID] = system
	return nil
}

func (m *mockRegistryRepository) Delete(ctx context.Context, orgID, id string) error {
	for k, sys := range m.systems {
		if sys.OrgID == orgID && sys.ID == id {
			sys.Status = SystemStatusRetired
			m.systems[k] = sys
			return nil
		}
	}
	return nil
}

func (m *mockRegistryRepository) GetSummary(ctx context.Context, orgID string) (*RegistrySummary, error) {
	summary := &RegistrySummary{OrgID: orgID}
	for _, sys := range m.systems {
		if sys.OrgID == orgID {
			summary.TotalSystems++
			if sys.Status == SystemStatusActive {
				summary.ActiveSystems++
			}
			switch sys.MaterialityClassification {
			case MaterialityHigh:
				summary.HighMateriality++
			case MaterialityMedium:
				summary.MediumMateriality++
			case MaterialityLow:
				summary.LowMateriality++
			}
		}
	}
	return summary, nil
}

func (m *mockRegistryRepository) CountByStatus(ctx context.Context, orgID string) (map[SystemStatus]int, error) {
	counts := make(map[SystemStatus]int)
	for _, sys := range m.systems {
		if sys.OrgID == orgID {
			counts[sys.Status]++
		}
	}
	return counts, nil
}

func TestRegistryService_RegisterSystem(t *testing.T) {
	tests := []struct {
		name    string
		orgID   string
		req     *CreateRegistryRequest
		wantErr bool
		errMsg  string
	}{
		{
			name:  "Valid registration",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Credit Scoring AI",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     4,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   4,
				OwnerTeam:            "Risk Team",
				OwnerEmail:           "risk@example.com",
			},
			wantErr: false,
		},
		{
			name:  "Missing system_id",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemName:           "Credit Scoring AI",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     4,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   4,
				OwnerTeam:            "Risk Team",
				OwnerEmail:           "risk@example.com",
			},
			wantErr: true,
			errMsg:  "system_id is required",
		},
		{
			name:  "Missing system_name",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     4,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   4,
				OwnerTeam:            "Risk Team",
				OwnerEmail:           "risk@example.com",
			},
			wantErr: true,
			errMsg:  "system_name is required",
		},
		{
			name:  "Invalid risk rating - too low",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Credit Scoring AI",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     0,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   4,
				OwnerTeam:            "Risk Team",
				OwnerEmail:           "risk@example.com",
			},
			wantErr: true,
			errMsg:  "risk_rating_impact must be between 1 and 5",
		},
		{
			name:  "Invalid risk rating - too high",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Credit Scoring AI",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     4,
				RiskRatingComplexity: 6,
				RiskRatingReliance:   4,
				OwnerTeam:            "Risk Team",
				OwnerEmail:           "risk@example.com",
			},
			wantErr: true,
			errMsg:  "risk_rating_complexity must be between 1 and 5",
		},
		{
			name:  "Missing owner_team",
			orgID: "org-123",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Credit Scoring AI",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     4,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   4,
				OwnerEmail:           "risk@example.com",
			},
			wantErr: true,
			errMsg:  "owner_team is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockRegistryRepository()
			service := NewRegistryService(repo)

			system, err := service.RegisterSystem(context.Background(), tt.orgID, tt.req, "test-user")

			if tt.wantErr {
				if err == nil {
					t.Errorf("RegisterSystem() expected error, got nil")
				} else if err.Error() != tt.errMsg {
					t.Errorf("RegisterSystem() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("RegisterSystem() unexpected error: %v", err)
				}
				if system == nil {
					t.Errorf("RegisterSystem() returned nil system")
				} else {
					if system.OrgID != tt.orgID {
						t.Errorf("RegisterSystem() OrgID = %v, want %v", system.OrgID, tt.orgID)
					}
					if system.Status != SystemStatusDraft {
						t.Errorf("RegisterSystem() Status = %v, want %v", system.Status, SystemStatusDraft)
					}
				}
			}
		})
	}
}

func TestRegistryService_RegisterSystem_Duplicate(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}

	// First registration should succeed
	_, err := service.RegisterSystem(context.Background(), "org-123", req, "test-user")
	if err != nil {
		t.Fatalf("First RegisterSystem() unexpected error: %v", err)
	}

	// Second registration with same system_id should fail
	_, err = service.RegisterSystem(context.Background(), "org-123", req, "test-user")
	if err == nil {
		t.Errorf("Second RegisterSystem() expected error for duplicate")
	}
	if err.Error() != "system with this system_id already exists" {
		t.Errorf("RegisterSystem() error = %v, want 'system with this system_id already exists'", err.Error())
	}
}

func TestRegistryService_GetSystem(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	// Register a system first
	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}
	created, _ := service.RegisterSystem(context.Background(), "org-123", req, "test-user")

	// Get the system
	system, err := service.GetSystem(context.Background(), "org-123", created.ID)
	if err != nil {
		t.Fatalf("GetSystem() unexpected error: %v", err)
	}
	if system == nil {
		t.Fatalf("GetSystem() returned nil")
	}
	if system.ID != created.ID {
		t.Errorf("GetSystem() ID = %v, want %v", system.ID, created.ID)
	}

	// Try to get non-existent system
	_, err = service.GetSystem(context.Background(), "org-123", "non-existent")
	if err == nil {
		t.Errorf("GetSystem() expected error for non-existent system")
	}
}

func TestRegistryService_UpdateSystem(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	// Register a system first
	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}
	created, _ := service.RegisterSystem(context.Background(), "org-123", req, "test-user")

	// Update the system
	newName := "Updated Credit Scoring AI"
	newImpact := 5
	updateReq := &UpdateRegistryRequest{
		SystemName:       newName,
		RiskRatingImpact: &newImpact,
	}

	updated, err := service.UpdateSystem(context.Background(), "org-123", created.ID, updateReq, "test-user")
	if err != nil {
		t.Fatalf("UpdateSystem() unexpected error: %v", err)
	}
	if updated.SystemName != newName {
		t.Errorf("UpdateSystem() SystemName = %v, want %v", updated.SystemName, newName)
	}
	if updated.RiskRatingImpact != newImpact {
		t.Errorf("UpdateSystem() RiskRatingImpact = %v, want %v", updated.RiskRatingImpact, newImpact)
	}
}

func TestRegistryService_DeleteSystem(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	// Register a system first
	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}
	created, _ := service.RegisterSystem(context.Background(), "org-123", req, "test-user")

	// Delete the system
	err := service.DeleteSystem(context.Background(), "org-123", created.ID)
	if err != nil {
		t.Fatalf("DeleteSystem() unexpected error: %v", err)
	}

	// Verify it's marked as retired
	system, _ := service.GetSystem(context.Background(), "org-123", created.ID)
	if system.Status != SystemStatusRetired {
		t.Errorf("DeleteSystem() Status = %v, want %v", system.Status, SystemStatusRetired)
	}
}

func TestRegistryService_ActivateSystem(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	// Register a system first (starts as draft)
	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}
	created, _ := service.RegisterSystem(context.Background(), "org-123", req, "test-user")

	// Activate the system
	activated, err := service.ActivateSystem(context.Background(), "org-123", created.ID, "test-user")
	if err != nil {
		t.Fatalf("ActivateSystem() unexpected error: %v", err)
	}
	if activated.Status != SystemStatusActive {
		t.Errorf("ActivateSystem() Status = %v, want %v", activated.Status, SystemStatusActive)
	}

	// Try to activate an already active system
	_, err = service.ActivateSystem(context.Background(), "org-123", created.ID, "test-user")
	if err == nil {
		t.Errorf("ActivateSystem() expected error for already active system")
	}
}

func TestRegistryService_GetSummary(t *testing.T) {
	repo := newMockRegistryRepository()
	service := NewRegistryService(repo)

	// Register some systems
	systems := []struct {
		systemID string
		impact   int
		status   SystemStatus
	}{
		{"sys-001", 5, SystemStatusActive},
		{"sys-002", 4, SystemStatusActive},
		{"sys-003", 2, SystemStatusDraft},
	}

	for _, s := range systems {
		req := &CreateRegistryRequest{
			SystemID:             s.systemID,
			SystemName:           "Test System",
			UseCase:              UseCaseCreditScoring,
			RiskRatingImpact:     s.impact,
			RiskRatingComplexity: 4,
			RiskRatingReliance:   4,
			OwnerTeam:            "Test Team",
			OwnerEmail:           "test@example.com",
		}
		created, _ := service.RegisterSystem(context.Background(), "org-123", req, "test-user")
		if s.status == SystemStatusActive {
			service.ActivateSystem(context.Background(), "org-123", created.ID, "test-user")
		}
	}

	// Get summary
	summary, err := service.GetSummary(context.Background(), "org-123")
	if err != nil {
		t.Fatalf("GetSummary() unexpected error: %v", err)
	}
	if summary.TotalSystems != 3 {
		t.Errorf("GetSummary() TotalSystems = %v, want 3", summary.TotalSystems)
	}
	if summary.ActiveSystems != 2 {
		t.Errorf("GetSummary() ActiveSystems = %v, want 2", summary.ActiveSystems)
	}
}

func TestRegistryService_validateCreateRequest(t *testing.T) {
	service := NewRegistryService(nil)

	tests := []struct {
		name    string
		req     *CreateRegistryRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid request",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Test",
				UseCase:              UseCaseCreditScoring,
				RiskRatingImpact:     3,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   3,
				OwnerTeam:            "Team",
				OwnerEmail:           "team@example.com",
			},
			wantErr: false,
		},
		{
			name: "Invalid use case",
			req: &CreateRegistryRequest{
				SystemID:             "sys-001",
				SystemName:           "Test",
				UseCase:              "invalid",
				RiskRatingImpact:     3,
				RiskRatingComplexity: 3,
				RiskRatingReliance:   3,
				OwnerTeam:            "Team",
				OwnerEmail:           "team@example.com",
			},
			wantErr: true,
			errMsg:  "invalid use_case",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateCreateRequest(tt.req)
			if tt.wantErr {
				if err == nil {
					t.Errorf("validateCreateRequest() expected error")
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("validateCreateRequest() error = %v, want %v", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateCreateRequest() unexpected error: %v", err)
				}
			}
		})
	}
}

// Test with repository error
func TestRegistryService_RegisterSystem_RepoError(t *testing.T) {
	repo := newMockRegistryRepository()
	repo.createFn = func(ctx context.Context, system *AISystemRegistry) error {
		return errors.New("database error")
	}
	service := NewRegistryService(repo)

	req := &CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring AI",
		UseCase:              UseCaseCreditScoring,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   4,
		OwnerTeam:            "Risk Team",
		OwnerEmail:           "risk@example.com",
	}

	_, err := service.RegisterSystem(context.Background(), "org-123", req, "test-user")
	if err == nil {
		t.Errorf("RegisterSystem() expected error")
	}
}
