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

// MockModelValidationRepository is a mock implementation for testing.
type MockModelValidationRepository struct {
	validations map[string]map[string]*ModelValidation // orgID -> id -> validation
	err         error
}

func NewMockModelValidationRepository() *MockModelValidationRepository {
	return &MockModelValidationRepository{
		validations: make(map[string]map[string]*ModelValidation),
	}
}

func (m *MockModelValidationRepository) Create(ctx context.Context, v *ModelValidation) error {
	if m.err != nil {
		return m.err
	}
	if m.validations[v.OrgID] == nil {
		m.validations[v.OrgID] = make(map[string]*ModelValidation)
	}
	if v.ID == "" {
		// Use a unique ID based on count to avoid overwrites
		v.ID = "mock-val-" + v.SystemID + "-" + string(rune(len(m.validations[v.OrgID])+'0'))
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	v.UpdatedAt = v.CreatedAt
	m.validations[v.OrgID][v.ID] = v
	return nil
}

func (m *MockModelValidationRepository) Get(ctx context.Context, orgID, id string) (*ModelValidation, error) {
	if m.err != nil {
		return nil, m.err
	}
	if orgVals, ok := m.validations[orgID]; ok {
		if v, ok := orgVals[id]; ok {
			return v, nil
		}
	}
	return nil, ErrValidationNotFound
}

func (m *MockModelValidationRepository) List(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	var result []*ModelValidation
	if orgVals, ok := m.validations[orgID]; ok {
		for _, v := range orgVals {
			if params != nil {
				if params.SystemID != "" && v.SystemID != params.SystemID {
					continue
				}
				if params.ValidationType != "" && string(v.ValidationType) != params.ValidationType {
					continue
				}
			}
			result = append(result, v)
		}
	}
	return result, len(result), nil
}

func (m *MockModelValidationRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*ModelValidation, error) {
	vals, _, err := m.List(ctx, orgID, &ListValidationsParams{SystemID: systemID})
	return vals, err
}

func (m *MockModelValidationRepository) Update(ctx context.Context, v *ModelValidation) error {
	if m.err != nil {
		return m.err
	}
	if orgVals, ok := m.validations[v.OrgID]; ok {
		if _, ok := orgVals[v.ID]; ok {
			v.UpdatedAt = time.Now().UTC()
			m.validations[v.OrgID][v.ID] = v
			return nil
		}
	}
	return ErrValidationNotFound
}

func (m *MockModelValidationRepository) Delete(ctx context.Context, orgID, id string) error {
	if m.err != nil {
		return m.err
	}
	if orgVals, ok := m.validations[orgID]; ok {
		if _, ok := orgVals[id]; ok {
			delete(orgVals, id)
			return nil
		}
	}
	return ErrValidationNotFound
}

func (m *MockModelValidationRepository) GetLatestBySystem(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error) {
	if m.err != nil {
		return nil, m.err
	}
	var latest *ModelValidation
	if orgVals, ok := m.validations[orgID]; ok {
		for _, v := range orgVals {
			if v.SystemID != systemID {
				continue
			}
			if validationType != "" && v.ValidationType != validationType {
				continue
			}
			if latest == nil || v.ValidationDate.After(latest.ValidationDate) {
				latest = v
			}
		}
	}
	if latest == nil {
		return nil, ErrValidationNotFound
	}
	return latest, nil
}

func TestModelValidationService_CreateValidation(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	t.Run("create development validation", func(t *testing.T) {
		req := &CreateValidationRequest{
			SystemID:       "credit-scoring-v1",
			ValidationType: "development",
			ValidatorType:  "internal",
			ValidatorName:  "ML Team",
			Recommendation: "approve",
			Methodology:    "Cross-validation",
			AccuracyMetrics: map[string]float64{
				"accuracy":  0.92,
				"precision": 0.89,
			},
		}

		validation, err := service.CreateValidation(ctx, "org-1", req)
		if err != nil {
			t.Fatalf("CreateValidation failed: %v", err)
		}

		if validation.ID == "" {
			t.Error("Expected validation ID to be set")
		}
		if validation.ValidationType != ValidationTypeDevelopment {
			t.Errorf("ValidationType = %v, want development", validation.ValidationType)
		}
		if validation.Recommendation != ValidationRecommendationApprove {
			t.Errorf("Recommendation = %v, want approve", validation.Recommendation)
		}
	})

	t.Run("create independent validation", func(t *testing.T) {
		req := &CreateValidationRequest{
			SystemID:              "credit-scoring-v1",
			ValidationType:        "independent",
			ValidatorType:         "external_auditor",
			ValidatorName:         "KPMG",
			ValidatorOrganization: "KPMG India",
			ValidatorCredentials:  "RBI Approved",
			Recommendation:        "conditional",
			Conditions:            "Address bias within 30 days",
			RemediationRequired:   true,
			Findings: []ValidationFinding{
				{
					Category:    "bias",
					Severity:    "medium",
					Title:       "Age bias detected",
					Description: "Model shows bias against applicants over 60",
				},
			},
		}

		validation, err := service.CreateValidation(ctx, "org-1", req)
		if err != nil {
			t.Fatalf("CreateValidation failed: %v", err)
		}

		if validation.ValidatorType != ValidatorTypeExternalAuditor {
			t.Errorf("ValidatorType = %v, want external_auditor", validation.ValidatorType)
		}
		if validation.Recommendation != ValidationRecommendationConditional {
			t.Errorf("Recommendation = %v, want conditional", validation.Recommendation)
		}
		if !validation.RemediationRequired {
			t.Error("Expected RemediationRequired to be true")
		}
		if len(validation.Findings) != 1 {
			t.Errorf("Findings length = %v, want 1", len(validation.Findings))
		}
		// Check that finding got an ID
		if validation.Findings[0].ID == "" {
			t.Error("Expected finding ID to be generated")
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *CreateValidationRequest
		}{
			{"nil request", nil},
			{"missing system_id", &CreateValidationRequest{ValidationType: "development", ValidatorType: "internal", ValidatorName: "Test", Recommendation: "approve"}},
			{"missing validation_type", &CreateValidationRequest{SystemID: "sys", ValidatorType: "internal", ValidatorName: "Test", Recommendation: "approve"}},
			{"missing validator_type", &CreateValidationRequest{SystemID: "sys", ValidationType: "development", ValidatorName: "Test", Recommendation: "approve"}},
			{"missing validator_name", &CreateValidationRequest{SystemID: "sys", ValidationType: "development", ValidatorType: "internal", Recommendation: "approve"}},
			{"missing recommendation", &CreateValidationRequest{SystemID: "sys", ValidationType: "development", ValidatorType: "internal", ValidatorName: "Test"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateValidation(ctx, "org-1", tc.req)
				if err == nil {
					t.Error("Expected error for invalid input")
				}
			})
		}
	})

	t.Run("invalid enum values", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *CreateValidationRequest
		}{
			{
				"invalid validation_type",
				&CreateValidationRequest{SystemID: "sys", ValidationType: "invalid", ValidatorType: "internal", ValidatorName: "Test", Recommendation: "approve"},
			},
			{
				"invalid validator_type",
				&CreateValidationRequest{SystemID: "sys", ValidationType: "development", ValidatorType: "invalid", ValidatorName: "Test", Recommendation: "approve"},
			},
			{
				"invalid recommendation",
				&CreateValidationRequest{SystemID: "sys", ValidationType: "development", ValidatorType: "internal", ValidatorName: "Test", Recommendation: "invalid"},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateValidation(ctx, "org-1", tc.req)
				if err == nil {
					t.Error("Expected error for invalid enum value")
				}
			})
		}
	})
}

func TestModelValidationService_GetValidation(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create a validation first
	req := &CreateValidationRequest{
		SystemID:       "get-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Test",
		Recommendation: "approve",
	}
	created, _ := service.CreateValidation(ctx, "org-1", req)

	t.Run("get existing validation", func(t *testing.T) {
		validation, err := service.GetValidation(ctx, "org-1", created.ID)
		if err != nil {
			t.Fatalf("GetValidation failed: %v", err)
		}
		if validation.ID != created.ID {
			t.Errorf("ID = %v, want %v", validation.ID, created.ID)
		}
	})

	t.Run("get non-existent validation", func(t *testing.T) {
		_, err := service.GetValidation(ctx, "org-1", "non-existent")
		if !errors.Is(err, ErrValidationNotFound) {
			t.Errorf("Expected ErrValidationNotFound, got %v", err)
		}
	})
}

func TestModelValidationService_UpdateValidation(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create a validation first
	req := &CreateValidationRequest{
		SystemID:       "update-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Test",
		Recommendation: "conditional",
	}
	created, _ := service.CreateValidation(ctx, "org-1", req)

	t.Run("update recommendation", func(t *testing.T) {
		newRec := "approve"
		updateReq := &UpdateValidationRequest{
			Recommendation: &newRec,
		}

		updated, err := service.UpdateValidation(ctx, "org-1", created.ID, updateReq)
		if err != nil {
			t.Fatalf("UpdateValidation failed: %v", err)
		}
		if updated.Recommendation != ValidationRecommendationApprove {
			t.Errorf("Recommendation = %v, want approve", updated.Recommendation)
		}
	})

	t.Run("add findings", func(t *testing.T) {
		findings := []ValidationFinding{
			{Category: "accuracy", Severity: "low", Title: "Minor accuracy issue"},
		}
		updateReq := &UpdateValidationRequest{
			Findings: findings,
		}

		updated, err := service.UpdateValidation(ctx, "org-1", created.ID, updateReq)
		if err != nil {
			t.Fatalf("UpdateValidation failed: %v", err)
		}
		if len(updated.Findings) != 1 {
			t.Errorf("Findings length = %v, want 1", len(updated.Findings))
		}
		if updated.Findings[0].ID == "" {
			t.Error("Expected finding ID to be generated")
		}
	})

	t.Run("nil request fails", func(t *testing.T) {
		_, err := service.UpdateValidation(ctx, "org-1", created.ID, nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
	})

	t.Run("invalid recommendation fails", func(t *testing.T) {
		invalidRec := "invalid"
		updateReq := &UpdateValidationRequest{
			Recommendation: &invalidRec,
		}

		_, err := service.UpdateValidation(ctx, "org-1", created.ID, updateReq)
		if err == nil {
			t.Error("Expected error for invalid recommendation")
		}
	})
}

func TestModelValidationService_DeleteValidation(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create a validation first
	req := &CreateValidationRequest{
		SystemID:       "delete-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Test",
		Recommendation: "approve",
	}
	created, _ := service.CreateValidation(ctx, "org-1", req)

	t.Run("delete existing validation", func(t *testing.T) {
		err := service.DeleteValidation(ctx, "org-1", created.ID)
		if err != nil {
			t.Fatalf("DeleteValidation failed: %v", err)
		}

		// Verify it's deleted
		_, err = service.GetValidation(ctx, "org-1", created.ID)
		if !errors.Is(err, ErrValidationNotFound) {
			t.Error("Expected validation to be deleted")
		}
	})

	t.Run("delete non-existent validation", func(t *testing.T) {
		err := service.DeleteValidation(ctx, "org-1", "non-existent")
		if !errors.Is(err, ErrValidationNotFound) {
			t.Errorf("Expected ErrValidationNotFound, got %v", err)
		}
	})
}

func TestModelValidationService_ListValidations(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create multiple validations
	validations := []CreateValidationRequest{
		{SystemID: "sys-1", ValidationType: "development", ValidatorType: "internal", ValidatorName: "Team A", Recommendation: "approve"},
		{SystemID: "sys-1", ValidationType: "independent", ValidatorType: "external_auditor", ValidatorName: "KPMG", Recommendation: "conditional"},
		{SystemID: "sys-2", ValidationType: "development", ValidatorType: "internal", ValidatorName: "Team B", Recommendation: "approve"},
	}
	for _, req := range validations {
		service.CreateValidation(ctx, "org-1", &req)
	}

	t.Run("list all validations", func(t *testing.T) {
		result, total, err := service.ListValidations(ctx, "org-1", nil)
		if err != nil {
			t.Fatalf("ListValidations failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Total = %v, want 3", total)
		}
		if len(result) != 3 {
			t.Errorf("Result length = %v, want 3", len(result))
		}
	})

	t.Run("filter by system", func(t *testing.T) {
		params := &ListValidationsParams{SystemID: "sys-1"}
		result, total, err := service.ListValidations(ctx, "org-1", params)
		if err != nil {
			t.Fatalf("ListValidations failed: %v", err)
		}
		if total != 2 {
			t.Errorf("Total = %v, want 2", total)
		}
		if len(result) != 2 {
			t.Errorf("Result length = %v, want 2", len(result))
		}
	})

	t.Run("filter by validation type", func(t *testing.T) {
		params := &ListValidationsParams{ValidationType: "development"}
		result, total, err := service.ListValidations(ctx, "org-1", params)
		if err != nil {
			t.Fatalf("ListValidations failed: %v", err)
		}
		if total != 2 {
			t.Errorf("Total = %v, want 2", total)
		}
		if len(result) != 2 {
			t.Errorf("Result length = %v, want 2", len(result))
		}
	})
}

func TestModelValidationService_GetLatestValidation(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create validations with different dates
	now := time.Now().UTC()
	older := now.Add(-24 * time.Hour)

	// Create older validation
	olderReq := &CreateValidationRequest{
		SystemID:       "latest-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Team A",
		Recommendation: "conditional",
		ValidationDate: &older,
	}
	service.CreateValidation(ctx, "org-1", olderReq)

	// Create newer validation
	newerReq := &CreateValidationRequest{
		SystemID:       "latest-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Team A",
		Recommendation: "approve",
		ValidationDate: &now,
	}
	service.CreateValidation(ctx, "org-1", newerReq)

	t.Run("get latest validation", func(t *testing.T) {
		latest, err := service.GetLatestValidation(ctx, "org-1", "latest-test-sys", ValidationTypeDevelopment)
		if err != nil {
			t.Fatalf("GetLatestValidation failed: %v", err)
		}
		if latest.Recommendation != ValidationRecommendationApprove {
			t.Errorf("Recommendation = %v, want approve (latest)", latest.Recommendation)
		}
	})

	t.Run("no validation found", func(t *testing.T) {
		_, err := service.GetLatestValidation(ctx, "org-1", "non-existent-sys", ValidationTypeDevelopment)
		if !errors.Is(err, ErrValidationNotFound) {
			t.Errorf("Expected ErrValidationNotFound, got %v", err)
		}
	})
}

func TestModelValidationService_AddFinding(t *testing.T) {
	repo := NewMockModelValidationRepository()
	service := NewModelValidationService(repo, nil)
	ctx := context.Background()

	// Create a validation first
	req := &CreateValidationRequest{
		SystemID:       "finding-test-sys",
		ValidationType: "development",
		ValidatorType:  "internal",
		ValidatorName:  "Test",
		Recommendation: "approve",
	}
	created, _ := service.CreateValidation(ctx, "org-1", req)

	t.Run("add finding", func(t *testing.T) {
		finding := &ValidationFinding{
			Category:    "bias",
			Severity:    "high",
			Title:       "Gender bias detected",
			Description: "Model shows 10% higher rejection rate for female applicants",
			Impact:      "Potential regulatory violation",
			Remediation: "Retrain with balanced dataset",
		}

		updated, err := service.AddFinding(ctx, "org-1", created.ID, finding)
		if err != nil {
			t.Fatalf("AddFinding failed: %v", err)
		}
		if len(updated.Findings) != 1 {
			t.Errorf("Findings length = %v, want 1", len(updated.Findings))
		}
		if updated.Findings[0].ID == "" {
			t.Error("Expected finding ID to be generated")
		}
		if updated.Findings[0].Category != "bias" {
			t.Errorf("Finding category = %v, want bias", updated.Findings[0].Category)
		}
	})

	t.Run("nil finding fails", func(t *testing.T) {
		_, err := service.AddFinding(ctx, "org-1", created.ID, nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Expected ErrInvalidInput, got %v", err)
		}
	})
}
