// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
)

// ModelValidationService provides business logic for model validation operations.
type ModelValidationService interface {
	CreateValidation(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error)
	GetValidation(ctx context.Context, orgID, id string) (*ModelValidation, error)
	ListValidations(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error)
	UpdateValidation(ctx context.Context, orgID, id string, req *UpdateValidationRequest) (*ModelValidation, error)
	DeleteValidation(ctx context.Context, orgID, id string) error
	GetLatestValidation(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error)
	AddFinding(ctx context.Context, orgID, validationID string, finding *ValidationFinding) (*ModelValidation, error)
}

// CreateValidationRequest is the request to create a validation.
type CreateValidationRequest struct {
	SystemID              string                 `json:"system_id" validate:"required"`
	ValidationType        string                 `json:"validation_type" validate:"required"`
	ValidatorType         string                 `json:"validator_type" validate:"required"`
	ValidatorName         string                 `json:"validator_name" validate:"required"`
	ValidatorOrganization string                 `json:"validator_organization,omitempty"`
	ValidatorCredentials  string                 `json:"validator_credentials,omitempty"`
	ValidationDate        *time.Time             `json:"validation_date,omitempty"`
	ValidationPeriodStart *time.Time             `json:"validation_period_start,omitempty"`
	ValidationPeriodEnd   *time.Time             `json:"validation_period_end,omitempty"`
	DatasetDescription    string                 `json:"dataset_description,omitempty"`
	DatasetSize           int                    `json:"dataset_size,omitempty"`
	DatasetCharacteristics map[string]interface{} `json:"dataset_characteristics,omitempty"`
	Methodology           string                 `json:"methodology,omitempty"`
	TestScenarios         []string               `json:"test_scenarios,omitempty"`
	Findings              []ValidationFinding    `json:"findings,omitempty"`
	AccuracyMetrics       map[string]float64     `json:"accuracy_metrics,omitempty"`
	BiasAssessment        map[string]float64     `json:"bias_assessment,omitempty"`
	BiasCategoriesTested  []string               `json:"bias_categories_tested,omitempty"`
	StressTestResults     map[string]interface{} `json:"stress_test_results,omitempty"`
	StressTestPassed      *bool                  `json:"stress_test_passed,omitempty"`
	Recommendation        string                 `json:"recommendation" validate:"required"`
	Conditions            string                 `json:"conditions,omitempty"`
	NextReviewDate        *time.Time             `json:"next_review_date,omitempty"`
	RemediationRequired   bool                   `json:"remediation_required"`
	RemediationDeadline   *time.Time             `json:"remediation_deadline,omitempty"`
	ReportFilePath        string                 `json:"report_file_path,omitempty"`
	ReportFileChecksum    string                 `json:"report_file_checksum,omitempty"`
}

// UpdateValidationRequest is the request to update a validation.
type UpdateValidationRequest struct {
	Findings            []ValidationFinding    `json:"findings,omitempty"`
	AccuracyMetrics     map[string]float64     `json:"accuracy_metrics,omitempty"`
	BiasAssessment      map[string]float64     `json:"bias_assessment,omitempty"`
	StressTestResults   map[string]interface{} `json:"stress_test_results,omitempty"`
	StressTestPassed    *bool                  `json:"stress_test_passed,omitempty"`
	Recommendation      *string                `json:"recommendation,omitempty"`
	Conditions          *string                `json:"conditions,omitempty"`
	NextReviewDate      *time.Time             `json:"next_review_date,omitempty"`
	RemediationRequired *bool                  `json:"remediation_required,omitempty"`
	RemediationDeadline *time.Time             `json:"remediation_deadline,omitempty"`
	ReportFilePath      *string                `json:"report_file_path,omitempty"`
	ReportFileChecksum  *string                `json:"report_file_checksum,omitempty"`
}

// ModelValidationServiceImpl implements ModelValidationService.
type ModelValidationServiceImpl struct {
	repo       ModelValidationRepository
	systemRepo AISystemRepository
}

// NewModelValidationService creates a new validation service.
func NewModelValidationService(repo ModelValidationRepository, systemRepo AISystemRepository) *ModelValidationServiceImpl {
	return &ModelValidationServiceImpl{
		repo:       repo,
		systemRepo: systemRepo,
	}
}

// CreateValidation creates a new validation record.
func (s *ModelValidationServiceImpl) CreateValidation(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate required fields
	if req.SystemID == "" {
		return nil, fmt.Errorf("%w: system_id is required", ErrInvalidInput)
	}
	if req.ValidationType == "" {
		return nil, fmt.Errorf("%w: validation_type is required", ErrInvalidInput)
	}
	if req.ValidatorType == "" {
		return nil, fmt.Errorf("%w: validator_type is required", ErrInvalidInput)
	}
	if req.ValidatorName == "" {
		return nil, fmt.Errorf("%w: validator_name is required", ErrInvalidInput)
	}
	if req.Recommendation == "" {
		return nil, fmt.Errorf("%w: recommendation is required", ErrInvalidInput)
	}

	// Validate enums
	validationType := ValidationType(req.ValidationType)
	if !validationType.Valid() {
		return nil, fmt.Errorf("%w: invalid validation_type", ErrInvalidInput)
	}
	validatorType := ValidatorType(req.ValidatorType)
	if !validatorType.Valid() {
		return nil, fmt.Errorf("%w: invalid validator_type", ErrInvalidInput)
	}
	recommendation := ValidationRecommendation(req.Recommendation)
	if !recommendation.Valid() {
		return nil, fmt.Errorf("%w: invalid recommendation", ErrInvalidInput)
	}

	// Verify system exists (if system repo is available)
	if s.systemRepo != nil {
		_, err := s.systemRepo.GetBySystemID(ctx, orgID, req.SystemID)
		if err != nil {
			return nil, fmt.Errorf("system not found: %w", err)
		}
	}

	// Build validation object
	validationDate := time.Now().UTC()
	if req.ValidationDate != nil {
		validationDate = *req.ValidationDate
	}

	validation := &ModelValidation{
		OrgID:                  orgID,
		SystemID:               req.SystemID,
		ValidationType:         validationType,
		ValidatorType:          validatorType,
		ValidatorName:          req.ValidatorName,
		ValidatorOrganization:  req.ValidatorOrganization,
		ValidatorCredentials:   req.ValidatorCredentials,
		ValidationDate:         validationDate,
		ValidationPeriodStart:  req.ValidationPeriodStart,
		ValidationPeriodEnd:    req.ValidationPeriodEnd,
		DatasetDescription:     req.DatasetDescription,
		DatasetSize:            req.DatasetSize,
		DatasetCharacteristics: req.DatasetCharacteristics,
		Methodology:            req.Methodology,
		TestScenarios:          req.TestScenarios,
		Findings:               req.Findings,
		AccuracyMetrics:        req.AccuracyMetrics,
		BiasAssessment:         req.BiasAssessment,
		BiasCategoriesTested:   req.BiasCategoriesTested,
		StressTestResults:      req.StressTestResults,
		StressTestPassed:       req.StressTestPassed,
		Recommendation:         recommendation,
		Conditions:             req.Conditions,
		NextReviewDate:         req.NextReviewDate,
		RemediationRequired:    req.RemediationRequired,
		RemediationDeadline:    req.RemediationDeadline,
		ReportFilePath:         req.ReportFilePath,
		ReportFileChecksum:     req.ReportFileChecksum,
	}

	// Generate IDs for findings that don't have them
	for i := range validation.Findings {
		if validation.Findings[i].ID == "" {
			validation.Findings[i].ID = uuid.New().String()
		}
	}

	if err := s.repo.Create(ctx, validation); err != nil {
		return nil, err
	}

	// Update system's last validation date if system repo available
	if s.systemRepo != nil {
		system, err := s.systemRepo.GetBySystemID(ctx, orgID, req.SystemID)
		if err == nil {
			system.LastValidationDate = &validationDate
			if system.ValidationFrequencyDays > 0 {
				nextDue := validationDate.Add(time.Duration(system.ValidationFrequencyDays) * 24 * time.Hour)
				system.NextValidationDue = &nextDue
			}
			s.systemRepo.Update(ctx, system)
		}
	}

	log.Printf("[RBI Validation] Created validation %s for system %s, type=%s, recommendation=%s",
		validation.ID, req.SystemID, validationType, recommendation)

	return validation, nil
}

// GetValidation retrieves a validation by ID.
func (s *ModelValidationServiceImpl) GetValidation(ctx context.Context, orgID, id string) (*ModelValidation, error) {
	return s.repo.Get(ctx, orgID, id)
}

// ListValidations retrieves validations with optional filtering.
func (s *ModelValidationServiceImpl) ListValidations(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// UpdateValidation updates a validation record.
func (s *ModelValidationServiceImpl) UpdateValidation(ctx context.Context, orgID, id string, req *UpdateValidationRequest) (*ModelValidation, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	validation, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Findings != nil {
		// Generate IDs for new findings
		for i := range req.Findings {
			if req.Findings[i].ID == "" {
				req.Findings[i].ID = uuid.New().String()
			}
		}
		validation.Findings = req.Findings
	}
	if req.AccuracyMetrics != nil {
		validation.AccuracyMetrics = req.AccuracyMetrics
	}
	if req.BiasAssessment != nil {
		validation.BiasAssessment = req.BiasAssessment
	}
	if req.StressTestResults != nil {
		validation.StressTestResults = req.StressTestResults
	}
	if req.StressTestPassed != nil {
		validation.StressTestPassed = req.StressTestPassed
	}
	if req.Recommendation != nil {
		rec := ValidationRecommendation(*req.Recommendation)
		if !rec.Valid() {
			return nil, fmt.Errorf("%w: invalid recommendation", ErrInvalidInput)
		}
		validation.Recommendation = rec
	}
	if req.Conditions != nil {
		validation.Conditions = *req.Conditions
	}
	if req.NextReviewDate != nil {
		validation.NextReviewDate = req.NextReviewDate
	}
	if req.RemediationRequired != nil {
		validation.RemediationRequired = *req.RemediationRequired
	}
	if req.RemediationDeadline != nil {
		validation.RemediationDeadline = req.RemediationDeadline
	}
	if req.ReportFilePath != nil {
		validation.ReportFilePath = *req.ReportFilePath
	}
	if req.ReportFileChecksum != nil {
		validation.ReportFileChecksum = *req.ReportFileChecksum
	}

	if err := s.repo.Update(ctx, validation); err != nil {
		return nil, err
	}

	log.Printf("[RBI Validation] Updated validation %s", id)

	return validation, nil
}

// DeleteValidation deletes a validation record.
func (s *ModelValidationServiceImpl) DeleteValidation(ctx context.Context, orgID, id string) error {
	if err := s.repo.Delete(ctx, orgID, id); err != nil {
		return err
	}
	log.Printf("[RBI Validation] Deleted validation %s", id)
	return nil
}

// GetLatestValidation gets the latest validation of a specific type for a system.
func (s *ModelValidationServiceImpl) GetLatestValidation(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error) {
	return s.repo.GetLatestBySystem(ctx, orgID, systemID, validationType)
}

// AddFinding adds a finding to an existing validation.
func (s *ModelValidationServiceImpl) AddFinding(ctx context.Context, orgID, validationID string, finding *ValidationFinding) (*ModelValidation, error) {
	if finding == nil {
		return nil, ErrInvalidInput
	}

	validation, err := s.repo.Get(ctx, orgID, validationID)
	if err != nil {
		return nil, err
	}

	// Generate ID if not provided
	if finding.ID == "" {
		finding.ID = uuid.New().String()
	}

	validation.Findings = append(validation.Findings, *finding)

	if err := s.repo.Update(ctx, validation); err != nil {
		return nil, err
	}

	log.Printf("[RBI Validation] Added finding %s to validation %s", finding.ID, validationID)

	return validation, nil
}
