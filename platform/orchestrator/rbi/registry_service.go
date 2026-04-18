// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// AISystemRegistryService provides business logic for AI system registry operations.
type AISystemRegistryService interface {
	// CreateSystem registers a new AI system.
	CreateSystem(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error)

	// GetSystem retrieves an AI system by ID.
	GetSystem(ctx context.Context, orgID, id string) (*AISystem, error)

	// ListSystems retrieves AI systems with optional filtering.
	ListSystems(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error)

	// UpdateSystem updates an AI system.
	UpdateSystem(ctx context.Context, orgID, id string, req *UpdateAISystemRequest) (*AISystem, error)

	// DeleteSystem soft-deletes an AI system.
	DeleteSystem(ctx context.Context, orgID, id string) error

	// ProcessBoardApproval processes a board approval request.
	ProcessBoardApproval(ctx context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error)

	// GetSystemSummary returns summary statistics.
	GetSystemSummary(ctx context.Context, orgID string) (*AISystemSummary, error)

	// ScheduleValidation schedules the next validation for a system.
	ScheduleValidation(ctx context.Context, orgID, id string, validationDate time.Time) (*AISystem, error)
}

// AISystemRegistryServiceImpl implements AISystemRegistryService.
type AISystemRegistryServiceImpl struct {
	repo AISystemRepository
}

// NewAISystemRegistryService creates a new AI system registry service.
func NewAISystemRegistryService(repo AISystemRepository) *AISystemRegistryServiceImpl {
	return &AISystemRegistryServiceImpl{repo: repo}
}

// CreateSystem registers a new AI system.
func (s *AISystemRegistryServiceImpl) CreateSystem(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate required fields
	if req.SystemID == "" {
		return nil, fmt.Errorf("%w: system_id is required", ErrInvalidInput)
	}
	if req.SystemName == "" {
		return nil, fmt.Errorf("%w: system_name is required", ErrInvalidInput)
	}
	if req.RiskCategory == "" {
		return nil, fmt.Errorf("%w: risk_category is required", ErrInvalidInput)
	}

	// Validate risk category
	riskCategory := RiskCategory(req.RiskCategory)
	if !riskCategory.Valid() {
		return nil, fmt.Errorf("%w: invalid risk_category", ErrInvalidInput)
	}

	// Check if system already exists
	existing, err := s.repo.GetBySystemID(ctx, orgID, req.SystemID)
	if err != nil && !errors.Is(err, ErrSystemNotFound) {
		return nil, fmt.Errorf("check existing system: %w", err)
	}
	if existing != nil {
		return nil, ErrSystemAlreadyExists
	}

	// Build system object
	system := &AISystem{
		OrgID:                   orgID,
		SystemID:                req.SystemID,
		SystemName:              req.SystemName,
		Version:                 req.Version,
		Description:             req.Description,
		RiskCategory:            riskCategory,
		DeploymentStatus:        DeploymentStatusDevelopment,
		ModelType:               req.ModelType,
		ModelProvider:           req.ModelProvider,
		UseCase:                 req.UseCase,
		UseCaseDescription:      req.UseCaseDescription,
		DataSources:             req.DataSources,
		SensitiveDataCategories: req.SensitiveDataCategories,
		DataResidency:           req.DataResidency,
		OwnerID:                 req.OwnerID,
		OwnerName:               req.OwnerName,
		OwnerDepartment:         req.OwnerDepartment,
		OwnerEmail:              req.OwnerEmail,
		ValidationFrequencyDays: req.ValidationFrequencyDays,
		Tags:                    req.Tags,
		Metadata:                req.Metadata,
	}

	// Set validation schedule if frequency is provided
	if req.ValidationFrequencyDays > 0 {
		nextDue := time.Now().UTC().Add(time.Duration(req.ValidationFrequencyDays) * 24 * time.Hour)
		system.NextValidationDue = &nextDue
	}

	// Create the system
	if err := s.repo.Create(ctx, system); err != nil {
		return nil, err
	}

	log.Printf("[RBI Registry] Created AI system %s (%s) for org %s, risk=%s",
		system.ID, system.SystemID, orgID, system.RiskCategory)

	return system, nil
}

// GetSystem retrieves an AI system by ID.
func (s *AISystemRegistryServiceImpl) GetSystem(ctx context.Context, orgID, id string) (*AISystem, error) {
	return s.repo.Get(ctx, orgID, id)
}

// ListSystems retrieves AI systems with optional filtering.
func (s *AISystemRegistryServiceImpl) ListSystems(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// UpdateSystem updates an AI system.
func (s *AISystemRegistryServiceImpl) UpdateSystem(ctx context.Context, orgID, id string, req *UpdateAISystemRequest) (*AISystem, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Get existing system
	system, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.SystemName != nil {
		system.SystemName = *req.SystemName
	}
	if req.Version != nil {
		system.Version = *req.Version
	}
	if req.Description != nil {
		system.Description = *req.Description
	}
	if req.RiskCategory != nil {
		riskCategory := RiskCategory(*req.RiskCategory)
		if !riskCategory.Valid() {
			return nil, fmt.Errorf("%w: invalid risk_category", ErrInvalidInput)
		}
		system.RiskCategory = riskCategory

		// Update board approval requirements if risk changes to high
		if riskCategory == RiskCategoryHigh && !system.BoardApprovalRequired {
			system.BoardApprovalRequired = true
			system.BoardApprovalStatus = BoardApprovalPending
			log.Printf("[RBI Registry] System %s elevated to high risk, board approval now required", id)
		}
	}
	if req.DeploymentStatus != nil {
		deploymentStatus := DeploymentStatus(*req.DeploymentStatus)
		if !deploymentStatus.Valid() {
			return nil, fmt.Errorf("%w: invalid deployment_status", ErrInvalidInput)
		}
		system.DeploymentStatus = deploymentStatus

		// If moving to production, verify board approval for high-risk systems
		if deploymentStatus == DeploymentStatusProduction &&
			system.BoardApprovalRequired &&
			system.BoardApprovalStatus != BoardApprovalApproved {
			return nil, fmt.Errorf("%w: high-risk system requires board approval before production deployment", ErrInvalidInput)
		}

		// Track deprecation time
		if deploymentStatus == DeploymentStatusDeprecated {
			now := time.Now().UTC()
			system.DeprecatedAt = &now
		}
	}
	if req.ModelType != nil {
		system.ModelType = *req.ModelType
	}
	if req.ModelProvider != nil {
		system.ModelProvider = *req.ModelProvider
	}
	if req.UseCase != nil {
		system.UseCase = *req.UseCase
	}
	if req.UseCaseDescription != nil {
		system.UseCaseDescription = *req.UseCaseDescription
	}
	if req.DataSources != nil {
		system.DataSources = req.DataSources
	}
	if req.SensitiveDataCategories != nil {
		system.SensitiveDataCategories = req.SensitiveDataCategories
	}
	if req.DataResidency != nil {
		system.DataResidency = *req.DataResidency
	}
	if req.OwnerID != nil {
		system.OwnerID = *req.OwnerID
	}
	if req.OwnerName != nil {
		system.OwnerName = *req.OwnerName
	}
	if req.OwnerDepartment != nil {
		system.OwnerDepartment = *req.OwnerDepartment
	}
	if req.OwnerEmail != nil {
		system.OwnerEmail = *req.OwnerEmail
	}
	if req.ValidationFrequencyDays != nil {
		system.ValidationFrequencyDays = *req.ValidationFrequencyDays
	}
	if req.Tags != nil {
		system.Tags = req.Tags
	}
	if req.Metadata != nil {
		system.Metadata = req.Metadata
	}

	// Update the system
	if err := s.repo.Update(ctx, system); err != nil {
		return nil, err
	}

	log.Printf("[RBI Registry] Updated AI system %s for org %s", id, orgID)

	return system, nil
}

// DeleteSystem soft-deletes an AI system.
func (s *AISystemRegistryServiceImpl) DeleteSystem(ctx context.Context, orgID, id string) error {
	if err := s.repo.Delete(ctx, orgID, id); err != nil {
		return err
	}

	log.Printf("[RBI Registry] Deleted (deprecated) AI system %s for org %s", id, orgID)
	return nil
}

// ProcessBoardApproval processes a board approval request.
func (s *AISystemRegistryServiceImpl) ProcessBoardApproval(ctx context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate action
	validActions := map[string]BoardApprovalStatus{
		"approve": BoardApprovalApproved,
		"reject":  BoardApprovalRejected,
		"revoke":  BoardApprovalRevoked,
	}

	newStatus, valid := validActions[req.Action]
	if !valid {
		return nil, fmt.Errorf("%w: invalid action, must be approve, reject, or revoke", ErrInvalidInput)
	}

	// Get existing system
	system, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Validate the approval is applicable
	if !system.BoardApprovalRequired {
		return nil, fmt.Errorf("%w: system does not require board approval", ErrInvalidInput)
	}

	// Update approval status
	now := time.Now().UTC()
	system.BoardApprovalStatus = newStatus
	system.BoardApprovalDate = &now
	system.BoardApprovalReference = req.Reference
	system.BoardApproverName = req.Approver
	system.BoardApprovalNotes = req.Notes

	// Update the system
	if err := s.repo.Update(ctx, system); err != nil {
		return nil, err
	}

	log.Printf("[RBI Registry] Board approval %s for system %s by %s, org %s",
		req.Action, id, req.Approver, orgID)

	return system, nil
}

// GetSystemSummary returns summary statistics.
func (s *AISystemRegistryServiceImpl) GetSystemSummary(ctx context.Context, orgID string) (*AISystemSummary, error) {
	return s.repo.GetSummary(ctx, orgID)
}

// ScheduleValidation schedules the next validation for a system.
func (s *AISystemRegistryServiceImpl) ScheduleValidation(ctx context.Context, orgID, id string, validationDate time.Time) (*AISystem, error) {
	// Get existing system
	system, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	// Update last validation date
	system.LastValidationDate = &validationDate

	// Calculate next validation due based on frequency
	if system.ValidationFrequencyDays > 0 {
		nextDue := validationDate.Add(time.Duration(system.ValidationFrequencyDays) * 24 * time.Hour)
		system.NextValidationDue = &nextDue
	}

	// Update the system
	if err := s.repo.Update(ctx, system); err != nil {
		return nil, err
	}

	log.Printf("[RBI Registry] Updated validation schedule for system %s, next due: %v",
		id, system.NextValidationDue)

	return system, nil
}
