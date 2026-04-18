// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"errors"
	"fmt"
)

// RegistryService provides business logic for AI system registry operations.
type RegistryService struct {
	repo RegistryRepository
}

// NewRegistryService creates a new registry service.
func NewRegistryService(repo RegistryRepository) *RegistryService {
	return &RegistryService{repo: repo}
}

// RegisterSystem registers a new AI system.
func (s *RegistryService) RegisterSystem(ctx context.Context, orgID string, req *CreateRegistryRequest, createdBy string) (*AISystemRegistry, error) {
	// Validate request
	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	// Check for duplicate system_id
	existing, err := s.repo.GetBySystemID(ctx, orgID, req.SystemID)
	if err != nil {
		return nil, fmt.Errorf("failed to check for duplicate: %w", err)
	}
	if existing != nil {
		return nil, errors.New("system with this system_id already exists")
	}

	system := &AISystemRegistry{
		OrgID:                orgID,
		SystemID:             req.SystemID,
		SystemName:           req.SystemName,
		Description:          req.Description,
		UseCase:              req.UseCase,
		Status:               SystemStatusDraft,
		RiskRatingImpact:     req.RiskRatingImpact,
		RiskRatingComplexity: req.RiskRatingComplexity,
		RiskRatingReliance:   req.RiskRatingReliance,
		OwnerTeam:            req.OwnerTeam,
		OwnerEmail:           req.OwnerEmail,
		DataSources:          req.DataSources,
		ModelType:            req.ModelType,
		Version:              req.Version,
		CreatedBy:            createdBy,
	}

	if err := s.repo.Create(ctx, system); err != nil {
		return nil, fmt.Errorf("failed to create system: %w", err)
	}

	return system, nil
}

// GetSystem retrieves an AI system by ID.
func (s *RegistryService) GetSystem(ctx context.Context, orgID, id string) (*AISystemRegistry, error) {
	system, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get system: %w", err)
	}
	if system == nil {
		return nil, errors.New("system not found")
	}
	return system, nil
}

// ListSystems lists AI systems for an organization.
func (s *RegistryService) ListSystems(ctx context.Context, orgID string, params ListParams) ([]*AISystemRegistry, error) {
	return s.repo.List(ctx, orgID, params)
}

// UpdateSystem updates an AI system.
func (s *RegistryService) UpdateSystem(ctx context.Context, orgID, id string, req *UpdateRegistryRequest, updatedBy string) (*AISystemRegistry, error) {
	system, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get system: %w", err)
	}
	if system == nil {
		return nil, errors.New("system not found")
	}

	// Apply updates
	if req.SystemName != "" {
		system.SystemName = req.SystemName
	}
	if req.Description != "" {
		system.Description = req.Description
	}
	if req.UseCase != "" && req.UseCase.Valid() {
		system.UseCase = req.UseCase
	}
	if req.Status != "" && req.Status.Valid() {
		system.Status = req.Status
	}
	if req.RiskRatingImpact != nil {
		if *req.RiskRatingImpact < 1 || *req.RiskRatingImpact > 5 {
			return nil, errors.New("risk_rating_impact must be between 1 and 5")
		}
		system.RiskRatingImpact = *req.RiskRatingImpact
	}
	if req.RiskRatingComplexity != nil {
		if *req.RiskRatingComplexity < 1 || *req.RiskRatingComplexity > 5 {
			return nil, errors.New("risk_rating_complexity must be between 1 and 5")
		}
		system.RiskRatingComplexity = *req.RiskRatingComplexity
	}
	if req.RiskRatingReliance != nil {
		if *req.RiskRatingReliance < 1 || *req.RiskRatingReliance > 5 {
			return nil, errors.New("risk_rating_reliance must be between 1 and 5")
		}
		system.RiskRatingReliance = *req.RiskRatingReliance
	}
	if req.OwnerTeam != "" {
		system.OwnerTeam = req.OwnerTeam
	}
	if req.OwnerEmail != "" {
		system.OwnerEmail = req.OwnerEmail
	}
	if req.DataSources != nil {
		system.DataSources = req.DataSources
	}
	if req.ModelType != "" {
		system.ModelType = req.ModelType
	}
	if req.Version != "" {
		system.Version = req.Version
	}

	system.UpdatedBy = updatedBy

	if err := s.repo.Update(ctx, system); err != nil {
		return nil, fmt.Errorf("failed to update system: %w", err)
	}

	return system, nil
}

// DeleteSystem soft-deletes an AI system.
func (s *RegistryService) DeleteSystem(ctx context.Context, orgID, id string) error {
	system, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return fmt.Errorf("failed to get system: %w", err)
	}
	if system == nil {
		return errors.New("system not found")
	}

	return s.repo.Delete(ctx, orgID, id)
}

// GetSummary returns a summary of registered AI systems.
func (s *RegistryService) GetSummary(ctx context.Context, orgID string) (*RegistrySummary, error) {
	return s.repo.GetSummary(ctx, orgID)
}

// ActivateSystem activates a draft system.
func (s *RegistryService) ActivateSystem(ctx context.Context, orgID, id, updatedBy string) (*AISystemRegistry, error) {
	system, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get system: %w", err)
	}
	if system == nil {
		return nil, errors.New("system not found")
	}

	if system.Status != SystemStatusDraft {
		return nil, errors.New("only draft systems can be activated")
	}

	system.Status = SystemStatusActive
	system.UpdatedBy = updatedBy

	if err := s.repo.Update(ctx, system); err != nil {
		return nil, fmt.Errorf("failed to activate system: %w", err)
	}

	return system, nil
}

// SuspendSystem suspends an active system.
func (s *RegistryService) SuspendSystem(ctx context.Context, orgID, id, updatedBy string) (*AISystemRegistry, error) {
	system, err := s.repo.GetByID(ctx, orgID, id)
	if err != nil {
		return nil, fmt.Errorf("failed to get system: %w", err)
	}
	if system == nil {
		return nil, errors.New("system not found")
	}

	if system.Status != SystemStatusActive {
		return nil, errors.New("only active systems can be suspended")
	}

	system.Status = SystemStatusSuspended
	system.UpdatedBy = updatedBy

	if err := s.repo.Update(ctx, system); err != nil {
		return nil, fmt.Errorf("failed to suspend system: %w", err)
	}

	return system, nil
}

// validateCreateRequest validates a create registry request.
func (s *RegistryService) validateCreateRequest(req *CreateRegistryRequest) error {
	if req.SystemID == "" {
		return errors.New("system_id is required")
	}
	if req.SystemName == "" {
		return errors.New("system_name is required")
	}
	if !req.UseCase.Valid() {
		return errors.New("invalid use_case")
	}
	if req.RiskRatingImpact < 1 || req.RiskRatingImpact > 5 {
		return errors.New("risk_rating_impact must be between 1 and 5")
	}
	if req.RiskRatingComplexity < 1 || req.RiskRatingComplexity > 5 {
		return errors.New("risk_rating_complexity must be between 1 and 5")
	}
	if req.RiskRatingReliance < 1 || req.RiskRatingReliance > 5 {
		return errors.New("risk_rating_reliance must be between 1 and 5")
	}
	if req.OwnerTeam == "" {
		return errors.New("owner_team is required")
	}
	if req.OwnerEmail == "" {
		return errors.New("owner_email is required")
	}
	return nil
}
