// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"fmt"
	"log"
	"time"
)

// KillSwitchService provides business logic for kill switch operations.
type KillSwitchService interface {
	CreateKillSwitch(ctx context.Context, orgID string, req *CreateKillSwitchRequest) (*KillSwitch, error)
	GetKillSwitch(ctx context.Context, orgID, id string) (*KillSwitch, error)
	ListKillSwitches(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error)
	ListActiveKillSwitches(ctx context.Context, orgID string) ([]*KillSwitch, error)
	Activate(ctx context.Context, orgID, id string, req *ActivateKillSwitchRequest) (*KillSwitch, error)
	Deactivate(ctx context.Context, orgID, id string, req *DeactivateKillSwitchRequest) (*KillSwitch, error)
	DeleteKillSwitch(ctx context.Context, orgID, id string) error
	CheckKillSwitch(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitchCheckResult, error)
	GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error)
	AutoTrigger(ctx context.Context, orgID, systemID, reason string) (*KillSwitch, error)
}

// CreateKillSwitchRequest is the request to create a kill switch.
type CreateKillSwitchRequest struct {
	Scope            string                 `json:"scope" validate:"required"`
	SystemID         string                 `json:"system_id,omitempty"`
	TargetIdentifier string                 `json:"target_identifier,omitempty"`
	FallbackBehavior string                 `json:"fallback_behavior" validate:"required"`
	FallbackConfig   map[string]interface{} `json:"fallback_config,omitempty"`
	TriggerCondition string                 `json:"trigger_condition,omitempty"`
	TriggerThreshold map[string]interface{} `json:"trigger_threshold,omitempty"`
}

// ActivateKillSwitchRequest is the request to activate a kill switch.
type ActivateKillSwitchRequest struct {
	ActorID     string `json:"actor_id" validate:"required"`
	ActorEmail  string `json:"actor_email,omitempty"`
	ActorRole   string `json:"actor_role,omitempty"`
	ActorIP     string `json:"actor_ip,omitempty"`
	Reason      string `json:"reason" validate:"required"`
}

// DeactivateKillSwitchRequest is the request to deactivate a kill switch.
type DeactivateKillSwitchRequest struct {
	ActorID    string `json:"actor_id" validate:"required"`
	ActorEmail string `json:"actor_email,omitempty"`
	ActorRole  string `json:"actor_role,omitempty"`
	ActorIP    string `json:"actor_ip,omitempty"`
	Reason     string `json:"reason" validate:"required"`
}

// KillSwitchCheckResult represents the result of a kill switch check.
type KillSwitchCheckResult struct {
	IsBlocked        bool              `json:"is_blocked"`
	KillSwitch       *KillSwitch       `json:"kill_switch,omitempty"`
	FallbackBehavior FallbackBehavior  `json:"fallback_behavior,omitempty"`
	FallbackConfig   map[string]interface{} `json:"fallback_config,omitempty"`
	Message          string            `json:"message"`
}

// KillSwitchServiceImpl implements KillSwitchService.
type KillSwitchServiceImpl struct {
	repo       KillSwitchRepository
	systemRepo AISystemRepository
}

// NewKillSwitchService creates a new kill switch service.
func NewKillSwitchService(repo KillSwitchRepository, systemRepo AISystemRepository) *KillSwitchServiceImpl {
	return &KillSwitchServiceImpl{
		repo:       repo,
		systemRepo: systemRepo,
	}
}

// CreateKillSwitch creates a new kill switch.
func (s *KillSwitchServiceImpl) CreateKillSwitch(ctx context.Context, orgID string, req *CreateKillSwitchRequest) (*KillSwitch, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}

	// Validate required fields
	if req.Scope == "" {
		return nil, fmt.Errorf("%w: scope is required", ErrInvalidInput)
	}
	if req.FallbackBehavior == "" {
		return nil, fmt.Errorf("%w: fallback_behavior is required", ErrInvalidInput)
	}

	// Validate enums
	scope := KillSwitchScope(req.Scope)
	if !scope.Valid() {
		return nil, fmt.Errorf("%w: invalid scope", ErrInvalidInput)
	}
	fallbackBehavior := FallbackBehavior(req.FallbackBehavior)
	if !fallbackBehavior.Valid() {
		return nil, fmt.Errorf("%w: invalid fallback_behavior", ErrInvalidInput)
	}

	// Validate scope-specific requirements
	if scope == KillSwitchScopeSystem || scope == KillSwitchScopeModel ||
	   scope == KillSwitchScopeFeature || scope == KillSwitchScopeUseCase {
		if req.SystemID == "" {
			return nil, fmt.Errorf("%w: system_id is required for scope %s", ErrInvalidInput, scope)
		}
	}
	if scope == KillSwitchScopeModel || scope == KillSwitchScopeFeature || scope == KillSwitchScopeUseCase {
		if req.TargetIdentifier == "" {
			return nil, fmt.Errorf("%w: target_identifier is required for scope %s", ErrInvalidInput, scope)
		}
	}

	// Verify system exists if specified
	if req.SystemID != "" && s.systemRepo != nil {
		_, err := s.systemRepo.GetBySystemID(ctx, orgID, req.SystemID)
		if err != nil {
			return nil, fmt.Errorf("system not found: %w", err)
		}
	}

	// Check if kill switch already exists for this scope
	existing, err := s.repo.GetByScope(ctx, orgID, scope, req.SystemID, req.TargetIdentifier)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("%w: kill switch already exists for this scope", ErrInvalidInput)
	}

	ks := &KillSwitch{
		OrgID:            orgID,
		Scope:            scope,
		SystemID:         req.SystemID,
		TargetIdentifier: req.TargetIdentifier,
		IsActive:         false, // Not active by default
		FallbackBehavior: fallbackBehavior,
		FallbackConfig:   req.FallbackConfig,
		TriggerCondition: req.TriggerCondition,
		TriggerThreshold: req.TriggerThreshold,
	}

	if err := s.repo.Create(ctx, ks); err != nil {
		return nil, err
	}

	// Add history entry
	s.repo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:        orgID,
		KillSwitchID: ks.ID,
		Action:       KillSwitchActionCreated,
		ActorID:      "system",
		NewState:     map[string]interface{}{"scope": scope, "is_active": false},
	})

	log.Printf("[RBI KillSwitch] Created kill switch %s scope=%s system=%s",
		ks.ID, scope, req.SystemID)

	return ks, nil
}

// GetKillSwitch retrieves a kill switch by ID.
func (s *KillSwitchServiceImpl) GetKillSwitch(ctx context.Context, orgID, id string) (*KillSwitch, error) {
	return s.repo.Get(ctx, orgID, id)
}

// ListKillSwitches retrieves kill switches with optional filtering.
func (s *KillSwitchServiceImpl) ListKillSwitches(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	return s.repo.List(ctx, orgID, params)
}

// ListActiveKillSwitches retrieves all active kill switches.
func (s *KillSwitchServiceImpl) ListActiveKillSwitches(ctx context.Context, orgID string) ([]*KillSwitch, error) {
	return s.repo.ListActive(ctx, orgID)
}

// Activate activates a kill switch.
func (s *KillSwitchServiceImpl) Activate(ctx context.Context, orgID, id string, req *ActivateKillSwitchRequest) (*KillSwitch, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}
	if req.ActorID == "" {
		return nil, fmt.Errorf("%w: actor_id is required", ErrInvalidInput)
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}

	ks, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if ks.IsActive {
		return nil, fmt.Errorf("%w: kill switch is already active", ErrInvalidInput)
	}

	// Store previous state for audit
	previousState := map[string]interface{}{
		"is_active": ks.IsActive,
	}

	// Activate
	now := time.Now().UTC()
	ks.IsActive = true
	ks.ActivatedBy = req.ActorID
	ks.ActivatedByEmail = req.ActorEmail
	ks.ActivatedAt = &now
	ks.ActivationReason = req.Reason

	// Clear deactivation fields
	ks.DeactivatedBy = ""
	ks.DeactivatedByEmail = ""
	ks.DeactivatedAt = nil
	ks.DeactivationReason = ""

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, err
	}

	// Add history entry
	s.repo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:         orgID,
		KillSwitchID:  id,
		Action:        KillSwitchActionActivated,
		ActorID:       req.ActorID,
		ActorEmail:    req.ActorEmail,
		ActorRole:     req.ActorRole,
		ActorIP:       req.ActorIP,
		Reason:        req.Reason,
		PreviousState: previousState,
		NewState:      map[string]interface{}{"is_active": true},
	})

	log.Printf("[RBI KillSwitch] ACTIVATED kill switch %s by %s - scope=%s reason=%s",
		id, req.ActorID, ks.Scope, req.Reason)

	return ks, nil
}

// Deactivate deactivates a kill switch.
func (s *KillSwitchServiceImpl) Deactivate(ctx context.Context, orgID, id string, req *DeactivateKillSwitchRequest) (*KillSwitch, error) {
	if req == nil {
		return nil, ErrInvalidInput
	}
	if req.ActorID == "" {
		return nil, fmt.Errorf("%w: actor_id is required", ErrInvalidInput)
	}
	if req.Reason == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}

	ks, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	if !ks.IsActive {
		return nil, fmt.Errorf("%w: kill switch is not active", ErrInvalidInput)
	}

	// Store previous state for audit
	previousState := map[string]interface{}{
		"is_active":         ks.IsActive,
		"activated_by":      ks.ActivatedBy,
		"activation_reason": ks.ActivationReason,
	}

	// Deactivate
	now := time.Now().UTC()
	ks.IsActive = false
	ks.DeactivatedBy = req.ActorID
	ks.DeactivatedByEmail = req.ActorEmail
	ks.DeactivatedAt = &now
	ks.DeactivationReason = req.Reason

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, err
	}

	// Add history entry
	s.repo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:         orgID,
		KillSwitchID:  id,
		Action:        KillSwitchActionDeactivated,
		ActorID:       req.ActorID,
		ActorEmail:    req.ActorEmail,
		ActorRole:     req.ActorRole,
		ActorIP:       req.ActorIP,
		Reason:        req.Reason,
		PreviousState: previousState,
		NewState:      map[string]interface{}{"is_active": false},
	})

	log.Printf("[RBI KillSwitch] DEACTIVATED kill switch %s by %s - scope=%s reason=%s",
		id, req.ActorID, ks.Scope, req.Reason)

	return ks, nil
}

// DeleteKillSwitch deletes a kill switch.
func (s *KillSwitchServiceImpl) DeleteKillSwitch(ctx context.Context, orgID, id string) error {
	ks, err := s.repo.Get(ctx, orgID, id)
	if err != nil {
		return err
	}

	if ks.IsActive {
		return fmt.Errorf("%w: cannot delete active kill switch, deactivate first", ErrInvalidInput)
	}

	// Add history entry before deletion
	s.repo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:        orgID,
		KillSwitchID: id,
		Action:       KillSwitchActionDeleted,
		ActorID:      "system",
		PreviousState: map[string]interface{}{
			"scope":     ks.Scope,
			"system_id": ks.SystemID,
		},
	})

	if err := s.repo.Delete(ctx, orgID, id); err != nil {
		return err
	}

	log.Printf("[RBI KillSwitch] Deleted kill switch %s", id)
	return nil
}

// CheckKillSwitch checks if any active kill switch applies to the given scope.
func (s *KillSwitchServiceImpl) CheckKillSwitch(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitchCheckResult, error) {
	isBlocked, ks, err := s.repo.CheckActive(ctx, orgID, scope, systemID, targetID)
	if err != nil {
		return nil, err
	}

	result := &KillSwitchCheckResult{
		IsBlocked: isBlocked,
	}

	if isBlocked && ks != nil {
		result.KillSwitch = ks
		result.FallbackBehavior = ks.FallbackBehavior
		result.FallbackConfig = ks.FallbackConfig
		result.Message = fmt.Sprintf("Kill switch active: %s (scope: %s)", ks.ActivationReason, ks.Scope)
	} else {
		result.Message = "No active kill switch"
	}

	return result, nil
}

// GetHistory retrieves history entries for a kill switch.
func (s *KillSwitchServiceImpl) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error) {
	return s.repo.GetHistory(ctx, orgID, killSwitchID, limit)
}

// AutoTrigger automatically triggers a kill switch for a system (used by monitoring).
func (s *KillSwitchServiceImpl) AutoTrigger(ctx context.Context, orgID, systemID, reason string) (*KillSwitch, error) {
	// Find system-level kill switch
	ks, err := s.repo.GetByScope(ctx, orgID, KillSwitchScopeSystem, systemID, "")
	if err != nil {
		if err == ErrKillSwitchNotFound {
			// Create a new kill switch if none exists
			ks = &KillSwitch{
				OrgID:            orgID,
				Scope:            KillSwitchScopeSystem,
				SystemID:         systemID,
				FallbackBehavior: FallbackBehaviorBlockAll,
			}
			if err := s.repo.Create(ctx, ks); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	if ks.IsActive {
		// Already active, just return
		return ks, nil
	}

	// Activate with auto-trigger flag
	now := time.Now().UTC()
	ks.IsActive = true
	ks.AutoTriggered = true
	ks.ActivatedBy = "automated_monitoring"
	ks.ActivatedAt = &now
	ks.ActivationReason = reason

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, err
	}

	// Add history entry
	s.repo.AddHistoryEntry(ctx, &KillSwitchHistoryEntry{
		OrgID:        orgID,
		KillSwitchID: ks.ID,
		Action:       KillSwitchActionAutoTriggered,
		ActorID:      "automated_monitoring",
		Reason:       reason,
		NewState:     map[string]interface{}{"is_active": true, "auto_triggered": true},
	})

	log.Printf("[RBI KillSwitch] AUTO-TRIGGERED kill switch %s for system %s - reason=%s",
		ks.ID, systemID, reason)

	return ks, nil
}
