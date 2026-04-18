// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// KillSwitchService provides business logic for kill switch operations.
type KillSwitchService struct {
	repo             KillSwitchRepository
	defaultBiasThreshold float64
}

// NewKillSwitchService creates a new kill switch service.
func NewKillSwitchService(repo KillSwitchRepository, defaultBiasThreshold float64) *KillSwitchService {
	return &KillSwitchService{
		repo:             repo,
		defaultBiasThreshold: defaultBiasThreshold,
	}
}

// GetKillSwitch retrieves the kill switch for a system.
func (s *KillSwitchService) GetKillSwitch(ctx context.Context, orgID, systemID string) (*KillSwitch, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}
	if ks == nil {
		return nil, errors.New("kill switch not found for this system")
	}
	return ks, nil
}

// GetOrCreateKillSwitch retrieves or creates a kill switch for a system.
func (s *KillSwitchService) GetOrCreateKillSwitch(ctx context.Context, orgID, systemID string) (*KillSwitch, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}

	if ks != nil {
		return ks, nil
	}

	// Create new kill switch with defaults
	ks = &KillSwitch{
		OrgID:              orgID,
		SystemID:           systemID,
		Status:             KillSwitchEnabled,
		AutoTriggerEnabled: true,
		BiasThreshold:      &s.defaultBiasThreshold,
	}

	if err := s.repo.Create(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to create kill switch: %w", err)
	}

	return ks, nil
}

// ConfigureKillSwitch configures the kill switch thresholds.
func (s *KillSwitchService) ConfigureKillSwitch(ctx context.Context, orgID, systemID string, req *ConfigureKillSwitchRequest, configuredBy string) (*KillSwitch, error) {
	ks, err := s.GetOrCreateKillSwitch(ctx, orgID, systemID)
	if err != nil {
		return nil, err
	}

	previousStatus := string(ks.Status)
	ks.AutoTriggerEnabled = req.AutoTriggerEnabled

	if req.AccuracyThreshold != nil {
		if *req.AccuracyThreshold < 0 || *req.AccuracyThreshold > 1 {
			return nil, errors.New("accuracy_threshold must be between 0 and 1")
		}
		ks.AccuracyThreshold = req.AccuracyThreshold
	}
	if req.BiasThreshold != nil {
		if *req.BiasThreshold < 0 || *req.BiasThreshold > 1 {
			return nil, errors.New("bias_threshold must be between 0 and 1")
		}
		ks.BiasThreshold = req.BiasThreshold
	}
	if req.ErrorRateThreshold != nil {
		if *req.ErrorRateThreshold < 0 || *req.ErrorRateThreshold > 1 {
			return nil, errors.New("error_rate_threshold must be between 0 and 1")
		}
		ks.ErrorRateThreshold = req.ErrorRateThreshold
	}
	if req.TriggerConditions != nil {
		ks.TriggerConditions = req.TriggerConditions
	}

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to update kill switch: %w", err)
	}

	// Record history (log but don't fail on error)
	if err := s.repo.RecordHistory(ctx, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "configured",
		PreviousStatus: previousStatus,
		NewStatus:      string(ks.Status),
		Reason:         "Configuration updated",
		PerformedBy:    configuredBy,
	}); err != nil {
		log.Printf("[KillSwitch] Failed to record history for configure: %v", err)
	}

	return ks, nil
}

// TriggerKillSwitch triggers the kill switch for a system.
func (s *KillSwitchService) TriggerKillSwitch(ctx context.Context, orgID, systemID string, req *TriggerKillSwitchRequest, triggeredBy string) (*KillSwitch, error) {
	ks, err := s.GetOrCreateKillSwitch(ctx, orgID, systemID)
	if err != nil {
		return nil, err
	}

	if ks.Status == KillSwitchTriggered {
		return nil, errors.New("kill switch is already triggered")
	}

	if req.Reason == "" {
		return nil, errors.New("reason is required for triggering kill switch")
	}

	previousStatus := string(ks.Status)
	now := time.Now().UTC()

	ks.Status = KillSwitchTriggered
	ks.TriggerReason = req.Reason
	ks.TriggeredAt = &now
	ks.TriggeredBy = triggeredBy

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to trigger kill switch: %w", err)
	}

	// Record history (log but don't fail on error)
	if err := s.repo.RecordHistory(ctx, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "triggered",
		PreviousStatus: previousStatus,
		NewStatus:      string(ks.Status),
		Reason:         req.Reason,
		PerformedBy:    triggeredBy,
	}); err != nil {
		log.Printf("[KillSwitch] Failed to record history for trigger: %v", err)
	}

	return ks, nil
}

// RestoreKillSwitch restores the kill switch (re-enables the system).
func (s *KillSwitchService) RestoreKillSwitch(ctx context.Context, orgID, systemID string, req *RestoreKillSwitchRequest, restoredBy string) (*KillSwitch, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}
	if ks == nil {
		return nil, errors.New("kill switch not found")
	}

	if ks.Status != KillSwitchTriggered {
		return nil, errors.New("kill switch is not currently triggered")
	}

	if req.Reason == "" {
		return nil, errors.New("reason is required for restoring kill switch")
	}

	previousStatus := string(ks.Status)
	now := time.Now().UTC()

	ks.Status = KillSwitchEnabled
	ks.RestoreReason = req.Reason
	ks.RestoredAt = &now
	ks.RestoredBy = restoredBy

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to restore kill switch: %w", err)
	}

	// Record history (log but don't fail on error)
	if err := s.repo.RecordHistory(ctx, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "restored",
		PreviousStatus: previousStatus,
		NewStatus:      string(ks.Status),
		Reason:         req.Reason,
		PerformedBy:    restoredBy,
	}); err != nil {
		log.Printf("[KillSwitch] Failed to record history for restore: %v", err)
	}

	return ks, nil
}

// DisableKillSwitch disables the kill switch (no auto-trigger).
func (s *KillSwitchService) DisableKillSwitch(ctx context.Context, orgID, systemID, disabledBy string) (*KillSwitch, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}
	if ks == nil {
		return nil, errors.New("kill switch not found")
	}

	if ks.Status == KillSwitchDisabled {
		return nil, errors.New("kill switch is already disabled")
	}

	previousStatus := string(ks.Status)
	ks.Status = KillSwitchDisabled

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to disable kill switch: %w", err)
	}

	// Record history (log but don't fail on error)
	if err := s.repo.RecordHistory(ctx, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "disabled",
		PreviousStatus: previousStatus,
		NewStatus:      string(ks.Status),
		Reason:         "Manually disabled",
		PerformedBy:    disabledBy,
	}); err != nil {
		log.Printf("[KillSwitch] Failed to record history for disable: %v", err)
	}

	return ks, nil
}

// EnableKillSwitch enables the kill switch.
func (s *KillSwitchService) EnableKillSwitch(ctx context.Context, orgID, systemID, enabledBy string) (*KillSwitch, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}
	if ks == nil {
		return nil, errors.New("kill switch not found")
	}

	if ks.Status == KillSwitchEnabled {
		return nil, errors.New("kill switch is already enabled")
	}

	previousStatus := string(ks.Status)
	ks.Status = KillSwitchEnabled

	if err := s.repo.Update(ctx, ks); err != nil {
		return nil, fmt.Errorf("failed to enable kill switch: %w", err)
	}

	// Record history (log but don't fail on error)
	if err := s.repo.RecordHistory(ctx, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "enabled",
		PreviousStatus: previousStatus,
		NewStatus:      string(ks.Status),
		Reason:         "Manually enabled",
		PerformedBy:    enabledBy,
	}); err != nil {
		log.Printf("[KillSwitch] Failed to record history for enable: %v", err)
	}

	return ks, nil
}

// GetHistory retrieves kill switch history for a system.
func (s *KillSwitchService) GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*KillSwitchHistory, error) {
	return s.repo.GetHistory(ctx, orgID, systemID, limit)
}

// CheckAndTrigger checks if thresholds are exceeded and auto-triggers if needed.
// This is called by the monitoring system.
func (s *KillSwitchService) CheckAndTrigger(ctx context.Context, orgID, systemID string, metrics map[string]float64) (*KillSwitch, bool, error) {
	ks, err := s.repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get kill switch: %w", err)
	}
	if ks == nil {
		return nil, false, nil // No kill switch configured
	}

	if !ks.AutoTriggerEnabled || ks.Status != KillSwitchEnabled {
		return ks, false, nil
	}

	var triggerReason string

	// Check accuracy threshold
	if ks.AccuracyThreshold != nil {
		if accuracy, ok := metrics["accuracy"]; ok {
			if accuracy < *ks.AccuracyThreshold {
				triggerReason = fmt.Sprintf("Accuracy %.2f%% below threshold %.2f%%",
					accuracy*100, *ks.AccuracyThreshold*100)
			}
		}
	}

	// Check bias threshold
	if ks.BiasThreshold != nil && triggerReason == "" {
		if bias, ok := metrics["bias"]; ok {
			if bias > *ks.BiasThreshold {
				triggerReason = fmt.Sprintf("Bias score %.2f%% exceeds threshold %.2f%%",
					bias*100, *ks.BiasThreshold*100)
			}
		}
	}

	// Check error rate threshold
	if ks.ErrorRateThreshold != nil && triggerReason == "" {
		if errorRate, ok := metrics["error_rate"]; ok {
			if errorRate > *ks.ErrorRateThreshold {
				triggerReason = fmt.Sprintf("Error rate %.2f%% exceeds threshold %.2f%%",
					errorRate*100, *ks.ErrorRateThreshold*100)
			}
		}
	}

	if triggerReason == "" {
		return ks, false, nil
	}

	// Auto-trigger
	triggered, err := s.TriggerKillSwitch(ctx, orgID, systemID, &TriggerKillSwitchRequest{
		Reason: "Auto-triggered: " + triggerReason,
	}, "system")
	if err != nil {
		return nil, false, fmt.Errorf("failed to auto-trigger: %w", err)
	}

	return triggered, true, nil
}
