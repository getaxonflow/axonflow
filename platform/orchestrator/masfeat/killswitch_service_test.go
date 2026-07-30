// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"testing"
)

// mockKillSwitchRepository is a mock implementation of KillSwitchRepository for testing.
type mockKillSwitchRepository struct {
	killSwitches map[string]*KillSwitch
	history      []*KillSwitchHistory
	// historyOrgIDs records the orgID RecordHistory was called with, in order
	// (#3133).
	historyOrgIDs []string
}

func newMockKillSwitchRepository() *mockKillSwitchRepository {
	return &mockKillSwitchRepository{
		killSwitches: make(map[string]*KillSwitch),
		history:      make([]*KillSwitchHistory, 0),
	}
}

func (m *mockKillSwitchRepository) Create(ctx context.Context, ks *KillSwitch) error {
	key := ks.OrgID + ":" + ks.SystemID
	m.killSwitches[key] = ks
	return nil
}

func (m *mockKillSwitchRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*KillSwitch, error) {
	key := orgID + ":" + systemID
	return m.killSwitches[key], nil
}

func (m *mockKillSwitchRepository) Update(ctx context.Context, ks *KillSwitch) error {
	key := ks.OrgID + ":" + ks.SystemID
	m.killSwitches[key] = ks
	return nil
}

func (m *mockKillSwitchRepository) RecordHistory(ctx context.Context, orgID string, history *KillSwitchHistory) error {
	// #3133: mas_kill_switch_history has no org_id column, so the caller's org
	// is an explicit parameter — the RLS wrap has nothing else to key on.
	// Recorded so TestKillSwitchService_RecordHistoryCarriesCallerOrg can prove
	// the service actually threads it through rather than passing "".
	m.historyOrgIDs = append(m.historyOrgIDs, orgID)
	m.history = append(m.history, history)
	return nil
}

func (m *mockKillSwitchRepository) GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*KillSwitchHistory, error) {
	var result []*KillSwitchHistory
	for _, h := range m.history {
		ks, _ := m.GetBySystemID(ctx, orgID, systemID)
		if ks != nil && h.KillSwitchID == ks.ID {
			result = append(result, h)
		}
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func TestKillSwitchService_GetOrCreateKillSwitch(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// First call should create
	ks, err := service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")
	if err != nil {
		t.Fatalf("GetOrCreateKillSwitch() unexpected error: %v", err)
	}
	if ks == nil {
		t.Fatalf("GetOrCreateKillSwitch() returned nil")
	}
	if ks.Status != KillSwitchEnabled {
		t.Errorf("GetOrCreateKillSwitch() Status = %v, want %v", ks.Status, KillSwitchEnabled)
	}
	if !ks.AutoTriggerEnabled {
		t.Errorf("GetOrCreateKillSwitch() AutoTriggerEnabled = false, want true")
	}
	if ks.BiasThreshold == nil || *ks.BiasThreshold != 0.10 {
		t.Errorf("GetOrCreateKillSwitch() BiasThreshold = %v, want 0.10", ks.BiasThreshold)
	}

	// Second call should return existing
	ks2, err := service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")
	if err != nil {
		t.Fatalf("GetOrCreateKillSwitch() unexpected error: %v", err)
	}
	if ks2.ID != ks.ID {
		t.Errorf("GetOrCreateKillSwitch() should return existing kill switch")
	}
}

func TestKillSwitchService_ConfigureKillSwitch(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Configure thresholds
	accuracyThreshold := 0.85
	biasThreshold := 0.05
	errorRateThreshold := 0.02

	req := &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracyThreshold,
		BiasThreshold:      &biasThreshold,
		ErrorRateThreshold: &errorRateThreshold,
	}

	ks, err := service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", req, "admin@example.com")
	if err != nil {
		t.Fatalf("ConfigureKillSwitch() unexpected error: %v", err)
	}

	if ks.AccuracyThreshold == nil || *ks.AccuracyThreshold != accuracyThreshold {
		t.Errorf("ConfigureKillSwitch() AccuracyThreshold = %v, want %v", ks.AccuracyThreshold, accuracyThreshold)
	}
	if ks.BiasThreshold == nil || *ks.BiasThreshold != biasThreshold {
		t.Errorf("ConfigureKillSwitch() BiasThreshold = %v, want %v", ks.BiasThreshold, biasThreshold)
	}
	if ks.ErrorRateThreshold == nil || *ks.ErrorRateThreshold != errorRateThreshold {
		t.Errorf("ConfigureKillSwitch() ErrorRateThreshold = %v, want %v", ks.ErrorRateThreshold, errorRateThreshold)
	}
}

func TestKillSwitchService_ConfigureKillSwitch_InvalidThresholds(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	tests := []struct {
		name   string
		req    *ConfigureKillSwitchRequest
		errMsg string
	}{
		{
			name: "accuracy_threshold too low",
			req: &ConfigureKillSwitchRequest{
				AccuracyThreshold: ptrFloat64(-0.5),
			},
			errMsg: "accuracy_threshold must be between 0 and 1",
		},
		{
			name: "accuracy_threshold too high",
			req: &ConfigureKillSwitchRequest{
				AccuracyThreshold: ptrFloat64(1.5),
			},
			errMsg: "accuracy_threshold must be between 0 and 1",
		},
		{
			name: "bias_threshold too low",
			req: &ConfigureKillSwitchRequest{
				BiasThreshold: ptrFloat64(-0.1),
			},
			errMsg: "bias_threshold must be between 0 and 1",
		},
		{
			name: "error_rate_threshold too high",
			req: &ConfigureKillSwitchRequest{
				ErrorRateThreshold: ptrFloat64(2.0),
			},
			errMsg: "error_rate_threshold must be between 0 and 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", tt.req, "admin@example.com")
			if err == nil {
				t.Errorf("ConfigureKillSwitch() expected error")
			} else if err.Error() != tt.errMsg {
				t.Errorf("ConfigureKillSwitch() error = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}

func TestKillSwitchService_TriggerKillSwitch(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Create a kill switch first
	service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")

	// Trigger without reason - should fail
	_, err := service.TriggerKillSwitch(context.Background(), "org-123", "sys-001", &TriggerKillSwitchRequest{}, "admin@example.com")
	if err == nil {
		t.Errorf("TriggerKillSwitch() expected error for missing reason")
	}

	// Trigger with reason
	ks, err := service.TriggerKillSwitch(context.Background(), "org-123", "sys-001", &TriggerKillSwitchRequest{
		Reason: "Bias detected in predictions",
	}, "admin@example.com")
	if err != nil {
		t.Fatalf("TriggerKillSwitch() unexpected error: %v", err)
	}

	if ks.Status != KillSwitchTriggered {
		t.Errorf("TriggerKillSwitch() Status = %v, want %v", ks.Status, KillSwitchTriggered)
	}
	if ks.TriggerReason != "Bias detected in predictions" {
		t.Errorf("TriggerKillSwitch() TriggerReason = %v, want 'Bias detected in predictions'", ks.TriggerReason)
	}
	if ks.TriggeredAt == nil {
		t.Errorf("TriggerKillSwitch() TriggeredAt should not be nil")
	}
	if ks.TriggeredBy != "admin@example.com" {
		t.Errorf("TriggerKillSwitch() TriggeredBy = %v, want admin@example.com", ks.TriggeredBy)
	}

	// Try to trigger again - should fail
	_, err = service.TriggerKillSwitch(context.Background(), "org-123", "sys-001", &TriggerKillSwitchRequest{
		Reason: "Another reason",
	}, "admin@example.com")
	if err == nil {
		t.Errorf("TriggerKillSwitch() expected error for already triggered")
	}
}

func TestKillSwitchService_RestoreKillSwitch(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Create and trigger a kill switch
	service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")
	service.TriggerKillSwitch(context.Background(), "org-123", "sys-001", &TriggerKillSwitchRequest{
		Reason: "Bias detected",
	}, "admin@example.com")

	// Restore without reason - should fail
	_, err := service.RestoreKillSwitch(context.Background(), "org-123", "sys-001", &RestoreKillSwitchRequest{}, "admin@example.com")
	if err == nil {
		t.Errorf("RestoreKillSwitch() expected error for missing reason")
	}

	// Restore with reason
	ks, err := service.RestoreKillSwitch(context.Background(), "org-123", "sys-001", &RestoreKillSwitchRequest{
		Reason: "Bias issue resolved, model retrained",
	}, "admin@example.com")
	if err != nil {
		t.Fatalf("RestoreKillSwitch() unexpected error: %v", err)
	}

	if ks.Status != KillSwitchEnabled {
		t.Errorf("RestoreKillSwitch() Status = %v, want %v", ks.Status, KillSwitchEnabled)
	}
	if ks.RestoreReason != "Bias issue resolved, model retrained" {
		t.Errorf("RestoreKillSwitch() RestoreReason = %v", ks.RestoreReason)
	}
	if ks.RestoredAt == nil {
		t.Errorf("RestoreKillSwitch() RestoredAt should not be nil")
	}
}

func TestKillSwitchService_RestoreKillSwitch_NotTriggered(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Create a kill switch (enabled state)
	service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")

	// Try to restore when not triggered - should fail
	_, err := service.RestoreKillSwitch(context.Background(), "org-123", "sys-001", &RestoreKillSwitchRequest{
		Reason: "Some reason",
	}, "admin@example.com")
	if err == nil {
		t.Errorf("RestoreKillSwitch() expected error for not triggered")
	}
}

func TestKillSwitchService_DisableEnableKillSwitch(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Create a kill switch
	service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")

	// Disable
	ks, err := service.DisableKillSwitch(context.Background(), "org-123", "sys-001", "admin@example.com")
	if err != nil {
		t.Fatalf("DisableKillSwitch() unexpected error: %v", err)
	}
	if ks.Status != KillSwitchDisabled {
		t.Errorf("DisableKillSwitch() Status = %v, want %v", ks.Status, KillSwitchDisabled)
	}

	// Try to disable again - should fail
	_, err = service.DisableKillSwitch(context.Background(), "org-123", "sys-001", "admin@example.com")
	if err == nil {
		t.Errorf("DisableKillSwitch() expected error for already disabled")
	}

	// Enable
	ks, err = service.EnableKillSwitch(context.Background(), "org-123", "sys-001", "admin@example.com")
	if err != nil {
		t.Fatalf("EnableKillSwitch() unexpected error: %v", err)
	}
	if ks.Status != KillSwitchEnabled {
		t.Errorf("EnableKillSwitch() Status = %v, want %v", ks.Status, KillSwitchEnabled)
	}

	// Try to enable again - should fail
	_, err = service.EnableKillSwitch(context.Background(), "org-123", "sys-001", "admin@example.com")
	if err == nil {
		t.Errorf("EnableKillSwitch() expected error for already enabled")
	}
}

func TestKillSwitchService_CheckAndTrigger(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Configure thresholds
	accuracyThreshold := 0.85
	biasThreshold := 0.10
	errorRateThreshold := 0.05

	req := &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracyThreshold,
		BiasThreshold:      &biasThreshold,
		ErrorRateThreshold: &errorRateThreshold,
	}
	service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", req, "admin@example.com")

	// Test accuracy below threshold
	metrics := map[string]float64{
		"accuracy": 0.80, // Below 0.85 threshold
	}
	ks, triggered, err := service.CheckAndTrigger(context.Background(), "org-123", "sys-001", metrics)
	if err != nil {
		t.Fatalf("CheckAndTrigger() unexpected error: %v", err)
	}
	if !triggered {
		t.Errorf("CheckAndTrigger() should have triggered for low accuracy")
	}
	if ks.Status != KillSwitchTriggered {
		t.Errorf("CheckAndTrigger() Status = %v, want %v", ks.Status, KillSwitchTriggered)
	}
}

func TestKillSwitchService_CheckAndTrigger_BiasExceeded(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Configure thresholds
	biasThreshold := 0.10

	req := &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		BiasThreshold:      &biasThreshold,
	}
	service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", req, "admin@example.com")

	// Test bias above threshold
	metrics := map[string]float64{
		"bias": 0.15, // Above 0.10 threshold
	}
	ks, triggered, err := service.CheckAndTrigger(context.Background(), "org-123", "sys-001", metrics)
	if err != nil {
		t.Fatalf("CheckAndTrigger() unexpected error: %v", err)
	}
	if !triggered {
		t.Errorf("CheckAndTrigger() should have triggered for high bias")
	}
	if ks.Status != KillSwitchTriggered {
		t.Errorf("CheckAndTrigger() Status = %v, want %v", ks.Status, KillSwitchTriggered)
	}
}

func TestKillSwitchService_CheckAndTrigger_NoTrigger(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Configure thresholds
	accuracyThreshold := 0.85
	biasThreshold := 0.10

	req := &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracyThreshold,
		BiasThreshold:      &biasThreshold,
	}
	service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", req, "admin@example.com")

	// Test metrics within thresholds
	metrics := map[string]float64{
		"accuracy": 0.90, // Above 0.85 threshold
		"bias":     0.05, // Below 0.10 threshold
	}
	ks, triggered, err := service.CheckAndTrigger(context.Background(), "org-123", "sys-001", metrics)
	if err != nil {
		t.Fatalf("CheckAndTrigger() unexpected error: %v", err)
	}
	if triggered {
		t.Errorf("CheckAndTrigger() should not have triggered")
	}
	if ks.Status != KillSwitchEnabled {
		t.Errorf("CheckAndTrigger() Status = %v, want %v", ks.Status, KillSwitchEnabled)
	}
}

func TestKillSwitchService_CheckAndTrigger_AutoDisabled(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Configure with auto-trigger disabled
	accuracyThreshold := 0.85

	req := &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: false,
		AccuracyThreshold:  &accuracyThreshold,
	}
	service.ConfigureKillSwitch(context.Background(), "org-123", "sys-001", req, "admin@example.com")

	// Test accuracy below threshold - should NOT trigger because auto is disabled
	metrics := map[string]float64{
		"accuracy": 0.70,
	}
	ks, triggered, err := service.CheckAndTrigger(context.Background(), "org-123", "sys-001", metrics)
	if err != nil {
		t.Fatalf("CheckAndTrigger() unexpected error: %v", err)
	}
	if triggered {
		t.Errorf("CheckAndTrigger() should not trigger when auto-trigger is disabled")
	}
	if ks.Status != KillSwitchEnabled {
		t.Errorf("CheckAndTrigger() Status = %v, want %v", ks.Status, KillSwitchEnabled)
	}
}

func TestKillSwitchService_GetHistory(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Create, trigger, and restore a kill switch
	service.GetOrCreateKillSwitch(context.Background(), "org-123", "sys-001")
	service.TriggerKillSwitch(context.Background(), "org-123", "sys-001", &TriggerKillSwitchRequest{
		Reason: "Bias detected",
	}, "admin@example.com")
	service.RestoreKillSwitch(context.Background(), "org-123", "sys-001", &RestoreKillSwitchRequest{
		Reason: "Issue resolved",
	}, "admin@example.com")

	// Get history
	history, err := service.GetHistory(context.Background(), "org-123", "sys-001", 10)
	if err != nil {
		t.Fatalf("GetHistory() unexpected error: %v", err)
	}

	// Should have 2 history entries (triggered, restored)
	if len(history) != 2 {
		t.Errorf("GetHistory() count = %v, want 2", len(history))
	}
}

func TestKillSwitchService_GetKillSwitch_NotFound(t *testing.T) {
	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	// Try to get non-existent kill switch
	_, err := service.GetKillSwitch(context.Background(), "org-123", "non-existent")
	if err == nil {
		t.Errorf("GetKillSwitch() expected error for non-existent")
	}
}

// Helper function to create pointer to float64
func ptrFloat64(v float64) *float64 {
	return &v
}

// TestKillSwitchService_RecordHistoryCarriesCallerOrg pins the one thing the
// #3133 signature change is FOR: mas_kill_switch_history has no org_id column,
// so migration 400's policy resolves ownership through a subquery on
// mas_kill_switches. If any service path called RecordHistory with "" — or with
// some other org — rls.WithOrgScope would either reject the call outright or
// pin the wrong GUC and the INSERT's WITH CHECK would refuse it on an app-role
// pool. Compilation alone does not catch that: `""` is a valid string.
//
// Every state-changing service method is exercised, not a sample: the census is
// the point. A method added later that records history without threading the
// caller's org through will not be covered here, which is why the repository
// method's doc comment states the contract too.
func TestKillSwitchService_RecordHistoryCarriesCallerOrg(t *testing.T) {
	const orgID = "org-history-scope"
	ctx := context.Background()

	repo := newMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)

	if _, err := service.ConfigureKillSwitch(ctx, orgID, "sys-1", &ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		BiasThreshold:      ptrFloat64(0.2),
	}, "admin"); err != nil {
		t.Fatalf("ConfigureKillSwitch: %v", err)
	}
	if _, err := service.TriggerKillSwitch(ctx, orgID, "sys-1", &TriggerKillSwitchRequest{
		Reason: "bias breach",
	}, "admin"); err != nil {
		t.Fatalf("TriggerKillSwitch: %v", err)
	}
	if _, err := service.RestoreKillSwitch(ctx, orgID, "sys-1", &RestoreKillSwitchRequest{
		Reason: "model retrained",
	}, "admin"); err != nil {
		t.Fatalf("RestoreKillSwitch: %v", err)
	}
	if _, err := service.DisableKillSwitch(ctx, orgID, "sys-1", "admin"); err != nil {
		t.Fatalf("DisableKillSwitch: %v", err)
	}
	if _, err := service.EnableKillSwitch(ctx, orgID, "sys-1", "admin"); err != nil {
		t.Fatalf("EnableKillSwitch: %v", err)
	}

	if len(repo.historyOrgIDs) != 5 {
		t.Fatalf("RecordHistory called %d times, want 5 (configure/trigger/restore/disable/enable) — "+
			"a state change that records no history is a gap in this census", len(repo.historyOrgIDs))
	}
	for i, got := range repo.historyOrgIDs {
		if got != orgID {
			t.Errorf("RecordHistory call %d carried orgID %q, want %q — rls.WithOrgScope would pin the "+
				"wrong app.current_org_id and migration 400's subquery WITH CHECK would refuse the "+
				"INSERT on an app-role pool (#3133)", i, got, orgID)
		}
	}
}
