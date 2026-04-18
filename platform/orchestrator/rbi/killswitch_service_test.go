// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"testing"
	"time"
)

// MockKillSwitchRepository is a mock implementation for testing.
type MockKillSwitchRepository struct {
	killSwitches map[string]map[string]*KillSwitch
	history      map[string][]*KillSwitchHistoryEntry
	counter      int
}

func NewMockKillSwitchRepository() *MockKillSwitchRepository {
	return &MockKillSwitchRepository{
		killSwitches: make(map[string]map[string]*KillSwitch),
		history:      make(map[string][]*KillSwitchHistoryEntry),
	}
}

func (m *MockKillSwitchRepository) Create(ctx context.Context, ks *KillSwitch) error {
	if ks.ID == "" {
		m.counter++
		ks.ID = "mock-ks-" + string(rune(m.counter+'0'))
	}
	ks.CreatedAt = time.Now().UTC()
	ks.UpdatedAt = ks.CreatedAt

	if m.killSwitches[ks.OrgID] == nil {
		m.killSwitches[ks.OrgID] = make(map[string]*KillSwitch)
	}
	m.killSwitches[ks.OrgID][ks.ID] = ks
	return nil
}

func (m *MockKillSwitchRepository) Get(ctx context.Context, orgID, id string) (*KillSwitch, error) {
	if orgSwitches, ok := m.killSwitches[orgID]; ok {
		if ks, ok := orgSwitches[id]; ok {
			return ks, nil
		}
	}
	return nil, ErrKillSwitchNotFound
}

func (m *MockKillSwitchRepository) GetByScope(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitch, error) {
	if orgSwitches, ok := m.killSwitches[orgID]; ok {
		for _, ks := range orgSwitches {
			if ks.Scope == scope && ks.SystemID == systemID && ks.TargetIdentifier == targetID {
				return ks, nil
			}
		}
	}
	return nil, ErrKillSwitchNotFound
}

func (m *MockKillSwitchRepository) List(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	if params == nil {
		params = &ListKillSwitchParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	var result []*KillSwitch
	orgSwitches := m.killSwitches[orgID]
	if orgSwitches == nil {
		return result, 0, nil
	}

	for _, ks := range orgSwitches {
		if params.SystemID != "" && ks.SystemID != params.SystemID {
			continue
		}
		if params.Scope != "" && string(ks.Scope) != params.Scope {
			continue
		}
		if params.IsActive != nil && ks.IsActive != *params.IsActive {
			continue
		}
		result = append(result, ks)
	}

	total := len(result)
	if params.Offset >= len(result) {
		return []*KillSwitch{}, total, nil
	}
	end := params.Offset + params.Limit
	if end > len(result) {
		end = len(result)
	}
	return result[params.Offset:end], total, nil
}

func (m *MockKillSwitchRepository) ListActive(ctx context.Context, orgID string) ([]*KillSwitch, error) {
	var result []*KillSwitch
	orgSwitches := m.killSwitches[orgID]
	if orgSwitches == nil {
		return result, nil
	}

	for _, ks := range orgSwitches {
		if ks.IsActive {
			result = append(result, ks)
		}
	}
	return result, nil
}

func (m *MockKillSwitchRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*KillSwitch, error) {
	var result []*KillSwitch
	orgSwitches := m.killSwitches[orgID]
	if orgSwitches == nil {
		return result, nil
	}

	for _, ks := range orgSwitches {
		if ks.SystemID == systemID {
			result = append(result, ks)
		}
	}
	return result, nil
}

func (m *MockKillSwitchRepository) Update(ctx context.Context, ks *KillSwitch) error {
	if orgSwitches, ok := m.killSwitches[ks.OrgID]; ok {
		if _, ok := orgSwitches[ks.ID]; ok {
			ks.UpdatedAt = time.Now().UTC()
			m.killSwitches[ks.OrgID][ks.ID] = ks
			return nil
		}
	}
	return ErrKillSwitchNotFound
}

func (m *MockKillSwitchRepository) Delete(ctx context.Context, orgID, id string) error {
	if orgSwitches, ok := m.killSwitches[orgID]; ok {
		if _, ok := orgSwitches[id]; ok {
			delete(m.killSwitches[orgID], id)
			return nil
		}
	}
	return ErrKillSwitchNotFound
}

func (m *MockKillSwitchRepository) AddHistoryEntry(ctx context.Context, entry *KillSwitchHistoryEntry) error {
	entry.CreatedAt = time.Now().UTC()
	m.counter++
	entry.ID = int64(m.counter)
	key := entry.OrgID + ":" + entry.KillSwitchID
	m.history[key] = append(m.history[key], entry)
	return nil
}

func (m *MockKillSwitchRepository) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error) {
	key := orgID + ":" + killSwitchID
	entries := m.history[key]
	if limit > 0 && len(entries) > limit {
		return entries[:limit], nil
	}
	return entries, nil
}

func (m *MockKillSwitchRepository) CheckActive(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (bool, *KillSwitch, error) {
	orgSwitches := m.killSwitches[orgID]
	if orgSwitches == nil {
		return false, nil, nil
	}

	// Check global first
	for _, ks := range orgSwitches {
		if ks.Scope == KillSwitchScopeGlobal && ks.IsActive {
			return true, ks, nil
		}
	}

	// Check system
	if systemID != "" {
		for _, ks := range orgSwitches {
			if ks.Scope == KillSwitchScopeSystem && ks.SystemID == systemID && ks.IsActive {
				return true, ks, nil
			}
		}
	}

	// Check specific scope
	if systemID != "" && targetID != "" && scope != KillSwitchScopeGlobal && scope != KillSwitchScopeSystem {
		for _, ks := range orgSwitches {
			if ks.Scope == scope && ks.SystemID == systemID && ks.TargetIdentifier == targetID && ks.IsActive {
				return true, ks, nil
			}
		}
	}

	return false, nil, nil
}

func TestKillSwitchService_CreateKillSwitch(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	t.Run("create system-level kill switch", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "system",
			SystemID:         "credit-scoring-v1",
			FallbackBehavior: "block_all",
		}

		ks, err := service.CreateKillSwitch(context.Background(), "org-1", req)
		if err != nil {
			t.Fatalf("CreateKillSwitch failed: %v", err)
		}

		if ks.ID == "" {
			t.Error("Expected ID to be set")
		}
		if ks.Scope != KillSwitchScopeSystem {
			t.Errorf("Scope = %v, want %v", ks.Scope, KillSwitchScopeSystem)
		}
		if ks.SystemID != "credit-scoring-v1" {
			t.Errorf("SystemID = %v, want credit-scoring-v1", ks.SystemID)
		}
		if ks.FallbackBehavior != FallbackBehaviorBlockAll {
			t.Errorf("FallbackBehavior = %v, want %v", ks.FallbackBehavior, FallbackBehaviorBlockAll)
		}
		if ks.IsActive {
			t.Error("Expected IsActive to be false by default")
		}
	})

	t.Run("create global kill switch", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "global",
			FallbackBehavior: "human_review",
		}

		ks, err := service.CreateKillSwitch(context.Background(), "org-2", req)
		if err != nil {
			t.Fatalf("CreateKillSwitch failed: %v", err)
		}

		if ks.Scope != KillSwitchScopeGlobal {
			t.Errorf("Scope = %v, want %v", ks.Scope, KillSwitchScopeGlobal)
		}
	})

	t.Run("create model-level kill switch", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "model",
			SystemID:         "fraud-detection",
			TargetIdentifier: "model-v2",
			FallbackBehavior: "previous_version",
		}

		ks, err := service.CreateKillSwitch(context.Background(), "org-3", req)
		if err != nil {
			t.Fatalf("CreateKillSwitch failed: %v", err)
		}

		if ks.Scope != KillSwitchScopeModel {
			t.Errorf("Scope = %v, want %v", ks.Scope, KillSwitchScopeModel)
		}
		if ks.TargetIdentifier != "model-v2" {
			t.Errorf("TargetIdentifier = %v, want model-v2", ks.TargetIdentifier)
		}
	})

	t.Run("invalid scope", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "invalid",
			FallbackBehavior: "block_all",
		}

		_, err := service.CreateKillSwitch(context.Background(), "org-1", req)
		if err == nil {
			t.Error("Expected error for invalid scope")
		}
	})

	t.Run("missing scope", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			FallbackBehavior: "block_all",
		}

		_, err := service.CreateKillSwitch(context.Background(), "org-1", req)
		if err == nil {
			t.Error("Expected error for missing scope")
		}
	})

	t.Run("missing system_id for system scope", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "system",
			FallbackBehavior: "block_all",
		}

		_, err := service.CreateKillSwitch(context.Background(), "org-1", req)
		if err == nil {
			t.Error("Expected error for missing system_id")
		}
	})

	t.Run("missing target_identifier for model scope", func(t *testing.T) {
		req := &CreateKillSwitchRequest{
			Scope:            "model",
			SystemID:         "credit-scoring",
			FallbackBehavior: "block_all",
		}

		_, err := service.CreateKillSwitch(context.Background(), "org-1", req)
		if err == nil {
			t.Error("Expected error for missing target_identifier")
		}
	})
}

func TestKillSwitchService_Activate(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	// Create a kill switch first
	ks := &KillSwitch{
		ID:               "ks-1",
		OrgID:            "org-1",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "credit-scoring-v1",
		IsActive:         false,
		FallbackBehavior: FallbackBehaviorBlockAll,
	}
	repo.Create(context.Background(), ks)

	t.Run("activate kill switch", func(t *testing.T) {
		req := &ActivateKillSwitchRequest{
			ActorID:    "user-123",
			ActorEmail: "admin@example.com",
			ActorRole:  "risk_officer",
			Reason:     "Detected bias in model outputs",
		}

		activated, err := service.Activate(context.Background(), "org-1", "ks-1", req)
		if err != nil {
			t.Fatalf("Activate failed: %v", err)
		}

		if !activated.IsActive {
			t.Error("Expected IsActive to be true")
		}
		if activated.ActivatedBy != "user-123" {
			t.Errorf("ActivatedBy = %v, want user-123", activated.ActivatedBy)
		}
		if activated.ActivatedByEmail != "admin@example.com" {
			t.Errorf("ActivatedByEmail = %v, want admin@example.com", activated.ActivatedByEmail)
		}
		if activated.ActivationReason != "Detected bias in model outputs" {
			t.Errorf("ActivationReason = %v, want 'Detected bias in model outputs'", activated.ActivationReason)
		}
		if activated.ActivatedAt == nil {
			t.Error("Expected ActivatedAt to be set")
		}
	})

	t.Run("activate already active", func(t *testing.T) {
		req := &ActivateKillSwitchRequest{
			ActorID: "user-123",
			Reason:  "Another reason",
		}

		_, err := service.Activate(context.Background(), "org-1", "ks-1", req)
		if err == nil {
			t.Error("Expected error for already active kill switch")
		}
	})

	t.Run("activate missing actor_id", func(t *testing.T) {
		req := &ActivateKillSwitchRequest{
			Reason: "Some reason",
		}

		_, err := service.Activate(context.Background(), "org-1", "ks-1", req)
		if err == nil {
			t.Error("Expected error for missing actor_id")
		}
	})

	t.Run("activate missing reason", func(t *testing.T) {
		req := &ActivateKillSwitchRequest{
			ActorID: "user-123",
		}

		_, err := service.Activate(context.Background(), "org-1", "ks-1", req)
		if err == nil {
			t.Error("Expected error for missing reason")
		}
	})
}

func TestKillSwitchService_Deactivate(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	// Create and activate a kill switch
	now := time.Now().UTC()
	ks := &KillSwitch{
		ID:               "ks-2",
		OrgID:            "org-1",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "credit-scoring-v1",
		IsActive:         true,
		ActivatedBy:      "user-100",
		ActivatedAt:      &now,
		ActivationReason: "Initial activation",
		FallbackBehavior: FallbackBehaviorBlockAll,
	}
	repo.Create(context.Background(), ks)

	t.Run("deactivate kill switch", func(t *testing.T) {
		req := &DeactivateKillSwitchRequest{
			ActorID:    "user-456",
			ActorEmail: "supervisor@example.com",
			Reason:     "Issue resolved after investigation",
		}

		deactivated, err := service.Deactivate(context.Background(), "org-1", "ks-2", req)
		if err != nil {
			t.Fatalf("Deactivate failed: %v", err)
		}

		if deactivated.IsActive {
			t.Error("Expected IsActive to be false")
		}
		if deactivated.DeactivatedBy != "user-456" {
			t.Errorf("DeactivatedBy = %v, want user-456", deactivated.DeactivatedBy)
		}
		if deactivated.DeactivationReason != "Issue resolved after investigation" {
			t.Errorf("DeactivationReason = %v, want 'Issue resolved after investigation'", deactivated.DeactivationReason)
		}
		if deactivated.DeactivatedAt == nil {
			t.Error("Expected DeactivatedAt to be set")
		}
	})

	t.Run("deactivate already inactive", func(t *testing.T) {
		req := &DeactivateKillSwitchRequest{
			ActorID: "user-456",
			Reason:  "Another deactivation",
		}

		_, err := service.Deactivate(context.Background(), "org-1", "ks-2", req)
		if err == nil {
			t.Error("Expected error for already inactive kill switch")
		}
	})
}

func TestKillSwitchService_CheckKillSwitch(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	t.Run("no active kill switches", func(t *testing.T) {
		result, err := service.CheckKillSwitch(context.Background(), "org-1", KillSwitchScopeSystem, "system-1", "")
		if err != nil {
			t.Fatalf("CheckKillSwitch failed: %v", err)
		}

		if result.IsBlocked {
			t.Error("Expected IsBlocked to be false")
		}
	})

	t.Run("global kill switch blocks everything", func(t *testing.T) {
		now := time.Now().UTC()
		globalKs := &KillSwitch{
			ID:               "ks-global",
			OrgID:            "org-global",
			Scope:            KillSwitchScopeGlobal,
			IsActive:         true,
			ActivatedBy:      "admin",
			ActivatedAt:      &now,
			ActivationReason: "Security incident",
			FallbackBehavior: FallbackBehaviorBlockAll,
		}
		repo.Create(context.Background(), globalKs)

		result, err := service.CheckKillSwitch(context.Background(), "org-global", KillSwitchScopeSystem, "any-system", "")
		if err != nil {
			t.Fatalf("CheckKillSwitch failed: %v", err)
		}

		if !result.IsBlocked {
			t.Error("Expected IsBlocked to be true with global kill switch")
		}
		if result.FallbackBehavior != FallbackBehaviorBlockAll {
			t.Errorf("FallbackBehavior = %v, want %v", result.FallbackBehavior, FallbackBehaviorBlockAll)
		}
	})

	t.Run("system-level kill switch", func(t *testing.T) {
		now := time.Now().UTC()
		systemKs := &KillSwitch{
			ID:               "ks-system",
			OrgID:            "org-system",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "credit-scoring",
			IsActive:         true,
			ActivatedBy:      "risk-officer",
			ActivatedAt:      &now,
			ActivationReason: "Model drift detected",
			FallbackBehavior: FallbackBehaviorHumanReview,
		}
		repo.Create(context.Background(), systemKs)

		// Should block the system
		result, err := service.CheckKillSwitch(context.Background(), "org-system", KillSwitchScopeSystem, "credit-scoring", "")
		if err != nil {
			t.Fatalf("CheckKillSwitch failed: %v", err)
		}

		if !result.IsBlocked {
			t.Error("Expected IsBlocked to be true for the specific system")
		}
		if result.FallbackBehavior != FallbackBehaviorHumanReview {
			t.Errorf("FallbackBehavior = %v, want %v", result.FallbackBehavior, FallbackBehaviorHumanReview)
		}

		// Should not block other systems
		result2, err := service.CheckKillSwitch(context.Background(), "org-system", KillSwitchScopeSystem, "other-system", "")
		if err != nil {
			t.Fatalf("CheckKillSwitch failed: %v", err)
		}

		if result2.IsBlocked {
			t.Error("Expected IsBlocked to be false for other systems")
		}
	})
}

func TestKillSwitchService_DeleteKillSwitch(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	t.Run("delete inactive kill switch", func(t *testing.T) {
		ks := &KillSwitch{
			ID:               "ks-delete",
			OrgID:            "org-1",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "test-system",
			IsActive:         false,
			FallbackBehavior: FallbackBehaviorBlockAll,
		}
		repo.Create(context.Background(), ks)

		err := service.DeleteKillSwitch(context.Background(), "org-1", "ks-delete")
		if err != nil {
			t.Fatalf("DeleteKillSwitch failed: %v", err)
		}

		// Verify it's deleted
		_, err = repo.Get(context.Background(), "org-1", "ks-delete")
		if err != ErrKillSwitchNotFound {
			t.Error("Expected kill switch to be deleted")
		}
	})

	t.Run("cannot delete active kill switch", func(t *testing.T) {
		now := time.Now().UTC()
		ks := &KillSwitch{
			ID:               "ks-active",
			OrgID:            "org-1",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "test-system",
			IsActive:         true,
			ActivatedBy:      "admin",
			ActivatedAt:      &now,
			FallbackBehavior: FallbackBehaviorBlockAll,
		}
		repo.Create(context.Background(), ks)

		err := service.DeleteKillSwitch(context.Background(), "org-1", "ks-active")
		if err == nil {
			t.Error("Expected error when deleting active kill switch")
		}
	})

	t.Run("delete non-existent", func(t *testing.T) {
		err := service.DeleteKillSwitch(context.Background(), "org-1", "non-existent")
		if err == nil {
			t.Error("Expected error for non-existent kill switch")
		}
	})
}

func TestKillSwitchService_AutoTrigger(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	t.Run("auto-trigger creates and activates kill switch", func(t *testing.T) {
		ks, err := service.AutoTrigger(context.Background(), "org-1", "ai-system-1", "Critical model failure detected")
		if err != nil {
			t.Fatalf("AutoTrigger failed: %v", err)
		}

		if !ks.IsActive {
			t.Error("Expected IsActive to be true")
		}
		if !ks.AutoTriggered {
			t.Error("Expected AutoTriggered to be true")
		}
		if ks.ActivatedBy != "automated_monitoring" {
			t.Errorf("ActivatedBy = %v, want automated_monitoring", ks.ActivatedBy)
		}
		if ks.ActivationReason != "Critical model failure detected" {
			t.Errorf("ActivationReason = %v, want 'Critical model failure detected'", ks.ActivationReason)
		}
		if ks.FallbackBehavior != FallbackBehaviorBlockAll {
			t.Errorf("FallbackBehavior = %v, want %v", ks.FallbackBehavior, FallbackBehaviorBlockAll)
		}
	})

	t.Run("auto-trigger existing inactive kill switch", func(t *testing.T) {
		// Create an inactive kill switch
		ks := &KillSwitch{
			ID:               "ks-existing",
			OrgID:            "org-2",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "existing-system",
			IsActive:         false,
			FallbackBehavior: FallbackBehaviorHumanReview,
		}
		repo.Create(context.Background(), ks)

		triggered, err := service.AutoTrigger(context.Background(), "org-2", "existing-system", "Auto triggered")
		if err != nil {
			t.Fatalf("AutoTrigger failed: %v", err)
		}

		if !triggered.IsActive {
			t.Error("Expected IsActive to be true")
		}
		if !triggered.AutoTriggered {
			t.Error("Expected AutoTriggered to be true")
		}
	})

	t.Run("auto-trigger already active", func(t *testing.T) {
		now := time.Now().UTC()
		ks := &KillSwitch{
			ID:               "ks-already-active",
			OrgID:            "org-3",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "active-system",
			IsActive:         true,
			ActivatedBy:      "admin",
			ActivatedAt:      &now,
			FallbackBehavior: FallbackBehaviorBlockAll,
		}
		repo.Create(context.Background(), ks)

		// Should return the existing active kill switch
		triggered, err := service.AutoTrigger(context.Background(), "org-3", "active-system", "Redundant trigger")
		if err != nil {
			t.Fatalf("AutoTrigger failed: %v", err)
		}

		if triggered.ID != "ks-already-active" {
			t.Errorf("Expected existing kill switch ID, got %v", triggered.ID)
		}
	})
}

func TestKillSwitchService_ListKillSwitches(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	// Create some kill switches
	for i := 0; i < 5; i++ {
		ks := &KillSwitch{
			ID:               "ks-list-" + string(rune('a'+i)),
			OrgID:            "org-list",
			Scope:            KillSwitchScopeSystem,
			SystemID:         "system-" + string(rune('0'+i)),
			IsActive:         i%2 == 0, // Every other one is active
			FallbackBehavior: FallbackBehaviorBlockAll,
		}
		repo.Create(context.Background(), ks)
	}

	t.Run("list all", func(t *testing.T) {
		switches, total, err := service.ListKillSwitches(context.Background(), "org-list", nil)
		if err != nil {
			t.Fatalf("ListKillSwitches failed: %v", err)
		}

		if total != 5 {
			t.Errorf("Total = %d, want 5", total)
		}
		if len(switches) != 5 {
			t.Errorf("Len = %d, want 5", len(switches))
		}
	})

	t.Run("filter by active", func(t *testing.T) {
		active := true
		params := &ListKillSwitchParams{IsActive: &active}
		switches, total, err := service.ListKillSwitches(context.Background(), "org-list", params)
		if err != nil {
			t.Fatalf("ListKillSwitches failed: %v", err)
		}

		if total != 3 {
			t.Errorf("Total = %d, want 3 active", total)
		}
		for _, ks := range switches {
			if !ks.IsActive {
				t.Error("Expected all returned switches to be active")
			}
		}
	})
}

func TestKillSwitchService_GetHistory(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, nil)

	// Create a kill switch with some history
	ks := &KillSwitch{
		ID:               "ks-history",
		OrgID:            "org-1",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "test-system",
		IsActive:         false,
		FallbackBehavior: FallbackBehaviorBlockAll,
	}
	repo.Create(context.Background(), ks)

	// Add history entries
	for i := 0; i < 3; i++ {
		entry := &KillSwitchHistoryEntry{
			OrgID:        "org-1",
			KillSwitchID: "ks-history",
			Action:       KillSwitchActionActivated,
			ActorID:      "user-" + string(rune('0'+i)),
			Reason:       "Test reason " + string(rune('0'+i)),
		}
		repo.AddHistoryEntry(context.Background(), entry)
	}

	t.Run("get history", func(t *testing.T) {
		history, err := service.GetHistory(context.Background(), "org-1", "ks-history", 50)
		if err != nil {
			t.Fatalf("GetHistory failed: %v", err)
		}

		if len(history) != 3 {
			t.Errorf("Len = %d, want 3", len(history))
		}
	})

	t.Run("get history with limit", func(t *testing.T) {
		history, err := service.GetHistory(context.Background(), "org-1", "ks-history", 2)
		if err != nil {
			t.Fatalf("GetHistory failed: %v", err)
		}

		if len(history) != 2 {
			t.Errorf("Len = %d, want 2", len(history))
		}
	})
}
