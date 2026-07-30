// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockKillSwitchService is a mock implementation for testing handlers.
type MockKillSwitchService struct {
	killSwitches map[string]*KillSwitch
	history      map[string][]*KillSwitchHistoryEntry
	counter      int
}

func NewMockKillSwitchService() *MockKillSwitchService {
	return &MockKillSwitchService{
		killSwitches: make(map[string]*KillSwitch),
		history:      make(map[string][]*KillSwitchHistoryEntry),
	}
}

func (m *MockKillSwitchService) CreateKillSwitch(ctx context.Context, orgID string, req *CreateKillSwitchRequest) (*KillSwitch, error) {
	m.counter++
	id := "ks-" + string(rune(m.counter+'0'))
	ks := &KillSwitch{
		ID:               id,
		OrgID:            orgID,
		Scope:            KillSwitchScope(req.Scope),
		SystemID:         req.SystemID,
		TargetIdentifier: req.TargetIdentifier,
		IsActive:         false,
		FallbackBehavior: FallbackBehavior(req.FallbackBehavior),
		FallbackConfig:   req.FallbackConfig,
		TriggerCondition: req.TriggerCondition,
		TriggerThreshold: req.TriggerThreshold,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	m.killSwitches[id] = ks
	return ks, nil
}

func (m *MockKillSwitchService) GetKillSwitch(ctx context.Context, orgID, id string) (*KillSwitch, error) {
	ks, ok := m.killSwitches[id]
	if !ok || ks.OrgID != orgID {
		return nil, ErrKillSwitchNotFound
	}
	return ks, nil
}

func (m *MockKillSwitchService) ListKillSwitches(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	var result []*KillSwitch
	for _, ks := range m.killSwitches {
		if ks.OrgID == orgID {
			result = append(result, ks)
		}
	}
	return result, len(result), nil
}

func (m *MockKillSwitchService) ListActiveKillSwitches(ctx context.Context, orgID string) ([]*KillSwitch, error) {
	var result []*KillSwitch
	for _, ks := range m.killSwitches {
		if ks.OrgID == orgID && ks.IsActive {
			result = append(result, ks)
		}
	}
	return result, nil
}

func (m *MockKillSwitchService) Activate(ctx context.Context, orgID, id string, req *ActivateKillSwitchRequest) (*KillSwitch, error) {
	ks, ok := m.killSwitches[id]
	if !ok || ks.OrgID != orgID {
		return nil, ErrKillSwitchNotFound
	}
	now := time.Now().UTC()
	ks.IsActive = true
	ks.ActivatedBy = req.ActorID
	ks.ActivatedByEmail = req.ActorEmail
	ks.ActivatedAt = &now
	ks.ActivationReason = req.Reason
	return ks, nil
}

func (m *MockKillSwitchService) Deactivate(ctx context.Context, orgID, id string, req *DeactivateKillSwitchRequest) (*KillSwitch, error) {
	ks, ok := m.killSwitches[id]
	if !ok || ks.OrgID != orgID {
		return nil, ErrKillSwitchNotFound
	}
	now := time.Now().UTC()
	ks.IsActive = false
	ks.DeactivatedBy = req.ActorID
	ks.DeactivatedByEmail = req.ActorEmail
	ks.DeactivatedAt = &now
	ks.DeactivationReason = req.Reason
	return ks, nil
}

func (m *MockKillSwitchService) DeleteKillSwitch(ctx context.Context, orgID, id string) error {
	ks, ok := m.killSwitches[id]
	if !ok || ks.OrgID != orgID {
		return ErrKillSwitchNotFound
	}
	delete(m.killSwitches, id)
	return nil
}

func (m *MockKillSwitchService) CheckKillSwitch(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitchCheckResult, error) {
	for _, ks := range m.killSwitches {
		if ks.OrgID == orgID && ks.IsActive {
			if ks.Scope == KillSwitchScopeGlobal {
				return &KillSwitchCheckResult{
					IsBlocked:        true,
					KillSwitch:       ks,
					FallbackBehavior: ks.FallbackBehavior,
					Message:          "Global kill switch active",
				}, nil
			}
			if ks.Scope == scope && ks.SystemID == systemID {
				return &KillSwitchCheckResult{
					IsBlocked:        true,
					KillSwitch:       ks,
					FallbackBehavior: ks.FallbackBehavior,
					Message:          "Kill switch active for this scope",
				}, nil
			}
		}
	}
	return &KillSwitchCheckResult{
		IsBlocked: false,
		Message:   "No active kill switch",
	}, nil
}

func (m *MockKillSwitchService) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error) {
	key := orgID + ":" + killSwitchID
	entries := m.history[key]
	if limit > 0 && len(entries) > limit {
		return entries[:limit], nil
	}
	return entries, nil
}

func (m *MockKillSwitchService) AutoTrigger(ctx context.Context, orgID, systemID, reason string) (*KillSwitch, error) {
	m.counter++
	id := "ks-auto-" + string(rune(m.counter+'0'))
	now := time.Now().UTC()
	ks := &KillSwitch{
		ID:               id,
		OrgID:            orgID,
		Scope:            KillSwitchScopeSystem,
		SystemID:         systemID,
		IsActive:         true,
		AutoTriggered:    true,
		ActivatedBy:      "automated_monitoring",
		ActivatedAt:      &now,
		ActivationReason: reason,
		FallbackBehavior: FallbackBehaviorBlockAll,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	m.killSwitches[id] = ks
	return ks, nil
}

func TestKillSwitchHandler_CreateKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	t.Run("create kill switch", func(t *testing.T) {
		body := `{"scope":"system","system_id":"credit-scoring","fallback_behavior":"block_all"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
		}

		var ks KillSwitch
		if err := json.NewDecoder(rr.Body).Decode(&ks); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if ks.ID == "" {
			t.Error("Expected ID to be set")
		}
		if ks.Scope != KillSwitchScopeSystem {
			t.Errorf("Scope = %v, want %v", ks.Scope, KillSwitchScopeSystem)
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		body := `{"scope":"system","system_id":"credit-scoring","fallback_behavior":"block_all"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches", bytes.NewBufferString("invalid"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestKillSwitchHandler_ListKillSwitches(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create some kill switches
	service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "system-1",
		FallbackBehavior: "block_all",
	})
	service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "system-2",
		FallbackBehavior: "human_review",
	})

	t.Run("list kill switches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		switches, ok := resp["kill_switches"].([]interface{})
		if !ok {
			t.Fatal("Expected kill_switches in response")
		}
		if len(switches) != 2 {
			t.Errorf("Len = %d, want 2", len(switches))
		}
	})
}

func TestKillSwitchHandler_GetKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create a kill switch
	ks, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "credit-scoring",
		FallbackBehavior: "block_all",
	})

	t.Run("get kill switch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/"+ks.ID, nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result KillSwitch
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ID != ks.ID {
			t.Errorf("ID = %v, want %v", result.ID, ks.ID)
		}
	})

	t.Run("get non-existent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/non-existent", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestKillSwitchHandler_ActivateKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create a kill switch
	ks, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "credit-scoring",
		FallbackBehavior: "block_all",
	})

	t.Run("activate kill switch", func(t *testing.T) {
		// INVERTED BY #3150. This case used to send actor_id in the body and
		// assert it became ActivatedBy — pinning the forgery as a requirement.
		// The body values below are now DECOYS: X-Client-ID is stamped by the
		// agent from the validated credential, so the credential must win.
		body := `{"actor_id":"user-123","actor_email":"admin@example.com","actor_role":"chief_risk_officer","actor_ip":"1.2.3.4","reason":"Security concern"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches/"+ks.ID+"/activate", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Client-ID", "client-alpha")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result KillSwitch
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !result.IsActive {
			t.Error("Expected IsActive to be true")
		}
		if result.ActivatedBy != "client-alpha" {
			t.Errorf("ActivatedBy = %v, want the authenticated credential client-alpha", result.ActivatedBy)
		}
		if result.ActivatedByEmail != "client-alpha@axonflow.local" {
			t.Errorf("ActivatedByEmail = %v, want the synthetic credential identity", result.ActivatedByEmail)
		}
	})
}

func TestKillSwitchHandler_DeactivateKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create and activate a kill switch
	ks, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "credit-scoring",
		FallbackBehavior: "block_all",
	})
	service.Activate(context.Background(), "org-1", ks.ID, &ActivateKillSwitchRequest{
		ActorID: "admin",
		Reason:  "Test activation",
	})

	t.Run("deactivate kill switch", func(t *testing.T) {
		// INVERTED BY #3150 — see the activate case. actor_id is a decoy.
		body := `{"actor_id":"user-456","actor_email":"cro@example.com","reason":"Issue resolved"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/killswitches/"+ks.ID+"/deactivate", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Client-ID", "client-alpha")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result KillSwitch
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.IsActive {
			t.Error("Expected IsActive to be false")
		}
		if result.DeactivatedBy != "client-alpha" {
			t.Errorf("DeactivatedBy = %v, want the authenticated credential client-alpha", result.DeactivatedBy)
		}
		if result.DeactivatedByEmail != "client-alpha@axonflow.local" {
			t.Errorf("DeactivatedByEmail = %v, want the synthetic credential identity", result.DeactivatedByEmail)
		}
	})
}

func TestKillSwitchHandler_DeleteKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create a kill switch
	ks, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "credit-scoring",
		FallbackBehavior: "block_all",
	})

	t.Run("delete kill switch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/killswitches/"+ks.ID, nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/killswitches/non-existent", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestKillSwitchHandler_CheckKillSwitch(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	t.Run("check with no active kill switch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/check?scope=system&system_id=credit-scoring", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result KillSwitchCheckResult
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.IsBlocked {
			t.Error("Expected IsBlocked to be false")
		}
	})

	t.Run("check with active kill switch", func(t *testing.T) {
		// Create and activate a kill switch
		ks, _ := service.CreateKillSwitch(context.Background(), "org-2", &CreateKillSwitchRequest{
			Scope:            "system",
			SystemID:         "blocked-system",
			FallbackBehavior: "block_all",
		})
		service.Activate(context.Background(), "org-2", ks.ID, &ActivateKillSwitchRequest{
			ActorID: "admin",
			Reason:  "Security concern",
		})

		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/check?scope=system&system_id=blocked-system", nil)
		req.Header.Set("X-Org-ID", "org-2")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result KillSwitchCheckResult
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if !result.IsBlocked {
			t.Error("Expected IsBlocked to be true")
		}
	})
}

func TestKillSwitchHandler_ListActiveKillSwitches(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create some kill switches, some active
	ks1, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "system-1",
		FallbackBehavior: "block_all",
	})
	service.Activate(context.Background(), "org-1", ks1.ID, &ActivateKillSwitchRequest{
		ActorID: "admin",
		Reason:  "Test",
	})

	service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "system-2",
		FallbackBehavior: "block_all",
	}) // Not activated

	t.Run("list active kill switches", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/active", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		switches, ok := resp["kill_switches"].([]interface{})
		if !ok {
			t.Fatal("Expected kill_switches in response")
		}
		if len(switches) != 1 {
			t.Errorf("Len = %d, want 1 active", len(switches))
		}
	})
}

func TestKillSwitchHandler_GetHistory(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	// Create a kill switch
	ks, _ := service.CreateKillSwitch(context.Background(), "org-1", &CreateKillSwitchRequest{
		Scope:            "system",
		SystemID:         "credit-scoring",
		FallbackBehavior: "block_all",
	})

	// Add some history entries
	key := "org-1:" + ks.ID
	service.history[key] = []*KillSwitchHistoryEntry{
		{ID: 1, OrgID: "org-1", KillSwitchID: ks.ID, Action: KillSwitchActionCreated, ActorID: "system"},
		{ID: 2, OrgID: "org-1", KillSwitchID: ks.ID, Action: KillSwitchActionActivated, ActorID: "admin"},
	}

	t.Run("get history", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/killswitches/"+ks.ID+"/history", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitchRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		history, ok := resp["history"].([]interface{})
		if !ok {
			t.Fatal("Expected history in response")
		}
		if len(history) != 2 {
			t.Errorf("Len = %d, want 2", len(history))
		}
	})
}

func TestKillSwitchHandler_CORS(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/rbi/killswitches", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNoContent)
		}

		if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected CORS headers to be set")
		}
	})
}

func TestKillSwitchHandler_MethodNotAllowed(t *testing.T) {
	service := NewMockKillSwitchService()
	handler := NewKillSwitchHandler(service)

	t.Run("PUT not allowed on collection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/killswitches", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleKillSwitches(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})
}
