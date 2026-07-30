// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// MockKillSwitchRepository implements KillSwitchRepository for testing.
type MockKillSwitchRepository struct {
	killSwitches   map[string]*KillSwitch
	history        map[string][]*KillSwitchHistory
	createErr      error
	getBySystemErr error
	updateErr      error
	recordHistErr  error
	getHistoryErr  error
}

func NewMockKillSwitchRepository() *MockKillSwitchRepository {
	return &MockKillSwitchRepository{
		killSwitches: make(map[string]*KillSwitch),
		history:      make(map[string][]*KillSwitchHistory),
	}
}

func (m *MockKillSwitchRepository) Create(ctx context.Context, ks *KillSwitch) error {
	if m.createErr != nil {
		return m.createErr
	}
	key := ks.OrgID + ":" + ks.SystemID
	m.killSwitches[key] = ks
	return nil
}

func (m *MockKillSwitchRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*KillSwitch, error) {
	if m.getBySystemErr != nil {
		return nil, m.getBySystemErr
	}
	key := orgID + ":" + systemID
	ks, ok := m.killSwitches[key]
	if !ok {
		return nil, nil
	}
	return ks, nil
}

func (m *MockKillSwitchRepository) Update(ctx context.Context, ks *KillSwitch) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	key := ks.OrgID + ":" + ks.SystemID
	m.killSwitches[key] = ks
	return nil
}

func (m *MockKillSwitchRepository) RecordHistory(ctx context.Context, orgID string, h *KillSwitchHistory) error {
	// #3133: mas_kill_switch_history has no org_id column, so the caller's org
	// is an explicit parameter — the RLS wrap has nothing else to key on.
	if m.recordHistErr != nil {
		return m.recordHistErr
	}
	// Store by kill switch ID
	m.history[h.KillSwitchID] = append(m.history[h.KillSwitchID], h)
	return nil
}

func (m *MockKillSwitchRepository) GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*KillSwitchHistory, error) {
	if m.getHistoryErr != nil {
		return nil, m.getHistoryErr
	}
	// Find the kill switch to get its ID
	key := orgID + ":" + systemID
	ks, ok := m.killSwitches[key]
	if !ok {
		return nil, nil
	}
	history := m.history[ks.ID]
	if limit > 0 && len(history) > limit {
		history = history[:limit]
	}
	return history, nil
}

func TestNewKillSwitchHandler(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestKillSwitchHandler_RegisterRoutes(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// Should create new kill switch if not exists
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_HandleKillSwitchRoute_Options(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/killswitch/sys-001", nil)
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRoute(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_HandleKillSwitchRoute_MissingOrgID(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001", nil)
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRoute(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_HandleKillSwitchRoute_MissingSystemID(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRoute(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_HandleKillSwitch_GetSuccess(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchEnabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitch(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillSwitchHandler_HandleKillSwitch_CreateNew(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitch(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var ks KillSwitch
	if err := json.NewDecoder(rec.Body).Decode(&ks); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// New kill switches are created with enabled status by default
	if ks.Status != KillSwitchEnabled {
		t.Errorf("Expected status enabled, got %s", ks.Status)
	}
}

func TestKillSwitchHandler_HandleKillSwitch_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitch(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Configure_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchEnabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	accuracy := 0.75
	bias := 0.05
	body := ConfigureKillSwitchRequest{
		AutoTriggerEnabled: true,
		AccuracyThreshold:  &accuracy,
		BiasThreshold:      &bias,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/configure", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "admin")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchConfigure(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillSwitchHandler_Configure_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/configure", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchConfigure(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Configure_InvalidJSON(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/configure", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchConfigure(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Trigger_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchEnabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	body := TriggerKillSwitchRequest{
		Reason: "Model accuracy dropped below threshold",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/trigger", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchTrigger(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := response["message"]; !ok {
		t.Error("Expected message in response")
	}
}

func TestKillSwitchHandler_Trigger_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/trigger", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchTrigger(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Trigger_InvalidJSON(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/trigger", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchTrigger(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Trigger_AlreadyTriggered(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:          "ks-123",
		OrgID:       "test-org",
		SystemID:    "sys-001",
		Status:      KillSwitchTriggered,
		TriggeredAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	body := TriggerKillSwitchRequest{
		Reason: "Another trigger attempt",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/trigger", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "operator")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchTrigger(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("Expected status 409, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillSwitchHandler_Restore_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:          "ks-123",
		OrgID:       "test-org",
		SystemID:    "sys-001",
		Status:      KillSwitchTriggered,
		TriggeredAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	body := RestoreKillSwitchRequest{
		Reason: "Issue resolved, resuming operations",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/restore", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "supervisor")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRestore(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if _, ok := response["message"]; !ok {
		t.Error("Expected message in response")
	}
}

func TestKillSwitchHandler_Restore_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/restore", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRestore(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Restore_InvalidJSON(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/restore", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRestore(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_History_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchEnabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	repo.history["ks-123"] = []*KillSwitchHistory{
		{
			ID:             "hist-1",
			KillSwitchID:   "ks-123",
			Action:         "enabled",
			PreviousStatus: "disabled",
			NewStatus:      "enabled",
			PerformedBy:    "admin",
			PerformedAt:    now,
		},
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/history", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if count, ok := response["count"].(float64); !ok || count != 1 {
		t.Errorf("Expected count 1, got %v", response["count"])
	}
}

func TestKillSwitchHandler_History_WithLimit(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/history?limit=10", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchHistory(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_History_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/history", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchHistory(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Enable_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchDisabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/enable", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "admin")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchEnable(rec, req, "test-org", "sys-001")

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillSwitchHandler_Enable_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/enable", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchEnable(rec, req, "test-org", "sys-001")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_Disable_Success(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	now := time.Now()
	repo.killSwitches["test-org:sys-001"] = &KillSwitch{
		ID:        "ks-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    KillSwitchEnabled,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/disable", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "admin")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchDisable(rec, req, "test-org", "sys-001")

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestKillSwitchHandler_Disable_MethodNotAllowed(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/disable", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchDisable(rec, req, "test-org", "sys-001")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestKillSwitchHandler_UnknownAction(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/unknown", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchRoute(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestExtractSystemIDFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/masfeat/killswitch/sys-001", "sys-001"},
		{"/api/v1/masfeat/killswitch/sys-001/trigger", "sys-001"},
		{"/api/v1/masfeat/killswitch/sys-001/restore", "sys-001"},
		{"/api/v1/masfeat/killswitch/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractSystemIDFromPath(tt.path)
			if got != tt.want {
				t.Errorf("extractSystemIDFromPath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestKillSwitchHandler_HistoryError(t *testing.T) {
	repo := NewMockKillSwitchRepository()
	repo.getHistoryErr = errors.New("database error")
	service := NewKillSwitchService(repo, 0.10)
	handler := NewKillSwitchHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/history", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleKillSwitchHistory(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rec.Code)
	}
}
