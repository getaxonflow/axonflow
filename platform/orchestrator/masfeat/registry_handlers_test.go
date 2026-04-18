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

// MockRegistryRepository implements RegistryRepository for testing.
type MockRegistryRepository struct {
	systems         map[string]*AISystemRegistry
	createErr       error
	getByIDErr      error
	getBySystemIDErr error
	listErr         error
	updateErr       error
	deleteErr       error
	summaryErr      error
}

func NewMockRegistryRepository() *MockRegistryRepository {
	return &MockRegistryRepository{
		systems: make(map[string]*AISystemRegistry),
	}
}

func (m *MockRegistryRepository) Create(ctx context.Context, system *AISystemRegistry) error {
	if m.createErr != nil {
		return m.createErr
	}
	// Set ID if not already set
	if system.ID == "" {
		system.ID = "gen-" + system.SystemID
	}
	// Calculate materiality like the real repository does
	system.MaterialityClassification = calculateMateriality(
		system.RiskRatingImpact,
		system.RiskRatingComplexity,
		system.RiskRatingReliance,
	)
	m.systems[system.ID] = system
	return nil
}

func (m *MockRegistryRepository) GetByID(ctx context.Context, orgID, id string) (*AISystemRegistry, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	system, ok := m.systems[id]
	if !ok || system.OrgID != orgID {
		return nil, nil
	}
	return system, nil
}

func (m *MockRegistryRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystemRegistry, error) {
	if m.getBySystemIDErr != nil {
		return nil, m.getBySystemIDErr
	}
	for _, s := range m.systems {
		if s.OrgID == orgID && s.SystemID == systemID {
			return s, nil
		}
	}
	return nil, nil
}

func (m *MockRegistryRepository) List(ctx context.Context, orgID string, params ListParams) ([]*AISystemRegistry, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var result []*AISystemRegistry
	for _, s := range m.systems {
		if s.OrgID == orgID {
			if params.Status == "" || string(s.Status) == params.Status {
				result = append(result, s)
			}
		}
	}
	return result, nil
}

func (m *MockRegistryRepository) Update(ctx context.Context, system *AISystemRegistry) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.systems[system.ID] = system
	return nil
}

func (m *MockRegistryRepository) Delete(ctx context.Context, orgID, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	if system, ok := m.systems[id]; ok && system.OrgID == orgID {
		system.Status = SystemStatusRetired
		return nil
	}
	return errors.New("system not found")
}

func (m *MockRegistryRepository) GetSummary(ctx context.Context, orgID string) (*RegistrySummary, error) {
	if m.summaryErr != nil {
		return nil, m.summaryErr
	}
	summary := &RegistrySummary{OrgID: orgID}
	for _, s := range m.systems {
		if s.OrgID == orgID {
			summary.TotalSystems++
			if s.Status == SystemStatusActive {
				summary.ActiveSystems++
			}
			switch s.MaterialityClassification {
			case MaterialityHigh:
				summary.HighMateriality++
			case MaterialityMedium:
				summary.MediumMateriality++
			case MaterialityLow:
				summary.LowMateriality++
			}
		}
	}
	return summary, nil
}

func (m *MockRegistryRepository) CountByStatus(ctx context.Context, orgID string) (map[SystemStatus]int, error) {
	counts := make(map[SystemStatus]int)
	for _, s := range m.systems {
		if s.OrgID == orgID {
			counts[s.Status]++
		}
	}
	return counts, nil
}

func TestNewRegistryHandler(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestRegistryHandler_RegisterRoutes(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test that routes are registered by making requests
	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	// Should return 200 with empty list
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistry_Options(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/registry", nil)
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistry_MissingOrgID(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry", nil)
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistry_MethodNotAllowed(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/masfeat/registry", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestRegistryHandler_CreateSystem_Success(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	body := CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Credit Scoring Model",
		UseCase:              UseCaseCreditScoring,
		OwnerTeam:            "ML Team",
		OwnerEmail:           "ml-team@example.com",
		RiskRatingImpact:     5,  // High impact
		RiskRatingComplexity: 4,  // High complexity
		RiskRatingReliance:   4,  // High reliance (sum = 13 >= 12 = high materiality)
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/registry", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var created AISystemRegistry
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if created.SystemID != "sys-001" {
		t.Errorf("Expected system ID sys-001, got %s", created.SystemID)
	}
	// Sum of risk ratings (5+4+4=13) >= 12 means high materiality
	if created.MaterialityClassification != MaterialityHigh {
		t.Errorf("Expected high materiality, got %s", created.MaterialityClassification)
	}
}

func TestRegistryHandler_CreateSystem_InvalidJSON(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/registry", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestRegistryHandler_ListSystems_Success(t *testing.T) {
	repo := NewMockRegistryRepository()
	repo.systems["1"] = &AISystemRegistry{
		ID:       "1",
		OrgID:    "test-org",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if count, ok := response["count"].(float64); !ok || count != 1 {
		t.Errorf("Expected count 1, got %v", response["count"])
	}
}

func TestRegistryHandler_ListSystems_WithFilters(t *testing.T) {
	repo := NewMockRegistryRepository()
	repo.systems["1"] = &AISystemRegistry{
		ID:       "1",
		OrgID:    "test-org",
		SystemID: "sys-001",
		Status:   SystemStatusActive,
	}
	repo.systems["2"] = &AISystemRegistry{
		ID:       "2",
		OrgID:    "test-org",
		SystemID: "sys-002",
		Status:   SystemStatusDraft,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry?status=active&limit=10&offset=0", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistrySummary_Success(t *testing.T) {
	repo := NewMockRegistryRepository()
	repo.systems["1"] = &AISystemRegistry{
		ID:                       "1",
		OrgID:                    "test-org",
		Status:                   SystemStatusActive,
		MaterialityClassification: MaterialityHigh,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry/summary", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistrySummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var summary RegistrySummary
	if err := json.NewDecoder(rec.Body).Decode(&summary); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if summary.TotalSystems != 1 {
		t.Errorf("Expected 1 total system, got %d", summary.TotalSystems)
	}
	if summary.HighMateriality != 1 {
		t.Errorf("Expected 1 high materiality, got %d", summary.HighMateriality)
	}
}

func TestRegistryHandler_HandleRegistrySummary_Options(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/registry/summary", nil)
	rec := httptest.NewRecorder()

	handler.handleRegistrySummary(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistrySummary_MethodNotAllowed(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/registry/summary", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistrySummary(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistryByID_GetSuccess(t *testing.T) {
	repo := NewMockRegistryRepository()
	now := time.Now()
	repo.systems["sys-123"] = &AISystemRegistry{
		ID:        "sys-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    SystemStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry/sys-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegistryHandler_HandleRegistryByID_NotFound(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry/nonexistent", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistryByID_MissingID(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry/", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestRegistryHandler_HandleRegistryByID_Update(t *testing.T) {
	repo := NewMockRegistryRepository()
	now := time.Now()
	repo.systems["sys-123"] = &AISystemRegistry{
		ID:         "sys-123",
		OrgID:      "test-org",
		SystemID:   "sys-001",
		SystemName: "Old Name",
		Status:     SystemStatusActive,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	updateReq := UpdateRegistryRequest{
		SystemName: "New Name",
	}
	bodyJSON, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/masfeat/registry/sys-123", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegistryHandler_HandleRegistryByID_Delete(t *testing.T) {
	repo := NewMockRegistryRepository()
	now := time.Now()
	repo.systems["sys-123"] = &AISystemRegistry{
		ID:        "sys-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    SystemStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/masfeat/registry/sys-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRegistryHandler_HandleRegistryByID_Options(t *testing.T) {
	repo := NewMockRegistryRepository()
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/registry/sys-123", nil)
	rec := httptest.NewRecorder()

	handler.handleRegistryByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestExtractIDFromPath(t *testing.T) {
	tests := []struct {
		path   string
		prefix string
		want   string
	}{
		{"/api/v1/masfeat/registry/sys-123", "/api/v1/masfeat/registry/", "sys-123"},
		{"/api/v1/masfeat/registry/sys-123/", "/api/v1/masfeat/registry/", "sys-123"},
		{"/api/v1/masfeat/registry/sys-123/action", "/api/v1/masfeat/registry/", "sys-123"},
		{"/api/v1/masfeat/registry/", "/api/v1/masfeat/registry/", ""},
		{"/different/path", "/api/v1/masfeat/registry/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractIDFromPath(tt.path, tt.prefix)
			if got != tt.want {
				t.Errorf("extractIDFromPath(%q, %q) = %q, want %q", tt.path, tt.prefix, got, tt.want)
			}
		})
	}
}

func TestRegistryHandler_CreateSystem_Duplicate(t *testing.T) {
	repo := NewMockRegistryRepository()
	repo.systems["1"] = &AISystemRegistry{
		ID:       "1",
		OrgID:    "test-org",
		SystemID: "sys-001",
	}
	service := NewRegistryService(repo)
	handler := NewRegistryHandler(service)

	body := CreateRegistryRequest{
		SystemID:             "sys-001",
		SystemName:           "Duplicate System",
		UseCase:              UseCaseCreditScoring,
		OwnerTeam:            "ML Team",
		OwnerEmail:           "ml-team@example.com",
		RiskRatingImpact:     3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   3,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/registry", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleRegistry(rec, req)

	if rec.Code != http.StatusConflict {
		t.Errorf("Expected status 409 for duplicate, got %d: %s", rec.Code, rec.Body.String())
	}
}
