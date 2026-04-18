// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

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

// MockExportRepository implements ExportRepository for testing.
type MockExportRepository struct {
	exports       map[string]*Export
	createErr     error
	getByIDErr    error
	listErr       error
	updateErr     error
	listTotal     int64
}

func NewMockExportRepository() *MockExportRepository {
	return &MockExportRepository{
		exports: make(map[string]*Export),
	}
}

func (m *MockExportRepository) Create(ctx context.Context, export *Export) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.exports[export.ID] = export
	return nil
}

func (m *MockExportRepository) GetByID(ctx context.Context, id string) (*Export, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	export, ok := m.exports[id]
	if !ok {
		return nil, nil
	}
	return export, nil
}

func (m *MockExportRepository) List(ctx context.Context, orgID string, limit, offset int) ([]*Export, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var exports []*Export
	for _, e := range m.exports {
		if e.OrgID == orgID {
			exports = append(exports, e)
		}
	}
	return exports, m.listTotal, nil
}

func (m *MockExportRepository) Update(ctx context.Context, export *Export) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.exports[export.ID] = export
	return nil
}

func (m *MockExportRepository) Delete(ctx context.Context, id string) error {
	delete(m.exports, id)
	return nil
}

func TestNewExportHandler(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestExportHandler_RegisterRoutes(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test that routes are registered by making requests
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	// Should not return 404 (route found)
	if rr.Code == http.StatusNotFound {
		t.Error("Expected route to be registered")
	}
}

func TestExportHandler_HandleExport_MethodNotAllowed(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/euaiact/export", nil)
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestExportHandler_CreateExport_MissingOrgID(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	body := `{"export_type": "full_audit", "format": "json"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_CreateExport_InvalidJSON(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_CreateExport_InvalidDateFrom(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	body := `{"export_type": "full_audit", "format": "json", "date_from": "invalid-date"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_CreateExport_InvalidDateTo(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	dateFrom := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	body := `{"export_type": "full_audit", "format": "json", "date_from": "` + dateFrom + `", "date_to": "invalid-date"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_CreateExport_InvalidExportType(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	body := `{"export_type": "invalid_type", "format": "json"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_CreateExport_Success(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	body := `{"export_type": "full_audit", "format": "json"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("Expected status %d, got %d", http.StatusAccepted, rr.Code)
	}

	var export Export
	if err := json.NewDecoder(rr.Body).Decode(&export); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if export.OrgID != "test-org" {
		t.Errorf("Expected OrgID 'test-org', got '%s'", export.OrgID)
	}
	if export.RequestedBy != "test-user" {
		t.Errorf("Expected RequestedBy 'test-user', got '%s'", export.RequestedBy)
	}
}

func TestExportHandler_CreateExport_WithTenantID(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	body := `{"export_type": "full_audit", "format": "json"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-123")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusAccepted {
		t.Errorf("Expected status %d, got %d", http.StatusAccepted, rr.Code)
	}
}

func TestExportHandler_ListExports_MissingOrgID(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export", nil)
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_ListExports_Success(t *testing.T) {
	repo := NewMockExportRepository()
	// Add some exports
	repo.exports["export-1"] = &Export{ID: "export-1", OrgID: "test-org", Status: ExportStatusCompleted}
	repo.exports["export-2"] = &Export{ID: "export-2", OrgID: "test-org", Status: ExportStatusPending}
	repo.listTotal = 2

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["total"].(float64) != 2 {
		t.Errorf("Expected total 2, got %v", response["total"])
	}
}

func TestExportHandler_ListExports_WithPagination(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export?limit=10&offset=5", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["limit"].(float64) != 10 {
		t.Errorf("Expected limit 10, got %v", response["limit"])
	}
	if response["offset"].(float64) != 5 {
		t.Errorf("Expected offset 5, got %v", response["offset"])
	}
}

func TestExportHandler_ListExports_Error(t *testing.T) {
	repo := NewMockExportRepository()
	repo.listErr = errors.New("database error")

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleExport(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestExportHandler_HandleExportByID_MissingID(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_HandleExportByID_NotFound(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/nonexistent", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestExportHandler_HandleExportByID_Success(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:     "export-123",
		OrgID:  "test-org",
		Status: ExportStatusCompleted,
	}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestExportHandler_HandleExportByID_MethodNotAllowed(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{ID: "export-123"}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/euaiact/export/export-123", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestExportHandler_HandleExportByID_Error(t *testing.T) {
	repo := NewMockExportRepository()
	repo.getByIDErr = errors.New("database error")

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestExportHandler_DownloadExport_NotCompleted(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:     "export-123",
		Status: ExportStatusPending,
	}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123/download", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestExportHandler_DownloadExport_NoFile(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:       "export-123",
		Status:   ExportStatusCompleted,
		FilePath: "",
	}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123/download", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestExportHandler_DownloadExport_Success(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:       "export-123",
		Status:   ExportStatusCompleted,
		FilePath: "/exports/export-123.json",
		FileSize: 1024,
		Format:   ExportFormatJSON,
	}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123/download", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestExportHandler_DownloadExport_MethodNotAllowed(t *testing.T) {
	repo := NewMockExportRepository()
	repo.exports["export-123"] = &Export{
		ID:       "export-123",
		Status:   ExportStatusCompleted,
		FilePath: "/exports/export-123.json",
	}

	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/export/export-123/download", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestExportHandler_DownloadExport_NotFound(t *testing.T) {
	repo := NewMockExportRepository()
	service := NewExportService(repo, nil)
	handler := NewExportHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/nonexistent/download", nil)
	rr := httptest.NewRecorder()

	handler.handleExportByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}
