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

// MockAssessmentRepository implements AssessmentRepository for testing.
type MockAssessmentRepository struct {
	assessments       map[string]*FEATAssessment
	createErr         error
	getByIDErr        error
	listErr           error
	updateErr         error
	getLatestErr      error
}

func NewMockAssessmentRepository() *MockAssessmentRepository {
	return &MockAssessmentRepository{
		assessments: make(map[string]*FEATAssessment),
	}
}

func (m *MockAssessmentRepository) Create(ctx context.Context, assessment *FEATAssessment) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.assessments[assessment.ID] = assessment
	return nil
}

func (m *MockAssessmentRepository) GetByID(ctx context.Context, orgID, id string) (*FEATAssessment, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	assessment, ok := m.assessments[id]
	if !ok || assessment.OrgID != orgID {
		return nil, nil
	}
	return assessment, nil
}

func (m *MockAssessmentRepository) List(ctx context.Context, orgID string, params ListParams) ([]*FEATAssessment, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var result []*FEATAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID {
			if params.Status == "" || string(a.Status) == params.Status {
				if params.SystemID == "" || a.SystemID == params.SystemID {
					result = append(result, a)
				}
			}
		}
	}
	return result, nil
}

func (m *MockAssessmentRepository) Update(ctx context.Context, assessment *FEATAssessment) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.assessments[assessment.ID] = assessment
	return nil
}

func (m *MockAssessmentRepository) GetLatestForSystem(ctx context.Context, orgID, systemID string) (*FEATAssessment, error) {
	if m.getLatestErr != nil {
		return nil, m.getLatestErr
	}
	var latest *FEATAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID && a.SystemID == systemID {
			if latest == nil || a.CreatedAt.After(latest.CreatedAt) {
				latest = a
			}
		}
	}
	return latest, nil
}

func TestNewAssessmentHandler(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestAssessmentHandler_RegisterRoutes(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessments_Options(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/assessments", nil)
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessments_MissingOrgID(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments", nil)
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessments_MethodNotAllowed(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/masfeat/assessments", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestAssessmentHandler_CreateAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	now := time.Now()
	// Use the same ID as the system_id in the request body
	registryRepo.systems["sys-001"] = &AISystemRegistry{
		ID:        "sys-001",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    SystemStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	body := CreateAssessmentRequest{
		SystemID:       "sys-001",
		AssessmentType: "initial",
		Assessors:      []string{"assessor1@example.com"},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var created FEATAssessment
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if created.SystemID != "sys-001" {
		t.Errorf("Expected system ID sys-001, got %s", created.SystemID)
	}
	if created.Status != FEATStatusPending {
		t.Errorf("Expected status pending, got %s", created.Status)
	}
}

func TestAssessmentHandler_CreateAssessment_InvalidJSON(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestAssessmentHandler_CreateAssessment_SystemNotFound(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	body := CreateAssessmentRequest{
		SystemID:       "nonexistent",
		AssessmentType: "initial",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_ListAssessments_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	assessmentRepo.assessments["1"] = &FEATAssessment{
		ID:        "1",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    FEATStatusPending,
		CreatedAt: now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

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

func TestAssessmentHandler_ListAssessments_WithFilters(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments?status=pending&system_id=sys-001&limit=10&offset=0", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessmentByID_Options(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/masfeat/assessments/assess-123", nil)
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessmentByID_MissingID(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestAssessmentHandler_GetAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	assessmentRepo.assessments["assess-123"] = &FEATAssessment{
		ID:        "assess-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    FEATStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_GetAssessment_NotFound(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/nonexistent", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestAssessmentHandler_UpdateAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	assessmentRepo.assessments["assess-123"] = &FEATAssessment{
		ID:        "assess-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    FEATStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	score := 85.0
	updateReq := UpdateAssessmentRequest{
		FairnessScore: &score,
	}
	bodyJSON, _ := json.Marshal(updateReq)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/masfeat/assessments/assess-123", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_UpdateAssessment_InvalidJSON(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/masfeat/assessments/assess-123", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestAssessmentHandler_SubmitAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	fairness := 85.0
	ethics := 90.0
	accountability := 88.0
	transparency := 92.0
	assessmentRepo.assessments["assess-123"] = &FEATAssessment{
		ID:                  "assess-123",
		OrgID:               "test-org",
		SystemID:            "sys-001",
		Status:              FEATStatusInProgress,
		FairnessScore:       &fairness,
		EthicsScore:         &ethics,
		AccountabilityScore: &accountability,
		TransparencyScore:   &transparency,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/submit", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_SubmitAssessment_MethodNotAllowed(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/assess-123/submit", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestAssessmentHandler_ApproveAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	assessmentRepo.assessments["assess-123"] = &FEATAssessment{
		ID:        "assess-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    FEATStatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/approve", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "approver")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_ApproveAssessment_MethodNotAllowed(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/assess-123/approve", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestAssessmentHandler_RejectAssessment_Success(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	now := time.Now()
	assessmentRepo.assessments["assess-123"] = &FEATAssessment{
		ID:        "assess-123",
		OrgID:     "test-org",
		SystemID:  "sys-001",
		Status:    FEATStatusCompleted,
		CreatedAt: now,
		UpdatedAt: now,
	}
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	body := map[string]string{"reason": "Insufficient evidence"}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/reject", bytes.NewReader(bodyJSON))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "reviewer")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAssessmentHandler_RejectAssessment_InvalidJSON(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/reject", bytes.NewReader([]byte("invalid")))
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestAssessmentHandler_RejectAssessment_MethodNotAllowed(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/assess-123/reject", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestAssessmentHandler_UnknownAction(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/unknown", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestAssessmentHandler_HandleAssessmentByID_MethodNotAllowed(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/masfeat/assessments/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessmentByID(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", rec.Code)
	}
}

func TestAssessmentHandler_ListError(t *testing.T) {
	assessmentRepo := NewMockAssessmentRepository()
	assessmentRepo.listErr = errors.New("database error")
	registryRepo := NewMockRegistryRepository()
	service := NewAssessmentService(assessmentRepo, registryRepo, 12)
	handler := NewAssessmentHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	handler.handleAssessments(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", rec.Code)
	}
}
