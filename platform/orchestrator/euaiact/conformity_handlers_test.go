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
)

// MockConformityRepository implements ConformityRepository for testing.
type MockConformityRepository struct {
	assessments map[string]*ConformityAssessment
	createErr   error
	getByIDErr  error
	listErr     error
	updateErr   error
	listTotal   int64
}

func NewMockConformityRepository() *MockConformityRepository {
	return &MockConformityRepository{
		assessments: make(map[string]*ConformityAssessment),
	}
}

func (m *MockConformityRepository) Create(ctx context.Context, assessment *ConformityAssessment) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.assessments[assessment.ID] = assessment
	return nil
}

// GetByID enforces the ORG PREDICATE, matching production.
//
// A mock that ignored orgID would replicate the pre-#3241 vulnerable semantics
// and every mock-based test above it would CERTIFY the cross-org bug rather
// than catch it (`[[feedback_mocks_that_replicate_prod_semantics_certify_the_bug]]`).
// Where it diverges from production it diverges STRICTER: an empty orgID is a
// miss here, and production also refuses it.
func (m *MockConformityRepository) GetByID(ctx context.Context, orgID, id string) (*ConformityAssessment, error) {
	if m.getByIDErr != nil {
		return nil, m.getByIDErr
	}
	assessment, ok := m.assessments[id]
	if !ok || orgID == "" || assessment.OrgID != orgID {
		return nil, ErrAssessmentNotFound
	}
	return assessment, nil
}

func (m *MockConformityRepository) List(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error) {
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	var assessments []*ConformityAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID {
			assessments = append(assessments, a)
		}
	}
	return assessments, m.listTotal, nil
}

func (m *MockConformityRepository) Update(ctx context.Context, assessment *ConformityAssessment) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	existing, ok := m.assessments[assessment.ID]
	if !ok || existing.OrgID != assessment.OrgID {
		return ErrAssessmentNotFound
	}
	m.assessments[assessment.ID] = assessment
	return nil
}

func (m *MockConformityRepository) Delete(ctx context.Context, orgID, id string) error {
	existing, ok := m.assessments[id]
	if !ok || orgID == "" || existing.OrgID != orgID {
		return ErrAssessmentNotFound
	}
	delete(m.assessments, id)
	return nil
}

func (m *MockConformityRepository) GetBySystemID(ctx context.Context, orgID, systemID string) ([]*ConformityAssessment, error) {
	var assessments []*ConformityAssessment
	for _, a := range m.assessments {
		if a.OrgID == orgID && a.SystemID == systemID {
			assessments = append(assessments, a)
		}
	}
	return assessments, nil
}

func TestNewConformityHandler(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != service {
		t.Error("Handler service not set correctly")
	}
}

func TestConformityHandler_RegisterRoutes(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Test that routes are registered
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code == http.StatusNotFound {
		t.Error("Expected route to be registered")
	}
}

func TestConformityHandler_HandleConformity_MethodNotAllowed(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/euaiact/conformity", nil)
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestConformityHandler_CreateAssessment_MissingOrgID(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_id": "sys-1", "system_name": "Test System", "risk_category": "high-risk"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_CreateAssessment_InvalidJSON(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString("invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_CreateAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_id": "sys-1", "system_name": "Test System", "risk_category": "high-risk", "assessors": ["user1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "creator")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

func TestConformityHandler_ListAssessments_MissingOrgID(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity", nil)
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_ListAssessments_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-1"] = &ConformityAssessment{ID: "assess-1", OrgID: "test-org"}
	repo.listTotal = 1

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_ListAssessments_WithPagination(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity?limit=10&offset=5&status=draft", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var response map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&response)

	if response["limit"].(float64) != 10 {
		t.Errorf("Expected limit 10, got %v", response["limit"])
	}
	if response["offset"].(float64) != 5 {
		t.Errorf("Expected offset 5, got %v", response["offset"])
	}
}

func TestConformityHandler_ListAssessments_Error(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.listErr = errors.New("database error")

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestConformityHandler_HandleByID_MissingID(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_GetAssessment_NotFound(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/nonexistent", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, rr.Code)
	}
}

func TestConformityHandler_GetAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:    "assess-123",
		OrgID: "test-org",
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_GetAssessment_Error(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.getByIDErr = errors.New("database error")

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, rr.Code)
	}
}

func TestConformityHandler_UpdateAssessment_InvalidJSON(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{ID: "assess-123"}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/euaiact/conformity/assess-123", bytes.NewBufferString("invalid"))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_UpdateAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusDraft,
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_name": "Updated System"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/euaiact/conformity/assess-123", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_HandleByID_MethodNotAllowed(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/euaiact/conformity/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestConformityHandler_HandleByID_InvalidAction(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/invalid-action", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_SubmitAssessment_MethodNotAllowed(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123/submit", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestConformityHandler_SubmitAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusDraft,
		Requirements: []RequirementStatus{
			{RequirementID: "req-1", Article: "Article 9", Description: "Risk management", Status: "compliant"},
		},
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/submit", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "submitter")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestConformityHandler_ApproveAssessment_MethodNotAllowed(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123/approve", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestConformityHandler_ApproveAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusSubmitted,
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"validity_years": 2}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/approve", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "approver")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestConformityHandler_ApproveAssessment_DefaultValidity(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusSubmitted,
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/approve", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "approver")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_RejectAssessment_MethodNotAllowed(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123/reject", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestConformityHandler_RejectAssessment_InvalidJSON(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/reject", bytes.NewBufferString("invalid"))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_RejectAssessment_Success(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusSubmitted,
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"reason": "Does not meet requirements"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/reject", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "reviewer")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestConformityHandler_CreateAssessment_ServiceError(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.createErr = errors.New("database error")

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_id": "sys-1", "system_name": "Test System", "risk_category": "high-risk", "assessors": ["user1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "creator")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	// The handler returns 400 for service errors
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 400 or 500, got %d", rr.Code)
	}
}

func TestConformityHandler_ListAssessments_InvalidLimit(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	// Test with limit > MaxListLimit (should use default)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity?limit=10000", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_ListAssessments_NegativeLimit(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	// Test with negative limit (should use default)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity?limit=-5", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_ListAssessments_NegativeOffset(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	// Test with negative offset (should use default 0)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity?offset=-10", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_ListAssessments_InvalidLimitString(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	// Test with non-numeric limit (should use default)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity?limit=abc", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestConformityHandler_UpdateAssessment_NotFound(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_name": "Updated System"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/euaiact/conformity/nonexistent", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	// Service returns error "assessment not found" which handler returns as 400
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 400 or 404, got %d", rr.Code)
	}
}

func TestConformityHandler_UpdateAssessment_ServiceError(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusDraft,
	}
	repo.updateErr = errors.New("database error")

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_name": "Updated System"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/euaiact/conformity/assess-123", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	// Should return error status
	if rr.Code == http.StatusOK {
		t.Errorf("Expected error status, got %d", rr.Code)
	}
}

func TestConformityHandler_SubmitAssessment_NotFound(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/nonexistent/submit", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "submitter")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	// Service returns error "assessment not found" which handler returns as 400
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 400 or 404, got %d", rr.Code)
	}
}

func TestConformityHandler_ApproveAssessment_NotFound(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/nonexistent/approve", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "approver")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	// Service returns error "assessment not found" which handler returns as 400
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 400 or 404, got %d", rr.Code)
	}
}

func TestConformityHandler_RejectAssessment_NotFound(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"reason": "Does not meet requirements"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/nonexistent/reject", bytes.NewBufferString(body))
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "reviewer")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	// Service returns error "assessment not found" which handler returns as 400
	if rr.Code != http.StatusBadRequest && rr.Code != http.StatusNotFound {
		t.Errorf("Expected status 400 or 404, got %d", rr.Code)
	}
}

func TestConformityHandler_RejectAssessment_MissingReason(t *testing.T) {
	repo := NewMockConformityRepository()
	repo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusSubmitted,
	}

	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	// Empty body - no reason provided
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/reject", nil)
	req.Header.Set("X-Org-ID", "test-org") // #3241: by-id paths require an authenticated organization
	req.Header.Set("X-User-ID", "reviewer")
	rr := httptest.NewRecorder()

	handler.handleConformityByID(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestConformityHandler_CreateAssessment_WithTenantIDHeader(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_id": "sys-1", "system_name": "Test System", "risk_category": "high-risk", "assessors": ["user1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "test-tenant") // Using X-Tenant-ID instead of X-Org-ID
	req.Header.Set("X-User-ID", "creator")
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusCreated, rr.Code, rr.Body.String())
	}
}

func TestConformityHandler_CreateAssessment_NoUserID(t *testing.T) {
	repo := NewMockConformityRepository()
	service := NewConformityService(repo)
	handler := NewConformityHandler(service)

	body := `{"system_id": "sys-1", "system_name": "Test System", "risk_category": "high-risk", "assessors": ["user1"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "test-org")
	// No X-User-ID set - should default to "system"
	rr := httptest.NewRecorder()

	handler.handleConformity(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, rr.Code)
	}
}
