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
	"net/url"
	"testing"
	"time"
)

// MockModelValidationService is a mock for testing handlers.
type MockModelValidationService struct {
	createFunc     func(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error)
	getFunc        func(ctx context.Context, orgID, id string) (*ModelValidation, error)
	listFunc       func(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error)
	updateFunc     func(ctx context.Context, orgID, id string, req *UpdateValidationRequest) (*ModelValidation, error)
	deleteFunc     func(ctx context.Context, orgID, id string) error
	getLatestFunc  func(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error)
	addFindingFunc func(ctx context.Context, orgID, validationID string, finding *ValidationFinding) (*ModelValidation, error)
}

func (m *MockModelValidationService) CreateValidation(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, orgID, req)
	}
	return &ModelValidation{ID: "test-id", OrgID: orgID, SystemID: req.SystemID}, nil
}

func (m *MockModelValidationService) GetValidation(ctx context.Context, orgID, id string) (*ModelValidation, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, orgID, id)
	}
	return &ModelValidation{ID: id, OrgID: orgID}, nil
}

func (m *MockModelValidationService) ListValidations(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, orgID, params)
	}
	return []*ModelValidation{{ID: "test-1", OrgID: orgID}}, 1, nil
}

func (m *MockModelValidationService) UpdateValidation(ctx context.Context, orgID, id string, req *UpdateValidationRequest) (*ModelValidation, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, orgID, id, req)
	}
	return &ModelValidation{ID: id, OrgID: orgID}, nil
}

func (m *MockModelValidationService) DeleteValidation(ctx context.Context, orgID, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, orgID, id)
	}
	return nil
}

func (m *MockModelValidationService) GetLatestValidation(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error) {
	if m.getLatestFunc != nil {
		return m.getLatestFunc(ctx, orgID, systemID, validationType)
	}
	return &ModelValidation{ID: "latest", OrgID: orgID, SystemID: systemID}, nil
}

func (m *MockModelValidationService) AddFinding(ctx context.Context, orgID, validationID string, finding *ValidationFinding) (*ModelValidation, error) {
	if m.addFindingFunc != nil {
		return m.addFindingFunc(ctx, orgID, validationID, finding)
	}
	return &ModelValidation{ID: validationID, OrgID: orgID, Findings: []ValidationFinding{*finding}}, nil
}

func TestModelValidationHandler_CreateValidation(t *testing.T) {
	mockService := &MockModelValidationService{}
	handler := NewModelValidationHandler(mockService)

	t.Run("successful creation", func(t *testing.T) {
		body := `{"system_id":"sys-1","validation_type":"development","validator_type":"internal","validator_name":"Team A","recommendation":"approve"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		body := `{"system_id":"sys-1"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := `{invalid}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestModelValidationHandler_ListValidations(t *testing.T) {
	// gotParams records what the handler actually parsed out of the query string.
	// A w.Code == 200 assertion alone cannot tell "filters parsed" from "filters
	// silently dropped" (a malformed URL such as `/api/v1/rbi/validations&system_id=sys-1`
	// leaves RawQuery empty and still returns 200), which would make the date-filter
	// subtest below exercise no date filter at all.
	var gotParams *ListValidationsParams
	mockService := &MockModelValidationService{
		listFunc: func(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
			gotParams = params
			return []*ModelValidation{
				{ID: "val-1", OrgID: orgID, SystemID: "sys-1"},
				{ID: "val-2", OrgID: orgID, SystemID: "sys-1"},
			}, 2, nil
		},
	}
	handler := NewModelValidationHandler(mockService)

	t.Run("list validations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response map[string]interface{}
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response["total"].(float64) != 2 {
			t.Errorf("Total = %v, want 2", response["total"])
		}
	})

	t.Run("with filters", func(t *testing.T) {
		gotParams = nil
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/rbi/validations?system_id=sys-1&validation_type=development&validator_type=internal&recommendation=approve&limit=10&offset=5", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotParams == nil {
			t.Fatal("ListValidations was never invoked, so no filter was parsed")
		}
		if gotParams.SystemID != "sys-1" {
			t.Errorf("SystemID = %q, want %q", gotParams.SystemID, "sys-1")
		}
		if gotParams.ValidationType != "development" {
			t.Errorf("ValidationType = %q, want %q", gotParams.ValidationType, "development")
		}
		if gotParams.ValidatorType != "internal" {
			t.Errorf("ValidatorType = %q, want %q", gotParams.ValidatorType, "internal")
		}
		if gotParams.Recommendation != "approve" {
			t.Errorf("Recommendation = %q, want %q", gotParams.Recommendation, "approve")
		}
		if gotParams.Limit != 10 {
			t.Errorf("Limit = %d, want 10", gotParams.Limit)
		}
		if gotParams.Offset != 5 {
			t.Errorf("Offset = %d, want 5", gotParams.Offset)
		}
	})

	t.Run("with date filters", func(t *testing.T) {
		gotParams = nil
		// UTC so RFC3339 renders a "Z" offset: a numeric "+05:30" offset would be
		// decoded as a space by url.Values and never reach time.Parse.
		startDate := time.Now().UTC().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
		endDate := time.Now().UTC().Format(time.RFC3339)
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/rbi/validations?start_date="+url.QueryEscape(startDate)+"&end_date="+url.QueryEscape(endDate), nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotParams == nil {
			t.Fatal("ListValidations was never invoked, so no date filter was parsed")
		}
		if gotParams.StartDate == nil {
			t.Fatalf("StartDate is nil, want %s parsed from the query string", startDate)
		}
		if got := gotParams.StartDate.UTC().Format(time.RFC3339); got != startDate {
			t.Errorf("StartDate = %s, want %s", got, startDate)
		}
		if gotParams.EndDate == nil {
			t.Fatalf("EndDate is nil, want %s parsed from the query string", endDate)
		}
		if got := gotParams.EndDate.UTC().Format(time.RFC3339); got != endDate {
			t.Errorf("EndDate = %s, want %s", got, endDate)
		}
	})
}

func TestModelValidationHandler_GetValidation(t *testing.T) {
	mockService := &MockModelValidationService{
		getFunc: func(ctx context.Context, orgID, id string) (*ModelValidation, error) {
			if id == "not-found" {
				return nil, ErrValidationNotFound
			}
			return &ModelValidation{ID: id, OrgID: orgID}, nil
		},
	}
	handler := NewModelValidationHandler(mockService)

	t.Run("get existing validation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations/val-123", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("validation not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations/not-found", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestModelValidationHandler_UpdateValidation(t *testing.T) {
	mockService := &MockModelValidationService{}
	handler := NewModelValidationHandler(mockService)

	t.Run("update validation", func(t *testing.T) {
		body := `{"recommendation":"approve"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/rbi/validations/val-123", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestModelValidationHandler_DeleteValidation(t *testing.T) {
	mockService := &MockModelValidationService{
		deleteFunc: func(ctx context.Context, orgID, id string) error {
			if id == "not-found" {
				return ErrValidationNotFound
			}
			return nil
		},
	}
	handler := NewModelValidationHandler(mockService)

	t.Run("delete existing validation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/validations/val-123", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent validation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/validations/not-found", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestModelValidationHandler_AddFinding(t *testing.T) {
	mockService := &MockModelValidationService{
		addFindingFunc: func(ctx context.Context, orgID, validationID string, finding *ValidationFinding) (*ModelValidation, error) {
			return &ModelValidation{
				ID:       validationID,
				OrgID:    orgID,
				Findings: []ValidationFinding{*finding},
			}, nil
		},
	}
	handler := NewModelValidationHandler(mockService)

	t.Run("add finding", func(t *testing.T) {
		body := `{"category":"bias","severity":"high","title":"Gender bias","description":"Model shows gender bias"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations/val-123/findings", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response ModelValidation
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if len(response.Findings) != 1 {
			t.Errorf("Findings length = %v, want 1", len(response.Findings))
		}
	})
}

func TestModelValidationHandler_CORS(t *testing.T) {
	mockService := &MockModelValidationService{}
	handler := NewModelValidationHandler(mockService)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/rbi/validations", nil)
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Missing CORS header")
		}
	})
}

func TestModelValidationHandler_MethodNotAllowed(t *testing.T) {
	mockService := &MockModelValidationService{}
	handler := NewModelValidationHandler(mockService)

	t.Run("PUT not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/validations", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestModelValidationHandler_RegisterRoutes(t *testing.T) {
	mockService := &MockModelValidationService{}
	handler := NewModelValidationHandler(mockService)
	mux := http.NewServeMux()

	handler.RegisterRoutes(mux)

	t.Run("routes are registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestModelValidationHandler_ServiceErrors(t *testing.T) {
	t.Run("system not found", func(t *testing.T) {
		mockService := &MockModelValidationService{
			createFunc: func(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error) {
				return nil, ErrSystemNotFound
			},
		}
		handler := NewModelValidationHandler(mockService)

		body := `{"system_id":"sys-1","validation_type":"development","validator_type":"internal","validator_name":"Test","recommendation":"approve"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})

	t.Run("invalid input", func(t *testing.T) {
		mockService := &MockModelValidationService{
			createFunc: func(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error) {
				return nil, ErrInvalidInput
			},
		}
		handler := NewModelValidationHandler(mockService)

		body := `{"system_id":"sys-1"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}
