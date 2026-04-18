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

// MockModelValidationService is a mock for testing handlers.
type MockModelValidationService struct {
	createFunc    func(ctx context.Context, orgID string, req *CreateValidationRequest) (*ModelValidation, error)
	getFunc       func(ctx context.Context, orgID, id string) (*ModelValidation, error)
	listFunc      func(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error)
	updateFunc    func(ctx context.Context, orgID, id string, req *UpdateValidationRequest) (*ModelValidation, error)
	deleteFunc    func(ctx context.Context, orgID, id string) error
	getLatestFunc func(ctx context.Context, orgID, systemID string, validationType ValidationType) (*ModelValidation, error)
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations?org_id=org-1", bytes.NewBufferString(body))
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestModelValidationHandler_ListValidations(t *testing.T) {
	mockService := &MockModelValidationService{
		listFunc: func(ctx context.Context, orgID string, params *ListValidationsParams) ([]*ModelValidation, int, error) {
			return []*ModelValidation{
				{ID: "val-1", OrgID: orgID, SystemID: "sys-1"},
				{ID: "val-2", OrgID: orgID, SystemID: "sys-1"},
			}, 2, nil
		},
	}
	handler := NewModelValidationHandler(mockService)

	t.Run("list validations", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations?org_id=org-1", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations?org_id=org-1&system_id=sys-1&validation_type=development&limit=10", nil)
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("with date filters", func(t *testing.T) {
		startDate := time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339)
		endDate := time.Now().Format(time.RFC3339)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations?org_id=org-1&start_date="+startDate+"&end_date="+endDate, nil)
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
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
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations/val-123?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("validation not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations/not-found?org_id=org-1", nil)
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
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/rbi/validations/val-123?org_id=org-1", bytes.NewBufferString(body))
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
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/validations/val-123?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleValidationByID(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent validation", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/validations/not-found?org_id=org-1", nil)
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations/val-123/findings?org_id=org-1", bytes.NewBufferString(body))
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
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/validations?org_id=org-1", nil)
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
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/validations?org_id=org-1", nil)
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations?org_id=org-1", bytes.NewBufferString(body))
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/validations?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleValidations(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}
