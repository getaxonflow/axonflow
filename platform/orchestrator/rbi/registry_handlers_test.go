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

// MockAISystemRegistryService is a mock implementation for testing handlers.
type MockAISystemRegistryService struct {
	createFunc       func(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error)
	getFunc          func(ctx context.Context, orgID, id string) (*AISystem, error)
	listFunc         func(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error)
	updateFunc       func(ctx context.Context, orgID, id string, req *UpdateAISystemRequest) (*AISystem, error)
	deleteFunc       func(ctx context.Context, orgID, id string) error
	processBoardFunc func(ctx context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error)
	getSummaryFunc   func(ctx context.Context, orgID string) (*AISystemSummary, error)
	scheduleValFunc  func(ctx context.Context, orgID, id string, validationDate time.Time) (*AISystem, error)
}

func (m *MockAISystemRegistryService) CreateSystem(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, orgID, req)
	}
	return &AISystem{ID: "test-id", OrgID: orgID, SystemID: req.SystemID}, nil
}

func (m *MockAISystemRegistryService) GetSystem(ctx context.Context, orgID, id string) (*AISystem, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, orgID, id)
	}
	return &AISystem{ID: id, OrgID: orgID}, nil
}

func (m *MockAISystemRegistryService) ListSystems(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, orgID, params)
	}
	return []*AISystem{{ID: "test-1", OrgID: orgID}}, 1, nil
}

func (m *MockAISystemRegistryService) UpdateSystem(ctx context.Context, orgID, id string, req *UpdateAISystemRequest) (*AISystem, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, orgID, id, req)
	}
	return &AISystem{ID: id, OrgID: orgID}, nil
}

func (m *MockAISystemRegistryService) DeleteSystem(ctx context.Context, orgID, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, orgID, id)
	}
	return nil
}

func (m *MockAISystemRegistryService) ProcessBoardApproval(ctx context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error) {
	if m.processBoardFunc != nil {
		return m.processBoardFunc(ctx, orgID, id, req)
	}
	return &AISystem{ID: id, OrgID: orgID, BoardApprovalStatus: BoardApprovalApproved}, nil
}

func (m *MockAISystemRegistryService) GetSystemSummary(ctx context.Context, orgID string) (*AISystemSummary, error) {
	if m.getSummaryFunc != nil {
		return m.getSummaryFunc(ctx, orgID)
	}
	return &AISystemSummary{TotalSystems: 5}, nil
}

func (m *MockAISystemRegistryService) ScheduleValidation(ctx context.Context, orgID, id string, validationDate time.Time) (*AISystem, error) {
	if m.scheduleValFunc != nil {
		return m.scheduleValFunc(ctx, orgID, id, validationDate)
	}
	now := time.Now().UTC()
	return &AISystem{ID: id, OrgID: orgID, LastValidationDate: &now}, nil
}

func TestAISystemRegistryHandler_CreateSystem(t *testing.T) {
	mockService := &MockAISystemRegistryService{}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("successful creation", func(t *testing.T) {
		body := `{"system_id":"test-sys","system_name":"Test System","risk_category":"low"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}

		var response AISystem
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response.SystemID != "test-sys" {
			t.Errorf("SystemID = %v, want test-sys", response.SystemID)
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		body := `{"system_id":"test-sys","system_name":"Test System","risk_category":"low"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("X-Org-ID header", func(t *testing.T) {
		body := `{"system_id":"test-sys-header","system_name":"Test System","risk_category":"low"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-from-header")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}
	})
}

func TestAISystemRegistryHandler_ListSystems(t *testing.T) {
	// gotParams records what the handler actually parsed out of the query string.
	// Asserting only w.Code == 200 cannot distinguish "filters parsed" from
	// "filters silently dropped" (a malformed URL such as
	// `/api/v1/rbi/ai-systems&risk_category=high` leaves RawQuery empty and still
	// returns 200), so the filter subtest below asserts the parsed values instead.
	var gotParams *ListAISystemsParams
	mockService := &MockAISystemRegistryService{
		listFunc: func(ctx context.Context, orgID string, params *ListAISystemsParams) ([]*AISystem, int, error) {
			gotParams = params
			return []*AISystem{
				{ID: "sys-1", OrgID: orgID, SystemName: "System 1"},
				{ID: "sys-2", OrgID: orgID, SystemName: "System 2"},
			}, 2, nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("list all systems", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/ai-systems", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

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
			"/api/v1/rbi/ai-systems?risk_category=high&deployment_status=production&owner_department=risk&validation_overdue=true&limit=10&offset=5", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
		if gotParams == nil {
			t.Fatal("ListSystems was never invoked, so no filter was parsed")
		}
		if gotParams.RiskCategory != "high" {
			t.Errorf("RiskCategory = %q, want %q", gotParams.RiskCategory, "high")
		}
		if gotParams.DeploymentStatus != "production" {
			t.Errorf("DeploymentStatus = %q, want %q", gotParams.DeploymentStatus, "production")
		}
		if gotParams.OwnerDepartment != "risk" {
			t.Errorf("OwnerDepartment = %q, want %q", gotParams.OwnerDepartment, "risk")
		}
		if gotParams.ValidationOverdue == nil || !*gotParams.ValidationOverdue {
			t.Errorf("ValidationOverdue = %v, want a non-nil true", gotParams.ValidationOverdue)
		}
		if gotParams.Limit != 10 {
			t.Errorf("Limit = %d, want 10", gotParams.Limit)
		}
		if gotParams.Offset != 5 {
			t.Errorf("Offset = %d, want 5", gotParams.Offset)
		}
	})
}

func TestAISystemRegistryHandler_GetSystem(t *testing.T) {
	mockService := &MockAISystemRegistryService{
		getFunc: func(ctx context.Context, orgID, id string) (*AISystem, error) {
			if id == "not-found" {
				return nil, ErrSystemNotFound
			}
			return &AISystem{ID: id, OrgID: orgID, SystemName: "Test System"}, nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("get existing system", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/ai-systems/sys-123", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response AISystem
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response.ID != "sys-123" {
			t.Errorf("ID = %v, want sys-123", response.ID)
		}
	})

	t.Run("system not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/ai-systems/not-found", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestAISystemRegistryHandler_UpdateSystem(t *testing.T) {
	mockService := &MockAISystemRegistryService{
		updateFunc: func(ctx context.Context, orgID, id string, req *UpdateAISystemRequest) (*AISystem, error) {
			name := "Updated Name"
			if req.SystemName != nil {
				name = *req.SystemName
			}
			return &AISystem{ID: id, OrgID: orgID, SystemName: name}, nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("update system", func(t *testing.T) {
		body := `{"system_name":"Updated System Name"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/rbi/ai-systems/sys-123", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAISystemRegistryHandler_DeleteSystem(t *testing.T) {
	mockService := &MockAISystemRegistryService{
		deleteFunc: func(ctx context.Context, orgID, id string) error {
			if id == "not-found" {
				return ErrSystemNotFound
			}
			return nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("delete existing system", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/ai-systems/sys-123", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent system", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/ai-systems/not-found", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestAISystemRegistryHandler_BoardApproval(t *testing.T) {
	mockService := &MockAISystemRegistryService{
		processBoardFunc: func(ctx context.Context, orgID, id string, req *BoardApprovalRequest) (*AISystem, error) {
			if req.Action != "approve" && req.Action != "reject" && req.Action != "revoke" {
				return nil, ErrInvalidInput
			}
			var status BoardApprovalStatus
			switch req.Action {
			case "approve":
				status = BoardApprovalApproved
			case "reject":
				status = BoardApprovalRejected
			case "revoke":
				status = BoardApprovalRevoked
			}
			return &AISystem{ID: id, OrgID: orgID, BoardApprovalStatus: status}, nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("approve system", func(t *testing.T) {
		body := `{"action":"approve","approver":"CRO","reference":"BOARD-001"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems/sys-123/board-approval", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response AISystem
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response.BoardApprovalStatus != BoardApprovalApproved {
			t.Errorf("BoardApprovalStatus = %v, want approved", response.BoardApprovalStatus)
		}
	})

	t.Run("reject system", func(t *testing.T) {
		body := `{"action":"reject","approver":"CRO","notes":"Risk assessment failed"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems/sys-123/board-approval", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAISystemRegistryHandler_ScheduleValidation(t *testing.T) {
	mockService := &MockAISystemRegistryService{}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("schedule validation", func(t *testing.T) {
		body := `{"validation_date":"2025-12-11T10:00:00Z"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems/sys-123/validation", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("schedule validation without date uses now", func(t *testing.T) {
		body := `{}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems/sys-123/validation", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAISystemRegistryHandler_GetSummary(t *testing.T) {
	mockService := &MockAISystemRegistryService{
		getSummaryFunc: func(ctx context.Context, orgID string) (*AISystemSummary, error) {
			return &AISystemSummary{
				TotalSystems: 10,
				SystemsByRisk: map[string]int{
					"low":    5,
					"medium": 3,
					"high":   2,
				},
				SystemsPendingApproval: 2,
			}, nil
		},
	}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("get summary", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/ai-systems/summary", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleSummary(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}

		var response AISystemSummary
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}
		if response.TotalSystems != 10 {
			t.Errorf("TotalSystems = %v, want 10", response.TotalSystems)
		}
	})
}

func TestAISystemRegistryHandler_CORS(t *testing.T) {
	mockService := &MockAISystemRegistryService{}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/rbi/ai-systems", nil)
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}

		allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
		if allowOrigin != "*" {
			t.Errorf("Access-Control-Allow-Origin = %v, want *", allowOrigin)
		}
	})
}

func TestAISystemRegistryHandler_MethodNotAllowed(t *testing.T) {
	mockService := &MockAISystemRegistryService{}
	handler := NewAISystemRegistryHandler(mockService)

	t.Run("PUT not allowed on collection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/ai-systems", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("POST not allowed on item", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems/sys-123", nil)
		req.Header.Set("X-Org-ID", "org-1")
		w := httptest.NewRecorder()

		handler.handleAISystemByID(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestAISystemRegistryHandler_ServiceErrors(t *testing.T) {
	t.Run("already exists error", func(t *testing.T) {
		mockService := &MockAISystemRegistryService{
			createFunc: func(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error) {
				return nil, ErrSystemAlreadyExists
			},
		}
		handler := NewAISystemRegistryHandler(mockService)

		body := `{"system_id":"test-sys","system_name":"Test System","risk_category":"low"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusConflict {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusConflict)
		}
	})

	t.Run("invalid input error", func(t *testing.T) {
		mockService := &MockAISystemRegistryService{
			createFunc: func(ctx context.Context, orgID string, req *CreateAISystemRequest) (*AISystem, error) {
				return nil, ErrInvalidInput
			},
		}
		handler := NewAISystemRegistryHandler(mockService)

		body := `{"system_id":"test-sys","system_name":"Test System","risk_category":"low"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/ai-systems", bytes.NewBufferString(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleAISystems(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestAISystemRegistryHandler_RegisterRoutes(t *testing.T) {
	mockService := &MockAISystemRegistryService{}
	handler := NewAISystemRegistryHandler(mockService)
	mux := http.NewServeMux()

	handler.RegisterRoutes(mux)

	t.Run("routes are registered", func(t *testing.T) {
		// Test that the routes are actually registered by making requests
		testCases := []struct {
			method string
			path   string
			want   int
		}{
			{http.MethodGet, "/api/v1/rbi/ai-systems", http.StatusOK},
			{http.MethodGet, "/api/v1/rbi/ai-systems/summary", http.StatusOK},
		}

		for _, tc := range testCases {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("X-Org-ID", "org-1")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)

			if w.Code != tc.want {
				t.Errorf("%s %s: Status = %d, want %d", tc.method, tc.path, w.Code, tc.want)
			}
		}
	})
}
