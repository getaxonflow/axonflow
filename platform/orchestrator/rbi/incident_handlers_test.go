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

// MockAIIncidentService is a mock for testing handlers.
type MockAIIncidentService struct {
	createFunc                func(ctx context.Context, orgID string, req *CreateIncidentRequest) (*AIIncident, error)
	getFunc                   func(ctx context.Context, orgID, id string) (*AIIncident, error)
	getByIncidentIDFunc       func(ctx context.Context, orgID, incidentID string) (*AIIncident, error)
	listFunc                  func(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error)
	updateFunc                func(ctx context.Context, orgID, id string, req *UpdateIncidentRequest) (*AIIncident, error)
	deleteFunc                func(ctx context.Context, orgID, id string) error
	updateStatusFunc          func(ctx context.Context, orgID, id string, status IncidentStatus, resolution string) (*AIIncident, error)
	addRemediationFunc        func(ctx context.Context, orgID, id string, action *RemediationAction) (*AIIncident, error)
	updateRemediationFunc     func(ctx context.Context, orgID, id, actionID string, req *UpdateRemediationActionRequest) (*AIIncident, error)
	recordBoardNotifyFunc     func(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error)
	recordRBINotifyFunc       func(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error)
	getOpenFunc               func(ctx context.Context, orgID string) ([]*AIIncident, error)
	getPendingBoardFunc       func(ctx context.Context, orgID string) ([]*AIIncident, error)
	getPendingRBIFunc         func(ctx context.Context, orgID string) ([]*AIIncident, error)
}

func (m *MockAIIncidentService) CreateIncident(ctx context.Context, orgID string, req *CreateIncidentRequest) (*AIIncident, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, orgID, req)
	}
	return &AIIncident{ID: "test-id", OrgID: orgID, IncidentID: "INC-001", Status: IncidentStatusOpen}, nil
}

func (m *MockAIIncidentService) GetIncident(ctx context.Context, orgID, id string) (*AIIncident, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, orgID, id)
	}
	return &AIIncident{ID: id, OrgID: orgID, IncidentID: "INC-001"}, nil
}

func (m *MockAIIncidentService) GetIncidentByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	if m.getByIncidentIDFunc != nil {
		return m.getByIncidentIDFunc(ctx, orgID, incidentID)
	}
	return &AIIncident{ID: "test-id", OrgID: orgID, IncidentID: incidentID}, nil
}

func (m *MockAIIncidentService) ListIncidents(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, orgID, params)
	}
	return []*AIIncident{{ID: "test-1", OrgID: orgID, IncidentID: "INC-001"}}, 1, nil
}

func (m *MockAIIncidentService) UpdateIncident(ctx context.Context, orgID, id string, req *UpdateIncidentRequest) (*AIIncident, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, orgID, id, req)
	}
	return &AIIncident{ID: id, OrgID: orgID}, nil
}

func (m *MockAIIncidentService) DeleteIncident(ctx context.Context, orgID, id string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, orgID, id)
	}
	return nil
}

func (m *MockAIIncidentService) UpdateStatus(ctx context.Context, orgID, id string, status IncidentStatus, resolution string) (*AIIncident, error) {
	if m.updateStatusFunc != nil {
		return m.updateStatusFunc(ctx, orgID, id, status, resolution)
	}
	return &AIIncident{ID: id, OrgID: orgID, Status: status}, nil
}

func (m *MockAIIncidentService) AddRemediationAction(ctx context.Context, orgID, id string, action *RemediationAction) (*AIIncident, error) {
	if m.addRemediationFunc != nil {
		return m.addRemediationFunc(ctx, orgID, id, action)
	}
	return &AIIncident{ID: id, OrgID: orgID, RemediationActions: []RemediationAction{*action}}, nil
}

func (m *MockAIIncidentService) UpdateRemediationAction(ctx context.Context, orgID, id, actionID string, req *UpdateRemediationActionRequest) (*AIIncident, error) {
	if m.updateRemediationFunc != nil {
		return m.updateRemediationFunc(ctx, orgID, id, actionID, req)
	}
	return &AIIncident{ID: id, OrgID: orgID}, nil
}

func (m *MockAIIncidentService) RecordBoardNotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error) {
	if m.recordBoardNotifyFunc != nil {
		return m.recordBoardNotifyFunc(ctx, orgID, id, req)
	}
	return &AIIncident{ID: id, OrgID: orgID, BoardNotified: true}, nil
}

func (m *MockAIIncidentService) RecordRBINotification(ctx context.Context, orgID, id string, req *RecordNotificationRequest) (*AIIncident, error) {
	if m.recordRBINotifyFunc != nil {
		return m.recordRBINotifyFunc(ctx, orgID, id, req)
	}
	return &AIIncident{ID: id, OrgID: orgID, RBINotified: true}, nil
}

func (m *MockAIIncidentService) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	if m.getOpenFunc != nil {
		return m.getOpenFunc(ctx, orgID)
	}
	return []*AIIncident{{ID: "open-1", OrgID: orgID, Status: IncidentStatusOpen}}, nil
}

func (m *MockAIIncidentService) GetPendingBoardNotifications(ctx context.Context, orgID string) ([]*AIIncident, error) {
	if m.getPendingBoardFunc != nil {
		return m.getPendingBoardFunc(ctx, orgID)
	}
	return []*AIIncident{{ID: "pending-1", OrgID: orgID, BoardNotificationRequired: true, BoardNotified: false}}, nil
}

func (m *MockAIIncidentService) GetPendingRBINotifications(ctx context.Context, orgID string) ([]*AIIncident, error) {
	if m.getPendingRBIFunc != nil {
		return m.getPendingRBIFunc(ctx, orgID)
	}
	return []*AIIncident{{ID: "pending-1", OrgID: orgID, RBINotificationRequired: true, RBINotified: false}}, nil
}

func TestAIIncidentHandler_CreateIncident(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("successful creation", func(t *testing.T) {
		body := `{"incident_type":"bias","severity":"high","detected_by":"automated_monitoring","title":"Test","description":"Test desc"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusCreated)
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		body := `{"incident_type":"bias"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		body := `{invalid}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusBadRequest)
		}
	})
}

func TestAIIncidentHandler_ListIncidents(t *testing.T) {
	mockService := &MockAIIncidentService{
		listFunc: func(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
			return []*AIIncident{
				{ID: "inc-1", OrgID: orgID, IncidentID: "INC-001"},
				{ID: "inc-2", OrgID: orgID, IncidentID: "INC-002"},
			}, 2, nil
		},
	}
	handler := NewAIIncidentHandler(mockService)

	t.Run("list incidents", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

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
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents?org_id=org-1&severity=critical&status=open", nil)
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_GetIncident(t *testing.T) {
	mockService := &MockAIIncidentService{
		getFunc: func(ctx context.Context, orgID, id string) (*AIIncident, error) {
			if id == "not-found" {
				return nil, ErrIncidentNotFound
			}
			return &AIIncident{ID: id, OrgID: orgID, IncidentID: "INC-001"}, nil
		},
	}
	handler := NewAIIncidentHandler(mockService)

	t.Run("get existing incident", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents/inc-123?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("incident not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents/not-found?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestAIIncidentHandler_UpdateStatus(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("update status", func(t *testing.T) {
		body := `{"status":"investigating"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents/inc-123/status?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_AddRemediationAction(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("add action", func(t *testing.T) {
		body := `{"action":"Retrain model","assigned_to":"data-science"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents/inc-123/actions?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_UpdateRemediationAction(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("update action", func(t *testing.T) {
		body := `{"status":"completed"}`
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/rbi/incidents/inc-123/actions/action-1?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_RecordNotifications(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("record board notification", func(t *testing.T) {
		notifyDate := time.Now().UTC().Format(time.RFC3339)
		body := `{"notification_date":"` + notifyDate + `","reference":"BOARD-001"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents/inc-123/notify/board?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("record RBI notification", func(t *testing.T) {
		notifyDate := time.Now().UTC().Format(time.RFC3339)
		body := `{"notification_date":"` + notifyDate + `","reference":"RBI-001"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/incidents/inc-123/notify/rbi?org_id=org-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_GetOpenIncidents(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("get open incidents", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents/open?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_GetPendingNotifications(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("get pending board notifications", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents/pending-board?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("get pending RBI notifications", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents/pending-rbi?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}

func TestAIIncidentHandler_DeleteIncident(t *testing.T) {
	mockService := &MockAIIncidentService{
		deleteFunc: func(ctx context.Context, orgID, id string) error {
			if id == "not-found" {
				return ErrIncidentNotFound
			}
			return nil
		},
	}
	handler := NewAIIncidentHandler(mockService)

	t.Run("delete existing incident", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/incidents/inc-123?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent incident", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/incidents/not-found?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidentRoutes(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}

func TestAIIncidentHandler_CORS(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/rbi/incidents", nil)
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusNoContent)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Missing CORS header")
		}
	})
}

func TestAIIncidentHandler_MethodNotAllowed(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)

	t.Run("PUT not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/incidents?org_id=org-1", nil)
		w := httptest.NewRecorder()

		handler.handleIncidents(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestAIIncidentHandler_RegisterRoutes(t *testing.T) {
	mockService := &MockAIIncidentService{}
	handler := NewAIIncidentHandler(mockService)
	mux := http.NewServeMux()

	handler.RegisterRoutes(mux)

	t.Run("routes are registered", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/incidents?org_id=org-1", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d", w.Code, http.StatusOK)
		}
	})
}
