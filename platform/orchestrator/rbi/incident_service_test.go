// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"testing"
	"time"
)

// MockAIIncidentRepository is a mock implementation for testing.
type MockAIIncidentRepository struct {
	incidents map[string]map[string]*AIIncident
	counter   int
}

func NewMockAIIncidentRepository() *MockAIIncidentRepository {
	return &MockAIIncidentRepository{
		incidents: make(map[string]map[string]*AIIncident),
	}
}

func (m *MockAIIncidentRepository) Create(ctx context.Context, incident *AIIncident) error {
	if incident.ID == "" {
		m.counter++
		incident.ID = "mock-inc-" + incident.SystemID + "-" + string(rune(m.counter+'0'))
	}
	if incident.IncidentID == "" {
		incident.IncidentID = "INC-" + incident.ID
	}
	incident.CreatedAt = time.Now().UTC()
	incident.UpdatedAt = incident.CreatedAt

	if m.incidents[incident.OrgID] == nil {
		m.incidents[incident.OrgID] = make(map[string]*AIIncident)
	}
	m.incidents[incident.OrgID][incident.ID] = incident
	return nil
}

func (m *MockAIIncidentRepository) Get(ctx context.Context, orgID, id string) (*AIIncident, error) {
	if orgIncidents, ok := m.incidents[orgID]; ok {
		if incident, ok := orgIncidents[id]; ok {
			return incident, nil
		}
	}
	return nil, ErrIncidentNotFound
}

func (m *MockAIIncidentRepository) GetByIncidentID(ctx context.Context, orgID, incidentID string) (*AIIncident, error) {
	if orgIncidents, ok := m.incidents[orgID]; ok {
		for _, incident := range orgIncidents {
			if incident.IncidentID == incidentID {
				return incident, nil
			}
		}
	}
	return nil, ErrIncidentNotFound
}

func (m *MockAIIncidentRepository) List(ctx context.Context, orgID string, params *ListIncidentsParams) ([]*AIIncident, int, error) {
	if params == nil {
		params = &ListIncidentsParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}

	var result []*AIIncident
	orgIncidents := m.incidents[orgID]
	if orgIncidents == nil {
		return result, 0, nil
	}

	for _, incident := range orgIncidents {
		if params.SystemID != "" && incident.SystemID != params.SystemID {
			continue
		}
		if params.IncidentType != "" && string(incident.IncidentType) != params.IncidentType {
			continue
		}
		if params.Severity != "" && string(incident.Severity) != params.Severity {
			continue
		}
		if params.Status != "" && string(incident.Status) != params.Status {
			continue
		}
		result = append(result, incident)
	}

	total := len(result)
	if params.Offset >= len(result) {
		return []*AIIncident{}, total, nil
	}
	end := params.Offset + params.Limit
	if end > len(result) {
		end = len(result)
	}
	return result[params.Offset:end], total, nil
}

func (m *MockAIIncidentRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*AIIncident, error) {
	var result []*AIIncident
	orgIncidents := m.incidents[orgID]
	if orgIncidents == nil {
		return result, nil
	}

	for _, incident := range orgIncidents {
		if incident.SystemID == systemID {
			result = append(result, incident)
		}
	}
	return result, nil
}

func (m *MockAIIncidentRepository) Update(ctx context.Context, incident *AIIncident) error {
	if orgIncidents, ok := m.incidents[incident.OrgID]; ok {
		if _, ok := orgIncidents[incident.ID]; ok {
			incident.UpdatedAt = time.Now().UTC()
			m.incidents[incident.OrgID][incident.ID] = incident
			return nil
		}
	}
	return ErrIncidentNotFound
}

func (m *MockAIIncidentRepository) Delete(ctx context.Context, orgID, id string) error {
	if orgIncidents, ok := m.incidents[orgID]; ok {
		if _, ok := orgIncidents[id]; ok {
			delete(m.incidents[orgID], id)
			return nil
		}
	}
	return ErrIncidentNotFound
}

func (m *MockAIIncidentRepository) GetOpenIncidents(ctx context.Context, orgID string) ([]*AIIncident, error) {
	var result []*AIIncident
	orgIncidents := m.incidents[orgID]
	if orgIncidents == nil {
		return result, nil
	}

	for _, incident := range orgIncidents {
		if incident.Status != IncidentStatusResolved && incident.Status != IncidentStatusClosed {
			result = append(result, incident)
		}
	}
	return result, nil
}

func (m *MockAIIncidentRepository) GetPendingNotifications(ctx context.Context, orgID string, notificationType string) ([]*AIIncident, error) {
	var result []*AIIncident
	orgIncidents := m.incidents[orgID]
	if orgIncidents == nil {
		return result, nil
	}

	for _, incident := range orgIncidents {
		if notificationType == "board" && incident.BoardNotificationRequired && !incident.BoardNotified {
			result = append(result, incident)
		}
		if notificationType == "rbi" && incident.RBINotificationRequired && !incident.RBINotified {
			result = append(result, incident)
		}
	}
	return result, nil
}

func TestAIIncidentService_CreateIncident(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	t.Run("create bias_detected incident", func(t *testing.T) {
		req := &CreateIncidentRequest{
			SystemID:             "credit-scoring-v1",
			IncidentType:         "bias_detected",
			Severity:             "high",
			DetectedBy:           "automated_monitoring",
			Title:                "Gender bias_detected detected in loan approvals",
			Description:          "Automated monitoring detected potential gender bias_detected in credit scoring model",
			ImmediateActionTaken: "Disabled model for manual review",
		}

		incident, err := service.CreateIncident(context.Background(), "org-1", req)
		if err != nil {
			t.Fatalf("CreateIncident failed: %v", err)
		}

		if incident.ID == "" {
			t.Error("Expected ID to be set")
		}
		if incident.IncidentID == "" {
			t.Error("Expected IncidentID to be set")
		}
		if incident.Status != IncidentStatusOpen {
			t.Errorf("Status = %v, want %v", incident.Status, IncidentStatusOpen)
		}
		// High severity auto-sets board notification
		if !incident.BoardNotificationRequired {
			t.Error("Expected BoardNotificationRequired to be true for high severity")
		}
	})

	t.Run("create critical incident auto-sets RBI notification", func(t *testing.T) {
		req := &CreateIncidentRequest{
			SystemID:     "fraud-detection-v1",
			IncidentType: "model_failure",
			Severity:     "critical",
			DetectedBy:   "human_review",
			Title:        "Critical model failure",
			Description:  "Complete model failure affecting all transactions",
		}

		incident, err := service.CreateIncident(context.Background(), "org-1", req)
		if err != nil {
			t.Fatalf("CreateIncident failed: %v", err)
		}

		if !incident.BoardNotificationRequired {
			t.Error("Expected BoardNotificationRequired to be true for critical severity")
		}
		if !incident.RBINotificationRequired {
			t.Error("Expected RBINotificationRequired to be true for critical severity")
		}
	})

	t.Run("missing required fields", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *CreateIncidentRequest
		}{
			{"nil request", nil},
			{"missing incident_type", &CreateIncidentRequest{Severity: "high", DetectedBy: "automated_monitoring", Title: "Title", Description: "Desc"}},
			{"missing severity", &CreateIncidentRequest{IncidentType: "bias_detected", DetectedBy: "automated_monitoring", Title: "Title", Description: "Desc"}},
			{"missing detected_by", &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "high", Title: "Title", Description: "Desc"}},
			{"missing title", &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "high", DetectedBy: "automated_monitoring", Description: "Desc"}},
			{"missing description", &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "high", DetectedBy: "automated_monitoring", Title: "Title"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateIncident(context.Background(), "org-1", tc.req)
				if err == nil {
					t.Error("Expected error for missing required field")
				}
			})
		}
	})

	t.Run("invalid enum values", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *CreateIncidentRequest
		}{
			{"invalid incident_type", &CreateIncidentRequest{IncidentType: "invalid", Severity: "high", DetectedBy: "automated_monitoring", Title: "Title", Description: "Desc"}},
			{"invalid severity", &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "invalid", DetectedBy: "automated_monitoring", Title: "Title", Description: "Desc"}},
			{"invalid detected_by", &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "high", DetectedBy: "invalid", Title: "Title", Description: "Desc"}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateIncident(context.Background(), "org-1", tc.req)
				if err == nil {
					t.Error("Expected error for invalid enum value")
				}
			})
		}
	})
}

func TestAIIncidentService_GetIncident(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create test incident
	req := &CreateIncidentRequest{
		SystemID:     "test-sys",
		IncidentType: "bias_detected",
		Severity:     "medium",
		DetectedBy:   "human_review",
		Title:        "Test incident",
		Description:  "Test description",
	}
	created, _ := service.CreateIncident(context.Background(), "org-1", req)

	t.Run("get existing incident", func(t *testing.T) {
		incident, err := service.GetIncident(context.Background(), "org-1", created.ID)
		if err != nil {
			t.Fatalf("GetIncident failed: %v", err)
		}
		if incident.ID != created.ID {
			t.Errorf("ID = %v, want %v", incident.ID, created.ID)
		}
	})

	t.Run("get non-existent incident", func(t *testing.T) {
		_, err := service.GetIncident(context.Background(), "org-1", "non-existent")
		if err != ErrIncidentNotFound {
			t.Errorf("Expected ErrIncidentNotFound, got %v", err)
		}
	})
}

func TestAIIncidentService_UpdateStatus(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create test incident
	req := &CreateIncidentRequest{
		IncidentType: "model_failure",
		Severity:     "high",
		DetectedBy:   "automated_monitoring",
		Title:        "Test incident",
		Description:  "Test description",
	}
	created, _ := service.CreateIncident(context.Background(), "org-1", req)

	t.Run("update to investigating", func(t *testing.T) {
		incident, err := service.UpdateStatus(context.Background(), "org-1", created.ID, IncidentStatusInvestigating, "")
		if err != nil {
			t.Fatalf("UpdateStatus failed: %v", err)
		}
		if incident.Status != IncidentStatusInvestigating {
			t.Errorf("Status = %v, want %v", incident.Status, IncidentStatusInvestigating)
		}
	})

	t.Run("resolve incident sets resolved_at", func(t *testing.T) {
		incident, err := service.UpdateStatus(context.Background(), "org-1", created.ID, IncidentStatusResolved, "Root cause identified and fixed")
		if err != nil {
			t.Fatalf("UpdateStatus failed: %v", err)
		}
		if incident.Status != IncidentStatusResolved {
			t.Errorf("Status = %v, want %v", incident.Status, IncidentStatusResolved)
		}
		if incident.ResolvedAt == nil {
			t.Error("Expected ResolvedAt to be set")
		}
		if incident.ResolutionSummary != "Root cause identified and fixed" {
			t.Errorf("ResolutionSummary = %v, want 'Root cause identified and fixed'", incident.ResolutionSummary)
		}
	})

	t.Run("invalid status", func(t *testing.T) {
		_, err := service.UpdateStatus(context.Background(), "org-1", created.ID, IncidentStatus("invalid"), "")
		if err == nil {
			t.Error("Expected error for invalid status")
		}
	})
}

func TestAIIncidentService_AddRemediationAction(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create test incident
	req := &CreateIncidentRequest{
		IncidentType: "bias_detected",
		Severity:     "high",
		DetectedBy:   "automated_monitoring",
		Title:        "Test incident",
		Description:  "Test description",
	}
	created, _ := service.CreateIncident(context.Background(), "org-1", req)

	t.Run("add remediation action", func(t *testing.T) {
		dueDate := time.Now().Add(7 * 24 * time.Hour)
		action := &RemediationAction{
			Action:     "Retrain model with balanced dataset",
			AssignedTo: "data-science-team",
			DueDate:    &dueDate,
		}

		incident, err := service.AddRemediationAction(context.Background(), "org-1", created.ID, action)
		if err != nil {
			t.Fatalf("AddRemediationAction failed: %v", err)
		}
		if len(incident.RemediationActions) != 1 {
			t.Fatalf("Expected 1 remediation action, got %d", len(incident.RemediationActions))
		}
		if incident.RemediationActions[0].ID == "" {
			t.Error("Expected action ID to be generated")
		}
		if incident.RemediationActions[0].Status != "pending" {
			t.Errorf("Status = %v, want 'pending'", incident.RemediationActions[0].Status)
		}
	})

	t.Run("nil action fails", func(t *testing.T) {
		_, err := service.AddRemediationAction(context.Background(), "org-1", created.ID, nil)
		if err == nil {
			t.Error("Expected error for nil action")
		}
	})
}

func TestAIIncidentService_UpdateRemediationAction(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create test incident with action
	req := &CreateIncidentRequest{
		IncidentType: "bias_detected",
		Severity:     "high",
		DetectedBy:   "automated_monitoring",
		Title:        "Test incident",
		Description:  "Test description",
		RemediationActions: []RemediationAction{
			{Action: "Fix the model", AssignedTo: "team-a"},
		},
	}
	created, _ := service.CreateIncident(context.Background(), "org-1", req)
	actionID := created.RemediationActions[0].ID

	t.Run("update action status", func(t *testing.T) {
		status := "completed"
		now := time.Now().UTC()
		updateReq := &UpdateRemediationActionRequest{
			Status:      &status,
			CompletedAt: &now,
		}

		incident, err := service.UpdateRemediationAction(context.Background(), "org-1", created.ID, actionID, updateReq)
		if err != nil {
			t.Fatalf("UpdateRemediationAction failed: %v", err)
		}
		if incident.RemediationActions[0].Status != "completed" {
			t.Errorf("Status = %v, want 'completed'", incident.RemediationActions[0].Status)
		}
		if incident.RemediationActions[0].CompletedAt == nil {
			t.Error("Expected CompletedAt to be set")
		}
	})

	t.Run("update non-existent action", func(t *testing.T) {
		status := "completed"
		updateReq := &UpdateRemediationActionRequest{Status: &status}
		_, err := service.UpdateRemediationAction(context.Background(), "org-1", created.ID, "non-existent", updateReq)
		if err == nil {
			t.Error("Expected error for non-existent action")
		}
	})
}

func TestAIIncidentService_RecordNotifications(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create test incident
	req := &CreateIncidentRequest{
		IncidentType:              "bias_detected",
		Severity:                  "critical",
		DetectedBy:                "automated_monitoring",
		Title:                     "Test incident",
		Description:               "Test description",
		BoardNotificationRequired: true,
		RBINotificationRequired:   true,
	}
	created, _ := service.CreateIncident(context.Background(), "org-1", req)

	t.Run("record board notification", func(t *testing.T) {
		notifyReq := &RecordNotificationRequest{
			NotificationDate: time.Now().UTC(),
			Reference:        "BOARD-2024-001",
		}

		incident, err := service.RecordBoardNotification(context.Background(), "org-1", created.ID, notifyReq)
		if err != nil {
			t.Fatalf("RecordBoardNotification failed: %v", err)
		}
		if !incident.BoardNotified {
			t.Error("Expected BoardNotified to be true")
		}
		if incident.BoardNotificationDate == nil {
			t.Error("Expected BoardNotificationDate to be set")
		}
		if incident.BoardNotificationReference != "BOARD-2024-001" {
			t.Errorf("BoardNotificationReference = %v, want 'BOARD-2024-001'", incident.BoardNotificationReference)
		}
	})

	t.Run("record RBI notification", func(t *testing.T) {
		notifyReq := &RecordNotificationRequest{
			NotificationDate: time.Now().UTC(),
			Reference:        "RBI-2024-001",
			Response:         "Acknowledged",
		}

		incident, err := service.RecordRBINotification(context.Background(), "org-1", created.ID, notifyReq)
		if err != nil {
			t.Fatalf("RecordRBINotification failed: %v", err)
		}
		if !incident.RBINotified {
			t.Error("Expected RBINotified to be true")
		}
		if incident.RBINotificationDate == nil {
			t.Error("Expected RBINotificationDate to be set")
		}
		if incident.RBIResponse != "Acknowledged" {
			t.Errorf("RBIResponse = %v, want 'Acknowledged'", incident.RBIResponse)
		}
	})
}

func TestAIIncidentService_ListIncidents(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create multiple incidents
	incidents := []CreateIncidentRequest{
		{SystemID: "sys-1", IncidentType: "bias_detected", Severity: "high", DetectedBy: "automated_monitoring", Title: "Inc 1", Description: "Desc 1"},
		{SystemID: "sys-1", IncidentType: "model_failure", Severity: "critical", DetectedBy: "human_review", Title: "Inc 2", Description: "Desc 2"},
		{SystemID: "sys-2", IncidentType: "bias_detected", Severity: "medium", DetectedBy: "customer_complaint", Title: "Inc 3", Description: "Desc 3"},
	}

	for _, req := range incidents {
		service.CreateIncident(context.Background(), "org-1", &req)
	}

	t.Run("list all incidents", func(t *testing.T) {
		result, total, err := service.ListIncidents(context.Background(), "org-1", nil)
		if err != nil {
			t.Fatalf("ListIncidents failed: %v", err)
		}
		if total != 3 {
			t.Errorf("Total = %d, want 3", total)
		}
		if len(result) != 3 {
			t.Errorf("Result count = %d, want 3", len(result))
		}
	})

	t.Run("filter by system", func(t *testing.T) {
		result, total, err := service.ListIncidents(context.Background(), "org-1", &ListIncidentsParams{SystemID: "sys-1"})
		if err != nil {
			t.Fatalf("ListIncidents failed: %v", err)
		}
		if total != 2 {
			t.Errorf("Total = %d, want 2", total)
		}
		if len(result) != 2 {
			t.Errorf("Result count = %d, want 2", len(result))
		}
	})

	t.Run("filter by severity", func(t *testing.T) {
		result, total, err := service.ListIncidents(context.Background(), "org-1", &ListIncidentsParams{Severity: "critical"})
		if err != nil {
			t.Fatalf("ListIncidents failed: %v", err)
		}
		if total != 1 {
			t.Errorf("Total = %d, want 1", total)
		}
		if len(result) != 1 {
			t.Errorf("Result count = %d, want 1", len(result))
		}
	})
}

func TestAIIncidentService_GetOpenIncidents(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create incidents
	req1 := &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "high", DetectedBy: "automated_monitoring", Title: "Open 1", Description: "Desc"}
	req2 := &CreateIncidentRequest{IncidentType: "bias_detected", Severity: "medium", DetectedBy: "human_review", Title: "Open 2", Description: "Desc"}

	inc1, _ := service.CreateIncident(context.Background(), "org-1", req1)
	service.CreateIncident(context.Background(), "org-1", req2)

	// Resolve one
	service.UpdateStatus(context.Background(), "org-1", inc1.ID, IncidentStatusResolved, "Fixed")

	t.Run("get open incidents", func(t *testing.T) {
		result, err := service.GetOpenIncidents(context.Background(), "org-1")
		if err != nil {
			t.Fatalf("GetOpenIncidents failed: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("Result count = %d, want 1", len(result))
		}
	})
}

func TestAIIncidentService_GetPendingNotifications(t *testing.T) {
	repo := NewMockAIIncidentRepository()
	service := NewAIIncidentService(repo, nil)

	// Create incident requiring board notification
	req := &CreateIncidentRequest{
		IncidentType:              "bias_detected",
		Severity:                  "critical",
		DetectedBy:                "automated_monitoring",
		Title:                     "Test",
		Description:               "Desc",
		BoardNotificationRequired: true,
		RBINotificationRequired:   true,
	}
	service.CreateIncident(context.Background(), "org-1", req)

	t.Run("get pending board notifications", func(t *testing.T) {
		result, err := service.GetPendingBoardNotifications(context.Background(), "org-1")
		if err != nil {
			t.Fatalf("GetPendingBoardNotifications failed: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("Result count = %d, want 1", len(result))
		}
	})

	t.Run("get pending RBI notifications", func(t *testing.T) {
		result, err := service.GetPendingRBINotifications(context.Background(), "org-1")
		if err != nil {
			t.Fatalf("GetPendingRBINotifications failed: %v", err)
		}
		if len(result) != 1 {
			t.Errorf("Result count = %d, want 1", len(result))
		}
	})
}
