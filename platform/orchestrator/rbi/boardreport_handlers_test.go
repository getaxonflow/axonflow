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

// MockBoardReportService is a mock implementation for testing handlers.
type MockBoardReportService struct {
	reports map[string]*BoardReport
	counter int
}

func NewMockBoardReportServiceForHandlers() *MockBoardReportService {
	return &MockBoardReportService{
		reports: make(map[string]*BoardReport),
	}
}

func (m *MockBoardReportService) GenerateReport(ctx context.Context, orgID string, req *GenerateReportRequest) (*BoardReport, error) {
	m.counter++
	id := "report-" + string(rune(m.counter+'0'))
	report := &BoardReport{
		ID:               id,
		OrgID:            orgID,
		ReportType:       ReportType(req.ReportType),
		ReportPeriodStart: req.ReportPeriodStart,
		ReportPeriodEnd:  req.ReportPeriodEnd,
		ReportQuarter:    req.ReportQuarter,
		GeneratedBy:      req.GeneratedBy,
		GeneratedByEmail: req.GeneratedByEmail,
		GeneratedAt:      time.Now().UTC(),
		GenerationMethod: "automatic",
		ApprovalStatus:   ReportApprovalDraft,
		ComplianceScore:  95.0,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	m.reports[id] = report
	return report, nil
}

func (m *MockBoardReportService) GetReport(ctx context.Context, orgID, id string) (*BoardReport, error) {
	report, ok := m.reports[id]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	return report, nil
}

func (m *MockBoardReportService) ListReports(ctx context.Context, orgID string, params *ListBoardReportsParams) ([]*BoardReport, int, error) {
	var result []*BoardReport
	for _, report := range m.reports {
		if report.OrgID == orgID {
			result = append(result, report)
		}
	}
	return result, len(result), nil
}

func (m *MockBoardReportService) SubmitForApproval(ctx context.Context, orgID, id string, req *SubmitForApprovalRequest) (*BoardReport, error) {
	report, ok := m.reports[id]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	report.ApprovalStatus = ReportApprovalPendingReview
	return report, nil
}

func (m *MockBoardReportService) ApproveReport(ctx context.Context, orgID, id string, req *ApproveReportRequest) (*BoardReport, error) {
	report, ok := m.reports[id]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	now := time.Now().UTC()
	report.ApprovalStatus = ReportApprovalApproved
	report.ApprovedBy = req.ApprovedBy
	report.ApprovedByEmail = req.ApprovedByEmail
	report.ApprovedAt = &now
	report.ApprovalNotes = req.ApprovalNotes
	return report, nil
}

func (m *MockBoardReportService) RejectReport(ctx context.Context, orgID, id string, req *RejectReportRequest) (*BoardReport, error) {
	report, ok := m.reports[id]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	report.ApprovalStatus = ReportApprovalRejected
	report.ApprovalNotes = req.RejectionReason
	return report, nil
}

func (m *MockBoardReportService) DeleteReport(ctx context.Context, orgID, id string) error {
	report, ok := m.reports[id]
	if !ok || report.OrgID != orgID {
		return ErrBoardReportNotFound
	}
	delete(m.reports, id)
	return nil
}

func (m *MockBoardReportService) GetLatestReport(ctx context.Context, orgID string, reportType ReportType) (*BoardReport, error) {
	var latest *BoardReport
	for _, report := range m.reports {
		if report.OrgID == orgID && report.ReportType == reportType {
			if latest == nil || report.GeneratedAt.After(latest.GeneratedAt) {
				latest = report
			}
		}
	}
	if latest == nil {
		return nil, ErrBoardReportNotFound
	}
	return latest, nil
}

func (m *MockBoardReportService) GetPendingApproval(ctx context.Context, orgID string) ([]*BoardReport, error) {
	var result []*BoardReport
	for _, report := range m.reports {
		if report.OrgID == orgID && report.ApprovalStatus == ReportApprovalPendingReview {
			result = append(result, report)
		}
	}
	return result, nil
}

func (m *MockBoardReportService) AddCorrectiveAction(ctx context.Context, orgID, reportID string, action *CorrectiveAction) (*BoardReport, error) {
	report, ok := m.reports[reportID]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	if action.ID == "" {
		action.ID = "ca-1"
	}
	if action.Status == "" {
		action.Status = "pending"
	}
	report.CorrectiveActions = append(report.CorrectiveActions, *action)
	return report, nil
}

func (m *MockBoardReportService) UpdateCorrectiveAction(ctx context.Context, orgID, reportID, actionID string, update *UpdateCorrectiveActionRequest) (*BoardReport, error) {
	report, ok := m.reports[reportID]
	if !ok || report.OrgID != orgID {
		return nil, ErrBoardReportNotFound
	}
	for i := range report.CorrectiveActions {
		if report.CorrectiveActions[i].ID == actionID {
			if update.Status != "" {
				report.CorrectiveActions[i].Status = update.Status
			}
			return report, nil
		}
	}
	return nil, ErrInvalidInput
}

func TestBoardReportHandler_GenerateReport(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	t.Run("generate report", func(t *testing.T) {
		body := `{"report_type":"quarterly","report_quarter":"Q4-2024","generated_by":"compliance-officer"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusCreated, rr.Body.String())
		}

		var report BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&report); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if report.ID == "" {
			t.Error("Expected ID to be set")
		}
		if report.ReportType != ReportTypeQuarterly {
			t.Errorf("ReportType = %v, want %v", report.ReportType, ReportTypeQuarterly)
		}
	})

	t.Run("missing org_id", func(t *testing.T) {
		body := `{"report_type":"quarterly"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusUnauthorized)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports", bytes.NewBufferString("invalid"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusBadRequest)
		}
	})
}

func TestBoardReportHandler_ListReports(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create some reports
	service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})
	service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "annual",
	})

	t.Run("list reports", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/reports", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		reports, ok := resp["reports"].([]interface{})
		if !ok {
			t.Fatal("Expected reports in response")
		}
		if len(reports) != 2 {
			t.Errorf("Len = %d, want 2", len(reports))
		}
	})
}

func TestBoardReportHandler_GetReport(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})

	t.Run("get report", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/reports/"+report.ID, nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ID != report.ID {
			t.Errorf("ID = %v, want %v", result.ID, report.ID)
		}
	})

	t.Run("get non-existent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/reports/non-existent", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestBoardReportHandler_ApprovalWorkflow(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})

	t.Run("submit for approval", func(t *testing.T) {
		body := `{"submitted_by":"compliance-officer","submitted_by_email":"compliance@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports/"+report.ID+"/submit", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ApprovalStatus != ReportApprovalPendingReview {
			t.Errorf("ApprovalStatus = %v, want %v", result.ApprovalStatus, ReportApprovalPendingReview)
		}
	})

	t.Run("approve report", func(t *testing.T) {
		body := `{"approved_by":"board-member","approval_notes":"Approved"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports/"+report.ID+"/approve", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ApprovalStatus != ReportApprovalApproved {
			t.Errorf("ApprovalStatus = %v, want %v", result.ApprovalStatus, ReportApprovalApproved)
		}
	})
}

func TestBoardReportHandler_RejectReport(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})

	t.Run("reject report", func(t *testing.T) {
		body := `{"rejected_by":"board-member","rejection_reason":"Missing details"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports/"+report.ID+"/reject", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ApprovalStatus != ReportApprovalRejected {
			t.Errorf("ApprovalStatus = %v, want %v", result.ApprovalStatus, ReportApprovalRejected)
		}
	})
}

func TestBoardReportHandler_DeleteReport(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "adhoc",
	})

	t.Run("delete report", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/reports/"+report.ID, nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNoContent)
		}
	})

	t.Run("delete non-existent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/rbi/reports/non-existent", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNotFound)
		}
	})
}

func TestBoardReportHandler_GetPendingApproval(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create and submit a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})
	service.SubmitForApproval(context.Background(), "org-1", report.ID, &SubmitForApprovalRequest{
		SubmittedBy: "user",
	})

	t.Run("get pending approval", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/reports/pending", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var resp map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		reports, ok := resp["reports"].([]interface{})
		if !ok {
			t.Fatal("Expected reports in response")
		}
		if len(reports) != 1 {
			t.Errorf("Pending count = %d, want 1", len(reports))
		}
	})
}

func TestBoardReportHandler_GetLatestReport(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create reports
	service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q3-2024",
	})
	time.Sleep(10 * time.Millisecond)
	service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType:    "quarterly",
		ReportQuarter: "Q4-2024",
	})

	t.Run("get latest report", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/rbi/reports/latest?report_type=quarterly", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if result.ReportQuarter != "Q4-2024" {
			t.Errorf("ReportQuarter = %v, want Q4-2024", result.ReportQuarter)
		}
	})
}

func TestBoardReportHandler_CorrectiveActions(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	// Create a report
	report, _ := service.GenerateReport(context.Background(), "org-1", &GenerateReportRequest{
		ReportType: "quarterly",
	})

	t.Run("add corrective action", func(t *testing.T) {
		body := `{"action":"Review high-risk systems","priority":"high","assigned_to":"risk-team"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/rbi/reports/"+report.ID+"/actions", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}

		var result BoardReport
		if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		if len(result.CorrectiveActions) != 1 {
			t.Errorf("CorrectiveActions count = %d, want 1", len(result.CorrectiveActions))
		}
	})

	t.Run("update corrective action", func(t *testing.T) {
		body := `{"status":"completed"}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/reports/"+report.ID+"/actions/ca-1", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReportRoutes(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Status = %d, want %d. Body: %s", rr.Code, http.StatusOK, rr.Body.String())
		}
	})
}

func TestBoardReportHandler_CORS(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/rbi/reports", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusNoContent)
		}

		if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected CORS headers to be set")
		}
	})
}

func TestBoardReportHandler_MethodNotAllowed(t *testing.T) {
	service := NewMockBoardReportServiceForHandlers()
	handler := NewBoardReportHandler(service)

	t.Run("PUT not allowed on collection", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/rbi/reports", nil)
		req.Header.Set("X-Org-ID", "org-1")

		rr := httptest.NewRecorder()
		handler.handleReports(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("Status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
		}
	})
}
