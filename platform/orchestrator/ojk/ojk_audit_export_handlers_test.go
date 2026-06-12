//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockOJKService struct {
	exportCalled   bool
	retentionCalled bool
	readinessCalled bool
	breachCalled    bool
	dashboardCalled bool
	ackCalled       bool
	evalCalled      bool
	ackErr          error
	evalErr         error
	evalFlipped     int
}

func (m *mockOJKService) ExportAuditData(ctx context.Context, tenantID string, req *OJKAuditExportRequest) (*OJKAuditExportResponse, error) {
	m.exportCalled = true
	return &OJKAuditExportResponse{
		ExportID:  "test-export-id",
		Status:    "completed",
		Framework: OJKFrameworkCombined,
		Format:    OJKFormatJSON,
		Summary: &OJKAuditExportSummary{
			TotalRecords:  0,
			RecordsByType: map[string]int{},
			ComplianceScore: 1.0,
		},
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (m *mockOJKService) GetExportStatus(ctx context.Context, tenantID string, exportID string) (*OJKAuditExportResponse, error) {
	return &OJKAuditExportResponse{
		ExportID: exportID,
		Status:   "completed",
	}, nil
}

func (m *mockOJKService) GetRetentionStatus(ctx context.Context, tenantID string, req *OJKRetentionStatusRequest) (*OJKRetentionStatusResponse, error) {
	m.retentionCalled = true
	return &OJKRetentionStatusResponse{
		ComplianceStatus: "compliant",
		Framework:        OJKFrameworkCombined,
		RetentionDays:    3650,
		MinRetentionDays: IndonesiaRetentionDays,
	}, nil
}

func (m *mockOJKService) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*OJKComplianceReadinessResponse, error) {
	m.readinessCalled = true
	return &OJKComplianceReadinessResponse{
		Ready:     true,
		Score:     100,
		Framework: OJKFrameworkCombined,
		Checks: []OJKComplianceCheck{
			{Name: "Data Retention", Status: "pass"},
		},
	}, nil
}

func (m *mockOJKService) SubmitBreachNotification(ctx context.Context, tenantID string, req *OJKBreachNotification) (*OJKBreachNotification, error) {
	m.breachCalled = true
	req.ID = "test-breach-id"
	req.Status = "submitted"
	req.CreatedAt = time.Now().UTC()
	req.NotificationDeadline = req.DiscoveryTime.Add(72 * time.Hour)
	return req, nil
}

func (m *mockOJKService) GetDashboard(ctx context.Context, tenantID string) (*OJKDashboardResponse, error) {
	m.dashboardCalled = true
	return &OJKDashboardResponse{
		Framework:       OJKFrameworkCombined,
		ComplianceScore: 100,
		LastUpdated:     time.Now().UTC(),
	}, nil
}

func (m *mockOJKService) AcknowledgeBreachNotification(ctx context.Context, tenantID string, id string) (*OJKBreachNotification, error) {
	m.ackCalled = true
	if m.ackErr != nil {
		return nil, m.ackErr
	}
	return &OJKBreachNotification{ID: id, Status: string(BreachStatusAcknowledged)}, nil
}

func (m *mockOJKService) EvaluateBreachDeadlines(ctx context.Context, tenantID string) (int, error) {
	m.evalCalled = true
	if m.evalErr != nil {
		return 0, m.evalErr
	}
	return m.evalFlipped, nil
}

func TestHandleExport_POST(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	body := `{"start_date":"2025-01-01","end_date":"2025-12-31","format":"json","framework":"OJK_BI_COMBINED"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/audit/export", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}
	if !svc.exportCalled {
		t.Error("service ExportAuditData was not called")
	}

	var resp OJKAuditExportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if resp.ExportID == "" {
		t.Error("response should have export_id")
	}
}

func TestHandleExport_MissingTenant(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	body := `{"start_date":"2025-01-01","end_date":"2025-12-31"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/audit/export", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleExport_InvalidMethod(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/export", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleRetention_GET(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/retention", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleRetentionStatus(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !svc.retentionCalled {
		t.Error("service GetRetentionStatus was not called")
	}
}

func TestHandleReadiness_GET(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/readiness", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleComplianceReadiness(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !svc.readinessCalled {
		t.Error("service ValidateComplianceReadiness was not called")
	}

	var resp OJKComplianceReadinessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if resp.Score != 100 {
		t.Errorf("score = %d, want 100", resp.Score)
	}
}

func TestHandleBreachNotify_POST(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	now := time.Now().UTC()
	notification := OJKBreachNotification{
		IncidentTimestamp:    now.Add(-24 * time.Hour),
		DiscoveryTime:        now,
		DataSubjectsAffected: 1000,
		DataTypesInvolved:    []string{"nik", "phone"},
		Description:          "Unauthorized access to customer records",
		RemediationSteps:     []string{"Revoke access", "Notify affected users"},
	}

	body, _ := json.Marshal(notification)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/notify", bytes.NewBuffer(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleBreachNotify(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d; body: %s", w.Code, http.StatusCreated, w.Body.String())
	}
	if !svc.breachCalled {
		t.Error("service SubmitBreachNotification was not called")
	}
}

func TestHandleBreachNotify_MissingFields(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	// Missing required fields
	body := `{"description": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/breach/notify", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleBreachNotify(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleDashboard_GET(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/dashboard", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.handleDashboard(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !svc.dashboardCalled {
		t.Error("service GetDashboard was not called")
	}
}

func TestValidateExportRequest(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	tests := []struct {
		name    string
		req     OJKAuditExportRequest
		wantErr bool
	}{
		{"valid", OJKAuditExportRequest{StartDate: "2025-01-01", EndDate: "2025-12-31"}, false},
		{"missing start", OJKAuditExportRequest{EndDate: "2025-12-31"}, true},
		{"missing end", OJKAuditExportRequest{StartDate: "2025-01-01"}, true},
		{"invalid start format", OJKAuditExportRequest{StartDate: "01-01-2025", EndDate: "2025-12-31"}, true},
		{"end before start", OJKAuditExportRequest{StartDate: "2025-12-31", EndDate: "2025-01-01"}, true},
		{"range > 5 years", OJKAuditExportRequest{StartDate: "2019-01-01", EndDate: "2025-12-31"}, true},
		{"invalid format", OJKAuditExportRequest{StartDate: "2025-01-01", EndDate: "2025-12-31", Format: "pdf"}, true},
		{"valid format", OJKAuditExportRequest{StartDate: "2025-01-01", EndDate: "2025-12-31", Format: "csv"}, false},
		{"invalid framework", OJKAuditExportRequest{StartDate: "2025-01-01", EndDate: "2025-12-31", Framework: "INVALID"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateExportRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateExportRequest() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateBreachNotification(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	now := time.Now()

	tests := []struct {
		name    string
		req     OJKBreachNotification
		wantErr bool
	}{
		{
			"valid",
			OJKBreachNotification{
				IncidentTimestamp:    now,
				DiscoveryTime:       now,
				DataSubjectsAffected: 1,
				DataTypesInvolved:   []string{"nik"},
				Description:         "breach",
				RemediationSteps:    []string{"fix"},
			},
			false,
		},
		{"missing incident", OJKBreachNotification{DiscoveryTime: now, DataSubjectsAffected: 1, DataTypesInvolved: []string{"nik"}, Description: "x", RemediationSteps: []string{"y"}}, true},
		{"zero subjects", OJKBreachNotification{IncidentTimestamp: now, DiscoveryTime: now, DataSubjectsAffected: 0, DataTypesInvolved: []string{"nik"}, Description: "x", RemediationSteps: []string{"y"}}, true},
		{"empty data types", OJKBreachNotification{IncidentTimestamp: now, DiscoveryTime: now, DataSubjectsAffected: 1, DataTypesInvolved: []string{}, Description: "x", RemediationSteps: []string{"y"}}, true},
		{"empty description", OJKBreachNotification{IncidentTimestamp: now, DiscoveryTime: now, DataSubjectsAffected: 1, DataTypesInvolved: []string{"nik"}, Description: "", RemediationSteps: []string{"y"}}, true},
		{"empty remediation", OJKBreachNotification{IncidentTimestamp: now, DiscoveryTime: now, DataSubjectsAffected: 1, DataTypesInvolved: []string{"nik"}, Description: "x", RemediationSteps: []string{}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateBreachNotification(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateBreachNotification() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHandleCORS(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/audit/export", nil)
		req.Header.Set("Origin", "https://app.getaxonflow.com")
		w := httptest.NewRecorder()

		handler.handleExport(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("CORS status = %d, want %d", w.Code, http.StatusNoContent)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "https://app.getaxonflow.com" {
			t.Error("CORS origin header not set for allowed origin")
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/audit/export", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		w := httptest.NewRecorder()

		handler.handleExport(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("CORS should NOT set origin header for disallowed origin")
		}
	})
}

func TestGetTenantID_Precedence(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})

	t.Run("X-Tenant-ID takes precedence", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Tenant-ID", "tenant-a")
		req.Header.Set("X-Org-ID", "org-b")
		if id := handler.getTenantID(req); id != "tenant-a" {
			t.Errorf("getTenantID = %q, want tenant-a", id)
		}
	})

	t.Run("Falls back to X-Org-ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("X-Org-ID", "org-b")
		if id := handler.getTenantID(req); id != "org-b" {
			t.Errorf("getTenantID = %q, want org-b", id)
		}
	})
}

func TestRegisterRoutes_ServeMux(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// POST /api/v1/ojk/audit/export via ServeMux
	body := `{"start_date":"2025-01-01","end_date":"2025-12-31"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/audit/export", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("ServeMux export: status = %d, want 200", w.Code)
	}
}

func TestHandleExportByID_NonMux(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/export/test-id-abc", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleExportByID(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestHandleExportByID_MissingID(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/export/", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleExportByID(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleExportByID_Options(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/audit/export/test-id", nil)
	req.Header.Set("X-Tenant-ID", "test")
	req.Header.Set("Origin", "https://app.getaxonflow.com")
	w := httptest.NewRecorder()
	handler.handleExportByID(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", w.Code)
	}
}

func TestHandleRetention_InvalidMethod(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/audit/retention", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleRetentionStatus(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleReadiness_InvalidMethod(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/audit/readiness", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleComplianceReadiness(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleDashboard_InvalidMethod(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ojk/dashboard", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleDashboard(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleBreachNotify_InvalidMethod(t *testing.T) {
	handler := NewOJKAuditExportHandler(&mockOJKService{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/breach/notify", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleBreachNotify(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHandleRetention_WithDataTypes(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ojk/audit/retention?data_types=policy_violations,llm_calls", nil)
	req.Header.Set("X-Tenant-ID", "test")
	w := httptest.NewRecorder()
	handler.handleRetentionStatus(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestHandleOJKModuleCORS(t *testing.T) {
	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/dashboard", nil)
		req.Header.Set("Origin", "https://app.getaxonflow.com")
		w := httptest.NewRecorder()
		handleOJKModuleCORS(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
		if w.Header().Get("Access-Control-Allow-Origin") != "https://app.getaxonflow.com" {
			t.Error("CORS origin not set")
		}
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/dashboard", nil)
		req.Header.Set("Origin", "https://evil.com")
		w := httptest.NewRecorder()
		handleOJKModuleCORS(w, req)
		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Error("CORS should not allow evil.com")
		}
	})

	t.Run("no origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/ojk/dashboard", nil)
		w := httptest.NewRecorder()
		handleOJKModuleCORS(w, req)
		if w.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", w.Code)
		}
	})
}

func TestRegisterRoutesWithMux_RegistersAllEndpoints(t *testing.T) {
	svc := &mockOJKService{}
	handler := NewOJKAuditExportHandler(svc)
	module := &OJKModule{
		AuditService: svc,
		AuditHandler: handler,
	}
	mux := http.NewServeMux()
	module.RegisterRoutes(mux)

	// Verify all 6 functional routes via ServeMux
	paths := []struct {
		method string
		path   string
		body   string
		expect int
	}{
		{http.MethodPost, "/api/v1/ojk/audit/export", `{"start_date":"2025-01-01","end_date":"2025-12-31"}`, 200},
		{http.MethodGet, "/api/v1/ojk/audit/retention", "", 200},
		{http.MethodGet, "/api/v1/ojk/audit/readiness", "", 200},
		{http.MethodGet, "/api/v1/ojk/dashboard", "", 200},
	}

	for _, p := range paths {
		var bodyReader *bytes.Buffer
		if p.body != "" {
			bodyReader = bytes.NewBufferString(p.body)
		} else {
			bodyReader = &bytes.Buffer{}
		}
		req := httptest.NewRequest(p.method, p.path, bodyReader)
		req.Header.Set("X-Tenant-ID", "test")
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != p.expect {
			t.Errorf("%s %s: status = %d, want %d; body: %s", p.method, p.path, w.Code, p.expect, w.Body.String())
		}
	}
}
