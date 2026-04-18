// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package sebi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewSEBIModule_NilDB(t *testing.T) {
	config := SEBIModuleConfig{
		DB: nil,
	}

	module, err := NewSEBIModule(config)
	if err != nil {
		t.Fatalf("NewSEBIModule() error = %v", err)
	}

	if module == nil {
		t.Fatal("NewSEBIModule() returned nil module")
	}

	if module.AuditService != nil {
		t.Error("NewSEBIModule() AuditService should be nil when DB is nil")
	}

	if module.AuditHandler != nil {
		t.Error("NewSEBIModule() AuditHandler should be nil when AuditService is nil")
	}
}

func TestSEBIModule_HealthCheck(t *testing.T) {
	tests := []struct {
		name           string
		module         *SEBIModule
		expectedStatus map[string]string
	}{
		{
			name: "no service",
			module: &SEBIModule{
				AuditService: nil,
			},
			expectedStatus: map[string]string{
				"audit_export": "unavailable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := tt.module.HealthCheck()

			for key, expected := range tt.expectedStatus {
				if status[key] != expected {
					t.Errorf("HealthCheck()[%s] = %v, want %v", key, status[key], expected)
				}
			}
		})
	}
}

func TestSEBIModule_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		module   *SEBIModule
		expected bool
	}{
		{
			name: "nil service",
			module: &SEBIModule{
				AuditService: nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.module.IsHealthy(); got != tt.expected {
				t.Errorf("IsHealthy() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSEBIModule_RegisterRoutesWithMux_NilHandler(t *testing.T) {
	module := &SEBIModule{
		AuditHandler: nil,
	}

	r := mux.NewRouter()

	// Should not panic
	module.RegisterRoutesWithMux(r)
}

func TestSEBIModule_RegisterRoutes_NilHandler(t *testing.T) {
	module := &SEBIModule{
		AuditHandler: nil,
	}

	mux := http.NewServeMux()

	// Should not panic
	module.RegisterRoutes(mux)
}

func TestHandleSEBIModuleCORS(t *testing.T) {
	tests := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{
			name:           "allowed origin app",
			origin:         "https://app.getaxonflow.com",
			expectedOrigin: "https://app.getaxonflow.com",
		},
		{
			name:           "allowed origin customer",
			origin:         "https://customer.getaxonflow.com",
			expectedOrigin: "https://customer.getaxonflow.com",
		},
		{
			name:           "allowed origin localhost",
			origin:         "http://localhost:3000",
			expectedOrigin: "http://localhost:3000",
		},
		{
			name:           "disallowed origin",
			origin:         "https://evil.com",
			expectedOrigin: "",
		},
		{
			name:           "no origin",
			origin:         "",
			expectedOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/api/v1/sebi/audit/export", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rr := httptest.NewRecorder()

			handleSEBIModuleCORS(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("handleSEBIModuleCORS() status = %v, want %v", rr.Code, http.StatusOK)
			}

			gotOrigin := rr.Header().Get("Access-Control-Allow-Origin")
			if gotOrigin != tt.expectedOrigin {
				t.Errorf("Access-Control-Allow-Origin = %v, want %v", gotOrigin, tt.expectedOrigin)
			}

			// Check other CORS headers
			if methods := rr.Header().Get("Access-Control-Allow-Methods"); methods != "GET, POST, OPTIONS" {
				t.Errorf("Access-Control-Allow-Methods = %v, want %v", methods, "GET, POST, OPTIONS")
			}
		})
	}
}

func TestWriteModuleError(t *testing.T) {
	rr := httptest.NewRecorder()

	writeModuleError(rr, http.StatusBadRequest, "BAD_REQUEST", "Test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("writeModuleError() status = %v, want %v", rr.Code, http.StatusBadRequest)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %v, want application/json", contentType)
	}

	body := rr.Body.String()
	// json.Encoder.Encode() appends a trailing newline
	expected := `{"error":{"code":"BAD_REQUEST","message":"Test error"}}` + "\n"
	if body != expected {
		t.Errorf("writeModuleError() body = %v, want %v", body, expected)
	}
}

func TestSEBIModule_HandleDashboard_MethodNotAllowed(t *testing.T) {
	module := &SEBIModule{
		AuditHandler: nil,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sebi/dashboard", nil)
	rr := httptest.NewRecorder()

	module.handleDashboard(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleDashboard() POST status = %v, want %v", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestSEBIModule_HandleDashboard_Options(t *testing.T) {
	module := &SEBIModule{
		AuditHandler: nil,
	}

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/sebi/dashboard", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rr := httptest.NewRecorder()

	module.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleDashboard() OPTIONS status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestSEBIModule_HandleDashboard_NilHandler(t *testing.T) {
	module := &SEBIModule{
		AuditHandler: nil,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/dashboard", nil)
	rr := httptest.NewRecorder()

	module.handleDashboard(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("handleDashboard() GET with nil handler status = %v, want %v", rr.Code, http.StatusServiceUnavailable)
	}
}

func TestSEBIModule_RegisterRoutesWithMux_WithHandler(t *testing.T) {
	// Create a mock service and handler
	mockService := &mockModuleSEBIService{}
	handler := NewSEBIAuditExportHandler(mockService)

	module := &SEBIModule{
		AuditService: mockService,
		AuditHandler: handler,
	}

	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r)

	// Test that routes are registered
	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/sebi/audit/export"},
		{"GET", "/api/v1/sebi/audit/export/test-export-id"},
		{"GET", "/api/v1/sebi/audit/retention"},
		{"GET", "/api/v1/sebi/audit/readiness"},
		{"GET", "/api/v1/sebi/dashboard"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-Tenant-ID", "travel-us")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			// Should not get 404 (route should be matched)
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s not found, got status %d", tt.method, tt.path, rr.Code)
			}
		})
	}
}

func TestSEBIModule_HandleExportByIDWithMux(t *testing.T) {
	mockService := &mockModuleSEBIService{}
	handler := NewSEBIAuditExportHandler(mockService)

	module := &SEBIModule{
		AuditService: mockService,
		AuditHandler: handler,
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/sebi/audit/export/{id}", module.handleExportByIDWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/audit/export/test-123", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should return 200 (mock service returns success)
	if rr.Code != http.StatusOK {
		t.Errorf("handleExportByIDWithMux() status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestSEBIModule_HandleDashboard_WithHandler(t *testing.T) {
	mockService := &mockModuleSEBIService{}
	handler := NewSEBIAuditExportHandler(mockService)

	module := &SEBIModule{
		AuditService: mockService,
		AuditHandler: handler,
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sebi/dashboard", nil)
	req.Header.Set("X-Tenant-ID", "travel-us")
	rr := httptest.NewRecorder()

	module.handleDashboard(rr, req)

	// Should return 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("handleDashboard() status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestSEBIModule_RegisterRoutes_WithHandler(t *testing.T) {
	mockService := &mockModuleSEBIService{}
	handler := NewSEBIAuditExportHandler(mockService)

	module := &SEBIModule{
		AuditService: mockService,
		AuditHandler: handler,
	}

	serveMux := http.NewServeMux()
	module.RegisterRoutes(serveMux)

	// Test that routes are registered
	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/sebi/audit/export"},
		{"GET", "/api/v1/sebi/audit/export/test-id"},
		{"GET", "/api/v1/sebi/audit/retention"},
		{"GET", "/api/v1/sebi/audit/readiness"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-Tenant-ID", "travel-us")
			rr := httptest.NewRecorder()
			serveMux.ServeHTTP(rr, req)

			// Should not get 404
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s not found", tt.method, tt.path)
			}
		})
	}
}

func TestSEBIModule_HealthCheck_WithService(t *testing.T) {
	mockService := &mockModuleSEBIService{}

	module := &SEBIModule{
		AuditService: mockService,
	}

	status := module.HealthCheck()

	if status["audit_export"] != "ok" {
		t.Errorf("HealthCheck()[audit_export] = %v, want ok", status["audit_export"])
	}
}

func TestSEBIModule_IsHealthy_WithService(t *testing.T) {
	mockService := &mockModuleSEBIService{}

	module := &SEBIModule{
		AuditService: mockService,
	}

	if !module.IsHealthy() {
		t.Error("IsHealthy() = false, want true")
	}
}

// mockModuleSEBIService implements SEBIAuditExportService for module-level tests
type mockModuleSEBIService struct{}

func (m *mockModuleSEBIService) ExportAuditData(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error) {
	return &SEBIAuditExportResponse{
		ExportID: "test-export",
		Status:   "completed",
	}, nil
}

func (m *mockModuleSEBIService) GetRetentionStatus(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error) {
	return &SEBIRetentionStatusResponse{
		TenantID:         tenantID,
		ComplianceStatus: "COMPLIANT",
	}, nil
}

func (m *mockModuleSEBIService) GetExportStatus(ctx context.Context, tenantID string, exportID string) (*SEBIAuditExportResponse, error) {
	return &SEBIAuditExportResponse{
		ExportID: exportID,
		Status:   "completed",
	}, nil
}

func (m *mockModuleSEBIService) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error) {
	return &SEBIComplianceReadinessResponse{
		Ready: true,
		Score: 100,
	}, nil
}
