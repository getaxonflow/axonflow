// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewModule_NilDB(t *testing.T) {
	config := ModuleConfig{
		DB: nil,
	}

	module, err := NewModule(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if module == nil {
		t.Fatal("Expected non-nil module")
	}

	// All handlers should be initialized
	if module.ExportHandler == nil {
		t.Error("Expected ExportHandler to be initialized")
	}
	if module.ConformityHandler == nil {
		t.Error("Expected ConformityHandler to be initialized")
	}
	if module.AccuracyHandler == nil {
		t.Error("Expected AccuracyHandler to be initialized")
	}
}

func TestNewModule_WithConfig(t *testing.T) {
	config := ModuleConfig{
		DB:                   nil,
		DefaultAccuracyMin:   0.90,
		DefaultBiasMax:       0.05,
		AlertCooldownMinutes: 30,
	}

	module, err := NewModule(config)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if module == nil {
		t.Fatal("Expected non-nil module")
	}

	// Check accuracy service config was applied
	if module.AccuracyService.config.DefaultAccuracyMin != 0.90 {
		t.Errorf("Expected DefaultAccuracyMin 0.90, got %f", module.AccuracyService.config.DefaultAccuracyMin)
	}
}

func TestModule_RegisterRoutes(t *testing.T) {
	// Create module with mock repositories to avoid nil DB panic
	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(NewMockExportRepository(), nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	serveMux := http.NewServeMux()
	module.RegisterRoutes(serveMux)

	// Test that routes are registered by making requests
	// Note: These will return various status codes based on missing org ID, etc.
	// The key is they should NOT return 404 (which means route is registered)
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/euaiact/export"},
		{"POST", "/api/v1/euaiact/export"},
		{"GET", "/api/v1/euaiact/conformity"},
		{"POST", "/api/v1/euaiact/conformity"},
		{"GET", "/api/v1/euaiact/accuracy"},
		{"POST", "/api/v1/euaiact/accuracy/record"},
		{"POST", "/api/v1/euaiact/accuracy/bias"},
		{"GET", "/api/v1/euaiact/accuracy/history"},
		{"GET", "/api/v1/euaiact/accuracy/alerts"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			// Don't set X-Org-ID - handler will return 400, but not 404
			rr := httptest.NewRecorder()
			serveMux.ServeHTTP(rr, req)

			// Should not get 404 (route should be registered)
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s not found", tt.method, tt.path)
			}
		})
	}
}

func TestModule_RegisterRoutesWithMux(t *testing.T) {
	// Create mock repos with test data to avoid 404s for resource lookups
	exportRepo := NewMockExportRepository()
	exportRepo.exports["export-123"] = &Export{ID: "export-123", OrgID: "test-org", Status: ExportStatusCompleted}

	conformityRepo := NewMockConformityRepository()
	conformityRepo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusDraft,
		Requirements: []RequirementStatus{
			{RequirementID: "req-1", Article: "Article 9", Description: "Risk management", Status: "compliant"},
		},
	}

	alertRepo := NewMockAccuracyRepository()
	alertRepo.alerts["alert-123"] = &AccuracyAlert{ID: "alert-123", OrgID: "test-org"}

	// Create module with mock repositories
	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(exportRepo, nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(conformityRepo)),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(alertRepo, AccuracyServiceConfig{})),
	}

	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r)

	// Test that routes are registered
	// Note: Some routes return various error codes when resources don't exist
	// The key is they should NOT return 404 (which means route not matched)
	// Download route is excluded since it returns 404 when file doesn't exist
	tests := []struct {
		method string
		path   string
	}{
		{"GET", "/api/v1/euaiact/export"},
		{"POST", "/api/v1/euaiact/export"},
		{"GET", "/api/v1/euaiact/export/export-123"},
		// Note: Download route excluded - returns 404 when file doesn't exist (not route mismatch)
		{"GET", "/api/v1/euaiact/conformity"},
		{"POST", "/api/v1/euaiact/conformity"},
		{"GET", "/api/v1/euaiact/conformity/assess-123"},
		{"PUT", "/api/v1/euaiact/conformity/assess-123"},
		{"POST", "/api/v1/euaiact/conformity/assess-123/submit"},
		{"POST", "/api/v1/euaiact/conformity/assess-123/approve"},
		{"POST", "/api/v1/euaiact/conformity/assess-123/reject"},
		{"GET", "/api/v1/euaiact/accuracy"},
		{"POST", "/api/v1/euaiact/accuracy/record"},
		{"POST", "/api/v1/euaiact/accuracy/bias"},
		{"GET", "/api/v1/euaiact/accuracy/history"},
		{"GET", "/api/v1/euaiact/accuracy/alerts"},
		{"GET", "/api/v1/euaiact/accuracy/alerts/alert-123"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("X-Org-ID", "test-org")
			req.Header.Set("X-User-ID", "test-user")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			// Should not get 404 (route should be registered)
			if rr.Code == http.StatusNotFound {
				t.Errorf("Route %s %s not found, got status %d", tt.method, tt.path, rr.Code)
			}
		})
	}
}

func TestModule_IsHealthy(t *testing.T) {
	// Create module with mock repositories
	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(NewMockExportRepository(), nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	if !module.IsHealthy() {
		t.Error("Expected module to be healthy")
	}
}

func TestModule_IsHealthy_NilHandlers(t *testing.T) {
	module := &Module{}

	if module.IsHealthy() {
		t.Error("Expected unhealthy module with nil handlers")
	}
}

func TestModule_HealthCheck(t *testing.T) {
	// Create module with mock repositories
	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(NewMockExportRepository(), nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	status := module.HealthCheck()

	if status["export"] != "ok" {
		t.Errorf("Expected export status 'ok', got '%s'", status["export"])
	}
	if status["conformity"] != "ok" {
		t.Errorf("Expected conformity status 'ok', got '%s'", status["conformity"])
	}
	if status["accuracy"] != "ok" {
		t.Errorf("Expected accuracy status 'ok', got '%s'", status["accuracy"])
	}
}

func TestModule_HealthCheck_NilHandlers(t *testing.T) {
	module := &Module{}

	status := module.HealthCheck()

	if status["export"] != "unavailable" {
		t.Errorf("Expected export status 'unavailable', got '%s'", status["export"])
	}
	if status["conformity"] != "unavailable" {
		t.Errorf("Expected conformity status 'unavailable', got '%s'", status["conformity"])
	}
	if status["accuracy"] != "unavailable" {
		t.Errorf("Expected accuracy status 'unavailable', got '%s'", status["accuracy"])
	}
}

func TestExtractAction(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/euaiact/conformity/id/submit", "submit"},
		{"/api/v1/euaiact/conformity/id/approve", "approve"},
		{"/api/v1/euaiact/conformity/id/reject", "reject"},
		{"/api/v1/euaiact/conformity/id", "id"},
		{"/path/to/action", "action"},
		{"action", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := extractAction(tt.path)
			if result != tt.expected {
				t.Errorf("extractAction(%q) = %q, want %q", tt.path, result, tt.expected)
			}
		})
	}
}

func createTestModule() *Module {
	return &Module{
		ExportHandler:     NewExportHandler(NewExportService(NewMockExportRepository(), nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}
}

func TestModule_HandleExportByIDWithMux(t *testing.T) {
	// Create mock repo with an export
	exportRepo := NewMockExportRepository()
	exportRepo.exports["export-123"] = &Export{ID: "export-123", OrgID: "test-org", Status: ExportStatusCompleted}

	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(exportRepo, nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/euaiact/export/{id}", module.handleExportByIDWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should get 200 OK
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
}

func TestModule_HandleExportDownloadWithMux(t *testing.T) {
	// Create mock repo with an export
	exportRepo := NewMockExportRepository()
	exportRepo.exports["export-123"] = &Export{
		ID:       "export-123",
		OrgID:    "test-org",
		Status:   ExportStatusCompleted,
		FilePath: "/tmp/export.json",
	}

	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(exportRepo, nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(NewMockConformityRepository())),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/euaiact/export/{id}/download", module.handleExportDownloadWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/export/export-123/download", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Will get 500 or similar since file doesn't exist, but route is hit
	// Just verify it's not 404 (which would mean route not matched)
	if rr.Code == http.StatusNotFound {
		t.Error("Expected route to be handled")
	}
}

func TestModule_HandleConformityByIDWithMux(t *testing.T) {
	// Create mock repo with an assessment
	conformityRepo := NewMockConformityRepository()
	conformityRepo.assessments["assess-123"] = &ConformityAssessment{
		ID:     "assess-123",
		OrgID:  "test-org",
		Status: AssessmentStatusDraft,
	}

	module := &Module{
		ExportHandler:     NewExportHandler(NewExportService(NewMockExportRepository(), nil)),
		ConformityHandler: NewConformityHandler(NewConformityService(conformityRepo)),
		AccuracyHandler:   NewAccuracyHandler(NewAccuracyService(NewMockAccuracyRepository(), AccuracyServiceConfig{})),
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/euaiact/conformity/{id}", module.handleConformityByIDWithMux).Methods("GET", "PUT")

	// Test GET
	req := httptest.NewRequest(http.MethodGet, "/api/v1/euaiact/conformity/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d, body: %s", http.StatusOK, rr.Code, rr.Body.String())
	}
}

func TestModule_HandleConformityActionWithMux(t *testing.T) {
	module := createTestModule()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/submit", module.handleConformityActionWithMux).Methods("POST")
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/approve", module.handleConformityActionWithMux).Methods("POST")
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/reject", module.handleConformityActionWithMux).Methods("POST")

	actions := []string{"submit", "approve", "reject"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/conformity/assess-123/"+action, nil)
			// Don't set X-Org-ID - handler will return 400, but not 404
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code == http.StatusNotFound {
				t.Errorf("Expected route for %s to be handled", action)
			}
		})
	}
}

func TestModule_HandleAlertByIDWithMux(t *testing.T) {
	module := createTestModule()

	r := mux.NewRouter()
	r.HandleFunc("/api/v1/euaiact/accuracy/alerts/{id}", module.handleAlertByIDWithMux).Methods("GET", "PUT", "POST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/euaiact/accuracy/alerts/alert-123", nil)
	// Don't set X-Org-ID - handler will return 400, but not 404
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should not get 404
	if rr.Code == http.StatusNotFound {
		t.Error("Expected route to be handled")
	}
}
