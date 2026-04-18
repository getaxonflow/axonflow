// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestModule_IsHealthy(t *testing.T) {
	tests := []struct {
		name   string
		module *Module
		want   bool
	}{
		{
			name: "all handlers initialized",
			module: &Module{
				RegistryHandler:   &RegistryHandler{},
				AssessmentHandler: &AssessmentHandler{},
				KillSwitchHandler: &KillSwitchHandler{},
			},
			want: true,
		},
		{
			name: "registry handler nil",
			module: &Module{
				RegistryHandler:   nil,
				AssessmentHandler: &AssessmentHandler{},
				KillSwitchHandler: &KillSwitchHandler{},
			},
			want: false,
		},
		{
			name: "assessment handler nil",
			module: &Module{
				RegistryHandler:   &RegistryHandler{},
				AssessmentHandler: nil,
				KillSwitchHandler: &KillSwitchHandler{},
			},
			want: false,
		},
		{
			name: "kill switch handler nil",
			module: &Module{
				RegistryHandler:   &RegistryHandler{},
				AssessmentHandler: &AssessmentHandler{},
				KillSwitchHandler: nil,
			},
			want: false,
		},
		{
			name: "all handlers nil",
			module: &Module{
				RegistryHandler:   nil,
				AssessmentHandler: nil,
				KillSwitchHandler: nil,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.module.IsHealthy(); got != tt.want {
				t.Errorf("Module.IsHealthy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestModule_HealthCheck(t *testing.T) {
	tests := []struct {
		name   string
		module *Module
		want   map[string]string
	}{
		{
			name: "all handlers initialized",
			module: &Module{
				RegistryHandler:   &RegistryHandler{},
				AssessmentHandler: &AssessmentHandler{},
				KillSwitchHandler: &KillSwitchHandler{},
			},
			want: map[string]string{
				"registry":    "ok",
				"assessments": "ok",
				"killswitch":  "ok",
			},
		},
		{
			name: "registry handler nil",
			module: &Module{
				RegistryHandler:   nil,
				AssessmentHandler: &AssessmentHandler{},
				KillSwitchHandler: &KillSwitchHandler{},
			},
			want: map[string]string{
				"registry":    "unavailable",
				"assessments": "ok",
				"killswitch":  "ok",
			},
		},
		{
			name: "all handlers nil",
			module: &Module{
				RegistryHandler:   nil,
				AssessmentHandler: nil,
				KillSwitchHandler: nil,
			},
			want: map[string]string{
				"registry":    "unavailable",
				"assessments": "unavailable",
				"killswitch":  "unavailable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.module.HealthCheck()
			for key, wantVal := range tt.want {
				if gotVal, ok := got[key]; !ok || gotVal != wantVal {
					t.Errorf("Module.HealthCheck()[%s] = %v, want %v", key, gotVal, wantVal)
				}
			}
		})
	}
}

func TestExtractAction(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/api/v1/masfeat/assessments/123/submit", "submit"},
		{"/api/v1/masfeat/assessments/123/approve", "approve"},
		{"/api/v1/masfeat/assessments/123/reject", "reject"},
		{"/api/v1/masfeat/assessments/123", "123"},
		{"/path/with/trailing/", ""},
		{"nopath", ""},  // no slash means empty result
		{"/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := extractAction(tt.path); got != tt.want {
				t.Errorf("extractAction(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestModule_RegisterRoutesWithMux_NilRouter(t *testing.T) {
	module := &Module{
		RegistryHandler:   &RegistryHandler{},
		AssessmentHandler: &AssessmentHandler{},
		KillSwitchHandler: &KillSwitchHandler{},
	}

	// Should not panic
	module.RegisterRoutesWithMux(nil)
}

func TestModule_RegisterRoutesWithMux_Success(t *testing.T) {
	registryRepo := NewMockRegistryRepository()
	assessmentRepo := NewMockAssessmentRepository()
	killSwitchRepo := NewMockKillSwitchRepository()

	registryService := NewRegistryService(registryRepo)
	assessmentService := NewAssessmentService(assessmentRepo, registryRepo, 12)
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		RegistryRepo:      registryRepo,
		AssessmentRepo:    assessmentRepo,
		KillSwitchRepo:    killSwitchRepo,
		RegistryService:   registryService,
		AssessmentService: assessmentService,
		KillSwitchService: killSwitchService,
		RegistryHandler:   NewRegistryHandler(registryService),
		AssessmentHandler: NewAssessmentHandler(assessmentService),
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	module.RegisterRoutesWithMux(router)

	// Test a few routes are registered
	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/api/v1/masfeat/registry", http.StatusBadRequest}, // Missing org ID
		{http.MethodGet, "/api/v1/masfeat/assessments", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Errorf("Expected status %d, got %d", tt.status, rec.Code)
			}
		})
	}
}

func TestModule_RegisterRoutes(t *testing.T) {
	registryRepo := NewMockRegistryRepository()
	assessmentRepo := NewMockAssessmentRepository()
	killSwitchRepo := NewMockKillSwitchRepository()

	registryService := NewRegistryService(registryRepo)
	assessmentService := NewAssessmentService(assessmentRepo, registryRepo, 12)
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		RegistryHandler:   NewRegistryHandler(registryService),
		AssessmentHandler: NewAssessmentHandler(assessmentService),
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	mux := http.NewServeMux()
	module.RegisterRoutes(mux)

	// Verify routes are registered
	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestModule_handleRegistryByIDWithMux(t *testing.T) {
	registryRepo := NewMockRegistryRepository()
	registryService := NewRegistryService(registryRepo)

	module := &Module{
		RegistryHandler: NewRegistryHandler(registryService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/registry/{id}", module.handleRegistryByIDWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/registry/sys-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should get 404 because system doesn't exist
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestModule_handleAssessmentByIDWithMux(t *testing.T) {
	registryRepo := NewMockRegistryRepository()
	assessmentRepo := NewMockAssessmentRepository()
	assessmentService := NewAssessmentService(assessmentRepo, registryRepo, 12)

	module := &Module{
		AssessmentHandler: NewAssessmentHandler(assessmentService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/assessments/{id}", module.handleAssessmentByIDWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/assessments/assess-123", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should get 404 because assessment doesn't exist
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestModule_handleAssessmentActionWithMux(t *testing.T) {
	registryRepo := NewMockRegistryRepository()
	assessmentRepo := NewMockAssessmentRepository()
	assessmentService := NewAssessmentService(assessmentRepo, registryRepo, 12)

	module := &Module{
		AssessmentHandler: NewAssessmentHandler(assessmentService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/assessments/{id}/submit", module.handleAssessmentActionWithMux).Methods("POST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/assessments/assess-123/submit", nil)
	req.Header.Set("X-Org-ID", "test-org")
	req.Header.Set("X-User-ID", "test-user")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should get 404 because assessment doesn't exist
	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestModule_handleKillSwitchByIDWithMux(t *testing.T) {
	killSwitchRepo := NewMockKillSwitchRepository()
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/killswitch/{system_id}", module.handleKillSwitchByIDWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 200 with new kill switch
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestModule_handleKillSwitchConfigureWithMux(t *testing.T) {
	killSwitchRepo := NewMockKillSwitchRepository()
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/configure", module.handleKillSwitchConfigureWithMux).Methods("POST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/configure", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 400 because no JSON body
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestModule_handleKillSwitchTriggerWithMux(t *testing.T) {
	killSwitchRepo := NewMockKillSwitchRepository()
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/trigger", module.handleKillSwitchTriggerWithMux).Methods("POST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/trigger", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 400 because no JSON body
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestModule_handleKillSwitchRestoreWithMux(t *testing.T) {
	killSwitchRepo := NewMockKillSwitchRepository()
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/restore", module.handleKillSwitchRestoreWithMux).Methods("POST")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/masfeat/killswitch/sys-001/restore", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 400 because no JSON body
	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rec.Code)
	}
}

func TestModule_handleKillSwitchHistoryWithMux(t *testing.T) {
	killSwitchRepo := NewMockKillSwitchRepository()
	killSwitchService := NewKillSwitchService(killSwitchRepo, 0.10)

	module := &Module{
		KillSwitchHandler: NewKillSwitchHandler(killSwitchService),
	}

	router := mux.NewRouter()
	router.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/history", module.handleKillSwitchHistoryWithMux).Methods("GET")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/masfeat/killswitch/sys-001/history", nil)
	req.Header.Set("X-Org-ID", "test-org")
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, req)

	// Should return 200 with empty history
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}
