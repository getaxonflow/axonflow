//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

package euaiact

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewModule_Community(t *testing.T) {
	module, err := NewModule(ModuleConfig{})
	if err != nil {
		t.Fatalf("NewModule() error = %v", err)
	}
	if module == nil {
		t.Fatal("NewModule() returned nil")
	}
}

func TestModule_IsHealthy_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	if module.IsHealthy() {
		t.Error("IsHealthy() should return false in Community builds")
	}
}

func TestModule_HealthCheck_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	health := module.HealthCheck()

	expected := map[string]string{
		"export":     "disabled",
		"conformity": "disabled",
		"accuracy":   "disabled",
	}

	for k, v := range expected {
		if health[k] != v {
			t.Errorf("HealthCheck()[%s] = %v, want %v", k, health[k], v)
		}
	}
}

func TestModule_RegisterRoutesWithMux_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	r := mux.NewRouter()

	// Should not panic
	module.RegisterRoutesWithMux(r)

	// Test that no routes are registered by trying to access an endpoint
	req := httptest.NewRequest("GET", "/api/v1/euaiact/export", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Should return 404 since no routes are registered in Community builds
	if rr.Code != http.StatusNotFound {
		t.Errorf("Expected 404 in Community builds, got %d", rr.Code)
	}
}

func TestModule_RegisterRoutes_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	mux := http.NewServeMux()

	// Should not panic
	module.RegisterRoutes(mux)
}
