//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewOJKModule_Community(t *testing.T) {
	config := OJKModuleConfig{
		DB: nil,
	}

	module, err := NewOJKModule(config)
	if err != nil {
		t.Fatalf("NewOJKModule() error = %v", err)
	}

	if module == nil {
		t.Fatal("NewOJKModule() returned nil module")
	}
}

func TestOJKModule_IsHealthy_Community(t *testing.T) {
	module := &OJKModule{}

	if module.IsHealthy() {
		t.Error("IsHealthy() should return false for Community stub")
	}
}

func TestOJKModule_HealthCheck_Community(t *testing.T) {
	module := &OJKModule{}

	status := module.HealthCheck()

	if status["audit_export"] != "disabled" {
		t.Errorf("HealthCheck()[audit_export] = %v, want disabled", status["audit_export"])
	}
}

func TestOJKModule_RegisterRoutes_Community(t *testing.T) {
	module := &OJKModule{}
	mux := http.NewServeMux()

	// Should not panic
	module.RegisterRoutes(mux)
}

func TestOJKModule_RegisterRoutesWithMux_Community(t *testing.T) {
	module := &OJKModule{}
	r := mux.NewRouter()

	// Should not panic
	module.RegisterRoutesWithMux(r)
}
