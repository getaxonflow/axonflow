//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

package sebi

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewSEBIModule_OSS(t *testing.T) {
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
}

func TestSEBIModule_IsHealthy_OSS(t *testing.T) {
	module := &SEBIModule{}

	if module.IsHealthy() {
		t.Error("IsHealthy() should return false for OSS stub")
	}
}

func TestSEBIModule_HealthCheck_OSS(t *testing.T) {
	module := &SEBIModule{}

	status := module.HealthCheck()

	if status["audit_export"] != "disabled" {
		t.Errorf("HealthCheck()[audit_export] = %v, want disabled", status["audit_export"])
	}
}

func TestSEBIModule_RegisterRoutes_OSS(t *testing.T) {
	module := &SEBIModule{}
	mux := http.NewServeMux()

	// Should not panic
	module.RegisterRoutes(mux)
}

func TestSEBIModule_RegisterRoutesWithMux_OSS(t *testing.T) {
	module := &SEBIModule{}
	r := mux.NewRouter()

	// Should not panic
	module.RegisterRoutesWithMux(r)
}
