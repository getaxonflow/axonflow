//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

package rbi

import (
	"testing"
)

func TestNewRBIModule_Community(t *testing.T) {
	config := DefaultConfig()
	module, err := NewRBIModule(config)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if module == nil {
		t.Fatal("Expected non-nil module")
	}
}

func TestRBIModule_HealthCheck_Community(t *testing.T) {
	module := &RBIModule{}
	health := module.HealthCheck()

	expectedComponents := []string{
		"ai_system_registry",
		"model_validation",
		"incident_management",
		"kill_switch",
		"board_reporting",
		"audit_export",
		"pii_detector",
	}

	for _, component := range expectedComponents {
		status, ok := health[component]
		if !ok {
			t.Errorf("Missing health status for component: %s", component)
			continue
		}
		if status != "disabled" {
			t.Errorf("Expected status 'disabled' for %s in Community mode, got: %s", component, status)
		}
	}
}

func TestRBIModule_IsHealthy_Community(t *testing.T) {
	module := &RBIModule{}

	// Community stub should always return false (feature not available)
	if module.IsHealthy() {
		t.Error("Expected IsHealthy() to return false in Community mode")
	}
}

func TestRBIModule_RegisterRoutes_Community(t *testing.T) {
	module := &RBIModule{}

	// Should not panic when called with nil (no-op in Community mode)
	module.RegisterRoutes(nil)
	module.RegisterRoutesWithMux(nil)
}
