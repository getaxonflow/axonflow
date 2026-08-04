//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package masfeat

import (
	"testing"
)

func TestNewModule_Community(t *testing.T) {
	module, err := NewModule(ModuleConfig{})
	if err != nil {
		t.Fatalf("NewModule() error = %v, want nil", err)
	}
	if module == nil {
		t.Fatal("NewModule() returned nil module")
	}
}

func TestModule_IsHealthy_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	if module.IsHealthy() {
		t.Error("Community stub IsHealthy() = true, want false")
	}
}

func TestModule_HealthCheck_Community(t *testing.T) {
	module, _ := NewModule(ModuleConfig{})
	health := module.HealthCheck()

	expected := []string{"registry", "assessments", "killswitch"}
	for _, key := range expected {
		if health[key] != "disabled" {
			t.Errorf("HealthCheck()[%q] = %q, want %q", key, health[key], "disabled")
		}
	}
}
