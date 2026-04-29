// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

func TestGetCapabilities(t *testing.T) {
	caps := getCapabilities()
	if len(caps) == 0 {
		t.Fatal("expected non-empty capabilities list")
	}

	for i, cap := range caps {
		if cap.Name == "" {
			t.Errorf("capability %d has empty name", i)
		}
		if cap.Since == "" {
			t.Errorf("capability %d (%s) has empty since", i, cap.Name)
		}
		if cap.Description == "" {
			t.Errorf("capability %d (%s) has empty description", i, cap.Name)
		}
	}
}

func TestGetCapabilitiesContainsVersionDiscovery(t *testing.T) {
	caps := getCapabilities()
	found := false
	for _, cap := range caps {
		if cap.Name == "version_discovery" {
			found = true
			if cap.Since != "4.8.0" {
				t.Errorf("version_discovery since = %q, want %q", cap.Since, "4.8.0")
			}
			break
		}
	}
	if !found {
		t.Error("expected version_discovery capability to be present")
	}
}

func TestGetSDKCompatibility(t *testing.T) {
	compat := getSDKCompatibility()
	if len(compat.MinSDKVersion) == 0 {
		t.Error("expected non-empty MinSDKVersion")
	}
	if len(compat.RecommendedSDKVersion) == 0 {
		t.Error("expected non-empty RecommendedSDKVersion")
	}
	for _, lang := range []string{"python", "typescript", "go", "java"} {
		if compat.MinSDKVersion[lang] == "" {
			t.Errorf("expected MinSDKVersion for %q", lang)
		}
		if compat.RecommendedSDKVersion[lang] == "" {
			t.Errorf("expected RecommendedSDKVersion for %q", lang)
		}
	}
}

func TestGetPluginCompatibility(t *testing.T) {
	compat := getPluginCompatibility()
	if len(compat.MinPluginVersion) == 0 {
		t.Error("expected non-empty MinPluginVersion")
	}
	if len(compat.RecommendedPluginVersion) == 0 {
		t.Error("expected non-empty RecommendedPluginVersion")
	}
	// Every plugin id the agent's integration_activation.go knows about
	// must have an entry here. A future plugin id added there without
	// mirrored entries here trips this test.
	for _, id := range []string{"openclaw", "claude-code", "cursor", "codex"} {
		if compat.MinPluginVersion[id] == "" {
			t.Errorf("expected MinPluginVersion for %q", id)
		}
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("expected RecommendedPluginVersion for %q", id)
		}
	}
}

// TestPluginCompatibilityKeysMatchKnownIntegrations is the alignment
// guard between capabilities.go and integration_activation.go. The two
// must use the same canonical plugin IDs — if integration_activation.go
// uses "claude-code" and capabilities.go uses "claude", a plugin querying
// /health for its own ID gets one answer in one place and another answer
// elsewhere. This test fails if the key sets drift apart in either
// direction.
func TestPluginCompatibilityKeysMatchKnownIntegrations(t *testing.T) {
	compat := getPluginCompatibility()

	knownIDs := make(map[string]bool, len(knownIntegrations))
	for _, k := range knownIntegrations {
		knownIDs[k.ID] = true
	}

	for id := range compat.MinPluginVersion {
		if !knownIDs[id] {
			t.Errorf("MinPluginVersion has key %q that's not in knownIntegrations", id)
		}
	}
	for id := range compat.RecommendedPluginVersion {
		if !knownIDs[id] {
			t.Errorf("RecommendedPluginVersion has key %q that's not in knownIntegrations", id)
		}
	}
	for id := range knownIDs {
		if compat.MinPluginVersion[id] == "" {
			t.Errorf("knownIntegrations id %q missing from MinPluginVersion", id)
		}
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("knownIntegrations id %q missing from RecommendedPluginVersion", id)
		}
	}

	// Both inner maps must have the same key set as each other (a min
	// without a recommended or vice versa is structural drift).
	if len(compat.MinPluginVersion) != len(compat.RecommendedPluginVersion) {
		t.Errorf(
			"MinPluginVersion has %d keys, RecommendedPluginVersion has %d — "+
				"every plugin must have both a min and a recommended entry",
			len(compat.MinPluginVersion),
			len(compat.RecommendedPluginVersion),
		)
	}
	for id := range compat.MinPluginVersion {
		if compat.RecommendedPluginVersion[id] == "" {
			t.Errorf("MinPluginVersion[%q] has no matching RecommendedPluginVersion", id)
		}
	}
}

// TestGetCapabilitiesContainsPluginCompatibility pins the new
// `plugin_compatibility` capability so a future cleanup that drops it
// from the list trips the test instead of silently telling clients the
// platform doesn't advertise plugin version info.
func TestGetCapabilitiesContainsPluginCompatibility(t *testing.T) {
	caps := getCapabilities()
	for _, cap := range caps {
		if cap.Name == "plugin_compatibility" {
			if cap.Since != "7.5.0" {
				t.Errorf("plugin_compatibility since = %q, want %q", cap.Since, "7.5.0")
			}
			return
		}
	}
	t.Error("expected plugin_compatibility capability to be present")
}

func TestGetPlatformVersion(t *testing.T) {
	// Without env var, should return default
	t.Setenv("AXONFLOW_VERSION", "")
	v := GetPlatformVersion()
	if v != defaultVersion {
		t.Errorf("got %q, want %q", v, defaultVersion)
	}

	// With valid env var
	t.Setenv("AXONFLOW_VERSION", "4.8.0")
	v = GetPlatformVersion()
	if v != "4.8.0" {
		t.Errorf("got %q, want %q", v, "4.8.0")
	}

	// With invalid env var, should fall back to default
	t.Setenv("AXONFLOW_VERSION", "invalid-version")
	v = GetPlatformVersion()
	if v != defaultVersion {
		t.Errorf("got %q, want %q", v, defaultVersion)
	}
}
