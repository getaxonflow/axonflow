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
