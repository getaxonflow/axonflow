// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/shared/plugincompat"
	"os"
	"strings"
	"testing"

	"axonflow/platform/shared/version"
)

// TestSDKCompatibilityPinnedToReleaseTrain pins the orchestrator's SDK
// version compat block to the v8.0.0 release train. This regresses on the
// drift that left orchestrator's /health reporting last-cycle pins while
// the agent's /health correctly reported the new train — operators hitting
// orchestrator /health for diagnostics would see inconsistent guidance
// versus the agent surface.
//
// Update both files in lockstep on the next release train; this test
// failing is the loud reminder that they have to move together.
func TestSDKCompatibilityPinnedToReleaseTrain(t *testing.T) {
	c := getSDKCompatibility()

	wantMin := map[string]string{
		"python":     "8.0.0",
		"typescript": "8.0.0",
		"go":         "8.0.0",
		"java":       "8.0.0",
		"rust":       "0.7.0",
	}
	wantRecommended := map[string]string{
		"python":     "9.2.0",
		"typescript": "9.2.0",
		"go":         "9.2.0",
		"java":       "9.2.0",
		"rust":       "0.9.0",
	}

	for lang, want := range wantMin {
		if got := c.MinSDKVersion[lang]; got != want {
			t.Errorf("MinSDKVersion[%q] = %q; want %q", lang, got, want)
		}
	}
	for lang, want := range wantRecommended {
		if got := c.RecommendedSDKVersion[lang]; got != want {
			t.Errorf("RecommendedSDKVersion[%q] = %q; want %q", lang, got, want)
		}
	}
	if len(c.MinSDKVersion) != 5 || len(c.RecommendedSDKVersion) != 5 {
		t.Errorf("expected 5 SDKs, got Min=%d Recommended=%d",
			len(c.MinSDKVersion), len(c.RecommendedSDKVersion))
	}
}

// TestPluginCompatComesFromTheSharedSourceOfTruth pins that this plane serves
// exactly what platform/shared/plugincompat holds.
//
// Successor to TestPluginCompatibilityPinnedToReleaseTrain, which hardcoded the
// values here. That was right while the orchestrator held its own copy — it is
// the test that caught one-sided drift — but now that both planes read one map,
// a second hardcoded list would be a third place to forget on a bump. The values
// are pinned once, in plugincompat's own test; this asserts the wiring.
func TestPluginCompatComesFromTheSharedSourceOfTruth(t *testing.T) {
	got := getPluginCompatibility()

	for name, pair := range map[string][2]map[string]string{
		"MinPluginVersion":         {got.MinPluginVersion, plugincompat.MinVersions()},
		"RecommendedPluginVersion": {got.RecommendedPluginVersion, plugincompat.RecommendedVersions()},
	} {
		served, canonical := pair[0], pair[1]
		if len(canonical) == 0 {
			t.Fatalf("%s: plugincompat returned an empty map — comparing two empty maps would pass", name)
		}
		if len(served) != len(canonical) {
			t.Errorf("%s: served %d entries, plugincompat holds %d", name, len(served), len(canonical))
		}
		for id, want := range canonical {
			if served[id] != want {
				t.Errorf("%s[%q] = %q; plugincompat holds %q", name, id, served[id], want)
			}
		}
		for id := range served {
			if _, ok := canonical[id]; !ok {
				t.Errorf("%s has key %q that plugincompat does not", name, id)
			}
		}
	}
}

// TestSDKFloorCommentAttribution mirrors the agent-side test. The SDK
// major bump v7 → v8 landed during the v7.9.0 release-train (#2016 +
// #2102), not the v8.0.0 platform bump (#2308). Keep the comment cite
// here in lockstep with platform/agent/capabilities.go.
func TestSDKFloorCommentAttribution(t *testing.T) {
	src, err := os.ReadFile("capabilities.go")
	if err != nil {
		t.Fatalf("read capabilities.go: %v", err)
	}
	s := string(src)

	startMarker := "func getSDKCompatibility() SDKCompatInfo {"
	endMarker := "func getPluginCompatibility()"
	startIdx := strings.Index(s, startMarker)
	endIdx := strings.Index(s, endMarker)
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		t.Fatalf("could not locate getSDKCompatibility() block: start=%d end=%d", startIdx, endIdx)
	}
	sdkBlock := s[startIdx:endIdx]

	if !strings.Contains(sdkBlock, "v7.9.0 release-train") {
		t.Errorf("getSDKCompatibility() comment must cite the v7.9.0 release-train as the location of the SDK v7→v8 floor bump (per axonflow-docs/docs/releases/v7-9-0.md and PR #2016+#2102). Got:\n%s", sdkBlock)
	}
	if !strings.Contains(sdkBlock, "#2016") {
		t.Errorf("getSDKCompatibility() comment must cite #2016 (the pre-emptive SDK floor bump PR). Got:\n%s", sdkBlock)
	}
	if strings.Contains(sdkBlock, "With the v8.0.0 release-train") {
		t.Errorf("getSDKCompatibility() comment must NOT say 'With the v8.0.0 release-train the SDK major bumps from v7 to v8' — that is historically false. The v8.0.0 platform bump (#2308) did NOT change the SDK floor. Got:\n%s", sdkBlock)
	}
}

// TestPluginFloorCommentAttribution guards the historical-attribution narrative
// for the plugin floors. The plugin v1.4.0 / v2.4.0 floor + recommended-version
// bump landed during the v7.9.0 release-train (#2102 on 2026-05-09), not the
// v8.0.0 platform bump (#2308). PR #2311 fixed the MinPluginVersion narrative;
// the structurally-identical RecommendedPluginVersion narrative directly below it
// was missed twice. This test catches both at once.
//
// It reads platform/shared/plugincompat, not this package: the two duplicated map
// literals were replaced by that single source of truth, and the narrative moved
// with the values it explains. Pointing this guard at the old location would have
// meant retiring it because its subject moved — which is exactly how the
// attribution was lost the first two times. The orchestrator has the mirror of
// this test and both now read the same file.
func TestPluginFloorCommentAttribution(t *testing.T) {
	const narrativePath = "../shared/plugincompat/plugincompat.go"
	src, err := os.ReadFile(narrativePath)
	if err != nil {
		t.Fatalf("read %s: %v", narrativePath, err)
	}
	pluginBlock := string(src)

	// Required PR citation: #2102 (the v7.9.0 release-train PR that
	// landed both the plugin floor + recommended bump) must appear at
	// least twice — once in MinPluginVersion, once in
	// RecommendedPluginVersion.
	prCount := strings.Count(pluginBlock, "#2102")
	if prCount < 2 {
		t.Errorf("getPluginCompatibility() must cite #2102 in BOTH the MinPluginVersion and RecommendedPluginVersion comment blocks (found %d, want ≥2). Got:\n%s", prCount, pluginBlock)
	}

	if strings.Contains(pluginBlock, "alongside the SDK v8.0.0 release-train") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'alongside the SDK v8.0.0 release-train' — that is historically false (plugin tags shipped at v7.9.0 release-train, #2102). Got:\n%s", pluginBlock)
	}
}

// TestGetPlatformVersionBakedWinsOverEnv is the #2662 anti-spoof guard at the
// orchestrator /health reader level: a version baked into the binary must win
// over a conflicting AXONFLOW_VERSION env var, so /health reports the true
// shipped binary version and cannot be overridden at runtime.
func TestGetPlatformVersionBakedWinsOverEnv(t *testing.T) {
	prev := version.Version
	version.Version = "8.7.0"
	t.Cleanup(func() { version.Version = prev })
	t.Setenv("AXONFLOW_VERSION", "1.2.3-spoofed")

	if got := getPlatformVersion(); got != "8.7.0" {
		t.Errorf("getPlatformVersion() = %q, want baked 8.7.0 (env must NOT win)", got)
	}
}

// TestGetPlatformVersionEnvFallbackWhenUnbaked covers the dev path: with no
// baked version, the env var is used; an invalid env value falls to the default.
func TestGetPlatformVersionEnvFallbackWhenUnbaked(t *testing.T) {
	prev := version.Version
	version.Version = ""
	t.Cleanup(func() { version.Version = prev })

	t.Setenv("AXONFLOW_VERSION", "4.8.0")
	if got := getPlatformVersion(); got != "4.8.0" {
		t.Errorf("getPlatformVersion() = %q, want env fallback 4.8.0", got)
	}

	t.Setenv("AXONFLOW_VERSION", "not-a-semver")
	if got := getPlatformVersion(); got != "1.0.0" {
		t.Errorf("getPlatformVersion() = %q, want default 1.0.0 for invalid env", got)
	}
}
