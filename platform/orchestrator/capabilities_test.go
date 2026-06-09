// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"strings"
	"testing"
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
	}
	wantRecommended := map[string]string{
		"python":     "8.5.0",
		"typescript": "8.5.0",
		"go":         "8.5.0",
		"java":       "8.5.0",
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
	if len(c.MinSDKVersion) != 4 || len(c.RecommendedSDKVersion) != 4 {
		t.Errorf("expected 4 SDKs, got Min=%d Recommended=%d",
			len(c.MinSDKVersion), len(c.RecommendedSDKVersion))
	}
}

// TestPluginCompatibilityPinnedToReleaseTrain pins the orchestrator's
// plugin compat block to the same release-train values the agent's
// PluginCompatInfo carries. The block was missing entirely before the
// orchestrator-vs-agent compat-drift fix; this test prevents regression
// to the empty / missing state.
func TestPluginCompatibilityPinnedToReleaseTrain(t *testing.T) {
	c := getPluginCompatibility()

	wantMin := map[string]string{
		"openclaw":    "2.4.0",
		"claude-code": "1.4.0",
		"cursor":      "1.4.0",
		"codex":       "1.4.0",
	}
	wantRecommended := map[string]string{
		"openclaw":    "2.6.5",
		"claude-code": "1.5.3",
		"cursor":      "1.5.3",
		"codex":       "1.5.2",
	}

	for id, want := range wantMin {
		if got := c.MinPluginVersion[id]; got != want {
			t.Errorf("MinPluginVersion[%q] = %q; want %q", id, got, want)
		}
	}
	for id, want := range wantRecommended {
		if got := c.RecommendedPluginVersion[id]; got != want {
			t.Errorf("RecommendedPluginVersion[%q] = %q; want %q", id, got, want)
		}
	}
	if len(c.MinPluginVersion) != 4 || len(c.RecommendedPluginVersion) != 4 {
		t.Errorf("expected 4 plugins, got Min=%d Recommended=%d",
			len(c.MinPluginVersion), len(c.RecommendedPluginVersion))
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

// TestPluginFloorCommentAttribution mirrors the agent-side test. Same
// scope: catches drift in either the MinPluginVersion or
// RecommendedPluginVersion narrative blocks of getPluginCompatibility().
func TestPluginFloorCommentAttribution(t *testing.T) {
	src, err := os.ReadFile("capabilities.go")
	if err != nil {
		t.Fatalf("read capabilities.go: %v", err)
	}
	s := string(src)

	startMarker := "func getPluginCompatibility() PluginCompatInfo {"
	startIdx := strings.Index(s, startMarker)
	if startIdx == -1 {
		t.Fatalf("could not locate getPluginCompatibility() block start")
	}
	endIdx := strings.Index(s[startIdx+len(startMarker):], "\nfunc ")
	if endIdx == -1 {
		endIdx = len(s) - startIdx
	} else {
		endIdx += len(startMarker)
	}
	pluginBlock := s[startIdx : startIdx+endIdx]

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
