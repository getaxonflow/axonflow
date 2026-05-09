// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
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
		"python":     "8.0.0",
		"typescript": "8.0.0",
		"go":         "8.0.0",
		"java":       "8.0.0",
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
		"openclaw":    "2.4.0",
		"claude-code": "1.4.0",
		"cursor":      "1.4.0",
		"codex":       "1.4.0",
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
