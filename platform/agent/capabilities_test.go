// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"axonflow/platform/shared/plugincompat"
	"os"
	"strings"
	"testing"
)

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
	for _, lang := range []string{"python", "typescript", "go", "java", "rust"} {
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
	for _, id := range []string{"openclaw", "claude-code", "cursor", "codex", "claude-desktop"} {
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

// TestGetCapabilitiesContainsClientVersionTelemetry pins the 9.7.0
// `client_version_telemetry` capability (per-client version-distribution
// telemetry, #2860/#2863) so a future cleanup that drops it from the list
// trips the test instead of silently telling clients the platform doesn't
// record client-version distribution.
func TestGetCapabilitiesContainsClientVersionTelemetry(t *testing.T) {
	caps := getCapabilities()
	for _, cap := range caps {
		if cap.Name == "client_version_telemetry" {
			if cap.Since != "9.7.0" {
				t.Errorf("client_version_telemetry since = %q, want %q", cap.Since, "9.7.0")
			}
			return
		}
	}
	t.Error("expected client_version_telemetry capability to be present")
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

// TestSDKFloorCommentAttribution guards the historical-attribution narrative
// in getSDKCompatibility(). The SDK major bump v7 → v8 landed during the
// v7.9.0 platform release-train (#2016 + #2102), not the v8.0.0 platform
// bump (#2308). PR #2311 fixed the equivalent plugin-floor narrative; this
// test prevents the SDK-floor narrative from drifting back to the wrong
// "v8.0.0 release-train" framing on a future edit. See Epic #2230 follow-up.
//
// The assertion reads the actual capabilities.go source from disk so it
// catches comment-only edits that wouldn't change any compiled value but
// would re-introduce the historical falsehood.
func TestSDKFloorCommentAttribution(t *testing.T) {
	src, err := os.ReadFile("capabilities.go")
	if err != nil {
		t.Fatalf("read capabilities.go: %v", err)
	}
	s := string(src)

	// Isolate the getSDKCompatibility() function body so we don't false-
	// positive on identical strings inside the plugin-floor block below it.
	startMarker := "func getSDKCompatibility() SDKCompatInfo {"
	endMarker := "func getPluginCompatibility()"
	startIdx := strings.Index(s, startMarker)
	endIdx := strings.Index(s, endMarker)
	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		t.Fatalf("could not locate getSDKCompatibility() block: start=%d end=%d", startIdx, endIdx)
	}
	sdkBlock := s[startIdx:endIdx]

	// Required attribution: the v7.9.0 release-train is the historically-
	// correct location of the SDK v7 → v8 floor bump.
	if !strings.Contains(sdkBlock, "v7.9.0 release-train") {
		t.Errorf("getSDKCompatibility() comment must cite the v7.9.0 release-train as the location of the SDK v7→v8 floor bump (per axonflow-docs/docs/releases/v7-9-0.md and PR #2016+#2102). Got:\n%s", sdkBlock)
	}

	// Required PR citation: explicit #2016 reference removes ambiguity for
	// future readers about WHICH PR landed the floor values.
	if !strings.Contains(sdkBlock, "#2016") {
		t.Errorf("getSDKCompatibility() comment must cite #2016 (the pre-emptive SDK floor bump PR). Got:\n%s", sdkBlock)
	}

	// Banned attribution: the old comment claimed the bump happened with
	// "the v8.0.0 release-train", which is historically wrong — v8.0.0 is
	// the PLATFORM bump (#2308) and did NOT change the SDK floor. Catch
	// any regression to this wording.
	if strings.Contains(sdkBlock, "With the v8.0.0 release-train") {
		t.Errorf("getSDKCompatibility() comment must NOT say 'With the v8.0.0 release-train the SDK major bumps from v7 to v8' — that is historically false (SDK floor was bumped during v7.9.0 release-train, per #2016 + #2102). The v8.0.0 platform bump (#2308) did NOT change the SDK floor. Got:\n%s", sdkBlock)
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
	// least twice — once in the MinPluginVersion comment block, once
	// in the RecommendedPluginVersion comment block. Both blocks are
	// adjacent-class historical-attribution sites and both need the
	// explicit citation so a future "refresh the comment" edit can't
	// drop the attribution from either half.
	prCount := strings.Count(pluginBlock, "#2102")
	if prCount < 2 {
		t.Errorf("getPluginCompatibility() must cite #2102 in BOTH the MinPluginVersion and RecommendedPluginVersion comment blocks (found %d, want ≥2). The plugin tags shipped at the v7.9.0 release-train, #2102. Got:\n%s", prCount, pluginBlock)
	}

	// Banned attribution: the old comment claimed the bump happened
	// "alongside the SDK v8.0.0 release-train". That's historically false
	// (the plugin tags shipped at the v7.9.0 platform release-train) AND
	// muddles the SDK/plugin/platform layers. Catch regression to this
	// wording. NOTE the assertion is on the RecommendedPluginVersion
	// block phrasing specifically — the MinPluginVersion block uses
	// "alongside the v8.0.0 release-train" (different prefix) and was
	// already fixed by PR #2311.
	if strings.Contains(pluginBlock, "alongside the SDK v8.0.0 release-train") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'alongside the SDK v8.0.0 release-train' — that is historically false (plugin tags shipped at v7.9.0 release-train, #2102). Got:\n%s", pluginBlock)
	}

	// Banned stale framing: pre-2026-05-09 the comment said "Plugin tags
	// + registry publish are held pending explicit per-version
	// authorization ... until the tags ship". The tags ARE shipped now
	// (openclaw 2.4.0 on npm, claude/cursor/codex 1.4.0 on ClawHub).
	// Catch regression to the pending/unshipped framing.
	if strings.Contains(pluginBlock, "until the tags ship") {
		t.Errorf("getPluginCompatibility() comment must NOT say 'until the tags ship' — plugin tags are live on their registries. Got:\n%s", pluginBlock)
	}
}

// TestPluginCompatComesFromTheSharedSourceOfTruth pins that this plane serves
// exactly what platform/shared/plugincompat holds — not a copy of it.
//
// This replaces a test that compared the two capabilities.go files as SOURCE
// TEXT. That test was defeated by four shapes that compile cleanly, the worst
// being a decoy `PluginCompatInfo` literal earlier in the same function: the
// parser matched the decoy, reported agreement, and the value actually served
// was different. It also could not see the shape that caused #2962 in the first
// place — NEITHER file being touched — because two maps that agree at a stale
// value agree.
//
// Comparing the compiled result removes both problems: there is one set of
// values, and this asserts the wiring to it. It says nothing about whether those
// values are current relative to npm/ClawHub; that is a fact about a registry
// and belongs to the release runbook.
func TestPluginCompatComesFromTheSharedSourceOfTruth(t *testing.T) {
	got := getPluginCompatibility()

	for name, pair := range map[string][2]map[string]string{
		"MinPluginVersion":         {got.MinPluginVersion, plugincompat.MinVersions()},
		"RecommendedPluginVersion": {got.RecommendedPluginVersion, plugincompat.RecommendedVersions()},
	} {
		served, canonical := pair[0], pair[1]
		if len(canonical) == 0 {
			t.Fatalf("%s: plugincompat returned an empty map — the source of truth is broken, and comparing two empty maps would pass", name)
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

// TestPluginCompatMapsAreNotAliased guards the copy-on-read contract. Handing
// out the package-level map would let any consumer mutate the source of truth
// for the whole process.
func TestPluginCompatMapsAreNotAliased(t *testing.T) {
	first := getPluginCompatibility()
	first.RecommendedPluginVersion["openclaw"] = "0.0.0-mutated"
	first.MinPluginVersion["openclaw"] = "0.0.0-mutated"

	second := getPluginCompatibility()
	if second.RecommendedPluginVersion["openclaw"] == "0.0.0-mutated" {
		t.Error("RecommendedPluginVersion is aliased: mutating one caller's map changed the next caller's")
	}
	if second.MinPluginVersion["openclaw"] == "0.0.0-mutated" {
		t.Error("MinPluginVersion is aliased: mutating one caller's map changed the next caller's")
	}
}
