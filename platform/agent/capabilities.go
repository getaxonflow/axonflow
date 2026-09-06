// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"axonflow/platform/shared/capability"
	"axonflow/platform/shared/plugincompat"
	"axonflow/platform/shared/sdkcompat"
)

// PlatformCapability describes a feature supported by the platform.
type PlatformCapability struct {
	Name        string `json:"name"`
	Since       string `json:"since"`
	Description string `json:"description"`
}

// SDKCompatInfo describes SDK version compatibility for this platform version.
type SDKCompatInfo struct {
	MinSDKVersion         map[string]string `json:"min_sdk_version"`
	RecommendedSDKVersion map[string]string `json:"recommended_sdk_version"`
}

// PluginCompatInfo describes plugin version compatibility for this platform
// version. Mirrors SDKCompatInfo so plugins can run the same min/recommended
// gate against /health that SDKs do — see Python SDK's
// `health_check_detailed()` and Go SDK's `SDKCompatibility.MinSDKVersionFor()`
// for the reference consumer pattern.
//
// Keys are the canonical plugin IDs the agent tracks in
// `integration_activation.go::knownIntegrations`. Keep this list in lockstep
// with that registry — a regression test (TestPluginCompatibilityKeysMatchKnownIntegrations)
// fails if the two drift apart.
//
//   - openclaw       — npm @axonflow/openclaw (TypeScript plugin)
//   - claude-code    — Claude Code CLI plugin (axonflow-claude-plugin)
//   - cursor         — Cursor CLI plugin (axonflow-cursor-plugin)
//   - codex          — OpenAI Codex CLI plugin (axonflow-codex-plugin)
//   - claude-desktop — Claude Desktop MCP governance proxy
//     (axonflow-claude-desktop-plugin; identifies on the wire as
//     "mcp-proxy/<v>" via X-Axonflow-Client)
//
// `MinPluginVersion[id]` is the lowest version that speaks the current
// platform's wire / hook contract. A plugin running below the floor logs
// an actionable upgrade warning. `RecommendedPluginVersion[id]` is the
// version this platform was tested against; below recommended-but-above-min
// is informational only.
type PluginCompatInfo struct {
	MinPluginVersion         map[string]string `json:"min_plugin_version"`
	RecommendedPluginVersion map[string]string `json:"recommended_plugin_version"`
}

// getCapabilities is the feature list served on /health. It is not
// documentation: SDKs, plugins and customers branch on it to discover what this
// platform supports, so an omission reads to a client as "not supported".
//
// IT IS NO LONGER A HAND-MAINTAINED LITERAL. Until #3618 it was one, and a
// hand-maintained list is a census bounded by whoever last remembered to edit
// it: four release trains — v10.0 through v10.3 — shipped without a single
// entry, including a route all five SDKs call. The list is now PROJECTED from
// platform/shared/capability, the one canonical capability registry (ADR-066
// decision 1), so this file cannot drift from the registry at all: there is
// nothing here to forget to edit.
//
// What still needs a judgement, and where it is now made: whether a new
// capability gets a /health entry at all. The test is unchanged — does this add
// or change a surface a CLIENT can observe, meaning a route, a header contract,
// an obligation type or a discovery field? Machinery with no client-visible
// surface (a store with no writer, a recorded-only comparison, an exported
// metric series, an internal control-plane route on another binary) does NOT
// get an entry. That judgement is now RECORDED rather than remembered: a
// registry entry either carries a health block or carries a
// health_absent_reason, and one of the two is mandatory. And the reminder to
// make the judgement arrives on its own, because the registry's route
// derivation fails CI when a registered route has no entry.
//
// RUNBOOK_RELEASE_PREP.md Step 0b (in axonflow-internal-docs) is the
// release-train control that walks the manifest and applies that test. It still
// describes editing a literal here, and says "nothing enforces this yet" —
// both of which this change makes untrue. Updating it is a companion PR in that
// repository; this comment says what is true of THIS file rather than what a
// document in another repository will say once it is merged.
func getCapabilities() []PlatformCapability {
	adv := capability.Advertise(capability.PlaneAgent)
	out := make([]PlatformCapability, 0, len(adv))
	for _, a := range adv {
		out = append(out, PlatformCapability{Name: a.Name, Since: a.Since, Description: a.Description})
	}
	return out
}

// -- the pre-#3618 literal, deleted -------------------------------------------
//
// The 29 entries that used to be here were captured by RUNNING this function
// before the change and are checked in at
// platform/shared/capability/testdata/health_wire_freeze_agent.json, where
// TestProjectionReproducesTheFrozenWire compares the projection against them
// byte for byte. They are not kept here as a second copy: the whole point of
// #3618 is that the /health list and the registry stop being two
// hand-maintained vocabularies, and a frozen Go literal beside the projection
// is exactly the second vocabulary, one edit away from being "kept current".

func getSDKCompatibility() SDKCompatInfo {
	// Both values come from platform/shared/sdkcompat, the single source of
	// truth for the two planes. These literals used to live here AND in the
	// sibling plane, and /health serves both -- the same duplication the plugin
	// maps below carried, and were consolidated to end (#3229). The SDK maps
	// were left behind by that fix; #3712 is the omission. The guard that stood
	// over them meanwhile was a source-parsing parity test comparing the two
	// copies, which is the instrument plugincompat's own package doc records as
	// insufficient: two files that agree at a stale value agree.
	//
	// The release-train narrative that used to sit inline moved to the sdkcompat
	// package doc, next to the values it explains.
	return SDKCompatInfo{
		MinSDKVersion:         sdkcompat.MinVersions(),
		RecommendedSDKVersion: sdkcompat.RecommendedVersions(),
	}
}

// getPluginCompatibility reports the min and recommended plugin versions for
// every plugin the platform speaks to. The values track the floor of each
// plugin's current major line and its latest released tag — kept in lockstep
// with each plugin's release-notes header. A future PR that ships the next
// plugin major (claude/cursor/codex graduating to 1.0; openclaw to 2.0)
// updates these values as part of the same release-train commit so the
// downgrade-warning gate flips on the moment the new majors are tagged.
func getPluginCompatibility() PluginCompatInfo {
	// Both values come from platform/shared/plugincompat, the single source of
	// truth for the two planes. These literals used to live here AND in the
	// sibling plane, and /health serves both — a duplication that produced
	// one-sided drift (claude-code 1.8.0 vs 1.9.0) and, on the v9.10.0 train,
	// released plugin versions advertised in neither file (#2962). A test that
	// compared the two copies was tried and is not sufficient: two files that
	// agree at a stale value agree, so it cannot see that second shape at all.
	//
	// The release-train narrative that used to sit inline moved to the
	// plugincompat package doc, next to the values it explains.
	return PluginCompatInfo{
		MinPluginVersion:         plugincompat.MinVersions(),
		RecommendedPluginVersion: plugincompat.RecommendedVersions(),
	}
}
