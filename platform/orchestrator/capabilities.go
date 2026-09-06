// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"regexp"

	"axonflow/platform/shared/capability"
	"axonflow/platform/shared/plugincompat"
	"axonflow/platform/shared/sdkcompat"
	"axonflow/platform/shared/version"
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
// version. Mirrors SDKCompatInfo + the agent-side getPluginCompatibility()
// so /health on both ports (agent 8080 and orchestrator 8081) returns the
// same downgrade-warning gate to plugin clients.
//
// Keys are the canonical plugin IDs:
//   - openclaw       — npm @axonflow/openclaw
//   - claude-code    — Claude Code IDE plugin
//   - cursor         — Cursor IDE plugin
//   - codex          — Codex CLI plugin
//   - claude-desktop — Claude Desktop MCP governance proxy
//     (identifies on the wire as "mcp-proxy/<v>" via X-Axonflow-Client)
type PluginCompatInfo struct {
	MinPluginVersion         map[string]string `json:"min_plugin_version"`
	RecommendedPluginVersion map[string]string `json:"recommended_plugin_version"`
}

var orchVersionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`)

// getPlatformVersion returns the platform version, preferring the value baked
// into the binary at build time (#2662) and falling back to the AXONFLOW_VERSION
// env var only for unbaked dev builds. A baked value always wins over the env so
// /health cannot be spoofed by a runtime override.
func getPlatformVersion() string {
	v := version.Resolve()
	if v == "" || !orchVersionRegex.MatchString(v) {
		v = "1.0.0"
	}
	return v
}

// getCapabilities is the orchestrator plane's feature list, served on /health at
// port 8081. Like the agent's, it is PROJECTED from platform/shared/capability
// rather than hand-maintained (#3618); see the long note on
// platform/agent/capabilities.go for why the literal that used to be here is
// gone.
//
// This plane's list is a deliberate SUBSET of the agent's, and the projection
// preserves that: a registry entry names the planes that advertise it, so a
// capability whose surface exists only on the agent simply does not list
// "orchestrator". The rule is unchanged — a client discovers a capability in
// order to CALL it, and advertising a route the orchestrator does not register
// sends that client to a port that answers 404. That is why
// decision_obligations, two_touch_redaction, seam_capability_decisioning,
// client_version_telemetry, identity_header_attribution, authzen_evaluation and
// the Community-SaaS entries are agent-only.
//
// What the projection additionally buys: agent-vs-orchestrator drift is failure
// mode 1 in RUNBOOK_RELEASE_PREP.md and has happened in a real train. Two
// literals could disagree about a shared entry's Since or description and each
// would look right on its own; a registry entry has ONE Since, and a
// per-plane description takes a `description_overrides` key that the validator
// checks. So the two planes can still differ — they do, for
// platform_identity_discovery, whose orchestrator copy carries an extra
// paragraph — but only deliberately and visibly, in one place.
func getCapabilities() []PlatformCapability {
	adv := capability.Advertise(capability.PlaneOrchestrator)
	out := make([]PlatformCapability, 0, len(adv))
	for _, a := range adv {
		out = append(out, PlatformCapability{Name: a.Name, Since: a.Since, Description: a.Description})
	}
	return out
}

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
// every plugin the platform speaks to. Mirrors platform/agent/capabilities.go
// so /health on both ports surfaces the same downgrade-warning gate.
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
