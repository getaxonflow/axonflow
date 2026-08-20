// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/shared/plugincompat"
	"regexp"

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

func getCapabilities() []PlatformCapability {
	return []PlatformCapability{
		{Name: "health_check", Since: "1.0.0", Description: "Basic health endpoint"},
		{Name: "proxy_llm_call", Since: "1.0.0", Description: "Proxy mode LLM calls with policy enforcement"},
		{Name: "audit_llm_call", Since: "1.0.0", Description: "Audit logging for LLM calls"},
		{Name: "static_policies", Since: "2.0.0", Description: "System policy CRUD"},
		{Name: "gateway_mode", Since: "3.0.0", Description: "Gateway mode integration"},
		{Name: "dynamic_policies", Since: "3.2.0", Description: "Runtime dynamic policy engine"},
		{Name: "multi_agent_planning", Since: "4.3.0", Description: "MAP plan and execute lifecycle"},
		{Name: "workflow_control", Since: "4.3.0", Description: "WCP workflow lifecycle management"},
		{Name: "execution_replay", Since: "4.3.0", Description: "Execution recording and replay"},
		{Name: "cost_controls", Since: "4.4.0", Description: "Budget and cost management"},
		{Name: "media_governance", Since: "4.4.0", Description: "Multimodal image governance"},
		{Name: "wcp_step_metrics", Since: "4.5.0", Description: "WCP step-complete post-execution metrics"},
		{Name: "mcp_check_endpoints", Since: "4.7.0", Description: "Standalone MCP policy check-input/check-output"},
		{Name: "circuit_breaker", Since: "4.7.0", Description: "Circuit breaker pipeline enforcement"},
		{Name: "version_discovery", Since: "4.8.0", Description: "Version and capability discovery"},
		{Name: "hitl_response_parity", Since: "7.4.0", Description: "WCP + MAP approve/reject responses share retry_context, approver metadata, policies_matched (ADR-046)"},
	}
}

func getSDKCompatibility() SDKCompatInfo {
	return SDKCompatInfo{
		// Floor of the current major line. The SDK major bumped from
		// v7 to v8 during the v7.9.0 release-train (#2016 pre-emptive
		// floor bump 2026-05-08, folded into the v7.9.0 community sync
		// at #2102 on 2026-05-09). The current v8.0.0 platform bump
		// (#2308) did NOT change the SDK floor — it stayed at v8.0.0.
		// Callers below 8.0.0 lack the typed 429 RateLimitError
		// upgrade-envelope handling and the list_decisions method
		// (Session γ / #1982). Kept in lockstep with
		// platform/agent/capabilities.go so /health on agent (8080)
		// and orchestrator (8081) report identical pins.
		// rust joined the compat maps in the 9.7.0 release-train. Its 0.x
		// preview line is versioned independently of the 8.x SDKs; the
		// floor is 0.7.0 — the first rust release that speaks the current
		// Decision Mode PEP contract (decide → fulfill → forward, engine-
		// only fulfill, fail-closed on missing verdict; epic #2563). The
		// 0.5/0.6 previews predate that contract. Mirrors
		// platform/agent/capabilities.go.
		MinSDKVersion: map[string]string{
			"python":     "8.0.0",
			"typescript": "8.0.0",
			"go":         "8.0.0",
			"java":       "8.0.0",
			"rust":       "0.7.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each SDK's release-train tag. java bumped 8.5.0 -> 8.5.1 in
		// the 9.1.1 security patch (2026-06-16): 8.5.1 adds a production
		// guard around the opt-in insecure-TLS dev hatch plus dependency
		// CVE clears. python/typescript/go bumped 8.5.0 -> 8.5.1 in the
		// 9.7.0 release-train (epic #2861 SDK hostile sweep): go 8.5.1
		// fails closed on 4xx auth errors instead of silently allowing,
		// python 8.5.1 bridges sync interceptors onto a persistent event
		// loop + detects AsyncOpenAI clients, typescript 8.5.1 sends auth
		// on getPlanStatus. java stays 8.5.1 (no new java tag this train).
		// rust enters at 0.8.1 (execute_plan status fix + the 9.7.0 train
		// examples baseline). Mirrors platform/agent/capabilities.go.
		RecommendedSDKVersion: map[string]string{
			"python":     "9.1.0",
			"typescript": "9.1.0",
			"go":         "9.1.1",
			"java":       "9.1.0",
			"rust":       "0.8.2",
		},
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
