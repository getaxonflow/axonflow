// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"regexp"
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
//   - openclaw     — npm @axonflow/openclaw
//   - claude-code  — Claude Code IDE plugin
//   - cursor       — Cursor IDE plugin
//   - codex        — Codex CLI plugin
type PluginCompatInfo struct {
	MinPluginVersion         map[string]string `json:"min_plugin_version"`
	RecommendedPluginVersion map[string]string `json:"recommended_plugin_version"`
}

var orchVersionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`)

// getPlatformVersion returns the platform version from the AXONFLOW_VERSION env var.
func getPlatformVersion() string {
	version := os.Getenv("AXONFLOW_VERSION")
	if version == "" || !orchVersionRegex.MatchString(version) {
		version = "1.0.0"
	}
	return version
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
		MinSDKVersion: map[string]string{
			"python":     "8.0.0",
			"typescript": "8.0.0",
			"go":         "8.0.0",
			"java":       "8.0.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each SDK's release-train tag.
		RecommendedSDKVersion: map[string]string{
			"python":     "8.5.0",
			"typescript": "8.5.0",
			"go":         "8.5.0",
			"java":       "8.5.0",
		},
	}
}

// getPluginCompatibility reports the min and recommended plugin versions for
// every plugin the platform speaks to. Mirrors platform/agent/capabilities.go
// so /health on both ports surfaces the same downgrade-warning gate.
func getPluginCompatibility() PluginCompatInfo {
	return PluginCompatInfo{
		// Floor of each plugin's current released contract. Bumped from
		// {2.0.0, 1.0.0×3} to {2.4.0, 1.4.0×3} during the v7.9.0
		// release-train prep (#2102): openclaw 2.0–2.3.x carried bugs
		// we no longer support; claude-code/cursor/codex 1.0–1.3.x
		// predate the v8 list_decisions integration. Anything below
		// this floor speaks an out-of-contract version and receives
		// the actionable downgrade-warning header on every governed
		// call. The plugin tags shipped within ~15-30 minutes of the
		// v7.9.0 community sync per the release-train order locked at
		// #2047. Mirrors platform/agent/capabilities.go.
		MinPluginVersion: map[string]string{
			"openclaw":    "2.4.0",
			"claude-code": "1.4.0",
			"cursor":      "1.4.0",
			"codex":       "1.4.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each plugin's release-train tag. Bumped to claude/cursor/codex
		// 1.4.0 + openclaw 2.4.0 during the v7.9.0 release-train (#2102
		// on 2026-05-09) — the new minor carries the SDK v8 list_decisions
		// integration so the "show me the last decisions for this user"
		// affordance lands natively in each host. The v8.0.0 platform bump
		// (#2308) did NOT change the plugin recommended-version. Bumped
		// claude-code + cursor to 1.5.3 during the v8.5.2 release-train
		// (headersHelper ${CLAUDE_PLUGIN_ROOT} Basic-auth fix); codex stays
		// 1.5.2 (v8.5.2 fix was docs-only, no codex 1.5.3); openclaw bumped
		// 2.6.1 -> 2.6.5 to track its latest published release (prior value
		// lagged the registry; openclaw 2.6.5 is live on npm).
		// MinPluginVersion floor stays 1.4.0 / 2.4.0. Mirrors
		// platform/agent/capabilities.go.
		RecommendedPluginVersion: map[string]string{
			"openclaw":    "2.6.5",
			"claude-code": "1.5.3",
			"cursor":      "1.5.3",
			"codex":       "1.5.2",
		},
	}
}
