// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

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
//   - openclaw     — npm @axonflow/openclaw (TypeScript plugin)
//   - claude-code  — Claude Code CLI plugin (axonflow-claude-plugin)
//   - cursor       — Cursor CLI plugin (axonflow-cursor-plugin)
//   - codex        — OpenAI Codex CLI plugin (axonflow-codex-plugin)
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
		{Name: "plugin_compatibility", Since: "7.5.0", Description: "Health response advertises min_plugin_version + recommended_plugin_version per plugin id (mirrors sdk_compatibility)"},
	}
}

func getSDKCompatibility() SDKCompatInfo {
	return SDKCompatInfo{
		// Floor of the current major line. SDKs below 7.0.0 ran the
		// pre-DNT-removal opt-out contract; bumping the floor signals
		// to those callers that they should upgrade to keep their
		// telemetry opt-out (and assorted v6.x→v7.x cleanups) honored.
		MinSDKVersion: map[string]string{
			"python":     "7.0.0",
			"typescript": "7.0.0",
			"go":         "7.0.0",
			"java":       "7.0.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each SDK's release-train tag.
		RecommendedSDKVersion: map[string]string{
			"python":     "7.0.0",
			"typescript": "7.0.0",
			"go":         "7.0.0",
			"java":       "7.0.0",
		},
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
	return PluginCompatInfo{
		// Floor of each plugin's current major line. OpenClaw graduated
		// from the v1.x line to v2.0.0 alongside the SDK v7.0.0 cycle;
		// the three CLI plugins (Claude / Cursor / Codex) graduated
		// from 0.x to 1.0.0 in the same release train. Plugins below
		// these floors ran the pre-DNT-removal contract.
		MinPluginVersion: map[string]string{
			"openclaw":    "2.0.0",
			"claude-code": "1.0.0",
			"cursor":      "1.0.0",
			"codex":       "1.0.0",
		},
		// Latest tag this platform was tested against. Kept in lockstep
		// with each plugin's release-train tag.
		RecommendedPluginVersion: map[string]string{
			"openclaw":    "2.0.0",
			"claude-code": "1.0.0",
			"cursor":      "1.0.0",
			"codex":       "1.0.0",
		},
	}
}
