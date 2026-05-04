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
		// Floor of the current major line. SDKs below 7.0.0 ran the
		// pre-DNT-removal opt-out contract; bumping the floor signals
		// to those callers that they should upgrade to keep their
		// telemetry opt-out (and assorted v6.x→v7.x cleanups) honored.
		// Kept in lockstep with platform/agent/capabilities.go so /health
		// on agent (8080) and orchestrator (8081) report identical pins.
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
// every plugin the platform speaks to. Mirrors platform/agent/capabilities.go
// so /health on both ports surfaces the same downgrade-warning gate.
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
		// with each plugin's release-train tag. Bumped alongside the W2
		// read-side governance plugin shipment (claude/cursor/codex 1.1.0,
		// openclaw 2.1.0) which exposes audit-search / explain-decision /
		// list-overrides / create-override / revoke-override as
		// agent-callable surfaces against this platform.
		RecommendedPluginVersion: map[string]string{
			"openclaw":    "2.1.0",
			"claude-code": "1.1.0",
			"cursor":      "1.1.0",
			"codex":       "1.1.0",
		},
	}
}
