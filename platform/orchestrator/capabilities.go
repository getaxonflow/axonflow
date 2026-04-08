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
	}
}

func getSDKCompatibility() SDKCompatInfo {
	return SDKCompatInfo{
		MinSDKVersion: map[string]string{
			"python":     "3.0.0",
			"typescript": "3.0.0",
			"go":         "3.0.0",
			"java":       "3.0.0",
		},
		RecommendedSDKVersion: map[string]string{
			"python":     "6.1.0",
			"typescript": "5.1.0",
			"go":         "5.1.0",
			"java":       "5.1.0",
		},
	}
}
