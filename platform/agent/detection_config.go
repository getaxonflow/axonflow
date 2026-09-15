// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// Cached detection configs — loaded once at startup via InitDetectionConfigs().
var (
	cachedMCPConfig     *ModeDetectionConfig
	cachedGatewayConfig *ModeDetectionConfig
	detectionConfigMu   sync.RWMutex
)

// DetectionAction represents the action to take when a detection is triggered.
type DetectionAction string

const (
	// DetectionActionBlock blocks the request immediately.
	DetectionActionBlock DetectionAction = "block"
	// DetectionActionWarn allows the request but logs a warning.
	DetectionActionWarn DetectionAction = "warn"
	// DetectionActionRedact masks/redacts the detected content.
	DetectionActionRedact DetectionAction = "redact"
	// DetectionActionLog allows the request and logs for audit only.
	DetectionActionLog DetectionAction = "log"
)

// ShouldBlock returns true if the action is block.
func (a DetectionAction) ShouldBlock() bool {
	return a == DetectionActionBlock
}

// ShouldRedact returns true if the action is redact.
func (a DetectionAction) ShouldRedact() bool {
	return a == DetectionActionRedact
}

// ShouldWarn returns true if the action is warn.
func (a DetectionAction) ShouldWarn() bool {
	return a == DetectionActionWarn
}

// ShouldLog returns true if the action is log (or any action, since all actions log).
func (a DetectionAction) ShouldLog() bool {
	return true // All actions result in logging
}

// ToOverrideAction converts DetectionAction to OverrideAction for policy compatibility.
func (a DetectionAction) ToOverrideAction() OverrideAction {
	switch a {
	case DetectionActionBlock:
		return ActionBlock
	case DetectionActionRedact:
		return ActionRedact
	case DetectionActionWarn:
		return ActionWarn
	case DetectionActionLog:
		return ActionLog
	default:
		return ActionBlock
	}
}

// ToPolicyAction converts DetectionAction to the shared policy.Action type.
func (a DetectionAction) ToPolicyAction() sharedpolicy.Action {
	switch a {
	case DetectionActionBlock:
		return sharedpolicy.ActionBlock
	case DetectionActionRedact:
		return sharedpolicy.ActionRedact
	case DetectionActionWarn:
		return sharedpolicy.ActionWarn
	case DetectionActionLog:
		return sharedpolicy.ActionLog
	default:
		return sharedpolicy.ActionBlock
	}
}

// =============================================================================
// The removed detection-posture environment variables (#3961)
// =============================================================================

// RemovedPostureEnvVars are the environment variables that set detection
// ACTIONS before v11. None of them sets anything any more (#3961; ADR-065
// amendment 2026-09-10).
//
// A control's action is part of the policy: authored, versioned, attributable.
// An environment variable is a deployment-time string with no author, no
// timestamp and no record, and before v11 these could move a shipped control to
// a weaker action with nothing in the audit trail to show it - the default
// profile alone turned a stored `block` into `warn`. Two ways to set one value is
// the defect, so the unrecorded half is deleted: the stored policy action
// decides, and the only thing that may replace it is the organization's RECORDED
// override (detection_action_overrides, written through the detection-posture
// API, audited to admin_audit_log - see detection_override.go).
//
// The list is the four category variables, their per-mode (MCP_ / GATEWAY_)
// copies, their deprecated aliases, the two that were already read by no
// enforcement path, and the two coarse levers that fanned a whole matrix of
// actions (AXONFLOW_PROFILE, AXONFLOW_ENFORCE). The profile and the enforce list
// had no effect other than setting actions and printing a banner, so nothing of
// them survives.
//
// A deployment that still sets one keeps running with the stored actions: the
// operator ruling was to apply the behaviour change and say so loudly, not to
// refuse to boot. ReportIgnoredPostureEnv is the saying so.
var RemovedPostureEnvVars = []string{
	"PII_ACTION",
	"SQLI_ACTION",
	"DANGEROUS_COMMAND_ACTION",
	"SENSITIVE_DATA_ACTION",
	"MCP_PII_ACTION",
	"MCP_SQLI_ACTION",
	"MCP_DANGEROUS_QUERY_ACTION",
	"MCP_DANGEROUS_COMMAND_ACTION",
	"GATEWAY_PII_ACTION",
	"GATEWAY_SQLI_ACTION",
	"GATEWAY_DANGEROUS_QUERY_ACTION",
	"GATEWAY_DANGEROUS_COMMAND_ACTION",
	"SQLI_BLOCK_MODE",
	"PII_BLOCK_CRITICAL",
	"DANGEROUS_QUERY_ACTION",
	"HIGH_RISK_ACTION",
	"AXONFLOW_PROFILE",
	"AXONFLOW_ENFORCE",
}

// ignoredPostureEnvTotal counts, per variable, the process starts at which a
// removed detection-posture variable was still set. It is the fleet-visible half
// of the boot WARN: a log line is read by whoever is looking at one process, a
// counter on /prometheus by whoever is looking at all of them.
var ignoredPostureEnvTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_ignored_posture_env_total",
		Help: "Process starts at which a removed detection-posture environment variable was set; it no longer sets an action (v11, #3961)",
	},
	[]string{"name"},
)

func init() {
	prometheus.MustRegister(ignoredPostureEnvTotal)
}

// ReportIgnoredPostureEnv logs one WARN line per removed detection-posture
// variable that is set to a non-empty value, increments
// axonflow_ignored_posture_env_total for it, and returns the names found, in
// RemovedPostureEnvVars order. Call once at process start. It changes nothing
// else: boot continues and the stored actions decide.
//
// An empty value is not reported. Before v11 an empty variable set nothing
// either, and a compose file that passes `PII_ACTION: ${PII_ACTION:-}` through
// has not chosen an action.
func ReportIgnoredPostureEnv(component string) []string {
	var found []string
	for _, name := range RemovedPostureEnvVars {
		value := os.Getenv(name)
		if value == "" {
			continue
		}
		found = append(found, name)
		ignoredPostureEnvTotal.WithLabelValues(name).Inc()
		log.Printf("WARN [%s] detection posture env var ignored: %s=%s no longer sets an action (v11); the stored policy action decides - see release notes. "+
			"To choose a different action for an organization, set its detection-posture override (audited), or change the action on the policy.",
			component, name, value)
	}
	return found
}

// =============================================================================
// Mode-Specific Detection Configuration
// =============================================================================

// Environment variable names for mode-specific detection configuration. None of
// them sets an ACTION: they enable or disable evaluation, skip categories, and
// scope evaluation to connectors.
const (
	// MCP mode master switch
	EnvMCPStaticPoliciesEnabled = "MCP_STATIC_POLICIES_ENABLED"

	// Gateway mode master switch
	EnvGatewayStaticPoliciesEnabled = "GATEWAY_STATIC_POLICIES_ENABLED"

	// Category skip lists
	EnvMCPStaticPoliciesSkipCategories     = "MCP_STATIC_POLICIES_SKIP_CATEGORIES"
	EnvGatewayStaticPoliciesSkipCategories = "GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES"

	// Enterprise: per-connector scoping
	EnvMCPStaticPoliciesConnectors = "MCP_STATIC_POLICIES_CONNECTORS"
)

// ModeDetectionConfig holds mode-specific detection configuration: whether
// static policy evaluation runs for this mode, category filtering, per-connector
// scoping (Enterprise only) and - once resolved for an organization - that
// organization's recorded detection-action overrides.
type ModeDetectionConfig struct {
	// Enabled controls whether static policy evaluation runs for this mode.
	// Default: true
	Enabled bool

	// The action fields carry ONLY the organization's recorded override for the
	// category (detection_action_overrides, applied by
	// applyOrgDetectionOverrides). Empty means there is no override and the
	// stored policy action decides - which is every category of every
	// organization that has not set one, and every call that resolved no
	// organization. Nothing else writes them (#3961).

	// PIIAction is the organization's override for the pii-* categories.
	PIIAction DetectionAction

	// SQLIAction is the organization's override for security-sqli.
	SQLIAction DetectionAction

	// DangerousQueryAction is the organization's `dangerous_query` override. It
	// is mapped onto no category: "dangerous_queries" is a legacy string
	// category carried only by tenant starter policies (#2706).
	DangerousQueryAction DetectionAction

	// DangerousCommandAction is the organization's override for
	// security-dangerous.
	DangerousCommandAction DetectionAction

	// SkipCategories lists policy categories to skip in this mode.
	// Parsed from comma-separated env var.
	SkipCategories []sharedpolicy.PolicyCategory

	// Connectors limits static policy eval to these connectors (Enterprise only).
	// Empty means all connectors.
	Connectors []string
}

// MCPDetectionConfigFromEnv creates the MCP-mode detection config from the
// environment: the enable switch, the category skip list and connector scoping.
// It sets no action (#3961).
func MCPDetectionConfigFromEnv() ModeDetectionConfig {
	cfg := ModeDetectionConfig{
		Enabled:        parseBoolEnv(EnvMCPStaticPoliciesEnabled, true),
		SkipCategories: parseCategoryList(os.Getenv(EnvMCPStaticPoliciesSkipCategories)),
	}

	// Per-connector scoping (Enterprise only)
	if connectors := os.Getenv(EnvMCPStaticPoliciesConnectors); connectors != "" {
		if license.IsEnterpriseTier(context.Background()) {
			cfg.Connectors = parseCSV(connectors)
		} else {
			log.Printf("[Detection] WARNING: %s requires Enterprise license, ignoring", EnvMCPStaticPoliciesConnectors)
		}
	}

	if !cfg.Enabled {
		log.Printf("[Detection] MCP static policies DISABLED")
	} else {
		log.Printf("[Detection] MCP static policies enabled: SkipCategories=%v, Connectors=%v", cfg.SkipCategories, cfg.Connectors)
	}

	return cfg
}

// GatewayDetectionConfigFromEnv creates the gateway-mode detection config from
// the environment: the enable switch and the category skip list. It sets no
// action (#3961).
func GatewayDetectionConfigFromEnv() ModeDetectionConfig {
	cfg := ModeDetectionConfig{
		Enabled:        parseBoolEnv(EnvGatewayStaticPoliciesEnabled, true),
		SkipCategories: parseCategoryList(os.Getenv(EnvGatewayStaticPoliciesSkipCategories)),
	}

	if !cfg.Enabled {
		log.Printf("[Detection] Gateway static policies DISABLED")
	} else {
		log.Printf("[Detection] Gateway static policies enabled: SkipCategories=%v", cfg.SkipCategories)
	}

	return cfg
}

// BuildActionOverrides converts the organization's recorded overrides into the
// shared engine's EvalOptions.ActionOverrides map. A category appears ONLY when
// the organization set an override for it; every other category keeps its
// stored policy action. For a config with no override the map is empty and
// displaces nothing (#3961). Each override reaches the policy categories
// sharedpolicy.OrgOverrideReach names - the one fan-out, which the anchored
// engine folds through as well (detectionposture.AnchoredCategoryActions) and
// TestOrgOverrideCategoryMatchesBuildActionOverrides holds in both directions.
//
// sensitive-data has no override category (the detection_action_overrides CHECK
// constraint does not list one), so its stored action always decides.
// media-pii is not reached: it is the orchestrator's OCR subsystem, with no text
// engine match to apply an override to.
func (c *ModeDetectionConfig) BuildActionOverrides() map[sharedpolicy.PolicyCategory]sharedpolicy.Action {
	overrides := make(map[sharedpolicy.PolicyCategory]sharedpolicy.Action)
	for category, action := range map[string]DetectionAction{
		DetectionCategoryPII:              c.PIIAction,
		DetectionCategorySQLI:             c.SQLIAction,
		DetectionCategoryDangerousCommand: c.DangerousCommandAction,
	} {
		if action == "" {
			continue
		}
		for _, cat := range sharedpolicy.OrgOverrideReach(category) {
			overrides[cat] = action.ToPolicyAction()
		}
	}
	return overrides
}

// IsConnectorEnabled returns true if the given connector should have static policies evaluated.
// If no connectors are configured, all connectors are enabled.
func (c *ModeDetectionConfig) IsConnectorEnabled(connector string) bool {
	if len(c.Connectors) == 0 {
		return true
	}
	for _, conn := range c.Connectors {
		if conn == connector {
			return true
		}
	}
	return false
}

// InitDetectionConfigs reads the MCP and Gateway detection configs from the
// environment and caches them for the lifetime of the process. Call once at
// startup, after the environment is fully loaded. Subsequent calls to
// GetMCPDetectionConfig() and GetGatewayDetectionConfig() return the cached
// values without re-parsing.
func InitDetectionConfigs() {
	detectionConfigMu.Lock()
	defer detectionConfigMu.Unlock()

	mcp := MCPDetectionConfigFromEnv()
	gw := GatewayDetectionConfigFromEnv()
	cachedMCPConfig = &mcp
	cachedGatewayConfig = &gw
}

// GetMCPDetectionConfig returns the cached MCP detection config.
// Falls back to parsing from env if InitDetectionConfigs() hasn't been called
// (e.g., in tests that don't go through full startup).
func GetMCPDetectionConfig() ModeDetectionConfig {
	detectionConfigMu.RLock()
	defer detectionConfigMu.RUnlock()
	if cachedMCPConfig != nil {
		return *cachedMCPConfig
	}
	return MCPDetectionConfigFromEnv()
}

// GetGatewayDetectionConfig returns the cached Gateway detection config.
// Falls back to parsing from env if InitDetectionConfigs() hasn't been called.
func GetGatewayDetectionConfig() ModeDetectionConfig {
	detectionConfigMu.RLock()
	defer detectionConfigMu.RUnlock()
	if cachedGatewayConfig != nil {
		return *cachedGatewayConfig
	}
	return GatewayDetectionConfigFromEnv()
}

// ResetDetectionConfigCache clears the cached configs. Used in tests to allow
// re-initialization with different env vars via t.Setenv + InitDetectionConfigs().
func ResetDetectionConfigCache() {
	detectionConfigMu.Lock()
	defer detectionConfigMu.Unlock()
	cachedMCPConfig = nil
	cachedGatewayConfig = nil
}

// parseBoolEnv parses a boolean environment variable with a default value.
func parseBoolEnv(envName string, defaultVal bool) bool {
	val := os.Getenv(envName)
	if val == "" {
		return defaultVal
	}
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		log.Printf("[Detection] WARNING: Invalid %s=%q, using default %v", envName, val, defaultVal)
		return defaultVal
	}
}

// parseCategoryList parses a comma-separated list of policy category strings.
func parseCategoryList(val string) []sharedpolicy.PolicyCategory {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	categories := make([]sharedpolicy.PolicyCategory, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			categories = append(categories, sharedpolicy.PolicyCategory(trimmed))
		}
	}
	return categories
}

// parseCSV parses a comma-separated string into a string slice.
func parseCSV(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
