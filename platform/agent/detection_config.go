// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// Cached detection configs — loaded once at startup via InitDetectionConfigs().
// Follows the same pattern as sharedpolicy.InitGlobalDynamicPolicyEvaluator().
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

// Environment variable names for detection configuration.
// These provide unified control over all detection types.
//
// Note: for strict RBI / regulated-environment posture, use
// AXONFLOW_PROFILE=compliance (see ADR-036). That supersedes the earlier
// proposal for a standalone RBI_COMPLIANCE_MODE flag.
const (
	// EnvSQLIAction controls SQL injection detection behavior.
	// Valid values: "block", "warn", "log"
	// Default (v6.2.0+): "warn". Set AXONFLOW_PROFILE=strict to block.
	EnvSQLIAction = "SQLI_ACTION"

	// EnvPIIAction controls PII detection behavior.
	// Valid values: "block", "warn", "redact", "log"
	// Default (v6.2.0+): "warn" (honest detection signal, no silent data mutation).
	// Set AXONFLOW_PROFILE=strict for the previous "redact" behavior.
	EnvPIIAction = "PII_ACTION"

	// EnvSensitiveDataAction controls sensitive data (credentials, tokens) detection.
	// Valid values: "block", "warn", "log"
	// Default: "warn" (may have false positives)
	EnvSensitiveDataAction = "SENSITIVE_DATA_ACTION"

	// EnvHighRiskAction controls high risk score (>0.8) behavior.
	// Valid values: "block", "warn", "log"
	// Default: "warn" (composite score needs tuning)
	EnvHighRiskAction = "HIGH_RISK_ACTION"

	// EnvDangerousQueryAction controls dangerous SQL query (DROP, TRUNCATE) behavior.
	// Valid values: "block", "warn", "log"
	// Default: "block" (destructive SQL operations)
	EnvDangerousQueryAction = "DANGEROUS_QUERY_ACTION"

	// EnvDangerousCommandAction controls dangerous shell command behavior
	// (reverse shells, rm -rf, credential access, SSRF, path traversal, curl|bash).
	// Valid values: "block", "warn", "log"
	// Default: "block" (dangerous command execution)
	EnvDangerousCommandAction = "DANGEROUS_COMMAND_ACTION"

	// Deprecated environment variables - these will be removed in a future release.
	// Use the new *_ACTION variables instead.

	// EnvSQLIBlockModeDeprecated is deprecated. Use SQLI_ACTION instead.
	EnvSQLIBlockModeDeprecated = "SQLI_BLOCK_MODE"

	// EnvPIIBlockCriticalDeprecated is deprecated. Use PII_ACTION instead.
	EnvPIIBlockCriticalDeprecated = "PII_BLOCK_CRITICAL"
)

// DetectionConfig holds the unified detection configuration for all detection types.
// This replaces the fragmented configuration across multiple env vars.
type DetectionConfig struct {
	// SQLIAction determines behavior when SQL injection is detected.
	// Default: block
	SQLIAction DetectionAction

	// PIIAction determines behavior when PII is detected.
	// Default: redact
	PIIAction DetectionAction

	// SensitiveDataAction determines behavior when sensitive data (credentials) is detected.
	// Default: warn
	SensitiveDataAction DetectionAction

	// HighRiskAction determines behavior when risk score exceeds threshold.
	// Default: warn
	HighRiskAction DetectionAction

	// DangerousQueryAction determines behavior when dangerous SQL queries are detected
	// (DROP TABLE, TRUNCATE, etc.).
	// Default: block
	DangerousQueryAction DetectionAction

	// DangerousCommandAction determines behavior when dangerous shell commands are
	// detected (reverse shells, rm -rf, credential access, SSRF, path traversal,
	// curl|bash, etc.). Separate from DangerousQueryAction because SQL dangers
	// and shell dangers have different risk profiles and different teams own them.
	// Default: block
	DangerousCommandAction DetectionAction
}

// DefaultDetectionConfig returns the default detection configuration.
// Philosophy (v6.2.0+): block only unambiguously dangerous patterns by default;
// warn on PII / SQLi / sensitive data so evaluators see honest detection signal
// without silent data mutation. Equivalent to AXONFLOW_PROFILE=default.
//
// To restore the v6.1.0 behavior (PII=redact, SQLi=block), set
// AXONFLOW_PROFILE=strict or PII_ACTION=redact + SQLI_ACTION=block.
func DefaultDetectionConfig() DetectionConfig {
	return ProfileDefaults(ProfileDefault)
}

// DetectionConfigFromEnv creates a detection configuration from environment
// variables, layered on top of the active profile and per-category enforce set.
//
// Precedence (highest → lowest):
//  1. Explicit category env vars (PII_ACTION, SQLI_ACTION, ...)
//  2. AXONFLOW_ENFORCE per-category opt-in
//  3. AXONFLOW_PROFILE built-in posture
//  4. Built-in defaults (DefaultDetectionConfig)
//
// See ADR-036 for the rationale.
func DetectionConfigFromEnv() DetectionConfig {
	profile := ResolveProfile()
	base := ProfileDefaults(profile)
	enforce, err := LoadEnforceFromEnv()
	if err != nil {
		// Log and keep going with just the profile base. The previous
		// behaviour (log.Fatalf) made a typo in AXONFLOW_ENFORCE crash
		// every test run that happened to have the env var set. Fail
		// loudly in logs so operators notice, but do not abort the
		// process — the profile base is still a valid, safe config.
		log.Printf("[Profile] ERROR: invalid AXONFLOW_ENFORCE — ignoring: %v", err)
	} else {
		base = ApplyEnforce(base, enforce)
	}
	return DetectionConfigFromEnvWithBase(base)
}

// DetectionConfigFromEnvWithBase parses explicit category env vars on top of
// a caller-provided base config. The base is typically the result of
// ProfileDefaults+ApplyEnforce, but tests may provide arbitrary bases.
//
// This is the lowest-level entry point and the only one that touches the
// individual *_ACTION env vars. It deliberately does NOT read AXONFLOW_PROFILE
// or AXONFLOW_ENFORCE — those are the caller's responsibility.
func DetectionConfigFromEnvWithBase(base DetectionConfig) DetectionConfig {
	cfg := base

	// Parse SQLI_ACTION (new) or SQLI_BLOCK_MODE (deprecated).
	// On invalid values, fall back to the BASE config's SQLIAction (which is
	// already the correctly-resolved profile value), NOT the hardcoded legacy
	// default. This preserves the active profile's posture under typo input.
	// See v6.2.0 review finding P2 — the previous hardcoded fallback to
	// DetectionActionBlock silently tightened behavior back to the v6.1.0 default.
	if action := os.Getenv(EnvSQLIAction); action != "" {
		cfg.SQLIAction = parseDetectionAction(action, "SQLI_ACTION", cfg.SQLIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	} else if deprecated := os.Getenv(EnvSQLIBlockModeDeprecated); deprecated != "" {
		// Deprecated: convert old format to new
		log.Printf("[Detection] WARNING: %s is deprecated. Use %s instead.", EnvSQLIBlockModeDeprecated, EnvSQLIAction)
		switch strings.ToLower(deprecated) {
		case "block":
			cfg.SQLIAction = DetectionActionBlock
		case "warn":
			cfg.SQLIAction = DetectionActionWarn
		default:
			cfg.SQLIAction = DetectionActionBlock
		}
	}

	// Parse PII_ACTION (new) or PII_BLOCK_CRITICAL (deprecated).
	// Same fix as SQLI_ACTION: preserve the base config's PIIAction on invalid
	// input instead of silently flipping back to the v6.1.0 redact default.
	if action := os.Getenv(EnvPIIAction); action != "" {
		cfg.PIIAction = parseDetectionAction(action, "PII_ACTION", cfg.PIIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionRedact, DetectionActionLog})
	} else if deprecated := os.Getenv(EnvPIIBlockCriticalDeprecated); deprecated != "" {
		// Deprecated: convert old format to new
		log.Printf("[Detection] WARNING: %s is deprecated. Use %s instead.", EnvPIIBlockCriticalDeprecated, EnvPIIAction)
		if deprecated == "false" || deprecated == "0" {
			cfg.PIIAction = DetectionActionLog // Disabled = log only
		} else {
			cfg.PIIAction = DetectionActionBlock // Enabled = block
		}
	}

	// Parse SENSITIVE_DATA_ACTION. Fallback preserves base config.
	if action := os.Getenv(EnvSensitiveDataAction); action != "" {
		cfg.SensitiveDataAction = parseDetectionAction(action, "SENSITIVE_DATA_ACTION", cfg.SensitiveDataAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Parse HIGH_RISK_ACTION. Fallback preserves base config.
	if action := os.Getenv(EnvHighRiskAction); action != "" {
		cfg.HighRiskAction = parseDetectionAction(action, "HIGH_RISK_ACTION", cfg.HighRiskAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Parse DANGEROUS_QUERY_ACTION (SQL: DROP, TRUNCATE). Fallback preserves base.
	if action := os.Getenv(EnvDangerousQueryAction); action != "" {
		cfg.DangerousQueryAction = parseDetectionAction(action, "DANGEROUS_QUERY_ACTION", cfg.DangerousQueryAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Parse DANGEROUS_COMMAND_ACTION (shell: rm -rf, reverse shells, curl|bash, SSRF).
	// Fallback preserves base.
	if action := os.Getenv(EnvDangerousCommandAction); action != "" {
		cfg.DangerousCommandAction = parseDetectionAction(action, "DANGEROUS_COMMAND_ACTION", cfg.DangerousCommandAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Log configuration summary
	log.Printf("[Detection] Configuration: SQLI=%s, PII=%s, SensitiveData=%s, HighRisk=%s, DangerousQuery=%s, DangerousCommand=%s",
		cfg.SQLIAction, cfg.PIIAction, cfg.SensitiveDataAction, cfg.HighRiskAction, cfg.DangerousQueryAction, cfg.DangerousCommandAction)

	return cfg
}

// parseDetectionAction parses an action string and returns the corresponding DetectionAction.
// If the value is invalid, it logs a warning and returns the default.
func parseDetectionAction(value, envName string, defaultAction DetectionAction, validActions []DetectionAction) DetectionAction {
	normalized := DetectionAction(strings.ToLower(strings.TrimSpace(value)))
	for _, valid := range validActions {
		if normalized == valid {
			return normalized
		}
	}
	log.Printf("[Detection] WARNING: Invalid %s=%q, using default %q. Valid values: %v",
		envName, value, defaultAction, validActions)
	return defaultAction
}

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
// Mode-Specific Detection Configuration
// =============================================================================

// Environment variable names for mode-specific detection configuration.
const (
	// MCP mode master switch
	EnvMCPStaticPoliciesEnabled = "MCP_STATIC_POLICIES_ENABLED"

	// Gateway mode master switch
	EnvGatewayStaticPoliciesEnabled = "GATEWAY_STATIC_POLICIES_ENABLED"

	// MCP action overrides
	EnvMCPPIIAction              = "MCP_PII_ACTION"
	EnvMCPSQLIAction             = "MCP_SQLI_ACTION"
	EnvMCPDangerousQueryAction   = "MCP_DANGEROUS_QUERY_ACTION"
	EnvMCPDangerousCommandAction = "MCP_DANGEROUS_COMMAND_ACTION"

	// Gateway action overrides
	EnvGatewayPIIAction              = "GATEWAY_PII_ACTION"
	EnvGatewaySQLIAction             = "GATEWAY_SQLI_ACTION"
	EnvGatewayDangerousQueryAction   = "GATEWAY_DANGEROUS_QUERY_ACTION"
	EnvGatewayDangerousCommandAction = "GATEWAY_DANGEROUS_COMMAND_ACTION"

	// Category skip lists
	EnvMCPStaticPoliciesSkipCategories     = "MCP_STATIC_POLICIES_SKIP_CATEGORIES"
	EnvGatewayStaticPoliciesSkipCategories = "GATEWAY_STATIC_POLICIES_SKIP_CATEGORIES"

	// Enterprise: per-connector scoping
	EnvMCPStaticPoliciesConnectors = "MCP_STATIC_POLICIES_CONNECTORS"
)

// ModeDetectionConfig holds mode-specific detection configuration.
// It supports enable/disable per mode, action overrides, category filtering,
// and per-connector scoping (Enterprise only).
type ModeDetectionConfig struct {
	// Enabled controls whether static policy evaluation runs for this mode.
	// Default: true
	Enabled bool

	// PIIAction is the action for PII detection in this mode.
	PIIAction DetectionAction

	// SQLIAction is the action for SQL injection detection in this mode.
	SQLIAction DetectionAction

	// DangerousQueryAction is the action for dangerous SQL query detection in this mode.
	DangerousQueryAction DetectionAction

	// DangerousCommandAction is the action for dangerous shell command detection in this mode.
	DangerousCommandAction DetectionAction

	// SkipCategories lists policy categories to skip in this mode.
	// Parsed from comma-separated env var.
	SkipCategories []sharedpolicy.PolicyCategory

	// Connectors limits static policy eval to these connectors (Enterprise only).
	// Empty means all connectors.
	Connectors []string
}

// MCPDetectionConfigFromEnv creates MCP-specific detection config from environment variables.
//
// Precedence (highest → lowest):
//  1. MCP-specific env vars (MCP_PII_ACTION, MCP_SQLI_ACTION, etc.)
//  2. Global env vars (PII_ACTION, SQLI_ACTION, etc.)
//  3. Engine defaults (redact for PII, block for SQLi, etc.)
func MCPDetectionConfigFromEnv() ModeDetectionConfig {
	globalCfg := DetectionConfigFromEnv()

	cfg := ModeDetectionConfig{
		Enabled:                parseBoolEnv(EnvMCPStaticPoliciesEnabled, true),
		PIIAction:              globalCfg.PIIAction,
		SQLIAction:             globalCfg.SQLIAction,
		DangerousQueryAction:   globalCfg.DangerousQueryAction,
		DangerousCommandAction: globalCfg.DangerousCommandAction,
	}

	// MCP-specific overrides (highest precedence)
	if action := os.Getenv(EnvMCPPIIAction); action != "" {
		cfg.PIIAction = parseDetectionAction(action, EnvMCPPIIAction, cfg.PIIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionRedact, DetectionActionLog})
	}
	if action := os.Getenv(EnvMCPSQLIAction); action != "" {
		cfg.SQLIAction = parseDetectionAction(action, EnvMCPSQLIAction, cfg.SQLIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}
	if action := os.Getenv(EnvMCPDangerousQueryAction); action != "" {
		cfg.DangerousQueryAction = parseDetectionAction(action, EnvMCPDangerousQueryAction, cfg.DangerousQueryAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}
	if action := os.Getenv(EnvMCPDangerousCommandAction); action != "" {
		cfg.DangerousCommandAction = parseDetectionAction(action, EnvMCPDangerousCommandAction, cfg.DangerousCommandAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Category skip list
	cfg.SkipCategories = parseCategoryList(os.Getenv(EnvMCPStaticPoliciesSkipCategories))

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
		log.Printf("[Detection] MCP static policies: PII=%s, SQLI=%s, DangerousQuery=%s, DangerousCommand=%s, SkipCategories=%v",
			cfg.PIIAction, cfg.SQLIAction, cfg.DangerousQueryAction, cfg.DangerousCommandAction, cfg.SkipCategories)
	}

	return cfg
}

// GatewayDetectionConfigFromEnv creates gateway-specific detection config from environment variables.
//
// Precedence (highest → lowest):
//  1. Gateway-specific env vars (GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION, etc.)
//  2. Global env vars (PII_ACTION, SQLI_ACTION, etc.)
//  3. Engine defaults (redact for PII, block for SQLi, etc.)
func GatewayDetectionConfigFromEnv() ModeDetectionConfig {
	globalCfg := DetectionConfigFromEnv()

	cfg := ModeDetectionConfig{
		Enabled:                parseBoolEnv(EnvGatewayStaticPoliciesEnabled, true),
		PIIAction:              globalCfg.PIIAction,
		SQLIAction:             globalCfg.SQLIAction,
		DangerousQueryAction:   globalCfg.DangerousQueryAction,
		DangerousCommandAction: globalCfg.DangerousCommandAction,
	}

	// Gateway-specific overrides (highest precedence)
	if action := os.Getenv(EnvGatewayPIIAction); action != "" {
		cfg.PIIAction = parseDetectionAction(action, EnvGatewayPIIAction, cfg.PIIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionRedact, DetectionActionLog})
	}
	if action := os.Getenv(EnvGatewaySQLIAction); action != "" {
		cfg.SQLIAction = parseDetectionAction(action, EnvGatewaySQLIAction, cfg.SQLIAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}
	if action := os.Getenv(EnvGatewayDangerousQueryAction); action != "" {
		cfg.DangerousQueryAction = parseDetectionAction(action, EnvGatewayDangerousQueryAction, cfg.DangerousQueryAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}
	if action := os.Getenv(EnvGatewayDangerousCommandAction); action != "" {
		cfg.DangerousCommandAction = parseDetectionAction(action, EnvGatewayDangerousCommandAction, cfg.DangerousCommandAction,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Category skip list
	cfg.SkipCategories = parseCategoryList(os.Getenv(EnvGatewayStaticPoliciesSkipCategories))

	if !cfg.Enabled {
		log.Printf("[Detection] Gateway static policies DISABLED")
	} else {
		log.Printf("[Detection] Gateway static policies: PII=%s, SQLI=%s, DangerousQuery=%s, DangerousCommand=%s, SkipCategories=%v",
			cfg.PIIAction, cfg.SQLIAction, cfg.DangerousQueryAction, cfg.DangerousCommandAction, cfg.SkipCategories)
	}

	return cfg
}

// BuildActionOverrides converts ModeDetectionConfig actions into a policy ActionOverrides map.
func (c *ModeDetectionConfig) BuildActionOverrides() map[sharedpolicy.PolicyCategory]sharedpolicy.Action {
	overrides := make(map[sharedpolicy.PolicyCategory]sharedpolicy.Action)

	piiAction := c.PIIAction.ToPolicyAction()
	overrides[sharedpolicy.CategoryPIIGlobal] = piiAction
	overrides[sharedpolicy.CategoryPIIUS] = piiAction
	overrides[sharedpolicy.CategoryPIIIndia] = piiAction
	overrides[sharedpolicy.CategoryPIIEU] = piiAction
	overrides[sharedpolicy.CategoryPIISingapore] = piiAction

	sqliAction := c.SQLIAction.ToPolicyAction()
	overrides[sharedpolicy.CategorySecuritySQLi] = sqliAction

	dangerousQueryAction := c.DangerousQueryAction.ToPolicyAction()
	// dangerous_queries category uses the SQL-specific action
	// (no explicit category constant — these are legacy policies using "dangerous_queries" string)

	dangerousCommandAction := c.DangerousCommandAction.ToPolicyAction()
	overrides[sharedpolicy.CategorySecurityDangerous] = dangerousCommandAction
	_ = dangerousQueryAction // Used by legacy engine for "dangerous_queries" category

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

// InitDetectionConfigs reads MCP and Gateway detection configs from environment
// variables and caches them for the lifetime of the process. Call once at startup,
// after environment is fully loaded. Subsequent calls to GetMCPDetectionConfig()
// and GetGatewayDetectionConfig() return the cached values without re-parsing.
//
// This follows the same startup-cache pattern as sharedpolicy.InitGlobalDynamicPolicyEvaluator().
//
// Also logs a one-line profile banner so operators see what posture the
// process is running in (relevant after the v6.2.0 default-relax change).
func InitDetectionConfigs() {
	detectionConfigMu.Lock()
	defer detectionConfigMu.Unlock()

	// Resolve global profile + log banner once.
	profile := ResolveProfile()
	globalCfg := DetectionConfigFromEnv()
	LogProfileBanner("agent", profile, globalCfg)

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
