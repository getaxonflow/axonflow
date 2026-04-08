// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// TestDefaultDetectionConfig tests the default configuration values.
// v6.2.0+: defaults are derived from ProfileDefault — see ADR-036.
func TestDefaultDetectionConfig(t *testing.T) {
	cfg := DefaultDetectionConfig()

	// v6.2.0 philosophy: warn on PII / SQLi / sensitive data; block only
	// unambiguously dangerous patterns. Restore strict via AXONFLOW_PROFILE=strict.
	tests := []struct {
		name     string
		got      DetectionAction
		expected DetectionAction
	}{
		{"SQLIAction defaults to warn", cfg.SQLIAction, DetectionActionWarn},
		{"PIIAction defaults to warn", cfg.PIIAction, DetectionActionWarn},
		{"SensitiveDataAction defaults to warn", cfg.SensitiveDataAction, DetectionActionWarn},
		{"HighRiskAction defaults to warn", cfg.HighRiskAction, DetectionActionWarn},
		{"DangerousQueryAction defaults to block", cfg.DangerousQueryAction, DetectionActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("got %s, expected %s", tt.got, tt.expected)
			}
		})
	}
}

// TestDetectionConfigFromEnv_Defaults tests that defaults are used when no env vars are set.
func TestDetectionConfigFromEnv_Defaults(t *testing.T) {
	// Clear all relevant env vars
	envVars := []string{
		EnvSQLIAction, EnvPIIAction, EnvSensitiveDataAction,
		EnvHighRiskAction, EnvDangerousQueryAction,
		EnvSQLIBlockModeDeprecated, EnvPIIBlockCriticalDeprecated,
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
	defer func() {
		for _, env := range envVars {
			os.Unsetenv(env)
		}
	}()

	// Also clear the profile/enforce env vars to test true defaults.
	os.Unsetenv(EnvProfile)
	os.Unsetenv(EnvEnforce)

	cfg := DetectionConfigFromEnv()

	// v6.2.0+: default profile relaxes PII/SQLi to warn.
	if cfg.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction: got %s, expected warn (v6.2.0)", cfg.SQLIAction)
	}
	if cfg.PIIAction != DetectionActionWarn {
		t.Errorf("PIIAction: got %s, expected warn (v6.2.0)", cfg.PIIAction)
	}
	if cfg.SensitiveDataAction != DetectionActionWarn {
		t.Errorf("SensitiveDataAction: got %s, expected %s", cfg.SensitiveDataAction, DetectionActionWarn)
	}
	if cfg.HighRiskAction != DetectionActionWarn {
		t.Errorf("HighRiskAction: got %s, expected %s", cfg.HighRiskAction, DetectionActionWarn)
	}
	if cfg.DangerousQueryAction != DetectionActionBlock {
		t.Errorf("DangerousQueryAction: got %s, expected %s", cfg.DangerousQueryAction, DetectionActionBlock)
	}
}

// TestDetectionConfigFromEnv_NewEnvVars tests that new env vars override defaults.
func TestDetectionConfigFromEnv_NewEnvVars(t *testing.T) {
	// Clear deprecated env vars first
	os.Unsetenv(EnvSQLIBlockModeDeprecated)
	os.Unsetenv(EnvPIIBlockCriticalDeprecated)

	tests := []struct {
		name     string
		envVar   string
		value    string
		field    string
		expected DetectionAction
	}{
		{"SQLI_ACTION=block", EnvSQLIAction, "block", "SQLIAction", DetectionActionBlock},
		{"SQLI_ACTION=warn", EnvSQLIAction, "warn", "SQLIAction", DetectionActionWarn},
		{"SQLI_ACTION=log", EnvSQLIAction, "log", "SQLIAction", DetectionActionLog},
		{"SQLI_ACTION uppercase", EnvSQLIAction, "BLOCK", "SQLIAction", DetectionActionBlock},
		{"SQLI_ACTION with spaces", EnvSQLIAction, "  warn  ", "SQLIAction", DetectionActionWarn},
		{"PII_ACTION=block", EnvPIIAction, "block", "PIIAction", DetectionActionBlock},
		{"PII_ACTION=redact", EnvPIIAction, "redact", "PIIAction", DetectionActionRedact},
		{"PII_ACTION=warn", EnvPIIAction, "warn", "PIIAction", DetectionActionWarn},
		{"PII_ACTION=log", EnvPIIAction, "log", "PIIAction", DetectionActionLog},
		{"SENSITIVE_DATA_ACTION=block", EnvSensitiveDataAction, "block", "SensitiveDataAction", DetectionActionBlock},
		{"SENSITIVE_DATA_ACTION=warn", EnvSensitiveDataAction, "warn", "SensitiveDataAction", DetectionActionWarn},
		{"SENSITIVE_DATA_ACTION=log", EnvSensitiveDataAction, "log", "SensitiveDataAction", DetectionActionLog},
		{"HIGH_RISK_ACTION=block", EnvHighRiskAction, "block", "HighRiskAction", DetectionActionBlock},
		{"HIGH_RISK_ACTION=warn", EnvHighRiskAction, "warn", "HighRiskAction", DetectionActionWarn},
		{"HIGH_RISK_ACTION=log", EnvHighRiskAction, "log", "HighRiskAction", DetectionActionLog},
		{"DANGEROUS_QUERY_ACTION=block", EnvDangerousQueryAction, "block", "DangerousQueryAction", DetectionActionBlock},
		{"DANGEROUS_QUERY_ACTION=warn", EnvDangerousQueryAction, "warn", "DangerousQueryAction", DetectionActionWarn},
		{"DANGEROUS_QUERY_ACTION=log", EnvDangerousQueryAction, "log", "DangerousQueryAction", DetectionActionLog},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars
			os.Unsetenv(EnvSQLIAction)
			os.Unsetenv(EnvPIIAction)
			os.Unsetenv(EnvSensitiveDataAction)
			os.Unsetenv(EnvHighRiskAction)
			os.Unsetenv(EnvDangerousQueryAction)
			os.Unsetenv(EnvSQLIBlockModeDeprecated)
			os.Unsetenv(EnvPIIBlockCriticalDeprecated)

			// Set the test env var
			os.Setenv(tt.envVar, tt.value)
			defer os.Unsetenv(tt.envVar)

			cfg := DetectionConfigFromEnv()

			var got DetectionAction
			switch tt.field {
			case "SQLIAction":
				got = cfg.SQLIAction
			case "PIIAction":
				got = cfg.PIIAction
			case "SensitiveDataAction":
				got = cfg.SensitiveDataAction
			case "HighRiskAction":
				got = cfg.HighRiskAction
			case "DangerousQueryAction":
				got = cfg.DangerousQueryAction
			}

			if got != tt.expected {
				t.Errorf("%s: got %s, expected %s", tt.field, got, tt.expected)
			}
		})
	}
}

// TestDetectionConfigFromEnv_DeprecatedEnvVars tests deprecated env var handling.
func TestDetectionConfigFromEnv_DeprecatedEnvVars(t *testing.T) {
	// Clear new env vars
	os.Unsetenv(EnvSQLIAction)
	os.Unsetenv(EnvPIIAction)

	tests := []struct {
		name     string
		envVar   string
		value    string
		field    string
		expected DetectionAction
	}{
		// SQLI_BLOCK_MODE (deprecated)
		{"SQLI_BLOCK_MODE=block", EnvSQLIBlockModeDeprecated, "block", "SQLIAction", DetectionActionBlock},
		{"SQLI_BLOCK_MODE=warn", EnvSQLIBlockModeDeprecated, "warn", "SQLIAction", DetectionActionWarn},
		{"SQLI_BLOCK_MODE=invalid defaults to block", EnvSQLIBlockModeDeprecated, "invalid", "SQLIAction", DetectionActionBlock},
		// PII_BLOCK_CRITICAL (deprecated)
		{"PII_BLOCK_CRITICAL=true", EnvPIIBlockCriticalDeprecated, "true", "PIIAction", DetectionActionBlock},
		{"PII_BLOCK_CRITICAL=false", EnvPIIBlockCriticalDeprecated, "false", "PIIAction", DetectionActionLog},
		{"PII_BLOCK_CRITICAL=0", EnvPIIBlockCriticalDeprecated, "0", "PIIAction", DetectionActionLog},
		{"PII_BLOCK_CRITICAL=1", EnvPIIBlockCriticalDeprecated, "1", "PIIAction", DetectionActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars
			os.Unsetenv(EnvSQLIAction)
			os.Unsetenv(EnvPIIAction)
			os.Unsetenv(EnvSQLIBlockModeDeprecated)
			os.Unsetenv(EnvPIIBlockCriticalDeprecated)

			// Set the test env var
			os.Setenv(tt.envVar, tt.value)
			defer os.Unsetenv(tt.envVar)

			cfg := DetectionConfigFromEnv()

			var got DetectionAction
			switch tt.field {
			case "SQLIAction":
				got = cfg.SQLIAction
			case "PIIAction":
				got = cfg.PIIAction
			}

			if got != tt.expected {
				t.Errorf("%s: got %s, expected %s", tt.field, got, tt.expected)
			}
		})
	}
}

// TestDetectionConfigFromEnv_NewOverridesDeprecated tests that new env vars take precedence.
func TestDetectionConfigFromEnv_NewOverridesDeprecated(t *testing.T) {
	// Set both new and deprecated env vars - new should win
	os.Setenv(EnvSQLIAction, "warn")
	os.Setenv(EnvSQLIBlockModeDeprecated, "block")
	os.Setenv(EnvPIIAction, "log")
	os.Setenv(EnvPIIBlockCriticalDeprecated, "true")
	defer func() {
		os.Unsetenv(EnvSQLIAction)
		os.Unsetenv(EnvSQLIBlockModeDeprecated)
		os.Unsetenv(EnvPIIAction)
		os.Unsetenv(EnvPIIBlockCriticalDeprecated)
	}()

	cfg := DetectionConfigFromEnv()

	// New env vars should take precedence
	if cfg.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction: expected new var to win, got %s", cfg.SQLIAction)
	}
	if cfg.PIIAction != DetectionActionLog {
		t.Errorf("PIIAction: expected new var to win, got %s", cfg.PIIAction)
	}
}

// TestDetectionConfigFromEnv_InvalidValues tests that invalid values fall back to defaults.
func TestDetectionConfigFromEnv_InvalidValues(t *testing.T) {
	// Clear deprecated vars
	os.Unsetenv(EnvSQLIBlockModeDeprecated)
	os.Unsetenv(EnvPIIBlockCriticalDeprecated)

	tests := []struct {
		name     string
		envVar   string
		value    string
		expected DetectionAction
	}{
		// v6.2.0+: defaults relaxed under AXONFLOW_PROFILE=default. Invalid values
		// fall back to the parseDetectionAction hardcoded fallback (block for SQLi,
		// redact for PII), not to the relaxed profile defaults — this preserves
		// the "fail to a stricter posture" intuition for malformed input.
		{"SQLI_ACTION invalid falls back to block", EnvSQLIAction, "invalid", DetectionActionBlock},
		{"SQLI_ACTION empty inherits profile (warn)", EnvSQLIAction, "", DetectionActionWarn},
		{"PII_ACTION invalid falls back to redact", EnvPIIAction, "invalid", DetectionActionRedact},
		// Note: "redact" is not valid for SQLI, should fallback to hardcoded block.
		{"SQLI_ACTION redact (invalid for sqli) falls back to block", EnvSQLIAction, "redact", DetectionActionBlock},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars
			os.Unsetenv(EnvSQLIAction)
			os.Unsetenv(EnvPIIAction)

			if tt.value != "" {
				os.Setenv(tt.envVar, tt.value)
				defer os.Unsetenv(tt.envVar)
			}

			cfg := DetectionConfigFromEnv()

			var got DetectionAction
			switch tt.envVar {
			case EnvSQLIAction:
				got = cfg.SQLIAction
			case EnvPIIAction:
				got = cfg.PIIAction
			}

			if got != tt.expected {
				t.Errorf("got %s, expected %s", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldBlock tests the ShouldBlock method.
func TestDetectionAction_ShouldBlock(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, true},
		{DetectionActionWarn, false},
		{DetectionActionRedact, false},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldBlock(); got != tt.expected {
				t.Errorf("ShouldBlock() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldRedact tests the ShouldRedact method.
func TestDetectionAction_ShouldRedact(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, false},
		{DetectionActionWarn, false},
		{DetectionActionRedact, true},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldRedact(); got != tt.expected {
				t.Errorf("ShouldRedact() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldWarn tests the ShouldWarn method.
func TestDetectionAction_ShouldWarn(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected bool
	}{
		{DetectionActionBlock, false},
		{DetectionActionWarn, true},
		{DetectionActionRedact, false},
		{DetectionActionLog, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ShouldWarn(); got != tt.expected {
				t.Errorf("ShouldWarn() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_ShouldLog tests the ShouldLog method.
func TestDetectionAction_ShouldLog(t *testing.T) {
	// All actions should log
	tests := []DetectionAction{
		DetectionActionBlock,
		DetectionActionWarn,
		DetectionActionRedact,
		DetectionActionLog,
	}

	for _, action := range tests {
		t.Run(string(action), func(t *testing.T) {
			if got := action.ShouldLog(); !got {
				t.Errorf("ShouldLog() = %v, expected true", got)
			}
		})
	}
}

// TestDetectionAction_ToOverrideAction tests conversion to OverrideAction.
func TestDetectionAction_ToOverrideAction(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected OverrideAction
	}{
		{DetectionActionBlock, ActionBlock},
		{DetectionActionWarn, ActionWarn},
		{DetectionActionRedact, ActionRedact},
		{DetectionActionLog, ActionLog},
		{DetectionAction("unknown"), ActionBlock}, // Unknown defaults to block
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ToOverrideAction(); got != tt.expected {
				t.Errorf("ToOverrideAction() = %v, expected %v", got, tt.expected)
			}
		})
	}
}

// TestParseDetectionAction tests the parseDetectionAction function.
func TestParseDetectionAction(t *testing.T) {
	tests := []struct {
		name         string
		value        string
		defaultVal   DetectionAction
		validActions []DetectionAction
		expected     DetectionAction
	}{
		{
			name:         "valid block",
			value:        "block",
			defaultVal:   DetectionActionWarn,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionBlock,
		},
		{
			name:         "valid warn",
			value:        "warn",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionWarn,
		},
		{
			name:         "valid log",
			value:        "log",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionLog,
		},
		{
			name:         "case insensitive",
			value:        "BLOCK",
			defaultVal:   DetectionActionWarn,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionBlock,
		},
		{
			name:         "with whitespace",
			value:        "  warn  ",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionWarn,
		},
		{
			name:         "invalid returns default",
			value:        "invalid",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionBlock,
		},
		{
			name:         "redact not in valid list returns default",
			value:        "redact",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog},
			expected:     DetectionActionBlock,
		},
		{
			name:         "redact in valid list works",
			value:        "redact",
			defaultVal:   DetectionActionBlock,
			validActions: []DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionRedact, DetectionActionLog},
			expected:     DetectionActionRedact,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseDetectionAction(tt.value, "TEST_ENV", tt.defaultVal, tt.validActions)
			if got != tt.expected {
				t.Errorf("parseDetectionAction(%q) = %s, expected %s", tt.value, got, tt.expected)
			}
		})
	}
}

// TestDetectionAction_Constants tests the constant values.
func TestDetectionAction_Constants(t *testing.T) {
	// Verify constant values match expected strings
	tests := []struct {
		action   DetectionAction
		expected string
	}{
		{DetectionActionBlock, "block"},
		{DetectionActionWarn, "warn"},
		{DetectionActionRedact, "redact"},
		{DetectionActionLog, "log"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if string(tt.action) != tt.expected {
				t.Errorf("constant value = %q, expected %q", string(tt.action), tt.expected)
			}
		})
	}
}

// TestEnvVarConstants tests environment variable constant values.
func TestEnvVarConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		{EnvSQLIAction, "SQLI_ACTION"},
		{EnvPIIAction, "PII_ACTION"},
		{EnvSensitiveDataAction, "SENSITIVE_DATA_ACTION"},
		{EnvHighRiskAction, "HIGH_RISK_ACTION"},
		{EnvDangerousQueryAction, "DANGEROUS_QUERY_ACTION"},
		{EnvSQLIBlockModeDeprecated, "SQLI_BLOCK_MODE"},
		{EnvPIIBlockCriticalDeprecated, "PII_BLOCK_CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("constant value = %q, expected %q", tt.constant, tt.expected)
			}
		})
	}
}

// =============================================================================
// ModeDetectionConfig Tests
// =============================================================================

// clearModeEnvVars clears all mode-specific env vars for clean test state.
func clearModeEnvVars() {
	envVars := []string{
		EnvSQLIAction, EnvPIIAction, EnvSensitiveDataAction,
		EnvHighRiskAction, EnvDangerousQueryAction,
		EnvSQLIBlockModeDeprecated, EnvPIIBlockCriticalDeprecated,
		EnvMCPStaticPoliciesEnabled, EnvGatewayStaticPoliciesEnabled,
		EnvMCPPIIAction, EnvMCPSQLIAction, EnvMCPDangerousQueryAction,
		EnvGatewayPIIAction, EnvGatewaySQLIAction,
		EnvMCPStaticPoliciesSkipCategories, EnvGatewayStaticPoliciesSkipCategories,
		EnvMCPStaticPoliciesConnectors,
	}
	for _, env := range envVars {
		os.Unsetenv(env)
	}
}

func TestMCPDetectionConfigFromEnv_Defaults(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	cfg := MCPDetectionConfigFromEnv()

	if !cfg.Enabled {
		t.Error("Expected MCP static policies enabled by default")
	}
	// v6.2.0+: defaults relaxed under AXONFLOW_PROFILE=default.
	// PII and SQLi now default to warn; only dangerous patterns block.
	if cfg.PIIAction != DetectionActionWarn {
		t.Errorf("PIIAction: got %s, expected warn (v6.2.0 default)", cfg.PIIAction)
	}
	if cfg.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction: got %s, expected warn (v6.2.0 default)", cfg.SQLIAction)
	}
	if cfg.DangerousQueryAction != DetectionActionBlock {
		t.Errorf("DangerousQueryAction: got %s, expected block", cfg.DangerousQueryAction)
	}
	if len(cfg.SkipCategories) != 0 {
		t.Errorf("SkipCategories: got %v, expected empty", cfg.SkipCategories)
	}
	if len(cfg.Connectors) != 0 {
		t.Errorf("Connectors: got %v, expected empty", cfg.Connectors)
	}
}

func TestMCPDetectionConfigFromEnv_Disabled(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPStaticPoliciesEnabled, "false")

	cfg := MCPDetectionConfigFromEnv()

	if cfg.Enabled {
		t.Error("Expected MCP static policies disabled")
	}
}

func TestMCPDetectionConfigFromEnv_ModeSpecificOverridesGlobal(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	// Set global PII_ACTION=block
	os.Setenv(EnvPIIAction, "block")
	// Set MCP-specific to log (should override global)
	os.Setenv(EnvMCPPIIAction, "log")

	cfg := MCPDetectionConfigFromEnv()

	if cfg.PIIAction != DetectionActionLog {
		t.Errorf("Expected MCP_PII_ACTION=log to override PII_ACTION=block, got %s", cfg.PIIAction)
	}
}

func TestMCPDetectionConfigFromEnv_GlobalFallback(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	// Set global PII_ACTION=block, no MCP-specific override
	os.Setenv(EnvPIIAction, "block")

	cfg := MCPDetectionConfigFromEnv()

	if cfg.PIIAction != DetectionActionBlock {
		t.Errorf("Expected PII_ACTION=block to apply when no MCP override, got %s", cfg.PIIAction)
	}
}

func TestMCPDetectionConfigFromEnv_SkipCategories(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPStaticPoliciesSkipCategories, "pii-global, pii-us")

	cfg := MCPDetectionConfigFromEnv()

	if len(cfg.SkipCategories) != 2 {
		t.Fatalf("Expected 2 skip categories, got %d: %v", len(cfg.SkipCategories), cfg.SkipCategories)
	}
	if cfg.SkipCategories[0] != "pii-global" {
		t.Errorf("Expected first skip category 'pii-global', got %s", cfg.SkipCategories[0])
	}
	if cfg.SkipCategories[1] != "pii-us" {
		t.Errorf("Expected second skip category 'pii-us', got %s", cfg.SkipCategories[1])
	}
}

func TestMCPDetectionConfigFromEnv_ConnectorsIgnoredWithoutEnterprise(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	// Without enterprise license, connectors should be ignored
	os.Setenv(EnvMCPStaticPoliciesConnectors, "postgres,mysql")
	// Ensure no enterprise license is set
	os.Unsetenv("AXONFLOW_LICENSE_KEY")

	cfg := MCPDetectionConfigFromEnv()

	if len(cfg.Connectors) != 0 {
		t.Errorf("Expected connectors to be empty without enterprise license, got %v", cfg.Connectors)
	}
}

func TestMCPDetectionConfigFromEnv_AllOverrides(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvMCPPIIAction, "warn")
	os.Setenv(EnvMCPSQLIAction, "log")
	os.Setenv(EnvMCPDangerousQueryAction, "warn")

	cfg := MCPDetectionConfigFromEnv()

	if cfg.PIIAction != DetectionActionWarn {
		t.Errorf("PIIAction: got %s, expected warn", cfg.PIIAction)
	}
	if cfg.SQLIAction != DetectionActionLog {
		t.Errorf("SQLIAction: got %s, expected log", cfg.SQLIAction)
	}
	if cfg.DangerousQueryAction != DetectionActionWarn {
		t.Errorf("DangerousQueryAction: got %s, expected warn", cfg.DangerousQueryAction)
	}
}

func TestGatewayDetectionConfigFromEnv_Defaults(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	cfg := GatewayDetectionConfigFromEnv()

	if !cfg.Enabled {
		t.Error("Expected Gateway static policies enabled by default")
	}
	// v6.2.0+: defaults relaxed under AXONFLOW_PROFILE=default.
	if cfg.PIIAction != DetectionActionWarn {
		t.Errorf("PIIAction: got %s, expected warn (v6.2.0 default)", cfg.PIIAction)
	}
	if cfg.SQLIAction != DetectionActionWarn {
		t.Errorf("SQLIAction: got %s, expected warn (v6.2.0 default)", cfg.SQLIAction)
	}
}

func TestGatewayDetectionConfigFromEnv_Disabled(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvGatewayStaticPoliciesEnabled, "false")

	cfg := GatewayDetectionConfigFromEnv()

	if cfg.Enabled {
		t.Error("Expected Gateway static policies disabled")
	}
}

func TestGatewayDetectionConfigFromEnv_ModeSpecificOverridesGlobal(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvPIIAction, "block")
	os.Setenv(EnvGatewayPIIAction, "log")

	cfg := GatewayDetectionConfigFromEnv()

	if cfg.PIIAction != DetectionActionLog {
		t.Errorf("Expected GATEWAY_PII_ACTION=log to override PII_ACTION=block, got %s", cfg.PIIAction)
	}
}

func TestGatewayDetectionConfigFromEnv_SkipCategories(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	os.Setenv(EnvGatewayStaticPoliciesSkipCategories, "security-sqli")

	cfg := GatewayDetectionConfigFromEnv()

	if len(cfg.SkipCategories) != 1 {
		t.Fatalf("Expected 1 skip category, got %d", len(cfg.SkipCategories))
	}
	if cfg.SkipCategories[0] != "security-sqli" {
		t.Errorf("Expected 'security-sqli', got %s", cfg.SkipCategories[0])
	}
}

func TestBuildActionOverrides(t *testing.T) {
	cfg := ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              DetectionActionBlock,
		SQLIAction:             DetectionActionWarn,
		DangerousQueryAction:   DetectionActionLog,
		DangerousCommandAction: DetectionActionBlock,
	}

	overrides := cfg.BuildActionOverrides()

	// Verify PII categories all get block
	for _, cat := range []sharedpolicy.PolicyCategory{
		sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore,
	} {
		if overrides[cat] != sharedpolicy.ActionBlock {
			t.Errorf("PII category %s: got %s, expected block", cat, overrides[cat])
		}
	}

	// Verify SQLi gets warn
	if overrides[sharedpolicy.CategorySecuritySQLi] != sharedpolicy.ActionWarn {
		t.Errorf("SQLi: got %s, expected warn", overrides[sharedpolicy.CategorySecuritySQLi])
	}

	// Verify dangerous commands (security-dangerous) get block — separate from dangerous queries
	if overrides[sharedpolicy.CategorySecurityDangerous] != sharedpolicy.ActionBlock {
		t.Errorf("DangerousCommand: got %s, expected block", overrides[sharedpolicy.CategorySecurityDangerous])
	}
}

func TestIsConnectorEnabled(t *testing.T) {
	tests := []struct {
		name       string
		connectors []string
		connector  string
		expected   bool
	}{
		{"empty list enables all", nil, "postgres", true},
		{"empty slice enables all", []string{}, "postgres", true},
		{"connector in list", []string{"postgres", "mysql"}, "postgres", true},
		{"connector not in list", []string{"postgres", "mysql"}, "redis", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := ModeDetectionConfig{Connectors: tt.connectors}
			if got := cfg.IsConnectorEnabled(tt.connector); got != tt.expected {
				t.Errorf("IsConnectorEnabled(%q) = %v, expected %v", tt.connector, got, tt.expected)
			}
		})
	}
}

func TestParseBoolEnv(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		defaultVal bool
		expected   bool
	}{
		{"empty uses default true", "", true, true},
		{"empty uses default false", "", false, false},
		{"true", "true", false, true},
		{"TRUE", "TRUE", false, true},
		{"1", "1", false, true},
		{"yes", "yes", false, true},
		{"false", "false", true, false},
		{"FALSE", "FALSE", true, false},
		{"0", "0", true, false},
		{"no", "no", true, false},
		{"invalid uses default", "invalid", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envName := "TEST_PARSE_BOOL"
			os.Unsetenv(envName)
			if tt.value != "" {
				os.Setenv(envName, tt.value)
				defer os.Unsetenv(envName)
			}
			if got := parseBoolEnv(envName, tt.defaultVal); got != tt.expected {
				t.Errorf("parseBoolEnv(%q, %v) = %v, expected %v", tt.value, tt.defaultVal, got, tt.expected)
			}
		})
	}
}

func TestParseCategoryList(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty string", "", 0},
		{"single category", "pii-global", 1},
		{"multiple categories", "pii-global,pii-us,pii-india", 3},
		{"with spaces", " pii-global , pii-us ", 2},
		{"trailing comma", "pii-global,", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCategoryList(tt.input)
			if len(result) != tt.expected {
				t.Errorf("parseCategoryList(%q) returned %d categories, expected %d", tt.input, len(result), tt.expected)
			}
		})
	}
}

func TestParseCSV(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"empty string", "", 0},
		{"single value", "postgres", 1},
		{"multiple values", "postgres,mysql,redis", 3},
		{"with spaces", " postgres , mysql ", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCSV(tt.input)
			if len(result) != tt.expected {
				t.Errorf("parseCSV(%q) returned %d values, expected %d", tt.input, len(result), tt.expected)
			}
		})
	}
}

func TestToPolicyAction(t *testing.T) {
	tests := []struct {
		action   DetectionAction
		expected sharedpolicy.Action
	}{
		{DetectionActionBlock, sharedpolicy.ActionBlock},
		{DetectionActionRedact, sharedpolicy.ActionRedact},
		{DetectionActionWarn, sharedpolicy.ActionWarn},
		{DetectionActionLog, sharedpolicy.ActionLog},
		{DetectionAction("unknown"), sharedpolicy.ActionBlock},
	}

	for _, tt := range tests {
		t.Run(string(tt.action), func(t *testing.T) {
			if got := tt.action.ToPolicyAction(); got != tt.expected {
				t.Errorf("ToPolicyAction() = %s, expected %s", got, tt.expected)
			}
		})
	}
}

func TestMCPAndGatewayIndependentConfig(t *testing.T) {
	clearModeEnvVars()
	defer clearModeEnvVars()

	// MCP: PII=warn, SQLi=log
	os.Setenv(EnvMCPPIIAction, "warn")
	os.Setenv(EnvMCPSQLIAction, "log")

	// Gateway: PII=block, SQLi defaults (block)
	os.Setenv(EnvGatewayPIIAction, "block")

	mcpCfg := MCPDetectionConfigFromEnv()
	gwCfg := GatewayDetectionConfigFromEnv()

	// Verify independence
	if mcpCfg.PIIAction != DetectionActionWarn {
		t.Errorf("MCP PIIAction: got %s, expected warn", mcpCfg.PIIAction)
	}
	if gwCfg.PIIAction != DetectionActionBlock {
		t.Errorf("Gateway PIIAction: got %s, expected block", gwCfg.PIIAction)
	}
	if mcpCfg.SQLIAction != DetectionActionLog {
		t.Errorf("MCP SQLIAction: got %s, expected log", mcpCfg.SQLIAction)
	}
	// v6.2.0+: gateway SQLi default is now warn (not block).
	if gwCfg.SQLIAction != DetectionActionWarn {
		t.Errorf("Gateway SQLIAction: got %s, expected warn (v6.2.0 default)", gwCfg.SQLIAction)
	}
}

func TestDetectionConfigCache_ReturnsStartupValues(t *testing.T) {
	// Reset any existing cache
	ResetDetectionConfigCache()

	// Set initial env vars and cache
	t.Setenv(EnvMCPPIIAction, "block")
	t.Setenv(EnvGatewayPIIAction, "warn")
	InitDetectionConfigs()

	// Verify cached values
	mcpCfg := GetMCPDetectionConfig()
	if mcpCfg.PIIAction != DetectionActionBlock {
		t.Errorf("Cached MCP PIIAction: got %s, expected block", mcpCfg.PIIAction)
	}
	gwCfg := GetGatewayDetectionConfig()
	if gwCfg.PIIAction != DetectionActionWarn {
		t.Errorf("Cached Gateway PIIAction: got %s, expected warn", gwCfg.PIIAction)
	}

	// Change env vars — cached values should NOT change
	t.Setenv(EnvMCPPIIAction, "log")
	t.Setenv(EnvGatewayPIIAction, "log")

	mcpCfg2 := GetMCPDetectionConfig()
	if mcpCfg2.PIIAction != DetectionActionBlock {
		t.Errorf("Cache should be stable after env change: got %s, expected block", mcpCfg2.PIIAction)
	}
	gwCfg2 := GetGatewayDetectionConfig()
	if gwCfg2.PIIAction != DetectionActionWarn {
		t.Errorf("Cache should be stable after env change: got %s, expected warn", gwCfg2.PIIAction)
	}

	// Reset cache and re-init — now picks up new values
	ResetDetectionConfigCache()
	InitDetectionConfigs()

	mcpCfg3 := GetMCPDetectionConfig()
	if mcpCfg3.PIIAction != DetectionActionLog {
		t.Errorf("After reset+reinit: got %s, expected log", mcpCfg3.PIIAction)
	}

	// Clean up for other tests
	ResetDetectionConfigCache()
}

func TestDetectionConfigCache_FallbackWhenNotInitialized(t *testing.T) {
	// Ensure cache is empty
	ResetDetectionConfigCache()

	t.Setenv(EnvMCPPIIAction, "warn")

	// Without InitDetectionConfigs(), should fall back to parsing from env
	cfg := GetMCPDetectionConfig()
	if cfg.PIIAction != DetectionActionWarn {
		t.Errorf("Fallback should parse from env: got %s, expected warn", cfg.PIIAction)
	}

	// Clean up
	ResetDetectionConfigCache()
}
