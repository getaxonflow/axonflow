// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"testing"
)

// TestDefaultDetectionConfig tests the default configuration values.
func TestDefaultDetectionConfig(t *testing.T) {
	cfg := DefaultDetectionConfig()

	// Verify defaults match Issue #891 philosophy:
	// Block high-confidence threats, warn on heuristics, redact PII
	tests := []struct {
		name     string
		got      DetectionAction
		expected DetectionAction
	}{
		{"SQLIAction defaults to block", cfg.SQLIAction, DetectionActionBlock},
		{"PIIAction defaults to redact", cfg.PIIAction, DetectionActionRedact},
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

	cfg := DetectionConfigFromEnv()

	if cfg.SQLIAction != DetectionActionBlock {
		t.Errorf("SQLIAction: got %s, expected %s", cfg.SQLIAction, DetectionActionBlock)
	}
	if cfg.PIIAction != DetectionActionRedact {
		t.Errorf("PIIAction: got %s, expected %s", cfg.PIIAction, DetectionActionRedact)
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
		{"SQLI_ACTION invalid defaults to block", EnvSQLIAction, "invalid", DetectionActionBlock},
		{"SQLI_ACTION empty defaults to block", EnvSQLIAction, "", DetectionActionBlock},
		{"PII_ACTION invalid defaults to redact", EnvPIIAction, "invalid", DetectionActionRedact},
		// Note: "redact" is not valid for SQLI, should fallback
		{"SQLI_ACTION redact (invalid for sqli) defaults to block", EnvSQLIAction, "redact", DetectionActionBlock},
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
