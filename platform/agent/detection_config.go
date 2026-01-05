// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"log"
	"os"
	"strings"
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
// TODO(Issue #891 follow-up): Add RBI_COMPLIANCE_MODE=strict env var that always blocks
// critical India PII (Aadhaar, PAN, UPI, Bank Account) regardless of PII_ACTION setting.
// This would be useful for organizations that must strictly comply with RBI FREE-AI guidelines.
// When RBI_COMPLIANCE_MODE=strict, RBI PII detection should override PII_ACTION.
const (
	// EnvSQLIAction controls SQL injection detection behavior.
	// Valid values: "block", "warn", "log"
	// Default: "block" (high confidence detection)
	EnvSQLIAction = "SQLI_ACTION"

	// EnvPIIAction controls PII detection behavior.
	// Valid values: "block", "warn", "redact", "log"
	// Default: "redact" (non-blocking, preserves UX)
	EnvPIIAction = "PII_ACTION"

	// EnvSensitiveDataAction controls sensitive data (credentials, tokens) detection.
	// Valid values: "block", "warn", "log"
	// Default: "warn" (may have false positives)
	EnvSensitiveDataAction = "SENSITIVE_DATA_ACTION"

	// EnvHighRiskAction controls high risk score (>0.8) behavior.
	// Valid values: "block", "warn", "log"
	// Default: "warn" (composite score needs tuning)
	EnvHighRiskAction = "HIGH_RISK_ACTION"

	// EnvDangerousQueryAction controls dangerous query (DROP, TRUNCATE) behavior.
	// Valid values: "block", "warn", "log"
	// Default: "block" (destructive operations)
	EnvDangerousQueryAction = "DANGEROUS_QUERY_ACTION"

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

	// DangerousQueryAction determines behavior when dangerous queries are detected.
	// Default: block
	DangerousQueryAction DetectionAction
}

// DefaultDetectionConfig returns the default detection configuration.
// Philosophy: Block high-confidence threats, warn on heuristics, redact PII.
func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		SQLIAction:           DetectionActionBlock,  // High confidence, real attacks
		PIIAction:            DetectionActionRedact, // Non-blocking, preserves UX
		SensitiveDataAction:  DetectionActionWarn,   // May have false positives
		HighRiskAction:       DetectionActionWarn,   // Composite score needs tuning
		DangerousQueryAction: DetectionActionBlock,  // Destructive operations
	}
}

// DetectionConfigFromEnv creates a detection configuration from environment variables.
// This function handles both new and deprecated environment variables.
//
// Precedence:
//  1. New env vars (SQLI_ACTION, PII_ACTION, etc.) take priority
//  2. Deprecated env vars are used as fallback with warning
//  3. Default values are used if no env var is set
func DetectionConfigFromEnv() DetectionConfig {
	cfg := DefaultDetectionConfig()

	// Parse SQLI_ACTION (new) or SQLI_BLOCK_MODE (deprecated)
	if action := os.Getenv(EnvSQLIAction); action != "" {
		cfg.SQLIAction = parseDetectionAction(action, "SQLI_ACTION", DetectionActionBlock,
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

	// Parse PII_ACTION (new) or PII_BLOCK_CRITICAL (deprecated)
	if action := os.Getenv(EnvPIIAction); action != "" {
		cfg.PIIAction = parseDetectionAction(action, "PII_ACTION", DetectionActionRedact,
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

	// Parse SENSITIVE_DATA_ACTION
	if action := os.Getenv(EnvSensitiveDataAction); action != "" {
		cfg.SensitiveDataAction = parseDetectionAction(action, "SENSITIVE_DATA_ACTION", DetectionActionWarn,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Parse HIGH_RISK_ACTION
	if action := os.Getenv(EnvHighRiskAction); action != "" {
		cfg.HighRiskAction = parseDetectionAction(action, "HIGH_RISK_ACTION", DetectionActionWarn,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Parse DANGEROUS_QUERY_ACTION
	if action := os.Getenv(EnvDangerousQueryAction); action != "" {
		cfg.DangerousQueryAction = parseDetectionAction(action, "DANGEROUS_QUERY_ACTION", DetectionActionBlock,
			[]DetectionAction{DetectionActionBlock, DetectionActionWarn, DetectionActionLog})
	}

	// Log configuration summary
	log.Printf("[Detection] Configuration: SQLI=%s, PII=%s, SensitiveData=%s, HighRisk=%s, DangerousQuery=%s",
		cfg.SQLIAction, cfg.PIIAction, cfg.SensitiveDataAction, cfg.HighRiskAction, cfg.DangerousQueryAction)

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
