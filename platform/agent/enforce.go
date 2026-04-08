// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// EnvEnforce is the env var for per-category enforcement opt-in.
//
// Format: comma-separated list of category tokens.
//
//	AXONFLOW_ENFORCE=pii,sqli,dangerous_commands
//	AXONFLOW_ENFORCE=all      # equivalent to AXONFLOW_PROFILE=strict
//	AXONFLOW_ENFORCE=none     # equivalent to AXONFLOW_PROFILE=dev
//
// Categories listed → action becomes "block".
// Categories NOT listed → action becomes "warn".
// Unknown tokens → fatal startup error (catches typos that would silently disable enforcement).
const EnvEnforce = "AXONFLOW_ENFORCE"

// EnforceCategory enumerates the categories supported by AXONFLOW_ENFORCE.
// These are deliberately NOT the same as sharedpolicy.PolicyCategory because
// the env var is a user-facing surface and needs friendly names.
type EnforceCategory string

const (
	EnforcePII               EnforceCategory = "pii"
	EnforceSQLI              EnforceCategory = "sqli"
	EnforceSensitiveData     EnforceCategory = "sensitive_data"
	EnforceHighRisk          EnforceCategory = "high_risk"
	EnforceDangerousQuery    EnforceCategory = "dangerous_queries"
	EnforceDangerousCommands EnforceCategory = "dangerous_commands"
)

// allEnforceCategories is the canonical set of valid AXONFLOW_ENFORCE tokens
// (excluding the special "all" / "none" sentinels).
var allEnforceCategories = []EnforceCategory{
	EnforcePII,
	EnforceSQLI,
	EnforceSensitiveData,
	EnforceHighRisk,
	EnforceDangerousQuery,
	EnforceDangerousCommands,
}

// EnforceSet is a parsed AXONFLOW_ENFORCE value.
// nil set means env var unset → no per-category override applied.
type EnforceSet map[EnforceCategory]bool

// ParseEnforce parses AXONFLOW_ENFORCE. Returns (nil, nil) when unset.
// Returns an error on unknown tokens (fail-loud, never silently drop typos).
func ParseEnforce(raw string) (EnforceSet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	lower := strings.ToLower(raw)
	if lower == "all" {
		set := EnforceSet{}
		for _, c := range allEnforceCategories {
			set[c] = true
		}
		return set, nil
	}
	if lower == "none" {
		// Empty (non-nil) set → all categories resolve to "warn"
		return EnforceSet{}, nil
	}

	set := EnforceSet{}
	for _, token := range strings.Split(raw, ",") {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		category := EnforceCategory(token)
		if !isValidEnforceCategory(category) {
			return nil, fmt.Errorf("invalid AXONFLOW_ENFORCE category %q (valid: pii, sqli, sensitive_data, high_risk, dangerous_queries, dangerous_commands, all, none)", token)
		}
		set[category] = true
	}
	return set, nil
}

func isValidEnforceCategory(c EnforceCategory) bool {
	for _, valid := range allEnforceCategories {
		if c == valid {
			return true
		}
	}
	return false
}

// ApplyEnforce applies an EnforceSet on top of a DetectionConfig.
// Categories present in the set become "block"; categories absent become "warn".
// Returns a new config; does not mutate the input.
//
// Called AFTER ProfileDefaults but BEFORE explicit category env vars.
func ApplyEnforce(cfg DetectionConfig, set EnforceSet) DetectionConfig {
	if set == nil {
		return cfg
	}
	out := cfg
	out.PIIAction = enforceAction(set, EnforcePII)
	out.SQLIAction = enforceAction(set, EnforceSQLI)
	out.SensitiveDataAction = enforceAction(set, EnforceSensitiveData)
	out.HighRiskAction = enforceAction(set, EnforceHighRisk)
	out.DangerousQueryAction = enforceAction(set, EnforceDangerousQuery)
	out.DangerousCommandAction = enforceAction(set, EnforceDangerousCommands)
	return out
}

func enforceAction(set EnforceSet, c EnforceCategory) DetectionAction {
	if set[c] {
		return DetectionActionBlock
	}
	return DetectionActionWarn
}

// LoadEnforceFromEnv reads AXONFLOW_ENFORCE from the environment and returns
// the parsed set. Logs a fatal error and exits the process on parse failure
// (typos must not silently disable enforcement).
func LoadEnforceFromEnv() EnforceSet {
	set, err := ParseEnforce(os.Getenv(EnvEnforce))
	if err != nil {
		log.Fatalf("[Profile] FATAL: %v", err)
	}
	return set
}
