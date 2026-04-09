// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
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
// Categories listed (in the explicit-list form) have their action forced to
// "block" on top of the active profile; categories NOT listed keep the active
// profile's value (they are not silently downgraded to warn).
//
// The `all` and `none` sentinels are true profile aliases: they produce the
// same category matrix as `AXONFLOW_PROFILE=strict` and `AXONFLOW_PROFILE=dev`
// respectively. Earlier versions of this code forced non-listed categories to
// "warn", which made `all` over-block high_risk and `none` under-log PII/SQLi
// relative to the documented profile equivalence.
//
// Unknown tokens are rejected with a startup error (never silently drop typos).
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

// EnforceResult is the parsed AXONFLOW_ENFORCE value.
//
// Exactly one of these is non-zero after parsing:
//
//	Sentinel    — "all", "none", or "" (no sentinel used)
//	Categories  — the explicit per-category set from a comma list
//
// When Sentinel == "", an Unset EnforceResult (Sentinel == "" and
// Categories == nil) means the env var was not set at all.
type EnforceResult struct {
	Sentinel   string          // "", "all", or "none"
	Categories EnforceCategorySet
}

// EnforceCategorySet is the explicit category set from a comma-separated list.
type EnforceCategorySet map[EnforceCategory]bool

// Unset reports whether AXONFLOW_ENFORCE was not set.
func (r EnforceResult) Unset() bool {
	return r.Sentinel == "" && r.Categories == nil
}

// ParseEnforce parses AXONFLOW_ENFORCE.
// Returns (EnforceResult{}, nil) when unset.
// Returns an error on unknown tokens (fail-loud, never silently drop typos).
func ParseEnforce(raw string) (EnforceResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return EnforceResult{}, nil
	}

	lower := strings.ToLower(raw)
	if lower == "all" || lower == "none" {
		return EnforceResult{Sentinel: lower}, nil
	}

	set := EnforceCategorySet{}
	for _, token := range strings.Split(raw, ",") {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" {
			continue
		}
		category := EnforceCategory(token)
		if !isValidEnforceCategory(category) {
			return EnforceResult{}, fmt.Errorf(
				"invalid AXONFLOW_ENFORCE category %q (valid: pii, sqli, sensitive_data, high_risk, dangerous_queries, dangerous_commands, all, none)",
				token,
			)
		}
		set[category] = true
	}
	return EnforceResult{Categories: set}, nil
}

func isValidEnforceCategory(c EnforceCategory) bool {
	for _, valid := range allEnforceCategories {
		if c == valid {
			return true
		}
	}
	return false
}

// ApplyEnforce applies an EnforceResult on top of a profile base DetectionConfig.
//
//   - Unset (no env var)              → return the input unchanged
//   - Sentinel "all"                  → return ProfileDefaults(ProfileStrict)
//   - Sentinel "none"                 → return ProfileDefaults(ProfileDev)
//   - Explicit category list          → start from the input, force listed
//     categories to "block", LEAVE non-listed categories at their current
//     profile value (do not downgrade to warn).
//
// Returns a new config; does not mutate the input.
// Called AFTER ProfileDefaults but BEFORE explicit *_ACTION env vars.
func ApplyEnforce(cfg DetectionConfig, result EnforceResult) DetectionConfig {
	if result.Unset() {
		return cfg
	}

	switch result.Sentinel {
	case "all":
		return ProfileDefaults(ProfileStrict)
	case "none":
		return ProfileDefaults(ProfileDev)
	}

	// Explicit per-category list: block the listed ones, keep everything else
	// at the current (profile-resolved) value. This is the fix for the review
	// finding where non-listed categories were silently downgraded to "warn".
	out := cfg
	if result.Categories[EnforcePII] {
		out.PIIAction = DetectionActionBlock
	}
	if result.Categories[EnforceSQLI] {
		out.SQLIAction = DetectionActionBlock
	}
	if result.Categories[EnforceSensitiveData] {
		out.SensitiveDataAction = DetectionActionBlock
	}
	if result.Categories[EnforceHighRisk] {
		out.HighRiskAction = DetectionActionBlock
	}
	if result.Categories[EnforceDangerousQuery] {
		out.DangerousQueryAction = DetectionActionBlock
	}
	if result.Categories[EnforceDangerousCommands] {
		out.DangerousCommandAction = DetectionActionBlock
	}
	return out
}

// LoadEnforceFromEnv reads AXONFLOW_ENFORCE from the environment and returns
// the parsed result. Returns an error on parse failure.
//
// Unlike the earlier version of this function, this does NOT call log.Fatalf.
// Callers at agent/orchestrator startup should print the error and exit
// cleanly; tests should call ParseEnforce directly or check the error return.
// Any developer with a stale AXONFLOW_ENFORCE in their shell used to crash
// the whole test binary on import; that footgun is removed.
func LoadEnforceFromEnv() (EnforceResult, error) {
	return ParseEnforce(os.Getenv(EnvEnforce))
}
