// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"log"
	"os"
	"strings"
)

// Profile represents a governance enforcement profile that bundles per-category
// detection actions into a single env var. Profiles let users pick a posture
// (dev | default | strict | compliance) instead of tuning eight individual env vars.
//
// Precedence (highest → lowest):
//  1. Explicit category env vars (PII_ACTION, SQLI_ACTION, etc.)
//  2. AXONFLOW_ENFORCE per-category opt-in
//  3. AXONFLOW_PROFILE
//  4. Built-in defaults (DefaultDetectionConfig)
//
// See ADR-036 for the rationale and category matrix.
type Profile string

const (
	// ProfileDev is observe-only. Nothing blocks. All detections logged
	// to audit trail. Use for local evaluation and developer workflows.
	ProfileDev Profile = "dev"

	// ProfileDefault blocks unambiguously dangerous patterns only
	// (reverse shells, rm -rf, SSRF to metadata endpoints, credential files).
	// Warns on PII / SQLi / sensitive data. Logs compliance patterns.
	// This is the post-v6.2.0 out-of-box behavior.
	ProfileDefault Profile = "default"

	// ProfileStrict blocks PII, SQLi, dangerous commands, credentials.
	// Equivalent to the pre-v6.2.0 default behavior. Recommended for
	// production deployments fronting real user data.
	ProfileStrict Profile = "strict"

	// ProfileCompliance is strict + hard-block on regulated PII categories
	// (HIPAA, GDPR, PCI, RBI, MAS FEAT). Use for regulated environments.
	ProfileCompliance Profile = "compliance"
)

// EnvProfile is the env var name for selecting a governance profile.
const EnvProfile = "AXONFLOW_PROFILE"

// ResolveProfile reads AXONFLOW_PROFILE from the environment and returns
// the matching Profile constant. Returns ProfileDefault if unset or invalid.
func ResolveProfile() Profile {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv(EnvProfile)))
	switch Profile(raw) {
	case ProfileDev, ProfileDefault, ProfileStrict, ProfileCompliance:
		return Profile(raw)
	case "":
		return ProfileDefault
	default:
		log.Printf("[Profile] WARNING: Invalid %s=%q, falling back to %q. Valid: dev, default, strict, compliance",
			EnvProfile, raw, ProfileDefault)
		return ProfileDefault
	}
}

// ProfileDefaults returns the per-category default DetectionConfig for a profile.
// These defaults are applied BEFORE explicit env vars override individual categories.
//
// Matrix (authoritative — must match docs/guides/governance-profiles.md):
//
//	Category               dev    default  strict  compliance
//	────────────────────  ─────  ───────  ──────  ──────────
//	PII                    log    warn     block   block
//	SQLi                   log    warn     block   block
//	SensitiveData          log    warn     block   block
//	HighRisk               log    warn     warn    block
//	DangerousQuery         warn   block    block   block
//	DangerousCommand       warn   block    block   block
func ProfileDefaults(p Profile) DetectionConfig {
	switch p {
	case ProfileDev:
		return DetectionConfig{
			SQLIAction:             DetectionActionLog,
			PIIAction:              DetectionActionLog,
			SensitiveDataAction:    DetectionActionLog,
			HighRiskAction:         DetectionActionLog,
			DangerousQueryAction:   DetectionActionWarn,
			DangerousCommandAction: DetectionActionWarn,
		}
	case ProfileStrict:
		return DetectionConfig{
			SQLIAction:             DetectionActionBlock,
			PIIAction:              DetectionActionBlock,
			SensitiveDataAction:    DetectionActionBlock,
			HighRiskAction:         DetectionActionWarn,
			DangerousQueryAction:   DetectionActionBlock,
			DangerousCommandAction: DetectionActionBlock,
		}
	case ProfileCompliance:
		return DetectionConfig{
			SQLIAction:             DetectionActionBlock,
			PIIAction:              DetectionActionBlock,
			SensitiveDataAction:    DetectionActionBlock,
			HighRiskAction:         DetectionActionBlock,
			DangerousQueryAction:   DetectionActionBlock,
			DangerousCommandAction: DetectionActionBlock,
		}
	case ProfileDefault:
		fallthrough
	default:
		return DetectionConfig{
			SQLIAction:             DetectionActionWarn,
			PIIAction:              DetectionActionWarn,
			SensitiveDataAction:    DetectionActionWarn,
			HighRiskAction:         DetectionActionWarn,
			DangerousQueryAction:   DetectionActionBlock,
			DangerousCommandAction: DetectionActionBlock,
		}
	}
}

// LogProfileBanner logs the active profile and resolved category actions.
// Called once at agent and orchestrator startup so operators can see what
// posture the process is running in.
func LogProfileBanner(component string, p Profile, cfg DetectionConfig) {
	log.Printf("[Profile] %s active: %s — PII=%s, SQLI=%s, SensitiveData=%s, HighRisk=%s, DangerousQuery=%s, DangerousCommand=%s",
		component, p,
		cfg.PIIAction, cfg.SQLIAction, cfg.SensitiveDataAction, cfg.HighRiskAction,
		cfg.DangerousQueryAction, cfg.DangerousCommandAction)
}
