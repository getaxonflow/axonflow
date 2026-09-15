//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package license provides license tier types, constants, validation, and
// helpers shared across community and enterprise builds.
package license

import (
	"crypto/ed25519"
	"time"
)

// Tier represents the license tier
type Tier string

const (
	TierProfessional   Tier = "Professional"
	TierEnterprise     Tier = "Enterprise"
	TierEnterprisePlus Tier = "Plus"
	TierEvaluation     Tier = "Evaluation" // Evaluation tier - free license with elevated limits
	TierCommunity      Tier = "Community"  // Community tier - no license required

	// SaaS Plugin tier constants (per ADR-050 §1) — duplicated here for
	// the community build because `auth.go` references `TierFree` and
	// `auth.go` is loaded in BOTH build tags. The enterprise validation.go
	// declares the same constants under `//go:build enterprise`; both
	// share the same string values so the rendered DB rows / API responses
	// are identical regardless of which build resolves the symbol.
	TierFree    Tier = "Free"
	TierPro     Tier = "Pro"
	TierPremium Tier = "Premium"
)

// IsPaidTier returns true if the tier is a paid tier (Professional, Enterprise, Plus).
func IsPaidTier(t Tier) bool {
	return t == TierProfessional || t == TierEnterprise || t == TierEnterprisePlus
}

// IsEvaluationOrHigher returns true if the tier is Evaluation or any paid tier.
func IsEvaluationOrHigher(t Tier) bool {
	return t == TierEvaluation || IsPaidTier(t)
}

// IsHITLApprovalEntitled reports whether a tier entitles the deployment to the
// Human-in-the-Loop approval queue.
//
// OPERATOR DECISION, 2026-08-26: HITL is Enterprise-only. The entitled set is
// Professional, Enterprise and Enterprise Plus - the tiers GetTierLimits maps
// onto EnterpriseLimits. Evaluation WAS entitled and is not any more;
// Community, Free, Pro and Premium never were.
//
// IT READS THE TIER MATRIX RATHER THAN RESTATING THE SET, and that is the
// point. #3416's whole class of defect is "a tier value exists but the code
// that loads it does something else" - a declared limit and an enforcing
// predicate that drift apart. Deriving the gate FROM TierLimits.HITLApprovalEnabled
// means the declaration and the enforcement are the same fact, so changing the
// entitled set is one edit to the tables and cannot leave a gate behind.
//
// DELIBERATELY NOT NAMED IsEnterpriseTier: that name is taken by a different
// predicate in this package whose set is NARROWER (Enterprise and Enterprise
// Plus only - it excludes Professional, which is #3416 item 3). Reusing it
// would have silently denied Professional licensees a feature they are
// entitled to.
//
// DELIBERATELY NOT IsEvaluationOrHigher EITHER: that predicate has ten other
// non-HITL callers - cost-estimation limits, org-tier policy quotas, upgrade
// URLs, the tier-warning banner - which all still legitimately mean
// "evaluation or higher". Repurposing a shared predicate is how this class of
// bug spreads.
func IsHITLApprovalEntitled(t Tier) bool {
	return GetTierLimits(t).HITLApprovalEnabled
}

// tierRank returns the numeric rank of a tier for comparison. Returns -1
// for any unknown tier so rank-based comparisons fail closed (GAP-3).
// Pre-fix the default returned 0 (== Community), silently treating unknown
// tiers as the lowest valid tier — a footgun for any future tier added
// without updating this switch. Mirrors the enterprise-build version in
// validation.go.
func tierRank(t Tier) int {
	switch t {
	case TierCommunity:
		return 0
	case TierEvaluation:
		return 0
	case TierProfessional:
		return 1
	case TierEnterprise:
		return 2
	case TierEnterprisePlus:
		return 3
	default:
		return -1
	}
}

// TierSatisfiesRequirement returns true if the current tier meets or exceeds
// the required tier level. Used for provider access gating.
//
// Fails closed when EITHER tier has rank -1 (unknown tier — GAP-3).
func TierSatisfiesRequirement(current, required Tier) bool {
	cr := tierRank(current)
	rr := tierRank(required)
	if cr < 0 || rr < 0 {
		return false
	}
	return cr >= rr
}

// normalizeTier validates that a tier string matches one of the canonical
// Tier constants. Returns the tier as-is if valid, or Tier(raw) for unknown
// values (which will fail downstream validation).
func normalizeTier(raw string) Tier {
	switch raw {
	case string(TierProfessional):
		return TierProfessional
	case string(TierEnterprise):
		return TierEnterprise
	case string(TierEnterprisePlus):
		return TierEnterprisePlus
	case string(TierEvaluation):
		return TierEvaluation
	default:
		return Tier(raw)
	}
}

// GetTierLimits returns the resource limits for a given tier.
func GetTierLimits(tier Tier) TierLimits {
	switch tier {
	case TierEvaluation:
		return EvaluationLimits
	case TierProfessional, TierEnterprise, TierEnterprisePlus:
		return EnterpriseLimits
	default:
		return CommunityLimits
	}
}

// Ed25519 public keys for license signature verification.
// These are embedded in the binary — the corresponding private keys
// never leave our infrastructure (AWS Secrets Manager / CF Worker).
// Generated by scripts/generate-license-keypair.sh on 2026-02-09.

// evaluationPublicKey verifies Evaluation tier licenses.
var evaluationPublicKey = ed25519.PublicKey{
	0x99, 0xbe, 0xd4, 0xd7, 0xa2, 0x50, 0xd8, 0xa0,
	0x8b, 0x2a, 0x79, 0x71, 0x4f, 0x52, 0xf0, 0x59,
	0xd5, 0x79, 0xa0, 0x7a, 0xf8, 0x16, 0x3f, 0x3e,
	0x85, 0x4f, 0x4b, 0x5e, 0x7f, 0xf6, 0x2a, 0x85,
}

// enterprisePublicKey verifies Professional, Enterprise, and Plus tier licenses.
// Rotated on 2026-04-09 (issue #1541). Must match ee/platform/agent/license/validation.go.
var enterprisePublicKey = ed25519.PublicKey{
	0x48, 0xac, 0xd8, 0xd1, 0x32, 0xaf, 0x9d, 0x4f,
	0xef, 0x3e, 0x6a, 0x92, 0x49, 0xb6, 0xdb, 0x2f,
	0xe8, 0x07, 0x21, 0x45, 0xd2, 0xaf, 0x2c, 0xfb,
	0x42, 0xb8, 0xc7, 0x22, 0x1e, 0x04, 0xa4, 0xb6,
}

// ValidationResult contains the result of license validation
type ValidationResult struct {
	Valid bool
	Tier  Tier
	// DeploymentID is the v9 name for the deployment/licensee identity that
	// the agent validates against the ORG_ID env var at startup. Per ADR-052
	// §3 + ADR-054 this is NOT the customer row org_id. Populated from the
	// V3 `deployment_id` payload field if present, else the legacy V2
	// `org_id` field. Use LicenseDeploymentID() to read.
	DeploymentID string
	// OrgID is the V2 license field name and equals DeploymentID for
	// backward compatibility. Removal in v10.
	//
	// Deprecated: use LicenseDeploymentID() instead.
	OrgID           string
	MaxNodes        int
	ExpiresAt       time.Time
	DaysUntilExpiry int
	GracePeriodDays int
	Error           string
	Message         string
	Features        map[string]bool
	Limits          TierLimits // Tier-specific resource limits

	// Service identity fields (optional - only for service licenses)
	ServiceName string   `json:"service_name,omitempty"`
	ServiceType string   `json:"service_type,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Email       string   `json:"email,omitempty"`
	LicenseID   string   `json:"license_id,omitempty"`
}

// LicenseDeploymentID returns the deployment/licensee identity for this
// validated license. Per ADR-052 §3 + ADR-054 this is the AxonFlow
// installation/license owner — used for startup validation against ORG_ID
// only and MUST NOT be written into customer-data rows (use the
// auth-derived request OrgID for that).
//
// Prefers the V3 `deployment_id` field; falls back to the V2 `org_id`
// field for legacy licenses. Always non-empty for a valid result.
func (r *ValidationResult) LicenseDeploymentID() string {
	if r.DeploymentID != "" {
		return r.DeploymentID
	}
	return r.OrgID
}

// ServiceLicensePayload represents the JSON payload in an Ed25519-signed license.
//
// Plugin-claim claims (TenantID, Aud, JTI, KID, Origin) are all `omitempty` so
// they only appear in plugin-claim tokens. Self-hosted tokens continue to
// serialize without these fields, preserving backward compatibility — existing
// validators don't read fields they don't know about. Carried in both
// community and enterprise builds so HasScope() / HostingMode() (defined in
// scope.go, no build tag) compile against a uniform shape.
type ServiceLicensePayload struct {
	LicenseID string `json:"id,omitempty"`
	Tier      string `json:"tier"`
	// DeploymentID is the v9 (V3 license payload) field name for the
	// deployment/licensee identity per ADR-052 §3 + ADR-054. New licenses
	// ship both `deployment_id` and `org_id`; V3 readers prefer the new
	// field. Carried in both community and enterprise builds.
	DeploymentID string      `json:"deployment_id,omitempty"`
	OrgID        string      `json:"org_id"`
	ServiceName  string      `json:"service_name,omitempty"`
	ServiceType  string      `json:"service_type,omitempty"`
	Permissions  []string    `json:"permissions,omitempty"`
	IssuedAt     string      `json:"issued_at,omitempty"` // Format: YYYYMMDD
	ExpiresAt    string      `json:"expires_at"`          // Format: YYYYMMDD
	Email        string      `json:"email,omitempty"`
	Email2       string      `json:"email2,omitempty"`
	Limits       *TierLimits `json:"limits,omitempty"`

	// Plugin-claim / SaaS-quadrant claims. Only present in tokens issued for
	// the SaaS Plugin path; self-hosted tokens leave them empty.
	TenantID string `json:"tenant_id,omitempty"`
	Aud      string `json:"aud,omitempty"` // see ADR-050 §1 for the canonical six values
	JTI      string `json:"jti,omitempty"`
	KID      string `json:"kid,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

// ValidateHMACSecretAtStartup is a no-op — HMAC is no longer used.
// Kept for interface compatibility during migration. Will be removed.
func ValidateHMACSecretAtStartup() error {
	return nil
}

// verifyEd25519Signature verifies the Ed25519 signature of a license payload.
// Selects the appropriate public key based on the license tier.
func verifyEd25519Signature(payload, signature []byte, tier Tier) bool {
	var pubKey ed25519.PublicKey
	switch tier {
	case TierEvaluation:
		pubKey = evaluationPublicKey
	default: // Professional, Enterprise, Plus
		pubKey = enterprisePublicKey
	}
	return ed25519.Verify(pubKey, payload, signature)
}
