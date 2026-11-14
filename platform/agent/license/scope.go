// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"fmt"
	"strings"

	"axonflow/platform/shared/capabilityresolution"
)

// scope.go — ADR-050 §2/§3/§4. Helpers for the canonical aud values and the
// X-Axonflow-Client header convention, callable from both community and
// enterprise builds (no build tag).
//
//   - HostingMode() / HasScope() — methods on the payload struct that derive
//     hosting mode + scope from the aud claim. Per ADR-050 §2 there are no
//     separate hosting_mode / scope fields; both are derived from the aud
//     segments (e.g. "axonflow.saas.plugin" → mode=saas, scope=plugin).
//   - DeriveScopeFromClientHeader() — maps an X-Axonflow-Client header value
//     to a scope (plugin/sdk/full). Per ADR-050 §4, absent or unrecognized
//     headers default to "full".
//   - SaaSPluginPathAcceptList — closed set of aud values the SaaS Plugin
//     path validator accepts.

// canonical aud values, day one (ADR-050 §1).
const (
	AudSaaSPlugin       = "axonflow.saas.plugin"
	AudSaaSSDK          = "axonflow.saas.sdk"
	AudSaaSFull         = "axonflow.saas.full"
	AudSelfHostedPlugin = "axonflow.self_hosted.plugin"
	AudSelfHostedSDK    = "axonflow.self_hosted.sdk"
	AudSelfHostedFull   = "axonflow.self_hosted.full"

	// AudLegacyPluginClaim is the W4-era plugin-claim aud, predating ADR-050's
	// six canonical values. New issuance uses AudSaaSPlugin; this constant
	// only exists so HasScope / accept-list checks stay compatible with
	// dormant W4 scaffolding tokens that may still be in flight.
	AudLegacyPluginClaim = "community_saas_plugin"
)

// hosting-mode + scope segments (ADR-050 §2).
const (
	HostingModeSaaS       = "saas"
	HostingModeSelfHosted = "self_hosted"

	ScopePlugin = "plugin"
	ScopeSDK    = "sdk"
	ScopeFull   = "full"
)

// SaaSPluginPathAcceptList is the closed set of aud values the SaaS Plugin
// path validator (validateCommunitySaasAuth) accepts. Anything else fails
// closed — see ADR-050 §3.
var SaaSPluginPathAcceptList = []string{
	AudSaaSPlugin,
	AudSaaSFull,
	AudLegacyPluginClaim, // backward compat for W4 scaffolding tokens
}

// IsSaaSPluginPathAud reports whether the aud is in the SaaS Plugin path
// accept list. Unknown / unset aud is rejected (caller must surface a 401
// with explicit reason).
func IsSaaSPluginPathAud(aud string) bool {
	for _, accepted := range SaaSPluginPathAcceptList {
		if aud == accepted {
			return true
		}
	}
	return false
}

// HostingMode returns the hosting-mode segment of the token's aud claim:
// "saas" or "self_hosted". Returns "" when the aud is unknown or unset.
//
// Per ADR-050 §8, missing-aud tokens fall back to self_hosted (the only
// quadrant they could plausibly belong to). Legacy W4 plugin-claim aud
// "community_saas_plugin" maps to "saas".
func (p *ServiceLicensePayload) HostingMode() string {
	if p.Aud == "" {
		return HostingModeSelfHosted
	}
	if p.Aud == AudLegacyPluginClaim {
		return HostingModeSaaS
	}
	parts := strings.SplitN(p.Aud, ".", 3)
	if len(parts) >= 2 && parts[0] == "axonflow" {
		switch parts[1] {
		case HostingModeSaaS, HostingModeSelfHosted:
			return parts[1]
		}
	}
	return ""
}

// HasScope reports whether the token's aud satisfies the requested scope.
// Per ADR-050 §2, "full" matches any query (full-scope tokens grant any
// scope). Plugin / sdk tokens match only their own scope.
//
// Tokens with aud="" (legacy self-hosted, predates ADR-050) are treated as
// full-scope per the §8 backward-compat rule — they were issued for
// self_hosted_full use and have no scope restriction.
//
// Tokens with the legacy W4 plugin-claim aud are treated as plugin-scope.
//
// Unknown / malformed aud values fail closed (return false).
func (p *ServiceLicensePayload) HasScope(scope string) bool {
	tokenScope := p.scopeSegment()
	if tokenScope == "" {
		return false
	}
	if tokenScope == ScopeFull {
		return true
	}
	return tokenScope == scope
}

// scopeSegment extracts the scope segment from the aud claim. Returns "" for
// unknown / malformed values so the caller can fail closed.
func (p *ServiceLicensePayload) scopeSegment() string {
	if p.Aud == "" {
		// ADR-050 §8: missing-aud tokens fall back to self_hosted_full.
		return ScopeFull
	}
	if p.Aud == AudLegacyPluginClaim {
		return ScopePlugin
	}
	parts := strings.SplitN(p.Aud, ".", 3)
	if len(parts) == 3 && parts[0] == "axonflow" {
		switch parts[2] {
		case ScopePlugin, ScopeSDK, ScopeFull:
			return parts[2]
		}
	}
	return ""
}

// DeriveScopeFromClientHeader maps an X-Axonflow-Client header value to a
// scope (plugin / sdk / full). Per ADR-050 §4:
//
//   - Absent or empty header → "full" (a caller hitting raw HTTP without
//     identification is by construction a sophisticated user with a
//     full-scope license; a plugin-only token hitting raw HTTP would
//     correctly reject downstream).
//   - "openclaw/<v>", "<name>-plugin/<v>" → plugin
//   - "sdk-<lang>/<v>" → sdk
//   - Anything else → full (forward compatible — agent doesn't know about
//     future client identities; downstream aud check is the actual
//     enforcement).
func DeriveScopeFromClientHeader(header string) string {
	if header == "" {
		return ScopeFull
	}
	clientID := header
	if slash := strings.IndexByte(header, '/'); slash >= 0 {
		clientID = header[:slash]
	}
	if clientID == "openclaw" || strings.HasSuffix(clientID, "-plugin") {
		return ScopePlugin
	}
	if strings.HasPrefix(clientID, "sdk-") {
		return ScopeSDK
	}
	return ScopeFull
}

const (
	SelfHostedCapabilityGrantVersion = "1.0"
	FinCrimeCapabilityVersion        = "1.0"
	FinCrimeScoreRequestsPeriod      = "calendar_month"
	OutcomeCapabilityVersion         = "1.0"
	OutcomeCasesPeriod               = "calendar_month"
)

type SelfHostedCapabilityClaim struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type SelfHostedLimitClaim struct {
	ID        string `json:"id"`
	Period    string `json:"period"`
	Allowance int64  `json:"allowance"`
}

// SelfHostedCapabilityGrant is part of the signed service-license payload.
// Repeating DeploymentID inside the grant makes extracted grants unusable in
// another deployment; TenantID is the exact customer tenant it may serve.
type SelfHostedCapabilityGrant struct {
	Version      string                      `json:"version"`
	DeploymentID string                      `json:"deployment_id"`
	TenantID     string                      `json:"tenant_id"`
	Module       string                      `json:"module"`
	Capabilities []SelfHostedCapabilityClaim `json:"capabilities"`
	Limits       []SelfHostedLimitClaim      `json:"limits"`
}

type FinCrimeSelfHostedLicenseInput struct {
	Tier          Tier
	DeploymentID  string
	TenantID      string
	ServiceName   string
	ServiceType   string
	Permissions   []string
	ValidityDays  int
	Audience      string
	ScoreRequests int64
}

// OutcomeModuleGrantInput describes one independently purchasable outcome
// module. Module must be payment_exception or support_refund.
type OutcomeModuleGrantInput struct {
	Module        string
	CaseAllowance int64
}

// OutcomeSelfHostedLicenseInput mints one signed service license containing
// one or both independent outcome-module grants.
type OutcomeSelfHostedLicenseInput struct {
	Tier         Tier
	DeploymentID string
	TenantID     string
	ServiceName  string
	ServiceType  string
	Permissions  []string
	ValidityDays int
	Audience     string
	Modules      []OutcomeModuleGrantInput
	// FinCrimeScoreRequests optionally includes the independently licensed
	// FinCrime grant in the same signed deployment license.
	FinCrimeScoreRequests int64
}

func newFinCrimeSelfHostedGrant(deploymentID, tenantID string, scoreRequests int64) (SelfHostedCapabilityGrant, error) {
	grant := SelfHostedCapabilityGrant{
		Version:      SelfHostedCapabilityGrantVersion,
		DeploymentID: deploymentID,
		TenantID:     tenantID,
		Module:       capabilityresolution.FinCrimeModuleID,
		Capabilities: []SelfHostedCapabilityClaim{
			{ID: capabilityresolution.FinCrimePolicyPackCapabilityID, Version: FinCrimeCapabilityVersion},
			{ID: capabilityresolution.FinCrimeRiskScoringCapabilityID, Version: FinCrimeCapabilityVersion},
		},
		Limits: []SelfHostedLimitClaim{{
			ID:        capabilityresolution.FinCrimeScoreRequestsLimitID,
			Period:    FinCrimeScoreRequestsPeriod,
			Allowance: scoreRequests,
		}},
	}
	if err := validateSelfHostedCapabilityGrant(grant, deploymentID); err != nil {
		return SelfHostedCapabilityGrant{}, err
	}
	return grant, nil
}

func newOutcomeSelfHostedGrant(deploymentID, tenantID string, in OutcomeModuleGrantInput) (SelfHostedCapabilityGrant, error) {
	capabilityID, limitID, ok := outcomeModuleVocabulary(in.Module)
	if !ok {
		return SelfHostedCapabilityGrant{}, fmt.Errorf("unknown self-hosted capability module %q", in.Module)
	}
	grant := SelfHostedCapabilityGrant{
		Version:      SelfHostedCapabilityGrantVersion,
		DeploymentID: deploymentID,
		TenantID:     tenantID,
		Module:       in.Module,
		Capabilities: []SelfHostedCapabilityClaim{{ID: capabilityID, Version: OutcomeCapabilityVersion}},
		Limits: []SelfHostedLimitClaim{{
			ID:        limitID,
			Period:    OutcomeCasesPeriod,
			Allowance: in.CaseAllowance,
		}},
	}
	if err := validateSelfHostedCapabilityGrant(grant, deploymentID); err != nil {
		return SelfHostedCapabilityGrant{}, err
	}
	return grant, nil
}

// validateSelfHostedCapabilityGrants runs only after signature verification.
// An absent field is the legacy-compatible no-grant state; once present, its
// vocabulary is closed and any ambiguity refuses the whole license.
func validateSelfHostedCapabilityGrants(payload *ServiceLicensePayload, tier Tier) error {
	if len(payload.SelfHostedCapabilityGrants) == 0 {
		return nil
	}
	if !IsPaidTier(tier) {
		return fmt.Errorf("self-hosted capability grants require a paid license tier; %s is not eligible", tier)
	}
	if payload.Aud == "" || payload.HostingMode() != HostingModeSelfHosted {
		return fmt.Errorf("self-hosted capability grants require an explicit self-hosted audience")
	}
	if strings.TrimSpace(payload.DeploymentID) == "" || payload.DeploymentID != strings.TrimSpace(payload.DeploymentID) {
		return fmt.Errorf("self-hosted capability grants require an explicit canonical deployment_id")
	}
	seenScopes := make(map[string]struct{}, len(payload.SelfHostedCapabilityGrants))
	for _, grant := range payload.SelfHostedCapabilityGrants {
		if err := validateSelfHostedCapabilityGrant(grant, payload.DeploymentID); err != nil {
			return err
		}
		scope := grant.TenantID + "\x00" + grant.Module
		if _, exists := seenScopes[scope]; exists {
			return fmt.Errorf("duplicate self-hosted capability grant for tenant %q and module %q", grant.TenantID, grant.Module)
		}
		seenScopes[scope] = struct{}{}
	}
	return nil
}

func validateSelfHostedCapabilityGrant(grant SelfHostedCapabilityGrant, deploymentID string) error {
	if grant.Version != SelfHostedCapabilityGrantVersion {
		return fmt.Errorf("unknown self-hosted capability grant version %q", grant.Version)
	}
	if grant.DeploymentID == "" || grant.DeploymentID != deploymentID {
		return fmt.Errorf("self-hosted capability grant deployment scope does not match its license")
	}
	if strings.TrimSpace(grant.TenantID) == "" || grant.TenantID != strings.TrimSpace(grant.TenantID) {
		return fmt.Errorf("self-hosted capability grant has an invalid tenant scope")
	}
	if grant.Module == capabilityresolution.FinCrimeModuleID {
		return validateFinCrimeSelfHostedCapabilityGrant(grant)
	}
	return validateOutcomeSelfHostedCapabilityGrant(grant)
}

func validateFinCrimeSelfHostedCapabilityGrant(grant SelfHostedCapabilityGrant) error {
	if len(grant.Capabilities) == 0 {
		return fmt.Errorf("self-hosted FinCrime grant has no capabilities")
	}
	seenCapabilities := make(map[string]struct{}, len(grant.Capabilities))
	hasPolicyPack, hasRiskScoring := false, false
	for _, capability := range grant.Capabilities {
		switch capability.ID {
		case capabilityresolution.FinCrimePolicyPackCapabilityID:
			hasPolicyPack = true
		case capabilityresolution.FinCrimeRiskScoringCapabilityID:
			hasRiskScoring = true
		default:
			return fmt.Errorf("unknown self-hosted FinCrime capability %q", capability.ID)
		}
		if capability.Version != FinCrimeCapabilityVersion {
			return fmt.Errorf("unknown version %q for self-hosted FinCrime capability %q", capability.Version, capability.ID)
		}
		if _, exists := seenCapabilities[capability.ID]; exists {
			return fmt.Errorf("duplicate self-hosted FinCrime capability %q", capability.ID)
		}
		seenCapabilities[capability.ID] = struct{}{}
	}
	if !hasPolicyPack {
		return fmt.Errorf("self-hosted FinCrime grant is missing %q", capabilityresolution.FinCrimePolicyPackCapabilityID)
	}
	if !hasRiskScoring {
		return fmt.Errorf("self-hosted FinCrime grant is missing %q", capabilityresolution.FinCrimeRiskScoringCapabilityID)
	}
	if len(grant.Limits) != 1 {
		return fmt.Errorf("self-hosted FinCrime scoring requires exactly one score-request allowance")
	}
	limit := grant.Limits[0]
	if limit.ID != capabilityresolution.FinCrimeScoreRequestsLimitID {
		return fmt.Errorf("unknown self-hosted FinCrime limit %q", limit.ID)
	}
	if limit.Period != FinCrimeScoreRequestsPeriod {
		return fmt.Errorf("unknown self-hosted FinCrime score-request period %q", limit.Period)
	}
	if limit.Allowance <= 0 {
		return fmt.Errorf("self-hosted FinCrime score-request allowance must be finite and positive")
	}
	return nil
}

func validateOutcomeSelfHostedCapabilityGrant(grant SelfHostedCapabilityGrant) error {
	capabilityID, limitID, ok := outcomeModuleVocabulary(grant.Module)
	if !ok {
		return fmt.Errorf("unknown self-hosted capability module %q", grant.Module)
	}
	if len(grant.Capabilities) != 1 {
		return fmt.Errorf("self-hosted %s grant requires exactly one workflow capability", grant.Module)
	}
	capability := grant.Capabilities[0]
	if capability.ID != capabilityID {
		return fmt.Errorf("unknown self-hosted %s capability %q", grant.Module, capability.ID)
	}
	if capability.Version != OutcomeCapabilityVersion {
		return fmt.Errorf("unknown version %q for self-hosted %s capability %q", capability.Version, grant.Module, capability.ID)
	}
	if len(grant.Limits) != 1 {
		return fmt.Errorf("self-hosted %s requires exactly one case allowance", grant.Module)
	}
	limit := grant.Limits[0]
	if limit.ID != limitID {
		return fmt.Errorf("unknown self-hosted %s limit %q", grant.Module, limit.ID)
	}
	if limit.Period != OutcomeCasesPeriod {
		return fmt.Errorf("unknown self-hosted %s case period %q", grant.Module, limit.Period)
	}
	if limit.Allowance <= 0 {
		return fmt.Errorf("self-hosted %s case allowance must be finite and positive", grant.Module)
	}
	return nil
}

func outcomeModuleVocabulary(module string) (capabilityID, limitID string, ok bool) {
	switch module {
	case capabilityresolution.PaymentExceptionModuleID:
		return capabilityresolution.PaymentExceptionWorkflowCapabilityID, capabilityresolution.PaymentExceptionCasesLimitID, true
	case capabilityresolution.SupportRefundModuleID:
		return capabilityresolution.SupportRefundWorkflowCapabilityID, capabilityresolution.SupportRefundCasesLimitID, true
	default:
		return "", "", false
	}
}

// FinCrimeScoreRequestAllowance returns authority only for an exact tenant and
// deployment match. A manually constructed or malformed result grants none.
func (r *ValidationResult) FinCrimeScoreRequestAllowance(tenantID string) (int64, bool) {
	if r == nil || !r.Valid || tenantID == "" || !IsPaidTier(r.Tier) {
		return 0, false
	}
	for _, grant := range r.selfHostedCapabilityGrants {
		if grant.Module != capabilityresolution.FinCrimeModuleID || grant.TenantID != tenantID || grant.DeploymentID != r.LicenseDeploymentID() {
			continue
		}
		if err := validateSelfHostedCapabilityGrant(grant, r.LicenseDeploymentID()); err != nil {
			continue
		}
		return grant.Limits[0].Allowance, true
	}
	return 0, false
}

// OutcomeCaseAllowance returns authority only for an exact tenant, deployment,
// and independent module match. The requested module comes from the trusted
// operation route, never from a caller-provided entitlement assertion.
func (r *ValidationResult) OutcomeCaseAllowance(module, tenantID string) (int64, bool) {
	if r == nil || !r.Valid || tenantID == "" || !IsPaidTier(r.Tier) {
		return 0, false
	}
	if _, _, ok := outcomeModuleVocabulary(module); !ok {
		return 0, false
	}
	for _, grant := range r.selfHostedCapabilityGrants {
		if grant.Module != module || grant.TenantID != tenantID || grant.DeploymentID != r.LicenseDeploymentID() {
			continue
		}
		if err := validateSelfHostedCapabilityGrant(grant, r.LicenseDeploymentID()); err != nil {
			continue
		}
		return grant.Limits[0].Allowance, true
	}
	return 0, false
}
