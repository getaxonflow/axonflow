// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import "strings"

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
