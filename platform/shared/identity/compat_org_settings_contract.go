// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// The per-organization identity settings contract (#3550, session ADR65-I).
//
// This file is the edition-independent half: the types both binaries name
// whether or not the Enterprise store is compiled in. The store itself is
// compat_org_settings.go (enterprise) and the constructor's community
// counterpart returns ErrEnterpriseOnly, the same pattern NewOIDCRealmSource
// follows, so the agent and the orchestrator call one constructor and skip
// on that sentinel.
package identity

import "context"

// OrgIdentitySettings is one organization's recorded identity-plane settings:
// the per-organization compatibility mode and the OIDC realm's Shared
// Signals (CAEP) opt-in. Persisted by enterprise migration 146 and managed
// through the customer-portal admin API.
type OrgIdentitySettings struct {
	// OrgID is the organization. It is the row's key and is always the
	// AUTHENTICATED organization on the read side.
	OrgID string
	// CompatMode is the recorded compatibility mode, meaningful only when
	// HasCompatMode is true. A record may exist for CAEP alone and leave the
	// mode unset, in which case the process flag decides (compat_org_mode.go).
	CompatMode CompatMode
	// HasCompatMode reports whether a mode is recorded. It is a separate
	// boolean rather than a sentinel mode value because the zero value of
	// CompatMode is Unspecified, which is refused everywhere, and "no record"
	// must not be spelled with a value that means "invalid record".
	HasCompatMode bool
	// CAEPEnabled reports whether the organization's OIDC realm has opted into
	// an OpenID Shared Signals stream. It is honored only on a deployment
	// where a receiver is wired (BuiltinRealmDeployment.HasCAEP); on one where
	// none is, it is logged and the realm declares RevocationSourceNone.
	CAEPEnabled bool
	// CAEPAudience is the audience every SET on that stream must carry. It
	// is the receiver's identity as configured at the transmitter, and it is
	// required whenever CAEPEnabled is true (the migration's CHECK enforces
	// that too).
	CAEPAudience string
	// UpdatedBy and UpdatedAt are the audit trail the admin API stamps.
	UpdatedBy string
	UpdatedAt string
}

// CAEPOrgSettings is the subset the Shared Signals receiver and the OIDC
// realm derivation consume.
type CAEPOrgSettings struct {
	// Enabled reports the opt-in.
	Enabled bool
	// Audience is the required SET audience. Empty when not enabled.
	Audience string
}

// CAEPOrgSettingsSource answers the OIDC realm derivation's and the CAEP
// receiver's question: has this organization opted its realm into Shared
// Signals, and what audience must its events carry.
type CAEPOrgSettingsSource interface {
	// CAEPSettingsForOrg returns the opt-in. An organization with no record
	// returns Enabled=false and a nil error: not opting in is the ordinary
	// state, not a failure. A non-nil error means the record could not be
	// read; callers treat that as an outage, never as an opt-out.
	CAEPSettingsForOrg(ctx context.Context, orgID string) (CAEPOrgSettings, error)
}

// OIDCRealmSourceOption customizes the Enterprise OIDC realm source. Declared
// here, edition-independently and as an opaque value rather than a function
// over the enterprise-only source type, so the agent's wiring can construct
// one in both builds; the community NewOIDCRealmSource ignores it and returns
// ErrEnterpriseOnly.
type OIDCRealmSourceOption struct {
	caep CAEPOrgSettingsSource
}

// WithOIDCRealmCAEPSettings wires the per-organization Shared Signals opt-in
// into the OIDC realm derivation: the realm declares
// RevocationSourceSharedSignals only for an organization whose settings row
// opts in, on a deployment that wires a receiver.
func WithOIDCRealmCAEPSettings(src CAEPOrgSettingsSource) OIDCRealmSourceOption {
	return OIDCRealmSourceOption{caep: src}
}

// OrgIdentitySettingsSource is what the Enterprise store implements: both
// read contracts plus the local invalidation hook the admin write path calls
// when it runs in the same process.
type OrgIdentitySettingsSource interface {
	CompatOrgModeSource
	CAEPOrgSettingsSource
	// Invalidate drops the memoized row for orgID so the next read consults
	// storage. Local to this process; the cross-process bound is the TTL.
	Invalidate(orgID string)
}
