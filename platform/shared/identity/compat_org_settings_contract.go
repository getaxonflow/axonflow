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
	// DecisionShadowMode is the recorded per-plane PDP shadow mode (#3564,
	// session v10.3-A), meaningful only when HasDecisionShadowMode is true.
	//
	// IT IS A SECOND AXIS ON THE SAME ROW, NOT A SECOND SURFACE. The two modes
	// are independent - an operator shadows identity and decisions on
	// different schedules - but they are per-organization facts about the same
	// organization, read on the same TTL, through the same store, in ONE query.
	// A parallel settings table would have doubled the read cost on the
	// authentication path and given the two axes two different staleness
	// windows for no reason a reader could defend.
	//
	// Only off and shadow are storable: enforce is v11's, and the column's own
	// CHECK refuses it. The read side refuses it again (see
	// parseOrgSettingsRow) because a CHECK added by a migration is not evidence
	// about a row a different migration might yet write.
	DecisionShadowMode CompatMode
	// HasDecisionShadowMode reports whether a decision shadow mode is
	// recorded, for the reason HasCompatMode gives: "no record" must not be
	// spelled with a value that means "invalid record".
	HasDecisionShadowMode bool
	// DecisionShadowPlanesRaw is the organization's per-plane narrowing as
	// STORED, uninterpreted (#3552 gap 3).
	//
	// THIS PACKAGE DELIBERATELY DOES NOT PARSE IT. The vocabulary belongs to
	// planeshadow.ParsePlanes, and planeshadow imports THIS package - so the
	// parse cannot live here without a cycle. Carrying the raw string keeps
	// ONE parser in the tree: the settings writer validates with it, the
	// reader applies it, and identity stores a value it does not interpret.
	//
	// Empty means "no per-organization narrowing: every implemented plane",
	// which is also what a NULL column and a pre-153 database yield. The
	// column's CHECK refuses an empty or whitespace-only string precisely so
	// that NULL is the only encoding of that posture in storage.
	DecisionShadowPlanesRaw string
	// HasDecisionShadowPlanes reports whether a per-plane narrowing is
	// recorded. False means every implemented plane.
	HasDecisionShadowPlanes bool
	// DecisionShadowModeUnusable names why the stored decision mode could not
	// be used, and is empty when there was nothing wrong with it.
	//
	// # WHY A FIELD RATHER THAN AN ERROR FROM THE WHOLE READ
	//
	// The two modes are INDEPENDENT axes that happen to share a row, and a
	// failure on one must not decide the other. An earlier revision returned
	// an error from parseOrgSettingsRow for an unusable decision mode, which
	// failed the ENTIRE read - so OrgCompatMode errored too, and
	// CompatAdapter.effectiveMode falls back to the process mode on a read
	// error. A restore that wrote decision_shadow_mode='enforce' for one
	// organization would therefore have SILENTLY DOWNGRADED that
	// organization's identity-plane enforcement to the deployment's mode: a
	// fail-open on a shipped security axis, caused by a defect on a new
	// observability one.
	//
	// So the defect stays on its own axis. The identity mode and the CAEP
	// opt-in are returned as read; OrgDecisionShadowMode turns this field into
	// an error for ITS caller, which counts the fall-back and logs it.
	DecisionShadowModeUnusable string
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

// DecisionShadowModeSource answers "does this organization have a recorded
// per-plane PDP shadow mode, and what is it" (#3564, session v10.3-A).
//
// It is a SEPARATE interface from CompatOrgModeSource although one store
// implements both, so that the decision shadow depends on the question it
// asks rather than on the identity plane's adapter. The two axes are
// independent settings that happen to live on one row.
type DecisionShadowModeSource interface {
	// OrgDecisionShadowMode returns the organization's recorded shadow mode.
	//
	// The contract is CompatOrgModeSource's, verbatim: found=false with a nil
	// error is "no record, the process mode applies" and is the ordinary
	// answer; a non-nil error means the record could not be read and the
	// caller falls back to the process mode and counts the fall-back.
	OrgDecisionShadowMode(ctx context.Context, orgID string) (mode CompatMode, found bool, err error)
}

// DecisionShadowPlanesSource is the per-organization, per-plane narrowing
// (#3552 gap 3), read by the same store that answers DecisionShadowModeSource.
//
// A SEPARATE INTERFACE RATHER THAN A WIDENED METHOD, so a caller that only
// needs the mode is unaffected and no existing implementation breaks. The
// concrete store answers both from ONE cached row read, so asking for both
// costs one query, not two.
//
// The raw string is returned UNPARSED for the reason DecisionShadowPlanesRaw
// carries it: the vocabulary lives in planeshadow, which imports this package.
type DecisionShadowPlanesSource interface {
	// OrgDecisionShadowPlanes returns the organization's recorded plane
	// narrowing, uninterpreted.
	//
	// found=false with a nil error is "no narrowing recorded: every
	// implemented plane", and is the ordinary answer.
	OrgDecisionShadowPlanes(ctx context.Context, orgID string) (raw string, found bool, err error)
}

// OrgIdentitySettingsSource is what the Enterprise store implements: all FOUR
// read contracts plus the local invalidation hook the admin write path calls
// when it runs in the same process.
type OrgIdentitySettingsSource interface {
	CompatOrgModeSource
	CAEPOrgSettingsSource
	DecisionShadowModeSource
	DecisionShadowPlanesSource
	// Invalidate drops the memoized row for orgID so the next read consults
	// storage. Local to this process; the cross-process bound is the TTL.
	Invalidate(orgID string)
}
