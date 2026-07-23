//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
)

// SegmentID identifies a governance segment (ADR-060 #2989) — a SCIM group
// used as a data-plane policy-targeting dimension. Phase 1 (this file) ships
// no segment resolution: IdentityAttributeResolver.Resolve always returns a
// nil Segments. Segment membership resolution (scim_users -> scim_group_
// members -> scim_groups) lands in Phase 2.
type SegmentID string

// ResolvedIdentity is the outcome of resolving a verified identity's
// governance-relevant attributes: the platform-authorization Role AND the
// data-plane policy-targeting Segments.
//
// Segments is the APPLICABLE SET — a user may belong to several segments —
// never collapsed to a single "deciding" segment here. Deriving the one
// binding/effective segment from a multi-segment set is a downstream
// combining/audit concern (ADR-060 Phase 3 combiner, Phase 5 audit
// attribution), never the resolver's job. Keep this field plural.
type ResolvedIdentity struct {
	// Role is the effective platform-authorization role, resolved by
	// exactly the same logic as scimRoleResolver.ResolveRole (delegated,
	// unchanged): strongest-wins precedence for AxonFlow's own control plane
	// (audit reads, config, etc).
	Role string
	// Segments is the governance-policy-targeting set (ADR-060), sourced
	// from SCIM group membership. Always nil in Phase 1 — the no-op stub.
	// When Phase 2 fills it, the combining semantics are most-restrictive-
	// wins (deny-overrides) — the OPPOSITE of Role's strongest-wins. The two
	// combining algorithms are deliberately NOT unified: see ADR-060
	// §"Role and segment: one substrate, opposite semantics."
	Segments []SegmentID
}

// IdentityAttributeResolver resolves a verified identity (an already-
// authenticated org + canonical email) to its governance-relevant
// attributes: Role (platform authorization) and Segments (data-plane policy
// targeting). Both are verified server-side facts sourced from the
// SCIM-synced directory, never a token claim — the same trust model
// #2919/#2924 already established for role resolution.
//
// Role and segment are the SAME kind of fact — a verified attribute resolved
// from SCIM — and this is why they share one fetch/cache/wiring seam
// (ADR-060 Decision 6): a single org-scoped, SCIM-backed lookup produces
// both. They are NOT combined the same way, and that is intentional:
//   - Role is strongest-wins (owner > admin > policy_admin > developer >
//     viewer, plus the wildcard/admin short-circuit) for platform
//     authorization over AxonFlow's own control plane.
//   - Segments (once Phase 2 populates it) is most-restrictive-wins
//     (deny-overrides) for data-plane governance-policy targeting.
//
// That combining logic lives downstream of this resolver, never inside it —
// do not add a "collapse Segments to one" helper here; see ADR-060
// §"Role and segment: one substrate, opposite semantics."
//
// IdentityAttributeResolver embeds RoleResolver so a resolver value can be
// used directly wherever a RoleResolver is expected (e.g. NewOIDCVerifier's
// RoleResolver dependency) without a separate adapter.
type IdentityAttributeResolver interface {
	RoleResolver
	// Resolve returns the caller's effective Role and applicable Segments
	// for orgID/email. Fails closed: any storage failure or malformed input
	// (empty org, empty email) is an error, never a partially-populated
	// identity — the same contract as RoleResolver.ResolveRole.
	Resolve(ctx context.Context, orgID, email string) (ResolvedIdentity, error)
}

// identityAttributeResolver is the enterprise IdentityAttributeResolver.
// Role resolution DELEGATES to the existing, unchanged scimRoleResolver
// (same role_assignments query, same precedence collapse) — this seam
// extraction moves no role logic, it only adds a shared entry point in
// front of it. Segments is the Phase 1 no-op stub.
type identityAttributeResolver struct {
	roles RoleResolver
}

// NewIdentityAttributeResolver builds the combined resolver over the shared
// platform database. It wraps NewSCIMRoleResolver's unchanged role-directory
// logic (role_assignments join custom_roles, FORCE-RLS org-scoped) and adds
// the (Phase-1-empty) Segments field alongside it.
func NewIdentityAttributeResolver(db *sql.DB) (IdentityAttributeResolver, error) {
	roles, err := NewSCIMRoleResolver(db)
	if err != nil {
		return nil, err
	}
	return &identityAttributeResolver{roles: roles}, nil
}

// Resolve returns {Role, Segments} for orgID/email. Role is exactly
// scimRoleResolver.ResolveRole's output (delegated, unchanged); Segments is
// always nil (Phase 1 no-op stub — filled in Phase 2).
func (r *identityAttributeResolver) Resolve(ctx context.Context, orgID, email string) (ResolvedIdentity, error) {
	role, err := r.roles.ResolveRole(ctx, orgID, email)
	if err != nil {
		return ResolvedIdentity{}, err
	}
	return ResolvedIdentity{Role: role, Segments: nil}, nil
}

// ResolveRole satisfies RoleResolver directly on the combined resolver, so
// existing RoleResolver-typed dependencies (NewOIDCVerifier) can take an
// IdentityAttributeResolver value unmodified. Delegates to the exact same
// unchanged logic behind Resolve's Role field — never a second code path.
func (r *identityAttributeResolver) ResolveRole(ctx context.Context, orgID, email string) (string, error) {
	return r.roles.ResolveRole(ctx, orgID, email)
}
