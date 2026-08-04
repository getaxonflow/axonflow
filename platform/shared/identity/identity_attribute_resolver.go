//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"database/sql"
	"fmt"
)

// SegmentID identifies a governance segment (ADR-060 #2989): the STABLE
// scim_groups.id of the backing SCIM group (never scim_groups.display_name,
// which an admin can rename — a rename must not silently re-target every
// policy authored against the old identifier). This is the cross-phase
// contract P3 (policy targeting) and P6 (portal write path) key on.
type SegmentID string

// Segment is one resolved governance segment: the stable SegmentID plus its
// human-readable DisplayName (scim_groups.display_name), carried alongside
// purely for observability / audit UIs / logs — never as a targeting key.
// P3/P6 key exclusively on ID; DisplayName is read-only convenience.
type Segment struct {
	ID          SegmentID
	DisplayName string
}

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
	// from SCIM group membership (scim_users -> scim_group_members ->
	// scim_groups), org-scoped. A user with no group memberships (or no
	// backing SCIM identity at all) resolves to an EMPTY, non-nil slice —
	// that is success, not an error; org/system-wide policy applies
	// downstream. The combining semantics (once P3 consumes this) are
	// most-restrictive-wins (deny-overrides) — the OPPOSITE of Role's
	// strongest-wins. The two combining algorithms are deliberately NOT
	// unified: see ADR-060 §"Role and segment: one substrate, opposite
	// semantics." NOT consumed for policy and NOT written to the audit row
	// in this phase (P2) — resolved and observable only; P3/P5 are separate,
	// later increments.
	Segments []Segment
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
//   - Segments is most-restrictive-wins (deny-overrides) for data-plane
//     governance-policy targeting.
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
	// InvalidateUserSegments drops any cached segment set for (orgID, email)
	// so the next Resolve re-reads SCIM group membership. Local to this
	// process only — there is no cross-service invalidation; propagation to
	// OTHER processes (e.g. a portal write reaching an agent replica) is
	// bounded by the cache TTL, never immediate. A no-op when segments were
	// never cached for that key.
	InvalidateUserSegments(orgID, email string)
}

// identityAttributeResolver is the enterprise IdentityAttributeResolver.
// Role resolution DELEGATES to the existing, unchanged scimRoleResolver
// (same role_assignments query, same precedence collapse) — this seam
// extraction moves no role logic, it only adds a shared entry point in
// front of it. Segments is resolved from SCIM group membership (P2), cached
// per (org, email) — see segment_cache.go.
type identityAttributeResolver struct {
	roles    RoleResolver
	segments *segmentCache
}

// NewIdentityAttributeResolver builds the combined resolver over the shared
// platform database. It wraps NewSCIMRoleResolver's unchanged role-directory
// logic (role_assignments join custom_roles, FORCE-RLS org-scoped) and adds
// a cached SCIM-group-membership Segments lookup alongside it (see
// segment_cache.go for the cache/TTL/invalidation contract).
func NewIdentityAttributeResolver(db *sql.DB) (IdentityAttributeResolver, error) {
	roles, err := NewSCIMRoleResolver(db)
	if err != nil {
		return nil, err
	}
	cache := newSegmentCache(&dbSegmentReader{db: db}, resolveSegmentCacheTTL())
	return &identityAttributeResolver{roles: roles, segments: cache}, nil
}

// Resolve returns {Role, Segments} for orgID/email.
//
// Role is exactly scimRoleResolver.ResolveRole's output (delegated,
// unchanged) — see that method's doc for the precedence rules.
//
// Segments is the applicable SCIM-group-membership set (scim_users(email) ->
// scim_group_members -> scim_groups), org-scoped via the same withOrgScope
// pattern as role resolution, and cached per (orgID, canonical email) with a
// clamped TTL (see segment_cache.go; default/bounds via
// EnvSegmentCacheTTLSeconds) — so a portal-side group-membership change
// becomes visible here within, at most, one cache TTL window on THIS
// process (no cross-process invalidation; see InvalidateUserSegments).
//
// Empty-vs-error contract (ADR-060, deliberate and security-relevant):
//   - Zero group memberships (including "no scim_users row for this email at
//     all") is SUCCESS: Resolve returns a non-nil, empty Segments slice and a
//     nil error. Org/system-wide policy applies downstream; this is not a
//     failure.
//   - Any error resolving Role OR Segments (a storage failure, a malformed
//     query, a schema/connection problem — anything short of "the query ran
//     and matched zero rows") is returned as a non-nil error and
//     ResolvedIdentity{} (the zero value) — Resolve NEVER returns a
//     partially-populated identity (e.g. a real Role paired with a
//     silently-emptied Segments after a Segments-query failure). A segment
//     lookup failure is never masked into a role-only success: the whole
//     call fails closed, exactly like RoleResolver.ResolveRole's existing
//     contract (empty org, empty email, or any storage error).
//
// SegmentID is the stable scim_groups.id (never display_name, which is
// admin-renamable); Segment additionally carries DisplayName for
// observability. See the Segment/SegmentID doc for the P3/P6 targeting
// contract.
func (r *identityAttributeResolver) Resolve(ctx context.Context, orgID, email string) (ResolvedIdentity, error) {
	role, err := r.roles.ResolveRole(ctx, orgID, email)
	if err != nil {
		return ResolvedIdentity{}, err
	}
	// ResolveRole already rejected an empty orgID/email above, so both are
	// guaranteed non-empty here; canonicalize email the same way role
	// resolution and every other identity consumer does (CanonicalEmail) so
	// the segment cache key and query match exactly what role resolution
	// keyed on.
	segments, err := r.segments.get(ctx, orgID, CanonicalEmail(email))
	if err != nil {
		// Do NOT mask a segment error into a role-only success (ADR-060,
		// R3-flagged risk): the whole Resolve call fails closed, discarding
		// the already-resolved role rather than returning a
		// partially-populated identity.
		return ResolvedIdentity{}, fmt.Errorf("identity: segment resolution failed: %w", err)
	}
	return ResolvedIdentity{Role: role, Segments: segments}, nil
}

// InvalidateUserSegments drops (orgID, email)'s cached segment set. See the
// interface doc: local to this process only, TTL-bounded elsewhere.
func (r *identityAttributeResolver) InvalidateUserSegments(orgID, email string) {
	r.segments.invalidate(orgID, CanonicalEmail(email))
}

// ResolveRole satisfies RoleResolver directly on the combined resolver, so
// existing RoleResolver-typed dependencies (NewOIDCVerifier) can take an
// IdentityAttributeResolver value unmodified. Delegates to the exact same
// unchanged logic behind Resolve's Role field — never a second code path.
func (r *identityAttributeResolver) ResolveRole(ctx context.Context, orgID, email string) (string, error) {
	return r.roles.ResolveRole(ctx, orgID, email)
}
