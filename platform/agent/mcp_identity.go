// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Fleet-plane per-user identity wiring (epic #2919, issues #2920 + #2924).
//
// The pluggable identity foundation lives in platform/shared/identity (the
// #2924 validator suite + the #2920 ResolveToken seam). This file only:
//   - extracts the per-user token off the request,
//   - registers the process-wide validators (HS256 Path A + OIDC Path B) once,
//   - lets authenticateMCPServerRequest resolve a validated {email, role}.
//
// The concrete validators are Enterprise-only (the constructors return
// ErrEnterpriseOnly in a community build); registration silently skips them
// there, so the fleet plane compiles and runs in both editions and a community
// caller carrying a token simply resolves to least-privilege.

// fleetValidatorsOnce guards the process-wide validator registration so the
// registry is populated exactly once, on the first enterprise-mode MCP request
// (usageDB + jwtSecret are wired by then).
var fleetValidatorsOnce sync.Once

// ensureFleetValidatorsRegistered registers the per-user token validators into
// the shared registry the resolver iterates. Enterprise build: HS256 (Path A,
// revocation-checked) + OIDC/JWKS (Path B, role from the SCIM directory).
// Community build: every constructor returns ErrEnterpriseOnly and nothing is
// registered — ResolveToken then treats any presented token as least-privilege.
//
// This is invoked deterministically at agent startup (run.go, right after
// usageDB + jwtSecret are wired) so registration NEVER depends on the timing of
// the first enterprise MCP request. The sync.Once still guards it so the
// belt-and-suspenders per-request calls are idempotent no-ops. The prior
// lazy-only form (#2932) could trip the Once on a first request that raced
// startup wiring, register nothing, and silently disable per-user authz for the
// whole process lifetime.
func ensureFleetValidatorsRegistered() {
	fleetValidatorsOnce.Do(registerFleetValidators)
}

// fleetValidatorWarnInterval rate-limits the "token presented but no validator
// registered" warning so a busy fleet cannot flood the log while still keeping
// a persistent misconfig observable.
const fleetValidatorWarnInterval = 5 * time.Minute

var (
	fleetValidatorWarnMu   sync.Mutex
	fleetValidatorWarnedAt time.Time
	fleetValidatorWarnNow  = time.Now // overridable in tests
)

// warnPerUserTokenWithoutValidator emits a rate-limited WARN when a caller
// presents a per-user token but the process has NO registered validator to
// check it against (#2932). With deterministic startup registration in place
// this only fires on a genuine misconfiguration — e.g. JWT_SECRET unset so
// Path A did not register and the org has no OIDC config — turning what was a
// silent least-privilege downgrade into an observable operational signal. It
// never changes behavior: the token is still ignored (least-privilege), never
// elevated.
func warnPerUserTokenWithoutValidator() {
	fleetValidatorWarnMu.Lock()
	defer fleetValidatorWarnMu.Unlock()
	now := fleetValidatorWarnNow()
	if !fleetValidatorWarnedAt.IsZero() && now.Sub(fleetValidatorWarnedAt) < fleetValidatorWarnInterval {
		return
	}
	fleetValidatorWarnedAt = now
	log.Printf("⚠️ [MCP-Server] per-user token presented but NO validator is registered — " +
		"the token is IGNORED (least-privilege attribution only). Per-user authz is DISABLED " +
		"until a validator registers; check JWT_SECRET / tenant OIDC config (#2932).")
}

// warnIfTokenWithoutValidator emits the #2932 misconfig warning when a per-user
// token is present but no validator is registered. Centralizes the check for
// the MCP-server and proxied-REST resolve sites.
func warnIfTokenWithoutValidator(perUserToken string) {
	if perUserToken != "" && !sharedidentity.HasRegisteredValidators() {
		warnPerUserTokenWithoutValidator()
	}
}

func registerFleetValidators() {
	db := usageDB

	// Path A — AxonFlow-minted HS256 per-user tokens, revocation-checked.
	if rev, err := sharedidentity.NewDBRevocationStore(db); err == nil {
		if v, verr := sharedidentity.NewHS256Validator(jwtSecret, rev); verr == nil {
			if regErr := sharedidentity.RegisterValidator(v); regErr != nil {
				log.Printf("[MCP-Server] HS256 validator not registered: %v", regErr)
			}
		} else if !errors.Is(verr, sharedidentity.ErrEnterpriseOnly) {
			log.Printf("[MCP-Server] HS256 per-user token validator unavailable: %v", verr)
		}
	} else if !errors.Is(err, sharedidentity.ErrEnterpriseOnly) {
		log.Printf("[MCP-Server] per-user token revocation store unavailable: %v", err)
	}

	// #2989 (ADR-060 P2): the shared IdentityAttributeResolver also resolves
	// governance Segments (SCIM group membership), independent of whether an
	// OIDC config exists — wire it process-wide so BOTH Path A (HS256) and
	// Path B (OIDC) can resolve segments for a validated per-user identity
	// (fleetSegmentResolver below), not only Path B. A resolver-construction
	// failure other than ErrEnterpriseOnly is logged; segment resolution then
	// simply stays unavailable (resolveUserSegments returns nil) — role
	// resolution and per-user auth are NOT gated on this.
	attrs, attrsErr := sharedidentity.NewIdentityAttributeResolver(db)
	if attrsErr == nil {
		setFleetSegmentResolver(attrs)
	} else if !errors.Is(attrsErr, sharedidentity.ErrEnterpriseOnly) {
		log.Printf("[MCP-Server] identity attribute resolver unavailable: %v", attrsErr)
	}

	// Path B — IdP-issued OIDC/JWKS tokens, role resolved from the SCIM-synced
	// directory (never the token's own role claim). #2989 (ADR-060 P1): the
	// role resolver is now reached through the shared IdentityAttributeResolver
	// seam rather than NewSCIMRoleResolver directly — IdentityAttributeResolver
	// embeds RoleResolver, so it satisfies NewOIDCVerifier's dependency
	// unmodified, and the role logic it delegates to is byte-for-byte the same
	// scimRoleResolver as before this change.
	cfg, cfgErr := sharedidentity.NewDBOIDCConfigProvider(db)
	if cfgErr == nil && attrsErr == nil {
		if v, verr := sharedidentity.NewOIDCVerifier(cfg, attrs); verr == nil {
			if regErr := sharedidentity.RegisterValidator(v); regErr != nil {
				log.Printf("[MCP-Server] OIDC validator not registered: %v", regErr)
			}
		} else if !errors.Is(verr, sharedidentity.ErrEnterpriseOnly) {
			log.Printf("[MCP-Server] OIDC per-user token validator unavailable: %v", verr)
		}
	} else if cfgErr != nil && !errors.Is(cfgErr, sharedidentity.ErrEnterpriseOnly) {
		log.Printf("[MCP-Server] OIDC config provider unavailable: %v", cfgErr)
	}
}

// sessionCanReadTenant reports whether this MCP session may read tenant-wide
// (cross-user) rows (#2922): a validated admin/owner/policy_admin role (#2993),
// or a Community-mode deployment (single-operator, no fleet — mirrors the
// orchestrator's resolveCallerReadScope Community posture so the two planes
// agree). Every other session — shared-credential, trust-gated header identity,
// developer/viewer tokens — reads own-rows only.
func sessionCanReadTenant(s *mcpSession) bool {
	if isCommunityMode() {
		return true
	}
	return sharedidentity.RoleCanReadTenant(s.userRole)
}

// extractPerUserToken pulls the per-user token off the request. The MCP-server
// plane authenticates the TENANT with HTTP Basic in Authorization, so the
// per-user token travels in X-User-Token; a Bearer Authorization is also
// accepted for deployments that authenticate the tenant out-of-band. Returns
// "" when no per-user token is present (the legacy shared-credential path).
func extractPerUserToken(r *http.Request) string {
	if t := strings.TrimSpace(r.Header.Get("X-User-Token")); t != "" {
		return t
	}
	// Authorization: Bearer <token>. When Authorization holds Basic tenant
	// credentials this prefix-check yields "" (no false positive).
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	const bearer = "Bearer "
	if len(auth) > len(bearer) && strings.EqualFold(auth[:len(bearer)], bearer) {
		return strings.TrimSpace(auth[len(bearer):])
	}
	return ""
}

// --- #2989 (ADR-060 Phase 2): fleet-plane segment resolution wiring ---
//
// Segments become resolved + OBSERVABLE this phase; they are deliberately
// NOT consumed for any policy decision (P3) and NOT written to the audit row
// (P5) here — see resolveUserSegments below.

// fleetSegmentResolver is the process-wide shared IdentityAttributeResolver
// used to resolve segments for a validated per-user identity, wired once at
// startup by registerFleetValidators (guarded by fleetValidatorsOnce, same
// as the token validators). nil in community builds / when construction
// fails (ErrEnterpriseOnly or a DB problem) — resolveUserSegments treats nil
// as "capability unavailable", never an error.
var (
	fleetSegmentResolverMu sync.RWMutex
	fleetSegmentResolver   sharedidentity.IdentityAttributeResolver
)

func setFleetSegmentResolver(r sharedidentity.IdentityAttributeResolver) {
	fleetSegmentResolverMu.Lock()
	fleetSegmentResolver = r
	fleetSegmentResolverMu.Unlock()
}

func getFleetSegmentResolver() sharedidentity.IdentityAttributeResolver {
	fleetSegmentResolverMu.RLock()
	defer fleetSegmentResolverMu.RUnlock()
	return fleetSegmentResolver
}

// ResetFleetSegmentResolverForTest clears the wired resolver. Test-only.
func ResetFleetSegmentResolverForTest() {
	setFleetSegmentResolver(nil)
}

// resolveUserSegments resolves the ADR-060 (#2989) governance-segment set
// for an ALREADY-VALIDATED per-user identity (orgID/email come from a
// successful Path A or Path B TokenValidator result — see
// authenticateMCPServerRequest in mcp_server_handler.go) and makes the
// outcome observable (log + Prometheus: the resolved set, latency, and
// error-vs-empty).
//
// Real-World-Path (#2989 constraint, coordinated with — and not duplicating
// — #2948): this MUST be called only for a validated identity, never on an
// absent or rejected token. #2948 owns making an absent/invalid user_token
// itself reject observably; this function's job starts only after that has
// already happened successfully. Callers must not invoke this on a
// ResolveToken error or a "" token.
//
// A resolution ERROR here does NOT reject the request or downgrade the
// caller's role/identity — Segments are observability-only in this phase
// (not consumed for policy, per DoD). It returns nil on any unavailability
// or error, logging + counting the outcome either way, so an operator can
// see the gap without the fleet plane's availability depending on it.
func resolveUserSegments(ctx context.Context, orgID, email string) []sharedidentity.Segment {
	resolver := getFleetSegmentResolver()
	if resolver == nil {
		return nil // community build, or resolver construction unavailable
	}
	start := time.Now()
	resolved, err := resolver.Resolve(ctx, orgID, email)
	latency := time.Since(start)
	if err != nil {
		segmentResolutionTotal.WithLabelValues("error").Inc()
		log.Printf("[Identity] WARNING: #2989 segment resolution failed org=%q latency=%s: %v", orgID, latency, err)
		return nil
	}
	segmentResolutionDurationSeconds.Observe(latency.Seconds())
	if len(resolved.Segments) == 0 {
		segmentResolutionTotal.WithLabelValues("empty").Inc()
		log.Printf("[Identity] #2989 segments resolved org=%q count=0 latency=%s", orgID, latency)
		return nil
	}
	segmentResolutionTotal.WithLabelValues("resolved").Inc()
	ids := make([]string, len(resolved.Segments))
	for i, s := range resolved.Segments {
		ids[i] = string(s.ID)
	}
	log.Printf("[Identity] #2989 segments resolved org=%q count=%d segments=%v latency=%s", orgID, len(resolved.Segments), ids, latency)
	return resolved.Segments
}
