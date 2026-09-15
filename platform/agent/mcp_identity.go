// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"


	"axonflow/platform/shared/deploymode"
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
		// #3550: record that a deny-list WAS wired, so the built-in minted
		// realm declares RevocationSourceLocalStore rather than the positive
		// "this realm has no revocation channel". The fact is taken from the
		// constructor succeeding, not from configuration, because those two
		// disagree exactly when the constructor failed.
		noteIdentityWiring(rev, nil, false)
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
		// #3550: a SCIM-backed directory IS wired, so the realms that can
		// carry one declare DirectorySourceSCIM. Declaring None here would
		// make an empty group closure authoritative (EX-45) for a deployment
		// that actually has a directory.
		noteIdentityWiring(nil, nil, true)
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
	if cfgErr == nil {
		// #3550: the tenant OIDC realm is derived from this same provider, so
		// EX-47 is real on that path without a second configuration surface:
		// an org with no enabled OIDC row declares no OIDC realm, and a
		// validly signed IdP token from it is UNKNOWN_REALM.
		noteIdentityWiring(nil, cfg, false)
	}

	// Session ADR65-I / #3602: the per-organization identity settings store.
	// Extracted so the schema gate has a call site a test can reach - see
	// wireOrgIdentitySettings.
	wireOrgIdentitySettings(db)

	// Whether this process can host a Shared Signals receiver, derived from
	// what was actually wired above. Must run AFTER the three constructors.
	noteIdentityCAEPReceivable(attrsErr == nil)
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

// --- #2989 (ADR-060) / #3473: fleet-plane segment resolution wiring ---
//
// The fleet/MCP-server plane has exactly ONE user->segments lookup
// (resolveUserSegments, segment_policy_gate.go), fail-closed, called from one
// place since #4253 removed the other:
//   - authenticateMCPSession (below) calls it once per resolved auth (once
//     per REQUEST for the stateless/hook-path callers that send no
//     Mcp-Session-Id — see segmentResolutionPhase's doc,
//     segment_resolution_metrics.go — not reliably once per session), purely
//     so the resolution outcome stays OBSERVABLE ("session_auth" phase) -
//     its return value is discarded, so a resolution error there denies
//     nothing and downgrades nothing.
//   - Until #4253, the /api/request proxy's segment gate (run.go) called it
//     on the policy-affecting path and acted on the result. The MCP-server
//     plane's own policy-affecting call went with its segment gate in v11:
//     the anchored engine authors check_policy's and check_output's verdicts
//     and reads no segments (PRD v11 §1.1, §1.2).
//
// Before #3473 these were two DIFFERENT functions with opposite error
// contracts (this file's own former resolveUserSegments swallowed an error
// into "nil, no decision"; segment_policy_gate.go's resolveSegmentsForPolicy
// denied on one). They were collapsed because they were never answering a
// different question - only the caller's use of the answer differed, which
// is exactly what a `(segmentIDs, ok)` return plus "does this caller check
// ok" already expresses without a second function.

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

// resolveUserSegments itself now lives in segment_policy_gate.go (#3473
// collapsed it with what used to be this file's own P2-era implementation);
// see that file's doc for the merged function's contract.

// wireOrgIdentitySettings constructs the per-organization identity settings
// store and notes it, or explains why it did not.
//
// # WHY THIS IS ITS OWN FUNCTION
//
// It was inline in registerFleetValidators, which is guarded by a sync.Once
// and additionally builds a revocation store, a SCIM resolver and an OIDC
// config provider - so no test could drive the schema gate across deployment
// modes without a database and a fresh process. R3 round 1 on #3607 proved
// what that cost: replacing the gate with `if true` left every Go test green
// while reintroducing the live defect. A guard nothing can call is a guard
// nothing tests.
//
// # THE SCHEMA GATE IS DEPLOYMENT_MODE, NOT THE BUILD TAG
//
// identity_org_settings is created by migrations/enterprise/146, and the
// migration selector applies migrations/enterprise/ only for the in-vpc-* and
// saas modes (deploymode.CanonicalModes). The community-saas fleet runs THIS
// binary - enterprise-tagged, so the constructor succeeds - on the
// `community-saas` schema, where the table was never created. Without the gate
// the store was wired there and every organization's first read per TTL window
// failed, live, with `relation "identity_org_settings" does not exist`: noise
// on the authentication path, and a settings-read failure counted on a
// deployment that has no settings to read.
//
// A deployment that DOES apply the enterprise schema is unchanged: the store is
// wired exactly as before, and any construction failure other than
// ErrEnterpriseOnly is still FATAL, because a deployment whose table exists and
// whose store cannot be opened would silently decline every organization's
// Shared Signals opt-in while its records say otherwise.
//
// A nil db is "nothing to read", the posture every constructor in
// registerFleetValidators takes: run.go refuses to boot without DATABASE_URL
// long before this runs, so a nil db here is a test or a no-DB harness, never a
// deployment whose table exists.
func wireOrgIdentitySettings(db *sql.DB) {
	if db == nil {
		return
	}
	if !deploymode.AppliesEnterpriseSchema() {
		log.Printf("[IDENTITY] no per-organization identity settings store: DEPLOYMENT_MODE=%q does not apply migrations/%s/, so identity_org_settings cannot exist here and no organization has a Shared Signals opt-in",
			deploymode.Current(), deploymode.CategoryEnterprise)
		return
	}
	settings, err := sharedidentity.NewDBOrgIdentitySettingsStore(db, "agent")
	if err == nil {
		noteIdentityOrgSettingsWired(settings)
		return
	}
	if !errors.Is(err, sharedidentity.ErrEnterpriseOnly) {
		log.Fatalf("❌ identity: per-organization settings store could not be built: %v", err)
	}
}
