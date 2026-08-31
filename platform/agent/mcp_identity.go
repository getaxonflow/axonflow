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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
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
		noteIdentityCompatWiring(rev, nil, false)
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
		noteIdentityCompatWiring(nil, nil, true)
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
		noteIdentityCompatWiring(nil, cfg, false)
	}

	// Session ADR65-I: the per-organization identity settings store. It feeds
	// the adapter's per-org mode, the OIDC realm's Shared Signals opt-in and
	// the CAEP receiver's audience. ErrEnterpriseOnly is skipped like every
	// other Enterprise capability here; any other failure is FATAL, because a
	// deployment whose table exists and whose store cannot be opened would
	// silently run every organization in the process mode while its records
	// say otherwise - the one outcome the record exists to rule out.
	//
	// A nil db is "nothing to read", the same posture every constructor
	// above takes (they log and skip), not a construction failure: run.go
	// refuses to boot without DATABASE_URL long before this runs, so a nil
	// db here is a test or a no-DB harness, never a deployment whose table
	// exists and whose store cannot be opened.
	if db != nil {
		if settings, serr := sharedidentity.NewDBOrgIdentitySettingsStore(db); serr == nil {
			noteIdentityOrgSettingsWired(settings)
		} else if !errors.Is(serr, sharedidentity.ErrEnterpriseOnly) {
			log.Fatalf("❌ identity compat: per-organization settings store could not be built: %v", serr)
		}
	}
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
// (resolveUserSegments, segment_policy_gate.go), fail-closed, called from two
// places with different jobs:
//   - authenticateMCPSession (below) calls it once per resolved auth (once
//     per REQUEST for the stateless/hook-path callers that send no
//     Mcp-Session-Id — see segmentResolutionPhase's doc,
//     segment_resolution_metrics.go — not reliably once per session), purely
//     so the resolution outcome stays OBSERVABLE ("session_auth" phase) -
//     its return value is discarded, so a resolution error there denies
//     nothing and downgrades nothing.
//   - resolveMCPServerSegmentsForPolicy below calls it fresh at every
//     policy-affecting tools/call (#3430, check_policy/check_output) and
//     DOES act on the result: a resolver error there denies the call
//     (fail-closed, ADR-060 §Fail-closed).
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

// --- #3430 (ADR-060 P3 fleet-plane promotion): policy-affecting segment
// resolution for the MCP-server (JSON-RPC) plane's check_policy/check_output
// tools ---
//
// resolveMCPServerSegmentsForPolicy below calls resolveUserSegments fresh at
// every tools/call, with segmentResolutionPhaseEnforcement, and DOES act on
// its `ok` return (denies on false) — in contrast to authenticateMCPSession's
// session-create call (mcp_server_handler.go), which passes
// segmentResolutionPhaseSessionAuth and discards `ok` entirely. A second
// resolver call per tools/call, rather than a reuse of the session-create-time
// outcome, is deliberate: it is what lets the enforcement phase's error
// contract be independent of whatever happened at session-create (see
// segment_policy_gate.go's file doc for why these were never two different
// LOOKUPS, only two different USES of the same one).

// mcpSegmentGateOutcome is what the MCP-server plane's segment gate decided.
// Three states, not a bool, because the two DENY reasons are operationally
// different things an operator must be able to tell apart in the audit row:
// a storage/query failure inside the resolver, versus a caller whose segment
// membership is not determinable at all.
type mcpSegmentGateOutcome int

const (
	// mcpSegmentGateProceed: the returned segment set is authoritative for
	// this caller (possibly nil/empty, the legitimate "no segments" outcome)
	// and evaluation may run with it.
	mcpSegmentGateProceed mcpSegmentGateOutcome = iota

	// mcpSegmentGateDenyResolutionFailed: the caller HAS a per-user principal
	// to resolve against and the resolution genuinely errored (ADR-060
	// Fail-closed). Deny before evaluation.
	mcpSegmentGateDenyResolutionFailed

	// mcpSegmentGateDenyIdentityUnresolved: this session has no per-user
	// principal whose segment membership could be determined, AND the policy
	// set for this (tenant, org, phase) contains at least one segment-scoped
	// row, so the verdict genuinely depends on a set that cannot be
	// established. Deny before evaluation (#3430 R3 BLOCKER 1).
	mcpSegmentGateDenyIdentityUnresolved
)

// Guard ids + operator-facing refusal text for the two deny outcomes. Both
// ids are resolvable through the builtin guard table in
// policy_identity_stamp.go, so the audit row and the portal render a name
// rather than a bare identifier.
const (
	mcpSegmentResolutionFailedPolicyID   = "segment_resolution_failed"
	mcpSegmentIdentityUnresolvedPolicyID = "segment_identity_unresolved"
)

// mcpSegmentPhaseLabel names which half of a tool call a segment-gate refusal
// belongs to, so one refusal builder can serve both without either handler
// re-spelling a literal the other must match.
type mcpSegmentPhaseLabel int

const (
	mcpSegmentPhaseRequest mcpSegmentPhaseLabel = iota
	mcpSegmentPhaseResponse
)

// mcpSegmentGateRefusal maps a deny outcome to the guard id stamped into the
// audit row / response and the operator-facing reason text.
//
// The request-phase RESOLUTION-FAILED string is byte-identical to
// run.go:clientRequestHandler's and gateway_handlers.go's, deliberately: it is
// the one message an operator sees for this same contract on all three planes,
// and tooling that keys on it must not have to special-case the plane. It is
// the ONLY place in this change that keeps an em dash; the repo's
// no-dash-on-added-lines rule yields to that byte parity here. Do not
// "normalise" it - see the PR body's dash-gate note.
//
// The response-phase string deliberately DIVERGES ("response withheld" rather
// than "request denied"): check_output governs content already produced, and
// telling an operator their request was denied when the response was withheld
// misdescribes what happened. It has no cross-plane twin to match, so it
// carries a plain hyphen.
func mcpSegmentGateRefusal(outcome mcpSegmentGateOutcome, phase mcpSegmentPhaseLabel) (policyID, reason string) {
	switch outcome {
	case mcpSegmentGateDenyResolutionFailed:
		if phase == mcpSegmentPhaseResponse {
			return mcpSegmentResolutionFailedPolicyID, "segment resolution unavailable - response withheld (fail-closed, ADR-060 #2989)"
		}
		return mcpSegmentResolutionFailedPolicyID, "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"
	case mcpSegmentGateDenyIdentityUnresolved:
		if phase == mcpSegmentPhaseResponse {
			return mcpSegmentIdentityUnresolvedPolicyID, "segment membership indeterminate for a caller with no validated per-user token - response withheld (fail-closed, ADR-060 #3430)"
		}
		return mcpSegmentIdentityUnresolvedPolicyID, "segment membership indeterminate for a caller with no validated per-user token - request denied (fail-closed, ADR-060 #3430)"
	default:
		// Unreachable: callers only build a refusal for a deny outcome. Never
		// return an empty policy id, which would write an unattributable
		// blocked row.
		return mcpSegmentIdentityUnresolvedPolicyID, "segment gate denied the call (fail-closed, ADR-060 #3430)"
	}
}

// segmentIdentityUnresolvedTotal counts tool calls DENIED because the caller
// has no per-user principal whose governance-segment membership could be
// determined while segment-scoped policies exist for their (tenant, org,
// phase) - the #3430 R3 BLOCKER 1 refusal. Deliberately distinct from
// segmentPolicyFailClosedTotal (segment_policy_gate.go), which counts denies
// caused by the resolver ERRORING for a caller who did have a principal: the
// two have different operator remedies (provision per-user tokens vs repair
// the SCIM/identity store), so collapsing them into one series would hide
// which one is firing.
var segmentIdentityUnresolvedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_agent_mcp_segment_identity_unresolved_total",
	Help: "ADR-060 (#3430) MCP-server tool calls denied because the caller's governance-segment membership was indeterminate while segment-scoped policies exist.",
}, []string{"tool"})

// mcpSessionHasPerUserPrincipal reports whether this session carries a
// per-user principal whose governance-segment membership can meaningfully be
// resolved.
//
// The ONLY trusted signal is session.identityInputs.tokenResolvedIdentity,
// set exclusively by authenticateMCPSession on a successful Path A (HS256) or
// Path B (OIDC) per-user-token validation. The trust-gated X-User-Email
// header is deliberately NOT accepted here even when
// AXONFLOW_TRUST_IDENTITY_HEADERS is on: that header is caller-supplied, so
// treating it as a segment-resolution key would let the same human shed their
// segments by naming a non-member colleague - the reported bypass recreated
// one level down, through a different header. The header keeps its documented
// attribution (and ADR-044 override) role untouched; it simply never decides
// which segment-scoped policies apply.
//
// A token-validated identity whose SUBJECT is one of the platform's shared
// synthetics is also rejected: mint() validates only that the address
// contains "@" and ResolveToken censuses nothing (see authenticateMCPSession's
// #3077 R3 comment), so a token minted for e.g. "svc@axonflow.local"
// validates while naming an identity shared by many callers. Resolving
// segments for it would return zero memberships and read as "this person is
// in no segment". IsSharedSyntheticIdentity is the ONE census predicate for
// this (#2896/#2938) - never a second copy of the list.
func mcpSessionHasPerUserPrincipal(session *mcpSession) bool {
	if session == nil || !session.identityInputs.tokenResolvedIdentity {
		return false
	}
	if session.orgID == "" || session.userEmail == "" {
		return false
	}
	return !sharedidentity.IsSharedSyntheticIdentity(session.userEmail, isCommunityMode())
}

// segmentScopedPoliciesInScope reports whether a verdict for this session's
// (tenant, org, phase) can depend on governance-segment membership at all,
// i.e. whether the effective policy set holds at least one ENABLED
// segment-scoped row. ok == false means the policy set could not be read and
// the answer is unknown.
//
// staticEvaluationWillRun mirrors the caller's own detection gate: when the
// static pass is not going to run for this request (detection disabled for
// the deployment/org, or no engine wired), no segment-scoped row can fire, so
// an indeterminate segment set cannot change any verdict and must not deny.
//
// Scope, stated so it is not over-read: this censuses the STATIC engine's
// policy set (static_policies) only. The orchestrator's dynamic-policy plane
// has its own segment_id column and its own gate (#3052); this plane never
// hands the dynamic evaluator a segment set, which predates #3430 and is
// unchanged by it. An org whose ONLY segment-scoped rows are dynamic
// therefore still answers false here and proceeds - the refusal covers
// exactly the rows this plane's own evaluation could have applied.
func segmentScopedPoliciesInScope(ctx context.Context, session *mcpSession, phase sharedpolicy.Phase, staticEvaluationWillRun bool) (present bool, ok bool) {
	if !staticEvaluationWillRun {
		return false, true
	}
	engine := sharedpolicy.GetGlobalEngine()
	if engine == nil {
		return false, true
	}
	// The org scope used here (session.orgID) and the one the subsequent
	// evaluateInputPolicies / evaluateOutputPolicies scope with
	// (OrgIDFromContext(ctx)) must keep denoting the same org. Both are
	// stamped from the same authenticated client identity on every reachable
	// path today, so they agree; if they ever diverge, this census would
	// answer "does the verdict depend on segments" for a different org than
	// the one actually evaluated, which is the one way this gate can be
	// wrong without any test noticing.
	return engine.HasSegmentScopedPolicies(ctx, session.tenantID, sharedpolicy.OrgScopePtr(session.orgID), phase)
}

// resolveMCPServerSegmentsForPolicy resolves the caller's governance-segment
// set (ADR-060) for POLICY-AFFECTING consumption on the MCP-server JSON-RPC
// plane (mcpToolCheckPolicy / mcpToolCheckOutput, mcp_server_handler.go).
//
// Fail-closed per ADR-060, on BOTH axes:
//
//   - The caller HAS a per-user principal and resolution errors: deny
//     (mcpSegmentGateDenyResolutionFailed). Identical contract to every
//     other resolveUserSegments enforcement-phase caller
//     (segment_policy_gate.go); never an org-only fallback.
//   - The caller has NO per-user principal at all (legacy shared-credential
//     fleet on the documented Basic-auth norm, a caller that simply omitted
//     X-User-Token, a deployment with no registered per-user-token validator,
//     or a token naming a shared synthetic): the segment set is INDETERMINATE.
//     Round 1 of this PR returned org-only here, which is exactly the reported
//     bypass - a nil Segments excludes every segment-scoped row
//     (CompiledPolicy.AppliesToSegments), so the same human dropping one
//     header turned every segment-scoped policy off for themselves at zero
//     cost. Indeterminate now DENIES
//     (mcpSegmentGateDenyIdentityUnresolved) whenever a segment-scoped policy
//     actually exists for this (tenant, org, phase), and proceeds org-only
//     when none does.
//
// The conditional is what keeps the refusal proportionate: a deployment that
// has never created a segment-scoped policy - every deployment before ADR-060
// segment targeting, and every deployment that never adopts it - sees
// literally no behavior change, while a deployment that HAS adopted segment
// targeting gets an enforceable boundary instead of an opt-out header. The
// class this newly denies is stated in the PR body.
//
// Deliberately NOT denying when no resolver is wired at all
// (getFleetSegmentResolver() == nil: a community build, or Enterprise with no
// identity-attribute resolver constructed): that is the "capability absent"
// arm of the shared contract (identity.ResolveUserSegments), and both
// already-merged planes - run.go's clientRequestHandler (#3051) and the
// gateway pre-check (#3312) - proceed org-only there. Denying here alone
// would make one plane refuse traffic its two siblings serve for the same
// deployment. It is also not a caller-reachable state: no request can turn the
// process-wide resolver off.
func resolveMCPServerSegmentsForPolicy(ctx context.Context, session *mcpSession, phase sharedpolicy.Phase, staticEvaluationWillRun bool) (segmentIDs []string, outcome mcpSegmentGateOutcome) {
	if session == nil {
		// Unreachable from a served request (requireMCPAuth refuses before
		// dispatch), but a gate must not decide "proceed" on an absent
		// principal if that ever changes.
		return nil, mcpSegmentGateDenyIdentityUnresolved
	}
	if getFleetSegmentResolver() == nil {
		return nil, mcpSegmentGateProceed
	}

	if mcpSessionHasPerUserPrincipal(session) {
		ids, ok := resolveUserSegmentsForEnforcement(ctx, session.orgID, session.userEmail)
		if !ok {
			return nil, mcpSegmentGateDenyResolutionFailed
		}
		return ids, mcpSegmentGateProceed
	}

	present, ok := segmentScopedPoliciesInScope(ctx, session, phase, staticEvaluationWillRun)
	if !ok {
		log.Printf("🛡️ [MCP-Server] denying a caller with no per-user principal: the %s-phase policy set for org %s could not be read, so whether the verdict depends on governance segments is unknown (fail-closed, #3430)",
			string(phase), logutil.Sanitize(session.orgID))
		return nil, mcpSegmentGateDenyIdentityUnresolved
	}
	if present {
		log.Printf("🛡️ [MCP-Server] denying a caller with no validated per-user token: org %s has %s-phase segment-scoped policies whose applicability cannot be determined for a shared-credential principal (fail-closed, #3430)",
			logutil.Sanitize(session.orgID), string(phase))
		return nil, mcpSegmentGateDenyIdentityUnresolved
	}
	return nil, mcpSegmentGateProceed
}
