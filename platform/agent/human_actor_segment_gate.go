// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"
	"time"

	logutil "axonflow/platform/shared/logger"

	sharedidentity "axonflow/platform/shared/identity"
)

// ADR-060 (#2989) Slice 3 — the one user->segments lookup shared by every
// ResolveUser-authenticated HTTP plane in this package.
//
// # Callers
//
// Five handlers, two issues, ONE contract — the helpers below are deliberately
// plane-neutral so a sixth caller adds a call, not a copy:
//
//   - #3447, the LEGACY MCP REST plane: mcpQueryHandler
//     /mcp/resources/query, mcpExecuteHandler /mcp/tools/execute,
//     mcpCheckInputHandler /api/v1/mcp/check-input, mcpCheckOutputHandler
//     /api/v1/mcp/check-output (all mcp_handler.go). Request AND response
//     phase, static AND dynamic plane.
//   - #3456, the DECISION plane: handleDecide POST /api/v1/decide
//     (decision_handler.go). Static request phase only — /decide passes
//     runDynamicPolicy=false (no dynamic relay) and has no response phase.
//
// Every one of them authenticates an end user with ResolveUser ->
// validateUserToken (run.go): algorithm-pinned HS256, jti revocation, a real
// `email` claim already consumed for audit attribution. Each then passed
// Segments: nil unconditionally into policy evaluation, so a verified SCIM
// member of a governance segment had every segment-scoped policy silently
// SKIPPED on those URLs while the same human, on the same credential, was
// blocked on the MCP-server JSON-RPC plane (#3430). A one-URL edit — no
// second credential, no privilege change — evaded the control.
//
// This file holds the shared decision those planes make about WHOSE segments
// to resolve, so no caller can drift from another.
//
// # Where the per-user token comes from (per plane, deliberately NOT unified)
//
// The token INGEST differs by plane and stays that way (#2941): the MCP REST
// handlers read it from their JSON body's `user_token` field; /decide reads it
// from DecideRequest.UserToken, also the body. Neither reads an X-User-Token
// header — that header is the OTHER envelope, and it has exactly two read
// seams of its own (extractPerUserToken on the MCP-server JSON-RPC plane;
// proxy.go for /api/v1/audit/*, /api/v1/decisions, /api/v1/overrides), pinned
// by user_token_ingest_census_test.go. Teaching a second spelling to a
// body-token plane is precisely the debt #2941 warns about: its promotion
// trigger is "any single endpoint starts accepting both spellings". What IS
// unified is what happens AFTER the identity is settled: everything below.
//
// # Why these planes' contract differs from #3430's
//
// The MCP-server JSON-RPC plane (resolveMCPServerSegmentsForPolicy,
// mcp_identity.go) DENIES a caller with no per-user principal whenever
// segment-scoped policies exist, because there a caller could simply omit the
// per-user token header and still be served, on a client-scoped
// pseudo-identity. (These planes carry their token in the JSON body, not that
// header; the ingest points are censused separately — see
// user_token_ingest_census_test.go.) Here the token-less arm is NOT a refusal
// and runs NO policy census:
//
//   - ADR-060's baseline rule is unchanged — no verified identity means
//     org-only. Org-tier and system-tier policies still evaluate normally;
//     only segment-scoped rows are skipped.
//   - What makes that safe on THESE planes is #3476 (require_user_token,
//     already landed, and honored by handleDecide's own ResolveUser block as
//     well as the MCP REST ones): an org that has opted in rejects a
//     token-less enterprise caller at AUTHENTICATION, before any of this runs, so
//     arriving without an identity is not a selectable opt-out. The refusal
//     lives there, once, rather than being re-derived per-plane from a
//     policy census.
//
// Two things still fail closed here, independent of #3476, and they are the
// whole reason this is a gate rather than a plain lookup:
//
//  1. A resolver ERROR for a caller who HAS a principal denies
//     (ok == false), with guard id segment_resolution_failed. The fail-open
//     observability result is never promoted into this decision.
//  2. A token that validates while naming a SHARED SYNTHETIC identity
//     ("svc@axonflow.local", "orchestrator@axonflow.internal", the
//     mcp-client pseudo-identity, ...) is not a per-user principal. It would
//     resolve to zero memberships and read as "member of nothing", which is
//     the same bypass with a mintable token instead of a dropped header.
//     sharedidentity.IsSharedSyntheticIdentity is the ONE census predicate
//     for this (#2896/#2938) — never a second copy of the list. Such a
//     caller passes nil (org-only). This is deliberately NOT a deny: it is
//     indistinguishable, at this layer, from the token-less service caller
//     the arm above already serves org-only.
//
// The resolution key is ALWAYS the validated token's `email` claim
// (user.Email), NEVER the trust-gated X-User-Email header
// (attributedUserEmail). That header is caller-supplied, so keying segment
// resolution on it would let the same human shed their segments by naming a
// non-member colleague — the reported bypass recreated one level down. The
// header keeps its documented attribution and ADR-044 override role; it
// simply never decides which segment-scoped policies apply.

// segmentResolutionFailedReason is the operator-facing refusal text for a
// fail-closed resolver-error deny on the request phase of every plane that
// calls this file. Byte-identical to clientRequestHandler's (run.go), the
// gateway pre-check's (#3312, gateway_handlers.go) and the MCP-server plane's
// (#3430, mcp_identity.go) so one grep finds every plane's instance of the
// same refusal — and, since #3456, that parity is ENFORCED rather than
// conventional: segment_refusal_literal_parity_test.go scans this package's
// sources and fails on any occurrence that is not byte-identical to one of the
// pinned variants. The em dash is load-bearing; do not normalise it.
//
// New callers must REUSE this constant rather than spell the text again.
const segmentResolutionFailedReason = "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"

// segmentResolutionFailedPolicyID is the guard id a plane stamps into the
// audit row + response when it denies at the resolution site. Declared as an
// alias of the MCP-server plane's constant (#3430, mcp_identity.go) rather than
// as a second copy of the string, so the id cannot drift between planes at all;
// it resolves through the builtin guard table in policy_identity_stamp.go, so
// the audit row and the portal render a name rather than a bare identifier.
const segmentResolutionFailedPolicyID = mcpSegmentResolutionFailedPolicyID

// callerIsVerifiedHuman reports whether this request carries a VERIFIED
// HUMAN principal whose governance-segment membership is worth resolving.
//
// The discriminator is exactly two facts, and nothing else:
//
//   - ResolveUser returned NO error, and
//   - auth.Kind == AuthKindEnterprise.
//
// Only the AuthKindEnterprise arm of ResolveUser (authenticator.go) runs
// validateUserToken; the other three arms SYNTHESIZE a fixed identity with no
// SCIM counterpart at all — AuthKindCommunity ("local-dev@axonflow.local"),
// AuthKindCommunitySaaS ("evaluator@try.getaxonflow.com") and
// AuthKindInternalService ("orchestrator@axonflow.internal") — so resolving
// segments for them could only ever return zero memberships while looking
// like a real answer.
//
// userErr != nil means the handler either synthesized the org-scoped service
// identity (client.ID+"@axonflow.local", the token-ABSENT compat path) or
// already returned 401 (#3472 presented-and-rejected, #3476
// absent-but-required). Neither reaches here with a principal to resolve.
func callerIsVerifiedHuman(auth *AuthResult, userErr *AuthError, presentedToken string) bool {
	if auth == nil {
		return false
	}
	// ONE predicate, shared with audit attribution (identity_trust.go), so
	// enforcement and attribution cannot key on different notions of "who this
	// is" — the audit row names the principal enforcement was evaluated
	// against, which is only meaningful if one function decides what counts as
	// verified.
	return callerHasVerifiedUserIdentity(auth.Kind, userErr, presentedToken)
}

// resolveHumanActorSegmentsForPolicy resolves the caller's governance-segment
// set (ADR-060) for POLICY-AFFECTING consumption on any of this file's planes.
//
// Call it EXACTLY ONCE per request, immediately after the identity is settled,
// and reuse the returned set for EVERY policy call in that request — the
// request-phase (evaluateInputPolicies) one, the response-phase
// (evaluateOutputPolicies) one where the plane has a response phase, and the
// dynamic relay where the plane has one. Two resolutions in one request could
// observe two different cache states (the segment cache has a TTL,
// segment_cache.go) and enforce two different sets on one logical call.
//
// Returns (segmentIDs, ok):
//
//   - ok == false: the caller HAS a principal and the resolver genuinely
//     errored. The handler MUST deny with guard id
//     segment_resolution_failed, BEFORE reaching evaluateInputPolicies /
//     evaluateOutputPolicies — the trailing `segments` parameter on both of
//     those is a plain slice whose nil means "resolved to no segments / this
//     plane does not resolve one", NEVER "resolution failed". Do NOT fold
//     this into InputPolicyOutcome.EvalUnavailable: that channel surfaces as
//     503 "Dynamic policy evaluation unavailable", and a deliberate
//     policy-side deny must stay distinguishable from a real orchestrator
//     outage in both the audit row and the operator dashboard.
//   - ok == true with a nil/empty set: the legitimate org-only outcome — no
//     resolver wired (community build / no identity-attribute resolver),
//     no verified human principal, a shared-synthetic subject, or a verified
//     human with zero group memberships. Never a failure.
//
// verifiedHuman comes from callerIsVerifiedHuman above; email must be
// the VALIDATED token's email claim (user.Email), never attributedUserEmail's
// header-influenced value.
func resolveHumanActorSegmentsForPolicy(ctx context.Context, orgID, authenticatedOrgID, email string, verifiedHuman bool) (segmentIDs []string, ok bool) {
	if !verifiedHuman {
		// Synthetic service identity / community / community-SaaS /
		// internal-service: no SCIM identity to resolve. Org-only, no
		// refusal, no census (see this file's header).
		return nil, true
	}
	if sharedidentity.IsSharedSyntheticIdentity(email, isCommunityMode()) {
		// A validated token naming one of the platform's shared synthetics is
		// not a per-user principal. Org-only, not a deny.
		return nil, true
	}
	// The subject org is the VALIDATED token's org_id claim; nothing binds it to
	// the credential's authenticated org (these handlers bind the TENANT, not
	// the org). A disagreement cannot escalate — segment ids are org-scoped
	// group UUIDs, so the asserted org's groups can never match the governing
	// org's policies — but it silently UNDER-enforces: the lookup joins to zero
	// rows, which is reported as a successful empty resolution, and a verified
	// member of a targeted segment is evaluated org-only, indistinguishable from
	// a genuine non-member.
	//
	// Compared with a plain !=, deliberately NOT guarded by `x != ""` on each
	// side. That guarded form is the fail-open tenancy shape #3065's census
	// rejects: it goes quiet exactly when one side is empty, and an unbound
	// credential (a licence carrying no org_id) is precisely the case worth
	// reporting. Empty-versus-set IS a disagreement here.
	//
	// This decides only whether to COUNT and LOG — the resolution below is
	// identical either way — so it is not an authorization decision and does
	// not route through tenantscope.Authorize, which denies rather than reports.
	if orgID != authenticatedOrgID {
		segmentSubjectOrgMismatchTotal.Inc()
		warnSegmentSubjectOrgMismatch(orgID, authenticatedOrgID)
	}

	// Unconditionally fail-closed on a resolver error; org-only (ok == true)
	// on a nil resolver or an empty orgID/email. See resolveUserSegments
	// (segment_policy_gate.go) and the shared contract it adapts.
	return resolveUserSegments(ctx, orgID, email, segmentResolutionPhaseEnforcement)
}

// mcpCheckInputIdempEndpoint derives the idempotency scope for
// /api/v1/mcp/check-input, binding the cached response to the principal the
// verdict was computed for.
//
// The store's key is (key, tenant_id, endpoint) and its replay path returns
// the cached body without running the handler, so anything the verdict depends
// on that is NOT in that key is replayable across callers. Segment-scoped
// policy made the verdict depend on the principal, so the principal has to be
// in the key.
//
// The value is hashed rather than embedded: idempotency_keys.endpoint is a
// plain TEXT column read by operators and sweeps, and it has no business
// holding an email. A hash keeps the partitioning exact while keeping identity
// out of the row.
func mcpCheckInputIdempEndpoint(principal string) string {
	sum := sha256.Sum256([]byte(sharedidentity.CanonicalEmail(principal)))
	return "mcp.check-input|p=" + hex.EncodeToString(sum[:])
}

// warnSegmentSubjectOrgMismatch rate-limits the subject/authenticated org
// disagreement warning. The condition is per-REQUEST on an affected
// deployment, so an unlatched log would flood; the counter carries the volume
// and this carries the diagnosis. Mirrors warnPerUserTokenWithoutValidator.
func warnSegmentSubjectOrgMismatch(subjectOrg, authenticatedOrg string) {
	segmentOrgMismatchWarnMu.Lock()
	defer segmentOrgMismatchWarnMu.Unlock()
	now := time.Now()
	if !segmentOrgMismatchWarnedAt.IsZero() && now.Sub(segmentOrgMismatchWarnedAt) < segmentOrgMismatchWarnInterval {
		return
	}
	segmentOrgMismatchWarnedAt = now
	log.Printf("[Identity] WARNING: #3447 segment subject org %q disagrees with the authenticated org %q — "+
		"resolving against the subject org, which can only UNDER-match; a verified member may be "+
		"evaluated org-only. Mint per-user tokens with an org_id matching the credential's org. "+
		"(rate-limited; see axonflow_segment_subject_org_mismatch_total for volume)",
		logutil.Sanitize(subjectOrg), logutil.Sanitize(authenticatedOrg))
}

var (
	segmentOrgMismatchWarnMu       sync.Mutex
	segmentOrgMismatchWarnedAt     time.Time
	segmentOrgMismatchWarnInterval = 5 * time.Minute
)
