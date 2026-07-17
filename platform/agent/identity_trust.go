// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	sharedidentity "axonflow/platform/shared/identity"
)

// Identity-header trust gate (#2896).
//
// X-User-Email / X-User-ID / X-Session-Id are client-assertable: any governed
// caller can set them, so honoring them unconditionally lets a compromised or
// malicious PEP forge the audit identity of another principal (and, on the
// check-input / MCP-server planes, hijack another user's ADR-044 session
// override — a deny→allow flip). All four governance planes (/api/v1/decide,
// /api/v1/mcp/check-input, /api/v1/mcp/check-output, MCP-server tools/call)
// therefore read these headers ONLY through the helpers below:
//
//   - Gate OFF (default): the headers are ignored everywhere. Attribution and
//     override scoping use the VALIDATED identity (ResolveUser / the
//     client-scoped pseudo-identity). A request carrying the headers logs a
//     once-per-process detection warning so an operator never silently loses
//     per-user attribution.
//   - Gate ON (AXONFLOW_TRUST_IDENTITY_HEADERS=true, exact string): the
//     deployment has declared that every hop that can reach this service
//     re-sets the identity headers from a validated source (desktop proxy,
//     JumpCloud-managed plugin settings, gateway jwtAuth claim). The headers
//     then attribute audit rows (audit_logs.user_email / session_id) and, as
//     before this gate existed, scope the per-user ADR-044 session-override
//     feature.
//
// SECURITY INVARIANT: with the gate OFF a request's verdict and audit
// identity are byte-identical with and without these headers. The headers
// must NEVER influence a verdict, authz decision, policy selection, or
// tenant/org resolution on any plane, gate on or off — EXCEPT the two
// documented identity-SCOPED features, which key on the same trusted
// identity as attribution and only under the gate: (1) the ADR-044 per-user
// session-override apply, and (2) per-user dynamic-policy evaluation on the
// MCP-server plane, whose session userID (header-derived when trusted) feeds
// user-scoped rate limits / budgets exactly as it did for pre-gate trusted
// fleets. With the gate off both key on the validated / client-scoped
// identity, so a forged header can influence neither (see #2896).
const (
	identityHeaderUserEmail = "X-User-Email"
	identityHeaderUserID    = "X-User-ID"
	identityHeaderSessionID = "X-Session-Id"
)

// Length bounds for client-asserted identity values landing in audit rows.
// Hostile input hygiene only — values are additionally stripped of
// control/unprintable runes via boundedAuditString.
const (
	maxAttributedEmailLen     = 254 // RFC 5321 maximum address length
	maxAttributedUserIDLen    = 128
	maxAttributedSessionIDLen = 128
)

// Once-per-process warning latches. Warnings (not sync.Once) so tests can
// reset them; atomics so concurrent handlers race-safely elect one logger.
var (
	unrecognizedTrustValueWarned atomic.Bool
	untrustedIdentityWarned      atomic.Bool
)

// trustIdentityHeaders reports whether this deployment opted in to trusting
// client-asserted identity headers. Parse semantics are the shared contract
// (platform/shared/identity, mirrored by the #2889 gateway adapters): only
// the exact string "true" opts in; ""/"false" are off; anything else is off
// plus a once-per-process warning so a "1"/"TRUE" typo leaves a trace.
func trustIdentityHeaders() bool {
	trusted, recognized := sharedidentity.FromEnv()
	if !recognized && unrecognizedTrustValueWarned.CompareAndSwap(false, true) {
		log.Printf("⚠️ [identity] %s=%q is not \"true\"/\"false\" — treating as false (identity headers stay untrusted)",
			sharedidentity.EnvVar, os.Getenv(sharedidentity.EnvVar))
	}
	return trusted
}

// trustedIdentityHeader returns the sanitized value of the named identity
// header when the trust gate is on, or "" when the header is absent or the
// gate is off. A present-but-untrusted value triggers the once-per-process
// detection warning: the caller sent identity we are deliberately dropping,
// and the operator should know attribution is falling back to the validated
// identity rather than discovering it weeks later in an audit review.
func trustedIdentityHeader(r *http.Request, name string, maxLen int) string {
	raw := strings.TrimSpace(r.Header.Get(name))
	if raw == "" {
		return ""
	}
	if !trustIdentityHeaders() {
		warnUntrustedIdentityHeader(name)
		return ""
	}
	return boundedAuditString(raw, maxLen)
}

// warnUntrustedIdentityHeader emits the once-per-process detection log for a
// governed request that carried identity headers while the gate is off.
func warnUntrustedIdentityHeader(name string) {
	if untrustedIdentityWarned.CompareAndSwap(false, true) {
		log.Printf("⚠️ [identity] received identity headers (%s) but %s is off — audit attribution is using the validated/fleet identity; set %s=true if your identity source (gateway, proxy, or managed plugin) is trusted to assert end-user identity",
			name, sharedidentity.EnvVar, sharedidentity.EnvVar)
	}
}

// attributedUserEmail resolves the audit-attribution email for a governed
// request: the trusted X-User-Email when the gate is on and the header is
// present (post-sanitize), else the validated identity. Attribution only —
// callers must not feed the result into any authz/verdict path except the
// documented ADR-044 override scope, which deliberately shares this identity.
func attributedUserEmail(r *http.Request, validatedEmail string) string {
	if e := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen); e != "" {
		return e
	}
	return validatedEmail
}

// attributedSessionID resolves the client-asserted AI-tool session id
// (X-Session-Id) under the trust gate; "" when absent or untrusted. Callers
// stamp it into the request context via withClientSessionID so the audit
// writers persist it into audit_logs.session_id.
func attributedSessionID(r *http.Request) string {
	return trustedIdentityHeader(r, identityHeaderSessionID, maxAttributedSessionIDLen)
}

// mcpClientPseudoIdentityPrefix is the MCP-server plane's client-scoped
// fallback identity ("mcp-client:<client-id>") minted by
// authenticateMCPServerRequest when no trusted per-user identity is
// available (legacy callers, or identity headers dropped by the gate).
// Aliased to the shared census constant so the mint site and the census
// predicate can never drift.
const mcpClientPseudoIdentityPrefix = sharedidentity.ClientPseudoIdentityPrefix

// isClientSharedPseudoIdentity reports whether email is a
// platform-synthesized identity SHARED by more than one caller — not a
// person. ADR-044 session overrides are scoped to (tenant, USER, policy); a
// shared identity must never create, be offered, or apply one, or an
// override created by one caller flips deny→allow for every other caller on
// the same client (#2896 R3). Attribution (audit rows) still uses these
// identities — they are honest about not knowing the person; only the
// override scope is refused.
//
// The census itself (#2896 WS1b) lives in platform/shared/identity
// (IsSharedSyntheticIdentity) so this trust plane and the orchestrator read
// plane (#2938 resolveCallerReadScope) consume ONE list — add any new
// synthesized identity THERE, never here. Community mode exempts only the
// local-dev community synthetic (a real single user by construction).
func isClientSharedPseudoIdentity(email string) bool {
	return sharedidentity.IsSharedSyntheticIdentity(email, isCommunityMode())
}
