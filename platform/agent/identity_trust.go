// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
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

// mcpIdentityInputs records the identity-resolution INPUTS of ONE request:
// what the caller presented, and what this agent's trust gate was, at the
// moment an attributed identity was derived from them (#3077).
//
// It exists because the MCP-server plane's refusal is raised on a LATER request
// than the one that decided the identity. An MCP-protocol session resolves its
// identity once, at session create, and userEmail is immutable afterwards
// (resolveMCPSession's cache-hit branch deliberately mutates nothing but
// lastUsed). Reading X-User-Email off the tools/call that trips the refusal
// would therefore report header state from a request that had no bearing on the
// attributed identity — a fresh instance of the confidently-wrong diagnosis
// #3062/#3069 removed, dressed as a fix for it. Record the inputs, not an
// answer recomputed later from the wrong ones.
//
// Diagnostic ONLY. Nothing here may influence a verdict, an authz decision,
// attribution, or tenant/org resolution; the sole permitted effect is which
// human-readable sentence a refusal carries. Note in particular that these
// fields describe headers this agent may have DISCARDED — they must never be
// read back as an identity.
type mcpIdentityInputs struct {
	// headerPresented: the resolving request carried a non-blank X-User-Email
	// or X-User-ID. Read BEFORE the trust gate, so it stays true even when the
	// gate discarded the value — that is the whole point of recording it.
	headerPresented bool

	// presentedIsReserved: the value presented, AFTER sanitization, is one of
	// the platform's reserved shared spellings. Separates "your value did not
	// survive sanitization" from "your value names a credential, not a person".
	presentedIsReserved bool

	// presentedSurvivedSanitization: something usable remained after the
	// printable-only, length-bounded sanitizer. Both this and presentedIsReserved
	// are gate-INDEPENDENT causes: if they hold, turning the trust gate on
	// honors the value and refuses it again, so the refusal must not offer the
	// gate as a remedy.
	presentedSurvivedSanitization bool

	// trustGateOn: this agent's AXONFLOW_TRUST_IDENTITY_HEADERS at resolve
	// time. Captured rather than re-read at refusal time so every clause of the
	// message describes one and the same request.
	trustGateOn bool

	// tokenResolvedIdentity: a validated per-user token supplied this session's
	// identity, so NONE of the three header fields above had any bearing on it.
	//
	// This is the field captureMCPIdentityInputs cannot compute (#3077 R3).
	// authenticateMCPSession resolves a per-user token under AuthKindEnterprise
	// and RETURNS from the vid != nil branch before it reads X-User-Email /
	// X-User-ID at all — so only the resolver, at that branch, can observe which
	// channel won. Nothing on that path censuses the token's subject: the portal
	// mint() validates only that the address is non-empty and contains "@", and
	// ResolveToken applies no census either, so a token minted for e.g.
	// "svc@axonflow.local" validates and resolves to a SHARED synthetic that
	// trips the override refusal.
	//
	// Without this field the refusal routed such a caller on header state that
	// had no bearing on the outcome: gate off + a perfectly good X-User-Email
	// produced "this agent removed it — set AXONFLOW_TRUST_IDENTITY_HEADERS=true",
	// which relaxes the identity-trust posture on every proxied route while the
	// call still fails. That is #3062 exactly, inside the change that closes
	// #3062's class, which is why it is tested FIRST in the refusal switch.
	tokenResolvedIdentity bool
}

// captureMCPIdentityInputs snapshots the HEADER half of the identity-resolution
// inputs of r. It is called from authenticateMCPSession, which owns the
// resolution, and which sets tokenResolvedIdentity on the returned value at the
// one point that fact is observable. It deliberately does NOT try to work out
// whether a token won: that would be re-deriving an answer from inputs the
// resolver never consulted, which is the defect shape this whole file removes.
func captureMCPIdentityInputs(r *http.Request) mcpIdentityInputs {
	rawEmail := strings.TrimSpace(r.Header.Get(identityHeaderUserEmail))
	rawUserID := strings.TrimSpace(r.Header.Get(identityHeaderUserID))

	// headerPresented is read on the RAW value, before the gate and before
	// sanitization, because its job is to separate "you sent nothing" from "we
	// removed what you sent". A blank-after-trim header is nothing.
	headerPresented := rawEmail != "" || rawUserID != ""

	// presentedIsReserved must be computed on the value that would ACTUALLY
	// have become the identity, which means mirroring authenticateMCPServerRequest's
	// sanitize-then-fall-back precedence exactly: boundedAuditString on
	// X-User-Email first, then on X-User-ID.
	//
	// Computing it on the raw header instead was wrong in a way that produced a
	// FALSE sentence, which is the one outcome this file exists to prevent. With
	// the gate on and X-User-Email: "mcp\x7f-client:acme", boundedAuditString
	// drops the DEL rune and the identity resolves to the reserved spelling
	// "mcp-client:acme" — while a raw-value census sees a non-reserved string and
	// sends the refusal down the "did not survive sanitization" branch. The value
	// survived perfectly; it simply named a credential. Verified by execution
	// before and after.
	//
	// With the mirror in place that branch is true by construction: gate on plus
	// a presented value that sanitizes to something non-reserved resolves to a
	// non-shared identity and never reaches a refusal at all, so the only way to
	// arrive there is a value that sanitized to empty.
	sanitized := boundedAuditString(rawEmail, maxAttributedEmailLen)
	if sanitized == "" {
		sanitized = boundedAuditString(rawUserID, maxAttributedUserIDLen)
	}

	return mcpIdentityInputs{
		headerPresented: headerPresented,
		// The census predicate, not a second copy of the list — the
		// isClientSharedPseudoIdentity wrapper carries the community-mode
		// posture with it.
		presentedIsReserved:           sanitized != "" && isClientSharedPseudoIdentity(sharedidentity.CanonicalEmail(sanitized)),
		presentedSurvivedSanitization: sanitized != "",
		trustGateOn:                   trustIdentityHeaders(),
	}
}

// errSharedIdentityRefusal builds the MCP-server plane's refusal for a session
// attributed to a shared platform synthetic, through the choke point shared
// with the orchestrator's two causes (#3077).
//
// It reports only what this process observed about the session-create request,
// and it names the trust gate as part of a remedy ONLY when the gate is off. A
// deployment that already set the gate and simply received no header lands here
// too, and telling it to set an already-true flag is the confidently-wrong
// diagnosis #3062 was filed about — with the added cost that acting on the
// advice is a security-posture relaxation that changes nothing.
//
// Per-user tokens are offered only when this session's auth kind can resolve
// one: authenticateMCPSession runs token resolution under AuthKindEnterprise
// exclusively, so on a community / community-saas / internal-service session
// X-User-Token is not a remedy the caller could act on — and when a token
// ALREADY supplied this session's (shared) identity it is not a remedy either,
// it is the cause. TokenResolvedIdentity carries that distinction through.
func errSharedIdentityRefusal(session *mcpSession, feature string) error {
	return fmt.Errorf("%s", sharedidentity.SharedIdentityRefusalMessage(sharedidentity.SharedIdentityRefusal{
		Feature:                               feature,
		ResolvedIdentity:                      session.userEmail,
		IdentityHeaderPresented:               session.identityInputs.headerPresented,
		PresentedIdentityIsReserved:           session.identityInputs.presentedIsReserved,
		PresentedIdentitySurvivedSanitization: session.identityInputs.presentedSurvivedSanitization,
		TrustGateOn:                           session.identityInputs.trustGateOn,
		TokenResolvedIdentity:                 session.identityInputs.tokenResolvedIdentity,
		PerUserTokenResolvable:                session.authKind == AuthKindEnterprise,
	}))
}
