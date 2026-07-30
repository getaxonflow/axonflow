// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"fmt"
	"strings"
)

// The identity-required refusal choke point (#3062 → #3069 → #3131 → #3077).
//
// ADR-044 policy overrides are scoped to (tenant, USER, policy), so every plane
// that exposes them refuses to act without a per-user identity. #3069 removed
// the duplicated refusal text on the orchestrator plane by routing both 401
// sites through one helper; the MCP-server plane (platform/agent) kept its own
// message and could not share that helper, because platform/orchestrator
// imports platform/agent and the reverse import would be a cycle. The choke
// point therefore lives here, in the package both planes already depend on for
// the trust-gate contract and the shared-synthetic census.
//
// There are THREE reasons to refuse, and each needs a DIFFERENT remedy:
//
//  1. No per-user identity reached the platform and the refusing service cannot
//     see why → RefusalNoIdentity.
//  2. The caller DID present one and the AxonFlow Agent removed it because the
//     deployment has not declared its identity source trusted; the agent says
//     so with HeaderIdentityGated → RefusalIdentityGated.
//  3. An identity IS present, but it is a platform-synthesized identity SHARED
//     by every caller on one credential (IsSharedSyntheticIdentity). It is not
//     a person, so it may never hold a per-user override — one caller's
//     override would flip a deny for every caller on that credential (#2896).
//     → SharedIdentityRefusalMessage.
//
// THE RULE THIS FILE EXISTS TO ENFORCE (#3062 R3, restated on #3077): a
// diagnostic must name only causes the emitting service can actually observe,
// and must never suggest a remedy that cannot help the caller it is talking to.
// The concrete failure that rule was written from: a marker fired for a header
// no handler reads, so the implied remedy relaxed the identity-trust posture on
// every proxied route AND the call still failed. A security relaxation that
// fixes nothing is strictly worse than an unactionable error.
//
// That rule is why the two planes get different helpers rather than one string.
// They can observe different things:
//
//   - The orchestrator is a DIFFERENT PROCESS from the agent. It cannot read
//     the agent's AXONFLOW_TRUST_IDENTITY_HEADERS, so it may state the release
//     DEFAULT (a fact about the build) but never the deployment's value. Its
//     one usable observation is the agent's advisory marker, honored only over
//     the validated proxy-auth channel (#3074).
//   - The MCP-server plane runs INSIDE the agent. It can read the gate
//     directly, it can see whether the caller presented an identity header, it
//     can see whether this credential's auth kind resolves per-user tokens at
//     all, and — the observation R3 round 3 found missing — it can see whether a
//     validated per-user token ACTUALLY supplied the identity, which makes every
//     header fact and the gate itself irrelevant to the outcome. So its message
//     asserts those facts instead of hedging — and, just as importantly, it
//     stays SILENT about the gate when the gate is already on or was never
//     consulted, because "flip the gate" is then advice that provably cannot
//     help.
//
// SECURITY: these are 4xx bodies. They must not disclose anything a caller
// could not already determine, and they must not echo unsanitized caller input.
// The only caller-influenced value any of them renders is the resolved identity.
// It gets TWO independent layers here, and the second is not redundant:
//
//   - %q, so a hostile spelling is quoted and every non-printable rune is
//     escaped rather than emitted raw into the terminal a plugin renders this
//     into (the ANSI-control-character class);
//   - renderedIdentityMax, because the length is otherwise attacker-scalable.
//
// An earlier draft of this comment claimed the identity always arrives
// pre-sanitized — "either platform-minted or a value that already passed the
// agent's printable-only, length-bounded sanitizer". That is FALSE for the
// platform-minted case, which is the half it presented as needing no sanitizer:
// the MCP-server plane builds "mcp-client:" + auth.ClientID, and ClientID comes
// from the Basic-auth username with no sanitizer and no length bound. A
// 512-byte username containing a raw ESC reaches this function today. %q
// neutralises it, so there is no exploit — but a comment that describes a layer
// which does not exist is how the next contributor justifies dropping the layer
// that does.

// TrustDocRef points at the in-repo/site doc that explains the trust gate, its
// security invariant, and when it is safe to turn on. Exported so a test can
// assert the citation is present without re-spelling the path — a duplicated
// literal is how a moved doc turns into a dead link nothing catches.
const TrustDocRef = "docs/security/identity-header-trust"

// Cause enumerates the observations the ORCHESTRATOR plane can make about a
// missing per-user identity. It deliberately has no "shared identity" member:
// the orchestrator does not run the census on the override write path, and a
// cause it cannot observe must not be expressible in its message selector.
type Cause int

const (
	// RefusalNoIdentity — no per-user identity arrived and this service cannot
	// tell whether the caller sent none or the agent removed one.
	RefusalNoIdentity Cause = iota

	// RefusalIdentityGated — the agent stamped HeaderIdentityGated over the
	// trusted channel: the caller DID present an identity and the trust gate
	// removed it. This is the ONE case in which "the gate is off" is an
	// observation rather than a guess.
	RefusalIdentityGated
)

// IdentityRequiredMessage builds the actionable 401 body for an endpoint that
// requires a per-user identity and did not receive one. feature names the
// capability being refused (e.g. "policy overrides") so the caller learns why a
// per-user identity is required here specifically.
func IdentityRequiredMessage(cause Cause, feature string) string {
	if cause == RefusalIdentityGated {
		return "Authenticated user identity required: " + feature +
			" are scoped to an individual user. Your client DID send a per-user identity header and the AxonFlow Agent removed it, because this deployment has not declared its identity source trusted (" +
			EnvVar + " is not \"true\" — the default since 9.9.0). To enable " + feature +
			", either set " + EnvVar +
			"=true on the agent — only if every hop that can reach it asserts end-user identity from a validated source — or have the caller present a validated per-user token (X-User-Token). See " +
			TrustDocRef + "."
	}
	// No marker, or a marker this request was not entitled to assert (#3074):
	// this branch cannot know the deployment's gate state, so it must not
	// assert one. It is reached with the gate ON too — a caller who simply sent
	// no identity, a value that sanitized away, or any MCP-server-plane request
	// (mcpProxyToOrchestrator builds a fresh request, so no marker rides along).
	// Telling an operator who has already enabled the gate that the flag "is not
	// true" is the same species of confidently-wrong diagnosis this file exists
	// to remove. State the DEFAULT — a fact about the release, observable here —
	// and let the reader check their own deployment.
	return "Authenticated user identity required (X-User-Email): " + feature +
		" are scoped to an individual user. No per-user identity reached the platform. If your client did not send one, send X-User-Email. If it did, the AxonFlow Agent strips it unless this deployment has declared its identity source trusted: " +
		EnvVar + " defaults to off (since 9.9.0). If it is not set to \"true\" on your agent, set it — only if every hop that can reach the agent asserts end-user identity from a validated source — or have the caller present a validated per-user token (X-User-Token). See " +
		TrustDocRef + "."
}

// SharedIdentityRefusal carries the facts the refusing service ACTUALLY
// OBSERVED about one request. Every clause of the message built from it is
// derived from one of these fields; nothing is inferred about state the emitter
// cannot see. Callers must populate it from the request that RESOLVED the
// identity — on the MCP-server plane that is the session-create request, not
// the tools/call that happens to trip the refusal, because the session's
// attributed identity is immutable after create. Reporting header state from
// the wrong request is the same defect in a new place.
type SharedIdentityRefusal struct {
	// Feature names the capability being refused, e.g.
	// "per-user session overrides".
	Feature string

	// ResolvedIdentity is the shared synthetic the session was attributed to.
	// Rendered with %q — see the SECURITY note in the file header.
	ResolvedIdentity string

	// IdentityHeaderPresented reports whether the resolving request carried a
	// non-blank X-User-Email or X-User-ID, read BEFORE the trust gate. This is
	// what separates "you sent nothing" from "we removed what you sent".
	IdentityHeaderPresented bool

	// PresentedIdentityIsReserved reports whether the value the caller
	// presented is ITSELF one of the platform's reserved shared spellings
	// (IsSharedSyntheticIdentity), evaluated on the SANITIZED value — the one
	// that would actually have become the identity.
	//
	// It is meaningful whatever the gate state, and an earlier draft's claim
	// that it only mattered under an ON gate is what let the gate-off branch
	// recommend flipping the gate for a caller presenting a reserved spelling.
	// Turning the gate on would honor that value and refuse it again, so the
	// advice was the very thing this file forbids.
	PresentedIdentityIsReserved bool

	// PresentedIdentitySurvivedSanitization reports whether anything usable
	// remained after the agent's printable-only, length-bounded sanitizer.
	// Also gate-independent for the same reason: if nothing survives, turning
	// the gate on cannot produce an identity.
	PresentedIdentitySurvivedSanitization bool

	// TrustGateOn is this process's own EnvVar state. The MCP-server plane is
	// inside the agent, so unlike the orchestrator it may assert this.
	TrustGateOn bool

	// TokenResolvedIdentity reports that a validated per-user token supplied
	// this session's identity — so the three header fields above describe
	// something that had NO BEARING on the outcome, and neither does the gate.
	//
	// The MCP-server resolver returns from its token branch before it reads
	// X-User-Email / X-User-ID at all, and nothing on that path censuses the
	// token's subject (the portal mint validates only for an "@"; the resolver
	// applies no census), so a token minted for a reserved spelling validates
	// and lands here. Routing that caller on header state produced the #3062
	// defect verbatim: "this agent removed your header — set the trust flag",
	// a security-posture relaxation on every proxied route for a call that
	// still fails. Tested FIRST for that reason.
	//
	// When it is set the emitter MUST also stop offering X-User-Token as an
	// alternative: the caller presented one, and it is the cause.
	TokenResolvedIdentity bool

	// PerUserTokenResolvable reports whether this session's authentication kind
	// resolves a validated per-user token at all. Token resolution runs only
	// for enterprise-credential callers; offering X-User-Token to a community,
	// community-saas or internal-service caller is advice that cannot help.
	PerUserTokenResolvable bool
}

// SharedIdentityRefusalMessage builds the refusal for cause 3: an identity is
// present but it is a shared platform synthetic.
//
// The branches are ordered by OBSERVATION STRENGTH, not by the shape of the
// truth table, and the order is the load-bearing part.
//
// An earlier draft keyed the first branch on (header presented && gate off) and
// emitted "this agent removed it — set the flag". R3 refuted it: that branch
// also catches a caller who presented a RESERVED spelling, or a value that
// sanitizes to nothing. Turning the gate on then honors the value and refuses it
// again, so the message recommended a security-posture relaxation that provably
// could not help — the exact defect this file exists to remove, reintroduced by
// the fix for it.
//
// So the gate-independent causes are tested FIRST. Only once a presented
// identity is known to be usable and non-reserved is "the gate dropped it" the
// remaining explanation, and only there is the flag named as a remedy. The rule:
// the flag appears as an ACTION in exactly the rows where setting it is
// NECESSARY, and nowhere else.
//
// R3 round 3 found the strongest gate-independent cause missing entirely, and it
// now leads: TokenResolvedIdentity. A validated per-user token does not merely
// survive the gate — it makes every header field irrelevant, because the
// resolver returns from the token branch before it reads a header at all. So it
// is tested ahead of the reserved-spelling and sanitization branches too, whose
// remedies ("present a real address on the request that OPENS the session") are
// about a channel this caller is not using. Full ordering, and the input each
// branch owns exclusively:
//
//  0. token supplied the identity     — header fields say nothing; gate inert
//  1. presented value is reserved      — !token, gate-independent
//  2. presented value sanitized away   — !token, !reserved (reserved implies survived)
//  3. presented, usable, gate off      — !token, implies survived && !reserved
//  4. nothing presented, gate off      — !token, disjoint from 3 on presented
//  5. nothing presented, gate on       — !token, disjoint from 4 on the gate
//     default                             — !token, presented && survived && !reserved
//     && gate on: resolves to a real identity
//     and never refuses
//
// No earlier branch swallows a later one's input: 0 is the only branch keyed on
// the token, and when it holds every later branch's REMEDY is inapplicable, so
// nothing is lost by taking it first.
func SharedIdentityRefusalMessage(f SharedIdentityRefusal) string {
	feature := f.Feature
	if feature == "" {
		feature = "this capability"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s are scoped to an individual user, and this session is attributed to %q — an identity the platform synthesizes for a caller it cannot resolve to a person. It is shared by every caller using the same credential, so an override held by it would apply to all of them. That is why this is refused: not because a header is missing from THIS call, but because the session has no person behind it.",
		capitalizeFirst(feature), boundRenderedIdentity(f.ResolvedIdentity))

	switch {
	case f.TokenResolvedIdentity:
		// GATE-INDEPENDENT *and* CHANNEL-DECISIVE, so it outranks every header
		// branch. The resolver returns from its token branch before it reads
		// X-User-Email / X-User-ID, so whatever this struct records about
		// headers had no bearing on the identity — and no value of the trust
		// gate changes that, because the gate only governs reads that never
		// happen on this path. Naming either as a cause or a remedy would be
		// #3062 in the file written to remove #3062.
		fmt.Fprintf(&b, " That identity was supplied by a validated per-user token, not by a header: this agent resolves a per-user token in preference to X-User-Email / X-User-ID and does not read them when one validates. So no header on any request could have changed this, and no value of %s changes it either. The token's own subject is one of the platform's reserved shared spellings (%s) — those name a credential or a service, never a person. Issue a per-user token whose subject is a real user address, then open a new session; the attributed identity is fixed when the session is created.",
			EnvVar, reservedSpellingList())

	case f.IdentityHeaderPresented && f.PresentedIdentityIsReserved:
		// GATE-INDEPENDENT. The value presented is itself a reserved spelling,
		// so honoring it produces a shared synthetic and refuses again. The flag
		// is named only to say it is not the lever.
		//
		// The enumeration is the ACTIONABLE half of this sentence — a reader
		// checks their own value against it — so it must cover the whole census
		// or it tells some callers the diagnostic is not about them. An earlier
		// version listed three of the five spellings and so was false for
		// evaluator@try.getaxonflow.com, which matches none of the three. It is
		// built from the census constants rather than retyped, so adding a
		// synthetic to IsSharedSyntheticIdentity updates this text too.
		fmt.Fprintf(&b, " The identity presented on the request that opened this session is itself one of the platform's reserved shared spellings (%s). Those name a credential or a service, never a person, so no value of %s changes this outcome: present a real user address on the request that OPENS the session.",
			reservedSpellingList(), EnvVar)

	case f.IdentityHeaderPresented && !f.PresentedIdentitySurvivedSanitization:
		// GATE-INDEPENDENT. Nothing usable survived, so there is no identity to
		// trust however the flag is set.
		fmt.Fprintf(&b, " The identity presented on the request that opened this session did not survive sanitization — X-User-Email / X-User-ID keep printable characters only and are length-bounded, and nothing usable remained. No value of %s changes that: present a plain address on the request that OPENS the session.",
			EnvVar)

	case f.IdentityHeaderPresented && !f.TrustGateOn:
		// Now — and only now — the gate is the remaining explanation: a usable,
		// non-reserved identity arrived and this agent dropped it. Naming the
		// flag here is a diagnosis, and setting it genuinely changes the
		// outcome.
		fmt.Fprintf(&b, " The request that opened this session DID present a usable per-user identity header, and this agent removed it: %s is not \"true\" (the default since 9.9.0). Set %s=true on this agent — only if every hop that can reach it asserts end-user identity from a validated source — and open a new session; the attributed identity is fixed when the session is created.",
			EnvVar, EnvVar)

	case !f.IdentityHeaderPresented && !f.TrustGateOn:
		// Nothing was presented AND the gate is off. Both must change; naming
		// only one sends the caller away half-fixed.
		fmt.Fprintf(&b, " The request that opened this session presented no per-user identity header, and this agent's %s is not \"true\" (the default since 9.9.0). The header route needs both of those together and neither alone is enough: send X-User-Email on the request that OPENS the session (the attributed identity is fixed at session create, so sending it later has no effect), and set %s=true on this agent — only if every hop that can reach it asserts end-user identity from a validated source.",
			EnvVar, EnvVar)

	case !f.IdentityHeaderPresented && f.TrustGateOn:
		// The row #3077 is about. The gate is ALREADY on, so "flip the gate" is
		// advice that provably cannot help — say so explicitly, because it is
		// the first thing a reader who has seen the other messages will try.
		fmt.Fprintf(&b, " This agent already trusts identity headers (%s is \"true\"), so changing that setting will not help. The request that opened this session simply presented no per-user identity header: send X-User-Email on the request that OPENS the session — the attributed identity is fixed at session create, so sending it on a later call has no effect.",
			EnvVar)

	default:
		// Now genuinely defensive. The header route cannot reach here —
		// presented + usable + non-reserved under an ON gate resolves to a real
		// identity and never refuses — and the per-user TOKEN route, which USED
		// to be the live occupant of this arm, is branch 0 above. An earlier
		// version left the token case here, which is how it inherited a message
		// that prescribed no channel while the switch above had already routed
		// most token callers into a header branch.
		//
		// Anything arriving here has an identity that censuses as shared with no
		// observed cause, so this branch names the requirement without
		// prescribing a channel and asserts nothing about the deployment.
		b.WriteString(" No per-user identity could be resolved for this session: every identity it presented resolves to a shared platform synthetic. Present an identity that names a person — via X-User-Email on the request that OPENS the session, or in the per-user token if one is being used.")
	}

	switch {
	case f.TokenResolvedIdentity:
		// Do NOT offer X-User-Token. This caller already presented one and it is
		// the CAUSE of the refusal; "alternatively, present a validated per-user
		// token" told them to do the thing that failed. The branch above has
		// already given them the token-shaped remedy (mint one naming a person).

	case f.PerUserTokenResolvable:
		b.WriteString(" Alternatively, present a validated per-user token (X-User-Token): it carries its own identity and needs no header trust at all.")

	default:
		// Do NOT offer X-User-Token here either. Token resolution runs only for
		// enterprise-credential callers, so on this session it is a remedy the
		// caller cannot act on — exactly the advice-that-cannot-help class.
		b.WriteString(" A validated per-user token (X-User-Token) is not an option on this session: per-user tokens are resolved only for enterprise-credential callers.")
	}

	b.WriteString(" See " + TrustDocRef + ".")
	return b.String()
}

// reservedSpellingList renders the WHOLE shared-synthetic census in the form a
// reader can check their own value against. Derived from the same constants
// IsSharedSyntheticIdentity matches on, so the two cannot drift: the two
// reserved DOMAINS are matched by suffix and the remaining spellings exactly,
// and the text says which is which because "@axonflow.local" as a bare item
// reads like an address rather than a suffix rule.
//
// local-dev@axonflow.local is deliberately absent: it is subsumed by the
// @axonflow.local suffix, and naming it separately would imply it is refused
// unconditionally when in community mode it is a real single user.
func reservedSpellingList() string {
	return "the \"" + ClientPseudoIdentityPrefix + "\" prefix, any address under " +
		SharedServiceIdentitySuffix + " or " + InternalServiceIdentitySuffix +
		", and " + CommunitySaaSEvaluatorIdentity
}

// renderedIdentityMax bounds the identity echoed into a refusal. RFC 5321's
// maximum address length is 254; the extra room covers the "mcp-client:" prefix
// and leaves a truncation marker visible rather than silently clipping a real
// address. See the SECURITY note above for why a bound is needed at all: the
// pseudo-identity is built from an unbounded Basic-auth username.
const renderedIdentityMax = 300

// boundRenderedIdentity truncates on a RUNE boundary — byte slicing a
// multi-byte identity would emit a replacement character and, worse, make the
// echoed value differ from the stored one in a way a reader would not notice.
func boundRenderedIdentity(s string) string {
	r := []rune(s)
	if len(r) <= renderedIdentityMax {
		return s
	}
	return string(r[:renderedIdentityMax]) + "…(truncated)"
}

// capitalizeFirst upper-cases the first rune so a lower-case feature name reads
// as a sentence opener. ASCII-only by construction: every feature name is a
// compile-time literal in this repo.
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
