// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// The choke point's contract, asserted exhaustively (#3077).
//
// platform/agent's tests drive the real MCP path and cover the rows a unit test
// can reach without credentials. This file covers the FULL truth table,
// including the enterprise row (PerUserTokenResolvable), and pins the one
// property the whole file exists for:
//
//	a refusal must never recommend an action that cannot change its outcome.
//
// Every row is checked against that property mechanically rather than by
// eyeballing the prose, because prose is what drifted the last three times
// (#3062 → #3069 → #3077).

import (
	"fmt"
	"strings"
	"testing"
)

// gateRemedyOffered reports whether the message asks the reader to CHANGE the
// trust gate, as opposed to merely reporting its state. The distinction is the
// entire point: "the gate is on, so this will not help" names the flag without
// recommending it, and must not count as advice.
func gateRemedyOffered(msg string) bool {
	return strings.Contains(msg, EnvVar+"=true")
}

// TestSharedIdentityRefusal_NeverAdvisesTheGateWhenItIsAlreadyOn is the
// property #3077 was filed for. Enumerated over EVERY other field so no
// combination can smuggle the advice back in — that exhaustiveness is what
// caught the reserved-spelling row the first draft got wrong.
//
// The assertion is the real property (the flag is not recommended) plus "the
// flag is at least mentioned", not a fixed phrase. Different causes disclaim it
// differently — "changing that setting will not help" when the gate is the
// obvious suspect, "no value of ... changes this outcome" when the cause is
// gate-independent — and pinning one wording would force a false sentence into
// the branch it does not fit.
func TestSharedIdentityRefusal_NeverAdvisesTheGateWhenItIsAlreadyOn(t *testing.T) {
	for _, presented := range []bool{false, true} {
		for _, reserved := range []bool{false, true} {
			for _, survived := range []bool{false, true} {
				for _, token := range []bool{false, true} {
					f := SharedIdentityRefusal{
						Feature:                               "per-user session overrides",
						ResolvedIdentity:                      "mcp-client:acme",
						IdentityHeaderPresented:               presented,
						PresentedIdentityIsReserved:           reserved,
						PresentedIdentitySurvivedSanitization: survived,
						TrustGateOn:                           true,
						PerUserTokenResolvable:                token,
					}
					msg := SharedIdentityRefusalMessage(f)
					if gateRemedyOffered(msg) {
						t.Errorf("gate ON (presented=%v reserved=%v survived=%v token=%v): message recommends setting a flag that is already set:\n%s",
							presented, reserved, survived, token, msg)
					}
					// The default branch deliberately asserts nothing about the
					// deployment, so it is the one row that may stay silent
					// about the flag. Every other row must name it, or a reader
					// who has seen a sibling message will try it anyway.
					reachedDefault := presented && survived && !reserved
					if !reachedDefault && !strings.Contains(msg, EnvVar) {
						t.Errorf("gate ON (presented=%v reserved=%v survived=%v): message must name the flag to disclaim it:\n%s",
							presented, reserved, survived, msg)
					}
				}
			}
		}
	}
}

// The mirror: when the gate is OFF *and it is genuinely the blocker*, setting it
// IS a real remedy on this plane (verified end-to-end by platform/agent
// TestSharedIdentity_TheStatedRemedyActuallyWorks), so the message must offer
// it. A fix that simply deleted the gate advice everywhere would pass the test
// above and fail this one.
func TestSharedIdentityRefusal_OffersTheGateWhenItIsOff(t *testing.T) {
	for _, presented := range []bool{false, true} {
		f := SharedIdentityRefusal{
			Feature:                               "per-user session overrides",
			ResolvedIdentity:                      "mcp-client:acme",
			IdentityHeaderPresented:               presented,
			PresentedIdentitySurvivedSanitization: presented,
			TrustGateOn:                           false,
		}
		msg := SharedIdentityRefusalMessage(f)
		if !gateRemedyOffered(msg) {
			t.Errorf("gate OFF (presented=%v): setting the gate is a real remedy here and must be offered:\n%s", presented, msg)
		}
		if strings.Contains(msg, "will not help") {
			t.Errorf("gate OFF (presented=%v): message wrongly claims the gate is irrelevant:\n%s", presented, msg)
		}
	}
}

// R3 finding. The two GATE-INDEPENDENT causes must never offer the gate,
// whatever the gate's current state — including OFF, which is the case the
// first draft got wrong. If the presented value is a reserved spelling or
// sanitizes to nothing, turning the gate on honors it and refuses again, so the
// advice is a security-posture relaxation that provably cannot help. That is
// precisely the defect class this file exists to remove.
func TestSharedIdentityRefusal_GateIndependentCausesNeverOfferTheGate(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reserved bool
		survived bool
		wantWord string
	}{
		{"presented a reserved spelling", true, true, "reserved"},
		{"presented value sanitized to nothing", false, false, "did not survive sanitization"},
	} {
		for _, gate := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/gate=%v", tc.name, gate), func(t *testing.T) {
				msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
					Feature:                               "per-user session overrides",
					ResolvedIdentity:                      "mcp-client:acme",
					IdentityHeaderPresented:               true,
					PresentedIdentityIsReserved:           tc.reserved,
					PresentedIdentitySurvivedSanitization: tc.survived,
					TrustGateOn:                           gate,
				})
				if gateRemedyOffered(msg) {
					t.Errorf("this cause is gate-independent — setting the flag cannot help, so it must not be recommended:\n%s", msg)
				}
				if !strings.Contains(msg, tc.wantWord) {
					t.Errorf("must name the real cause (%q):\n%s", tc.wantWord, msg)
				}
			})
		}
	}
}

// The reserved-spelling branch's enumeration is the ACTIONABLE half of that
// sentence — a reader checks their own value against it — so it must cover the
// WHOLE census. R3 caught it listing three of five: a caller attributed to
// evaluator@try.getaxonflow.com was told their value "is itself one of the
// platform's reserved shared spellings" followed by a list it does not appear
// in, which reads as "this message is not about me".
//
// Driven from IsSharedSyntheticIdentity itself, so adding a synthetic to the
// census without updating the text turns this red.
func TestSharedIdentityRefusal_ReservedBranchNamesTheWholeCensus(t *testing.T) {
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:                               "per-user session overrides",
		ResolvedIdentity:                      "mcp-client:acme",
		IdentityHeaderPresented:               true,
		PresentedIdentityIsReserved:           true,
		PresentedIdentitySurvivedSanitization: true,
		TrustGateOn:                           true,
	})
	for _, spelling := range []string{
		"mcp-client:x",
		"anything@axonflow.local",
		"anything@axonflow.internal",
		CommunitySaaSEvaluatorIdentity,
	} {
		if !IsSharedSyntheticIdentity(spelling, false) {
			t.Fatalf("test is stale: %q is no longer in the census", spelling)
		}
	}
	// Every census RULE must be findable in the message.
	for _, want := range []string{
		ClientPseudoIdentityPrefix,
		SharedServiceIdentitySuffix,
		InternalServiceIdentitySuffix,
		CommunitySaaSEvaluatorIdentity,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the enumeration omits %q, so a caller matching only that rule is told the message is not about them:\n%s", want, msg)
		}
	}
}

// The reserved cause outranks the sanitization cause: a value that survives
// sanitization INTO a reserved spelling is reserved, not unusable. Ordering the
// switch the other way would produce a false sentence for the exact input that
// motivated the mirror-the-sanitizer fix.
func TestSharedIdentityRefusal_ReservedOutranksSanitization(t *testing.T) {
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:                               "per-user session overrides",
		ResolvedIdentity:                      "mcp-client:acme",
		IdentityHeaderPresented:               true,
		PresentedIdentityIsReserved:           true,
		PresentedIdentitySurvivedSanitization: true,
		TrustGateOn:                           true,
	})
	if strings.Contains(msg, "did not survive sanitization") {
		t.Errorf("the value survived — into a reserved spelling; the refusal must not claim otherwise:\n%s", msg)
	}
}

// --- TokenResolvedIdentity (R3 round 3) --------------------------------------
//
// The MCP-server resolver returns from its per-user-token branch BEFORE it reads
// X-User-Email / X-User-ID, and nothing on that path censuses the token's
// subject. So a token minted for a reserved spelling resolves to a shared
// synthetic and reaches this builder with header fields that had no bearing on
// the outcome. Routing it on them reproduced #3062 exactly.

// tokenBranchTaken reports whether the message blames the token. Kept as one
// literal so the three tests below cannot drift apart from the branch text.
const tokenCauseSentence = "supplied by a validated per-user token"

// The headline property, enumerated over EVERY other field including the gate:
// when the token supplied the identity, setting the gate cannot change the
// outcome, so it must never be recommended. This is the same exhaustive shape
// that caught the reserved-spelling row in round 1 — the row a hand-picked case
// list would have missed.
func TestSharedIdentityRefusal_TokenResolved_NeverAdvisesTheGate(t *testing.T) {
	for _, presented := range []bool{false, true} {
		for _, reserved := range []bool{false, true} {
			for _, survived := range []bool{false, true} {
				for _, gate := range []bool{false, true} {
					msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
						Feature:                               "per-user session overrides",
						ResolvedIdentity:                      "svc@axonflow.local",
						IdentityHeaderPresented:               presented,
						PresentedIdentityIsReserved:           reserved,
						PresentedIdentitySurvivedSanitization: survived,
						TrustGateOn:                           gate,
						TokenResolvedIdentity:                 true,
						// Necessarily true in production: token resolution runs
						// only for enterprise-credential callers.
						PerUserTokenResolvable: true,
					})
					if gateRemedyOffered(msg) {
						t.Errorf("token-resolved (presented=%v reserved=%v survived=%v gate=%v): the gate was never consulted, so recommending it is advice that cannot help:\n%s",
							presented, reserved, survived, gate, msg)
					}
					if !strings.Contains(msg, tokenCauseSentence) {
						t.Errorf("token-resolved (presented=%v reserved=%v survived=%v gate=%v): the refusal must name the token as the cause:\n%s",
							presented, reserved, survived, gate, msg)
					}
					// And it must still disclaim the flag, or a reader who has
					// seen a sibling message tries it anyway.
					if !strings.Contains(msg, EnvVar) {
						t.Errorf("token-resolved (presented=%v reserved=%v survived=%v gate=%v): the flag must be named to disclaim it:\n%s",
							presented, reserved, survived, gate, msg)
					}
				}
			}
		}
	}
}

// The token branch OUTRANKS every header branch, including the two
// gate-independent ones. Their remedies ("present a real address on the request
// that OPENS the session") are about a channel this caller is not using: the
// token overrides the header, so following them changes nothing. Enumerated over
// the header fields so no combination can smuggle a header diagnosis back in.
func TestSharedIdentityRefusal_TokenResolved_OutranksEveryHeaderBranch(t *testing.T) {
	headerBranchPhrases := []string{
		"is itself one of the platform's reserved shared spellings",
		"did not survive sanitization",
		"DID present a usable per-user identity header",
		"presented no per-user identity header",
		"already trusts identity headers",
		"send X-User-Email",
	}
	for _, presented := range []bool{false, true} {
		for _, reserved := range []bool{false, true} {
			for _, survived := range []bool{false, true} {
				for _, gate := range []bool{false, true} {
					msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
						Feature:                               "per-user session overrides",
						ResolvedIdentity:                      "svc@axonflow.local",
						IdentityHeaderPresented:               presented,
						PresentedIdentityIsReserved:           reserved,
						PresentedIdentitySurvivedSanitization: survived,
						TrustGateOn:                           gate,
						TokenResolvedIdentity:                 true,
						PerUserTokenResolvable:                true,
					})
					for _, phrase := range headerBranchPhrases {
						if strings.Contains(msg, phrase) {
							t.Errorf("token-resolved (presented=%v reserved=%v survived=%v gate=%v): message reached a header branch (%q), whose remedy the token overrides:\n%s",
								presented, reserved, survived, gate, phrase, msg)
						}
					}
				}
			}
		}
	}
}

// The trailer half of the same finding. "Alternatively, present a validated
// per-user token" told a caller who HAD presented one to do the thing that
// failed — and it is the cause. The remedy that does apply (mint a token naming
// a person) has to be there instead, or the message is unactionable.
func TestSharedIdentityRefusal_TokenResolved_DoesNotOfferTheTokenBack(t *testing.T) {
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:                "per-user session overrides",
		ResolvedIdentity:       "svc@axonflow.local",
		TokenResolvedIdentity:  true,
		PerUserTokenResolvable: true,
	})
	if strings.Contains(msg, "Alternatively, present a validated per-user token") {
		t.Errorf("the caller presented a token and it is the cause — it must not be offered as the remedy:\n%s", msg)
	}
	if strings.Contains(msg, "not an option on this session") {
		t.Errorf("a token IS resolvable here (it just resolved) — the message must not say otherwise:\n%s", msg)
	}
	if !strings.Contains(msg, "Issue a per-user token whose subject is a real user address") {
		t.Errorf("the actionable remedy must be present, or the refusal is a dead end:\n%s", msg)
	}
	// And the whole census is enumerated here too, for the same reason the
	// reserved branch enumerates it: the reader checks their token's subject
	// against it.
	for _, want := range []string{
		ClientPseudoIdentityPrefix,
		SharedServiceIdentitySuffix,
		InternalServiceIdentitySuffix,
		CommunitySaaSEvaluatorIdentity,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the enumeration omits %q, so a caller matching only that rule reads the message as not being about them:\n%s", want, msg)
		}
	}
}

// The mirror, and the mutation tripwire for "just set the flag everywhere": with
// TokenResolvedIdentity FALSE the five header branches must still be reachable
// and must still say what they said. A fix that hard-wired the token branch on
// would pass all three tests above and silently delete every header diagnosis.
func TestSharedIdentityRefusal_TokenNotResolved_HeaderBranchesUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name                                string
		presented, reserved, survived, gate bool
		phrase                              string
	}{
		{name: "reserved spelling", presented: true, reserved: true, survived: true, gate: true, phrase: "is itself one of the platform's reserved shared spellings"},
		{name: "sanitized away", presented: true, survived: false, gate: true, phrase: "did not survive sanitization"},
		{name: "gate dropped it", presented: true, survived: true, gate: false, phrase: "DID present a usable per-user identity header"},
		{name: "nothing presented, gate off", gate: false, phrase: "neither alone is enough"},
		{name: "nothing presented, gate on", gate: true, phrase: "already trusts identity headers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
				Feature:                               "per-user session overrides",
				ResolvedIdentity:                      "mcp-client:acme",
				IdentityHeaderPresented:               tc.presented,
				PresentedIdentityIsReserved:           tc.reserved,
				PresentedIdentitySurvivedSanitization: tc.survived,
				TrustGateOn:                           tc.gate,
				TokenResolvedIdentity:                 false,
			})
			if !strings.Contains(msg, tc.phrase) {
				t.Errorf("the header branch must still be reachable and must still say %q:\n%s", tc.phrase, msg)
			}
			if strings.Contains(msg, tokenCauseSentence) {
				t.Errorf("no token supplied this identity — the refusal must not blame one:\n%s", msg)
			}
		})
	}
}

// A per-user token is resolved only for enterprise-credential callers
// (authenticateMCPServerRequest gates ResolveToken on AuthKindEnterprise).
// Offering X-User-Token to a community / community-saas / internal-service
// session is the same advice-that-cannot-help defect in a second place.
func TestSharedIdentityRefusal_OffersTokenOnlyWhereItIsResolvable(t *testing.T) {
	base := SharedIdentityRefusal{
		Feature:          "per-user session overrides",
		ResolvedIdentity: "mcp-client:acme",
	}

	yes := base
	yes.PerUserTokenResolvable = true
	if !strings.Contains(SharedIdentityRefusalMessage(yes), "Alternatively, present a validated per-user token") {
		t.Errorf("token IS resolvable: the remedy must be offered:\n%s", SharedIdentityRefusalMessage(yes))
	}

	no := base
	no.PerUserTokenResolvable = false
	msgNo := SharedIdentityRefusalMessage(no)
	if strings.Contains(msgNo, "Alternatively, present a validated per-user token") {
		t.Errorf("token is NOT resolvable on this session: it must not be offered as a remedy:\n%s", msgNo)
	}
	if !strings.Contains(msgNo, "not an option on this session") {
		t.Errorf("token is NOT resolvable: say so, or the reader tries it anyway:\n%s", msgNo)
	}
}

// Every branch has to explain WHY a shared identity is refused, cite the doc,
// and render the identity quoted. A branch that reaches the switch's default
// and forgets one of these is the failure mode a per-branch test misses.
func TestSharedIdentityRefusal_EveryBranchIsComplete(t *testing.T) {
	for _, presented := range []bool{false, true} {
		for _, reserved := range []bool{false, true} {
			for _, gate := range []bool{false, true} {
				msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
					Feature:                     "per-user session overrides",
					ResolvedIdentity:            "mcp-client:acme",
					IdentityHeaderPresented:     presented,
					PresentedIdentityIsReserved: reserved,
					TrustGateOn:                 gate,
				})
				for _, want := range []string{
					"shared by every caller", // why
					`"mcp-client:acme"`,      // the identity, quoted
					TrustDocRef,              // where to read more
					"scoped to an individual user",
				} {
					if !strings.Contains(msg, want) {
						t.Errorf("presented=%v reserved=%v gate=%v: missing %q:\n%s", presented, reserved, gate, want, msg)
					}
				}
			}
		}
	}
}

// A hostile identity must be escaped, not emitted raw. %q is the mechanism; a
// future edit to %s would silently reopen the ANSI-control-character class.
func TestSharedIdentityRefusal_EscapesHostileIdentity(t *testing.T) {
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:          "per-user session overrides",
		ResolvedIdentity: "a\x1b[31m\nb@axonflow.local",
	})
	for _, raw := range []rune{'\x1b', '\n'} {
		if strings.ContainsRune(msg, raw) {
			t.Errorf("raw control rune %q survived into the message: %q", raw, msg)
		}
	}
}

// The rendered identity is length-bounded. R3 finding: the MCP-server plane
// builds "mcp-client:" + the Basic-auth username, which passes through no
// sanitizer and no length bound, so without this the message size is
// attacker-scalable. Truncation is on a rune boundary — byte slicing would emit
// a replacement character and make the echoed value silently differ from the
// stored one.
func TestSharedIdentityRefusal_BoundsTheRenderedIdentity(t *testing.T) {
	huge := "mcp-client:" + strings.Repeat("é", 4000)
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:          "per-user session overrides",
		ResolvedIdentity: huge,
	})
	if !strings.Contains(msg, "(truncated)") {
		t.Errorf("an oversized identity must be truncated visibly: %d runes rendered", len([]rune(msg)))
	}
	if strings.Contains(msg, "�") {
		t.Error("truncation split a multi-byte rune — it must cut on a rune boundary")
	}
	// A normal address must be untouched: a bound that clips real identities
	// would be its own defect.
	normal := SharedIdentityRefusalMessage(SharedIdentityRefusal{
		Feature:          "per-user session overrides",
		ResolvedIdentity: "mcp-client:acme-production-cluster-01",
	})
	if strings.Contains(normal, "(truncated)") || !strings.Contains(normal, `"mcp-client:acme-production-cluster-01"`) {
		t.Errorf("a normal identity must be rendered in full: %s", normal)
	}
}

// The orchestrator's two causes keep their #3062/#3069/#3131 contract after the
// move: the marked branch may assert the gate is off (it observed the agent say
// so); the unmarked branch may not assert deployment state at all.
func TestIdentityRequiredMessage_CauseContract(t *testing.T) {
	gated := IdentityRequiredMessage(RefusalIdentityGated, "policy overrides")
	if !strings.Contains(gated, "DID send") {
		t.Errorf("the gated cause is an observation and must diagnose:\n%s", gated)
	}

	generic := IdentityRequiredMessage(RefusalNoIdentity, "policy overrides")
	for _, forbidden := range []string{
		EnvVar + " is not",
		`is not "true"`,
		"has not declared",
	} {
		if strings.Contains(generic, forbidden) {
			t.Errorf("the no-identity cause asserts deployment state it cannot observe (%q):\n%s", forbidden, generic)
		}
	}
	if !strings.Contains(generic, "defaults to off") {
		t.Errorf("the no-identity cause may state the RELEASE default, and must:\n%s", generic)
	}
	for _, msg := range []string{gated, generic} {
		for _, want := range []string{EnvVar, "X-User-Token", TrustDocRef, "scoped to an individual user"} {
			if !strings.Contains(msg, want) {
				t.Errorf("message missing %q:\n%s", want, msg)
			}
		}
	}
}

// The Cause type deliberately has no shared-identity member: the orchestrator
// does not run the synthetic census on the override write path, so a cause it
// cannot observe must not be expressible in its selector. Guard the enum's size
// so a later "just add one more" edit has to read that reasoning first.
func TestCause_HasExactlyTheTwoOrchestratorObservableCauses(t *testing.T) {
	if RefusalNoIdentity != 0 || RefusalIdentityGated != 1 {
		t.Fatalf("Cause members renumbered: NoIdentity=%d Gated=%d", RefusalNoIdentity, RefusalIdentityGated)
	}
	// An out-of-range cause must degrade to the safe generic message rather
	// than produce an empty body.
	if got := IdentityRequiredMessage(Cause(99), "policy overrides"); !strings.Contains(got, "defaults to off") {
		t.Errorf("an unrecognized cause must fall back to the non-asserting message, got:\n%s", got)
	}
}

// An empty feature name must not produce a sentence starting with a space or a
// dangling "are scoped to". Cheap, but this string is rendered into a user's
// terminal by four plugins.
func TestSharedIdentityRefusal_EmptyFeatureDegradesReadably(t *testing.T) {
	msg := SharedIdentityRefusalMessage(SharedIdentityRefusal{ResolvedIdentity: "mcp-client:acme"})
	if !strings.HasPrefix(msg, "This capability are scoped") && !strings.HasPrefix(msg, "This capability") {
		t.Errorf("empty feature must degrade to a readable placeholder, got: %s", msg)
	}
}
