// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 actor chains and delegation attenuation (#3556).
//
// # CHAIN ORDER IS ROOT-FIRST, AND THE REVERSAL IS DELIBERATE
//
// In memory, ActorChain[0] is the authority on whose behalf access is
// requested, and each later element is a nearer intermediary. RFC 8693 nests
// the other way round: `act` is a claim INSIDE the token describing who is
// acting, nested outward from the immediate actor. Ingestion from a token
// therefore reverses; see ActorChainFromRFC8693.
//
// The order is fixed in memory because two consumers depend on it and would
// otherwise each pick their own: the delegation check walks consecutive pairs
// and needs to know which side is the delegator, and a decision trace names
// "the requester", which is a different principal depending on the direction.
// Both are documented at their use sites rather than left incidental.
//
// # ATTENUATION IS A MEET, NEVER A UNION
//
// EX-27 is the case: alice may spend $5,000 and agent-A holds a
// principal-scoped grant up to $50,000. A union across the chain grants
// $30,000 to a principal entitled to $5,000. That is the confused deputy, and
// every policy involved looks correct in isolation. Effective authority is the
// INTERSECTION of every hop, so adding a hop can only ever narrow.
//
// The empty-chain boundary is where a fold like this usually goes wrong. The
// identity element of intersection is the universal set, so a naive fold over
// zero hops yields "everything permitted". MeetAll returns the EMPTY authority
// for an empty input instead, and AdmitChain refuses an empty chain outright,
// so the universal set is not constructible here.
package identity

import (
	"fmt"
	"sort"
	"strings"
)

// DefaultMaxDelegationDepth is the fallback bound on chain length when a
// governed surface declares none. Governed surfaces declare their own
// (ADR-065's tool registry carries max_delegation_depth per tool); this is
// what AdmitChain uses when it is handed a non-positive bound, so a caller
// that forgets to configure one gets a bound rather than none.
const DefaultMaxDelegationDepth = 4

// ActorChain is an ordered, root-first delegation chain.
type ActorChain []PrincipalID

// String renders the chain for traces and test failures.
func (c ActorChain) String() string {
	parts := make([]string, len(c))
	for i, p := range c {
		parts[i] = p.String()
	}
	return "[" + strings.Join(parts, " -> ") + "]"
}

// Root returns the authority on whose behalf access is requested, and whether
// the chain has one. A chain with no root authorizes nothing.
func (c ActorChain) Root() (PrincipalID, bool) {
	if len(c) == 0 {
		return PrincipalID{}, false
	}
	return c[0], true
}

// Immediate returns the nearest actor, the one that actually made the call.
func (c ActorChain) Immediate() (PrincipalID, bool) {
	if len(c) == 0 {
		return PrincipalID{}, false
	}
	return c[len(c)-1], true
}

// Contains reports whether p appears anywhere in the chain. Used by
// separation-of-duties self-exclusion: an approver that appears anywhere in
// the requesting chain cannot approve its own request, not merely the root.
func (c ActorChain) Contains(p PrincipalID) bool {
	for _, hop := range c {
		if hop == p {
			return true
		}
	}
	return false
}

// ActorChainFromRFC8693 converts an actor list in RFC 8693 `act` nesting order
// (immediate actor first, outward to the original subject) into the root-first
// order this package uses.
//
// It copies rather than reversing in place: the caller's slice frequently
// belongs to a parsed token structure that other code still reads.
func ActorChainFromRFC8693(actOrder []PrincipalID) ActorChain {
	out := make(ActorChain, len(actOrder))
	for i, p := range actOrder {
		out[len(actOrder)-1-i] = p
	}
	return out
}

// AdmitChain checks a delegation chain against the realm registry.
//
// maxDepth bounds the chain length. A non-positive maxDepth is replaced by
// DefaultMaxDelegationDepth rather than treated as unbounded: an unbounded
// chain is an unbounded number of hops each of which the realm layer has to
// trust, and "the caller passed 0" is not evidence that the operator wanted
// that.
//
// Checks run in this order, and each has its own reason code because the
// remedies differ:
//
//  1. non-empty, within depth;
//  2. every hop is a well-formed canonical principal;
//  3. no hop is a Group (a group is not an actor) and the root is not a
//     Client (a client credential is attribution, not authority);
//  4. no principal repeats;
//  5. every hop's realm is declared in this organization and enabled, and
//     asserts that hop's subject type;
//  6. every consecutive pair is a delegation the delegator's realm permits.
func AdmitChain(reg *RealmRegistry, orgID string, chain ActorChain, maxDepth int) Admission {
	if reg == nil {
		return IndeterminateAdmission(ReasonUnknownRealm,
			"no realm registry is configured, so no hop's realm can be resolved")
	}
	if strings.TrimSpace(orgID) == "" {
		return DenyAdmission(ReasonOrgBindingMismatch,
			"the request carries no authenticated organization to resolve the chain's realms in")
	}
	if len(chain) == 0 {
		return DenyAdmission(ReasonChainEmpty,
			"the actor chain is empty; an empty chain has no authority to intersect and is never unconstrained")
	}
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDelegationDepth
	}
	if len(chain) > maxDepth {
		return DenyAdmission(ReasonDelegationDepth, fmt.Sprintf(
			"the actor chain has %d hops and the governed surface allows %d", len(chain), maxDepth))
	}

	realms := make([]TrustRealm, len(chain))
	seen := make(map[PrincipalID]int, len(chain))

	for i, hop := range chain {
		if err := hop.Validate(); err != nil {
			return DenyAdmission(ReasonMalformedPrincipal, fmt.Sprintf("hop %d: %v", i, err))
		}
		if hop.Type == SubjectGroup {
			return DenyAdmission(ReasonSubjectTypeRejected, fmt.Sprintf(
				"hop %d is a Group; a group is a set of subjects, never an actor in a chain", i))
		}
		if i == 0 && hop.Type == SubjectClient {
			// ADR-065 invariant 2: client_id identifies the authenticated
			// application. It is attribution, not a policy-selected identity.
			// A Client at the root would make the calling application the
			// authority a grant is scoped to, which is the shape #3333
			// describes on the legacy path. A Client may still appear as an
			// intermediary hop, where it is attributed and constrains the
			// meet without ever being the subject.
			return DenyAdmission(ReasonSubjectTypeRejected,
				"the chain root is a Client; a client credential is attribution and cannot be the authority a request is evaluated for (see #3279 for the verified machine principal that replaces it)")
		}
		if prior, dup := seen[hop]; dup {
			return DenyAdmission(ReasonChainCycle, fmt.Sprintf(
				"principal %s appears at hops %d and %d", hop, prior, i))
		}
		seen[hop] = i

		realm, ok := reg.Lookup(orgID, hop.Realm)
		if !ok {
			return DenyAdmission(ReasonUnknownRealm, fmt.Sprintf(
				"hop %d names realm %q, which has no declaration in this organization", i, hop.Realm))
		}
		if !realm.Enabled {
			return DenyAdmission(ReasonRealmDisabled, fmt.Sprintf(
				"hop %d names realm %q, which is declared but disabled", i, hop.Realm))
		}
		if !realm.AcceptsSubjectType(hop.Type) {
			return DenyAdmission(ReasonSubjectTypeRejected, fmt.Sprintf(
				"hop %d asserts subject type %q, which realm %q does not assert", i, hop.Type, hop.Realm))
		}
		realms[i] = realm
	}

	// Consecutive pairs: realms[i] is the delegator, realms[i+1] the delegate.
	// EX-27 makes cross-realm chains the normal case, so this is a permission
	// check on the delegator's declared policy, not a same-realm requirement.
	for i := 0; i+1 < len(chain); i++ {
		if !realms[i].PermitsDelegateRealm(realms[i+1].RealmID) {
			return DenyAdmission(ReasonDelegationNotPermitted, fmt.Sprintf(
				"realm %q does not permit realm %q to act on behalf of its subjects (policy: %s)",
				realms[i].RealmID, realms[i+1].RealmID, realms[i].Delegation))
		}
	}

	root := chain[0]
	return AcceptAdmission(root)
}

// Authority is a set of capability identifiers a principal holds.
//
// It is an opaque value type with no exported field, so the only way to build
// one is NewAuthority, which sorts and de-duplicates. That matters for two
// reasons: Meet's implementation can then assume sorted input, and a decision
// proof over an authority set is stable regardless of construction order.
//
// The zero Authority is EMPTY, meaning nothing is permitted. It is never the
// universal set. A consumer that reads a zero Authority and proceeds has
// granted nothing, which is the correct direction for a missing value.
type Authority struct {
	caps []string
}

// NewAuthority builds an authority from capability identifiers. Empty strings
// are dropped, duplicates collapse, and the result is sorted.
func NewAuthority(capabilities ...string) Authority {
	seen := make(map[string]struct{}, len(capabilities))
	out := make([]string, 0, len(capabilities))
	for _, c := range capabilities {
		if c == "" {
			continue
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Strings(out)
	return Authority{caps: out}
}

// Capabilities returns a copy of the capability set, sorted. A copy, so a
// caller cannot mutate an Authority that another decision still holds.
func (a Authority) Capabilities() []string {
	return append([]string(nil), a.caps...)
}

// IsEmpty reports whether this authority permits nothing.
func (a Authority) IsEmpty() bool { return len(a.caps) == 0 }

// Len returns the number of capabilities.
func (a Authority) Len() int { return len(a.caps) }

// Contains reports whether the authority holds a capability.
func (a Authority) Contains(capability string) bool {
	i := sort.SearchStrings(a.caps, capability)
	return i < len(a.caps) && a.caps[i] == capability
}

// Subset reports whether every capability in a is also in other.
func (a Authority) Subset(other Authority) bool {
	for _, c := range a.caps {
		if !other.Contains(c) {
			return false
		}
	}
	return true
}

// Equal reports set equality.
func (a Authority) Equal(other Authority) bool {
	if len(a.caps) != len(other.caps) {
		return false
	}
	for i, c := range a.caps {
		if other.caps[i] != c {
			return false
		}
	}
	return true
}

// String renders the authority for traces and test failures.
func (a Authority) String() string { return "{" + strings.Join(a.caps, ",") + "}" }

// Meet returns the intersection: the authority a delegation of a through other
// can exercise. Intersection is the only combinator this type offers, because
// offering a union would make the confused deputy a one-call mistake.
func (a Authority) Meet(other Authority) Authority {
	if a.IsEmpty() || other.IsEmpty() {
		return Authority{}
	}
	out := make([]string, 0, smaller(len(a.caps), len(other.caps)))
	for _, c := range a.caps {
		if other.Contains(c) {
			out = append(out, c)
		}
	}
	// a.caps is sorted and out preserves that order, so no re-sort is needed.
	return Authority{caps: out}
}

// smaller returns the lesser of two ints. Named rather than using the builtin
// min so this file does not shadow a builtin identifier, which the repository
// linter flags.
func smaller(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// MeetAll folds Meet over a chain's per-hop authorities, root first.
//
// An EMPTY input returns the EMPTY authority, not the universal set. That is
// the opposite of intersection's mathematical identity and it is deliberate:
// the universal set is what a naive fold produces for zero hops, and it would
// mean "a request with no identity may do anything". AdmitChain independently
// refuses an empty chain, so this is the second of two guards on the same
// boundary; either alone would leave a path to it.
//
// Note the monotonicity property this function has, and the one it does not.
// For a NON-EMPTY chain, appending a hop can only narrow the result. For the
// empty chain it cannot, because the result is already empty and appending the
// first hop widens it to that hop's own authority. The property tests state it
// for chains of length one and above, which is the only length AdmitChain
// admits.
func MeetAll(authorities []Authority) Authority {
	if len(authorities) == 0 {
		return Authority{}
	}
	out := authorities[0]
	for _, a := range authorities[1:] {
		out = out.Meet(a)
		if out.IsEmpty() {
			// Nothing can widen it again; stop early.
			return out
		}
	}
	return out
}
