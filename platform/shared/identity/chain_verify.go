// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 whole-chain verification (#3556).
//
// VerifyCredential answers "is this one credential admissible in this realm".
// AdmitChain answers "is this sequence of principals a permitted delegation".
// Neither alone satisfies the #3556 criterion that actor-chain cycles,
// excessive depth, wrong audience, expiry AND REVOKED HOPS fail closed, because
// audience, expiry and revocation are per-credential facts while cycles and
// depth are per-chain ones.
//
// Composing them at each call site would be the usual way to close that, and it
// is the wrong way: the composition has an ordering requirement, and a call
// site that gets it wrong fails in a direction nobody notices. VerifyChain is
// the one place the composition lives.
package identity

import (
	"fmt"
	"time"
)

// VerifyChain verifies every hop's credential and then admits the resulting
// delegation chain.
//
// creds is ROOT-FIRST, the same order as ActorChain: index 0 is the authority
// on whose behalf access is requested. A chain ingested from an RFC 8693 `act`
// claim is nearest-first on the wire and must be reversed before it reaches
// here; ActorChainFromRFC8693 does that for principals, and a caller assembling
// credentials does the same.
//
// # ORDER, AND WHY IT IS THIS WAY ROUND
//
// Every credential is verified BEFORE any chain-level check runs. The
// alternative, admitting the chain first and verifying credentials afterwards,
// looks cheaper because a malformed chain short-circuits before any signature
// work. It is wrong for a reason that only shows up in the diagnostics: a chain
// containing a REVOKED hop and a cycle would report the cycle, an operator
// would fix the cycle, and the revoked credential would still be there and
// would still be accepted on the next attempt if the cycle had been the only
// thing stopping it. Per-hop facts first means the report always names the
// credential problem when there is one.
//
// The first refusal wins and verification stops there. A caller gets one
// actionable refusal rather than a list, and the hop index is in the detail so
// the refusal names WHICH hop even when several hops share a realm.
//
// Returns the admitted chain, the per-hop verified subjects in the same order,
// and the admission. On any refusal the chain and the subjects are nil: a
// partially verified chain is not a thing a caller should be able to reach for.
func VerifyChain(
	reg *RealmRegistry,
	authenticatedOrgID string,
	creds []Credential,
	maxDepth int,
	now time.Time,
	revocations RevocationOracle,
) (ActorChain, []VerifiedSubject, Admission) {
	if len(creds) == 0 {
		return nil, nil, DenyAdmission(ReasonChainEmpty,
			"no credentials were presented; an empty chain has no authority to intersect and is never unconstrained")
	}

	// DEPTH IS CHECKED BEFORE ANY CREDENTIAL WORK, and it is the one
	// chain-level check that is. The bound exists to limit how many hops the
	// realm layer has to trust, and every hop costs a verification and, where a
	// realm declares one, a revocation-source round trip. Applying it only
	// after the loop makes it a correctness bound that is no longer a WORK
	// bound: a caller presenting five thousand credentials against a depth of
	// four still buys five thousand revocation lookups before being refused.
	//
	// It does not weaken the credentials-first ordering below, because that
	// ordering is about which refusal a chain of ADMISSIBLE LENGTH reports, and
	// a chain longer than the bound is refused whatever its credentials say.
	if maxDepth <= 0 {
		maxDepth = DefaultMaxDelegationDepth
	}
	if len(creds) > maxDepth {
		return nil, nil, DenyAdmission(ReasonDelegationDepth, fmt.Sprintf(
			"%d credentials were presented and the governed surface allows %d; refused before any credential was verified",
			len(creds), maxDepth))
	}

	chain := make(ActorChain, 0, len(creds))
	subjects := make([]VerifiedSubject, 0, len(creds))

	for i, cred := range creds {
		verified := VerifyCredential(reg, authenticatedOrgID, cred, now, revocations)
		if !verified.Admission.State.IsAdmitted() {
			return nil, nil, atHop(i, len(creds), verified.Admission)
		}
		chain = append(chain, verified.Admission.Principal)
		subjects = append(subjects, verified)
	}

	if adm := AdmitChain(reg, authenticatedOrgID, chain, maxDepth); !adm.State.IsAdmitted() {
		return nil, nil, adm
	}

	root := chain[0]
	return chain, subjects, AcceptAdmission(root)
}

// atHop re-labels a per-credential admission with the hop it came from,
// preserving its state and reason.
//
// It rebuilds through the constructors rather than editing a copy, so a refusal
// keeps its state and its reason while gaining the hop label.
//
// NOTE FOR A SECOND CALL SITE, because the first draft of this comment got it
// wrong: DenyAdmission and IndeterminateAdmission PANIC on an empty reason,
// they do not refuse. So this function must never be handed a determinate
// refusal that carries no reason code. Today's single call site cannot produce
// one, because every refusal VerifyCredential returns is built by those same
// constructors. A future caller that hands over a hand-built Admission must
// check that first.
func atHop(index, total int, adm Admission) Admission {
	label := fmt.Sprintf("hop %d of %d: %s", index, total, adm.Detail)
	if adm.Detail == "" {
		label = fmt.Sprintf("hop %d of %d", index, total)
	}
	switch adm.State {
	case AdmissionDeny:
		return DenyAdmission(adm.Reason, label)
	case AdmissionIndeterminate:
		return IndeterminateAdmission(adm.Reason, label)
	case AdmissionAccept, AdmissionUnspecified:
		// Neither is reachable from the one call site, which relabels only a
		// refusal. Refusing rather than returning the input is what stops a
		// future second call site quietly turning an unspecified admission
		// into an admitted one.
		return IndeterminateAdmission(ReasonIdentityInternalError, fmt.Sprintf(
			"hop %d of %d produced an admission in state %s, which cannot be relabelled as a refusal", index, total, adm.State))
	default:
		return IndeterminateAdmission(ReasonIdentityInternalError, fmt.Sprintf(
			"hop %d of %d produced an unrecognized admission state", index, total))
	}
}
