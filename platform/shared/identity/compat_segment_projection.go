// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-060 segment projection from the ADR-065 directory graph (#3550).
//
// The legacy segment resolver answers one question - "which governance
// segments does this user belong to" - with a flat, sorted list of
// scim_groups.id values, resolved by a SQL join keyed on a canonicalized
// email. The ADR-065 directory graph answers a richer question: a bounded
// transitive closure over realm-qualified group principals, with witness
// paths, a closure STATE, and quarantined edges.
//
// This file flattens the second into the shape the first produces, so the two
// can be diffed on a live stack. That diff is the migration's evidence: until
// the graph reproduces the resolver's answer on real data, nothing should be
// re-pointed at it.
//
// # THE THREE PROJECTION OUTCOMES ARE NOT INTERCHANGEABLE
//
// A closure has three states and they must not collapse into "a list of
// segments, possibly empty" - that collapse is EX-45, and it is the reason
// ClosureResult keeps its resolved set unexported behind
// MustBeAuthoritative. The projection preserves all three:
//
//   - AUTHORITATIVE: the realm declares a group graph and the traversal
//     finished. The projection is complete and diffable.
//   - NO GRAPH: the realm declares DirectorySourceNone. The empty projection
//     is AUTHORITATIVE - this realm has no group concept - and it is a
//     legitimate zero, not an outage.
//   - UNREACHABLE or TRUNCATED: the answer is not known. The projection is
//     REFUSED, never returned as an empty or partial list, because a ceiling
//     scoped to a segment that was not enumerated would silently not apply.
//
// # WHY THE SEGMENT ID IS THE SUBJECT ID AND NOT THE PRINCIPAL STRING
//
// A legacy SegmentID is scim_groups.id. A group PrincipalID is
// `Group::<realm>:<scim group id>` - the SCIM ingestion adapter makes the SCIM
// `id` the canonical subject precisely so this correspondence exists. So the
// projection is the group principal's SUBJECT, and the realm qualification is
// dropped. Dropping it is a real loss of information (two realms could each
// hold a group with the same SCIM id), and it is dropped anyway because the
// legacy resolver has no realm concept and a projection that emitted a
// qualified id would diff as 100% different against every row. The loss is
// recorded per segment in CrossRealmCollisions so it cannot be silent.
package identity

import (
	"fmt"
	"sort"
)

// SegmentProjection is the ADR-060 view of one closure.
type SegmentProjection struct {
	// Subject is the principal the closure was computed for.
	Subject PrincipalID
	// SegmentIDs is the flattened, deduped, sorted segment set, in exactly the
	// shape ResolveUserSegments returns (NormalizeSegmentIDs' canonical form).
	// Nil, never a non-nil empty slice, for an authoritative zero.
	SegmentIDs []string
	// Authoritative reports whether the projection is complete. It mirrors
	// ClosureResult.State.IsAuthoritative and exists so a consumer that
	// ignores the Admission still cannot read a refusal as an empty set: the
	// zero value of this struct has Authoritative false.
	Authoritative bool
	// SourceVersion is the directory snapshot version the closure came from,
	// carried so a diff can name which snapshot disagreed.
	SourceVersion string
	// CrossRealmCollisions names any segment id produced by more than one
	// realm IN THIS CLOSURE. The projection drops realm qualification, so a
	// collision means two distinct groups flattened onto one segment id.
	//
	// IT IS SCOPED TO ONE SUBJECT AND THEREFORE DOES NOT CATCH THE
	// CROSS-SUBJECT CASE. Two realms in one organization can each hold a group
	// with the same SCIM id; a subject who is a member of only one of them
	// projects to that id with no collision reported, and a policy scoped to
	// the OTHER realm's group then applies to them. Answering that requires a
	// directory-wide scan of every realm's group ids, which is an operator
	// report and not a per-request computation. Naming the limit here rather
	// than claiming the field closes the class.
	CrossRealmCollisions []string
	// NoGraph reports that the closure was authoritatively empty because the
	// realm declares no group graph at all (EX-45), rather than because a
	// traversal ran and found nothing.
	//
	// The two are indistinguishable in SegmentIDs and both are admitted by
	// MustBeAuthoritative, so a diff that ignored this would report "the graph
	// reproduces the resolver" for a deployment whose graph was never
	// consulted - which is exactly what a mis-declared DirectorySourceNone
	// produces. DiffSegmentProjection refuses to compare on it.
	NoGraph bool
}

// ProjectSegments flattens a closure into the ADR-060 segment set.
//
// It returns the projection AND an Admission. The Admission is the authority:
// a caller must check it, exactly as it must for
// ClosureResult.MustBeAuthoritative, and on a non-Accept the projection's
// SegmentIDs is nil and Authoritative is false. Both are populated so that a
// caller which reads only the struct still cannot mistake a refusal for a
// legitimate zero.
func ProjectSegments(closure ClosureResult) (SegmentProjection, Admission) {
	groups, adm := closure.MustBeAuthoritative()
	if !adm.State.IsAdmitted() {
		return SegmentProjection{
			Subject:       closure.Subject,
			Authoritative: false,
			SourceVersion: closure.SourceVersion,
		}, adm
	}

	ids := make([]string, 0, len(groups))
	byID := map[string]map[RealmID]bool{}
	for _, g := range groups {
		if g.Subject == "" {
			// Unreachable through NewPrincipalID, which refuses an empty
			// subject. REFUSED rather than skipped: dropping a member from a
			// set that then reports itself authoritative is a silently
			// incomplete answer, which is the one thing this projection may
			// not produce.
			return SegmentProjection{Subject: closure.Subject, SourceVersion: closure.SourceVersion},
				IndeterminateAdmission(ReasonIdentityInternalError,
					"a group in the closure carries no subject identifier; the projection would be silently incomplete")
		}
		ids = append(ids, g.Subject)
		realms, seen := byID[g.Subject]
		if !seen {
			realms = map[RealmID]bool{}
			byID[g.Subject] = realms
		}
		realms[g.Realm] = true
	}

	var collisions []string
	for id, realms := range byID {
		if len(realms) > 1 {
			collisions = append(collisions, id)
		}
	}
	sort.Strings(collisions)

	return SegmentProjection{
		Subject:              closure.Subject,
		SegmentIDs:           NormalizeSegmentIDs(ids),
		Authoritative:        true,
		NoGraph:              closure.State == ClosureStateNoGraph,
		SourceVersion:        closure.SourceVersion,
		CrossRealmCollisions: collisions,
	}, adm
}

// SegmentProjectionDiff is the comparison between the legacy resolver's answer
// and the graph's projection for the same subject.
type SegmentProjectionDiff struct {
	// Comparable reports whether a comparison was possible at all. False when
	// either side refused to answer - and a refusal is NOT zero differences.
	Comparable bool
	// Incomparable names why, when Comparable is false.
	IncomparableReason string
	// OnlyLegacy is present in the resolver's answer and absent from the
	// projection. These are the dangerous ones during a migration: a segment
	// a policy targets today that the graph would stop resolving.
	OnlyLegacy []string
	// OnlyProjected is present in the projection and absent from the
	// resolver's answer: a segment the graph would newly resolve.
	OnlyProjected []string
	// Both is the agreed set.
	Both []string
	// CrossRealmCollisions is carried up from the projection.
	CrossRealmCollisions []string
}

// Identical reports whether the two answers agree exactly. It is false for an
// incomparable diff: "we could not compare" is never "they matched".
func (d SegmentProjectionDiff) Identical() bool {
	return d.Comparable && len(d.OnlyLegacy) == 0 && len(d.OnlyProjected) == 0
}

// String renders the diff for a log line or a test failure.
func (d SegmentProjectionDiff) String() string {
	if !d.Comparable {
		return fmt.Sprintf("incomparable: %s", d.IncomparableReason)
	}
	return fmt.Sprintf("only_legacy=%v only_projected=%v both=%d collisions=%v",
		d.OnlyLegacy, d.OnlyProjected, len(d.Both), d.CrossRealmCollisions)
}

// DiffSegmentProjection compares the legacy resolver's segment set against the
// graph's projection for the same subject.
//
// legacyOK is the resolver's own ok flag (ResolveUserSegments' second return).
// A resolution FAILURE is incomparable, not an empty set: ADR-060 is explicit
// that a segment resolution failure must never be papered over as "proceed
// org-only", and papering over it here would produce a diff reporting that
// every segment the graph found is new.
func DiffSegmentProjection(subject PrincipalID, legacySegments []string, legacyOK bool, projection SegmentProjection, projectionAdm Admission) SegmentProjectionDiff {
	// The two answers must be about the SAME principal. Nothing else in this
	// function would notice Alice's legacy set being compared against Bob's
	// projection, and it would report Identical whenever they happened to
	// match - in a function whose only purpose is producing migration
	// evidence.
	//
	// A ZERO SUBJECT ON EITHER SIDE IS INCOMPARABLE, NOT AN EXEMPTION. An
	// earlier revision skipped the check when the caller passed the zero value,
	// which made the guard opt-in from the one direction that would bypass it.
	// "No subject" is not a match; it is an unanswerable question, and that is
	// the same shape sameScopeToken applies to an empty org two files away.
	if subject.IsZero() || projection.Subject.IsZero() {
		return SegmentProjectionDiff{
			IncomparableReason: "one side names no principal, so the two answers cannot be shown to be about the same one",
		}
	}
	if projection.Subject != subject {
		return SegmentProjectionDiff{
			IncomparableReason: fmt.Sprintf("the legacy answer is for %s and the projection is for %s", subject, projection.Subject),
		}
	}
	if !legacyOK {
		return SegmentProjectionDiff{
			IncomparableReason: "the legacy resolver failed; a failed resolution is not an empty segment set",
		}
	}
	if !projectionAdm.State.IsAdmitted() {
		return SegmentProjectionDiff{
			IncomparableReason: fmt.Sprintf("the directory closure is not authoritative: %s %s", projectionAdm.State, projectionAdm.Reason),
		}
	}
	if projection.NoGraph {
		// The realm declares no group graph, so the projection is an
		// authoritative zero that the directory was never asked about.
		// Comparing it against a legacy answer would report agreement whenever
		// the legacy answer is also empty, which is what a mis-declared
		// DirectorySourceNone produces for every user in the organization.
		return SegmentProjectionDiff{
			IncomparableReason: "the realm declares no group graph, so the projection is an authoritative zero the directory was never consulted for",
		}
	}
	if !projection.Authoritative {
		// Defence in depth: an admitted Admission and a non-authoritative
		// projection disagree, and continuing would compare against a set the
		// projection itself does not vouch for.
		return SegmentProjectionDiff{
			IncomparableReason: "the projection reports itself non-authoritative while its admission accepted; the two disagree",
		}
	}

	legacy := NormalizeSegmentIDs(legacySegments)
	projected := NormalizeSegmentIDs(projection.SegmentIDs)

	inProjected := make(map[string]bool, len(projected))
	for _, id := range projected {
		inProjected[id] = true
	}
	inLegacy := make(map[string]bool, len(legacy))
	for _, id := range legacy {
		inLegacy[id] = true
	}

	diff := SegmentProjectionDiff{
		Comparable:           true,
		CrossRealmCollisions: projection.CrossRealmCollisions,
	}
	for _, id := range legacy {
		if inProjected[id] {
			diff.Both = append(diff.Both, id)
		} else {
			diff.OnlyLegacy = append(diff.OnlyLegacy, id)
		}
	}
	for _, id := range projected {
		if !inLegacy[id] {
			diff.OnlyProjected = append(diff.OnlyProjected, id)
		}
	}
	return diff
}
