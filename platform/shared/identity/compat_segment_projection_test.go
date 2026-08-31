// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"strings"
	"testing"
)

func projectionSubject(t *testing.T) PrincipalID {
	t.Helper()
	p, err := NewPrincipalID(realmWorkspace, SubjectUser, "user-1138")
	if err != nil {
		t.Fatalf("NewPrincipalID: %v", err)
	}
	return p
}

func groupPrincipal(t *testing.T, realm RealmID, scimGroupID string) PrincipalID {
	t.Helper()
	p, err := NewPrincipalID(realm, SubjectGroup, scimGroupID)
	if err != nil {
		t.Fatalf("NewPrincipalID: %v", err)
	}
	return p
}

// TestProjectSegmentsFlattensAnAuthoritativeClosure: the segment id is the
// group principal's SUBJECT, which the SCIM ingestion adapter makes the SCIM
// `id` precisely so the legacy resolver's scim_groups.id and this line up.
func TestProjectSegmentsFlattensAnAuthoritativeClosure(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewAuthoritativeClosure(subject, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-b"),
		groupPrincipal(t, realmWorkspace, "grp-a"),
		groupPrincipal(t, realmWorkspace, "grp-a"), // a duplicate must collapse
	}, nil, nil, 2, "scim/v7", fixtureNow)

	proj, adm := ProjectSegments(closure)
	if !adm.State.IsAdmitted() {
		t.Fatalf("admission = %s %s", adm.State, adm.Reason)
	}
	if !proj.Authoritative {
		t.Fatalf("an authoritative closure projected as non-authoritative")
	}
	if got := strings.Join(proj.SegmentIDs, ","); got != "grp-a,grp-b" {
		t.Fatalf("segments = %q, want the deduped, sorted set", got)
	}
	if proj.SourceVersion != "scim/v7" {
		t.Fatalf("source version = %q", proj.SourceVersion)
	}
	if len(proj.CrossRealmCollisions) != 0 {
		t.Fatalf("collisions = %v", proj.CrossRealmCollisions)
	}
}

// TestProjectSegmentsNoGraphIsAnAuthoritativeZero is EX-45: a realm that
// declares no group graph produces an empty set that is AUTHORITATIVE, not an
// outage.
func TestProjectSegmentsNoGraphIsAnAuthoritativeZero(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewNoGraphClosure(subject, cloudIAMRealm(), fixtureNow)

	proj, adm := ProjectSegments(closure)
	if !adm.State.IsAdmitted() {
		t.Fatalf("a no-graph closure was not admitted: %s %s", adm.State, adm.Reason)
	}
	if !proj.Authoritative {
		t.Fatalf("a no-graph projection is not authoritative")
	}
	if proj.SegmentIDs != nil {
		t.Fatalf("segments = %v, want nil", proj.SegmentIDs)
	}
}

// TestProjectSegmentsRefusesANonAuthoritativeClosure: a truncated or
// unreachable closure must never project as an empty or partial list, because
// a ceiling scoped to a segment that was not enumerated would silently not
// apply.
func TestProjectSegmentsRefusesANonAuthoritativeClosure(t *testing.T) {
	subject := projectionSubject(t)
	partial := []PrincipalID{groupPrincipal(t, realmWorkspace, "grp-a")}

	for _, tc := range []struct {
		name    string
		closure ClosureResult
	}{
		{"truncated", NewTruncatedClosure(subject, partial, nil, nil, 3, "bound hit", "scim/v7", fixtureNow)},
		{"unreachable", NewUnreachableClosure(subject, "SCIM outage", fixtureNow)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proj, adm := ProjectSegments(tc.closure)
			if adm.State.IsAdmitted() {
				t.Fatalf("a %s closure was admitted", tc.name)
			}
			if proj.Authoritative {
				t.Fatalf("a %s closure projected as authoritative", tc.name)
			}
			if proj.SegmentIDs != nil {
				t.Fatalf("a %s closure leaked a partial segment set: %v", tc.name, proj.SegmentIDs)
			}
		})
	}
}

// TestProjectSegmentsReportsCrossRealmCollisions: the projection drops realm
// qualification, so two realms holding the same SCIM id flatten onto one
// segment. That is a silent widening if it goes unreported.
func TestProjectSegmentsReportsCrossRealmCollisions(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewAuthoritativeClosure(subject, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-shared"),
		groupPrincipal(t, realmCloudIAM, "grp-shared"),
		groupPrincipal(t, realmWorkspace, "grp-unique"),
	}, nil, nil, 1, "scim/v7", fixtureNow)

	proj, adm := ProjectSegments(closure)
	if !adm.State.IsAdmitted() {
		t.Fatalf("admission = %s", adm.State)
	}
	if len(proj.CrossRealmCollisions) != 1 || proj.CrossRealmCollisions[0] != "grp-shared" {
		t.Fatalf("collisions = %v, want [grp-shared]", proj.CrossRealmCollisions)
	}
	if got := strings.Join(proj.SegmentIDs, ","); got != "grp-shared,grp-unique" {
		t.Fatalf("segments = %q", got)
	}
}

// --- the diff ---

func TestDiffSegmentProjectionAgreement(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewAuthoritativeClosure(subject, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-a"),
		groupPrincipal(t, realmWorkspace, "grp-b"),
	}, nil, nil, 1, "scim/v7", fixtureNow)
	proj, adm := ProjectSegments(closure)

	// Deliberately unsorted and duplicated on the legacy side: both answers go
	// through the same canonical form, so an ordering difference is not a
	// difference.
	diff := DiffSegmentProjection(subject, []string{"grp-b", "grp-a", "grp-a"}, true, proj, adm)
	if !diff.Identical() {
		t.Fatalf("diff = %s, want identical", diff)
	}
	if len(diff.Both) != 2 {
		t.Fatalf("both = %v", diff.Both)
	}
}

func TestDiffSegmentProjectionReportsBothDirections(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewAuthoritativeClosure(subject, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-a"),
		groupPrincipal(t, realmWorkspace, "grp-new"),
	}, nil, nil, 1, "scim/v7", fixtureNow)
	proj, adm := ProjectSegments(closure)

	diff := DiffSegmentProjection(subject, []string{"grp-a", "grp-gone"}, true, proj, adm)
	if diff.Identical() {
		t.Fatalf("a real difference reported as identical")
	}
	if len(diff.OnlyLegacy) != 1 || diff.OnlyLegacy[0] != "grp-gone" {
		t.Fatalf("only_legacy = %v, want [grp-gone]", diff.OnlyLegacy)
	}
	if len(diff.OnlyProjected) != 1 || diff.OnlyProjected[0] != "grp-new" {
		t.Fatalf("only_projected = %v, want [grp-new]", diff.OnlyProjected)
	}
	if len(diff.Both) != 1 || diff.Both[0] != "grp-a" {
		t.Fatalf("both = %v", diff.Both)
	}
}

// TestDiffSegmentProjectionIncomparability is the load-bearing half: a
// resolution FAILURE on either side is not zero differences and is not an
// empty set. ADR-060 is explicit that a segment resolution failure must never
// be papered over as "proceed org-only", and papering over it here would
// report every segment the graph found as new.
func TestDiffSegmentProjectionIncomparability(t *testing.T) {
	subject := projectionSubject(t)
	good := NewAuthoritativeClosure(subject, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-a"),
	}, nil, nil, 1, "scim/v7", fixtureNow)
	goodProj, goodAdm := ProjectSegments(good)

	t.Run("the legacy resolver failed", func(t *testing.T) {
		diff := DiffSegmentProjection(subject, nil, false, goodProj, goodAdm)
		if diff.Comparable || diff.Identical() {
			t.Fatalf("a legacy failure compared as %s", diff)
		}
		if diff.IncomparableReason == "" {
			t.Fatalf("no reason given")
		}
	})

	t.Run("the closure is not authoritative", func(t *testing.T) {
		bad := NewUnreachableClosure(subject, "SCIM outage", fixtureNow)
		badProj, badAdm := ProjectSegments(bad)
		diff := DiffSegmentProjection(subject, []string{"grp-a"}, true, badProj, badAdm)
		if diff.Comparable || diff.Identical() {
			t.Fatalf("a non-authoritative closure compared as %s", diff)
		}
	})

	t.Run("an admitted admission with a non-authoritative projection disagree", func(t *testing.T) {
		// Defence in depth: a hand-built pair that disagrees must not be
		// compared against a set the projection itself does not vouch for.
		diff := DiffSegmentProjection(subject, []string{"grp-a"}, true,
			SegmentProjection{Subject: subject, Authoritative: false}, AcceptAdmission(subject))
		if diff.Comparable {
			t.Fatalf("a disagreeing pair was compared")
		}
	})
}

// TestDiffSegmentProjectionZeroValueIsNotAgreement: the zero SegmentProjection
// has Authoritative false, so a consumer that forgets the Admission still
// cannot read a refusal as a legitimate empty set.
func TestDiffSegmentProjectionZeroValueIsNotAgreement(t *testing.T) {
	var zero SegmentProjection
	if zero.Authoritative {
		t.Fatalf("the zero projection claims to be authoritative")
	}
	var zeroDiff SegmentProjectionDiff
	if zeroDiff.Identical() {
		t.Fatalf("the zero diff reports the two answers as identical")
	}
}

// TestDiffSegmentProjectionRefusesANoGraphProjection is the EX-45 half of the
// diff. A realm declaring no group graph produces an authoritative empty
// projection, and against a legacy resolver that also returned nothing the
// diff would report Identical - reading as "the graph reproduces the resolver"
// for a graph that was never consulted. That is exactly what a mis-declared
// DirectorySourceNone produces for every user in an organization.
func TestDiffSegmentProjectionRefusesANoGraphProjection(t *testing.T) {
	subject := projectionSubject(t)
	closure := NewNoGraphClosure(subject, cloudIAMRealm(), fixtureNow)
	proj, adm := ProjectSegments(closure)
	if !proj.NoGraph {
		t.Fatalf("a no-graph closure did not project as NoGraph")
	}

	diff := DiffSegmentProjection(subject, nil, true, proj, adm)
	if diff.Comparable || diff.Identical() {
		t.Fatalf("a no-graph projection compared as %s", diff)
	}
	if diff.IncomparableReason == "" {
		t.Fatalf("no reason given")
	}

	// The control: an authoritative closure over a realm that DOES have a
	// graph, resolving to nothing, IS comparable. Without this the fix could
	// be "refuse every empty projection", which would make the diff useless
	// for every user with no groups.
	real := NewAuthoritativeClosure(subject, nil, nil, nil, 0, "scim/v7", fixtureNow)
	realProj, realAdm := ProjectSegments(real)
	if realProj.NoGraph {
		t.Fatalf("a traversal that ran and found nothing was reported as NoGraph")
	}
	if d := DiffSegmentProjection(subject, nil, true, realProj, realAdm); !d.Identical() {
		t.Fatalf("a genuine empty closure was not comparable: %s", d)
	}
}

// TestDiffSegmentProjectionRefusesAMismatchedSubject: for a function whose only
// purpose is producing migration evidence, comparing two different people and
// reporting Identical is the worst available answer.
func TestDiffSegmentProjectionRefusesAMismatchedSubject(t *testing.T) {
	alice := projectionSubject(t)
	bob, err := NewPrincipalID(realmWorkspace, SubjectUser, "user-other")
	if err != nil {
		t.Fatalf("NewPrincipalID: %v", err)
	}
	closure := NewAuthoritativeClosure(bob, []PrincipalID{
		groupPrincipal(t, realmWorkspace, "grp-a"),
	}, nil, nil, 1, "scim/v7", fixtureNow)
	proj, adm := ProjectSegments(closure)

	diff := DiffSegmentProjection(alice, []string{"grp-a"}, true, proj, adm)
	if diff.Comparable || diff.Identical() {
		t.Fatalf("one subject's legacy answer was compared against another's projection: %s", diff)
	}

	// A ZERO SUBJECT IS INCOMPARABLE, NOT AN EXEMPTION. An earlier revision
	// skipped the same-principal check when the caller passed the zero value,
	// which made the guard opt-in from the one direction that bypasses it -
	// and the sets would then be compared and could report Identical whenever
	// they happened to match.
	if d := DiffSegmentProjection(PrincipalID{}, []string{"grp-a"}, true, proj, adm); d.Comparable || d.Identical() {
		t.Fatalf("a zero legacy subject bypassed the same-principal check: %s", d)
	}
	zeroProj := proj
	zeroProj.Subject = PrincipalID{}
	if d := DiffSegmentProjection(alice, []string{"grp-a"}, true, zeroProj, adm); d.Comparable || d.Identical() {
		t.Fatalf("a zero projection subject bypassed the same-principal check: %s", d)
	}
	// THE CASE THE MISMATCH CHECK CANNOT SEE. When BOTH sides are the zero
	// value they are EQUAL, so the not-equal comparison passes and the two
	// sets are compared as though they were about the same principal - which
	// neither of them names. This is the input that makes the zero check
	// load-bearing rather than redundant.
	if d := DiffSegmentProjection(PrincipalID{}, []string{"grp-a"}, true, zeroProj, adm); d.Comparable || d.Identical() {
		t.Fatalf("two ZERO subjects compared as the same principal: %s", d)
	}
}
