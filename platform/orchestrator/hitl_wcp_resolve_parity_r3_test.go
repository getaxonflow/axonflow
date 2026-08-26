// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// R3 round 2 regression pins for the two blockers the entitlement change
// created. Both are the round-1 pattern: the fix for one defect made the next.
//
// Edition-neutral on purpose. The defect in the first pin was that the two
// build tags disagreed about a field in the published API contract, so a test
// that only ever compiles under one tag cannot see it.

package orchestrator

import (
	"os"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
)

// TestHITLResolveIsNotGatedOnTheCreationEntitlement pins the predicate that
// separates RESOLVING an approval from CREATING one.
//
// The 2026-08-26 operator decision made HITL Enterprise-only. Applied to
// resolution it strands rows: a deployment holding pending approvals at
// upgrade time loses approve, reject and the pending list in the same release,
// so the entries can never be cleared and their workflows can never proceed -
// verbatim the phantom-row defect #3408 exists to close, reintroduced by the
// entitlement change itself.
//
// Evaluation is the case that matters and is asserted explicitly: it is the
// tier the decision REMOVES creation from, so it is exactly the tier that will
// be holding rows it can no longer add to.
func TestHITLResolveIsNotGatedOnTheCreationEntitlement(t *testing.T) {
	for _, tc := range []struct {
		tier       license.Tier
		mayResolve bool
		why        string
	}{
		{license.TierEvaluation, true, "holds rows it may no longer create; must be able to drain them"},
		{license.TierProfessional, true, "entitled to create, so certainly entitled to resolve"},
		{license.TierEnterprise, true, "entitled"},
		{license.TierEnterprisePlus, true, "entitled"},
		{license.TierCommunity, false, "below Evaluation; unchanged by this release"},
	} {
		got := hitlResolveAllowed(stubTierChecker{tier: tc.tier})
		if got != tc.mayResolve {
			t.Errorf("hitlResolveAllowed(%s) = %v, want %v (%s)",
				tc.tier, got, tc.mayResolve, tc.why)
		}

		// The creation entitlement must be STRICTLY NARROWER. If the two ever
		// coincide the separation has collapsed and the stranding returns,
		// whichever direction it collapsed in.
		if license.IsHITLApprovalEntitled(tc.tier) && !got {
			t.Errorf("tier %s may CREATE approvals but may not RESOLVE them - "+
				"a deployment could add entries it cannot clear", tc.tier)
		}
	}

	// Evaluation is the pin that fails if someone unifies the predicates.
	if !hitlResolveAllowed(stubTierChecker{tier: license.TierEvaluation}) {
		t.Error("Evaluation cannot resolve: pending approvals are stranded, #3408 reintroduced")
	}
	if license.IsHITLApprovalEntitled(license.TierEvaluation) {
		t.Error("Evaluation is entitled to CREATE: the operator decision has been reverted")
	}
}

// TestNilTierCheckerCannotResolve - no tier resolved is not a licence to act.
func TestNilTierCheckerCannotResolve(t *testing.T) {
	if hitlResolveAllowed(nil) {
		t.Error("a nil licence checker was allowed to resolve approvals; must fail closed")
	}
}

// TestMAPAndWCPShareTheResolvePredicate is a SOURCE census, and it is a source
// census because the defect it pins was invisible to behavioural tests.
//
// Round 1 fixed the WCP registration and left the three MAP handlers on
// IsHITLApprovalEnabled. On DEPLOYMENT_MODE=community with an Evaluation
// licence, WCP drained and MAP returned 403 - while the MAP comment directly
// above the gate still asserted "Now both planes accept Evaluation+". Every
// existing test passed, because no test compared the two planes.
//
// Reading the source is the only way to assert "these two call sites agree
// about which predicate governs them" without booting both planes.
func TestMAPAndWCPShareTheResolvePredicate(t *testing.T) {
	mapSrc := mustReadSource(t, "map_hitl_adapter.go")
	runSrc := mustReadSource(t, "run.go")

	// All three MAP resolve handlers (approve, reject, pending list).
	if n := strings.Count(mapSrc, "!hitlResolveAllowed(tierChecker)"); n != 3 {
		t.Errorf("MAP resolve gates using the shared predicate = %d, want 3; "+
			"a handler has drifted onto its own tier check", n)
	}

	// And the WCP registration.
	if !strings.Contains(runSrc, "hitlResolveAllowed(tierChecker)") {
		t.Error("run.go no longer gates the WCP Evaluation routes on hitlResolveAllowed; " +
			"the two planes can now disagree for an Evaluation licensee")
	}

	// The creation entitlement must not reappear as a gate on either plane.
	// Comments are stripped first: this file and map_hitl_adapter.go both
	// NAME the retired predicate in prose explaining why it is not used, and
	// a naive substring search would match that prose and fail for ever.
	if s := stripGoComments(mapSrc); strings.Contains(s, "IsHITLApprovalEnabled()") {
		t.Error("map_hitl_adapter.go gates on IsHITLApprovalEnabled again: " +
			"an Evaluation deployment's pending MAP approvals are stranded")
	}
}

// stripGoComments removes // line comments and /* */ block comments.
//
// Block comments are stripped FIRST. Doing it the other way round lets a `/*`
// inside a `//` comment open a block state that never closes and swallow the
// rest of the file - the defect that hid 303 lines from the #3334 migration
// guard until its fourth hostile round.
func stripGoComments(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '*' {
			if j := strings.Index(s[i+2:], "*/"); j >= 0 {
				i += 2 + j + 2
				b.WriteByte(' ')
				continue
			}
			break
		}
		if s[i] == '/' && i+1 < len(s) && s[i+1] == '/' {
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				break
			}
			i += j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func mustReadSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	// An empty read would make every assertion below vacuous.
	if len(b) < 1000 {
		t.Fatalf("%s is %d bytes; the census would assert nothing", name, len(b))
	}
	return string(b)
}

// stubTierChecker is the whole of what hitlResolveAllowed reads.
type stubTierChecker struct{ tier license.Tier }

func (s stubTierChecker) Tier() license.Tier { return s.tier }

// TestResolveRefusalNamesTheTierThatWouldWork pins the remedy in the refusal,
// not just the status code.
//
// R3 round 2 changed these three MAP handlers from the creation entitlement to
// hitlResolveAllowed but left their message saying "requires a Professional,
// Enterprise or Enterprise Plus license". After the gate change only Community
// can reach that refusal - and Community was being told to buy Professional
// when the FREE Evaluation licence is enough to reach the endpoint. A refusal
// that names the wrong remedy is worse than one that names none: it sells an
// upgrade the caller does not need to solve the problem they have.
//
// Every existing test asserted only the 403. A status code cannot tell you the
// body is lying.
func TestResolveRefusalNamesTheTierThatWouldWork(t *testing.T) {
	msg := mapHITLResolveRefusal("MAP step approval")

	// The tier that actually clears this gate must be named.
	if !strings.Contains(msg, "Evaluation") {
		t.Errorf("refusal does not name Evaluation, the lowest tier that clears "+
			"this gate: %q", msg)
	}

	// And the sentence about the REFUSED ACTION must not present the creation
	// entitlement as its requirement. Scoped to the first sentence on purpose:
	// the message legitimately names Professional later, in the clause that
	// explains what CREATING needs, and a whole-string search would flag that
	// correct half. The first version of this assertion did exactly that and
	// failed against the fixed message - a reminder that an assertion aimed at
	// the wrong span is as wrong as no assertion.
	first := msg
	if i := strings.Index(msg, ". "); i >= 0 {
		first = msg[:i]
	}
	if strings.Contains(first, "Professional") {
		t.Errorf("the refusal's own sentence names Professional as the "+
			"requirement; a Community caller is told to buy Professional when "+
			"Evaluation would do: %q", first)
	}

	// The distinction is the point, so the message has to carry both halves.
	if !strings.Contains(msg, "CREATING") {
		t.Errorf("refusal does not distinguish creating from resolving, so a "+
			"reader cannot tell which entitlement they actually need: %q", msg)
	}
}
