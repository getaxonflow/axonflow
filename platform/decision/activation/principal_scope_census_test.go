// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"sort"
	"testing"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// THE #3936 REACHABILITY TRIPWIRE, OVER WHAT AN ANCHORED ENGINE ACTIVATES.
//
// pdp.compileScope renders a policy's scope principals into a string equality
// on principal.id, and ID.String() renders the principal TYPE, so a policy
// naming User::acme:alice does not apply to the same subject presented as
// Service::acme:alice. #3936 left that uncorrected because no production path
// compiles a principal scope onto a decision.
//
// legacycompile.TestNoCompilerPathConstructsAPrincipalScope holds the
// compiler's half of that fact structurally. This holds the other half over the
// documents themselves: every system-authored document an anchored engine
// activates - the shipped system corpus, the organization template and the
// baseline permission pack - and so every restriction of them too, since a
// restriction only ever leaves policies out. The shipped corpus is compiled from
// a real capture and held byte-identical to one
// (legacycompile.TestRegenerateTheShippedCorpusArtifact), so this is the
// real-capture census, run on every change rather than behind a capture.
func TestNoActivatedDocumentSelectsOnNamedPrincipals(t *testing.T) {
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatalf("the shipped corpus: %v", err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("the organization template: %v", err)
	}
	pack, err := authoringcatalog.BaselinePermissionPack(snapshot(t))
	if err != nil {
		t.Fatalf("the baseline permission pack: %v", err)
	}
	censused := 0
	for _, d := range []struct {
		name string
		doc  *pdp.Document
	}{
		{"the shipped system corpus", corpus},
		{"the organization template", template},
		{"the baseline permission pack", pack},
	} {
		// THE DENOMINATOR IS READ BEFORE THE NUMERATOR: an empty document
		// produces an empty offender list, which reads exactly like a clean one.
		if d.doc == nil || len(d.doc.Policies) == 0 {
			t.Fatalf("%s carries no policy, so the census below would be vacuous", d.name)
		}
		censused += len(d.doc.Policies)
		if bad := principalScopedPolicies(d.doc.Policies); len(bad) > 0 {
			t.Errorf(`%s: %d policy(ies) select on named principals: %v

#3936 IS NOW LIVE AND ITS RULING NO LONGER HOLDS. pdp.compileScope renders a
scope principal into a string equality on principal.id INCLUDING the principal
type, so such a policy applies to one classification of a subject and not to
another spelling of the same subject. Re-open #3936 and decide the currency
before this ships: the fix has to move pdp.compileScope and authoring.sharesID /
containsAllIDs together, with a test for a policy that STARTS applying and one
that STOPS.`, d.name, len(bad), bad)
		}
	}
	t.Logf("censused %d policies across the three system-authored documents", censused)
}

// TestThePrincipalScopeScannerSeesAPlantedScope is the census's control: the
// census passes when principalScopedPolicies returns nothing, which a scanner
// that cannot see a principal scope would also do.
func TestThePrincipalScopeScannerSeesAPlantedScope(t *testing.T) {
	planted := []pdp.Policy{
		{ID: "not-principal-scoped", Scope: pdp.Scope{Organization: true}},
		{ID: "planted-principal-scope", Scope: pdp.Scope{Principals: []contract.ID{
			contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice"),
		}}},
	}
	if got := principalScopedPolicies(planted); len(got) != 1 || got[0] != "planted-principal-scope" {
		t.Fatalf("the scanner returned %v for a population with exactly one principal-scoped policy; want [planted-principal-scope]", got)
	}
	if got := principalScopedPolicies(planted[:1]); len(got) != 0 {
		t.Fatalf("the scanner reports %v for a population with no principal scope; it would fire on anything", got)
	}
}

// principalScopedPolicies returns the ids of the policies that select on named
// principals, sorted. It takes the policies as an argument so the control can
// drive the same function over a planted population.
func principalScopedPolicies(policies []pdp.Policy) []string {
	var out []string
	for _, p := range policies {
		if len(p.Scope.Principals) > 0 {
			out = append(out, p.ID)
		}
	}
	sort.Strings(out)
	return out
}
