// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheExportedConstructCheckIsTheOnePublicationRuns is the property that
// makes activation's check worth having.
//
// activation cannot import the unexported checkEditionConstructs, so it calls
// Profile.CheckConstructs. If those two ever became different functions - one
// rewritten, one forgotten - a document would be refused at one door and
// admitted at the other, and the operator-facing sentence would differ between
// them. Asserting they return the same findings for the same document is what
// stops the exported wrapper drifting into a second implementation.
func TestTheExportedConstructCheckIsTheOnePublicationRuns(t *testing.T) {
	community := mustProfile(t, EditionCommunity)
	doc := organizationDocumentWith(t, baseCatalog(t), func(_ *Metadata, d *pdp.Document) {
		if len(d.Policies) == 0 {
			t.Fatal("the fixture document carries no policy to scope")
		}
		// Group scope floors at Enterprise (groupScopeFloor), so this is a
		// construct Community may not spend - the cheapest one to state.
		d.Policies[0].Scope.Groups = []contract.ID{gid(t, "Group::acme:finance")}
	})

	internal := checkEditionConstructs(doc, community)
	exported := community.CheckConstructs(doc)

	if len(internal) == 0 {
		t.Fatal("the fixture produced no findings on Community, so this test would pass against any pair of " +
			"functions; the fixture no longer spends a construct Community lacks")
	}
	if len(internal) != len(exported) {
		t.Fatalf("the exported check returned %d findings and the internal one %d", len(exported), len(internal))
	}
	for i := range internal {
		if internal[i] != exported[i] {
			t.Errorf("finding %d differs: internal %+v, exported %+v", i, internal[i], exported[i])
		}
	}
	if !exported.Has(CodeGroupScopeNotInEdition) {
		t.Errorf("the exported check returned %v, and not %s; the fixture or the table moved",
			exported.Codes(), CodeGroupScopeNotInEdition)
	}
}

// TestTheExportedCheckIsSilentOnTheEditionThatCarriesTheConstruct is the
// positive control for the test above: without it, a wrapper that returned
// every document's findings unconditionally would satisfy the comparison.
func TestTheExportedCheckIsSilentOnTheEditionThatCarriesTheConstruct(t *testing.T) {
	enterprise := mustProfile(t, EditionEnterprise)
	doc := organizationDocumentWith(t, baseCatalog(t), func(_ *Metadata, d *pdp.Document) {
		d.Policies[0].Scope.Groups = []contract.ID{gid(t, "Group::acme:finance")}
	})
	if got := enterprise.CheckConstructs(doc); len(got) != 0 {
		t.Errorf("Enterprise refused its own construct: %v", got.Codes())
	}
}

// TestValidateRefusesTheZeroProfile pins the exported validator.
//
// It exists because Profile now crosses a package boundary: activation takes
// one and must refuse a zero value rather than read it as an edition. validate
// is unexported, so without this wrapper the only check available to a caller
// outside this package would be to guess at the edition string.
func TestValidateRefusesTheZeroProfile(t *testing.T) {
	var zero Profile
	if err := zero.Validate(); err == nil {
		t.Error("the zero-value Profile validated; a caller that forgot to set one would get " +
			"\"Community constructs, duties on\" without ever declaring it")
	}
	if err := mustProfile(t, EditionCommunity).Validate(); err != nil {
		t.Errorf("a profile this package constructed did not validate: %v", err)
	}
	// The unestablished profile is a real profile and must validate: it is what
	// a process resolves to when it cannot establish its tier, and refusing it
	// here would turn a fallback into a failure.
	if err := ProfileForUnestablishedTier().Validate(); err != nil {
		t.Errorf("the unestablished-tier profile did not validate: %v", err)
	}
}
