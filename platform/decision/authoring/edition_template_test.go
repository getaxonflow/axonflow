// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"fmt"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// templateDocument is the shipped organization template as an organization
// document: what an organization's first draft is seeded with (PRD §1.4).
func templateDocument(t *testing.T) *Document {
	t.Helper()
	tmpl, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	// The seed is 22 CONTROLS; a template redaction ships as two policies bound
	// by discharge (#4131), so the policy count is higher.
	controls := map[string]bool{}
	for _, p := range tmpl.Policies {
		control, _, _ := legacycompile.CorpusControlOf(p.ID)
		controls[control] = true
	}
	if tmpl.Root != pdp.RootOrganization || len(controls) != 22 {
		t.Fatalf("the shipped template is %s-rooted with %d controls (%d policies); these tests are written against the 22-control organization seed",
			tmpl.Root, len(controls), len(tmpl.Policies))
	}
	return &Document{Policy: *tmpl}
}

// signalPaths returns the signal.* paths pol reads: the construct Community's
// floor refuses an organization's own policy.
func signalPaths(pol pdp.Policy) []string {
	var out []string
	for _, path := range pol.ReferencedPaths() {
		if contract.NamespaceOf(path) == contract.NsSignal {
			out = append(out, path)
		}
	}
	return out
}

func countCode(f Findings, code string) int {
	n := 0
	for _, x := range f {
		if x.Code == code {
			n++
		}
	}
	return n
}

// TestTheOrganizationTemplateIsExemptFromTheAuthoringFloors is K12 (PRD §1.4):
// a policy carried from the organization template is deployment-authored, so
// the draft an organization is seeded with passes the construct check on every
// edition, Community included.
func TestTheOrganizationTemplateIsExemptFromTheAuthoringFloors(t *testing.T) {
	d := templateDocument(t)
	// The exemption is only evidence if the template spends a construct the
	// floor refuses. Every template policy reads signal.*, which is
	// Evaluation-and-up - both halves of a redaction bound by discharge (#4131)
	// read their row's detector.
	readers := 0
	for _, pol := range d.Policy.Policies {
		if len(signalPaths(pol)) > 0 {
			readers++
		}
	}
	if readers != len(d.Policy.Policies) {
		t.Fatalf("%d of the template's %d policies read signal.*; the exemption this test asserts would be vacuous for the rest", readers, len(d.Policy.Policies))
	}
	for _, ed := range AllEditions() {
		if rej := mustProfile(t, ed).CheckConstructs(d).Rejections(); len(rej) != 0 {
			t.Errorf("the %s edition refused the template drafts are seeded with: %v", ed, rej)
		}
	}
}

// TestAnOrganizationsOwnSignalConstraintKeepsTheFloor is the other half of the
// same PRD sentence: the same template policies under ids the organization chose are
// its own, and Community refuses each of them for reading signal.*. The
// Evaluation edition accepting them is the control that the refusal is the
// floor and not something else about the document.
func TestAnOrganizationsOwnSignalConstraintKeepsTheFloor(t *testing.T) {
	d := templateDocument(t)
	for i := range d.Policy.Policies {
		d.Policy.Policies[i].ID = fmt.Sprintf("org.own.%02d", i)
	}
	rej := mustProfile(t, EditionCommunity).CheckConstructs(d).Rejections()
	if n := len(d.Policy.Policies); countCode(rej, CodeAttributeNamespaceNotInEdition) != n || len(rej) != n {
		t.Fatalf("Community raised %d %s findings (%d in all) over %d of the organization's own signal readers, want %d: %v",
			countCode(rej, CodeAttributeNamespaceNotInEdition), CodeAttributeNamespaceNotInEdition, len(rej), n, n, rej.Codes())
	}
	if rej := mustProfile(t, EditionEvaluation).CheckConstructs(d).Rejections(); len(rej) != 0 {
		t.Errorf("Evaluation refused signal readers its floor admits: %v", rej)
	}
}

// TestAnEditedTemplatePolicyKeepsTheExemptionOnlyForTheTemplatesConstructs
// pins the edit rule: a carried policy may be tuned over what its template
// policy already spends, and loses the exemption for exactly the construct an
// edit adds.
func TestAnEditedTemplatePolicyKeepsTheExemptionOnlyForTheTemplatesConstructs(t *testing.T) {
	community := mustProfile(t, EditionCommunity)

	t.Run("a tuning edit over the same paths keeps it", func(t *testing.T) {
		d := templateDocument(t)
		pol := &d.Policy.Policies[0]
		pol.Where = pdp.Not(pol.Where)
		pol.Description = "re-actioned by the organization"
		if rej := community.CheckConstructs(d).Rejections(); len(rej) != 0 {
			t.Fatalf("an edit that spends nothing the template policy does not was refused: %v", rej)
		}
	})

	t.Run("reading another template policy's path loses it for that path", func(t *testing.T) {
		d := templateDocument(t)
		own, other := &d.Policy.Policies[0], d.Policy.Policies[1]
		borrowed := signalPaths(other)[0]
		for _, p := range signalPaths(*own) {
			if p == borrowed {
				t.Fatalf("policies 0 and 1 share %s; pick two that do not", borrowed)
			}
		}
		own.Where = pdp.And(own.Where, pdp.Compare(borrowed, pdp.OpEq, true))
		rej := community.CheckConstructs(d).Rejections()
		if len(rej) != 1 || rej[0].Code != CodeAttributeNamespaceNotInEdition || rej[0].PolicyID != own.ID ||
			!strings.Contains(rej[0].Detail, borrowed) {
			t.Fatalf("want one %s on %s naming %s; the exemption is per template policy, not per template: got %+v",
				CodeAttributeNamespaceNotInEdition, own.ID, borrowed, rej)
		}
	})

	t.Run("a template id at another root carries nothing", func(t *testing.T) {
		d := templateDocument(t)
		d.Policy.Root = pdp.RootSystem
		if got, want := countCode(community.CheckConstructs(d).Rejections(), CodeAttributeNamespaceNotInEdition), len(d.Policy.Policies); got != want {
			t.Fatalf("a system-root document carrying template ids raised %d namespace findings, want %d: the template seeds organization documents only", got, want)
		}
	})
}

// TestTheCarriedSpendCoversObligationFamiliesAndGroupScope drives the two
// carve-outs the shipped template does not exercise on Community today: its
// obligation families (disclosure, audit) are Community's already and none of
// its policies is group-scoped. The PRD exempts a carried policy from every
// authoring floor, so a template that grew either would need them.
func TestTheCarriedSpendCoversObligationFamiliesAndGroupScope(t *testing.T) {
	community := mustProfile(t, EditionCommunity)
	pol := pdp.Policy{
		ID:          "tmpl.synthetic",
		Obligations: []contract.Obligation{quotaObligation("tmpl.synthetic")},
		Scope:       pdp.Scope{Groups: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::realm:ops")}},
	}
	own := checkPolicyConstructs(pol, community, nil)
	if !own.Has(CodeObligationFamilyNotInEdition) || !own.Has(CodeGroupScopeNotInEdition) {
		t.Fatalf("the organization's own policy must be refused both constructs on Community; got %v", own.Codes())
	}
	carried := &templateSpend{
		paths:    map[string]bool{},
		families: map[contract.ObligationFamily]bool{contract.FamilyBudget: true},
		groups:   true,
	}
	if got := checkPolicyConstructs(pol, community, carried).Rejections(); len(got) != 0 {
		t.Fatalf("constructs the template policy itself spends were refused: %v", got.Codes())
	}
}
