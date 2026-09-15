// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// EVERY IDENTIFIER A POLICY NAMES IS VALIDATED, AND ITS KIND IS CHECKED (#3711).
//
// Two separate refusals, because they are two separate author mistakes: an
// identifier can be well formed and in the wrong field, and it can be in the
// right field and malformed. The authoring layer relays them as
// IDENTIFIER_WRONG_KIND and MALFORMED_IDENTIFIER.
//
// These live here rather than only in authoring's declared-check table because
// that table admits ONE case per code, so it cannot hold both halves of one
// rule - and a half nothing exercises is a half a mutant survives. R3 round 2
// found exactly that: disabling the kind comparison left every suite green.
func TestAPolicyIdentifierOfTheWrongKindIsRefused(t *testing.T) {
	resource := contract.MustParseID(contract.KindResource, "Ticket::jira:T-1")
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	group := contract.MustParseID(contract.KindGroup, "Group::realm_ws:support-tier2")
	action := contract.MustParseID(contract.KindAction, "Action::stripe.create_refund")

	cases := []struct {
		name  string
		field string
		apply func(p *Policy)
	}{
		{"a resource in scope.principals", "scope.principals", func(p *Policy) { p.Scope = Scope{Principals: []contract.ID{resource}} }},
		{"a principal in scope.groups", "scope.groups", func(p *Policy) { p.Scope = Scope{Groups: []contract.ID{principal}} }},
		{"a resource in the action selector", "actions", func(p *Policy) { p.Actions = ActionSelector{Actions: []contract.ID{resource}} }},
		{"a principal in pierceable_by", "pierceable_by", func(p *Policy) { p.PierceableBy = []contract.ID{principal} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := testDoc()
			p := &d.Policies[0]
			tc.apply(p)
			errs := d.Validate()
			var found bool
			for _, e := range errs {
				if e.Rule == RuleIdentifierWrongKind && strings.Contains(e.Detail, tc.field) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s was accepted; a well-formed identifier in the wrong field is not malformed, so only the KIND comparison can refuse it (errors: %v)", tc.name, errs)
			}
		})
	}

	// The positive control: the same policy with the RIGHT kinds in the right
	// fields raises neither identifier rule, so the checks above are not simply
	// refusing every document.
	d := testDoc()
	p := &d.Policies[0]
	p.Scope = Scope{Principals: []contract.ID{principal}, Groups: []contract.ID{group}}
	p.Actions = ActionSelector{Actions: []contract.ID{action}}
	for _, e := range d.Validate() {
		if e.Rule == RuleIdentifierWrongKind || e.Rule == RuleMalformedIdentifier {
			t.Errorf("a policy naming the right kinds in the right fields was refused: %s %s", e.Rule, e.Detail)
		}
	}
}

// The FORM half: a principal type outside the closed vocabulary, in the right
// field and of the right kind, is refused as malformed.
func TestAPolicyPrincipalOutsideTheVocabularyIsRefused(t *testing.T) {
	d := testDoc()
	// Built field by field: ParseID refuses this now, and the point is that a
	// hand-written or machine-generated document can still carry it.
	d.Policies[0].Scope = Scope{Principals: []contract.ID{{
		Kind: contract.KindPrincipal, Type: "Robot", Qualifier: "acme", Local: "r1",
	}}}
	var found bool
	for _, e := range d.Validate() {
		if e.Rule == RuleMalformedIdentifier && strings.Contains(e.Detail, "Robot") {
			found = true
		}
	}
	if !found {
		t.Error("a policy scoped to a principal type outside the closed vocabulary was accepted; the compiler reads Scope.Principals through ID.String() with no Kind and no Validate, so nothing downstream would catch it")
	}
}
