// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// WHAT A SCOPE PRINCIPAL ACTUALLY SELECTS (#3936).
//
// compileScope renders a scope principal into `principal.id == "<rendered
// form>"`, and the rendered form carries the principal TYPE. So the equality
// that decides whether a policy APPLIES to a subject also decides whether the
// subject was CLASSIFIED the way the author wrote them down.
//
// This file executes that rather than describing it. The reachability ruling
// recorded on #3936 rests on the claim that folding the type would change
// targeting in both directions at once, and a claim about behaviour that is
// only ever read is the kind that turns out to be false. Everything below runs
// through a real signed bundle, a real trust store and the real evaluator.
//
// IT IS ALSO THE MARKER. If the currency is ever changed - at the #3564
// cutover, or because one of the three reachability tripwires fires - these
// expectations invert, and inverting them is a deliberate edit a reviewer sees
// rather than a silent widening. The tripwires are:
//
//   - shadow.TestNoCompiledDocumentSelectsOnNamedPrincipals, for a compiler
//     that starts emitting a principal scope onto a live path;
//   - identity.TestEveryShippedRealmAcceptsOnlyTheTypeItMints, for a realm
//     that starts accepting a type it cannot mint;
//   - shadow.TestNoLegacyConditionFieldOverwritesTheCanonicalPrincipal, for a
//     producer that puts something other than a rendered principal on
//     principal.id.

func scopePrincipalTypeDoc(scoped string) *Document {
	return &Document{
		Root:    RootSystem,
		Version: 1,
		Attributes: []AttributeSchema{
			{Path: "principal.id", Type: TypeString},
			{Path: "action.id", Type: TypeString},
			{Path: "action.tags", Type: TypeArray},
		},
		Policies: []Policy{
			{
				ID:        "P_SCOPED",
				Authority: contract.AuthorityPermission,
				Root:      RootSystem,
				Scope:     Scope{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, scoped)}},
				Actions:   ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::stripe.create_refund")}},
				Where:     Compare("action.id", OpEq, "Action::stripe.create_refund"),
			},
		},
	}
}

func scopePrincipalTypeRequest(spelling string) *contract.Request {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	principal := contract.MustParseID(contract.KindPrincipal, spelling)
	return &contract.Request{
		RequestID:    "req_3936",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::jira:T-1"),
		Context: contract.Context{ActorChain: []contract.Actor{{
			ID: principal,
			Attributes: contract.AttributeSet{
				"principal.id": contract.Known(principal.String(), contract.ProvAuthentication, 1, now),
			},
		}}},
		Snapshot: contract.Snapshot{
			SchemaVersion: contract.SchemaVersion,
			PolicyBundle:  "sha256:deadbeef",
		},
		Attributes: contract.AttributeSet{
			"action.id":   contract.Known("Action::stripe.create_refund", contract.ProvPlatform, 18, now),
			"action.tags": contract.Known([]any{"spend"}, contract.ProvPlatform, 18, now),
		},
		EvaluatedAt: now,
	}
}

// TestAScopePrincipalSelectsOnTheRenderedFormIncludingTheType is the measured
// statement of #3936.
//
// Both directions are driven from ONE scoped policy: the spelling the author
// wrote is permitted and every OTHER classification of the SAME subject in the
// SAME realm is not applicable. A single-direction test could not tell a
// currency that carries the type from one that does not - the permit arm passes
// either way.
func TestAScopePrincipalSelectsOnTheRenderedFormIncludingTheType(t *testing.T) {
	const scoped = "User::realm_ws:alice"
	e := buildTestEngine(t, scopePrincipalTypeDoc(scoped))

	dec, err := e.Decide(context.Background(), scopePrincipalTypeRequest(scoped))
	if err != nil {
		t.Fatalf("Decide(%s): %v", scoped, err)
	}
	if dec.Authorization != contract.AuthzPermit || dec.State != contract.StateAllow {
		t.Fatalf("the scoped spelling %s got %s/%s (reason %s); a scope that does not select the subject it "+
			"names would make everything below vacuous", scoped, dec.Authorization, dec.State, dec.Reason)
	}
	if len(dec.Determining.MatchedPermissions) != 1 || dec.Determining.MatchedPermissions[0] != "P_SCOPED" {
		t.Fatalf("the scoped spelling matched %v, want [P_SCOPED]", dec.Determining.MatchedPermissions)
	}

	// Every OTHER type in the closed principal vocabulary, over the same realm
	// and the same local segment. Enumerated rather than sampled: a fold that
	// covered five of the six would be invisible to a test that drove two.
	others := 0
	for _, typ := range contract.PrincipalTypes() {
		spelling := string(typ) + "::realm_ws:alice"
		if spelling == scoped {
			continue
		}
		if typ == contract.PrincipalGroup {
			// A Group is a set of subjects, never a request principal;
			// contract.Request.Validate refuses it, so it is not a spelling of
			// this subject and is excluded by that rule rather than skipped.
			continue
		}
		others++
		dec, err := e.Decide(context.Background(), scopePrincipalTypeRequest(spelling))
		if err != nil {
			t.Fatalf("Decide(%s): %v", spelling, err)
		}
		if dec.Authorization != contract.AuthzNotApplicable {
			t.Errorf("%s got %s (reason %s); #3936's premise is that it gets not_applicable, and the "+
				"ruling recorded on that issue is built on this being the behaviour",
				spelling, dec.Authorization, dec.Reason)
		}
		if dec.Reason != contract.ReasonNoMatchingPermission {
			t.Errorf("%s was refused for %q, not %q; the policy is not applying, but not for the reason "+
				"this test is about", spelling, dec.Reason, contract.ReasonNoMatchingPermission)
		}
		if len(dec.Determining.MatchedPermissions) != 0 {
			t.Errorf("%s matched %v; the scope was expected to select nothing",
				spelling, dec.Determining.MatchedPermissions)
		}
	}
	if others < 3 {
		t.Fatalf("only %d alternative spellings were driven; the vocabulary has six types and this "+
			"assertion is about the ones the scope does NOT name", others)
	}
	t.Logf("one scoped spelling permitted; %d other classifications of the same subject not applicable", others)
}
