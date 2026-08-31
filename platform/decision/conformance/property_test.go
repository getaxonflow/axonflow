package conformance

import (
	"fmt"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// propertyRequests is the request population every property is checked over.
//
// It is deliberately varied along the axes the properties are about: a
// principal with only permissions, one who also carries a restriction, one in a
// realm with no group graph, actions with different tag sets, resources with
// and without a containment closure, and amounts on both sides of every
// threshold in the fixture policy set.
func propertyRequests() []Scenario {
	var out []Scenario
	for _, principal := range []string{"alice", "bob", "carol", "dana", "erin", "frank", "agent-A"} {
		for _, amount := range []int{1000, 30000, 300000, 3000000, 8000000} {
			for _, resource := range []string{"SUP-42", "SUP-43", "SUP-99", "LEG-7"} {
				out = append(out, Scenario{Principal: principal, Action: "T1", Resource: resource,
					Args: map[string]any{"amount_cents": amount}})
			}
		}
		out = append(out,
			Scenario{Principal: principal, Action: "T2", Args: map[string]any{"segment": "all"}},
			Scenario{Principal: principal, Action: "T3", Args: map[string]any{"query": "invoices"}},
			Scenario{Principal: principal, Action: "T4", Args: map[string]any{"contact_id": "c1"}},
			Scenario{Principal: principal, Action: "T5", Resource: "SUP-42",
				Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}},
			Scenario{Principal: principal, Action: "T5", Resource: "LEG-7",
				Args: map[string]any{"ticket_id": "LEG-7", "to_status": "done"}},
			Scenario{Principal: principal, Action: "T6", Resource: "P-900", Args: map[string]any{"page_id": "P-900"}},
			Scenario{Principal: principal, Action: "T6", Resource: "P-311", Args: map[string]any{"page_id": "P-311"}},
			Scenario{Principal: principal, Action: "T6", Resource: "P-500", Args: map[string]any{"page_id": "P-500"}},
		)
	}
	return out
}

// candidateConstraints generates constraint policies mechanically from the
// declared attribute schema, so the property is checked against constraints
// nobody hand-picked to be harmless.
func candidateConstraints(d *pdp.Document) []pdp.Policy {
	var out []pdp.Policy
	i := 0
	for _, a := range d.Attributes {
		var conds []pdp.Condition
		switch a.Type {
		case pdp.TypeNumber:
			conds = append(conds,
				pdp.Compare(a.Path, pdp.OpGt, 0),
				pdp.Compare(a.Path, pdp.OpLe, 1000000000),
				pdp.Compare(a.Path, pdp.OpEq, 30000))
		case pdp.TypeString:
			conds = append(conds,
				pdp.Compare(a.Path, pdp.OpNe, "impossible-sentinel-value"),
				pdp.Compare(a.Path, pdp.OpEq, "internal"))
		case pdp.TypeBoolean:
			conds = append(conds, pdp.Compare(a.Path, pdp.OpEq, false))
		case pdp.TypeArray:
			conds = append(conds,
				pdp.Member(a.Path, "Group::realm_ws:all-staff"),
				pdp.Member(a.Path, "irreversible"))
		}
		for _, c := range conds {
			// A generated condition over an optional attribute must declare
			// what absence means, exactly as an authored one must. Both
			// handlings are generated, so the property is checked against a
			// constraint that treats absence as a non-match AND against one
			// that treats it as unknown; the second is the shape that can turn
			// a permit into an error, which is a narrowing and therefore must
			// still not widen.
			if a.Optional {
				// Caller-supplied absence is caller-CONTROLLED absence, so the
				// validator refuses a non-match handling on an args path.
				handling := pdp.AbsentIsUnknown
				if contract.NamespaceOf(a.Path) != contract.NsArgs && i%2 == 0 {
					handling = pdp.AbsentIsNoMatch
				}
				c = c.HandlingAbsence(handling)
			}
			i++
			out = append(out, pdp.Policy{
				ID:        fmt.Sprintf("PROP-C%03d", i),
				Authority: contract.AuthorityConstraint, Root: pdp.RootSystem,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
				Where:       c,
				Description: "generated constraint for the monotonicity property",
			})
		}
	}
	return out
}

// TestPropertyAddingAConstraintNeverWidens is ADR-065 acceptance gate 5.
//
// Adding a constraint cannot widen access. It is the mechanical form of the
// authority separation: a constraint may only restrict, so no request may
// become more permissive because one more constraint exists. A violation here
// would mean a customer could gain access by adding a restriction, which is the
// shape of every privilege-escalation-through-policy bug.
func TestPropertyAddingAConstraintNeverWidens(t *testing.T) {
	base := defaultWorld(t)
	requests := propertyRequests()
	baseline := make([]int, len(requests))
	for i, s := range requests {
		baseline[i] = permissiveness(decide(t, base, s))
	}

	// Obligations are compared as well as states, because a widening does not
	// have to change the operational state to be one: a decision that stays
	// ALLOW while losing a mandatory redaction has widened access to the field
	// that redaction covered, and a rank over states alone cannot see it.
	baselineObligations := make([][]string, len(requests))
	for i, s := range requests {
		baselineObligations[i] = ObligationKeys(decide(t, base, s))
	}

	candidates := candidateConstraints(SystemDocument())
	if len(candidates) < 10 {
		t.Fatalf("only %d candidate constraints were generated; the property would barely be exercised", len(candidates))
	}
	checks := 0
	for _, extra := range candidates {
		w := newWorld(t, WithSystemDocument(systemDocWith(extra)))
		for i, s := range requests {
			d := decide(t, w, s)
			got := permissiveness(d)
			checks++
			if got > baseline[i] {
				t.Fatalf("adding constraint %q (%s) widened %s on %s from rank %d to rank %d",
					extra.ID, extra.Where.Kind, s.Principal, s.Action, baseline[i], got)
			}
			if got < baseline[i] {
				// The request narrowed, so its obligation set is not
				// comparable: a denial carries none.
				continue
			}
			for _, o := range baselineObligations[i] {
				if !contains(ObligationKeys(d), o) {
					t.Fatalf("adding constraint %q left %s on %s at rank %d but dropped the obligation %q",
						extra.ID, s.Principal, s.Action, got, o)
				}
			}
		}
	}
	// The floor is derived from the two measured populations rather than
	// hand-picked, so a shrunken request set or a shrunken candidate set fails
	// here instead of quietly checking less.
	if want := len(candidates) * len(requests); checks != want {
		t.Fatalf("the property ran %d checks, expected %d (%d candidates over %d requests)",
			checks, want, len(candidates), len(requests))
	}
}

// TestPropertyAddingAnActorNeverWidens is ADR-065 acceptance gate 6.
//
// Adding an actor to the delegation chain cannot widen authority. Effective
// authority is the intersection over the chain, so every hop can only narrow.
// Pooling the chain's identities instead builds a privilege-escalation machine:
// place an agent in a powerful group, have any low-privilege user invoke it,
// and that user inherits the agent's reach while every individual policy still
// reads correctly.
func TestPropertyAddingAnActorNeverWidens(t *testing.T) {
	w := defaultWorld(t)
	extras := []string{"agent-A", "sub-B", "erin", "dana"}
	checks := 0
	eligible := 0
	for _, s := range propertyRequests() {
		// An action whose declared delegation depth cannot hold a second hop is
		// refused at ADMISSION, so chaining it would measure the depth check
		// rather than the meet. Skipping it here keeps the property about the
		// meet.
		if Actions[s.Action].MaxDelegationDepth < 2 {
			continue
		}
		eligible++
		alone := permissiveness(decide(t, w, s))
		for _, extra := range extras {
			if extra == s.Principal {
				continue
			}
			chained := s
			chained.Chain = []string{s.Principal, extra}
			got := permissiveness(decide(t, w, chained))
			checks++
			if got > alone {
				t.Fatalf("adding actor %q to %s on %s widened the outcome from rank %d to rank %d",
					extra, s.Principal, s.Action, alone, got)
			}
		}
	}
	// The floor is derived from the two measured populations rather than
	// chosen: every eligible request is chained with every extra actor that is
	// not already its principal, so a shrunken request set or a shrunken actor
	// set fails here instead of quietly checking less.
	if want := eligible * (len(extras) - 1); checks < want {
		t.Fatalf("the property ran %d checks over %d eligible requests and %d extra actors, fewer than the %d floor",
			checks, eligible, len(extras), want)
	}
}

// TestPropertyAnOrganizationPermissionCannotEscapeASystemConstraint proves the
// separation of authority roots.
//
// System and organization permissions can grant only WITHIN system constraints.
// The two roots are separate signed artifacts verified against separate keys,
// and their outcomes are unioned rather than merged, so there is no operation
// anywhere by which an organization document edits a system one. This checks
// the consequence rather than the mechanism: an organization permission over
// every action and every principal must not turn a single system denial into a
// permit.
func TestPropertyAnOrganizationPermissionCannotEscapeASystemConstraint(t *testing.T) {
	base := defaultWorld(t)
	org := OrganizationDocument()
	org.Policies = append(org.Policies, pdp.Policy{
		ID: "PROP-G001", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where: pdp.True(), Description: "generated permission over everything",
	})
	wide := newWorld(t, WithOrganizationDocument(org))

	denials, widened := 0, 0
	for _, s := range propertyRequests() {
		before := decide(t, base, s)
		if before.Authorization != contract.AuthzDeny {
			continue
		}
		denials++
		after := decide(t, wide, s)
		if after.Authorization != contract.AuthzDeny {
			widened++
			t.Errorf("an organization permission over everything turned the denial of %s on %s (%v) into %s",
				s.Principal, s.Action, before.Determining.MatchedConstraints, after.Authorization)
		}
	}
	if denials == 0 {
		t.Fatal("no request in the population was denied by a system constraint, so the property was not exercised")
	}
	if widened > 0 {
		t.Fatalf("%d of %d system denials were escaped by an organization permission", widened, denials)
	}
}

// TestPropertyReplayIsDeterministic proves that identical input and bundle
// reproduce an identical decision, which is what makes a decision auditable at
// all.
func TestPropertyReplayIsDeterministic(t *testing.T) {
	w := defaultWorld(t)
	checks := 0
	for _, s := range propertyRequests() {
		first := decide(t, w, s)
		second := decide(t, w, s)
		checks++
		if first.DecisionID != second.DecisionID {
			t.Fatalf("%s on %s produced two decision identifiers", s.Principal, s.Action)
		}
		if first.Authorization != second.Authorization || first.State != second.State || first.Reason != second.Reason {
			t.Fatalf("%s on %s produced two different decisions", s.Principal, s.Action)
		}
		a, errA := contract.Digest(first.Determining)
		b, errB := contract.Digest(second.Determining)
		if errA != nil || errB != nil || a != b {
			t.Fatalf("%s on %s produced two different determining sets", s.Principal, s.Action)
		}
	}
	if checks != len(propertyRequests()) {
		t.Fatalf("replay checked %d of %d requests", checks, len(propertyRequests()))
	}
}
