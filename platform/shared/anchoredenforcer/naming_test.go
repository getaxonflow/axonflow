// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestEveryUnknownReasonHasItsOwnPhrase: a reason added to the contract without
// its own words would name a constraint with the fallback phrase (#4227).
func TestEveryUnknownReasonHasItsOwnPhrase(t *testing.T) {
	fallback := UnknownReasonPhrase("not-a-declared-reason")
	seen := map[string]contract.UnknownReason{}
	for _, r := range contract.AllUnknownReasons() {
		phrase := UnknownReasonPhrase(r)
		if phrase == fallback {
			t.Errorf("%s has no phrase of its own; it reads %q", r, phrase)
		}
		if strings.Count(phrase, "%") != 1 || !strings.Contains(phrase, "%s") {
			t.Errorf("%s: phrase %q must take the attributes exactly once, as %%s", r, phrase)
		}
		if other, dup := seen[phrase]; dup {
			t.Errorf("%s and %s share the phrase %q", r, other, phrase)
		}
		seen[phrase] = r
	}
}

// TestAnUnknownConstraintIsNamedByWhoseItIs: the source and version beside the
// id, as policy_identities names them (PRD v11 §1.14).
func TestAnUnknownConstraintIsNamedByWhoseItIs(t *testing.T) {
	u := contract.UnknownPolicy{Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied, Paths: []string{"args.request_type"}}
	const why = " could not be evaluated: no value was supplied for args.request_type"
	for _, c := range []struct {
		identity activation.PolicyIdentity
		want     string
	}{
		{activation.PolicyIdentity{ID: "ceiling.refund", Source: activation.SourceOrganization, Version: 1}, "ceiling.refund (organization, document version 1)" + why},
		{activation.PolicyIdentity{ID: "pack.ceiling", Source: activation.SourcePack, Version: 2}, "pack.ceiling (pack, version 2)" + why},
		{activation.PolicyIdentity{ID: "corpus:static_policies:sys__x:block", Source: activation.SourceShipped}, "corpus:static_policies:sys__x:block (shipped)" + why},
		{activation.PolicyIdentity{ID: "not.activated"}, "not.activated" + why},
	} {
		if got := UnknownConstraintReason(c.identity, u); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.identity, got, c.want)
		}
	}
}

// TestAnUnknownGroupClosureCarriesTheDirectorysDetail: the directory's account
// of an unknown principal.groups follows the reason of exactly the constraints
// that could not establish it, and no other.
func TestAnUnknownGroupClosureCarriesTheDirectorysDetail(t *testing.T) {
	act := factsActivation(t)
	groups := contract.UnknownPolicy{PolicyID: "ceiling.group", Reason: contract.ReasonClosureUnavailable, Paths: []string{"args.query", "principal.groups"}}
	other := contract.UnknownPolicy{PolicyID: "ceiling.refund", Reason: contract.ReasonNotSupplied, Paths: []string{"args.request_type"}}
	const detail = "realm \"axonflow-minted\"'s directory could not be read"

	got := UnknownConstraintReasons(act, []contract.UnknownPolicy{groups, other}, detail)
	want := []string{
		"ceiling.group could not be evaluated: the group or resource closure behind args.query, principal.groups could not be computed (" + detail + ")",
		"ceiling.refund could not be evaluated: no value was supplied for args.request_type",
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("reasons %q; want %q", got, want)
	}
	if plain := UnknownConstraintReasons(act, []contract.UnknownPolicy{groups}, ""); plain[0] != "ceiling.group could not be evaluated: the group or resource closure behind args.query, principal.groups could not be computed" {
		t.Fatalf("with no detail the reason is %q; want the reason alone", plain[0])
	}
}

// admissionRefusal builds the decision the engine answers when pdp.Registry.Admit
// refuses, in pdp.admissionDecision's shape: no determining policy, the
// admission's detail on the trace.
func admissionRefusal(adm pdp.AdmissionResult) *contract.Decision {
	return &contract.Decision{
		Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: adm.Reason,
		Trace: &contract.Trace{State: contract.StateDeny, Reason: adm.Reason, Remediation: adm.Detail},
	}
}

// TestAnAdmissionRefusalCarriesItsDetail (#4249): a refusal before any policy
// ran names what could not be admitted, from the real registry's own words; no
// other decision does.
func TestAnAdmissionRefusalCarriesItsDetail(t *testing.T) {
	reg := &pdp.Registry{
		Actions: map[string]pdp.ActionEntry{"Action::tool.call": {MaxDelegationDepth: 1}},
		Realms:  map[string]bool{"axonflow-minted": true},
	}
	oidc := contract.MustParseID(contract.KindPrincipal, "User::oidc:00u-alice")
	minted := contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:alice")
	for name, tc := range map[string]struct {
		req  *contract.Request
		code contract.ReasonCode
		want string
	}{
		"an undeclared realm": {
			req:  &contract.Request{Principal: oidc, Action: contract.MustParseID(contract.KindAction, "Action::tool.call"), Context: contract.Context{ActorChain: []contract.Actor{{ID: oidc}}}},
			code: contract.ReasonUnknownRealm, want: `actor_chain[0] "User::oidc:00u-alice" resolves in realm "oidc", which has no declared trust realm`,
		},
		"an unregistered action": {
			req:  &contract.Request{Principal: minted, Action: contract.MustParseID(contract.KindAction, "Action::not.registered"), Context: contract.Context{ActorChain: []contract.Actor{{ID: minted}}}},
			code: contract.ReasonUnknownAction, want: `action "Action::not.registered" is not in the registry`,
		},
		"a chain deeper than declared": {
			req:  &contract.Request{Principal: minted, Action: contract.MustParseID(contract.KindAction, "Action::tool.call"), Context: contract.Context{ActorChain: []contract.Actor{{ID: minted}, {ID: minted}}}},
			code: contract.ReasonDelegationDepth, want: "actor chain of length 2 exceeds the declared maximum delegation depth 1",
		},
	} {
		adm := reg.Admit(tc.req)
		if !adm.Failed || adm.Reason != tc.code {
			t.Fatalf("%s: admission %+v; want refused %s", name, adm, tc.code)
		}
		if got := AdmissionDetail(admissionRefusal(adm)); !strings.Contains(got, tc.want) || got != adm.Detail {
			t.Fatalf("%s: detail %q; want the admission's own %q", name, got, adm.Detail)
		}
	}

	schema := admissionRefusal(pdp.AdmissionResult{Reason: contract.ReasonSchemaViolation, Detail: `missing required argument fields "query"`})
	if got := AdmissionDetail(schema); got != `missing required argument fields "query"` {
		t.Fatalf("schema_violation at admission: detail %q", got)
	}
	// The same code after policies MATCHED is obligation composition, whose
	// detail can name what a policy attached: never read as an admission's.
	composed := admissionRefusal(pdp.AdmissionResult{Reason: contract.ReasonSchemaViolation, Detail: "an obligation a policy attached"})
	composed.Determining = contract.Determining{MatchedPermissions: []string{"grant.x"}}
	if got := AdmissionDetail(composed); got != "" {
		t.Fatalf("a composed schema_violation with a matched policy carried %q", got)
	}
	for _, d := range []contract.Determining{
		{MatchedConstraints: []string{"c"}}, {MatchedRequirement: []string{"r"}}, {MatchedInspections: []string{"i"}},
		{Unknown: []contract.UnknownPolicy{{PolicyID: "u"}}},
	} {
		c := admissionRefusal(pdp.AdmissionResult{Reason: contract.ReasonUnknownRealm, Detail: "x"})
		c.Determining = d
		if got := AdmissionDetail(c); got != "" {
			t.Fatalf("determining %+v: carried %q", d, got)
		}
	}
	policy := admissionRefusal(pdp.AdmissionResult{Reason: contract.ReasonExplicitConstraint, Detail: "a policy's remediation"})
	if got := AdmissionDetail(policy); got != "" {
		t.Fatalf("a policy refusal carried %q", got)
	}
	if AdmissionDetail(nil) != "" || AdmissionDetail(&contract.Decision{Reason: contract.ReasonUnknownRealm}) != "" {
		t.Fatal("a nil decision or a decision with no trace carried a detail")
	}
}
