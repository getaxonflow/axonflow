// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"sort"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestAdmissionRefusalReasonsAreExactlyWhatAdmitRefusesWith (#4249): the list a
// seam keys an admission refusal's detail on is the set of codes Admit
// actually produces against a configured registry, driven, not restated.
func TestAdmissionRefusalReasonsAreExactlyWhatAdmitRefusesWith(t *testing.T) {
	minted := contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:alice")
	action := contract.MustParseID(contract.KindAction, "Action::tool.call")
	reg := &Registry{
		Actions: map[string]ActionEntry{
			action.String():            {MaxDelegationDepth: 1, Arguments: map[string]ValueType{"query": TypeString}, RequiredArguments: []string{"query"}},
			"Action::depth.undeclared": {},
		},
		Realms: map[string]bool{"axonflow-minted": true},
	}
	chain := func(ids ...contract.ID) contract.Context {
		c := contract.Context{}
		for _, id := range ids {
			c.ActorChain = append(c.ActorChain, contract.Actor{ID: id})
		}
		return c
	}
	query := contract.AttributeSet{"args.query": contract.Known("select 1", contract.ProvCaller, 1, time.Now())}
	produced := map[contract.ReasonCode]bool{}
	for name, req := range map[string]*contract.Request{
		"unregistered action": {Principal: minted, Action: contract.MustParseID(contract.KindAction, "Action::nope"), Context: chain(minted)},
		"undeclared realm":    {Principal: minted, Action: action, Context: chain(contract.MustParseID(contract.KindPrincipal, "User::oidc:x"))},
		"undeclared depth":    {Principal: minted, Action: contract.MustParseID(contract.KindAction, "Action::depth.undeclared"), Context: chain(minted)},
		"chain too deep":      {Principal: minted, Action: action, Context: chain(minted, minted), Attributes: query},
		"missing argument":    {Principal: minted, Action: action, Context: chain(minted)},
	} {
		adm := reg.Admit(req)
		if !adm.Failed || adm.Detail == "" {
			t.Fatalf("%s: %+v; want a refusal with a detail", name, adm)
		}
		produced[adm.Reason] = true
	}
	if ok := reg.Admit(&contract.Request{Principal: minted, Action: action, Context: chain(minted), Attributes: query}); ok.Failed {
		t.Fatalf("the control was refused: %+v", ok)
	}
	var got, want []string
	for r := range produced {
		got = append(got, string(r))
	}
	for _, r := range AdmissionRefusalReasons() {
		want = append(want, string(r))
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("Admit refused with %v; AdmissionRefusalReasons declares %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("Admit refused with %v; AdmissionRefusalReasons declares %v", got, want)
		}
	}
}
