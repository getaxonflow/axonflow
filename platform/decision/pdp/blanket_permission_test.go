// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// The anchored engine's half of the blanket-permission rule (#3895).
//
// Three cases, and the middle one is the control that makes the other two
// mean something: ANCHORED refuses the blanket shape with the named code,
// UNANCHORED accepts the identical documents (the shadow harness compiles
// exactly this permission on purpose), and ANCHORED accepts a per-action
// permission of the same authority in the same organization document.

func blanketPermission(id string) Policy {
	return Policy{
		ID: id, Authority: contract.AuthorityPermission, Root: RootOrganization,
		Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: True(),
	}
}

func TestIsBlanketPermissionRequiresAllFourProperties(t *testing.T) {
	base := blanketPermission("p")
	if !IsBlanketPermission(base) {
		t.Fatal("the reference shape is not recognised")
	}
	cond := Compare("args.amount_cents", OpLe, 5)
	variants := map[string]func(p *Policy){
		"a constraint": func(p *Policy) { p.Authority = contract.AuthorityConstraint },
		"a named action": func(p *Policy) {
			p.Actions = ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::a.b")}}
		},
		"a required tag": func(p *Policy) { p.Actions = ActionSelector{Any: true, RequiredTags: []string{"spend"}} },
		"a group scope": func(p *Policy) {
			p.Scope = Scope{Groups: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::r:g")}}
		},
		"a condition":          func(p *Policy) { p.Where = cond },
		"an exception":         func(p *Policy) { p.Unless = &cond },
		"a resource scope":     func(p *Policy) { p.ResourceScope = &cond },
		"not the organization": func(p *Policy) { p.Scope = Scope{} },
	}
	for name, mutate := range variants {
		p := blanketPermission("p")
		mutate(&p)
		if IsBlanketPermission(p) {
			t.Errorf("%s is classified as blanket; the rule needs the conjunction", name)
		}
	}
}

// blanketWorld builds the two documents and their bundles: the shipped corpus
// under the system root, and an organization document carrying `org`.
func blanketWorld(t *testing.T, org Policy) ([]*Bundle, []*Document, *TrustStore) {
	t.Helper()
	system, err := SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	orgDoc := &Document{Root: RootOrganization, Version: 1, Policies: []Policy{org}}
	ts := NewTrustStore()
	var bundles []*Bundle
	for _, d := range []*Document{system, orgDoc} {
		b, err := BuildBundle(d)
		if err != nil {
			t.Fatalf("building the %s bundle: %v", d.Root, err)
		}
		pub, priv, _ := ed25519.GenerateKey(nil)
		if err := b.Sign(string(d.Root)+"-key", priv); err != nil {
			t.Fatal(err)
		}
		ts.Authorize(d.Root, string(d.Root)+"-key", pub)
		bundles = append(bundles, b)
	}
	return bundles, []*Document{system, orgDoc}, ts
}

func blanketRegistry() *Registry {
	return &Registry{
		Actions: map[string]ActionEntry{"Action::a.b": {ID: contract.MustParseID(contract.KindAction, "Action::a.b"), MaxDelegationDepth: 1}},
		Realms:  map[string]bool{"r": true},
	}
}

func TestAnAnchoredEngineRefusesABlanketPermissionByName(t *testing.T) {
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatal(err)
	}
	bundles, docs, ts := blanketWorld(t, blanketPermission("org.blanket"))
	_, err = NewEngine(context.Background(), EngineConfig{
		Bundles: bundles, Documents: docs, TrustStore: ts, Registry: blanketRegistry(), SystemCorpus: anchor,
	})
	var refusal *ActivationRefusal
	if !errors.As(err, &refusal) {
		t.Fatalf("an anchored engine activated a blanket permission (err=%v)", err)
	}
	if refusal.Code != RefusalBlanketPermission {
		t.Fatalf("refused with %q, want %q", refusal.Code, RefusalBlanketPermission)
	}
	// The REASON is asserted, not only the refusal: the detail names the
	// policy, so a refusal for some other cause cannot satisfy this test.
	if want := "org.blanket"; !strings.Contains(refusal.Detail, want) {
		t.Fatalf("the refusal does not name the policy %q: %s", want, refusal.Detail)
	}
}

func TestAnUnanchoredEngineStillAcceptsTheBlanketPermissionTheShadowCompiles(t *testing.T) {
	bundles, docs, ts := blanketWorld(t, blanketPermission("org.blanket"))
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: bundles, Documents: docs, TrustStore: ts, Registry: blanketRegistry(),
		SystemCorpus: Unanchored("this test is the shadow harness's control: it compiles the baseline permission on purpose"),
	}); err != nil {
		t.Fatalf("an unanchored engine refused the shape the shadow harness compiles; the exemption is by construction and it moved: %v", err)
	}
}

func TestAnAnchoredEngineAcceptsAPerActionPermission(t *testing.T) {
	anchor, err := AnchorToShippedCorpus()
	if err != nil {
		t.Fatal(err)
	}
	perAction := blanketPermission("org.permit.a_b")
	perAction.Actions = ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::a.b")}}
	bundles, docs, ts := blanketWorld(t, perAction)
	if _, err := NewEngine(context.Background(), EngineConfig{
		Bundles: bundles, Documents: docs, TrustStore: ts, Registry: blanketRegistry(), SystemCorpus: anchor,
	}); err != nil {
		t.Fatalf("an anchored engine refused a per-action permission, so the blanket rule is too wide: %v", err)
	}
}
