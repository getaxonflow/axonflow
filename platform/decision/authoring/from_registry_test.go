package authoring

import (
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

var registryNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

// sourceRegistry builds a small registry catalog through the real registration
// path, carrying one resource type of each recursion class.
func sourceRegistry(t *testing.T) *registry.Catalog {
	t.Helper()
	c := registry.NewCatalog(registryNow)
	for _, tag := range []registry.TagRecord{
		{Tag: "read_only", Governance: registry.TagGovernanceUngoverned, Description: "the action only reads"},
		{Tag: "pii_egress", Governance: registry.TagGovernanceGoverned, Owner: "security", Description: "personal data leaves"},
	} {
		if err := c.RegisterTag(tag); err != nil {
			t.Fatalf("registering tag %q: %v", tag.Tag, err)
		}
	}
	for _, rt := range []registry.ResourceTypeRecord{
		{Type: "Ticket", Ancestors: []string{"project", "instance"}, Recursion: registry.RecursionNone,
			PayloadLeaves: []string{"response.status"}},
		{Type: "Page", Ancestors: []string{"space", "instance"}, Recursion: registry.RecursionBounded,
			MaxDepth: 32, PayloadLeaves: []string{"response.body"}},
	} {
		if err := c.RegisterResourceType(rt); err != nil {
			t.Fatalf("registering resource type %q: %v", rt.Type, err)
		}
	}
	if err := c.RegisterRealm("realm_ws"); err != nil {
		t.Fatalf("registering the realm: %v", err)
	}
	if err := c.RegisterAction(registry.ActionRecord{
		ID:                 contract.MustParseID(contract.KindAction, "Action::docs.search"),
		Tags:               []string{"read_only"},
		Posture:            registry.FailClosedPosture(),
		MaxDelegationDepth: 3,
		Arguments:          map[string]pdp.ValueType{"query": pdp.TypeString},
		RequiredArguments:  []string{"query"},
		PayloadLeaves:      []string{"response.title"},
		ResourceType:       "Ticket",
		Effects: registry.Effects{
			Irreversible: registry.DeclarationNo, Spend: registry.DeclarationNo,
			DataEgress: registry.DeclarationNo, Privileged: registry.DeclarationNo,
		},
	}); err != nil {
		t.Fatalf("registering the action: %v", err)
	}
	return c
}

func sourceRealms() map[string]RealmEntry {
	return map[string]RealmEntry{"realm_ws": {Interactive: true, HasGroupGraph: true}}
}

// TestTheAuthoringCatalogIsDerivedFromTheRegistry proves the two layers carry
// one set of facts rather than two.
func TestTheAuthoringCatalogIsDerivedFromTheRegistry(t *testing.T) {
	reg := sourceRegistry(t)
	cat, err := NewCatalogFromRegistry(reg, sourceRealms())
	if err != nil {
		t.Fatalf("deriving the authoring catalog: %v", err)
	}
	if err := cat.Validate(); err != nil {
		t.Fatalf("the derived catalog is not a usable validation authority: %v", err)
	}

	for _, name := range reg.ResourceTypeNames() {
		want, _ := reg.ResourceType(name)
		got, ok := cat.ResourceTypes[name]
		if !ok {
			t.Errorf("resource type %q did not survive the derivation", name)
			continue
		}
		if got.Recursive != want.Recursion.Recursive() {
			t.Errorf("%s: derived Recursive=%t, the registry declares %s", name, got.Recursive, want.Recursion)
		}
		if got.MaxDepth != want.MaxDepth {
			t.Errorf("%s: derived MaxDepth=%d, the registry declares %d", name, got.MaxDepth, want.MaxDepth)
		}
		if len(got.Ancestors) != len(want.Ancestors) {
			t.Errorf("%s: derived ancestors %v, the registry declares %v", name, got.Ancestors, want.Ancestors)
		}
	}
	for _, id := range reg.ActionIDs() {
		if _, ok := cat.Actions[id]; !ok {
			t.Errorf("action %q did not survive the derivation", id)
		}
	}

	// The derivation copies rather than sharing, so an author-side edit cannot
	// reach the registry the admission path projects from.
	cat.ResourceTypes["Page"].Ancestors[0] = "smuggled"
	again, _ := reg.ResourceType("Page")
	if again.Ancestors[0] != "space" {
		t.Errorf("editing the derived catalog reached the registry: %v", again.Ancestors)
	}
}

// TestTheTwoContainmentChecksCannotDisagree is the anti-divergence gate.
//
// This package answers SCOPE_REQUIRES_RECURSION and LEVEL_NOT_DECLARED per
// POLICY, naming the policy that would be inert; the registry answers the same
// two per RESOURCE TYPE, for any consumer that has a type and no policy. Two
// implementations of one rule is exactly the shape the brief warned against, so
// the two are held to the same answer on every declared type and level. A
// disagreement here is one of them being wrong, and it would show up in
// production as a policy that one layer accepted and the other refused.
func TestTheTwoContainmentChecksCannotDisagree(t *testing.T) {
	reg := sourceRegistry(t)
	cat, err := NewCatalogFromRegistry(reg, sourceRealms())
	if err != nil {
		t.Fatalf("deriving the authoring catalog: %v", err)
	}

	checked := 0
	for _, name := range reg.ResourceTypeNames() {
		rt := cat.ResourceTypes[name]
		registryRefuses := reg.CheckContainmentScope(name) != nil
		if registryRefuses == rt.Recursive {
			t.Errorf("%s: the registry %s a containment scope while the authoring catalog records Recursive=%t",
				name, refusalWord(registryRefuses), rt.Recursive)
		}
		checked++

		for _, level := range rt.Ancestors {
			if f := reg.CheckAncestorLevel(name, level); f != nil {
				t.Errorf("%s: the registry refuses declared level %q: %v", name, level, f)
			}
			checked++
		}
		if f := reg.CheckAncestorLevel(name, "no_such_level"); f == nil {
			t.Errorf("%s: the registry accepted an undeclared level", name)
		}
		checked++
	}
	if checked == 0 {
		t.Fatalf("no resource type was compared, so this gate asserts nothing")
	}

	// Both layers must have at least one type of each recursion class, or the
	// comparison above would hold vacuously on one side.
	var recursive, flat int
	for _, rt := range cat.ResourceTypes {
		if rt.Recursive {
			recursive++
			continue
		}
		flat++
	}
	if recursive == 0 || flat == 0 {
		t.Fatalf("the fixture has %d recursive and %d non-recursive types; both are needed", recursive, flat)
	}
}

func refusalWord(refuses bool) string {
	if refuses {
		return "refuses"
	}
	return "accepts"
}

// TestTheDerivationRefusesADisagreementAboutRealms proves the realm split is
// enforced in both directions rather than papered over.
func TestTheDerivationRefusesADisagreementAboutRealms(t *testing.T) {
	reg := sourceRegistry(t)

	if _, err := NewCatalogFromRegistry(reg, map[string]RealmEntry{}); err == nil {
		t.Fatalf("a registry realm with no supplied attributes was accepted")
	}
	extra := sourceRealms()
	extra["realm_nobody_trusts"] = RealmEntry{Interactive: true, HasGroupGraph: true}
	if _, err := NewCatalogFromRegistry(reg, extra); err == nil {
		t.Fatalf("realm attributes for an untrusted realm were accepted")
	}
	if _, err := NewCatalogFromRegistry(nil, sourceRealms()); err == nil {
		t.Fatalf("a nil registry was accepted")
	}
}

// TestTheDerivationInheritsTheRegistrysRefusal proves an invalid registry
// cannot become a valid authoring catalog.
//
// Without it the authoring plane would be a second place a record with an
// undeclared posture could enter the system, and the registry's projection gate
// would be enforcing a rule only one of its two consumers respected.
func TestTheDerivationInheritsTheRegistrysRefusal(t *testing.T) {
	reg := sourceRegistry(t)
	// An exception that expires makes the registry unprojectable through the
	// passage of time alone, with no edit to any record.
	if err := reg.RegisterCompatibilityException(registry.CompatibilityException{
		Action:       contract.MustParseID(contract.KindAction, "Action::docs.search"),
		Owner:        "platform-migration",
		Metric:       "axonflow_compatibility_posture_total",
		RemovalIssue: "getaxonflow/axonflow-enterprise#3558",
		ExpiresAt:    registryNow.Add(time.Hour),
	}); err != nil {
		t.Fatalf("registering the exception: %v", err)
	}
	if _, err := NewCatalogFromRegistry(reg, sourceRealms()); err != nil {
		t.Fatalf("a valid registry did not derive: %v", err)
	}
	reg.Now = registryNow.Add(2 * time.Hour)
	if _, err := NewCatalogFromRegistry(reg, sourceRealms()); err == nil {
		t.Fatalf("a registry whose compatibility exception expired still derived an authoring catalog")
	}
}
