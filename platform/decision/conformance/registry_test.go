package conformance

import (
	"reflect"
	"sort"
	"testing"

	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// TestFixtureRegistryIsTheCatalogProjection holds the corpus's admission
// registry to the registry catalog, field by field.
//
// The corpus's cases are written against Actions, and the engine admits against
// Registry(). If those two could differ, EX-36's unregistered action, EX-37's
// argument schema and EX-43's resource depth would be proved against a fixture
// map rather than against the registry the product uses, which is the whole
// reason this PR rewired Registry() through the catalog.
func TestFixtureRegistryIsTheCatalogProjection(t *testing.T) {
	reg := Registry()
	if len(reg.Actions) != len(Actions) {
		t.Fatalf("the projection carries %d actions, the fixture declares %d", len(reg.Actions), len(Actions))
	}
	for key, want := range Actions {
		got, ok := reg.Actions[want.ID.String()]
		if !ok {
			t.Errorf("fixture action %s (%s) is not in the projection", key, want.ID)
			continue
		}
		if got.ID != want.ID {
			t.Errorf("%s: the projected identifier is %q", key, got.ID)
		}
		if got.MaxDelegationDepth != want.MaxDelegationDepth {
			t.Errorf("%s: the projected delegation depth is %d, declared %d", key, got.MaxDelegationDepth, want.MaxDelegationDepth)
		}
		if !reflect.DeepEqual(got.Arguments, want.Arguments) {
			t.Errorf("%s: the projected argument schema is %v, declared %v", key, got.Arguments, want.Arguments)
		}
		if !sameStrings(got.RequiredArguments, want.RequiredArguments) {
			t.Errorf("%s: the projected required arguments are %v, declared %v", key, got.RequiredArguments, want.RequiredArguments)
		}
		if !sameStrings(got.PayloadLeaves, want.PayloadLeaves) {
			t.Errorf("%s: the projected payload leaves are %v, declared %v", key, got.PayloadLeaves, want.PayloadLeaves)
		}
		if !sameStrings(got.Tags, want.Tags) {
			t.Errorf("%s: the projected tags are %v, declared %v", key, got.Tags, want.Tags)
		}
		if got.Irreversible != want.Irreversible || got.DataEgress != want.DataEgress || got.Privileged != want.Privileged {
			t.Errorf("%s: the projected risk classes are irreversible=%t egress=%t privileged=%t, declared %t/%t/%t",
				key, got.Irreversible, got.DataEgress, got.Privileged,
				want.Irreversible, want.DataEgress, want.Privileged)
		}
	}
	for _, realm := range []string{RealmWorkspace, RealmGCP, RealmConnector} {
		if !reg.Realms[realm] {
			t.Errorf("the projection does not declare realm %q", realm)
		}
	}
}

// TestEveryFixtureActionDeclaresItsSpendClass proves the one risk class the
// merged entry does not carry is declared for every action rather than defaulted
// for the ones nobody thought about.
func TestEveryFixtureActionDeclaresItsSpendClass(t *testing.T) {
	for key := range Actions {
		d, ok := actionSpend[key]
		if !ok {
			t.Errorf("fixture action %s declares no spend risk class", key)
			continue
		}
		if !d.IsValid() {
			t.Errorf("fixture action %s declares spend as %s", key, d)
		}
	}
	for key := range actionSpend {
		if _, ok := Actions[key]; !ok {
			t.Errorf("the spend table names %s, which is not a fixture action", key)
		}
	}
}

// TestFixtureCatalogAnswersTheAuthoringChecks proves the query surface an
// authoring validator needs answers correctly over this world.
func TestFixtureCatalogAnswersTheAuthoringChecks(t *testing.T) {
	c, err := Catalog()
	if err != nil {
		t.Fatalf("building the catalog: %v", err)
	}

	// EX-43's page hierarchy is recursive with a declared bound, which is what
	// makes a truncated closure a representable condition at all.
	page, ok := c.ResourceType("Page")
	if !ok {
		t.Fatalf("the Page resource type is not registered")
	}
	if !page.Recursion.Recursive() {
		t.Errorf("the Page type declares recursion %s", page.Recursion)
	}
	if page.MaxDepth != 32 {
		t.Errorf("the Page type declares maximum depth %d", page.MaxDepth)
	}
	if f := c.CheckContainmentScope("Page"); f != nil {
		t.Errorf("a containment scope over Page was refused: %v", f)
	}

	// A ticket hierarchy is exactly its named levels, so a containment scope
	// over it would resolve to the empty set on every request. That is
	// structurally why EX-43's failure mode cannot occur for a ticket.
	if f := c.CheckContainmentScope("Ticket"); f == nil || f.Code != registry.CodeScopeRequiresRecursion {
		t.Errorf("a containment scope over Ticket produced %v", f)
	}
	for _, level := range []string{"project", "instance"} {
		if f := c.CheckAncestorLevel("Ticket", level); f != nil {
			t.Errorf("declared level %q on Ticket was refused: %v", level, f)
		}
	}
	if f := c.CheckAncestorLevel("Ticket", "space"); f == nil || f.Code != registry.CodeLevelNotDeclared {
		t.Errorf("the undeclared level \"space\" on Ticket produced %v", f)
	}

	// Every action's posture is declared, and it is the fail-closed one: this
	// world carries no compatibility exception, and a permissive posture
	// without one would not have registered.
	for key, a := range Actions {
		posture, err := c.Posture(a.ID)
		if err != nil {
			t.Errorf("fixture action %s has no declared posture: %v", key, err)
			continue
		}
		if posture != registry.FailClosedPosture() {
			t.Errorf("fixture action %s declares posture %#v", key, posture)
		}
	}
	if c.CompatibilityProfile() != nil {
		t.Errorf("the fixture world carries a compatibility exception, which no case expects")
	}
}

// TestGovernedFixtureTagsAreTheOnesPoliciesSelectOn proves the vocabulary's
// governance classes describe this world rather than being a guess.
//
// A tag no policy reads is descriptive and a change to it reaches no evaluator;
// a tag a policy selects on is a policy channel. Deriving the list from the
// policies is what stops the two drifting when a policy is added.
func TestGovernedFixtureTagsAreTheOnesPoliciesSelectOn(t *testing.T) {
	selected := map[string]bool{}
	for _, d := range []*pdp.Document{SystemDocument(), OrganizationDocument()} {
		for _, p := range d.Policies {
			for _, tag := range p.Actions.RequiredTags {
				selected[tag] = true
			}
		}
	}
	if len(selected) == 0 {
		t.Fatalf("no policy in this world selects on a tag, so this test asserts nothing")
	}
	for tag := range selected {
		if _, governed := governedTags[tag]; !governed {
			t.Errorf("policies select on tag %q, which the fixture vocabulary records as ungoverned", tag)
		}
	}
	for tag := range governedTags {
		if !selected[tag] {
			t.Errorf("the vocabulary records tag %q as governed, but no policy in this world selects on it", tag)
		}
	}

	c, err := Catalog()
	if err != nil {
		t.Fatalf("building the catalog: %v", err)
	}
	for tag := range selected {
		rec, ok := c.Tag(tag)
		if !ok {
			t.Errorf("tag %q is selected on but is not in the catalog's vocabulary", tag)
			continue
		}
		if !rec.Governance.Governed() {
			t.Errorf("tag %q is selected on but the catalog records it as %s", tag, rec.Governance)
		}
		if rec.Owner == "" {
			t.Errorf("governed tag %q has no owner", tag)
		}
	}
}

func sameStrings(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
