package registry

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// fixtureNow is the fixed instant every fixture catalog is evaluated at.
//
// Fixed rather than time.Now, because compatibility expiry is judged against it
// and a wall clock would make a passing suite become a failing one at an
// arbitrary future date, which is the worst possible way to learn about an
// expiry rule.
var fixtureNow = time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)

func actionID(name string) contract.ID {
	return contract.MustParseID(contract.KindAction, "Action::"+name)
}

func toolID(name string) contract.ID {
	return contract.MustParseID(contract.KindTool, "Tool::"+name)
}

// failClosedEffects declares every risk class as absent. It is the fixture for
// an ordinary low-risk action.
func failClosedEffects() Effects {
	return Effects{
		Irreversible: DeclarationNo,
		Spend:        DeclarationNo,
		DataEgress:   DeclarationNo,
		Privileged:   DeclarationNo,
	}
}

// sampleAction is a complete, valid action record.
func sampleAction(name string) ActionRecord {
	return ActionRecord{
		ID:                 actionID(name),
		Tags:               []string{"read_only"},
		Posture:            FailClosedPosture(),
		MaxDelegationDepth: 3,
		Arguments:          map[string]pdp.ValueType{"query": pdp.TypeString},
		RequiredArguments:  []string{"query"},
		PayloadLeaves:      []string{"response.title"},
		ResourceType:       "Ticket",
		Effects:            failClosedEffects(),
	}
}

// newFixtureCatalog builds a catalog with the vocabulary, one resource type of
// each recursion class, one realm and one action.
//
// Every test that needs a catalog builds its own through the real registration
// path. A shared pre-built catalog would let one test's mutation reach another,
// and more importantly it would let a test assert a property of a catalog that
// the registration rules would have refused.
func newFixtureCatalog(t *testing.T) *Catalog {
	t.Helper()
	c := NewCatalog(fixtureNow)
	for _, tag := range []TagRecord{
		{Tag: "read_only", Governance: TagGovernanceUngoverned, Description: "the action only reads"},
		{Tag: "pii_egress", Governance: TagGovernanceGoverned, Owner: "security", Description: "personal data leaves the organization"},
		{Tag: "spend", Governance: TagGovernanceGoverned, Owner: "finance", Description: "the action moves money"},
		{Tag: "beta", Governance: TagGovernanceUngoverned, Description: "the connector is in preview"},
	} {
		if err := c.RegisterTag(tag); err != nil {
			t.Fatalf("registering tag %q: %v", tag.Tag, err)
		}
	}
	for _, rt := range []ResourceTypeRecord{
		{Type: "Ticket", Ancestors: []string{"project", "instance"}, Recursion: RecursionNone,
			PayloadLeaves: []string{"response.title"}},
		{Type: "Page", Ancestors: []string{"space", "instance"}, Recursion: RecursionBounded, MaxDepth: 32,
			PayloadLeaves: []string{"response.body"}},
	} {
		if err := c.RegisterResourceType(rt); err != nil {
			t.Fatalf("registering resource type %q: %v", rt.Type, err)
		}
	}
	if err := c.RegisterRealm("realm_ws"); err != nil {
		t.Fatalf("registering realm: %v", err)
	}
	if err := c.RegisterAction(sampleAction("docs.search")); err != nil {
		t.Fatalf("registering the sample action: %v", err)
	}
	return c
}

// mustRegisterAction fails the test if registration is refused.
func mustRegisterAction(t *testing.T, c *Catalog, a ActionRecord) {
	t.Helper()
	if err := c.RegisterAction(a); err != nil {
		t.Fatalf("registering action %q: %v", a.ID, err)
	}
}

// refusal asserts that an error was returned and that it names a code.
func refusal(t *testing.T, err error, want Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected a refusal naming %s, got none", want)
	}
	if !strings.Contains(err.Error(), string(want)) {
		t.Fatalf("expected a refusal naming %s, got: %v", want, err)
	}
}

// accepted asserts that registration succeeded, so a test proving a refusal
// always has a counterfactual: the same record without the defect is accepted.
// Without one, a rule that refuses everything would pass every refusal test.
func accepted(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected the record to be accepted, got: %v", err)
	}
}

// completeException is a compatibility exception with every required field.
func completeException(action contract.ID) CompatibilityException {
	return CompatibilityException{
		Action:       action,
		Owner:        "platform-migration",
		Metric:       "axonflow_compatibility_posture_total",
		RemovalIssue: "https://github.com/getaxonflow/axonflow-enterprise/issues/3558",
		ExpiresAt:    fixtureNow.Add(30 * 24 * time.Hour),
	}
}

// samplePEP is a complete enforcement point record.
func samplePEP(id string, edition Edition, caps ...contract.Capability) PEPRecord {
	if caps == nil {
		caps = []contract.Capability{}
	}
	return PEPRecord{ID: id, Realm: "realm_ws", Edition: edition, Capabilities: caps}
}

func obligation(t contract.ObligationType, version int, mandatory bool) contract.Obligation {
	return contract.Obligation{Type: t, SchemaVersion: version, Mandatory: mandatory, SourcePolicy: "P1"}
}
