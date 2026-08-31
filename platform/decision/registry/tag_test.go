package registry

import (
	"strings"
	"testing"
)

func governedChange(name string, add, remove []string) TagChange {
	return TagChange{
		Action: actionID(name), Add: add, Remove: remove,
		Actor: "alice", Reason: "the connector no longer returns personal data",
		ApprovalRef: "CR-8821", At: fixtureNow,
	}
}

// piiAction is an action carrying the governed pii_egress tag.
func piiAction(name string) ActionRecord {
	a := sampleAction(name)
	a.Tags = []string{"pii_egress", "read_only"}
	return a
}

// TestGovernedTagRemovalRaisesAnAlarm is AXC-321.
func TestGovernedTagRemovalRaisesAnAlarm(t *testing.T) {
	MarkConformanceCase("AXC-321")

	c := newFixtureCatalog(t)
	mustRegisterAction(t, c, piiAction("crm.export"))

	events, err := c.ApplyTagChange(governedChange("crm.export", nil, []string{"pii_egress"}))
	if err != nil {
		t.Fatalf("applying the change: %v", err)
	}
	if !events.Has(EventGovernedTagRemoved, actionID("crm.export").String()) {
		t.Fatalf("removing a governed tag produced no removal event: %v", events)
	}
	alarms := events.Alarms()
	if !alarms.Has(EventGovernedTagRemoved, actionID("crm.export").String()) {
		t.Fatalf("the removal event is not an alarm: %v", events)
	}
	// The alarm is only useful if it names who to page and what stopped
	// matching.
	detail := alarms[0].Detail
	for _, want := range []string{"pii_egress", "alice", "CR-8821", "security", "constraint"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the alarm detail does not name %q: %s", want, detail)
		}
	}
	// The tag really left.
	a, ok := c.Action(actionID("crm.export"))
	if !ok {
		t.Fatalf("the action vanished")
	}
	for _, tag := range a.Tags {
		if tag == "pii_egress" {
			t.Fatalf("the governed tag is still on the action: %v", a.Tags)
		}
	}

	// A removal of a tag the action never carried changes nothing that any
	// policy reaches, so it raises no alarm. Without this, every no-op change
	// would page the owner and the alarm would be trained away.
	quiet := newFixtureCatalog(t)
	mustRegisterAction(t, quiet, sampleAction("docs.other"))
	noop, err := quiet.ApplyTagChange(governedChange("docs.other", nil, []string{"pii_egress"}))
	if err != nil {
		t.Fatalf("applying the no-op change: %v", err)
	}
	if len(noop.Alarms()) != 0 {
		t.Fatalf("removing a tag the action never carried raised an alarm: %v", noop)
	}
}

// TestGovernedTagAdditionRaisesAnAlarm is AXC-322.
func TestGovernedTagAdditionRaisesAnAlarm(t *testing.T) {
	MarkConformanceCase("AXC-322")

	c := newFixtureCatalog(t)
	mustRegisterAction(t, c, sampleAction("crm.read"))

	events, err := c.ApplyTagChange(governedChange("crm.read", []string{"pii_egress"}, nil))
	if err != nil {
		t.Fatalf("applying the change: %v", err)
	}
	if !events.Alarms().Has(EventGovernedTagAdded, actionID("crm.read").String()) {
		t.Fatalf("adding a governed tag raised no alarm: %v", events)
	}
	// The reason the addition alarms too, spelled out so the asymmetry cannot
	// quietly be reintroduced: a permission with RequiredTags reaches this
	// action now, and no policy document was edited to make that happen.
	if !strings.Contains(events.Alarms()[0].Detail, "permission") {
		t.Fatalf("the addition alarm does not say what it arms: %s", events.Alarms()[0].Detail)
	}

	// An ungoverned tag moves without an alarm, which is what makes the alarm
	// mean something.
	ungoverned, err := c.ApplyTagChange(TagChange{
		Action: actionID("crm.read"), Add: []string{"beta"},
		Actor: "alice", Reason: "the connector is in preview", At: fixtureNow,
	})
	if err != nil {
		t.Fatalf("applying the ungoverned change: %v", err)
	}
	if len(ungoverned.Alarms()) != 0 {
		t.Fatalf("an ungoverned tag change raised an alarm: %v", ungoverned)
	}
	if !ungoverned.Has(EventTagChanged, actionID("crm.read").String()) {
		t.Fatalf("an ungoverned tag change recorded no event at all: %v", ungoverned)
	}
}

// TestGovernedTagChangeRequiresApproval is AXC-323.
func TestGovernedTagChangeRequiresApproval(t *testing.T) {
	MarkConformanceCase("AXC-323")

	c := newFixtureCatalog(t)
	mustRegisterAction(t, c, piiAction("crm.export"))

	unapproved := governedChange("crm.export", nil, []string{"pii_egress"})
	unapproved.ApprovalRef = ""
	_, err := c.ApplyTagChange(unapproved)
	refusal(t, err, CodeTagChangeUnapproved)

	// The action is untouched: a refused change is refused in full.
	a, _ := c.Action(actionID("crm.export"))
	found := false
	for _, tag := range a.Tags {
		if tag == "pii_egress" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a refused change still removed the tag: %v", a.Tags)
	}

	// The requirement tracks GOVERNANCE, not the operation: the same change
	// over an ungoverned tag needs no approval.
	ungoverned := TagChange{
		Action: actionID("crm.export"), Add: []string{"beta"},
		Actor: "alice", Reason: "preview connector", At: fixtureNow,
	}
	if _, err := c.ApplyTagChange(ungoverned); err != nil {
		t.Fatalf("an ungoverned change without an approval was refused: %v", err)
	}

	// A change with no actor or no reason is refused whatever its governance,
	// because a vocabulary edit with neither is indistinguishable from a
	// mistake.
	anonymous := TagChange{Action: actionID("crm.export"), Add: []string{"beta"}, At: fixtureNow}
	_, err = c.ApplyTagChange(anonymous)
	refusal(t, err, CodeTagChangeUnapproved)

	// A tag both added and removed is a contradiction rather than a no-op.
	contradiction := governedChange("crm.export", []string{"spend"}, []string{"spend"})
	_, err = c.ApplyTagChange(contradiction)
	refusal(t, err, CodeTagChangeUnapproved)

	// A change cannot invent a tag: the vocabulary is what carries the owner
	// and the governance class, so a tag outside it has neither.
	invented := governedChange("crm.export", []string{"not_in_the_vocabulary"}, nil)
	_, err = c.ApplyTagChange(invented)
	refusal(t, err, CodeTagNotDeclared)
}

// TestActionTagsMustBeInTheVocabulary is AXC-325.
func TestActionTagsMustBeInTheVocabulary(t *testing.T) {
	MarkConformanceCase("AXC-325")

	c := newFixtureCatalog(t)
	a := sampleAction("crm.rogue")
	a.Tags = []string{"read_only", "invented_here"}
	refusal(t, c.RegisterAction(a), CodeTagNotDeclared)

	// The counterfactual: the same record with only declared tags registers.
	a.Tags = []string{"read_only"}
	accepted(t, c.RegisterAction(a))
}

// TestGovernedTagVocabularyRequiresAnOwner proves the vocabulary itself is
// governed: a governed tag with nobody to page is an alarm that goes nowhere.
func TestGovernedTagVocabularyRequiresAnOwner(t *testing.T) {
	c := NewCatalog(fixtureNow)
	refusal(t, c.RegisterTag(TagRecord{Tag: "pii_egress", Governance: TagGovernanceGoverned,
		Description: "personal data leaves"}), CodeTagOwnerRequired)

	// And a tag whose governance class nobody declared is refused, because
	// tags are an ungoverned policy channel BY DEFAULT and a default is
	// exactly what an unset class would reinstate.
	refusal(t, c.RegisterTag(TagRecord{Tag: "pii_egress", Owner: "security",
		Description: "personal data leaves"}), CodeTagGovernanceNotDeclared)

	accepted(t, c.RegisterTag(TagRecord{Tag: "pii_egress", Governance: TagGovernanceGoverned,
		Owner: "security", Description: "personal data leaves"}))
}

// TestTagGovernanceIsValidatedByMembership proves the governance class is
// checked by membership rather than against its zero value.
//
// The #3576 finding, restated for this enumeration: a check written as
// g != TagGovernanceUnspecified accepts every other out-of-range value, and one
// value past the top of the range is enough to register an ungoverned tag as
// governed or the reverse.
func TestTagGovernanceIsValidatedByMembership(t *testing.T) {
	for _, g := range []TagGovernance{TagGovernance(99), TagGovernance(-1), TagGovernanceUnspecified} {
		if g.IsValid() {
			t.Errorf("TagGovernance(%d) reported itself a declared member", int(g))
		}
		if g.Governed() {
			t.Errorf("TagGovernance(%d) reported itself governed", int(g))
		}
		c := NewCatalog(fixtureNow)
		refusal(t, c.RegisterTag(TagRecord{Tag: "x", Governance: g, Owner: "security", Description: "d"}),
			CodeTagGovernanceNotDeclared)
	}
	for _, g := range []TagGovernance{TagGovernanceGoverned, TagGovernanceUngoverned} {
		if !g.IsValid() {
			t.Errorf("%s is not reported as a declared member", g)
		}
	}
}
