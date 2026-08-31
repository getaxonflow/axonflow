package registry

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestProjectionCarriesTheDeclaredSchema is AXC-304.
func TestProjectionCarriesTheDeclaredSchema(t *testing.T) {
	MarkConformanceCase("AXC-304")

	c := newFixtureCatalog(t)
	a := sampleAction("crm.export_contacts")
	a.Tags = []string{"pii_egress", "read_only"}
	a.Arguments = map[string]pdp.ValueType{"segment": pdp.TypeString, "limit": pdp.TypeNumber}
	a.RequiredArguments = []string{"segment"}
	a.PayloadLeaves = []string{"response.email", "response.name"}
	a.MaxDelegationDepth = 2
	effects := failClosedEffects()
	effects.Irreversible = DeclarationYes
	effects.DataEgress = DeclarationYes
	a.Effects = effects
	accepted(t, c.RegisterAction(a))

	reg, err := c.PDPRegistry()
	if err != nil {
		t.Fatalf("projecting: %v", err)
	}
	entry, ok := reg.Actions[a.ID.String()]
	if !ok {
		t.Fatalf("the projected registry does not carry %q", a.ID)
	}
	if !reflect.DeepEqual(entry.Arguments, a.Arguments) {
		t.Errorf("the projected argument schema is %v, declared %v", entry.Arguments, a.Arguments)
	}
	if !reflect.DeepEqual(entry.RequiredArguments, []string{"segment"}) {
		t.Errorf("the projected required arguments are %v", entry.RequiredArguments)
	}
	if !reflect.DeepEqual(entry.PayloadLeaves, []string{"response.email", "response.name"}) {
		t.Errorf("the projected payload leaves are %v", entry.PayloadLeaves)
	}
	if !reflect.DeepEqual(entry.Tags, []string{"pii_egress", "read_only"}) {
		t.Errorf("the projected tags are %v", entry.Tags)
	}
	if entry.MaxDelegationDepth != 2 {
		t.Errorf("the projected delegation depth is %d", entry.MaxDelegationDepth)
	}
	// The risk classes reach the projection as the booleans the compatibility
	// rule reads, which is the whole reason they are declared rather than
	// defaulted.
	if !entry.Irreversible || !entry.DataEgress || entry.Privileged {
		t.Errorf("the projected risk classes are irreversible=%t egress=%t privileged=%t",
			entry.Irreversible, entry.DataEgress, entry.Privileged)
	}
	if !reg.Realms["realm_ws"] {
		t.Errorf("the projected realm set does not carry the declared realm")
	}

	// The projection is a copy: mutating it does not reach the catalog, so a
	// consumer cannot edit the registry through the map it was handed.
	delete(reg.Actions, a.ID.String())
	reg.Realms["realm_ws"] = false
	again, err := c.PDPRegistry()
	if err != nil {
		t.Fatalf("re-projecting: %v", err)
	}
	if _, ok := again.Actions[a.ID.String()]; !ok {
		t.Fatalf("deleting from a projection removed the action from the catalog")
	}
	if !again.Realms["realm_ws"] {
		t.Fatalf("mutating a projection changed the catalog's realm set")
	}

	// And the projected registry really admits what the catalog declared. This
	// is the end-to-end statement: the schema a request is admitted against is
	// the schema somebody registered.
	res := again.Admit(&contract.Request{
		Action: a.ID,
		Attributes: contract.AttributeSet{
			"args.segment": contract.Known("all", contract.ProvCaller, 0, fixtureNow),
		},
		Context: contract.Context{ActorChain: []contract.Actor{
			{ID: contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")},
		}},
	})
	if res.Failed {
		t.Fatalf("the projected registry refused a conforming request: %s", res.Detail)
	}
	missing := again.Admit(&contract.Request{
		Action:     a.ID,
		Attributes: contract.AttributeSet{},
		Context: contract.Context{ActorChain: []contract.Actor{
			{ID: contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")},
		}},
	})
	if !missing.Failed || missing.Reason != contract.ReasonSchemaViolation {
		t.Fatalf("the projected registry admitted a request missing a required argument: %#v", missing)
	}
}

// TestProjectionRefusesAnInvalidCatalog is AXC-319.
//
// It reaches past the registration path on purpose. Registration refuses a bad
// record, so a test that only used RegisterAction could not tell whether the
// projection is a second gate or a restatement of the first. Writing directly
// into the catalog's own map is the only way to ask that question, and the
// answer has to be that an undeclared posture still cannot reach an evaluator.
func TestProjectionRefusesAnInvalidCatalog(t *testing.T) {
	MarkConformanceCase("AXC-319")

	c := newFixtureCatalog(t)
	if _, err := c.PDPRegistry(); err != nil {
		t.Fatalf("a valid catalog did not project: %v", err)
	}

	for name, inject := range map[string]func(*Catalog){
		"an undeclared posture": func(cat *Catalog) {
			a := sampleAction("smuggled")
			a.Posture = Posture{}
			cat.actions[a.ID.String()] = a
		},
		"a permissive error posture": func(cat *Catalog) {
			a := sampleAction("smuggled")
			a.Posture = Posture{Unmatched: contract.AuthzNotApplicable, OnError: contract.AuthzPermit}
			cat.actions[a.ID.String()] = a
		},
		"an unspecified risk class": func(cat *Catalog) {
			a := sampleAction("smuggled")
			a.Effects.Privileged = DeclarationUnspecified
			cat.actions[a.ID.String()] = a
		},
		"a tag outside the vocabulary": func(cat *Catalog) {
			a := sampleAction("smuggled")
			a.Tags = []string{"invented"}
			cat.actions[a.ID.String()] = a
		},
		"a tool bound to nothing": func(cat *Catalog) {
			cat.tools[toolID("orphan").String()] = sampleTool("orphan", "nowhere")
		},
		"an enforcement point in an undeclared realm": func(cat *Catalog) {
			p := samplePEP("stray", EditionEnterprise)
			p.Realm = "realm_nobody_declared"
			cat.peps[p.ID] = p
		},
		"an alias resolving to nothing": func(cat *Catalog) {
			cat.aliases["orphaned_alias"] = actionID("never.registered")
		},
		"a tool alias resolving to nothing": func(cat *Catalog) {
			cat.toolAliases["orphaned_alias"] = toolID("never.registered")
		},
	} {
		t.Run(name, func(t *testing.T) {
			cat := newFixtureCatalog(t)
			inject(cat)
			if _, err := cat.PDPRegistry(); err == nil {
				t.Fatalf("an invalid catalog projected into an admission registry")
			}
		})
	}

	// Time alone invalidates a catalog: an exception that was live at
	// registration expires, and the projection has to notice. This is why
	// Validate re-runs rather than trusting the registration result.
	expiring := NewCatalog(fixtureNow)
	accepted(t, expiring.RegisterTag(TagRecord{Tag: "read_only", Governance: TagGovernanceUngoverned, Description: "reads"}))
	accepted(t, expiring.RegisterResourceType(ResourceTypeRecord{Type: "Ticket", Ancestors: []string{"project"}, Recursion: RecursionNone}))
	accepted(t, expiring.RegisterRealm("realm_ws"))
	e := completeException(actionID("legacy.list"))
	e.ExpiresAt = fixtureNow.Add(time.Hour)
	accepted(t, expiring.RegisterCompatibilityException(e))
	a := sampleAction("legacy.list")
	a.Posture = Posture{Unmatched: contract.AuthzPermit, OnError: contract.AuthzIndeterminate}
	accepted(t, expiring.RegisterAction(a))
	if _, err := expiring.PDPRegistry(); err != nil {
		t.Fatalf("a catalog with a live exception did not project: %v", err)
	}
	expiring.Now = fixtureNow.Add(2 * time.Hour)
	if _, err := expiring.PDPRegistry(); err == nil {
		t.Fatalf("a catalog whose exception expired still projected")
	}

	// A catalog with no evaluation instant is refused rather than reading the
	// wall clock, because a registry that silently did could not be replayed.
	clockless := newFixtureCatalog(t)
	clockless.Now = time.Time{}
	if _, err := clockless.PDPRegistry(); err == nil {
		t.Fatalf("a catalog with no evaluation instant projected")
	}

	// An empty catalog is refused: every request would be denied for naming an
	// unregistered action, which is a deployment defect rather than a policy
	// outcome, and it must not look like a working registry.
	if _, err := NewCatalog(fixtureNow).PDPRegistry(); err == nil {
		t.Fatalf("an empty catalog projected")
	}
}

// TestRegistrationIsCreateOnly is AXC-324.
func TestRegistrationIsCreateOnly(t *testing.T) {
	MarkConformanceCase("AXC-324")

	c := newFixtureCatalog(t)
	mustRegisterAction(t, c, piiAction("crm.export"))

	// The bypass this closes: re-registering the action without the governed
	// tag would remove it with no alarm and no approval reference.
	stripped := piiAction("crm.export")
	stripped.Tags = []string{"read_only"}
	err := c.RegisterAction(stripped)
	refusal(t, err, CodeAlreadyRegistered)
	if !strings.Contains(err.Error(), "ApplyTagChange") {
		t.Fatalf("the refusal does not point at the change path: %v", err)
	}

	a, _ := c.Action(actionID("crm.export"))
	found := false
	for _, tag := range a.Tags {
		if tag == "pii_egress" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a refused re-registration still changed the tags: %v", a.Tags)
	}

	// Create-only holds for every record kind, not only for actions. Each of
	// these registers a fresh identifier, so the first call must succeed and
	// the second must be refused.
	for name, again := range map[string]func() error{
		"tool":  func() error { return c.RegisterTool(sampleTool("dup", "crm.export")) },
		"realm": func() error { return c.RegisterRealm("realm_fresh") },
		"tag": func() error {
			return c.RegisterTag(TagRecord{Tag: "fresh_tag", Governance: TagGovernanceUngoverned, Description: "d"})
		},
		"resource type": func() error {
			return c.RegisterResourceType(ResourceTypeRecord{Type: "Fresh", Recursion: RecursionNone})
		},
		"pep":       func() error { return c.RegisterPEP(samplePEP("dup", EditionEnterprise)) },
		"exception": func() error { return c.RegisterCompatibilityException(completeException(actionID("crm.export"))) },
	} {
		if err := again(); err != nil {
			t.Fatalf("the first %s registration was refused: %v", name, err)
		}
		if err := again(); err == nil {
			t.Fatalf("a second %s registration of the same identifier was accepted", name)
		}
	}
}

// TestFindingsBlockOnAnUnorderableSeverity proves the ordered comparison is
// guarded at both ends.
//
// A severity nobody declared must not be filtered out of the blocking set. The
// #3576 finding applies to the ordering half here: Severity(99) >= SeverityError
// is true and Severity(-1) is quieter than everything, so a bare comparison
// answers on both sides of the range without noticing.
func TestFindingsBlockOnAnUnorderableSeverity(t *testing.T) {
	for _, s := range []Severity{Severity(99), Severity(-1), SeverityUnspecified} {
		f := Findings{{Code: CodePostureNotDeclared, Severity: s, Subject: "x", Message: "m"}}
		if !f.Blocking() {
			t.Errorf("Severity(%d) did not block", int(s))
		}
		if _, err := s.AtLeast(SeverityError); err == nil {
			t.Errorf("Severity(%d) ordered without complaint", int(s))
		}
		if _, err := SeverityError.AtLeast(s); err == nil {
			t.Errorf("Severity(%d) was accepted as an ordering floor", int(s))
		}
		// And an event carrying it stays in the alarm list rather than being
		// filtered out of the thing somebody pages from.
		if len((Events{{Code: EventGovernedTagRemoved, Severity: s}}).Alarms()) != 1 {
			t.Errorf("Severity(%d) was filtered out of the alarm list", int(s))
		}
	}
	if (Findings{{Severity: SeverityInfo}}).Blocking() {
		t.Fatalf("an info finding blocked")
	}
	if (Findings{{Severity: SeverityAlarm}}).Blocking() {
		t.Fatalf("an alarm finding blocked; an alarm pages, it does not refuse")
	}
	if !(Findings{{Severity: SeverityError}}).Blocking() {
		t.Fatalf("an error finding did not block")
	}
}

// TestFindingsAreCompleteAndOrdered proves a registration reports every reason
// it was refused, in a stable order.
//
// A first-error interface turns one fix into a queue of them, and map iteration
// would make two runs over one catalog produce two different reports.
func TestFindingsAreCompleteAndOrdered(t *testing.T) {
	c := newFixtureCatalog(t)
	a := sampleAction("crm.everything_wrong")
	a.Posture = Posture{}
	a.MaxDelegationDepth = 0
	a.Effects = Effects{}
	a.Tags = []string{"invented"}
	err := c.RegisterAction(a)
	if err == nil {
		t.Fatalf("a record with five classes of defect was accepted")
	}
	for _, want := range []Code{
		CodePostureNotDeclared, CodeDelegationDepthNotDeclared, CodeEffectNotDeclared, CodeTagNotDeclared,
	} {
		if !strings.Contains(err.Error(), string(want)) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}

	unsorted := Findings{
		{Code: CodeTagNotDeclared, Severity: SeverityError, Subject: "b", Message: "m"},
		{Code: CodePostureNotDeclared, Severity: SeverityError, Subject: "a", Message: "z"},
		{Code: CodeEffectNotDeclared, Severity: SeverityError, Subject: "a", Message: "m"},
	}
	first := unsorted.Sorted()
	second := unsorted.Sorted()
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("sorting is not stable")
	}
	if first[0].Subject != "a" || first[0].Code != CodeEffectNotDeclared {
		t.Fatalf("findings are not ordered by subject then code: %v", first)
	}
}

// TestLookupsFailClosedOnAMissingRecord proves no query hands back a plausible
// zero value for something nobody registered.
func TestLookupsFailClosedOnAMissingRecord(t *testing.T) {
	c := newFixtureCatalog(t)

	if _, err := c.Posture(actionID("never.registered")); err == nil {
		t.Fatalf("the posture of an unregistered action was returned without an error")
	}
	got, err := c.Posture(actionID("docs.search"))
	if err != nil {
		t.Fatalf("the posture of a registered action was refused: %v", err)
	}
	if got != FailClosedPosture() {
		t.Fatalf("the declared posture came back as %#v", got)
	}

	for name, lookup := range map[string]func() bool{
		"action":        func() bool { _, ok := c.Action(actionID("nope")); return ok },
		"tool":          func() bool { _, ok := c.Tool(toolID("nope")); return ok },
		"resource type": func() bool { _, ok := c.ResourceType("Nope"); return ok },
		"pep":           func() bool { _, ok := c.PEP("nope"); return ok },
		"tag":           func() bool { _, ok := c.Tag("nope"); return ok },
		"realm":         func() bool { return c.RealmDeclared("nope") },
	} {
		if lookup() {
			t.Errorf("the %s lookup found something nobody registered", name)
		}
	}
}

// TestTheCatalogHandsOutCopies proves no accessor returns a writable reference
// to the catalog's own state.
//
// Without it, every registration rule is advisory: a caller registers a clean
// record, takes it back from the accessor, adds an argument or removes a
// governed tag, and the change reaches the next projection having passed
// through no rule at all. Go makes this easy to reintroduce, because returning
// a struct by value copies the struct and shares every slice and map in it.
func TestTheCatalogHandsOutCopies(t *testing.T) {
	c := newFixtureCatalog(t)
	a := sampleAction("crm.copied")
	a.Aliases = []string{"crm_copied"}
	a.RequiredCapabilities = []contract.Capability{{Type: contract.ObFieldRedact, Version: 1}}
	accepted(t, c.RegisterAction(a))
	tool := sampleTool("crm.copied", "crm.copied")
	tool.Aliases = []string{"crm_copied_tool"}
	accepted(t, c.RegisterTool(tool))
	accepted(t, c.RegisterPEP(samplePEP("copied", EditionEnterprise,
		contract.Capability{Type: contract.ObImmutableAudit, Version: 1})))

	// Mutating the record the CALLER still holds must not reach the catalog
	// either, which is what makes the copy on store load bearing as well as the
	// copy on read.
	a.Tags[0] = "invented"
	a.Arguments["smuggled"] = pdp.TypeAny
	tool.Aliases[0] = "smuggled_alias"

	got, ok := c.Action(actionID("crm.copied"))
	if !ok {
		t.Fatalf("the action vanished")
	}
	if got.Tags[0] == "invented" {
		t.Errorf("mutating the caller's tag slice reached the catalog: %v", got.Tags)
	}
	if _, smuggled := got.Arguments["smuggled"]; smuggled {
		t.Errorf("mutating the caller's argument map reached the catalog: %v", got.Arguments)
	}

	// And mutating what the accessor handed back must not reach it either.
	got.Tags[0] = "invented"
	got.Arguments["smuggled"] = pdp.TypeAny
	got.RequiredCapabilities[0].Version = 99
	got.Aliases[0] = "smuggled_alias"
	again, _ := c.Action(actionID("crm.copied"))
	if again.Tags[0] == "invented" {
		t.Errorf("mutating a returned tag slice reached the catalog: %v", again.Tags)
	}
	if _, smuggled := again.Arguments["smuggled"]; smuggled {
		t.Errorf("mutating a returned argument map reached the catalog: %v", again.Arguments)
	}
	if again.RequiredCapabilities[0].Version != 1 {
		t.Errorf("mutating a returned capability slice reached the catalog: %v", again.RequiredCapabilities)
	}
	if again.Aliases[0] != "crm_copied" {
		t.Errorf("mutating a returned alias slice reached the catalog: %v", again.Aliases)
	}

	gotTool, _ := c.Tool(toolID("crm.copied"))
	gotTool.Aliases[0] = "smuggled_again"
	againTool, _ := c.Tool(toolID("crm.copied"))
	if againTool.Aliases[0] != "crm_copied_tool" {
		t.Errorf("mutating a returned tool alias slice reached the catalog: %v", againTool.Aliases)
	}

	gotPEP, _ := c.PEP("copied")
	gotPEP.Capabilities[0].Version = 99
	againPEP, _ := c.PEP("copied")
	if againPEP.Capabilities[0].Version != 1 {
		t.Errorf("mutating a returned capability slice reached the catalog: %v", againPEP.Capabilities)
	}

	gotRT, _ := c.ResourceType("Ticket")
	gotRT.Ancestors[0] = "smuggled"
	againRT, _ := c.ResourceType("Ticket")
	if againRT.Ancestors[0] != "project" {
		t.Errorf("mutating a returned ancestor slice reached the catalog: %v", againRT.Ancestors)
	}

	// A declared-empty capability set comes back non-nil, so it cannot
	// round-trip through JSON into an absent field and collapse into the
	// no-record state.
	accepted(t, c.RegisterPEP(samplePEP("declares-nothing", EditionEnterprise)))
	empty, _ := c.PEP("declares-nothing")
	if empty.Capabilities == nil {
		t.Errorf("a declared-empty capability set came back nil")
	}
	if len(empty.Capabilities) != 0 {
		t.Errorf("a declared-empty capability set came back with %d entries", len(empty.Capabilities))
	}
}
