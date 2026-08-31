package registry

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

func sampleTool(name, action string) ToolRecord {
	return ToolRecord{
		ID: toolID(name), Action: actionID(action), Connector: "docs",
		SchemaVersion: 18, Mapping: MappingProfile{Name: MappingCOAZMCP, Version: 1},
	}
}

func toolCall(name string, version int64) contract.ToolCall {
	return contract.ToolCall{RegistryID: toolID(name), RegistryVersion: version, ArgumentsDigest: "sha256:deadbeef"}
}

// TestUnregisteredToolIsRefusedBeforePolicy is AXC-300.
func TestUnregisteredToolIsRefusedBeforePolicy(t *testing.T) {
	MarkConformanceCase("AXC-300")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterTool(sampleTool("docs.search", "docs.search")))

	// The counterfactual: the registered tool resolves.
	got := c.ResolveTool(toolCall("docs.search", 18))
	if !got.Admits() {
		t.Fatalf("the registered tool did not resolve: %#v", got)
	}
	if got.Action != actionID("docs.search") {
		t.Fatalf("the tool resolved to %q", got.Action)
	}

	unknown := c.ResolveTool(toolCall("docs.unregistered", 18))
	if unknown.Admits() {
		t.Fatalf("an unregistered tool was admitted: %#v", unknown)
	}
	if unknown.Status != ResolutionUnknownTool {
		t.Fatalf("an unregistered tool resolved to %s", unknown.Status)
	}
	// The reason is one contract already declares. A registry-specific reason
	// code would fork the vocabulary gate 15 requires every plane to share.
	if unknown.Reason != contract.ReasonUnknownAction {
		t.Fatalf("the refusal names reason %q", unknown.Reason)
	}
	if unknown.Reason == contract.ReasonNoMatchingPermission {
		t.Fatalf("an unregistered surface is indistinguishable from a registered one with no matching permission")
	}
	if !strings.Contains(unknown.Detail, "before any policy") {
		t.Fatalf("the detail does not say the refusal precedes policy: %s", unknown.Detail)
	}
}

// TestToolSchemaDriftInvalidatesTheMapping is AXC-301.
func TestToolSchemaDriftInvalidatesTheMapping(t *testing.T) {
	MarkConformanceCase("AXC-301")

	c := newFixtureCatalog(t)
	accepted(t, c.RegisterTool(sampleTool("docs.search", "docs.search")))

	for name, version := range map[string]int64{
		"a newer schema": 19,
		"an older one":   17,
	} {
		t.Run(name, func(t *testing.T) {
			got := c.ResolveTool(toolCall("docs.search", version))
			if got.Admits() {
				t.Fatalf("a drifted call was admitted: %#v", got)
			}
			if got.Status != ResolutionSchemaDrift {
				t.Fatalf("a drifted call resolved to %s", got.Status)
			}
			if got.Reason != contract.ReasonSchemaViolation {
				t.Fatalf("drift names reason %q", got.Reason)
			}
			// Drift is distinguishable from an unregistered tool. An operator
			// fixing "the mapping is stale" and one fixing "nobody registered
			// this" are different people.
			if got.Status == ResolutionUnknownTool {
				t.Fatalf("drift is indistinguishable from an unregistered tool")
			}
		})
	}

	// A tool whose action was never registered is a registry defect rather
	// than a caller defect, and answers as one.
	broken := NewCatalog(fixtureNow)
	broken.tools[toolID("orphan").String()] = sampleTool("orphan", "nowhere")
	got := broken.ResolveTool(toolCall("orphan", 18))
	if got.Status != ResolutionActionMissing {
		t.Fatalf("an orphaned tool resolved to %s", got.Status)
	}
	if got.Admits() {
		t.Fatalf("an orphaned tool was admitted")
	}
}

// TestToolBoundToAnUnregisteredActionIsRefused is AXC-302.
func TestToolBoundToAnUnregisteredActionIsRefused(t *testing.T) {
	MarkConformanceCase("AXC-302")

	c := newFixtureCatalog(t)
	// The action was never registered, which is also what happens to an action
	// whose posture was undeclared: it was refused, so it is not in the
	// catalog, so no tool can bind to it.
	err := c.RegisterTool(sampleTool("legacy.thing", "legacy.thing"))
	refusal(t, err, CodeUnknownAction)
	if !strings.Contains(err.Error(), "posture") {
		t.Fatalf("the refusal does not explain that posture comes from the action: %v", err)
	}

	// And end to end: an action refused for an undeclared posture leaves its
	// tool unregisterable, which is the property the brief states from the
	// tool's side.
	bad := sampleAction("legacy.thing")
	bad.Posture = Posture{}
	refusal(t, c.RegisterAction(bad), CodePostureNotDeclared)
	refusal(t, c.RegisterTool(sampleTool("legacy.thing", "legacy.thing")), CodeUnknownAction)

	// The counterfactual: declare the posture, and both register.
	accepted(t, c.RegisterAction(sampleAction("legacy.thing")))
	accepted(t, c.RegisterTool(sampleTool("legacy.thing", "legacy.thing")))
}

// TestUnsupportedMappingProfileIsRefused proves the profile is negotiated
// rather than defaulted.
func TestUnsupportedMappingProfileIsRefused(t *testing.T) {
	c := newFixtureCatalog(t)
	for name, mapping := range map[string]MappingProfile{
		"an unknown profile name": {Name: "xacml", Version: 1},
		"an unknown version":      {Name: MappingCOAZ, Version: 2},
		"no profile at all":       {},
	} {
		t.Run(name, func(t *testing.T) {
			rec := sampleTool("docs.search", "docs.search")
			rec.Mapping = mapping
			refusal(t, c.RegisterTool(rec), CodeMappingProfileUnsupported)
		})
	}
	for _, profile := range SupportedMappingProfiles() {
		rec := sampleTool("docs."+profile.Name, "docs.search")
		rec.Mapping = profile
		accepted(t, c.RegisterTool(rec))
	}
}

// TestToolAliasCollisionIsRefused proves an alias resolves to one thing.
//
// An alias resolving to two tools makes the operation it names ungoverned: the
// migration adapter picks one, and which one depends on registration order.
func TestToolAliasCollisionIsRefused(t *testing.T) {
	c := newFixtureCatalog(t)
	first := sampleTool("docs.search", "docs.search")
	first.Aliases = []string{"search_docs"}
	accepted(t, c.RegisterTool(first))

	second := sampleTool("docs.search_v2", "docs.search")
	second.Aliases = []string{"search_docs"}
	refusal(t, c.RegisterTool(second), CodeAliasCollision)

	id, ok := c.ResolveToolAlias("search_docs")
	if !ok || id != toolID("docs.search") {
		t.Fatalf("the alias resolves to %q (found=%t)", id, ok)
	}
	if _, ok := c.ResolveToolAlias("never_registered"); ok {
		t.Fatalf("an unregistered alias resolved")
	}
}

// TestActionAliasResolvesWithoutAHeuristic proves the migration adapter has a
// table rather than a string heuristic.
func TestActionAliasResolvesWithoutAHeuristic(t *testing.T) {
	c := newFixtureCatalog(t)
	a := sampleAction("crm.get_contact")
	a.Aliases = []string{"getContact", "crm__get_contact"}
	accepted(t, c.RegisterAction(a))

	for _, alias := range a.Aliases {
		id, ok := c.ResolveActionAlias(alias)
		if !ok || id != a.ID {
			t.Fatalf("alias %q resolved to %q (found=%t)", alias, id, ok)
		}
	}
	// A name nobody registered does not resolve to a near neighbour.
	if _, ok := c.ResolveActionAlias("get_contact"); ok {
		t.Fatalf("an unregistered alias resolved, which is the heuristic this table replaces")
	}

	other := sampleAction("crm.other")
	other.Aliases = []string{"getContact"}
	refusal(t, c.RegisterAction(other), CodeAliasCollision)
}

// TestResolutionStatusAdmitsOnlyOneMember proves the admitting check is
// membership against the one admitting value rather than a comparison against
// a refusal.
//
// A status added later without a decision about it must refuse. Writing
// Admits as "not one of the known refusals" would make the next member a
// silent permit.
func TestResolutionStatusAdmitsOnlyOneMember(t *testing.T) {
	for _, s := range []ResolutionStatus{
		ResolutionUnspecified, ResolutionUnknownTool, ResolutionSchemaDrift,
		ResolutionActionMissing, ResolutionStatus(99), ResolutionStatus(-1),
	} {
		if (Resolution{Status: s}).Admits() {
			t.Errorf("ResolutionStatus(%d) admitted a call", int(s))
		}
	}
	if !(Resolution{Status: ResolutionResolved}).Admits() {
		t.Fatalf("the resolved status did not admit a call")
	}
	for _, s := range []ResolutionStatus{ResolutionStatus(99), ResolutionStatus(-1), ResolutionUnspecified} {
		if s.IsValid() {
			t.Errorf("ResolutionStatus(%d) reported itself a declared member", int(s))
		}
	}
}
