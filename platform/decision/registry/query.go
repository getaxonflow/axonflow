package registry

import (
	"fmt"
	"sort"

	"axonflow/platform/decision/contract"
)

// Action returns one registered action.
//
// Every lookup on this catalog returns an explicit found flag rather than a
// zero value, and no lookup falls back to a default. A registry query that
// returned a zero ActionRecord for a missing action would hand its caller a
// posture of UNSPECIFIED, a delegation depth of zero and an empty tag set, all
// of which read as facts.
func (c *Catalog) Action(id contract.ID) (ActionRecord, bool) {
	a, ok := c.actions[id.String()]
	if !ok {
		return ActionRecord{}, false
	}
	return a.clone(), true
}

// Tool returns one registered tool.
func (c *Catalog) Tool(id contract.ID) (ToolRecord, bool) {
	t, ok := c.tools[id.String()]
	if !ok {
		return ToolRecord{}, false
	}
	return t.clone(), true
}

// ResourceType returns one registered resource type.
func (c *Catalog) ResourceType(name string) (ResourceTypeRecord, bool) {
	r, ok := c.resources[name]
	if !ok {
		return ResourceTypeRecord{}, false
	}
	return r.clone(), true
}

// PEP returns one registered enforcement point.
func (c *Catalog) PEP(id string) (PEPRecord, bool) {
	p, ok := c.peps[id]
	if !ok {
		return PEPRecord{}, false
	}
	return p.clone(), true
}

// Tag returns one vocabulary entry.
func (c *Catalog) Tag(name string) (TagRecord, bool) {
	t, ok := c.tags[name]
	return t, ok
}

// RealmDeclared reports whether a realm qualifier is declared.
func (c *Catalog) RealmDeclared(qualifier string) bool { return c.realms[qualifier] }

// ActionIDs returns every registered action identifier in a stable order.
func (c *Catalog) ActionIDs() []string { return sortedKeys(c.actions) }

// PEPIDs returns every registered enforcement point identifier in a stable
// order.
func (c *Catalog) PEPIDs() []string { return sortedKeys(c.peps) }

// ResourceTypeNames returns every registered resource type in a stable order.
func (c *Catalog) ResourceTypeNames() []string { return sortedKeys(c.resources) }

// Posture returns an action's declared posture.
//
// It fails closed on a missing record. Returning FailClosedPosture with no
// error would be the more convenient shape and is exactly wrong: a caller
// asking for the posture of an action nobody registered has a bug, and handing
// it a plausible answer hides the bug behind correct-looking behaviour.
func (c *Catalog) Posture(id contract.ID) (Posture, error) {
	a, ok := c.actions[id.String()]
	if !ok {
		return Posture{}, fmt.Errorf("registry: action %q is not registered, so it has no declared posture", id)
	}
	return a.Posture, nil
}

// ResolveActionAlias resolves a legacy connector or terminal name to its
// canonical action.
//
// Aliases exist so the migration adapter can resolve a legacy name WITHOUT a
// string heuristic. ADR-065 keeps heuristic and terminal-name authorization in
// an observable, time-bound adapter only, and an alias table is the observable
// form: every name that resolves is one somebody registered.
func (c *Catalog) ResolveActionAlias(alias string) (contract.ID, bool) {
	id, ok := c.aliases[alias]
	return id, ok
}

// ResolveToolAlias resolves a prior tool name to its canonical tool.
func (c *Catalog) ResolveToolAlias(alias string) (contract.ID, bool) {
	id, ok := c.toolAliases[alias]
	return id, ok
}

// ResolveTool resolves one tool call to its canonical action.
//
// This is the catalog lookup at ADR-065 Phase 0.2. It answers three distinct
// conditions rather than one, because an unregistered surface, a surface whose
// schema has moved under its mapping, and a registry whose own binding is
// broken need three different fixes and only one of them is the caller's.
//
// Schema drift refuses rather than mapping anyway. ADR-065's acceptance
// criterion is that "tool schema drift invalidates the mapping instead of
// producing a partial request": a mapping registered against version 18 that
// extracts $params.arguments.ticket_id has no guarantee that version 19 still
// has that field, and a mapping that silently produces a request missing a
// resource identifier produces a decision about the wrong thing.
func (c *Catalog) ResolveTool(call contract.ToolCall) Resolution {
	key := call.RegistryID.String()
	rec, ok := c.tools[key]
	if !ok {
		return Resolution{
			Status: ResolutionUnknownTool,
			Reason: contract.ReasonUnknownAction,
			Detail: fmt.Sprintf(
				"tool %q is not registered; an unregistered surface has no declared posture to consult, so it is refused before any policy loads and distinguishably from a registered action with no matching permission",
				key),
		}
	}
	if call.RegistryVersion != rec.SchemaVersion {
		return Resolution{
			Status: ResolutionSchemaDrift,
			Reason: contract.ReasonSchemaViolation,
			Detail: fmt.Sprintf(
				"tool %q is called at registry version %d but its %s mapping is registered against version %d; the mapping is invalidated rather than applied, because a mapping that extracts a field a moved schema no longer has produces a decision about the wrong resource",
				key, call.RegistryVersion, rec.Mapping, rec.SchemaVersion),
		}
	}
	if _, ok := c.actions[rec.Action.String()]; !ok {
		return Resolution{
			Status: ResolutionActionMissing,
			Reason: contract.ReasonUnknownAction,
			Detail: fmt.Sprintf(
				"tool %q resolves to action %q, which the catalog does not hold; this is a registry defect rather than an unregistered caller surface",
				key, rec.Action),
		}
	}
	return Resolution{Status: ResolutionResolved, Action: rec.Action}
}

// CheckAncestorLevel is the source specification's LEVEL_NOT_DECLARED check.
//
// A policy reading resource.<level> for a level the type does not declare is
// refused at SAVE time. The runtime alternative is worse than it looks: an
// undeclared level resolves to authoritatively absent, the condition is
// NO_MATCH rather than UNKNOWN, and the policy therefore never fires and never
// errors. The author sees a constraint that is deployed, green and inert.
//
// It returns nil when the check passes, and a finding otherwise. An unknown
// resource type is a finding rather than a pass: a check that answers "fine" on
// a type it has never heard of is a check that stops running the moment a
// catalog is loaded empty.
func (c *Catalog) CheckAncestorLevel(resourceType, level string) *Finding {
	rec, ok := c.resources[resourceType]
	if !ok {
		return &Finding{
			Code: CodeUnknownResourceType, Severity: SeverityError, Subject: resourceType,
			Message: fmt.Sprintf(
				"resource type %q is not registered, so whether it declares level %q cannot be established; an unregistered type is refused rather than assumed to declare everything",
				resourceType, level),
		}
	}
	if rec.DeclaresLevel(level) {
		return nil
	}
	return &Finding{
		Code: CodeLevelNotDeclared, Severity: SeverityError, Subject: resourceType,
		Message: fmt.Sprintf(
			"resource type %q declares ancestor levels %v and not %q; a policy reading an undeclared level resolves to authoritatively absent, so it never matches and never errors",
			resourceType, rec.Ancestors, level),
	}
}

// CheckContainmentScope is the source specification's SCOPE_REQUIRES_RECURSION
// check.
//
// A containment scope over a type whose hierarchy admits no transitive closure
// resolves to the empty set forever. Same failure shape as an undeclared level:
// deployed, green, inert.
func (c *Catalog) CheckContainmentScope(resourceType string) *Finding {
	rec, ok := c.resources[resourceType]
	if !ok {
		return &Finding{
			Code: CodeUnknownResourceType, Severity: SeverityError, Subject: resourceType,
			Message: fmt.Sprintf(
				"resource type %q is not registered, so whether a containment scope over it can resolve cannot be established", resourceType),
		}
	}
	if rec.Recursion.Recursive() {
		return nil
	}
	return &Finding{
		Code: CodeScopeRequiresRecursion, Severity: SeverityError, Subject: resourceType,
		Message: fmt.Sprintf(
			"resource type %q declares recursion %s, so a containment scope over it resolves to the empty set on every request; scope the policy to a declared ancestor level instead",
			resourceType, rec.Recursion),
	}
}

// SupportsObligation answers whether one enforcement point can discharge one
// obligation.
//
// It is the check ADR-065 invariant 8 requires: "a mandatory obligation that
// the PEP cannot understand or enforce produces deny". The answer is a typed
// status rather than a boolean so that the two ways of not knowing stay
// distinguishable; see CapabilityStatus.
func (c *Catalog) SupportsObligation(pepID string, o contract.Obligation) CapabilityCheck {
	rec, ok := c.peps[pepID]
	return checkCapability(pepID, rec, ok, o)
}

// CheckPublication refuses a policy set whose mandatory obligations no named
// enforcement point can discharge.
//
// R3 focus, and the reason this exists at all: a capability check consulted at
// decision time but not at publication turns every request through that policy
// into a deny, discovered in production by the first caller rather than at save
// time by the author. ADR-065 says the same thing from the other side, in the
// coordinator's pre-permit proof: "the PEP advertises the exact capability and
// version" is proved BEFORE the permit, and the only way to prove it early is
// to have asked before the policy was published.
//
// Every named enforcement point must be able to discharge every mandatory
// obligation. The alternative reading, that ANY one of them suffices, is the
// wrong quantifier: a decision routed to whichever plane the caller happened to
// reach would permit through the capable one and deny through the others, which
// is a policy whose meaning depends on the entry point.
//
// Two of ADR-065's ineligibility classes for the compatibility posture,
// identity-dependent and security-control-dependent actions, are properties of
// the policy set rather than of an action, and are therefore NOT decided here:
// this function sees the obligations, not the conditions that produced them.
// They are enforced by the authoring plane's own validator, which does see the
// conditions.
func (c *Catalog) CheckPublication(pepIDs []string, obligations []contract.Obligation) Findings {
	var out Findings
	if len(pepIDs) == 0 {
		return out.errorf(CodeCapabilityMissing, "(publication)",
			"publication names no enforcement point, so no capability can be proved; ADR-065 proves the exact capability and version BEFORE a permit, and an unnamed enforcement point makes that unprovable rather than satisfied")
	}
	ids := append([]string(nil), pepIDs...)
	sort.Strings(ids)
	for _, o := range sortObligations(obligations) {
		if !o.Mandatory {
			// An advisory obligation that no enforcement point can discharge is
			// dropped at composition rather than refused at publication. An
			// advisory control that can block publication is an enforcement
			// control that was never declared as one.
			continue
		}
		for _, id := range ids {
			check := c.SupportsObligation(id, o)
			if check.Supported() {
				continue
			}
			out = out.errorf(CodeCapabilityMissing, id, "%s", check.Detail)
		}
	}
	return out.Sorted()
}

func sortObligations(in []contract.Obligation) []contract.Obligation {
	out := append([]contract.Obligation(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		if out[i].SchemaVersion != out[j].SchemaVersion {
			return out[i].SchemaVersion < out[j].SchemaVersion
		}
		return out[i].SourcePolicy < out[j].SourcePolicy
	})
	return out
}

// RequiredCapabilityCheck proves that an enforcement point advertises
// everything an action's own registration says enforcing it requires.
//
// This is separate from CheckPublication because the two ask different
// questions. Publication asks whether the obligations these POLICIES attach can
// be discharged; this asks whether the enforcement point meets the action's own
// floor, which holds whether or not any policy has been written yet. An
// enforcement point that fails this must not admit the action at all.
func (c *Catalog) RequiredCapabilityCheck(pepID string, action contract.ID) Findings {
	var out Findings
	a, ok := c.actions[action.String()]
	if !ok {
		return out.errorf(CodeUnknownAction, action.String(),
			"action %q is not registered, so its required capabilities cannot be established", action)
	}
	for _, want := range sortedCapabilities(a.RequiredCapabilities) {
		check := c.SupportsObligation(pepID, contract.Obligation{
			Type: want.Type, SchemaVersion: want.Version, Mandatory: true,
		})
		if check.Supported() {
			continue
		}
		out = out.errorf(CodeCapabilityMissing, pepID,
			"action %q requires %q at version %d: %s", action, want.Type, want.Version, check.Detail)
	}
	return out.Sorted()
}
