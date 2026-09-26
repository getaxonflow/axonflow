// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// AN ORGANIZATION'S CONTROL OF THE SHIPPED SET, BY ID (PRD v11 §1.5)
//
// A document's system_controls names shipped system controls by their corpus
// control identifier. On every plane - not only those that pass recorded
// overrides - each named control's policies leave the scope's restriction. A
// disabled control returns nowhere. A re-actioned one returns on the
// organization root with the document's action, compiled by
// legacycompile.ActionPolicy exactly as a recorded category override's
// replacement is (#4045).
//
// THE FOLD RUNS BEFORE foldOverrides, so a control the document names is no
// longer in the restriction the category fold reads: per-policy control takes
// precedence over the recorded category posture on the same control.
//
// A SCOPE THAT FORCES AN ACTION IS THE EXCEPTION (#4259). Where the scope's
// plane coerces an action for a policy's category (legacycompile.PlaneSpec.
// Forces: the cowork ingest storage plane masks every pii-* category), the
// entry neither removes nor re-actions that policy there: it stays in the
// restriction as shipped, and the effect names it as kept (Forced). The entry
// is legitimate on every other plane it reaches, so publication warns of it
// (authoring.CodeSystemControlForcedOnScope) rather than refusing it, and the
// guarantee is this fold with refuseForcedControlMissing behind it.

// OrganizationControlPolicyIDPrefix begins the id of every policy the
// organization root carries because the organization's document re-actioned a
// shipped control. The rest of the id is the shipped policy it replaces.
const OrganizationControlPolicyIDPrefix = "organization_control:"

// SystemControlEffect is what one system_controls entry did on one scope.
type SystemControlEffect struct {
	// Control is the corpus control identifier the entry names.
	Control string
	// Disabled reports that the entry leaves the control out; otherwise Action
	// is its replacement action.
	Disabled bool
	Action   legacycompile.LegacyAction
	// Policies are the shipped policies the entry displaced on this scope,
	// sorted: empty when no policy of the control binds here.
	Policies []string
	// Forced are the shipped policies of the control this scope keeps as
	// shipped, sorted, because the scope forces an action on their category
	// (#4259): empty on every scope that forces nothing.
	Forced []string `json:",omitempty"`
}

// systemControlFold is a scope's restriction with the controlled policies left
// out, the replacements the re-actioned ones carry, the attribute schemas those
// read, what each entry did, and why.
type systemControlFold struct {
	system       *pdp.Document
	replacements []pdp.Policy
	schemas      []pdp.AttributeSchema
	effects      []SystemControlEffect
	// disabled are the shipped policies a disabled entry left out, as the
	// restriction held them, so the activation can still say what each enforced.
	disabled []pdp.Policy
	reason   string
}

// foldSystemControls folds a document's system_controls into a scope's
// restriction. With no entry it returns the restriction unchanged and no reason.
//
// Publication validated the section (authoring.validateSystemControls); the
// refusals here are for an artifact that reached activation without it, and
// for what only activation can know - whether a re-actioned policy reads a
// censused detector, whose category and severity its replacement is compiled
// from.
func foldSystemControls(scope legacycompile.EnforcementScope, restricted *pdp.Document, entries []authoring.SystemControlEntry) (systemControlFold, error) {
	fold := systemControlFold{system: restricted}
	if len(entries) == 0 {
		return fold, nil
	}
	named := make(map[string]authoring.SystemControlEntry, len(entries))
	for _, e := range entries {
		if _, twice := named[e.Control]; twice {
			return fold, fmt.Errorf("activation: the organization's document names system control %s twice", e.Control)
		}
		if !e.Disabled() && authoring.DynamicSystemControl(e.Control) {
			return fold, fmt.Errorf("activation: the organization's document assigns %q to the shipped dynamic control %s, which v11 lets an organization disable but not re-action", e.Action, e.Control)
		}
		named[e.Control] = e
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		return fold, err
	}
	spec, err := legacycompile.SpecFor(scope.Plane)
	if err != nil {
		return fold, fmt.Errorf("activation: %w", err)
	}
	displaced, forced := map[string][]string{}, map[string][]string{}
	kept := &pdp.Document{Root: restricted.Root, Version: restricted.Version, InteractiveRealms: restricted.InteractiveRealms}
	for _, p := range restricted.Policies {
		control, _, isCorpus := legacycompile.CorpusControlOf(p.ID)
		entry, isNamed := named[control]
		if !isCorpus || !isNamed {
			kept.Policies = append(kept.Policies, p)
			continue
		}
		_, fact, censused := censusFactFor(p, census)
		if _, does := spec.Forces(fact.category); censused && does {
			forced[control] = append(forced[control], p.ID)
			kept.Policies = append(kept.Policies, p)
			continue
		}
		displaced[control] = append(displaced[control], p.ID)
		if entry.Disabled() {
			fold.disabled = append(fold.disabled, p)
			continue
		}
		if !censused {
			return fold, fmt.Errorf("activation: the organization's document assigns %q to %s, whose policy %s reads no censused detector, so no replacement can be compiled for it",
				entry.Action, control, p.ID)
		}
		base := pdp.Policy{
			ID: OrganizationControlPolicyIDPrefix + p.ID, Name: p.Name, Root: pdp.RootOrganization,
			Scope: p.Scope, Actions: p.Actions, ResourceScope: p.ResourceScope, Where: p.Where, Unless: p.Unless,
			Description: fmt.Sprintf("the organization's document assigns %q to shipped control %s (PRD v11 §1.5): %s, enforced on %s with that action",
				entry.Action, control, p.ID, scope),
		}
		replacement, reasons := legacycompile.ActionPolicy(base, entry.Action, fact.category, fact.severity, legacycompile.DefaultContentTarget, scope.Plane)
		if replacement == nil {
			return fold, fmt.Errorf("activation: the organization's document assigns %q to %s, which does not compile for %s: %v", entry.Action, control, p.ID, reasons)
		}
		class, isControl := pdp.DeriveAssurance(*replacement)
		if !isControl {
			return fold, fmt.Errorf("activation: the organization's document assigns %q to %s, which compiles %s to a %s policy with no assurance class",
				entry.Action, control, p.ID, replacement.Authority)
		}
		replacement.Assurance = class
		fold.replacements = append(fold.replacements, *replacement)
	}
	kept.Attributes = schemasRead(kept.Policies, restricted.Attributes)
	fold.system = kept
	fold.schemas = schemasRead(fold.replacements, restricted.Attributes)

	controls := make([]string, 0, len(named))
	for c := range named {
		controls = append(controls, c)
	}
	sort.Strings(controls)
	parts := make([]string, 0, len(controls))
	for _, c := range controls {
		e := named[c]
		policies, keptForced := displaced[c], forced[c]
		sort.Strings(policies)
		sort.Strings(keptForced)
		fold.effects = append(fold.effects, SystemControlEffect{Control: c, Disabled: e.Disabled(), Action: e.Action, Policies: policies, Forced: keptForced})
		instruction := "disabled"
		if !e.Disabled() {
			instruction = "action=" + string(e.Action)
		}
		switch {
		case len(policies) == 0 && len(keptForced) == 0:
			parts = append(parts, fmt.Sprintf("%s %s binds nowhere on %s", c, instruction, scope))
		case len(policies) > 0:
			parts = append(parts, fmt.Sprintf("%s %s displaces %d shipped policy(ies)", c, instruction, len(policies)))
		}
		if len(keptForced) > 0 {
			parts = append(parts, fmt.Sprintf("%s %s is not applied to %d shipped policy(ies) on %s, which forces %s on their category",
				c, instruction, len(keptForced), scope, spec.ForcedAction))
		}
	}
	fold.reason = "the organization's document controls the shipped set (PRD v11 §1.5): " + strings.Join(parts, "; ")
	return fold, nil
}

// RefusalForcedControlMissing is the code Activate refuses with when a shipped
// control whose category the scope forces (legacycompile.PlaneSpec.Forces) is
// missing from the restriction the engine would enforce after every fold
// (#4259). It holds by construction, so it names a defect.
const RefusalForcedControlMissing = "FORCED_CONTROL_MISSING"

// refuseForcedControlMissing is the backstop behind foldSystemControls: every
// policy of the scope's restriction whose category the scope forces must still
// be in folded, byte-identical, or the activation refuses.
func refuseForcedControlMissing(scope legacycompile.EnforcementScope, restricted, folded *pdp.Document) error {
	spec, err := legacycompile.SpecFor(scope.Plane)
	if err != nil {
		return fmt.Errorf("activation: %w", err)
	}
	if spec.ForcedAction == "" {
		return nil
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		return err
	}
	kept := make(map[string]pdp.Policy, len(folded.Policies))
	for _, p := range folded.Policies {
		kept[p.ID] = p
	}
	for _, p := range restricted.Policies {
		_, fact, censused := censusFactFor(p, census)
		if _, does := spec.Forces(fact.category); !censused || !does {
			continue
		}
		if got, ok := kept[p.ID]; !ok || !reflect.DeepEqual(got, p) {
			return &pdp.ActivationRefusal{Code: RefusalForcedControlMissing, Detail: fmt.Sprintf(
				"%s forces %s on category %q, and the shipped policy %s is not enforced here as shipped after the organization's "+
					"system controls and overrides were folded; the plane refuses rather than store content it was built to mask",
				scope, spec.ForcedAction, fact.category, p.ID)}
		}
	}
	return nil
}
