// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
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
	displaced := map[string][]string{}
	kept := &pdp.Document{Root: restricted.Root, Version: restricted.Version, InteractiveRealms: restricted.InteractiveRealms}
	for _, p := range restricted.Policies {
		control, _, isCorpus := legacycompile.CorpusControlOf(p.ID)
		entry, isNamed := named[control]
		if !isCorpus || !isNamed {
			kept.Policies = append(kept.Policies, p)
			continue
		}
		displaced[control] = append(displaced[control], p.ID)
		if entry.Disabled() {
			fold.disabled = append(fold.disabled, p)
			continue
		}
		_, fact, censused := censusFactFor(p, census)
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
		policies := displaced[c]
		sort.Strings(policies)
		fold.effects = append(fold.effects, SystemControlEffect{Control: c, Disabled: e.Disabled(), Action: e.Action, Policies: policies})
		instruction := "disabled"
		if !e.Disabled() {
			instruction = "action=" + string(e.Action)
		}
		if len(policies) == 0 {
			parts = append(parts, fmt.Sprintf("%s %s binds nowhere on %s", c, instruction, scope))
		} else {
			parts = append(parts, fmt.Sprintf("%s %s displaces %d shipped policy(ies)", c, instruction, len(policies)))
		}
	}
	fold.reason = "the organization's document controls the shipped set (PRD v11 §1.5): " + strings.Join(parts, "; ")
	return fold, nil
}
