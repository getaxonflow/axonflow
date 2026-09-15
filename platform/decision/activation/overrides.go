// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// AN ORGANIZATION'S RECORDED DETECTION OVERRIDE, ON THE ANCHORED ENGINE (#4045)
//
// detection_action_overrides is the one lever that changes the action a shipped
// detection control enforces for an organization (#3961). The legacy engine
// reads it as override-else-stored, keyed by the row's policy category
// (legacycompile.CategoryActions.Apply), on every plane whose call sites pass
// the map (PlaneSpec.PassesOrgOverrides). The anchored engine read the shipped
// actions only, so cutting a plane over silently returned an organization that
// had recorded an override to the shipped default.
//
// The fold expresses the override on ADR-065's two roots and edits no control:
//
//   - LEAVE OUT. Each shipped control on the scope whose censused category the
//     organization assigned an action to leaves the system restriction. The
//     anchor admits it, because a restriction may only leave controls out, and
//     the restriction's reason names the organization and the categories.
//   - REPLACE. The same control - the same scope, action selector and
//     condition - returns on the organization root with the assigned action,
//     compiled by legacycompile.ActionPolicy, the mapping the shipped corpus is
//     compiled through. authoring.CompositionAuthority signs it beside the
//     organization's authored document.
//
// WHAT IT HONOURS, AS THE LEGACY ENGINE DOES:
//
//   - A WEAKER action. A recorded pii=log displaces a shipped redaction. The
//     organization recorded that choice through an audited write, and refusing
//     it would be the anchored engine enforcing a posture nobody chose.
//   - An EQUAL action. It still displaces: CategoryActions counts an assigned
//     action equal to the stored one as a displacement, and the replacement is
//     then the shipped control on the root the record says it comes from.
//   - A plane that passes no override (cowork_ingest) displaces nothing, and an
//     assigned category no control on the scope carries displaces nothing. The
//     reason says which, so an override never vanishes silently.
//
// WHAT IT DOES NOT CHANGE: a replacement's obligations are mandatory exactly as
// ActionPolicy makes them. A redact override is a mandatory field_redact, and a
// caller that cannot discharge it is refused unsupported_obligation where the
// legacy engine's obligation fallback may release (ADR-065's #4045 amendment).

// OverridePolicyIDPrefix begins the id of every policy the organization root
// carries because a recorded override re-actioned a shipped control. The rest of
// the id is the shipped policy it displaces.
const OverridePolicyIDPrefix = "organization_override:"

// RefusalOverridePolicyIDReserved is the code Activate refuses an authored
// policy with whose id takes OverridePolicyIDPrefix. It is refused on every
// activation, dry runs included, so a document that would collide with an
// override's replacement never becomes active.
const RefusalOverridePolicyIDReserved = "OVERRIDE_POLICY_ID_RESERVED"

// RefusalCompositionKeySignsAnotherRoot is the code Activate refuses with when
// the composition authority's key is the system key or the key that signed the
// organization document.
const RefusalCompositionKeySignsAnotherRoot = "COMPOSITION_KEY_SIGNS_ANOTHER_ROOT"

// OverrideDisplacement is what one assigned category did on one scope.
type OverrideDisplacement struct {
	// Category is the policy category the organization assigned an action to,
	// as legacycompile.CategoryActions keys it.
	Category string
	// Action is the assigned action.
	Action legacycompile.LegacyAction
	// Controls are the shipped policies it displaced on this scope, sorted:
	// empty when the plane passes no override or no control of the category
	// binds on the scope.
	Controls []string
}

// overrideFold is a scope's restriction with the displaced controls left out,
// their replacements, the attribute schemas the replacements read, and why.
type overrideFold struct {
	system        *pdp.Document
	replacements  []pdp.Policy
	schemas       []pdp.AttributeSchema
	displacements []OverrideDisplacement
	reason        string
}

// foldOverrides folds an organization's assigned actions into a scope's
// restriction. With nothing assigned it returns the restriction unchanged and
// no reason.
//
// The legacy compile applies a plane's forced action after the override. The
// fold applies none, because no plane both passes overrides and forces an
// action; TestNoPlaneBothPassesOverridesAndForcesAnAction reds the day one does.
func foldOverrides(scope legacycompile.EnforcementScope, restricted *pdp.Document, org string, assigned legacycompile.CategoryActions) (overrideFold, error) {
	fold := overrideFold{system: restricted}
	if len(assigned) == 0 {
		return fold, nil
	}
	if org == "" {
		return fold, fmt.Errorf("activation: recorded detection overrides were supplied with no organization to attribute them to")
	}
	categories := slices.Sorted(maps.Keys(assigned))
	for _, c := range categories {
		if !slices.Contains(legacycompile.OverrideActions(), assigned[c]) {
			return fold, fmt.Errorf("activation: organization %q assigns action %q to category %q; a detection override records one of %v, and nothing else is compiled",
				org, assigned[c], c, legacycompile.OverrideActions())
		}
	}
	spec, err := legacycompile.SpecFor(scope.Plane)
	if err != nil {
		return fold, fmt.Errorf("activation: %w", err)
	}
	displaced := map[string][]string{}
	if spec.PassesOrgOverrides {
		census, err := detectorCensusBySignalPath()
		if err != nil {
			return fold, err
		}
		kept := &pdp.Document{Root: restricted.Root, Version: restricted.Version, InteractiveRealms: restricted.InteractiveRealms}
		for _, p := range restricted.Policies {
			_, fact, censused := censusFactFor(p, census)
			act, isAssigned := assigned[fact.category]
			if !censused || !isAssigned {
				kept.Policies = append(kept.Policies, p)
				continue
			}
			// The replacement is the shipped control enforced with the recorded
			// action, so it carries that control's display name (PRD v11 §1.14):
			// its id and description say an override assigned the action.
			base := pdp.Policy{
				ID: OverridePolicyIDPrefix + p.ID, Name: p.Name, Root: pdp.RootOrganization,
				Scope: p.Scope, Actions: p.Actions, ResourceScope: p.ResourceScope, Where: p.Where, Unless: p.Unless,
				Description: fmt.Sprintf("organization %s's recorded detection override assigns %q to category %q: shipped control %s, enforced on %s with that action",
					org, act, fact.category, p.ID, scope),
			}
			replacement, reasons := legacycompile.ActionPolicy(base, act, fact.category, fact.severity, legacycompile.DefaultContentTarget, scope.Plane)
			if replacement == nil {
				return fold, fmt.Errorf("activation: organization %q's override %s=%s does not compile for %s: %v", org, fact.category, act, p.ID, reasons)
			}
			class, isControl := pdp.DeriveAssurance(*replacement)
			if !isControl {
				return fold, fmt.Errorf("activation: organization %q's override %s=%s compiled %s to a %s policy, which has no assurance class", org, fact.category, act, p.ID, replacement.Authority)
			}
			replacement.Assurance = class
			fold.replacements = append(fold.replacements, *replacement)
			displaced[fact.category] = append(displaced[fact.category], p.ID)
		}
		kept.Attributes = schemasRead(kept.Policies, restricted.Attributes)
		fold.system = kept
		fold.schemas = schemasRead(fold.replacements, restricted.Attributes)
	}
	parts := make([]string, 0, len(categories))
	for _, c := range categories {
		controls := displaced[c]
		slices.Sort(controls)
		fold.displacements = append(fold.displacements, OverrideDisplacement{Category: c, Action: assigned[c], Controls: controls})
		switch {
		case len(controls) > 0:
			parts = append(parts, fmt.Sprintf("%s=%s displaces %d shipped control(s), carried on the organization root with that action", c, assigned[c], len(controls)))
		case spec.PassesOrgOverrides:
			parts = append(parts, fmt.Sprintf("%s=%s displaces nothing, because no shipped control of that category binds on %s", c, assigned[c], scope))
		default:
			parts = append(parts, fmt.Sprintf("%s=%s displaces nothing", c, assigned[c]))
		}
	}
	if spec.PassesOrgOverrides {
		fold.reason = fmt.Sprintf("organization %s's recorded detection overrides (#4045): %s", org, strings.Join(parts, "; "))
	} else {
		fold.reason = fmt.Sprintf("organization %s records detection overrides, and plane %s passes none to its legacy engine (PlaneSpec.PassesOrgOverrides), so none displaces a control here: %s",
			org, scope.Plane, strings.Join(parts, "; "))
	}
	return fold, nil
}

// refuseReservedOverrideIDs refuses an authored policy whose id takes a prefix a
// replacement on the organization root carries: a recorded override's
// (OverridePolicyIDPrefix) or the document's own system control's
// (OrganizationControlPolicyIDPrefix).
func refuseReservedOverrideIDs(doc *pdp.Document) error {
	for _, p := range doc.Policies {
		for _, reserved := range []struct{ prefix, carrier string }{
			{OverridePolicyIDPrefix, "an organization's recorded detection override"},
			{OrganizationControlPolicyIDPrefix, "the organization's system_controls"},
		} {
			if strings.HasPrefix(p.ID, reserved.prefix) {
				return &pdp.ActivationRefusal{
					Code: RefusalOverridePolicyIDReserved,
					Detail: fmt.Sprintf("authored policy %q takes the prefix %q, which names a shipped control that %s carries on the "+
						"organization root; rename the policy", p.ID, reserved.prefix, reserved.carrier),
				}
			}
		}
	}
	return nil
}
