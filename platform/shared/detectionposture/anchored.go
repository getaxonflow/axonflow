// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package detectionposture

import (
	"fmt"
	"maps"
	"sort"

	"axonflow/platform/decision/legacycompile"
	sharedpolicy "axonflow/platform/shared/policy"
)

// inertCategories are the recorded categories that assign no action to any
// control on either engine, each with the reason (#4045). A recorded category
// that reaches no policy category and is not here is an override the anchored
// engine cannot express, and AnchoredCategoryActions refuses it rather than
// dropping it.
var inertCategories = map[string]string{
	CategoryDangerousQuery: "it reaches no policy category: \"dangerous_queries\" is a legacy string category only tenant starter policies carry (#2706)",
	CategoryObligationFallback: "it is not a detection action but the answer to a seam that cannot redact; the anchored engine answers an undischargeable mandatory obligation " +
		"with unsupported_obligation, and its obligation model is unchanged by an override",
}

// InertCategories returns a copy of the recorded categories that assign no
// action on either engine, each with its reason, for a guard that checks them
// against the categories the migrations admit.
func InertCategories() map[string]string { return maps.Clone(inertCategories) }

// AnchoredCategoryActions is an organization's recorded posture - category to
// action, as detection_action_overrides stores it - in the anchored compiler's
// key (#4045): each recorded action assigned to every policy category its
// category reaches (policy.OrgOverrideReach), the fan-out the legacy engine
// applies too.
//
// The enforcing seam and both publication dry runs fold through it, so a
// document is judged under the posture it will be enforced under (PRD v11
// §1.5). A recorded category that reaches nothing is accepted only when it is
// inert; any other category, and any action outside the four a posture records,
// is refused. With nothing assigned it returns nil.
func AnchoredCategoryActions(recorded map[string]string) (legacycompile.CategoryActions, error) {
	categories := make([]string, 0, len(recorded))
	for category := range recorded {
		categories = append(categories, category)
	}
	sort.Strings(categories)
	out := legacycompile.CategoryActions{}
	for _, category := range categories {
		action := recorded[category]
		if !ValidAction(action) {
			return nil, fmt.Errorf("detectionposture: recorded override %s=%q is not one of the actions a posture records", category, action)
		}
		reach := sharedpolicy.OrgOverrideReach(category)
		if len(reach) == 0 {
			if _, inert := inertCategories[category]; inert {
				continue
			}
			return nil, fmt.Errorf("detectionposture: recorded detection override category %q is neither folded into the anchored engine nor declared inert", category)
		}
		for _, c := range reach {
			out[string(c)] = legacycompile.LegacyAction(action)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
