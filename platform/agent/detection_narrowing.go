// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/retiredenv"
)

// refuseNarrowedDetection refuses to boot a process whose detection
// configuration narrows what the anchored engine can decide (PRD v11 §1.7,
// #4032).
//
// # WHY A REFUSAL
//
// Every enforcing scope's verdict reads the detector facts its call sites
// produce. A narrowing value stops a detector running, so the anchored engine
// reads every control behind it as UNKNOWN and refuses every request that
// reaches one - an outage that reads as a policy decision. Until v11 that
// needed an organization to opt into enforcement as well; with no decision mode
// the narrowing alone is enough. Restricting the engine to what the narrowed
// sites still evaluate instead would stop enforcing those controls with no
// author and no record, which is #4027's problem.
//
// Three narrowings, each refused by name:
//
//   - MCP_STATIC_POLICIES_ENABLED or GATEWAY_STATIC_POLICIES_ENABLED set off;
//   - a *_STATIC_POLICIES_SKIP_CATEGORIES list naming a category some
//     enforcing scope's call sites evaluate - derived from the plane registry
//     exactly as activation derives each scope's restriction, never from a
//     list kept here;
//   - any MCP_STATIC_POLICIES_CONNECTORS value, which turns detection off for
//     every connector it does not name.
//
// The default values - on, and no skip or connector list - boot, and nothing
// the platform ships sets any of them otherwise. The per-organization
// detection override (detection_action_overrides) writes an action, never
// whether a detector runs, and it is the supported way to change what a
// category does for an organization.
func refuseNarrowedDetection() error {
	var refusals []string
	for _, name := range []string{EnvMCPStaticPoliciesEnabled, EnvGatewayStaticPoliciesEnabled} {
		if !parseBoolEnv(name, true) {
			refusals = append(refusals, fmt.Sprintf("%s=%q turns detection off", name, os.Getenv(name)))
		}
	}
	for _, name := range []string{EnvMCPStaticPoliciesSkipCategories, EnvGatewayStaticPoliciesSkipCategories} {
		admitted, err := admittedByAnEnforcingScope(parseCategoryList(os.Getenv(name)))
		if err != nil {
			return err
		}
		if len(admitted) > 0 {
			refusals = append(refusals, fmt.Sprintf("%s skips %s, which an enforcing plane evaluates", name, strings.Join(admitted, ", ")))
		}
	}
	if raw := strings.TrimSpace(os.Getenv(EnvMCPStaticPoliciesConnectors)); raw != "" {
		refusals = append(refusals, fmt.Sprintf("%s=%q turns detection off for every connector it does not name", EnvMCPStaticPoliciesConnectors, raw))
	}
	if len(refusals) == 0 {
		return nil
	}
	return fmt.Errorf(
		"%s. No process flag narrows what the ADR-065 decision plane decides (%s §1.7): a detector these switch off leaves every "+
			"control that reads it UNKNOWN, and the engine refuses every request that reaches one. Remove the variable. To change what "+
			"a category does for an organization, record its detection override (detection_action_overrides, audited); to disable a "+
			"policy, use the typed policy authoring path (§1.5)",
		strings.Join(refusals, "; "), retiredenv.PRD)
}

// admittedByAnEnforcingScope returns the categories of skipped that some
// enforcing scope in this binary evaluates, sorted and de-duplicated. A scope's
// admission is derived as activation's restriction derives it: the union, over
// the scope's phases, of legacycompile.AdmissionFor, on a plane that evaluates
// the static substrate.
func admittedByAnEnforcingScope[C ~string](skipped []C) ([]string, error) {
	if len(skipped) == 0 {
		return nil, nil
	}
	var admission legacycompile.CategoryAdmission
	for _, seam := range enforcingSeams {
		if !evaluatesStaticSubstrate(seam.scope.Plane) {
			continue
		}
		for _, ph := range seam.scope.Phases() {
			a, err := legacycompile.AdmissionFor(seam.scope.Plane, ph)
			if err != nil {
				return nil, fmt.Errorf("detection: which categories %s evaluates cannot be derived, so a skip list cannot be checked against it: %w", seam.scope, err)
			}
			admission = admission.Union(a)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range skipped {
		name := string(c)
		if admission.Admits(name) && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// evaluatesStaticSubstrate reports whether a plane's call sites evaluate the
// static substrate - the one a detection category filters.
func evaluatesStaticSubstrate(p legacycompile.Plane) bool {
	for _, s := range legacycompile.MustSpecFor(p).Substrates {
		if s == legacycompile.SubstrateStatic {
			return true
		}
	}
	return false
}
