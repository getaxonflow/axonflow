// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// The override fold's own arms (#4045), each against a restriction and census
// fact derived here rather than named.

const foldOrg = "org_1"

func restrictionAndCensus(t *testing.T, scope legacycompile.EnforcementScope) (*pdp.Document, map[string]censusFact) {
	t.Helper()
	restricted, _, err := RestrictToScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	census, err := detectorCensusBySignalPath()
	if err != nil {
		t.Fatal(err)
	}
	return restricted, census
}

func carriesCategory(doc *pdp.Document, census map[string]censusFact, category string) bool {
	for _, p := range doc.Policies {
		if _, fact, ok := censusFactFor(p, census); ok && fact.category == category {
			return true
		}
	}
	return false
}

func TestNoRecordedOverrideFoldsNothing(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, _ := restrictionAndCensus(t, scope)
	fold, err := foldOverrides(scope, restricted, "", nil)
	if err != nil || fold.system != restricted || fold.reason != "" || fold.replacements != nil || fold.displacements != nil {
		t.Fatalf("an empty override set folded %+v (err=%v)", fold, err)
	}
}

func TestAPlaneThatPassesNoOverrideDisplacesNothingAndSaysSo(t *testing.T) {
	// cowork_ingest is the one plane that passes no organization override since
	// #4253 (it builds its own map; proxy_tier was the other). Its restriction
	// binds the PII redactions, so pii-us is a category an override would
	// otherwise displace there.
	scope := legacycompile.MustScopeFor(legacycompile.PlaneCoworkIngest, "")
	spec, err := legacycompile.SpecFor(scope.Plane)
	if err != nil {
		t.Fatal(err)
	}
	restricted, census := restrictionAndCensus(t, scope)
	if spec.PassesOrgOverrides || !carriesCategory(restricted, census, "pii-us") {
		t.Fatal("PREMISE: cowork_ingest passes no override and binds a pii-us control an override would otherwise displace")
	}
	fold, err := foldOverrides(scope, restricted, foldOrg, legacycompile.CategoryActions{"pii-us": legacycompile.ActionBlock})
	if err != nil {
		t.Fatal(err)
	}
	if fold.system != restricted || len(fold.replacements) != 0 {
		t.Fatalf("a plane that passes no override displaced %d controls", len(fold.replacements))
	}
	if want := []OverrideDisplacement{{Category: "pii-us", Action: legacycompile.ActionBlock}}; !reflect.DeepEqual(fold.displacements, want) {
		t.Fatalf("the fold reports %+v; want %+v", fold.displacements, want)
	}
	if !strings.Contains(fold.reason, "plane cowork_ingest passes none to its legacy engine") || !strings.Contains(fold.reason, "pii-us=block displaces nothing") {
		t.Fatalf("the reason %q does not say the override displaced nothing because the plane passes none", fold.reason)
	}
}

func TestAnAssignedCategoryNoControlOnTheScopeCarriesDisplacesNothingAndSaysSo(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
	restricted, census := restrictionAndCensus(t, scope)
	if carriesCategory(restricted, census, "security-sqli") {
		t.Fatal("PREMISE: the MCP response pass binds no security-sqli control")
	}
	fold, err := foldOverrides(scope, restricted, foldOrg, legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock})
	if err != nil {
		t.Fatal(err)
	}
	if len(fold.replacements) != 0 || !reflect.DeepEqual(fold.system.Policies, restricted.Policies) || len(fold.displacements) != 1 || fold.displacements[0].Controls != nil {
		t.Fatalf("an override no control on the scope carries changed the restriction: %+v", fold.displacements)
	}
	if want := "security-sqli=block displaces nothing, because no shipped control of that category binds on mcp:response"; !strings.Contains(fold.reason, want) {
		t.Fatalf("the reason %q does not contain %q", fold.reason, want)
	}
}

func TestEachOverrideActionCompilesTheShapeOfThatAction(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, census := restrictionAndCensus(t, scope)
	shipped := map[string]pdp.Policy{}
	for _, p := range restricted.Policies {
		shipped[p.ID] = p
	}
	for _, act := range legacycompile.OverrideActions() {
		t.Run(string(act), func(t *testing.T) {
			fold, err := foldOverrides(scope, restricted, foldOrg, legacycompile.CategoryActions{"security-sqli": act})
			if err != nil {
				t.Fatal(err)
			}
			if len(fold.replacements) == 0 || len(fold.replacements) != len(fold.displacements[0].Controls) {
				t.Fatalf("%d replacements for %d displaced controls", len(fold.replacements), len(fold.displacements[0].Controls))
			}
			for _, r := range fold.replacements {
				s, ok := shipped[strings.TrimPrefix(r.ID, OverridePolicyIDPrefix)]
				if !ok || !strings.HasPrefix(r.ID, OverridePolicyIDPrefix) {
					t.Fatalf("replacement %s names no shipped control", r.ID)
				}
				_, fact, _ := censusFactFor(s, census)
				if r.Root != pdp.RootOrganization || !reflect.DeepEqual(r.Where, s.Where) || !reflect.DeepEqual(r.Scope, s.Scope) ||
					!reflect.DeepEqual(r.Actions, s.Actions) || !strings.Contains(r.Description, foldOrg) {
					t.Fatalf("replacement %s is %+v; want the shipped control's applicability on the organization root", r.ID, r)
				}
				if derived, _ := pdp.DeriveAssurance(r); r.Assurance == "" || r.Assurance != derived {
					t.Fatalf("replacement %s declares assurance %q; its shape derives %q", r.ID, r.Assurance, derived)
				}
				var obligation contract.ObligationType
				if len(r.Obligations) == 1 {
					obligation = r.Obligations[0].Type
				}
				switch act {
				case legacycompile.ActionBlock:
					if r.Authority != contract.AuthorityConstraint || len(r.Obligations) != 0 {
						t.Fatalf("block compiled %+v; want a constraint", r)
					}
				case legacycompile.ActionRedact:
					if r.Authority != contract.AuthorityRequirement || !r.Mandatory || obligation != contract.ObFieldRedact ||
						!r.Obligations[0].Mandatory || r.Obligations[0].Target != legacycompile.DefaultContentTarget {
						t.Fatalf("redact compiled %+v; want a mandatory field_redact of %s", r, legacycompile.DefaultContentTarget)
					}
				case legacycompile.ActionWarn:
					want := map[string]string{"category": fact.category, "severity": fact.severity}
					if r.Authority != contract.AuthorityRequirement || r.Mandatory || obligation != contract.ObNotification || !reflect.DeepEqual(r.Obligations[0].Params, want) {
						t.Fatalf("warn compiled %+v; want a notification carrying %v", r, want)
					}
				case legacycompile.ActionLog:
					if r.Authority != contract.AuthorityRequirement || r.Mandatory || obligation != contract.ObImmutableAudit {
						t.Fatalf("log compiled %+v; want an immutable_audit requirement", r)
					}
				}
			}
			replacements := &pdp.Document{Root: pdp.RootOrganization, Attributes: fold.schemas, Policies: fold.replacements}
			if errs := replacements.Validate(); len(errs) > 0 {
				t.Fatalf("the replacements with the schemas the fold declares do not validate: %v", errs)
			}
			if errs := fold.system.Validate(); len(errs) > 0 || carriesCategory(fold.system, census, "security-sqli") {
				t.Fatalf("the kept restriction does not validate or still carries security-sqli: %v", errs)
			}
			kept := map[string]bool{}
			for _, a := range fold.system.Attributes {
				kept[a.Path] = true
			}
			for _, a := range fold.schemas {
				if kept[a.Path] {
					t.Fatalf("the kept restriction still declares %s, which only a displaced control reads", a.Path)
				}
			}
		})
	}
}

// TestNoPlaneBothPassesOverridesAndForcesAnAction holds the premise the fold
// relies on to apply no forced action: the legacy compile coerces after the
// override, and a plane that did both would enforce the coercion there.
func TestNoPlaneBothPassesOverridesAndForcesAnAction(t *testing.T) {
	passing := 0
	for _, p := range legacycompile.AllPlanes() {
		spec, err := legacycompile.SpecFor(p)
		if err != nil {
			t.Fatal(err)
		}
		if spec.PassesOrgOverrides {
			passing++
			if spec.ForcedAction != "" {
				t.Fatalf("plane %s passes organization overrides and forces %q; the override fold must apply the coercion before this plane enforces", p, spec.ForcedAction)
			}
		}
	}
	if passing == 0 {
		t.Fatal("PREMISE: no plane passes organization overrides, so this guard checks nothing")
	}
}

func TestFoldOverridesRefusesAnOverrideAttributedToNoOrganization(t *testing.T) {
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, _ := restrictionAndCensus(t, scope)
	if _, err := foldOverrides(scope, restricted, "", legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}); err == nil {
		t.Fatal("an override attributed to no organization was folded")
	}
}
