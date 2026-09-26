// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"errors"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// TestAnEmptyBindsOnIsRefusedNotRead: publication refuses binds_on: [], and
// a document carrying one anyway (another build's, or a store edited under
// the platform) is refused at activation on every scope. It is never read as
// absent (every scope, which enforces what the author confined) nor as
// nowhere (which removes a constraint from every scope).
func TestAnEmptyBindsOnIsRefusedNotRead(t *testing.T) {
	doc := &pdp.Document{Policies: []pdp.Policy{
		{ID: "unscoped"},
		{ID: "confined", BindsOn: &[]string{}},
	}}
	for _, scope := range legacycompile.AllScopes() {
		_, err := scopeUnboundControls(scope, doc, legacycompile.EnforcingScopes(), legacycompile.RouteSeamSplitCatalogVersion)
		var refusal *pdp.ActivationRefusal
		if !errors.As(err, &refusal) || refusal.Code != RefusalBindsOnInvalid {
			t.Fatalf("%s: %v, want %s", scope, err, RefusalBindsOnInvalid)
		}
	}
}

// TestScopeUnboundControlsNamesOnlyTheConfined: an absent binds_on is never
// unbound, and a list is unbound exactly where it does not name the scope.
func TestScopeUnboundControlsNamesOnlyTheConfined(t *testing.T) {
	doc := &pdp.Document{Policies: []pdp.Policy{
		{ID: "unscoped"},
		{ID: "steps", BindsOn: &[]string{"map", "wcp"}},
		{ID: "mcp", BindsOn: &[]string{"mcp:request"}},
	}}
	cases := map[string][]string{
		"wcp":          {"mcp"},
		"map":          {"mcp"},
		"mcp:request":  {"steps"},
		"mcp:response": {"steps", "mcp"},
		"decide":       {"steps", "mcp"},
		// A document published AT the split binds what it names, so a control
		// naming wcp is unbound on the routes' own plane.
		"orchestrator_request": {"steps", "mcp"},
	}
	for name, want := range cases {
		plane, phase, _ := strings.Cut(name, ":")
		got, err := scopeUnboundControls(legacycompile.MustScopeFor(legacycompile.Plane(plane), legacycompile.Phase(phase)), doc, legacycompile.EnforcingScopes(), legacycompile.RouteSeamSplitCatalogVersion)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: unbound %v, want %v", name, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: unbound %v, want %v", name, got, want)
			}
		}
	}
}

// TestTheBackstopRefusesACarriedOffScopeControlByCode: the organization root
// refuseCarriedOffScope is handed carries a control whose binds_on excludes the
// scope, which composition never produces, so the backstop names the defect by
// its code; an absent binds_on binds everywhere and is never refused.
func TestTheBackstopRefusesACarriedOffScopeControlByCode(t *testing.T) {
	mcpRequest := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseRequest)
	err := refuseCarriedOffScope(mcpRequest, &pdp.Document{Policies: []pdp.Policy{{ID: "steps", BindsOn: &[]string{"wcp"}}}}, legacycompile.RouteSeamSplitCatalogVersion)
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) || refusal.Code != RefusalBindsOnCarriedOffScope || !strings.Contains(refusal.Detail, "[wcp]") {
		t.Fatalf("got %v; want %s naming [wcp]", err, RefusalBindsOnCarriedOffScope)
	}
	if err := refuseCarriedOffScope(mcpRequest, &pdp.Document{Policies: []pdp.Policy{{ID: "everywhere"}}}, legacycompile.RouteSeamSplitCatalogVersion); err != nil {
		t.Fatalf("an absent binds_on was refused: %v", err)
	}
	if got := describeBindsOn(nil); got != "every scope" {
		t.Fatalf("describeBindsOn(nil) = %q", got)
	}
	// THE BACKSTOP READS THE SAME PINNED ANSWER THE OMISSION DID. A pre-split
	// document's wcp control is KEPT on the routes' plane by the alias, so a
	// backstop reading the unaliased answer would refuse the whole plane for
	// the one control the compatibility rule exists to keep.
	routes := legacycompile.MustScopeFor(legacycompile.PlaneOrchestratorRequest, "")
	preSplit := &pdp.Document{Policies: []pdp.Policy{{ID: "steps", BindsOn: &[]string{"wcp"}}}}
	if err := refuseCarriedOffScope(routes, preSplit, 0); err != nil {
		t.Fatalf("the backstop refused a pre-split wcp control on the routes' plane: %v", err)
	}
	if err := refuseCarriedOffScope(routes, preSplit, legacycompile.RouteSeamSplitCatalogVersion); err == nil {
		t.Fatal("the backstop admitted a post-split wcp control on the routes' plane; composition never carries one there")
	}
}

// A DOCUMENT PUBLISHED BEFORE THE SPLIT KEEPS THE ROUTES (#4249 row
// 5706695827). Until the split `wcp` meant the step gate AND the two request
// routes, so a control that named it governed both; the alias keeps that until
// the document is republished. Every other scope answers as it did, at every
// pin: the alias is one plane's, not a general widening.
func TestAPreSplitDocumentKeepsTheRoutesUntilItIsRepublished(t *testing.T) {
	doc := &pdp.Document{Policies: []pdp.Policy{
		{ID: "steps", BindsOn: &[]string{"wcp"}},
		{ID: "mcp", BindsOn: &[]string{"mcp:request"}},
	}}
	routes := legacycompile.MustScopeFor(legacycompile.PlaneOrchestratorRequest, "")
	for _, pin := range []int64{0, legacycompile.RouteSeamSplitCatalogVersion - 1} {
		got, err := scopeUnboundControls(routes, doc, legacycompile.EnforcingScopes(), pin)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "mcp" {
			t.Errorf("pin %d: unbound on the routes = %v, want only the mcp control: a wcp control of a pre-split document still binds there", pin, got)
		}
	}
	for _, pin := range []int64{legacycompile.RouteSeamSplitCatalogVersion, legacycompile.RouteSeamSplitCatalogVersion + 1} {
		got, err := scopeUnboundControls(routes, doc, legacycompile.EnforcingScopes(), pin)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Errorf("pin %d: unbound on the routes = %v, want both controls: a document published at or after the split binds what it names", pin, got)
		}
	}
	// THE ALIAS IS ONE PLANE'S. On every other scope the answer is the pin's
	// independent, so an old document is not widened anywhere else.
	for _, scope := range legacycompile.AllScopes() {
		if scope == routes {
			continue
		}
		old, err := scopeUnboundControls(scope, doc, legacycompile.EnforcingScopes(), 0)
		if err != nil {
			t.Fatal(err)
		}
		now, err := scopeUnboundControls(scope, doc, legacycompile.EnforcingScopes(), legacycompile.RouteSeamSplitCatalogVersion)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(old, ",") != strings.Join(now, ",") {
			t.Errorf("%s: unbound %v at pin 0 and %v at the split; only the routes' plane may differ", scope, old, now)
		}
	}
}
