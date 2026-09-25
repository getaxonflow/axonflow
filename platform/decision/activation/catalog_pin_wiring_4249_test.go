// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"slices"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// THE SIGNED PIN IS WIRED INTO ACTIVATION, AND THIS IS WHAT PROVES THE WIRE
// (#4249 row 5706695827; master R3 round 1 on #4394, MEDIUM-1).
//
// `activation.go` reads the organization artifact's own provenance -
// `in.Organization.Provenance().CatalogVersion` - and hands it to
// BindsOnPinned, which decides whether a control naming `wcp` still binds the
// two orchestrator request routes. That single line is the whole wire, and
// before this cell existed NOTHING pinned it: master replaced it with the
// constant RouteSeamSplitCatalogVersion (every document reads as post-split, so
// a pre-split `wcp` document silently STOPS governing the routes) and with 0
// (every document reads as pre-split, so a republished `wcp` document silently
// KEEPS them), and `go test ./activation/` stayed green both times.
//
// WHY THE EXISTING CELLS MISSED IT, which is the shape worth remembering:
//   - the eight committed base artifacts carry no `binds_on` at all, so the
//     stored-bytes test's derived-scope branch is vacuous for the ALIAS: it
//     proves the pin is omitempty and the signature verifies, not what the pin
//     MEANS;
//   - the alias cells that do red call scopeUnboundControls and
//     refuseCarriedOffScope with a LITERAL pin, which is below the wiring.
//
// So this cell publishes through a catalog whose Provenance.RegistryVersion is
// set, and asserts at Activate level. It is the only cell that reads the pin
// the way production reads it.
//
// The six cases are master's, run in its own plant tree before being asked for
// here.
func TestTheCatalogPinTheArtifactCarriesDecidesWhatWcpMeant(t *testing.T) {
	base := newDigestWorld(t, registry.EditionEnterprise)
	const id = "org.catalog-pin.probe"
	routes, wcp, multiAgent := legacycompile.PlaneOrchestratorRequest, legacycompile.PlaneWCP, legacycompile.PlaneMAP

	// pinAsPublished is the world's own catalog, which pins
	// DeploymentCatalogVersion; the cases that use it are marked with this.
	const pinAsPublished int64 = -1

	cases := []struct {
		name string
		pin  int64
		// binds is the control's binds_on; nil means the member is ABSENT,
		// which binds every scope.
		binds []string
		// unboundOn says, per plane, whether the control is left OFF that
		// plane. false = it binds there.
		unboundOn map[legacycompile.Plane]bool
	}{
		{
			// The alias: at a catalog older than the split, `wcp` still meant
			// the step gate AND the two routes, so a document published then
			// must keep governing both until it is republished.
			name: "pin 6, wcp: the alias binds the routes too",
			pin:  6, binds: []string{"wcp"},
			unboundOn: map[legacycompile.Plane]bool{routes: false, wcp: false, multiAgent: true},
		},
		{
			// Every artifact published before the pin existed carries none,
			// which is pin 0 and must read as pre-split for the same reason.
			name: "pin 0 (an artifact published before the pin existed), wcp: the alias binds the routes too",
			pin:  0, binds: []string{"wcp"},
			unboundOn: map[legacycompile.Plane]bool{routes: false, wcp: false, multiAgent: true},
		},
		{
			name: "pin as published (at or past the split), wcp: the step gate alone",
			pin:  pinAsPublished, binds: []string{"wcp"},
			unboundOn: map[legacycompile.Plane]bool{routes: true, wcp: false, multiAgent: true},
		},
		{
			name: "pin as published, orchestrator_request: the routes alone",
			pin:  pinAsPublished, binds: []string{"orchestrator_request"},
			unboundOn: map[legacycompile.Plane]bool{routes: false, wcp: true, multiAgent: true},
		},
		{
			// ABSENT is every scope, at either side of the split: the pin must
			// move nothing for a document that names no scopes.
			name: "pin as published, absent: every plane",
			pin:  pinAsPublished, binds: nil,
			unboundOn: map[legacycompile.Plane]bool{routes: false, wcp: false, multiAgent: false},
		},
		{
			name: "pin 6, absent: every plane",
			pin:  6, binds: nil,
			unboundOn: map[legacycompile.Plane]bool{routes: false, wcp: false, multiAgent: false},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := base
			if tc.pin != pinAsPublished {
				w = pinnedAt(t, base, tc.pin)
			}
			doc := detectorControlDocument(t, w, id, pdp.True())
			if tc.binds != nil {
				binds := slices.Clone(tc.binds)
				doc.Policies[len(doc.Policies)-1].BindsOn = &binds
			}
			art := publishDetectorControl(t, w, id, doc)

			// THE ARTIFACT CARRIES THE PIN IT WAS PUBLISHED AT, which is what
			// activation reads; without this the cases below could all be
			// reading one pin.
			//
			// The published case expects THE CATALOG'S OWN version, not the
			// split constant (master R3 round 2 on #4394, LOW-3). Welding it
			// to RouteSeamSplitCatalogVersion would red this cell on the next
			// legitimate catalog bump - a vocabulary change has nothing to do
			// with the wiring under test - and would read as a wiring defect.
			// What the case actually needs is that the catalog is at or past
			// the split, which is what makes `wcp` mean the step gate alone,
			// so that is asserted instead of assumed.
			wantPin := tc.pin
			if tc.pin == pinAsPublished {
				wantPin = w.snap.Catalog.Provenance.RegistryVersion
				if wantPin < legacycompile.RouteSeamSplitCatalogVersion {
					t.Fatalf("PREMISE: this deployment publishes at catalog %d, older than the route-seam split at %d, so a document published now is pre-split and the post-split cases below cannot hold",
						wantPin, legacycompile.RouteSeamSplitCatalogVersion)
				}
			}
			if got := art.Provenance().CatalogVersion; got != wantPin {
				t.Fatalf("the published artifact pins catalog %d, want %d; the cases below would then all read one pin", got, wantPin)
			}

			for plane, want := range tc.unboundOn {
				act := w.activateOn(t, art, plane, "")
				if got := slices.Contains(act.ScopeUnboundControls, id); got != want {
					t.Errorf("on %s: left off = %v, want %v (ScopeUnboundControls = %v). The pin the artifact carries is %d",
						plane, got, want, act.ScopeUnboundControls, art.Provenance().CatalogVersion)
				}
			}
		})
	}
}

// pinnedAt republishes through a catalog stating registry version v, so the
// artifact carries that pin. v = 0 writes no pin at all, which is every
// artifact published before the field existed (the member is omitempty).
func pinnedAt(t *testing.T, w *digestWorld, v int64) *digestWorld {
	t.Helper()
	out := w.unpinned(t)
	out.snap.Catalog.Provenance.RegistryVersion = v
	profile, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(out.snap.Catalog, authoring.StaticTrust(out.trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	out.api = api
	return out
}
