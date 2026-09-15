// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/authoringvocabulary"
)

// rotatingTrust hands out the next store on every read, as a durable open that
// authorized another replica's key between two activations does.
type rotatingTrust struct {
	reads  int
	stores []*pdp.TrustStore
}

func (r *rotatingTrust) Current() *pdp.TrustStore {
	s := r.stores[r.reads%len(r.stores)]
	r.reads++
	return s
}

func newBuilder(t testing.TB) activationinputs.Builder {
	t.Helper()
	system, composition, err := activationinputs.NewAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	return activationinputs.Builder{
		Snapshot: &authoringcatalog.Snapshot{}, Trust: authoring.StaticTrust(pdp.NewTrustStore()),
		System: system, Composition: composition, Profile: profile,
		RefuseConstructsOutsideEdition: true, OrganizationID: "org-a",
	}
}

// sameInputs reports the first field on which two inputs differ, or "".
func sameInputs(got, want activation.Inputs) string {
	switch {
	case got.Snapshot != want.Snapshot:
		return "Snapshot"
	case got.Trust != want.Trust:
		return "Trust"
	case got.System != want.System:
		return "System"
	case got.Composition != want.Composition:
		return "Composition"
	case got.Plane != want.Plane:
		return "Plane"
	case got.Phase != want.Phase:
		return "Phase"
	case !reflect.DeepEqual(got.Delivers, want.Delivers):
		return "Delivers"
	case !reflect.DeepEqual(got.Profile, want.Profile):
		return "Profile"
	case got.RefuseConstructsOutsideEdition != want.RefuseConstructsOutsideEdition:
		return "RefuseConstructsOutsideEdition"
	case got.OrganizationID != want.OrganizationID:
		return "OrganizationID"
	case !reflect.DeepEqual(got.Overrides, want.Overrides):
		return "Overrides"
	case !reflect.DeepEqual(got.Packs, want.Packs):
		return "Packs"
	case got.Organization != nil:
		return "Organization (the builder never sets the document)"
	}
	return ""
}

// The decide inputs are exactly the ones the orchestrator's and the portal's
// typed-authoring workspaces built by hand before this package: the decide
// plane, no phase, what decide's wire delivers, the recorded posture, and the
// edition boundary as the caller asked.
func TestTheDecideInputsAreTheOnesTheWorkspacesBuiltByHand(t *testing.T) {
	b := newBuilder(t)
	posture := legacycompile.CategoryActions{"pii-us": legacycompile.ActionRedact}
	var askedFor string
	b.Posture = func(_ context.Context, orgID string) (legacycompile.CategoryActions, error) {
		askedFor = orgID
		return posture, nil
	}
	got, err := b.For(context.Background(), legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	delivers := legacycompile.ScopeDeliveries(legacycompile.MustScopeFor(legacycompile.PlaneDecide, ""))
	if len(delivers) == 0 {
		t.Fatal("PREMISE: decide's wire delivers nothing, so the Delivers comparison proves nothing")
	}
	want := activation.Inputs{
		Snapshot: b.Snapshot, Trust: b.Trust.Current(), System: b.System, Composition: b.Composition,
		Plane: string(legacycompile.PlaneDecide), Delivers: delivers,
		Profile: b.Profile, RefuseConstructsOutsideEdition: true,
		OrganizationID: "org-a", Overrides: posture,
	}
	if field := sameInputs(got, want); field != "" {
		t.Fatalf("the decide inputs differ from the hand-built ones on %s:\n got %+v\nwant %+v", field, got, want)
	}
	if askedFor != "org-a" {
		t.Fatalf("the posture was read for %q; want the builder's organization", askedFor)
	}
	via, err := b.Source(legacycompile.PlaneDecide, "")(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if field := sameInputs(via, want); field != "" {
		t.Fatalf("Source differs from For on %s", field)
	}
}

// For #4254: the workflow control plane and the multi-agent plane each take
// their inputs from the same builder. Neither wire delivers a capability
// (ScopeDeliveries names only decide and gateway_request), and each is one
// phase, so no phase is named.
func TestTheOrchestratorPlanesTakeTheirInputsFromTheSameBuilder(t *testing.T) {
	b := newBuilder(t)
	for _, plane := range []legacycompile.Plane{legacycompile.PlaneWCP, legacycompile.PlaneMAP} {
		in, err := b.For(context.Background(), plane, "")
		if err != nil {
			t.Fatalf("%s: %v", plane, err)
		}
		if in.Plane != string(plane) || in.Phase != "" || len(in.Delivers) != 0 || in.OrganizationID != "org-a" {
			t.Fatalf("%s inputs are plane %q phase %q delivers %v org %q; want the plane, no phase, nothing delivered", plane, in.Plane, in.Phase, in.Delivers, in.OrganizationID)
		}
	}
}

// A plane that evaluates two phases is one activation per phase: the builder
// refuses to choose one for the caller, and names the one it is given.
func TestATwoPhasePlaneNeedsItsPhaseNamed(t *testing.T) {
	mcp := legacycompile.Plane("mcp")
	spec, err := legacycompile.SpecFor(mcp)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Phases) < 2 {
		t.Fatalf("PREMISE: mcp evaluates %v, not two phases", spec.Phases)
	}
	b := newBuilder(t)
	if _, err := b.For(context.Background(), mcp, ""); err == nil || !strings.Contains(err.Error(), "name one") {
		t.Fatalf("mcp with no phase: %v; want the scope refused until a phase is named", err)
	}
	in, err := b.For(context.Background(), mcp, legacycompile.PhaseResponse)
	if err != nil {
		t.Fatal(err)
	}
	if in.Plane != string(mcp) || in.Phase != legacycompile.PhaseResponse {
		t.Fatalf("mcp response inputs are plane %q phase %q", in.Plane, in.Phase)
	}
}

// The recorded posture fails closed: a read that fails fails the inputs with
// the caller's own error, and no reader means no posture is recorded.
func TestTheRecordedPostureFailsClosed(t *testing.T) {
	b := newBuilder(t)
	unreadable := errors.New("the posture table is unreachable")
	b.Posture = func(context.Context, string) (legacycompile.CategoryActions, error) { return nil, unreadable }
	if _, err := b.For(context.Background(), legacycompile.PlaneDecide, ""); !errors.Is(err, unreadable) {
		t.Fatalf("with the posture unreadable: %v; want the reader's error", err)
	}
	b.Posture = nil
	in, err := b.For(context.Background(), legacycompile.PlaneDecide, "")
	if err != nil || in.Overrides != nil {
		t.Fatalf("with no posture reader: overrides %v, err %v; want none recorded", in.Overrides, err)
	}
}

// #3991: the trust store is read per activation, never captured, and there is
// no activation without one.
func TestTheTrustStoreIsReadPerActivation(t *testing.T) {
	b := newBuilder(t)
	first, second := pdp.NewTrustStore(), pdp.NewTrustStore()
	b.Trust = &rotatingTrust{stores: []*pdp.TrustStore{first, second}}
	one, err := b.For(context.Background(), legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	two, err := b.For(context.Background(), legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	if one.Trust != first || two.Trust != second {
		t.Fatal("the builder captured one trust store instead of reading the source per activation")
	}
	b.Trust = nil
	if _, err := b.For(context.Background(), legacycompile.PlaneDecide, ""); err == nil {
		t.Fatal("inputs were built with no trust source")
	}
}

// #4047: the system key and the composition key are two keys, and a second
// mint is a second pair.
func TestNewAuthoritiesMintsTwoSeparateKeys(t *testing.T) {
	system, composition, err := activationinputs.NewAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if system.PublicKey().Equal(composition.PublicKey()) {
		t.Fatal("the system authority and the composition authority share one key")
	}
	again, _, err := activationinputs.NewAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	if again.PublicKey().Equal(system.PublicKey()) {
		t.Fatal("a second mint returned the same system key")
	}
}

// #4254: the builder carries the deployment's installed policy packs into every
// activation it builds, as the agent's enforcer carries them, through For and
// Source alike; a builder given none hands none on.
func TestTheBuilderCarriesTheInstalledPacks(t *testing.T) {
	b := newBuilder(t)
	b.Packs = []activation.InstalledPack{{}, {}}
	for _, plane := range []legacycompile.Plane{legacycompile.PlaneDecide, legacycompile.PlaneWCP, legacycompile.PlaneMAP} {
		in, err := b.For(context.Background(), plane, "")
		if err != nil {
			t.Fatalf("%s: %v", plane, err)
		}
		if len(in.Packs) != len(b.Packs) || !reflect.DeepEqual(in.Packs, b.Packs) {
			t.Errorf("%s: the inputs carry %d pack(s); want the builder's %d", plane, len(in.Packs), len(b.Packs))
		}
		via, err := b.Source(plane, "")(context.Background())
		if err != nil {
			t.Fatalf("%s via Source: %v", plane, err)
		}
		if !reflect.DeepEqual(via.Packs, b.Packs) {
			t.Errorf("%s: Source carries %d pack(s); want the builder's %d", plane, len(via.Packs), len(b.Packs))
		}
	}
	b.Packs = nil
	in, err := b.For(context.Background(), legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	if in.Packs != nil {
		t.Errorf("a builder with no packs handed on %d; want none", len(in.Packs))
	}
}

// #4254: the workflow control plane and the multi-agent plane ACTIVATE against
// the shipped corpus, on both editions, with the inputs this builder hands the
// orchestrator's enforcer and the vocabulary production resolves. The shape
// test above holds only what the builder passes; this one is the engine's
// answer to it. Neither wire delivers a capability, so a shipped control that
// binds here with a mandatory obligation neither plane's profile discharges
// refuses the whole scope (activation's discharge guard, #4046), and the
// orchestrator could not build an engine for either plane.
func TestTheOrchestratorPlanesActivateOnBothEditions(t *testing.T) {
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", string(edition))
			snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
			if err != nil {
				t.Fatalf("resolving the %s deployment vocabulary: %v", edition, err)
			}
			profile, err := authoring.ProfileFor(edition)
			if err != nil {
				t.Fatal(err)
			}
			system, composition, err := activationinputs.NewAuthorities()
			if err != nil {
				t.Fatal(err)
			}
			// The strict setting: an edition boundary that may refuse, so a
			// shipped control outside the edition would red here too.
			b := activationinputs.Builder{
				Snapshot: snap, Trust: authoring.StaticTrust(pdp.NewTrustStore()),
				System: system, Composition: composition, Profile: profile,
				RefuseConstructsOutsideEdition: true, OrganizationID: "org-a",
			}
			for _, plane := range []legacycompile.Plane{legacycompile.PlaneWCP, legacycompile.PlaneMAP} {
				scope := legacycompile.MustScopeFor(plane, "")
				restricted, _, err := activation.RestrictToScope(scope)
				if err != nil {
					t.Fatalf("%s: %v", scope, err)
				}
				// ANTI-VACUITY: a plane no shipped control binds on would
				// activate whatever the guard said.
				if restricted == nil || len(restricted.Policies) == 0 {
					t.Fatalf("PREMISE: no shipped control binds on %s, so its activation proves nothing", scope)
				}
				in, err := b.For(context.Background(), plane, "")
				if err != nil {
					t.Fatalf("%s: %v", scope, err)
				}
				act, err := activation.Activate(context.Background(), in)
				if err != nil {
					t.Errorf("%s did not activate on the %s edition (%d shipped controls bind there): %v", scope, edition, len(restricted.Policies), err)
					continue
				}
				if act.Scope != scope {
					t.Errorf("activating %s built an engine for %s", scope, act.Scope)
				}
			}
		})
	}
}
