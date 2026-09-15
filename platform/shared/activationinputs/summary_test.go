// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/activationinputs"
)

// deploymentBuilder is newBuilder over a vocabulary a deployment resolves, so
// the activation it builds is one the engine really activates.
func deploymentBuilder(t testing.TB) activationinputs.Builder {
	t.Helper()
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, authoringcatalog.Deployment{
		Edition: registry.EditionCommunity,
		Realms: map[string]authoring.RealmEntry{
			"axonflow-trusted-header": {Interactive: true},
			"axonflow-api-credential": {},
		},
		Now: time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := newBuilder(t)
	b.Snapshot = snap
	return b
}

// testPack is an installed pack with two request detectors, which decide
// composes, and one response detector, which it does not.
func testPack(t *testing.T) *policypack.Pack {
	t.Helper()
	src := &policypack.Source{
		ID: "summarypack", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "summarypack-approvers"},
		Detectors: []policypack.Detector{
			{ID: "sp_block", Name: "Summary block", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Priority: 90, Pattern: "blockme", Description: "blocks."},
			{ID: "sp_step", Name: "Summary step-up", Category: "fincrime", Severity: "medium", Phase: "request", Action: "require_approval", Priority: 80, Pattern: "stepme", Description: "steps up."},
			{ID: "sp_response", Name: "Summary response", Category: "pii-global", Severity: "low", Phase: "response", Action: "warn", Priority: 70, Pattern: "respme", Description: "warns."},
		},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The summary is the count of the activation built from the organization's
// inputs, on the scope it names. With nothing published, nothing is the
// organization's; the pack count is unknown, so it is null on the wire and not
// in the total.
func TestTheSummaryCountsWhatIsActiveOnTheScopeItNames(t *testing.T) {
	ctx := context.Background()
	b := deploymentBuilder(t)
	got, err := activationinputs.ActiveSummary(ctx, b.Source(legacycompile.PlaneDecide, ""), nil, false)
	if err != nil {
		t.Fatal(err)
	}

	in, err := b.For(ctx, legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	in.RefuseConstructsOutsideEdition = false
	act, err := activation.Activate(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	counts, err := activation.CountEffects(act.PolicyEffects())
	if err != nil {
		t.Fatal(err)
	}
	if !act.ImplicitBaseline || counts.Shipped == 0 {
		t.Fatalf("PREMISE: the activation is implicit=%v with %d shipped policies", act.ImplicitBaseline, counts.Shipped)
	}
	want := activationinputs.Summary{Scope: "decide", Shipped: counts.Shipped, Total: counts.Shipped}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary %+v; want %+v", got, want)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"scope":"decide"`, `"organization":0`, `"pack":null`, `"packs_counted":false`, `"disabled":0`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("the summary's JSON %s does not carry %s", raw, field)
		}
	}
}

// The dry-run inputs refuse a construct outside the edition unconditionally.
// The summary takes the caller's EnforcesConstructBoundary answer instead, as
// the agent's enforcing seam does, activates the artifact it is handed, and
// takes every other input from the workspace unchanged.
func TestTheSummaryGatesTheConstructBoundaryAsTheEnforcingSeamDoes(t *testing.T) {
	ctx := context.Background()
	b := deploymentBuilder(t)
	if !b.RefuseConstructsOutsideEdition {
		t.Fatal("PREMISE: the workspaces' inputs refuse unconditionally, and this builder does not")
	}
	art := &authoring.Artifact{}
	planted := errors.New("planted: the activation was not run")
	for _, enforced := range []bool{false, true} {
		var seen activation.Inputs
		restoreActivate := activationinputs.SetActivate(func(_ context.Context, in activation.Inputs) (*activation.Activation, error) {
			seen = in
			return nil, planted
		})
		_, err := activationinputs.ActiveSummary(ctx, b.Source(legacycompile.PlaneDecide, ""), art, enforced)
		restoreActivate()
		if !errors.Is(err, planted) {
			t.Fatalf("boundary %v: the activation's error came back as %v", enforced, err)
		}
		if seen.RefuseConstructsOutsideEdition != enforced {
			t.Fatalf("boundary %v: the activation refused constructs outside the edition = %v", enforced, seen.RefuseConstructsOutsideEdition)
		}
		if seen.Organization != art {
			t.Fatalf("boundary %v: the activation was not handed the active artifact", enforced)
		}
		want, err := b.For(ctx, legacycompile.PlaneDecide, "")
		if err != nil {
			t.Fatal(err)
		}
		seen.Organization, seen.RefuseConstructsOutsideEdition = nil, want.RefuseConstructsOutsideEdition
		if field := sameInputs(seen, want); field != "" {
			t.Fatalf("boundary %v: the summary changed the workspace's %s", enforced, field)
		}
	}
}

// Installed packs are counted only when the inputs carry them, and then they
// are in the total. A pack policy in an activation whose inputs carry no pack
// is refused rather than folded into a count that says packs were not counted.
func TestTheSummaryCountsInstalledPacksOnlyWhenTheInputsCarryThem(t *testing.T) {
	ctx := context.Background()
	b := deploymentBuilder(t)
	installed, err := activation.InstallPacks(b.Snapshot, []*policypack.Pack{testPack(t)})
	if err != nil {
		t.Fatal(err)
	}
	withPacks := func(ctx context.Context) (activation.Inputs, error) {
		in, err := b.For(ctx, legacycompile.PlaneDecide, "")
		in.Packs = installed
		return in, err
	}
	without, err := activationinputs.ActiveSummary(ctx, b.Source(legacycompile.PlaneDecide, ""), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	with, err := activationinputs.ActiveSummary(ctx, withPacks, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if with.Pack == nil || *with.Pack == 0 || !with.PacksCounted || with.Shipped != without.Shipped || with.Total != without.Total+*with.Pack {
		t.Fatalf("summary %+v with the pack, %+v without; want the pack's policies counted and in the total", with, without)
	}
	if without.Pack != nil || without.PacksCounted {
		t.Fatalf("summary %+v with no pack in the inputs; want pack null and packs_counted false", without)
	}

	t.Cleanup(activationinputs.SetActivate(func(ctx context.Context, in activation.Inputs) (*activation.Activation, error) {
		in.Packs = installed
		return activation.Activate(ctx, in)
	}))
	if _, err := activationinputs.ActiveSummary(ctx, b.Source(legacycompile.PlaneDecide, ""), nil, false); err == nil || !strings.Contains(err.Error(), "no installed pack") {
		t.Fatalf("pack policies with no pack in the inputs summarized with error %v; want a refusal", err)
	}
}

// A surface with no inputs is refused by name, and an inputs error - the
// recorded posture failing closed - is the summary's error.
func TestTheSummaryRefusesWithoutInputsAndReturnsTheirError(t *testing.T) {
	ctx := context.Background()
	if _, err := activationinputs.ActiveSummary(ctx, nil, nil, false); !errors.Is(err, activationinputs.ErrNoInputs) {
		t.Fatalf("no inputs summarized with error %v; want ErrNoInputs", err)
	}
	b := deploymentBuilder(t)
	unreadable := errors.New("planted: the recorded posture could not be read")
	b.Posture = func(context.Context, string) (legacycompile.CategoryActions, error) { return nil, unreadable }
	if _, err := activationinputs.ActiveSummary(ctx, b.Source(legacycompile.PlaneDecide, ""), nil, false); !errors.Is(err, unreadable) {
		t.Fatalf("an unreadable posture summarized with error %v; want it returned", err)
	}
}

// BenchmarkActiveSummary is what one summary request pays past its store read
// (#4152): the organization's inputs, an activation of the implicit baseline
// on decide, and the count. A request also pays the recorded posture's
// database read, which this builder does not make. How the activation grows
// with a published document's size is gate 17's BenchmarkGate17Activation.
func BenchmarkActiveSummary(b *testing.B) {
	ctx := context.Background()
	source := deploymentBuilder(b).Source(legacycompile.PlaneDecide, "")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := activationinputs.ActiveSummary(ctx, source, nil, false); err != nil {
			b.Fatal(err)
		}
	}
}
