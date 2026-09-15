// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/decision/registry"
)

// INSTALLED POLICY PACKS (PRD v11 §1.9, #4126), through the production
// activation path.

func testPackSource(id string) *policypack.Source {
	return &policypack.Source{
		ID: id, Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: id + "-approvers"},
		Detectors: []policypack.Detector{
			{ID: "tp_block", Name: "Test block", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Priority: 90, Pattern: "blockme", Description: "blocks."},
			{ID: "tp_step", Name: "Test step-up", Category: "fincrime", Severity: "medium", Phase: "request", Action: "require_approval", Priority: 80, Pattern: "stepme", Description: "steps up."},
			// A response detector: it binds on no request scope, so decide
			// composes two of this pack's three controls.
			{ID: "tp_response", Name: "Test response", Category: "pii-global", Severity: "low", Phase: "response", Action: "warn", Priority: 70, Pattern: "respme", Description: "warns."},
		},
	}
}

func loadPack(t *testing.T, src *policypack.Source) *policypack.Pack {
	t.Helper()
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

var (
	packBlockID    = policypack.PolicyID("testpack", "tp_block")
	packStepID     = policypack.PolicyID("testpack", "tp_step")
	packResponseID = policypack.PolicyID("testpack", "tp_response")
)

func TestInstallPacksQualifiesThePoolWithEveryRealmAPersonCanAnswerIn(t *testing.T) {
	snap := snapshot(t)
	installed, err := activation.InstallPacks(snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
	if err != nil {
		t.Fatalf("InstallPacks: %v", err)
	}
	if len(installed) != 1 || installed[0].Digest == "" || installed[0].Ref() != "testpack@"+installed[0].Digest {
		t.Fatalf("installed = %+v", installed)
	}
	for _, p := range installed[0].Document.Policies {
		if p.ID != packStepID {
			continue
		}
		// realms() declares testRealm interactive and the API-credential realm
		// not; the platform's own two realms are not interactive either.
		if got := p.Obligations[0].Params["eligible"]; got != "Group::"+testRealm+":testpack-approvers" {
			t.Fatalf("the step-up's pool is %q, want the one interactive realm's group", got)
		}
		return
	}
	t.Fatal("the instantiated document carries no step-up")
}

func TestInstallPacksRefusesWhatCannotBeInstalled(t *testing.T) {
	pack := loadPack(t, testPackSource("testpack"))
	t.Run("a deployment with no realm a person can answer in", func(t *testing.T) {
		snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, authoringcatalog.Deployment{
			Edition: registry.EditionCommunity,
			Realms:  map[string]authoring.RealmEntry{"axonflow-api-credential": {Interactive: false}},
			Now:     time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = activation.InstallPacks(snap, []*policypack.Pack{pack})
		var refusal *pdp.ActivationRefusal
		if !errors.As(err, &refusal) || refusal.Code != activation.RefusalPackApproverRealm {
			t.Fatalf("InstallPacks = %v, want %s", err, activation.RefusalPackApproverRealm)
		}
	})
	t.Run("one pack installed twice", func(t *testing.T) {
		if _, err := activation.InstallPacks(snapshot(t), []*policypack.Pack{pack, pack}); err == nil || !strings.Contains(err.Error(), "installed twice") {
			t.Fatalf("InstallPacks = %v, want the duplicate refusal", err)
		}
	})
	t.Run("two packs that ship one detector", func(t *testing.T) {
		other := loadPack(t, testPackSource("otherpack"))
		if _, err := activation.InstallPacks(snapshot(t), []*policypack.Pack{pack, other}); err == nil || !strings.Contains(err.Error(), "both ship detector") {
			t.Fatalf("InstallPacks = %v, want the shared-detector refusal", err)
		}
	})
}

// A pack composes on the organization root beside the baseline pack, and an
// organization's published document does not remove it (PRD v11 §1.9: the pack
// is the deployment's, like the baseline pack).
func TestAnInstalledPackComposesBesideTheBaselinePackWhateverIsPublished(t *testing.T) {
	w := newWorld(t)
	installed, err := activation.InstallPacks(w.snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
	if err != nil {
		t.Fatal(err)
	}
	withoutPacks := w.activate(t)
	if _, ok := withoutPacks.Policy(packBlockID); ok || len(withoutPacks.Packs) != 0 {
		t.Fatalf("with no pack installed the engine carries a pack control (packs %+v)", withoutPacks.Packs)
	}

	check := func(t *testing.T, act *activation.Activation) {
		t.Helper()
		for _, id := range []string{packBlockID, packStepID} {
			if _, ok := act.Policy(id); !ok {
				t.Errorf("%s is not composed on decide", id)
			}
		}
		if _, ok := act.Policy(packResponseID); ok {
			t.Errorf("%s, a response detector's control, is composed on decide, which scans no response", packResponseID)
		}
		want := []activation.PackActivation{{ID: "testpack", Version: 1, Digest: installed[0].Digest, Policies: 2, Of: 3}}
		if !slices.Equal(act.Packs, want) {
			t.Errorf("Packs = %+v, want %+v", act.Packs, want)
		}
		signals := act.DetectorSignalPaths()
		for _, d := range []string{"tp_block", "tp_step"} {
			if !slices.Contains(signals, legacycompile.DetectorSignalPath(d)) {
				t.Errorf("DetectorSignalPaths omits the pack detector %s", d)
			}
		}
	}

	implicit := w.activateWith(t, installed)
	if !implicit.ImplicitBaseline {
		t.Fatal("no document is published, yet the activation is not the implicit baseline")
	}
	check(t, implicit)
	if implicit.PolicyBundle == withoutPacks.PolicyBundle {
		t.Fatal("installing a pack did not move the policy bundle digest")
	}

	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	w.promote(t, w.publish(t, pack, 1, ""))
	published := w.activateWith(t, installed)
	if published.ImplicitBaseline {
		t.Fatal("a published document is active, yet the activation is the implicit baseline")
	}
	check(t, published)
}

// On decide, an Enterprise enforcement point that discharges approvals: a pack
// block is a deny, a pack step-up is a challenge whose reason is
// approval_required (PRD v11 §1.13 - the seam refuses it there, naming the
// plane), and a pack detector the evaluation did not report is not a permit.
func TestOnDecideAPackBlockDeniesAndAStepUpChallenges(t *testing.T) {
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, authoringcatalog.Deployment{
		Edition: registry.EditionEnterprise, Realms: realms(),
		Now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := activation.InstallPacks(snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
	if err != nil {
		t.Fatal(err)
	}
	_, sysPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	system, err := authoring.NewSystemAuthority(sysPriv)
	if err != nil {
		t.Fatal(err)
	}
	act, err := activation.Activate(context.Background(), activation.Inputs{
		Snapshot: snap, Trust: pdp.NewTrustStore(), System: system, Composition: compositionFrom(t, nil),
		Plane: testPlane, Delivers: contract.DecisionWireCapabilities(), Packs: installed,
	})
	if err != nil {
		t.Fatalf("activate: %v", err)
	}
	now := time.Date(2026, 9, 10, 12, 5, 0, 0, time.UTC)
	decideWith := func(t *testing.T, signals map[string]*bool) *contract.Decision {
		t.Helper()
		req := request(t, act, authoringcatalog.ActionLLMCompletion)
		for d, v := range signals {
			path := legacycompile.DetectorSignalPath(d)
			if v == nil {
				delete(req.Attributes, path)
				continue
			}
			req.Attributes[path] = contract.Known(*v, contract.ProvDetector, 1, now)
		}
		dec, err := act.Engine.Decide(context.Background(), req)
		if err != nil {
			t.Fatalf("decide: %v", err)
		}
		return dec
	}
	yes, no := true, false

	if d := decideWith(t, map[string]*bool{"tp_block": &no, "tp_step": &no}); d.State != contract.StateAllow {
		t.Fatalf("neither pack detector fired: state %s reason %s, want ALLOW (the positive control)", d.State, d.Reason)
	}
	if d := decideWith(t, map[string]*bool{"tp_block": &no, "tp_step": &yes}); d.State != contract.StateChallenge ||
		d.Reason != contract.ReasonApprovalRequired || !slices.Contains(d.Determining.MatchedRequirement, packStepID) {
		t.Fatalf("the step-up fired: state %s reason %s requirements %v, want a CHALLENGE for approval naming %s",
			d.State, d.Reason, d.Determining.MatchedRequirement, packStepID)
	}
	if d := decideWith(t, map[string]*bool{"tp_block": &yes, "tp_step": &no}); d.State != contract.StateDeny ||
		!slices.Contains(d.Determining.MatchedConstraints, packBlockID) {
		t.Fatalf("the block fired: state %s constraints %v, want a DENY naming %s", d.State, d.Determining.MatchedConstraints, packBlockID)
	}
	if d := decideWith(t, map[string]*bool{"tp_block": nil, "tp_step": &no}); d.State == contract.StateAllow {
		t.Fatal("the block's detector was not reported, and the engine permitted: an unrun detector must not read as did-not-fire")
	}
}
