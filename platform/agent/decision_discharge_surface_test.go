// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"sort"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
)

// WHAT A SEAM DELIVERS, HELD TO THE CODE THAT DELIVERS IT (#4046).
//
// activation refuses a scope whose restriction carries a mandatory obligation
// nothing on it can discharge, and it counts what the scope's wire hands to a
// caller that declares it (activation.Inputs.Delivers). That delivery is stated
// once, beside the seam list (enforcingSeams), and these tests are why the
// statement cannot drift from the seam: one drives the renderer and holds it to
// the vocabulary activation reads, the other activates every registered seam
// with exactly the delivery it declares.

// TestTheDecisionWireRendersExactlyItsVocabulary holds wireObligationsFor to
// contract.DecisionWireCapabilities - the capabilities activation is told the
// decide seam delivers - in both directions, by DRIVING it.
//
// Every declared obligation type, at every version the vocabulary names for it,
// the version after, and versions 1 and 2, is handed to the renderer as a
// mandatory obligation on the evaluated content. What it renders without
// refusing is what the Decision API can carry, and that set must equal the
// vocabulary: a type the renderer carries and the table does not would be
// delivered to callers activation never counted, and a type the table names and
// the renderer refuses would let activation pass a scope whose every such
// request is then denied. immutable_audit is discharged by the handler's own
// audit row, so it is neither rendered nor refused.
func TestTheDecisionWireRendersExactlyItsVocabulary(t *testing.T) {
	vocabulary := map[contract.Capability]bool{}
	for _, c := range contract.DecisionWireCapabilities() {
		vocabulary[c] = true
	}
	if len(vocabulary) == 0 {
		t.Fatal("the Decision API vocabulary is empty, so this comparison could agree on nothing")
	}

	rendered := map[contract.Capability]bool{}
	probed := 0
	for _, typ := range contract.AllObligationTypes() {
		versions := map[int]bool{1: true, 2: true}
		for c := range vocabulary {
			if c.Type == typ {
				versions[c.Version], versions[c.Version+1] = true, true
			}
		}
		for v := range versions {
			o := contract.Obligation{Type: typ, Target: legacycompile.DefaultContentTarget, Mandatory: true, SchemaVersion: v, SourcePolicy: "probe"}
			probed++
			out, refusal := wireObligationsFor([]contract.Obligation{o}, decideSeamScope)
			switch {
			case typ == contract.ObImmutableAudit:
				if refusal != "" || len(out) != 0 {
					t.Errorf("%s is discharged by the audit row and must be neither rendered nor refused: rendered %+v, refusal %q", o.CapabilityOf(), out, refusal)
				}
			case refusal == "" && len(out) == 1:
				rendered[o.CapabilityOf()] = true
				if name, ok := contract.DecisionWireNameFor(o); !ok || out[0].Type != name {
					t.Errorf("%s rendered as %q; the vocabulary names it %q (carried=%v)", o.CapabilityOf(), out[0].Type, name, ok)
				}
			case refusal != "" && out == nil:
			default:
				t.Errorf("%s rendered %+v with refusal %q; a mandatory obligation is carried or refused, never both and never neither", o.CapabilityOf(), out, refusal)
			}
		}
	}

	var onlyRendered, onlyVocabulary []string
	for c := range rendered {
		if !vocabulary[c] {
			onlyRendered = append(onlyRendered, c.String())
		}
	}
	for c := range vocabulary {
		if !rendered[c] {
			onlyVocabulary = append(onlyVocabulary, c.String())
		}
	}
	sort.Strings(onlyRendered)
	sort.Strings(onlyVocabulary)
	if len(onlyRendered) > 0 || len(onlyVocabulary) > 0 {
		t.Fatalf("the renderer and the Decision API vocabulary disagree after %d probes: rendered but not in the vocabulary %v; in the vocabulary but refused %v",
			probed, onlyRendered, onlyVocabulary)
	}
}

// TestEveryEnforcingSeamActivatesOnBothEditions is the guard #4046 asks for,
// at the SEAM: every scope this binary registers as enforcing is activated
// against the shipped corpus, in both editions, with exactly the delivery its
// seam declares, through the activation.Activate the enforcer calls and the
// vocabulary resolution production uses. The population is enforcingSeams -
// the list the enforcer is built from and /health reports - so a seam added
// there is judged here the day it lands, and one whose restriction it cannot
// discharge reds in CI rather than failing closed on its first request. This is the check that would have refused decide when #4025 merged.
func TestEveryEnforcingSeamActivatesOnBothEditions(t *testing.T) {
	if len(enforcingSeams) == 0 {
		t.Fatal("enforcingSeams is empty, so no seam was judged")
	}
	ctx := context.Background()
	for _, mode := range []string{"community", "enterprise"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
			if err != nil {
				t.Fatalf("resolving the %s deployment vocabulary: %v", mode, err)
			}
			_, sysPriv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			system, err := authoring.NewSystemAuthority(sysPriv)
			if err != nil {
				t.Fatal(err)
			}
			// An organization with no document is decided under the implicit
			// baseline, which the enforcer's composition authority signs.
			_, compositionPriv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			composition, err := authoring.NewCompositionAuthority(compositionPriv)
			if err != nil {
				t.Fatal(err)
			}
			inputs := func(scope legacycompile.EnforcementScope, delivers []contract.Capability) activation.Inputs {
				return activation.Inputs{
					Snapshot: snap, Trust: pdp.NewTrustStore(), System: system, Composition: composition,
					Plane: string(scope.Plane), Phase: scope.Phase, Delivers: delivers,
				}
			}

			for _, seam := range enforcingSeams {
				if got := seamDelivers(seam.scope); fmt.Sprint(got) != fmt.Sprint(seam.delivers) {
					t.Errorf("seamDelivers(%s) = %v; the seam list declares %v", seam.scope, got, seam.delivers)
				}
				if seam.scope.ContentPhase() == "" {
					t.Errorf("%s names no content phase, so a redaction of the content it evaluated could not be fulfilled anywhere", seam.scope)
				}
				act, err := activation.Activate(ctx, inputs(seam.scope, seam.delivers))
				if err != nil {
					t.Errorf("%s did not activate on the %s edition with the delivery its seam declares (%v): %v", seam.scope, mode, seam.delivers, err)
					continue
				}
				if act.Scope != seam.scope {
					t.Errorf("activating %s built an engine for %s", seam.scope, act.Scope)
				}
			}
			// The delivery is not load bearing on the SHIPPED corpus: it binds
			// decide the action decide's legacy engine enforces, so no seam's
			// restriction carries a mandatory obligation only its wire discharges.
			// What the delivery discharges is proven on a planted document
			// (activation's TestAMandatoryRedactionOnDecideIsDischargedOnlyThroughTheDecisionWire);
			// that the enforcer hands it to activation is the test below.
		})
	}
}

// TestTheEnforcerActivatesEverySeamWithTheDeliveryItDeclares holds the one
// production path that builds a seam's engine - anchoredEnforcer.activationFor -
// to the delivery the seam list declares. It reads the built Activation rather
// than a verdict, because on the shipped corpus no verdict depends on the
// delivery: the day a shipped or authored control binds a mandatory obligation
// on a decision-returning scope, the delivery decides whether that scope
// activates, and an enforcer that dropped it would refuse the scope then.
func TestTheEnforcerActivatesEverySeamWithTheDeliveryItDeclares(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	snap := enfSnapshot(t)
	docs := enfPublishDocument(t, snap)
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newAnchoredEnforcer(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	digest, _, err := docs.ActiveTip(ctx, enfOrgPublished)
	if err != nil || digest == "" {
		t.Fatalf("CONTROL: the published document has no active tip for %s (digest %q, err %v)", enfOrgPublished, digest, err)
	}
	delivering, silent := 0, 0
	for _, seam := range enforcingSeams {
		act, err := e.activationFor(ctx, seam.scope, enfOrgPublished, digest, nil)
		if err != nil {
			t.Errorf("the enforcer did not activate %s: %v", seam.scope, err)
			continue
		}
		if fmt.Sprint(act.Delivers) != fmt.Sprint(seam.delivers) {
			t.Errorf("the enforcer activated %s delivering %v; the seam list declares %v", seam.scope, act.Delivers, seam.delivers)
		}
		if len(seam.delivers) > 0 {
			delivering++
		} else {
			silent++
		}
	}
	// ANTI-VACUITY: a seam that delivers and one that delivers nothing, or an
	// enforcer passing a constant would satisfy the comparison.
	if delivering == 0 || silent == 0 {
		t.Fatalf("the seam list has %d delivering and %d silent seams; the comparison needs both", delivering, silent)
	}
}
