// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"slices"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// TestAFirstPublishOfTheSeededTemplateDoesNotRefuseTheMCPResponsePass is the
// published twin of TestAScopeThatRunsNoneOfTheTemplatesDetectorsIsNotAskedForThem
// (PRD v11 §1.5; W3-I item 9, written first by ruling).
//
// Drafts are seeded with the organization template's 22 policies, and a
// published document is activated on every scope. The MCP response pass runs
// none of the template's detectors, so a copy carried whole there would read
// each signal as UNKNOWN and refuse every response of an organization that
// published its seeded draft. Activation restricts the copies to the scope as
// OrganizationTemplateForScope restricts the template, and only those: a copy a
// scope binds stays and decides.
func TestAFirstPublishOfTheSeededTemplateDoesNotRefuseTheMCPResponsePass(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	art, findings, err := templateArtifact(t, w, authoring.EditionEnterprise, nil)
	if err != nil {
		t.Fatalf("publishing the template drafts are seeded with: %v\n%v", err, findings)
	}
	seeded := func(in *activation.Inputs) { in.Organization = art }
	offTheRoot := func(t *testing.T, act *activation.Activation) {
		t.Helper()
		for _, id := range act.UnboundTemplateControls {
			if _, ok := act.Policy(id); ok {
				t.Fatalf("%s is reported unbound on %s and is on the organization root", id, act.Scope)
			}
		}
	}

	t.Run("the MCP response pass binds none of the copies, leaves every one out, and allows", func(t *testing.T) {
		mcpResponse := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
		act := w.mustActivateScope(t, mcpResponse, seeded)
		if len(act.UnboundTemplateControls) != len(template.Policies) {
			t.Fatalf("%s reports %d of the published document's %d template controls unbound: %v",
				mcpResponse, len(act.UnboundTemplateControls), len(template.Policies), act.UnboundTemplateControls)
		}
		offTheRoot(t, act)
		req := request(t, act, authoringcatalog.ActionToolCall)
		for _, a := range template.Attributes {
			delete(req.Attributes, a.Path)
		}
		d, err := act.Engine.Decide(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if d.State != contract.StateAllow {
			t.Fatalf("%s under a published copy of the template decides %s %s %+v; want ALLOW - the scope runs none of the "+
				"template's detectors, so publishing a seeded draft must not make it read them",
				mcpResponse, d.State, d.Reason, d.Determining.Unknown)
		}
	})

	t.Run("decide binds a template constraint, so its published copy stays and denies", func(t *testing.T) {
		restricted, err := activation.OrganizationTemplateForScope(decideScope)
		if err != nil {
			t.Fatal(err)
		}
		var control pdp.Policy
		for _, p := range restricted.Policies {
			if p.Authority == contract.AuthorityConstraint {
				control = p
				break
			}
		}
		if control.ID == "" {
			t.Fatal("PREMISE: decide binds no constraint of the organization template")
		}
		act := w.mustActivateScope(t, decideScope, seeded)
		if slices.Contains(act.UnboundTemplateControls, control.ID) {
			t.Fatalf("%s binds on %s and is reported unbound: %v", control.ID, decideScope, act.UnboundTemplateControls)
		}
		if _, ok := act.Policy(control.ID); !ok {
			t.Fatalf("%s binds on %s and the published copy is not on the organization root", control.ID, decideScope)
		}
		offTheRoot(t, act)
		signal := signalOf(t, control)
		if d := decideFired(t, act, signal); d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, control.ID) {
			t.Fatalf("with %s fired under the published copy the request decides %s %s %+v; want DENY by %s",
				signal, d.State, d.Reason, d.Determining, control.ID)
		}
	})
}
