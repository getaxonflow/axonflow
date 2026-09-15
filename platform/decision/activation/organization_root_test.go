// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// THE ORGANIZATION ROOT (PRD v11 §1.4). Whatever is active, the root composes
// the deployment's baseline permission pack - the explicit permission set a
// deployment runs under, which an organization narrows with constraints - and,
// while no document is active, the organization template restricted to the
// scope. A published document replaces the template by digest: the
// organization owns its root. The tests below hold each edge: the root cannot
// be activated unsigned, the pack stands beside a published document and
// constraints still deny over it, and the template decides only until the
// organization publishes.

// publishOneGrant publishes and promotes a document carrying ONE permission of
// the baseline pack, and returns that permission.
func (w *world) publishOneGrant(t *testing.T) pdp.Policy {
	t.Helper()
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Policies) < 2 {
		t.Fatalf("PREMISE: the pack carries %d permissions; a one-grant document must grant fewer than the pack", len(pack.Policies))
	}
	one := *pack
	one.Policies = pack.Policies[:1]
	art := w.publish(t, &one, 1, "")
	w.promote(t, art)
	return one.Policies[0]
}

func TestAnActivationWithNoCompositionAuthorityIsRefused(t *testing.T) {
	w := newWorld(t)
	refused := func(t *testing.T) {
		t.Helper()
		in := w.inputs()
		if art, ok, err := w.api.Store().Active(context.Background(), pdp.RootOrganization); err != nil {
			t.Fatal(err)
		} else if ok {
			in.Organization = art
		}
		in.Composition = nil
		_, err := activation.Activate(context.Background(), in)
		var refusal *pdp.ActivationRefusal
		if !errors.As(err, &refusal) || refusal.Code != activation.RefusalBaselinePackUnsigned {
			t.Fatalf("an activation with no composition authority returned %v; want %s, never the shipped corpus activated alone",
				err, activation.RefusalBaselinePackUnsigned)
		}
	}
	t.Run("no document is active", func(t *testing.T) {
		if w.activate(t) == nil {
			t.Fatal("CONTROL: the activation with a composition authority failed")
		}
		refused(t)
	})
	t.Run("a published document is active: the pack still composes beside it", func(t *testing.T) {
		w.publishOneGrant(t)
		if w.activate(t) == nil {
			t.Fatal("CONTROL: the activation with a composition authority failed")
		}
		refused(t)
	})
}

// An organization with no document that has recorded a detection override -
// the state community-SaaS provisioning leaves every new organization in
// (#4017) - is decided by the baseline pack AND the override's replacement,
// signed as one organization root.
func TestAnOverrideOnAnOrganizationWithNoDocumentComposesOntoTheImplicitBaseline(t *testing.T) {
	w := newWorld(t)
	restricted, _, err := activation.RestrictToScope(decideScope)
	if err != nil {
		t.Fatal(err)
	}
	sqli := controlsOfCategory(t, restricted, "security-sqli")
	if len(sqli) == 0 {
		t.Fatal("PREMISE: decide binds no security-sqli control, so an override on it displaces nothing here")
	}
	bare := w.mustActivateScope(t, decideScope, nil)
	act := w.mustActivateScope(t, decideScope, withOverrides(w.composition,
		legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}))

	if !bare.ImplicitBaseline || !act.ImplicitBaseline {
		t.Fatalf("no document is active and the activations report implicit=%v and %v", bare.ImplicitBaseline, act.ImplicitBaseline)
	}
	if act.PolicyBundle == bare.PolicyBundle {
		t.Fatal("the override moved no digest, so a decision could not say which of the two organization roots decided it")
	}
	if _, ok := act.Policy(activation.OverridePolicyIDPrefix + sqli[0].ID); !ok {
		t.Fatalf("%s's replacement is not on the implicit organization root", sqli[0].ID)
	}
	if d := decideFired(t, act, ""); d.State != contract.StateAllow {
		t.Fatalf("a request no detector fired on decides %s %s; the baseline pack must still grant it beside the override", d.State, d.Reason)
	}
	d := decideFired(t, act, signalOf(t, sqli[0]))
	if d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, activation.OverridePolicyIDPrefix+sqli[0].ID) {
		t.Fatalf("under sqli=block the request decides %s %s %+v; want DENY by the replacement", d.State, d.Reason, d.Determining)
	}
}

// THE PACK STANDS BESIDE A PUBLISHED DOCUMENT. An organization's first
// document is rarely a complete permission set, and one that denied every
// action it did not name would be the outage §1.4 exists to prevent. A
// document that already carries the whole pack keeps its own copy: that is
// TestTheFirstAnchoredProductionEngine's publish, which composition would
// otherwise refuse for a second policy under one id.
func TestTheBaselinePackComposesBesideAPublishedDocument(t *testing.T) {
	w := newWorld(t)
	grant := w.publishOneGrant(t)
	act := w.activate(t)
	if act.ImplicitBaseline {
		t.Fatal("a document is active and the activation reports the implicit baseline")
	}

	t.Run("a one-grant document still permits every registered action", func(t *testing.T) {
		for _, local := range authoringcatalog.DeploymentActions() {
			if d := decide(t, act, local); d.State != contract.StateAllow {
				t.Fatalf("%s: state %s reason %s under a document granting only %s; the pack must permit it beside the document",
					local, d.State, d.Reason, grant.ID)
			}
		}
	})

	t.Run("a constraint still denies over the pack", func(t *testing.T) {
		restricted, _, err := activation.RestrictToScope(decideScope)
		if err != nil {
			t.Fatal(err)
		}
		sqli := controlsOfCategory(t, restricted, "security-sqli")
		if len(sqli) == 0 {
			t.Fatal("PREMISE: decide binds no security-sqli control")
		}
		over := w.mustActivateScope(t, decideScope, withOverrides(w.composition,
			legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}))
		d := decideFired(t, over, signalOf(t, sqli[0]))
		if d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, activation.OverridePolicyIDPrefix+sqli[0].ID) {
			t.Fatalf("under a published document and sqli=block the request decides %s %s %+v; want DENY by the replacement over the pack",
				d.State, d.Reason, d.Determining)
		}
	})
}

// THE TEMPLATE DECIDES UNTIL THE ORGANIZATION PUBLISHES. While no document is
// active, the template's controls a scope evaluates are on the organization
// root; a published document replaces them, and one it omits stops deciding.
// Until the authoring surface seeds every draft from the template, publish and
// activation report the omission - the safety net lives in the transports.
func TestTheOrganizationTemplateComposesOnlyIntoTheImplicitBundle(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	// 22 CONTROLS: a template redaction ships as two policies bound by
	// discharge (#4131), so the policy count is higher than the control count.
	controls := map[string]bool{}
	for _, p := range template.Policies {
		control, _, _ := legacycompile.CorpusControlOf(p.ID)
		controls[control] = true
	}
	if len(controls) != 22 {
		t.Fatalf("the organization template carries %d controls (%d policies); the count this suite was measured against is 22 controls", len(controls), len(template.Policies))
	}
	for _, s := range legacycompile.AllScopes() {
		doc, err := activation.OrganizationTemplateForScope(s)
		if err != nil {
			t.Logf("%s: the template cannot be restricted: %v", s, err)
			continue
		}
		t.Logf("%s binds %d of the template's %d policies", s, len(doc.Policies), len(template.Policies))
	}

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
	signal := signalOf(t, control)

	w := newWorld(t)
	t.Run("no document is active: the template's constraint is on the root and denies", func(t *testing.T) {
		implicit := w.activate(t)
		if _, ok := implicit.Policy(control.ID); !ok {
			t.Fatalf("%s is not on the implicit organization root", control.ID)
		}
		d := decideFired(t, implicit, signal)
		if d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, control.ID) {
			t.Fatalf("with %s fired the request decides %s %s %+v; want DENY by the template's %s", signal, d.State, d.Reason, d.Determining, control.ID)
		}
	})
	t.Run("a published document replaces the template: the control is gone and the same request is allowed", func(t *testing.T) {
		w.publishOneGrant(t)
		published := w.activate(t)
		if _, ok := published.Policy(control.ID); ok {
			t.Fatalf("%s is still on the root after the organization published a document that does not carry it", control.ID)
		}
		if d := decideFired(t, published, signal); d.State != contract.StateAllow {
			t.Fatalf("with %s fired under a published document the request decides %s %s; the template control must have stopped deciding",
				signal, d.State, d.Reason)
		}
	})
}

// THE TEMPLATE IS RESTRICTED TO WHAT THE SCOPE EVALUATES. A scope that runs
// none of the template's detectors - the MCP response pass binds none of its
// request-phase controls - must not be asked for their signals: an unrestricted
// template would read each as UNKNOWN there and refuse every response of an
// organization that has published nothing.
func TestAScopeThatRunsNoneOfTheTemplatesDetectorsIsNotAskedForThem(t *testing.T) {
	mcpResponse := legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
	restricted, err := activation.OrganizationTemplateForScope(mcpResponse)
	if err != nil {
		t.Fatal(err)
	}
	if len(restricted.Policies) != 0 {
		t.Fatalf("PREMISE: %s binds %d template controls; this test needs a scope that runs none of them", mcpResponse, len(restricted.Policies))
	}
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	act := w.mustActivateScope(t, mcpResponse, nil)
	req := request(t, act, authoringcatalog.ActionToolCall)
	for _, a := range template.Attributes {
		delete(req.Attributes, a.Path)
	}
	d, err := act.Engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if d.State != contract.StateAllow {
		t.Fatalf("%s with none of the template's signals decides %s %s %+v; want ALLOW - it runs none of their detectors, so it may not read them",
			mcpResponse, d.State, d.Reason, d.Determining.Unknown)
	}
}

// THE OMISSION REPORT FIRES ON A DOCUMENT THAT DROPS TEMPLATE CONTROLS AND IS
// SILENT ON ONE THAT CARRIES ALL OF THEM. It is the safety net publish and
// activation return until the authoring surface seeds every draft from the
// template.
func TestAPublishedDocumentReportsTheTemplateControlsItOmits(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a one-grant document omits every template control, and says so", func(t *testing.T) {
		oneGrant := &pdp.Document{Root: pdp.RootOrganization, Version: 1, Policies: pack.Policies[:1]}
		report, err := activation.ReportTemplateOmissions(oneGrant)
		if err != nil {
			t.Fatal(err)
		}
		if report == nil || len(report.Omitted) != len(template.Policies) || report.Of != len(template.Policies) {
			t.Fatalf("report %+v; want all %d template policies omitted", report, len(template.Policies))
		}
		if want := fmt.Sprintf("this document omits %d of the %d template policies: ", len(template.Policies), len(template.Policies)); len(report.Message) < len(want) || report.Message[:len(want)] != want {
			t.Fatalf("message %q; want it to open %q", report.Message, want)
		}
	})

	t.Run("a document carrying every template control is silent", func(t *testing.T) {
		if report, err := activation.ReportTemplateOmissions(template); err != nil || report != nil {
			t.Fatalf("the template itself reported %+v (err %v); a document carrying all of it must report nothing", report, err)
		}
	})

	t.Run("dropping one template control names exactly that one", func(t *testing.T) {
		dropped := template.Policies[0].ID
		doc := &pdp.Document{Root: pdp.RootOrganization, Version: 1, Policies: slices.Clone(template.Policies[1:])}
		report, err := activation.ReportTemplateOmissions(doc)
		if err != nil {
			t.Fatal(err)
		}
		if report == nil || len(report.Omitted) != 1 || report.Omitted[0] != dropped {
			t.Fatalf("report %+v; want exactly [%s]", report, dropped)
		}
	})
}
