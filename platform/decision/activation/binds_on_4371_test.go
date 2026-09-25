// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/decision/registry"
)

// TestTheDigestScopesAreTheEnforcingScopes holds the proof's written-out
// scopes (binds_on_digest_4371_test.go, which must compile on the base and so
// cannot call EnforcingScopes) to the statement.
func TestTheDigestScopesAreTheEnforcingScopes(t *testing.T) {
	var got []string
	for _, s := range digestScopes {
		got = append(got, legacycompile.MustScopeFor(s.plane, s.phase).String())
	}
	// The derived scope has no base-computed row (a scope added after the base
	// cannot), so the proof activates it against the base scope it must equal
	// instead. It is part of the proof's coverage all the same, and the two
	// lists together are what must equal the enforcing scopes: a scope in
	// neither is a scope nothing proves anything about.
	got = append(got, legacycompile.MustScopeFor(derivedScope.plane, derivedScope.phase).String())
	slices.Sort(got)
	want := legacycompile.EnforcingScopes()
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("the digest proof activates %v (%d base-computed, 1 derived) and the enforcing scopes are %v", got, len(digestScopes), want)
	}
}

// scopedApproval is the EQwise document with its approval requirement scoped
// by binds_on (nil = unscoped).
func scopedApproval(t *testing.T, snap *authoringcatalog.Snapshot, binds []string) pdp.Document {
	t.Helper()
	doc := withApprovalOnToolCall(t, snap)
	doc.Policies[len(doc.Policies)-1].BindsOn = pdp.BindingScopes(binds)
	return doc
}

// decisionShape is what Gate 15 compares: the outcome, the reason, what
// determined it and what it obliges - never the ids or the snapshot, which
// name the document and so differ between two documents by construction.
func decisionShape(t *testing.T, d *contract.Decision) string {
	t.Helper()
	raw, err := json.Marshal(struct {
		Authorization contract.Authorization
		State         contract.OperationalState
		Reason        contract.ReasonCode
		Obligations   []contract.Obligation
		Approval      *contract.ApprovalRequirement
		Determining   contract.Determining
	}{d.Authorization, d.State, d.Reason, d.Obligations, d.Approval, d.Determining})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestAControlBindsOnlyWhereItsDocumentSays is the plane matrix of #4371 for
// the EQwise document: an approval requirement on tool.call scoped to the
// step gate and the multi-agent plane is carried, and challenges, there; on
// every other scope it is left out, is named as left out, and the tool call
// is allowed.
func TestAControlBindsOnlyWhereItsDocumentSays(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	doc := scopedApproval(t, w.snap, []string{"map", "wcp"})
	art := w.publish(t, "eqwise-scoped", doc, approvalFixtures(&doc))
	for _, s := range w.scopes() {
		act := w.activateOn(t, art, s.plane, s.phase)
		scope := act.Scope.String()
		_, carried := act.Policy("approve.tool_calls")
		bound := scope == "wcp" || scope == "map"
		if carried != bound {
			t.Errorf("%s: the engine carries the approval requirement = %t, want %t", scope, carried, bound)
		}
		if listed := slices.Contains(act.ScopeUnboundControls, "approve.tool_calls"); listed == bound {
			t.Errorf("%s: ScopeUnboundControls = %v", scope, act.ScopeUnboundControls)
		}
		d := decide(t, act, authoringcatalog.ActionToolCall)
		switch {
		case bound && d.State != contract.StateChallenge:
			t.Errorf("%s: a tool call decides %s (%s), want a challenge", scope, d.State, d.Reason)
		case !bound && d.State == contract.StateChallenge:
			t.Errorf("%s: a tool call is challenged where the requirement is not bound", scope)
		case !bound && slices.Contains(d.Determining.MatchedRequirement, "approve.tool_calls"):
			t.Errorf("%s: the decision names the unbound requirement: %+v", scope, d.Determining)
		}
	}
}

// GATE 15, PART 3: OFF-SCOPE IS DELETION (#4371).
//
// ADR-065 acceptance gate 15 (conformance/cross_plane_test.go) admitted one
// reason two planes decide one request differently: the capability refusal.
// binds_on adds a second, declared by the author, and this is its executable
// statement, so it is a property and not an exception:
//
//   - XP-B1: on a scope a control is not bound to, the decision is IDENTICAL to
//     the same document with that control deleted. An unbound scope gets
//     exactly what withdrawing the control there would give, and nothing more,
//     including for a copy of a pack's or the baseline's own policy
//     (TestGate15OffScopeIsDeletionForAPackIDCopy).
//   - XP-B2: on a scope it is bound to, the decision is identical to the same
//     document with binds_on absent.
//   - XP-B3: binds_on naming every scope that presents the control's actions
//     decides identically to absent, for every request a scope PRESENTS
//     (legacycompile.ScopeActions). On a scope that never presents the action
//     the two differ, and only for a request no seam there can send: the full
//     list leaves the control out where it can never be reached. That absent
//     is what it was before #4371 is the digest proof's
//     (binds_on_digest_4371_test.go).
//
// The planted defect this reds is an activation that ignores binds_on.
func TestGate15OffScopeIsDeletion(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	scopedDoc := scopedApproval(t, w.snap, []string{"map", "wcp"})
	unscopedDoc := scopedApproval(t, w.snap, nil)
	everyDoc := scopedApproval(t, w.snap, legacycompile.ScopesPresenting(authoringcatalog.ActionToolCall))
	deletedDoc := baselineDocument(t, w.snap)
	scoped := w.publish(t, "xp-scoped", scopedDoc, approvalFixtures(&scopedDoc))
	unscoped := w.publish(t, "xp-unscoped", unscopedDoc, approvalFixtures(&unscopedDoc))
	every := w.publish(t, "xp-every", everyDoc, approvalFixtures(&everyDoc))
	deleted := w.publish(t, "xp-deleted", deletedDoc, fixturesFor(&deletedDoc))
	offScope, presented := 0, 0
	for _, s := range w.scopes() {
		scope := legacycompile.MustScopeFor(s.plane, s.phase)
		for _, local := range authoringcatalog.DeploymentActions() {
			got := decisionShape(t, decide(t, w.activateOn(t, scoped, s.plane, s.phase), local))
			if legacycompile.BindsOn(scopedDoc.Policies[len(scopedDoc.Policies)-1].BindsOn, scope) {
				if want := decisionShape(t, decide(t, w.activateOn(t, unscoped, s.plane, s.phase), local)); got != want {
					t.Errorf("XP-B2 %s %s: bound, decides %s; unscoped decides %s", scope, local, got, want)
				}
			} else {
				offScope++
				if want := decisionShape(t, decide(t, w.activateOn(t, deleted, s.plane, s.phase), local)); got != want {
					t.Errorf("XP-B1 %s %s: off scope, decides %s; with the control deleted, %s", scope, local, got, want)
				}
			}
			if !slices.Contains(legacycompile.ScopeActions(scope), local) {
				continue
			}
			presented++
			a := decisionShape(t, decide(t, w.activateOn(t, every, s.plane, s.phase), local))
			b := decisionShape(t, decide(t, w.activateOn(t, unscoped, s.plane, s.phase), local))
			if a != b {
				t.Errorf("XP-B3 %s %s: every presenting scope decides %s; absent decides %s", scope, local, a, b)
			}
		}
	}
	if offScope == 0 || presented == 0 {
		t.Fatalf("%d off-scope and %d presented cells ran; a part of the gate asserted nothing", offScope, presented)
	}
	t.Logf("XP-B1 %d off-scope cells, XP-B3 %d presented cells", offScope, presented)
}

// TestAScopedCommunityDocumentDecidesAlikeOnBothBuilds: binds_on is not an
// Enterprise construct. A Community document's constraint scoped to the step
// gate is admitted by both editions and decides identically on every scope of
// each: it withholds a tool call on wcp and leaves it alone elsewhere.
func TestAScopedCommunityDocumentDecidesAlikeOnBothBuilds(t *testing.T) {
	shapes := map[registry.Edition]map[string]string{}
	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		w := newDigestWorld(t, edition)
		doc := baselineDocument(t, w.snap)
		doc.Policies = append(doc.Policies, pdp.Policy{
			ID: "no.tool_steps", Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
			Scope:   pdp.Scope{Organization: true},
			Actions: pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}},
			Where:   pdp.True(),
			BindsOn: pdp.BindingScopes([]string{"wcp"}),
		})
		fixtures := fixturesFor(&pdp.Document{Policies: doc.Policies[:len(doc.Policies)-1]})
		for i := range fixtures {
			fixtures[i].Expect["no.tool_steps"] = pdp.VerdictNoMatch
		}
		fixtures[len(fixtures)-1].Expect["no.tool_steps"] = pdp.VerdictMatch
		art := w.publish(t, "community-scoped", doc, fixtures)
		shapes[edition] = map[string]string{}
		for _, s := range w.scopes() {
			act := w.activateOn(t, art, s.plane, s.phase)
			d := decide(t, act, authoringcatalog.ActionToolCall)
			if withheld := d.State != contract.StateAllow; withheld != (act.Scope.String() == "wcp") {
				t.Errorf("%s on %s: a tool call decides %s (%s)", edition, act.Scope, d.State, d.Reason)
			}
			shapes[edition][act.Scope.String()] = decisionShape(t, d)
		}
	}
	for scope, c := range shapes[registry.EditionCommunity] {
		if e := shapes[registry.EditionEnterprise][scope]; c != e {
			t.Errorf("%s: community decides %s, enterprise %s", scope, c, e)
		}
	}
}

// TestActivationRefusesAScopeFromAnotherBuild: a document can name a scope
// this build does not enforce only if another build's vocabulary admitted it
// (see RefusalBindsOnInvalid). It refuses, by name, on every scope - including
// wcp, which it also names - rather than reading the list as "everywhere" or
// "nowhere". The empty list's refusal is binds_on_internal_test.go's.
func TestActivationRefusesAScopeFromAnotherBuild(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	{
		{
			doc := scopedApproval(t, w.snap, []string{"wcp", "workflow_step_gate"})
			art := forgePublication(t, w, doc)
			for _, s := range w.scopes() {
				_, err := activation.Activate(context.Background(), activation.Inputs{
					Snapshot: w.snap, Trust: w.trust, System: w.system, Composition: w.comp,
					Plane: string(s.plane), Phase: s.phase,
					Delivers:     legacycompile.ScopeDeliveries(legacycompile.MustScopeFor(s.plane, s.phase)),
					Organization: art,
				})
				var refusal *pdp.ActivationRefusal
				if !errors.As(err, &refusal) || refusal.Code != activation.RefusalBindsOnInvalid {
					t.Fatalf("%s/%s: activation answered %v, want %s", s.plane, s.phase, err, activation.RefusalBindsOnInvalid)
				}
			}
		}
	}
}

// forgePublication publishes doc through a catalog whose actions also state a
// scope this build does not enforce (workflow_step_gate), so a binds_on this
// deployment's validator refuses reaches a signed artifact - the shape a
// document published by another build's vocabulary has.
func forgePublication(t *testing.T, w *digestWorld, doc pdp.Document) *authoring.Artifact {
	t.Helper()
	cat := *w.snap.Catalog
	cat.Actions = map[string]pdp.ActionEntry{}
	for id, e := range w.snap.Catalog.Actions {
		e.Planes = append(slices.Clone(e.Planes), "workflow_step_gate")
		cat.Actions[id] = e
	}
	profile, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(&cat, authoring.StaticTrust(w.trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	meta := authoring.Metadata{DocumentID: "another-build", Title: "another build", Author: contract.MustParseID(contract.KindPrincipal, testAuthor)}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, &cat)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	art, findings, err := api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: testOrgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  approvalFixtures(&doc), Now: digestNow,
	})
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}
	return art
}

// activateWithPacks is activateOn beside installed policy packs.
func (w *digestWorld) activateWithPacks(t *testing.T, org *authoring.Artifact, plane legacycompile.Plane, phase legacycompile.Phase, packs []activation.InstalledPack) *activation.Activation {
	t.Helper()
	scope := legacycompile.MustScopeFor(plane, phase)
	act, err := activation.Activate(context.Background(), activation.Inputs{
		Snapshot: w.snap, Trust: w.trust, System: w.system, Composition: w.comp,
		Plane: string(plane), Phase: phase, Delivers: legacycompile.ScopeDeliveries(scope),
		Organization: org, Packs: packs,
	})
	if err != nil {
		t.Fatalf("activate on %s: %v", scope, err)
	}
	return act
}

// decideWithSignals is decide with detector signals stated known.
func decideWithSignals(t *testing.T, act *activation.Activation, local string, signals map[string]bool) *contract.Decision {
	t.Helper()
	req := request(t, act, local)
	for d, v := range signals {
		req.Attributes[legacycompile.DetectorSignalPath(d)] = contract.Known(v, contract.ProvDetector, 1, req.EvaluatedAt)
	}
	d, err := act.Engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("decide %s: %v", local, err)
	}
	return d
}

// withoutPolicy is doc less the policy id.
func withoutPolicy(doc pdp.Document, id string) pdp.Document {
	out := doc
	out.Policies = slices.DeleteFunc(slices.Clone(doc.Policies), func(p pdp.Policy) bool { return p.ID == id })
	return out
}

// GATE 15 PART 3, XP-B1 FOR A PACK'S OWN ID (#4371, the hostile round's
// finding). A document may carry a pack's or the baseline's policy by its id,
// and that copy then stands for the pack's own (notCarried). Scoped elsewhere,
// the copy leaves the plane - and the plane must then carry what deleting the
// copy would give it: the pack's or the baseline's own policy of that id, not
// nothing. Before the fix the id stayed taken and the plane carried neither,
// which for a pack CONSTRAINT is more permissive than deletion.
func TestGate15OffScopeIsDeletionForAPackIDCopy(t *testing.T) {
	t.Run("a baseline permission copied by id", func(t *testing.T) {
		w := newDigestWorld(t, registry.EditionEnterprise)
		base := baselineDocument(t, w.snap)
		const permit = "baseline.permit." + authoringcatalog.ActionToolCall
		scopedDoc := base
		scopedDoc.Policies = slices.Clone(base.Policies)
		for i := range scopedDoc.Policies {
			if scopedDoc.Policies[i].ID == permit {
				scopedDoc.Policies[i].BindsOn = pdp.BindingScopes([]string{"wcp"})
			}
		}
		deletedDoc := withoutPolicy(base, permit)
		scoped := w.publish(t, "xp-baseline-scoped", scopedDoc, fixturesFor(&scopedDoc))
		deleted := w.publish(t, "xp-baseline-deleted", deletedDoc, fixturesFor(&deletedDoc))
		offScope := 0
		for _, s := range w.scopes() {
			if legacycompile.MustScopeFor(s.plane, s.phase).String() == "wcp" {
				continue
			}
			offScope++
			got := decide(t, w.activateOn(t, scoped, s.plane, s.phase), authoringcatalog.ActionToolCall)
			want := decide(t, w.activateOn(t, deleted, s.plane, s.phase), authoringcatalog.ActionToolCall)
			if decisionShape(t, got) != decisionShape(t, want) {
				t.Errorf("%s/%s: off scope decides %s; with the copy deleted, %s", s.plane, s.phase, decisionShape(t, got), decisionShape(t, want))
			}
			if got.State != contract.StateAllow || !slices.Contains(got.Determining.MatchedPermissions, permit) {
				t.Errorf("%s/%s: the baseline's own %s did not compose in the copy's place: %s", s.plane, s.phase, permit, decisionShape(t, got))
			}
		}
		t.Logf("%d off-scope planes decide as deletion, the baseline permission refilled", offScope)
	})

	t.Run("an installed pack's block copied by id", func(t *testing.T) {
		w := newDigestWorld(t, registry.EditionEnterprise)
		installed, err := activation.InstallPacks(w.snap, []*policypack.Pack{loadPack(t, testPackSource("testpack"))})
		if err != nil {
			t.Fatal(err)
		}
		var block pdp.Policy
		var blockAttrs []pdp.AttributeSchema
		for _, p := range installed[0].Document.Policies {
			if p.ID == packBlockID {
				block = p
			}
		}
		signal := legacycompile.DetectorSignalPath("tp_block")
		for _, a := range installed[0].Document.Attributes {
			if a.Path == signal {
				blockAttrs = append(blockAttrs, a)
			}
		}
		if block.ID == "" || len(blockAttrs) != 1 {
			t.Fatalf("PREMISE: the pack's block control %s and its signal schema were not found", packBlockID)
		}
		base := baselineDocument(t, w.snap)
		scopedDoc := base
		scopedDoc.Attributes = append(slices.Clone(base.Attributes), blockAttrs...)
		copyOf := block
		copyOf.BindsOn = pdp.BindingScopes([]string{"decide"})
		scopedDoc.Policies = append(slices.Clone(base.Policies), copyOf)
		fixtures := fixturesFor(&base)
		for i := range fixtures {
			fixtures[i].Attributes[signal] = contract.Known(false, contract.ProvDetector, 1, digestNow)
			fixtures[i].Expect[packBlockID] = pdp.VerdictNoMatch
		}
		scoped := w.publish(t, "xp-pack-scoped", scopedDoc, fixtures)
		deleted := w.publish(t, "xp-pack-deleted", base, fixturesFor(&base))
		fires := map[string]bool{"tp_block": true, "tp_step": false, "tp_response": false}
		refilled := 0
		for _, s := range w.scopes() {
			scope := legacycompile.MustScopeFor(s.plane, s.phase).String()
			if scope == "decide" {
				continue
			}
			got := decideWithSignals(t, w.activateWithPacks(t, scoped, s.plane, s.phase, installed), authoringcatalog.ActionLLMCompletion, fires)
			want := decideWithSignals(t, w.activateWithPacks(t, deleted, s.plane, s.phase, installed), authoringcatalog.ActionLLMCompletion, fires)
			if decisionShape(t, got) != decisionShape(t, want) {
				t.Errorf("%s: off scope decides %s; with the copy deleted, %s", scope, decisionShape(t, got), decisionShape(t, want))
			}
			if slices.Contains(want.Determining.MatchedConstraints, packBlockID) {
				refilled++
			}
		}
		if refilled == 0 {
			t.Fatal("PREMISE: the pack's block bound on no off-scope plane, so the cell asserted nothing about a refill")
		}
		t.Logf("%d off-scope planes carry the pack's own block where the copy is left out, as deletion does", refilled)
	})
}

// TestATemplateControlScopedByBindsOnIsReportedModified (#4371): binds_on can
// narrow where a shipped template control applies, so a copy that gains one is
// not carried as shipped (carriedAsShipped digests the whole policy) and the
// report names it Modified: the activation must acknowledge it, as it must an
// omission. The control: the template carried unchanged reports nothing.
func TestATemplateControlScopedByBindsOnIsReportedModified(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	doc := *template
	doc.Policies = slices.Clone(template.Policies)
	if report, err := activation.ReportTemplateOmissions(&doc); err != nil || report != nil {
		t.Fatalf("CONTROL: the template carried unchanged reported %+v (err %v)", report, err)
	}
	const scoped = "corpus:static_policies:eu__ai__act__pricing__fairness"
	i := slices.IndexFunc(doc.Policies, func(p pdp.Policy) bool { return p.ID == scoped })
	if i < 0 {
		t.Fatalf("PREMISE: the template carries no %s", scoped)
	}
	doc.Policies[i].BindsOn = pdp.BindingScopes([]string{"wcp"})
	report, err := activation.ReportTemplateOmissions(&doc)
	if err != nil {
		t.Fatal(err)
	}
	if report == nil || !slices.Contains(report.Modified, scoped) || len(report.Omitted) != 0 {
		t.Fatalf("a template control scoped by binds_on reported %+v; want it Modified and nothing omitted", report)
	}
}

// TestActivationAdmitsTheScopesTheVocabularyStates (#4371): activation reads
// the planes a document may name from the resolved vocabulary (the union of
// pdp.ActionEntry.Planes), the statement publication checks, not from the
// compile-time scope list. A vocabulary that does not state mcp:request
// refuses a document bound there, though the build enforces the scope.
func TestActivationAdmitsTheScopesTheVocabularyStates(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	doc := scopedApproval(t, w.snap, []string{"mcp:request"})
	art := w.publish(t, "admitted-scopes", doc, approvalFixtures(&doc))
	snap := *w.snap
	cat := *w.snap.Catalog
	cat.Actions = map[string]pdp.ActionEntry{}
	for id, e := range w.snap.Catalog.Actions {
		e.Planes = slices.DeleteFunc(slices.Clone(e.Planes), func(p string) bool { return p == "mcp:request" })
		cat.Actions[id] = e
	}
	snap.Catalog = &cat
	_, err := activation.Activate(context.Background(), activation.Inputs{
		Snapshot: &snap, Trust: w.trust, System: w.system, Composition: w.comp,
		Plane: string(legacycompile.PlaneWCP), Delivers: legacycompile.ScopeDeliveries(legacycompile.MustScopeFor(legacycompile.PlaneWCP, "")),
		Organization: art,
	})
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) || refusal.Code != activation.RefusalBindsOnInvalid || !strings.Contains(refusal.Detail, "mcp:request") {
		t.Fatalf("activation answered %v; want %s naming mcp:request", err, activation.RefusalBindsOnInvalid)
	}
}
