// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// An organization's recorded detection override, on the anchored engine
// (#4045). Every expectation is derived from the scope's restriction and the
// census, and every changed decision has the unchanged decision beside it.

const overrideOrg = "org_1"

var (
	decideScope   = legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	responseScope = legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
)

// overrideWorld is a world whose baseline permission pack is active.
func overrideWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	w.promote(t, w.publish(t, pack, 1, ""))
	return w
}

func compositionFrom(t *testing.T, priv ed25519.PrivateKey) *authoring.CompositionAuthority {
	t.Helper()
	if priv == nil {
		var err error
		if _, priv, err = ed25519.GenerateKey(nil); err != nil {
			t.Fatal(err)
		}
	}
	c, err := authoring.NewCompositionAuthority(priv)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// deliversOn is what each scope's seam delivers: the Decision API's vocabulary
// on decide, nothing on a pass that discharges inline.
func deliversOn(scope legacycompile.EnforcementScope) []contract.Capability {
	if scope == decideScope {
		return contract.DecisionWireCapabilities()
	}
	return nil
}

// activateScope activates scope for the world's active document, with mutate
// applied to the inputs.
func (w *world) activateScope(t *testing.T, scope legacycompile.EnforcementScope, mutate func(*activation.Inputs)) (*activation.Activation, error) {
	t.Helper()
	in := w.inputs()
	in.Plane, in.Phase, in.Delivers = string(scope.Plane), scope.Phase, deliversOn(scope)
	art, ok, err := w.api.Store().Active(context.Background(), pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		in.Organization = art
	}
	if mutate != nil {
		mutate(&in)
	}
	return activation.Activate(context.Background(), in)
}

func withOverrides(comp *authoring.CompositionAuthority, assigned legacycompile.CategoryActions) func(*activation.Inputs) {
	return func(in *activation.Inputs) {
		in.OrganizationID, in.Composition, in.Overrides = overrideOrg, comp, assigned
	}
}

func (w *world) mustActivateScope(t *testing.T, scope legacycompile.EnforcementScope, mutate func(*activation.Inputs)) *activation.Activation {
	t.Helper()
	act, err := w.activateScope(t, scope, mutate)
	if err != nil {
		t.Fatalf("activate %s: %v", scope, err)
	}
	return act
}

// controlsOfCategory returns the policies of doc whose censused detector
// carries category, sorted by id.
func controlsOfCategory(t *testing.T, doc *pdp.Document, category string) []pdp.Policy {
	t.Helper()
	var out []pdp.Policy
	for _, p := range doc.Policies {
		if row, ok := censusRowFor(t, p); ok && row.Category == category {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func idsOf(policies []pdp.Policy) []string {
	out := make([]string, 0, len(policies))
	for _, p := range policies {
		out = append(out, p.ID)
	}
	return out
}

func signalOf(t *testing.T, p pdp.Policy) string {
	t.Helper()
	row, ok := censusRowFor(t, p)
	if !ok {
		t.Fatalf("%s reads no censused detector", p.ID)
	}
	return registry.DetectorID(row.PolicyID).SignalPath()
}

// decideFired decides an llm.completion request on which only the detector
// behind path fired; an empty path fires none.
func decideFired(t *testing.T, act *activation.Activation, path string) *contract.Decision {
	t.Helper()
	req := request(t, act, authoringcatalog.ActionLLMCompletion)
	if path != "" {
		req.Attributes[path] = contract.Known(true, contract.ProvDetector, 1, time.Date(2026, 9, 10, 12, 5, 0, 0, time.UTC))
	}
	d, err := act.Engine.Decide(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func obligationsFrom(d *contract.Decision, source string) []contract.Obligation {
	var out []contract.Obligation
	for _, o := range d.Obligations {
		if o.SourcePolicy == source {
			out = append(out, o)
		}
	}
	return out
}

func hasObligation(d *contract.Decision, typ contract.ObligationType) bool {
	return slices.ContainsFunc(d.Obligations, func(o contract.Obligation) bool { return o.Type == typ })
}

func TestARecordedOverrideLeavesItsControlsOutAndCarriesThemOnTheOrganizationRoot(t *testing.T) {
	w := overrideWorld(t)
	base := w.mustActivateScope(t, decideScope, nil)
	restricted, _, err := activation.RestrictToScope(decideScope)
	if err != nil {
		t.Fatal(err)
	}
	sqli := controlsOfCategory(t, restricted, "security-sqli")
	if len(sqli) == 0 {
		t.Fatal("PREMISE: decide binds no security-sqli control, so an override on it displaces nothing here")
	}
	act := w.mustActivateScope(t, decideScope, withOverrides(compositionFrom(t, nil),
		legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}))

	if base.Overrides != nil {
		t.Fatalf("an activation with no recorded override reports %+v", base.Overrides)
	}
	if want := []activation.OverrideDisplacement{{Category: "security-sqli", Action: legacycompile.ActionBlock, Controls: idsOf(sqli)}}; !reflect.DeepEqual(act.Overrides, want) {
		t.Fatalf("the activation reports %+v; want %+v", act.Overrides, want)
	}
	if act.SystemPolicies != base.SystemPolicies-len(sqli) {
		t.Fatalf("the restriction keeps %d controls; the scope keeps %d and the override leaves out %d", act.SystemPolicies, base.SystemPolicies, len(sqli))
	}
	for _, shipped := range sqli {
		if _, kept := act.Policy(shipped.ID); kept {
			t.Fatalf("%s is still active beside its replacement", shipped.ID)
		}
		r, ok := act.Policy(activation.OverridePolicyIDPrefix + shipped.ID)
		if !ok {
			t.Fatalf("%s left the restriction and nothing replaced it", shipped.ID)
		}
		if r.Root != pdp.RootOrganization || r.Authority != contract.AuthorityConstraint || len(r.Obligations) != 0 ||
			!reflect.DeepEqual(r.Where, shipped.Where) || !reflect.DeepEqual(r.Scope, shipped.Scope) || !reflect.DeepEqual(r.Actions, shipped.Actions) {
			t.Fatalf("the replacement of %s is %+v; want an organization-root constraint over the same scope, actions and condition", shipped.ID, r)
		}
	}
	if !strings.HasPrefix(act.Restriction, base.Restriction+"; ") ||
		!strings.Contains(act.Restriction, fmt.Sprintf("organization %s's recorded detection overrides (#4045): security-sqli=block displaces %d shipped control(s)", overrideOrg, len(sqli))) {
		t.Fatalf("the restriction reads %q; want the scope's reason followed by the organization's overrides", act.Restriction)
	}
	if act.PolicyBundle == base.PolicyBundle || act.OrganizationBundleDigest == base.OrganizationBundleDigest || act.OrganizationArtifactDigest != base.OrganizationArtifactDigest {
		t.Fatalf("bundle %s org bundle %s artifact %s; want the policy set and organization bundle to move and the artifact to stay",
			act.PolicyBundle, act.OrganizationBundleDigest, act.OrganizationArtifactDigest)
	}

	fired := signalOf(t, sqli[0])
	if d := decideFired(t, base, fired); d.State != contract.StateAllow {
		t.Fatalf("CONTROL: with no override the shipped control decides %s %s", d.State, d.Reason)
	}
	d := decideFired(t, act, fired)
	if d.State != contract.StateDeny || d.Reason != contract.ReasonExplicitConstraint ||
		!slices.Contains(d.Determining.MatchedConstraints, activation.OverridePolicyIDPrefix+sqli[0].ID) {
		t.Fatalf("under sqli=block the request decides %s %s %+v; want DENY by the replacement", d.State, d.Reason, d.Determining)
	}
	if d := decideFired(t, act, ""); d.State != contract.StateAllow {
		t.Fatalf("a request no detector fired on decides %s %s under the override", d.State, d.Reason)
	}
}

func TestAnOverrideEqualToTheShippedActionStillDisplaces(t *testing.T) {
	w := overrideWorld(t)
	restricted, _, err := activation.RestrictToScope(decideScope)
	if err != nil {
		t.Fatal(err)
	}
	sqli := controlsOfCategory(t, restricted, "security-sqli")
	if len(sqli) == 0 || len(sqli[0].Obligations) != 1 || sqli[0].Obligations[0].Type != contract.ObNotification {
		t.Fatal("PREMISE: decide's security-sqli controls ship warn, the action this test assigns")
	}
	act := w.mustActivateScope(t, decideScope, withOverrides(compositionFrom(t, nil),
		legacycompile.CategoryActions{"security-sqli": legacycompile.ActionWarn}))

	if got := act.Overrides; len(got) != 1 || !reflect.DeepEqual(got[0].Controls, idsOf(sqli)) {
		t.Fatalf("an override equal to the shipped action reports %+v; it still displaces %v", got, idsOf(sqli))
	}
	for _, shipped := range sqli {
		r, ok := act.Policy(activation.OverridePolicyIDPrefix + shipped.ID)
		if !ok || r.Authority != shipped.Authority || r.Mandatory != shipped.Mandatory || len(r.Obligations) != 1 ||
			r.Obligations[0].Type != shipped.Obligations[0].Type || !reflect.DeepEqual(r.Obligations[0].Params, shipped.Obligations[0].Params) ||
			r.Obligations[0].SourcePolicy != r.ID {
			t.Fatalf("the replacement of %s is %+v; want the shipped control's shape, sourced from the replacement", shipped.ID, r)
		}
	}
	d := decideFired(t, act, signalOf(t, sqli[0]))
	if d.State != contract.StateAllow || len(obligationsFrom(d, activation.OverridePolicyIDPrefix+sqli[0].ID)) != 1 || len(obligationsFrom(d, sqli[0].ID)) != 0 {
		t.Fatalf("under sqli=warn the request decides %s with %+v; want the notification sourced from the replacement only", d.State, d.Obligations)
	}
}

func TestAWeakeningOverrideIsHonouredOnTheResponsePass(t *testing.T) {
	w := overrideWorld(t)
	base := w.mustActivateScope(t, responseScope, nil)
	restricted, _, err := activation.RestrictToScope(responseScope)
	if err != nil {
		t.Fatal(err)
	}
	var redacting *pdp.Policy
	for _, p := range controlsOfCategory(t, restricted, "pii-us") {
		if p.Mandatory && len(p.Obligations) == 1 && p.Obligations[0].Type == contract.ObFieldRedact {
			redacting = &p
			break
		}
	}
	if redacting == nil {
		t.Fatal("PREMISE: the response pass binds no mandatory pii-us redaction, so pii-us=log weakens nothing here")
	}
	act := w.mustActivateScope(t, responseScope, withOverrides(compositionFrom(t, nil),
		legacycompile.CategoryActions{"pii-us": legacycompile.ActionLog}))

	r, ok := act.Policy(activation.OverridePolicyIDPrefix + redacting.ID)
	if !ok || r.Mandatory || len(r.Obligations) != 1 || r.Obligations[0].Type != contract.ObImmutableAudit {
		t.Fatalf("the replacement of %s is %+v; want a non-mandatory immutable_audit requirement", redacting.ID, r)
	}
	fired := signalOf(t, *redacting)
	if d := decideFired(t, base, fired); d.State != contract.StateAllow || len(obligationsFrom(d, redacting.ID)) != 1 || !hasObligation(d, contract.ObFieldRedact) {
		t.Fatalf("CONTROL: with no override the response decides %s with %+v; want the shipped redaction", d.State, d.Obligations)
	}
	d := decideFired(t, act, fired)
	if d.State != contract.StateAllow || hasObligation(d, contract.ObFieldRedact) || len(obligationsFrom(d, r.ID)) != 1 {
		t.Fatalf("under pii-us=log the response decides %s with %+v; want a release with the replacement's audit and no redaction", d.State, d.Obligations)
	}
}

// TestARedactOverrideIsAsMandatoryAsTheCorpusMakesARedaction is the stated
// divergence: the obligation model is unchanged, so a caller that cannot
// discharge a redaction an override makes mandatory is refused, where the
// legacy engine's obligation fallback may release.
func TestARedactOverrideIsAsMandatoryAsTheCorpusMakesARedaction(t *testing.T) {
	w := overrideWorld(t)
	base := w.mustActivateScope(t, decideScope, nil)
	restricted, _, err := activation.RestrictToScope(decideScope)
	if err != nil {
		t.Fatal(err)
	}
	pii := controlsOfCategory(t, restricted, "pii-us")
	if len(pii) == 0 || pii[0].Mandatory {
		t.Fatal("PREMISE: decide binds a non-mandatory pii-us control")
	}
	act := w.mustActivateScope(t, decideScope, withOverrides(compositionFrom(t, nil),
		legacycompile.CategoryActions{"pii-us": legacycompile.ActionRedact}))

	r, ok := act.Policy(activation.OverridePolicyIDPrefix + pii[0].ID)
	if !ok || !r.Mandatory || len(r.Obligations) != 1 || r.Obligations[0].Type != contract.ObFieldRedact ||
		!r.Obligations[0].Mandatory || r.Obligations[0].Target != legacycompile.DefaultContentTarget {
		t.Fatalf("the replacement of %s is %+v; want a mandatory field_redact of %s", pii[0].ID, r, legacycompile.DefaultContentTarget)
	}
	fired := signalOf(t, pii[0])
	if d := decideFired(t, base, fired); d.State != contract.StateAllow {
		t.Fatalf("CONTROL: with no override the shipped control decides %s %s", d.State, d.Reason)
	}
	if d := decideFired(t, act, fired); d.State != contract.StateDeny || d.Reason != contract.ReasonUnsupportedObligation {
		t.Fatalf("an enforcement point that cannot redact decides %s %s under pii-us=redact; want DENY unsupported_obligation", d.State, d.Reason)
	}
}

func TestAnOverrideActivationRefusesByName(t *testing.T) {
	w := overrideWorld(t)
	sqli := legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}

	if _, err := w.activateScope(t, decideScope, withOverrides(compositionFrom(t, nil), sqli)); err != nil {
		t.Fatalf("CONTROL: the unmutated override activation failed, so the refusals below prove nothing: %v", err)
	}
	for _, c := range []struct {
		name   string
		mutate func(*activation.Inputs)
		want   string
	}{
		{"overrides attributed to no organization", func(in *activation.Inputs) {
			withOverrides(compositionFrom(t, nil), sqli)(in)
			in.OrganizationID = ""
		}, "no organization to attribute them to"},
		{"a displacing override with no composition authority", withOverrides(nil, sqli), "no composition authority"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := w.activateScope(t, decideScope, c.mutate); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v; want a refusal saying %q", err, c.want)
			}
		})
	}
	for _, act := range []legacycompile.LegacyAction{legacycompile.ActionAllow, legacycompile.ActionDeny, legacycompile.ActionLogOnly, legacycompile.ActionRequireApproval} {
		t.Run("an action no override records: "+string(act), func(t *testing.T) {
			_, err := w.activateScope(t, decideScope, withOverrides(compositionFrom(t, nil), legacycompile.CategoryActions{"security-sqli": act}))
			if err == nil || !strings.Contains(err.Error(), "a detection override records one of") {
				t.Fatalf("got %v; want %q refused", err, act)
			}
		})
	}
	for _, c := range []struct {
		name string
		priv ed25519.PrivateKey
	}{{"the system key as the composition key", w.sysPriv}, {"the organization's key as the composition key", w.orgPriv}} {
		t.Run(c.name, func(t *testing.T) {
			_, err := w.activateScope(t, decideScope, withOverrides(compositionFrom(t, c.priv), sqli))
			var refusal *pdp.ActivationRefusal
			if !errors.As(err, &refusal) || refusal.Code != activation.RefusalCompositionKeySignsAnotherRoot {
				t.Fatalf("got %v; want %s", err, activation.RefusalCompositionKeySignsAnotherRoot)
			}
		})
	}
}

// TestAnAuthoredPolicyMayNotTakeAReservedPrefix is refused on activation with
// nothing recorded and no system control, so the promote dry run refuses it too.
// Each prefix names a shipped control a replacement on the organization root
// carries: a recorded override's, and the document's own system control's.
func TestAnAuthoredPolicyMayNotTakeAReservedPrefix(t *testing.T) {
	for _, prefix := range []string{activation.OverridePolicyIDPrefix, activation.OrganizationControlPolicyIDPrefix} {
		t.Run(prefix, func(t *testing.T) { refusesTheReservedPrefix(t, prefix) })
	}
}

func refusesTheReservedPrefix(t *testing.T, prefix string) {
	w := newWorld(t)
	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	fixtures := fixturesFor(pack)
	renamed := "baseline.permit." + authoringcatalog.ActionLLMCompletion
	for i, p := range pack.Policies {
		if p.ID == renamed {
			pack.Policies[i].ID = prefix + renamed
		}
	}
	for _, f := range fixtures {
		if v, ok := f.Expect[renamed]; ok {
			delete(f.Expect, renamed)
			f.Expect[prefix+renamed] = v
		}
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: authoring.Metadata{
		DocumentID: authoringcatalog.BaselinePermissionPackID, Title: "baseline permissions",
		Author: contract.MustParseID(contract.KindPrincipal, testAuthor),
	}, Policy: *pack}, w.snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	art, findings, err := w.api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: w.orgKeyID, PrivateKey: w.orgPriv,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, testApprover)},
		Fixtures:  fixtures, Now: time.Date(2026, 9, 10, 12, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}

	in := w.inputs()
	in.Organization = art
	_, err = activation.Activate(context.Background(), in)
	var refusal *pdp.ActivationRefusal
	if !errors.As(err, &refusal) || refusal.Code != activation.RefusalOverridePolicyIDReserved {
		t.Fatalf("got %v; want %s", err, activation.RefusalOverridePolicyIDReserved)
	}
	actor := contract.MustParseID(contract.KindPrincipal, testApprover)
	if _, err := w.api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), actor, time.Now().UTC(), "install"); err == nil ||
		!strings.Contains(err.Error(), activation.RefusalOverridePolicyIDReserved) {
		t.Fatalf("the promote dry run gave %v; want %s", err, activation.RefusalOverridePolicyIDReserved)
	}
}
