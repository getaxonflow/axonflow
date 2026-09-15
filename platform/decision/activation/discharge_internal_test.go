// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

func internalSnapshot(t *testing.T) *authoringcatalog.Snapshot {
	t.Helper()
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, authoringcatalog.Deployment{
		Edition: registry.EditionCommunity,
		Realms: map[string]authoring.RealmEntry{
			"axonflow-trusted-header": {Interactive: true},
			"axonflow-api-credential": {},
		},
		Now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// shippedMandatoryRedactions are the shipped system policies carrying a
// mandatory field_redact, whichever scopes bind them: the shape a control takes
// the day one binds a mandatory redaction on a decision-returning scope.
func shippedMandatoryRedactions(t *testing.T) []pdp.Policy {
	t.Helper()
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	var out []pdp.Policy
	for _, p := range shipped.Policies {
		for _, o := range p.Obligations {
			if o.Mandatory && o.Type == contract.ObFieldRedact {
				out = append(out, p)
				break
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("CONTROL: the shipped corpus carries no mandatory field_redact at all; there is nothing to plant")
	}
	return out
}

// TestDecidesShippedRestrictionCarriesNoMandatoryObligation is #4046 closed on
// the shipped data: the corpus binds decide the action decide's legacy engine
// enforces - warn or log for the PII controls - so decide's restriction carries
// no obligation a caller must discharge. The surface is EMPTY, so the assertion
// does not depend on what any profile or wire discharges.
func TestDecidesShippedRestrictionCarriesNoMandatoryObligation(t *testing.T) {
	doc, _, err := RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneDecide, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Policies) == 0 {
		t.Fatal("decide's restriction binds nothing; the absence below would be vacuous")
	}
	for id, capabilities := range UndischargeableControls(doc, DischargeSurface{}) {
		t.Errorf("decide binds %s, which carries mandatory %v; the corpus must bind decide the action its legacy engine enforces", id, capabilities)
	}
}

// TestAMandatoryRedactionOnDecideIsDischargedOnlyThroughTheDecisionWire is the
// anti-vacuity half of the discharge surface (#4046). decide's shipped
// restriction carries no mandatory obligation (the test above), so the wire is
// proven on a PLANTED document: decide's own restriction plus every shipped
// policy carrying a mandatory field_redact. decide's registered profile
// discharges no field_redact, so:
//
//   - with nothing delivered, the guard refuses and names EVERY planted control -
//     derived from the corpus, never listed;
//   - with the Decision API's vocabulary delivered, the guard passes;
//   - a wire that carries field_redact at a schema version the corpus does not
//     attach discharges nothing, because a PEP claiming one version cannot be
//     assumed to implement another.
func TestAMandatoryRedactionOnDecideIsDischargedOnlyThroughTheDecisionWire(t *testing.T) {
	snap := internalSnapshot(t)
	scope := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	restricted, _, err := RestrictToScope(scope)
	if err != nil {
		t.Fatal(err)
	}
	pep, ok := snap.PEPFor(string(scope.Plane))
	if !ok {
		t.Fatal("the community vocabulary registers no decide profile")
	}
	planted := shippedMandatoryRedactions(t)
	doc := *restricted
	doc.Policies = append(append([]pdp.Policy(nil), restricted.Policies...), planted...)
	t.Logf("planted %d shipped control(s) carrying a mandatory field_redact into decide's restriction", len(planted))

	err = refuseUndischargeable(scope, &doc, NewDischargeSurface(pep, nil, snap.Edition))
	if err == nil {
		t.Fatal("with nothing delivered, a mandatory redaction on decide was not refused; the guard is not reading the surface")
	}
	for _, p := range planted {
		if !strings.Contains(err.Error(), p.ID) {
			t.Errorf("the refusal does not name %s: %v", p.ID, err)
		}
	}

	if err := refuseUndischargeable(scope, &doc, NewDischargeSurface(pep, contract.DecisionWireCapabilities(), snap.Edition)); err != nil {
		t.Fatalf("a mandatory redaction on decide was refused with the Decision API's vocabulary delivered: %v", err)
	}

	otherVersion := []contract.Capability{{Type: contract.ObFieldRedact, Version: 2}}
	if err := refuseUndischargeable(scope, &doc, NewDischargeSurface(pep, otherVersion, snap.Edition)); err == nil {
		t.Fatal("a wire carrying field_redact@2 discharged the corpus's field_redact@1; capabilities must match by exact version")
	}
}

// TestADeliveredCapabilityTheEditionMayNotDeclareDischargesNothing holds the
// narrowing: a community enforcement point's declaration of an Enterprise-only
// family is dropped (registry.SplitOverAdvertised), so a wire delivering that
// family to a community caller can never have it discharged there. The
// capability is derived from the registry's own family set, never named here.
func TestADeliveredCapabilityTheEditionMayNotDeclareDischargesNothing(t *testing.T) {
	enterpriseOnly := map[contract.ObligationFamily]bool{}
	for _, f := range registry.EnterpriseOnlyFamilies() {
		enterpriseOnly[f] = true
	}
	var typ contract.ObligationType
	for _, candidate := range contract.AllObligationTypes() {
		if fam, err := contract.FamilyOf(candidate); err == nil && enterpriseOnly[fam] {
			typ = candidate
			break
		}
	}
	if typ == "" {
		t.Fatal("CONTROL: no declared obligation type belongs to an Enterprise-only family; the narrowing has nothing to narrow")
	}
	o := contract.Obligation{Type: typ, Mandatory: true, SchemaVersion: 1, SourcePolicy: "fixture"}
	delivers := []contract.Capability{o.CapabilityOf()}

	if NewDischargeSurface(nil, delivers, registry.EditionCommunity).Discharges(o) {
		t.Errorf("a community surface discharged %s, which a community enforcement point may not declare", o.CapabilityOf())
	}
	if !NewDischargeSurface(nil, delivers, registry.EditionEnterprise).Discharges(o) {
		t.Errorf("CONTROL: an enterprise surface did not discharge the delivered %s", o.CapabilityOf())
	}
}

// TestAnEmptySurfaceDischargesNothing: the absence of a profile and a wire must
// refuse every mandatory obligation, never pass one.
func TestAnEmptySurfaceDischargesNothing(t *testing.T) {
	planted := shippedMandatoryRedactions(t)
	got := UndischargeableControls(&pdp.Document{Policies: planted}, DischargeSurface{})
	for _, p := range planted {
		if _, refused := got[p.ID]; !refused {
			t.Errorf("an empty surface was reported as discharging %s's mandatory field_redact", p.ID)
		}
	}
}
