// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// splitFixtureRow is one legacy row whose planes resolve `warn` on two
// request-phase planes and `redact` on the MCP response pass - the shape of the
// sixteen PII controls the corpus used to collapse to `redact` (#4046). When
// gatewayDiffers, the gateway plane compiles a DIFFERENT `warn` policy from
// decide's, which is the group the build must refuse.
func splitFixtureRow(t *testing.T, tier string, gatewayDiffers bool) (Record, map[string]string) {
	t.Helper()
	const table, rowID = "static_policies", "sys_split_fixture"
	policy := func(plane Plane, ph Phase, authority contract.Authority, path string, obligation contract.ObligationType) pdp.Policy {
		p := pdp.Policy{
			ID: PolicyIDFor(table, rowID, plane, ph), Root: pdp.RootSystem, Authority: authority,
			Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
			Where:       pdp.Compare(path, pdp.OpEq, true),
			Description: "compiled for plane " + string(plane),
		}
		o := contract.Obligation{Type: obligation, SourcePolicy: p.ID, SchemaVersion: 1}
		if obligation == contract.ObFieldRedact {
			o.Target, o.Mandatory, p.Mandatory = DefaultContentTarget, true, true
		}
		p.Obligations = []contract.Obligation{o}
		return p
	}
	signal := DetectorSignalPath(rowID)
	gatewayPath := signal
	if gatewayDiffers {
		gatewayPath = DetectorSignalPath("a_different_detector")
	}
	var rec Record
	rec.Source.Table, rec.Source.PolicyID, rec.Source.OrgScope = table, rowID, "global"
	rec.Planes = []PlaneResult{
		{Plane: PlaneDecide, Phase: PhaseRequest, ResolvedAction: "warn", EnforcedAction: "warn",
			Policies: []pdp.Policy{policy(PlaneDecide, PhaseRequest, contract.AuthorityRequirement, signal, contract.ObNotification)}},
		{Plane: PlaneGatewayRequest, Phase: PhaseRequest, ResolvedAction: "warn", EnforcedAction: "warn",
			Policies: []pdp.Policy{policy(PlaneGatewayRequest, PhaseRequest, contract.AuthorityRequirement, gatewayPath, contract.ObNotification)}},
		{Plane: PlaneMCP, Phase: PhaseResponse, ResolvedAction: "redact", EnforcedAction: "redact",
			Policies: []pdp.Policy{policy(PlaneMCP, PhaseResponse, contract.AuthorityRequirement, signal, contract.ObFieldRedact)}},
	}
	return rec, map[string]string{corpusRowKey(table, "global", rowID): tier}
}

func buildSplitFixture(t *testing.T, tier string, gatewayDiffers bool) ([]pdp.Policy, map[string][]string, []Divergence, error) {
	t.Helper()
	rec, tierOf := splitFixtureRow(t, tier, gatewayDiffers)
	return corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
}

// TestASystemRowWhoseScopesResolveDifferentActionsIsSplitAndBound is the
// emission half of #4046: one policy per resolved action, each named for its
// action, each bound to exactly the scopes that resolved it, and no collapse
// declared because none happened.
func TestASystemRowWhoseScopesResolveDifferentActionsIsSplitAndBound(t *testing.T) {
	policies, bindings, divs, err := buildSplitFixture(t, "system", false)
	if err != nil {
		t.Fatalf("a consistent split was refused: %v", err)
	}
	warn := CorpusVariantIDFor("static_policies", "sys_split_fixture", "warn")
	redact := CorpusVariantIDFor("static_policies", "sys_split_fixture", "redact")
	var ids []string
	for _, p := range policies {
		ids = append(ids, p.ID)
		for _, o := range p.Obligations {
			if o.SourcePolicy != p.ID {
				t.Errorf("%s carries an obligation sourced from %q; a re-keyed policy's obligations must name it", p.ID, o.SourcePolicy)
			}
		}
		if !strings.Contains(p.Description, "binds this one to those scopes only") {
			t.Errorf("%s's description does not say it is bound to its scopes: %q", p.ID, p.Description)
		}
	}
	if fmt.Sprint(ids) != fmt.Sprint([]string{warn, redact}) {
		t.Fatalf("the split emitted %v; want [%s %s]", ids, warn, redact)
	}
	want := map[string]string{warn: "decide,gateway_request", redact: "mcp:response"}
	if len(bindings) != len(want) {
		t.Fatalf("the split bound %v; want %v", bindings, want)
	}
	for id, scopes := range want {
		if got := strings.Join(bindings[id], ","); got != scopes {
			t.Errorf("%s is bound to %q; want %q, the scopes that resolved its action, sorted", id, got, scopes)
		}
	}
	for _, d := range divs {
		if d.Kind == DivergencePlaneActionCollapsed {
			t.Errorf("a split row declared %s: %s", d.Kind, d.Detail)
		}
	}
}

// TestASplitGroupWhosePlanesCompiledDifferentContentIsRefused is the planted
// positive for the build's loud refusal: two planes resolve `warn` and the
// gateway plane compiled a policy reading a different signal. Binding decide's
// policy to the gateway scope would enforce there a policy that plane never
// compiled, so the build must refuse - and a refusal nothing triggers would be
// indistinguishable from no refusal at all.
func TestASplitGroupWhosePlanesCompiledDifferentContentIsRefused(t *testing.T) {
	_, _, _, err := buildSplitFixture(t, "system", true)
	if err == nil {
		t.Fatal("two planes compiled different policies for one action and the build merged them into one variant")
	}
	for _, want := range []string{"sys_split_fixture", `"warn"`, "compiled different policies"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s: %v", want, err)
		}
	}
}

// TestARowWhoseResolvedActionsAgreeIsSplitByWhatItsPlanesEnforce is the case the
// real capture exposed: two planes resolve `log`, and cowork_ingest COERCES the
// pii-* match to `redact` before it persists, so its compilation enforces
// `redact`. The split follows the compilation - grouping by the resolved action
// would put a `log` and a `redact` policy in one group - and a row that resolves
// one action everywhere is still split when its planes enforce two.
func TestARowWhoseResolvedActionsAgreeIsSplitByWhatItsPlanesEnforce(t *testing.T) {
	const table, rowID = "static_policies", "sys_coerced_fixture"
	signal := DetectorSignalPath(rowID)
	compiled := func(plane Plane, ph Phase, redact bool) pdp.Policy {
		p := pdp.Policy{
			ID: PolicyIDFor(table, rowID, plane, ph), Root: pdp.RootSystem, Authority: contract.AuthorityRequirement,
			Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
			Where: pdp.Compare(signal, pdp.OpEq, true), Description: "compiled for plane " + string(plane),
		}
		o := contract.Obligation{Type: contract.ObImmutableAudit, SourcePolicy: p.ID, SchemaVersion: 1}
		if redact {
			o = contract.Obligation{Type: contract.ObFieldRedact, Target: DefaultContentTarget, Mandatory: true, SourcePolicy: p.ID, SchemaVersion: 1}
			p.Mandatory = true
		}
		p.Obligations = []contract.Obligation{o}
		return p
	}
	cowork := PlaneCoworkIngest
	var rec Record
	rec.Source.Table, rec.Source.PolicyID, rec.Source.OrgScope = table, rowID, "global"
	rec.Planes = []PlaneResult{
		{Plane: cowork, Phase: PhaseResponse, ResolvedAction: "log", EnforcedAction: "redact", Policies: []pdp.Policy{compiled(cowork, PhaseResponse, true)}},
		{Plane: PlaneDecide, Phase: PhaseRequest, ResolvedAction: "log", EnforcedAction: "log", Policies: []pdp.Policy{compiled(PlaneDecide, PhaseRequest, false)}},
	}
	tierOf := map[string]string{corpusRowKey(table, "global", rowID): "system"}
	policies, bindings, _, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err != nil {
		t.Fatalf("a row whose planes enforce two actions was refused: %v", err)
	}
	logID, redactID := CorpusVariantIDFor(table, rowID, "log"), CorpusVariantIDFor(table, rowID, "redact")
	if len(policies) != 2 {
		t.Fatalf("the row emitted %d policies; want one per enforced action", len(policies))
	}
	if got := strings.Join(bindings[logID], ","); got != "decide" {
		t.Errorf("%s is bound to %q; want decide, the plane whose compilation enforces log", logID, got)
	}
	if got := strings.Join(bindings[redactID], ","); got != "cowork_ingest" {
		t.Errorf("%s is bound to %q; want cowork_ingest, the plane whose coerced compilation enforces redact", redactID, got)
	}
}

// The organization-template boundary of this split - a template row is not
// split by what each legacy engine resolved, and its collapsed redaction is
// bound by discharge instead - is TestATemplateRedactionIsSplitByDischargeNotByResolution
// (template_discharge_test.go, #4131), which replaced the test that held a
// template row to one unbound policy.

// TestASystemRowWhoseWeakerPlaneCompiledNothingDeclaresItsCollapse holds the
// collapse divergence to the split decision: a system row whose planes resolve
// two actions, only one of which any plane compiled, is not split - one policy,
// no bindings - so it declares the collapse like any other collapsed row.
func TestASystemRowWhoseWeakerPlaneCompiledNothingDeclaresItsCollapse(t *testing.T) {
	const table, rowID = "static_policies", "sys_uncompiled_weaker_plane"
	warn := pdp.Policy{
		ID: PolicyIDFor(table, rowID, PlaneDecide, PhaseRequest), Root: pdp.RootSystem, Authority: contract.AuthorityRequirement,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where: pdp.Compare(DetectorSignalPath(rowID), pdp.OpEq, true), Description: "compiled for plane decide",
	}
	warn.Obligations = []contract.Obligation{{Type: contract.ObNotification, SourcePolicy: warn.ID, SchemaVersion: 1}}
	var rec Record
	rec.Source.Table, rec.Source.PolicyID, rec.Source.OrgScope = table, rowID, "global"
	rec.Planes = []PlaneResult{
		{Plane: PlaneDecide, Phase: PhaseRequest, ResolvedAction: "warn", EnforcedAction: "warn", Policies: []pdp.Policy{warn}},
		{Plane: PlaneGatewayRequest, Phase: PhaseRequest, ResolvedAction: "log", EnforcedAction: "log"},
	}
	tierOf := map[string]string{corpusRowKey(table, "global", rowID): "system"}
	policies, bindings, divs, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err != nil {
		t.Fatalf("the row was refused: %v", err)
	}
	if len(policies) != 1 || policies[0].ID != CorpusPolicyIDFor(table, rowID) || len(bindings) != 0 {
		t.Fatalf("the row emitted %d policies and bindings %v; a row with one compiled action is not split", len(policies), bindings)
	}
	for _, d := range divs {
		if d.Kind == DivergencePlaneActionCollapsed && d.Chosen == "warn" && fmt.Sprint(d.LegacyActions) == "[log warn]" {
			return
		}
	}
	t.Fatalf("a system row resolving [log warn] and collapsed to warn declared no plane_action_collapsed: %v", divs)
}

// TestASplitRowNamesEveryPlaneWhoseBoundCompilationCarriesTheDefect: the corpus
// binds a group's representative compilation to every plane in the group, so a
// defect a member plane's compilation carries is carried by the variant, and the
// declared divergence names that plane although another plane's compilation was
// the one imported.
func TestASplitRowNamesEveryPlaneWhoseBoundCompilationCarriesTheDefect(t *testing.T) {
	rec, tierOf := splitFixtureRow(t, "system", false)
	defect := DefectReasonCodes()[0]
	issue, _ := IsDefectReason(defect)
	for i := range rec.Planes {
		if rec.Planes[i].Plane == PlaneGatewayRequest {
			rec.Planes[i].Reasons = append(rec.Planes[i].Reasons, Reason{Code: defect, Issue: issue, Plane: PlaneGatewayRequest, Detail: "planted"})
		}
	}
	rec.Status = StatusPreservedDefect
	if st, ok := rec.StatusForPlane(PlaneGatewayRequest); !ok || st != StatusPreservedDefect {
		t.Fatalf("CONTROL: the planted reason did not make gateway_request's compilation a preserved defect (status %q); the test would prove nothing", st)
	}
	if st, _ := rec.StatusForPlane(PlaneDecide); st == StatusPreservedDefect {
		t.Fatal("CONTROL: the representative plane carries the defect too, so this test could not tell a representative-only scan from a member scan")
	}
	_, _, divs, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range divs {
		if d.Kind != DivergenceLegacyDefectReproduced {
			continue
		}
		if !strings.Contains(d.Detail, "the compilations from [gateway_request] carry the defect") {
			t.Fatalf("the divergence does not name the member plane whose bound compilation carries the defect: %s", d.Detail)
		}
		return
	}
	t.Fatalf("a split row with a preserved defect declared no %s: %v", DivergenceLegacyDefectReproduced, divs)
}
