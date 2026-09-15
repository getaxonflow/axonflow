// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// The (plane, phase) restriction and the discharge guard (#3564, #4046).

func editionSnapshot(t *testing.T, edition registry.Edition) *authoringcatalog.Snapshot {
	t.Helper()
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, authoringcatalog.Deployment{
		Edition: edition, Realms: realms(), Now: time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// censusRowFor returns the census row of the censused detector a policy reads.
func censusRowFor(t *testing.T, p pdp.Policy) (registry.CensusRow, bool) {
	t.Helper()
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]registry.CensusRow{}
	for _, r := range rows {
		byPath[registry.DetectorID(r.PolicyID).SignalPath()] = r
	}
	for _, path := range p.ReferencedPaths() {
		if contract.NamespaceOf(path) != contract.NsSignal {
			continue
		}
		if r, ok := byPath[path]; ok {
			return r, true
		}
	}
	return registry.CensusRow{}, false
}

// controlOf reads a corpus policy identifier back to the control it belongs to:
// a split control's per-scope variant (#4046) and a "#n" sibling are the same
// control, so two scopes binding different variants of one control are
// compared as binding that control.
func controlOf(t *testing.T, id string) string {
	t.Helper()
	control, _, ok := legacycompile.CorpusControlOf(id)
	if !ok {
		t.Fatalf("%s is not a corpus policy identifier", id)
	}
	return control
}

// controlsOf is the set of controls a document binds.
func controlsOf(t *testing.T, doc *pdp.Document) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, p := range doc.Policies {
		out[controlOf(t, p.ID)] = true
	}
	return out
}

// variantsOf returns the policies a document keeps for one control.
func variantsOf(t *testing.T, doc *pdp.Document, table, rowID string) []pdp.Policy {
	t.Helper()
	control := legacycompile.CorpusPolicyIDFor(table, rowID)
	var out []pdp.Policy
	for _, p := range doc.Policies {
		if controlOf(t, p.ID) == control {
			out = append(out, p)
		}
	}
	return out
}

// TestTheMCPPhasesAreTwoDerivedRestrictions: the response pass binds a strict
// subset of what the request pass binds, and each control it leaves out is
// left out by one of the two phase arms for a reason the census and the
// per-site admission state - checked here without naming a single control.
func TestTheMCPPhasesAreTwoDerivedRestrictions(t *testing.T) {
	req, _, err := activation.RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseRequest))
	if err != nil {
		t.Fatal(err)
	}
	resp, reason, err := activation.RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse))
	if err != nil {
		t.Fatal(err)
	}
	reqControls, respControls := controlsOf(t, req), controlsOf(t, resp)
	for control := range respControls {
		if !reqControls[control] {
			t.Errorf("%s binds on the MCP response pass and not its request pass; the response pass loads nothing the plane does not", control)
		}
	}
	if len(resp.Policies) == 0 || len(resp.Policies) >= len(req.Policies) {
		t.Fatalf("the MCP response pass binds %d controls and the request pass %d; the phase arms must remove some and leave some",
			len(resp.Policies), len(req.Policies))
	}
	if !strings.Contains(reason, "response phase") {
		t.Errorf("the response restriction's reason does not name its phase: %s", reason)
	}

	respAdmission, err := legacycompile.AdmissionFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse)
	if err != nil {
		t.Fatal(err)
	}
	droppedByLoad, droppedByCategory := 0, 0
	for _, p := range req.Policies {
		row, ok := censusRowFor(t, p)
		if !ok {
			continue
		}
		loadsInResponse := false
		for _, plane := range row.Planes {
			spec, err := legacycompile.SpecFor(legacycompile.Plane(plane))
			if err == nil && len(spec.Phases) == 1 && spec.Phases[0] == legacycompile.PhaseResponse &&
				spec.StaticReadPath == legacycompile.MustSpecFor(legacycompile.PlaneMCP).StaticReadPath {
				loadsInResponse = true
			}
		}
		switch {
		case !loadsInResponse:
			droppedByLoad++
			if respControls[controlOf(t, p.ID)] {
				t.Errorf("%s (seeded for the request phase only; census planes %v) binds on the MCP response pass, which never loads it", p.ID, row.Planes)
			}
		case !respAdmission.Admits(row.Category):
			droppedByCategory++
			if respControls[controlOf(t, p.ID)] {
				t.Errorf("%s (category %s) binds on the MCP response pass, whose call sites admit only %v", p.ID, row.Category, respAdmission)
			}
		case !respControls[controlOf(t, p.ID)]:
			t.Errorf("%s loads in the response phase and its category %s is admitted there, yet the response restriction dropped it", p.ID, row.Category)
		}
	}
	// ANTI-VACUITY: both arms must actually remove something from the shipped
	// corpus, or the loop above checked two empty branches.
	if droppedByLoad == 0 || droppedByCategory == 0 {
		t.Fatalf("the load arm removed %d and the category arm %d controls from the MCP response pass; both must fire on the shipped corpus",
			droppedByLoad, droppedByCategory)
	}
	t.Logf("mcp:request binds %d of the shipped controls; mcp:response binds %d (%d not loaded in the response phase, %d not admitted there)",
		len(req.Policies), len(resp.Policies), droppedByLoad, droppedByCategory)
	// STATED BY CODE: ADR-065's amendment of 2026-09-11 and the #3564 CHANGELOG
	// entry quote these four numbers. A change to the corpus, the census or a
	// call site's admission that moves one reds here, so the prose is restated
	// rather than left to drift. They count POLICIES, and a scope keeps one
	// variant of a split control, so splitting the corpus by scope moves none.
	const wantRequest, wantResponse, wantNotLoaded, wantNotAdmitted = 66, 27, 1, 38
	if len(req.Policies) != wantRequest || len(resp.Policies) != wantResponse || droppedByLoad != wantNotLoaded || droppedByCategory != wantNotAdmitted {
		t.Errorf("mcp:request binds %d and mcp:response %d (%d not loaded, %d not admitted); the stated figures are %d and %d (%d, %d). Restate them in ADR-065 and here",
			len(req.Policies), len(resp.Policies), droppedByLoad, droppedByCategory, wantRequest, wantResponse, wantNotLoaded, wantNotAdmitted)
	}
}

// TestTheResponsePassBindsEachControlTheActionItsLegacyPassEnforces holds the
// MCP response pass to #4016's resolution. The corpus used to carry ONE policy
// per control, compiled from one plane, so a pass whose own legacy action was
// weaker enforced a stricter plane's; it now carries one policy per enforced
// action, bound to the scopes that enforce it (#4046).
//
// DERIVED: no control this pass binds declares plane_action_collapsed, while
// the artifact still declares collapses - for its organization-template rows,
// which the organization activates and no scope restricts - so the join reads.
//
// PINNED, as the acceptance evidence the reversals were measured by on a
// migrated capture:
//   - the four injection constraints core/128 stores as action_response =
//     'redact' bind a mandatory redaction here and their block on the request
//     pass, so the anchored engine strips the span where it used to withhold
//     the response;
//   - sys_pii_booking_ref resolves log on every plane but cowork_ingest, which
//     coerces it to redact. The corpus used to import cowork_ingest's mandatory
//     redaction for every plane, and declared no collapse, because the row's
//     resolved action set was one action; it binds log here.
func TestTheResponsePassBindsEachControlTheActionItsLegacyPassEnforces(t *testing.T) {
	request, _, err := activation.RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseRequest))
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := activation.RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse))
	if err != nil {
		t.Fatal(err)
	}

	var corpus struct {
		Divergences []struct {
			PolicyID string `json:"policy_id"`
			Table    string `json:"table"`
			Kind     string `json:"kind"`
		} `json:"divergences"`
	}
	if err := json.Unmarshal(pdp.SystemCorpusSource, &corpus); err != nil {
		t.Fatal(err)
	}
	bound := controlsOf(t, response)
	collapsed := 0
	for _, d := range corpus.Divergences {
		if d.Kind != string(legacycompile.DivergencePlaneActionCollapsed) {
			continue
		}
		collapsed++
		if id := legacycompile.CorpusPolicyIDFor(d.Table, d.PolicyID); bound[id] {
			t.Errorf("%s binds on mcp:response and the corpus collapsed its action across planes; a system control carries one policy per enforced action, or this pass enforces another plane's", id)
		}
	}
	if collapsed == 0 {
		t.Fatal("the shipped corpus declares no plane_action_collapsed divergence, not even for its organization-template rows; the join above read nothing")
	}

	for _, c := range []struct {
		rowID                 string
		onRequest, onResponse string
	}{
		{"sys_dangerous_injection_bracket_marker", "block", "redact"},
		{"sys_dangerous_injection_override", "block", "redact"},
		{"sys_dangerous_injection_role_override", "block", "redact"},
		{"sys_dangerous_injection_system_exfil", "block", "redact"},
		{"sys_pii_booking_ref", "log", "log"},
	} {
		for _, pass := range []struct {
			name   string
			doc    *pdp.Document
			action string
		}{{"mcp:request", request, c.onRequest}, {"mcp:response", response, c.onResponse}} {
			kept := variantsOf(t, pass.doc, "static_policies", c.rowID)
			if len(kept) != 1 {
				t.Errorf("%s keeps %d policies of %s; want exactly its %s variant", pass.name, len(kept), c.rowID, pass.action)
				continue
			}
			p := kept[0]
			if _, action, _ := legacycompile.CorpusControlOf(p.ID); action != pass.action {
				t.Errorf("%s binds %s; want the %s variant", pass.name, p.ID, pass.action)
			}
			redacts := false
			for _, o := range p.Obligations {
				if o.Mandatory && o.Type == contract.ObFieldRedact {
					redacts = true
				}
			}
			switch {
			case pass.action == "block" && p.Authority != contract.AuthorityConstraint:
				t.Errorf("%s binds %s as a %s; a block is a constraint", pass.name, p.ID, p.Authority)
			case pass.action == "redact" && !redacts:
				t.Errorf("%s binds %s with no mandatory field_redact, so the anchored engine would not strip the span", pass.name, p.ID)
			case pass.action != "redact" && redacts:
				t.Errorf("%s binds %s with a mandatory field_redact where its legacy pass enforces %s", pass.name, p.ID, pass.action)
			}
		}
	}
}

func TestActivateBuildsAnEngineForEachMCPPhaseAndRefusesTheWholePlane(t *testing.T) {
	w := newWorld(t)
	base := w.inputs()

	whole := base
	whole.Plane = string(legacycompile.PlaneMCP)
	if _, err := activation.Activate(context.Background(), whole); err == nil {
		t.Fatal("an engine was activated for mcp with no phase; its two phases bind different controls, so either answer is wrong for one of them")
	}

	for _, ph := range []legacycompile.Phase{legacycompile.PhaseRequest, legacycompile.PhaseResponse} {
		in := base
		in.Plane, in.Phase = string(legacycompile.PlaneMCP), ph
		act, err := activation.Activate(context.Background(), in)
		if err != nil {
			t.Fatalf("mcp:%s: %v", ph, err)
		}
		want, _, err := activation.RestrictToScope(legacycompile.MustScopeFor(legacycompile.PlaneMCP, ph))
		if err != nil {
			t.Fatal(err)
		}
		if act.Scope.String() != "mcp:"+string(ph) || act.SystemPolicies != len(want.Policies) {
			t.Fatalf("mcp:%s activated scope %s with %d system controls; want scope mcp:%s with the %d its restriction binds",
				ph, act.Scope, act.SystemPolicies, ph, len(want.Policies))
		}
	}
}

// TestActivationRefusesAScopeItsProfileCannotDischarge is the guard #4046 asks
// for, driven through Activate on a declared scope whose restriction carries a
// mandatory obligation its registered profile cannot discharge with nothing
// delivered. The scope is DERIVED - the first such scope in declaration order -
// because which scopes carry one is a fact of the corpus: gateway_request did
// until the corpus bound each scope its own action, and an engine there would
// have denied every request a shipped redaction matched.
func TestActivationRefusesAScopeItsProfileCannotDischarge(t *testing.T) {
	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		t.Run(edition.String(), func(t *testing.T) {
			w := newWorld(t)
			snap := editionSnapshot(t, edition)

			var refused legacycompile.EnforcementScope
			var failing map[string][]string
			for _, scope := range legacycompile.AllScopes() {
				pep, registered := snap.PEPFor(string(scope.Plane))
				if !registered {
					continue
				}
				doc, err := activationPopulation(scope)
				if err != nil {
					t.Fatal(err)
				}
				if f := activation.UndischargeableControls(doc, activation.NewDischargeSurface(pep, nil, edition)); len(f) > 0 {
					refused, failing = scope, f
					break
				}
			}
			if len(failing) == 0 {
				t.Fatalf("CONTROL: no declared scope's restriction carries a mandatory obligation its %s profile cannot discharge; this test's premise is gone", edition)
			}

			// Nothing delivered: the scope is built the way a deployment builds
			// one no enforcing seam renders a decision for.
			in := w.inputs()
			in.Snapshot, in.Plane, in.Phase, in.Delivers = snap, string(refused.Plane), refused.Phase, nil
			_, err := activation.Activate(context.Background(), in)
			if err == nil {
				t.Fatalf("%s activated although %d shipped controls carry an obligation its profile cannot discharge", refused, len(failing))
			}
			for id := range failing {
				if !strings.Contains(err.Error(), id) {
					t.Errorf("the refusal does not name %s: %v", id, err)
				}
			}
			if !strings.Contains(err.Error(), "unsupported_obligation") {
				t.Errorf("the refusal does not say what the engine would have answered: %v", err)
			}

			// CONTROLS: the guard refuses the mismatch, not activation itself.
			// decide activates through its wire and echoes what it was built with
			// (the implicit bundle's template binds eu_gdpr_cross_border_pii's
			// redaction there, which a declaring caller discharges, #4131); the
			// MCP response pass discharges its redactions inline.
			decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
			for _, c := range []struct {
				scope    legacycompile.EnforcementScope
				delivers []contract.Capability
			}{
				{decide, contract.DecisionWireCapabilities()},
				{legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseResponse), nil},
			} {
				ok := w.inputs()
				ok.Snapshot, ok.Plane, ok.Phase, ok.Delivers = snap, string(c.scope.Plane), c.scope.Phase, c.delivers
				act, err := activation.Activate(context.Background(), ok)
				if err != nil {
					t.Errorf("%s did not activate delivering %v: %v", c.scope, c.delivers, err)
					continue
				}
				if fmt.Sprint(act.Delivers) != fmt.Sprint(c.delivers) {
					t.Errorf("%s activated delivering %v; want %v", c.scope, act.Delivers, c.delivers)
				}
			}
			t.Logf("%s: %s refused, naming %d control(s)", edition, refused, len(failing))
		})
	}
}

// TestEveryScopeActivatesExactlyWhenItsSurfaceDischargesItsRestriction is the
// guard #4046 asks for, over a DERIVED population: every declared scope, in both
// editions, with nothing delivered and with the Decision API's vocabulary
// delivered. Activate refuses a scope if and only if a control its restriction
// binds carries a mandatory obligation the surface cannot discharge, and the
// refusal names every such control. The population is legacycompile.AllScopes
// and each scope's own restriction, so a plane added to the model or a control
// added to the corpus is judged the day it lands - the check that would have
// refused decide before #4025 merged with an exemption.
func TestEveryScopeActivatesExactlyWhenItsSurfaceDischargesItsRestriction(t *testing.T) {
	refused, activated := 0, 0
	var refusedSurfaces []string
	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		snap := editionSnapshot(t, edition)
		w := newWorld(t)
		for _, scope := range legacycompile.AllScopes() {
			pep, registered := snap.PEPFor(string(scope.Plane))
			if !registered {
				continue
			}
			doc, err := activationPopulation(scope)
			if err != nil {
				// A scope whose restriction cannot be derived is refused for
				// that reason, which is restriction.go's subject, not this one.
				continue
			}
			for _, delivers := range [][]contract.Capability{nil, contract.DecisionWireCapabilities()} {
				failing := activation.UndischargeableControls(doc, activation.NewDischargeSurface(pep, delivers, edition))
				in := w.inputs()
				in.Snapshot, in.Plane, in.Phase, in.Delivers = snap, string(scope.Plane), scope.Phase, delivers
				_, err := activation.Activate(context.Background(), in)
				label := fmt.Sprintf("%s %s delivering %v", edition, scope, delivers)
				if len(failing) == 0 {
					if err != nil {
						t.Errorf("%s: every mandatory obligation is dischargeable and activation failed: %v", label, err)
						continue
					}
					activated++
					continue
				}
				if err == nil {
					t.Errorf("%s: activated although %d control(s) carry an obligation nothing here discharges: %v", label, len(failing), failing)
					continue
				}
				refused++
				ids := make([]string, 0, len(failing))
				for id := range failing {
					ids = append(ids, id)
				}
				sort.Strings(ids)
				refusedSurfaces = append(refusedSurfaces, fmt.Sprintf("%s %v", label, ids))
				if !strings.Contains(err.Error(), "unsupported_obligation") {
					t.Errorf("%s: the refusal does not say what the engine would have answered: %v", label, err)
				}
				for id := range failing {
					if !strings.Contains(err.Error(), id) {
						t.Errorf("%s: the refusal does not name %s: %v", label, id, err)
					}
				}
			}
		}
	}
	if refused == 0 || activated == 0 {
		t.Fatalf("refused %d and activated %d scope surfaces; a population that only ever answers one way checks nothing", refused, activated)
	}
	t.Logf("judged every declared scope in both editions: %d surfaces refused, %d activated; refused: %v", refused, activated, refusedSurfaces)
}

// activationPopulation is everything Activate judges for discharge on a scope:
// the system restriction and the organization template the implicit bundle
// composes restricted to it (#4131).
func activationPopulation(scope legacycompile.EnforcementScope) (*pdp.Document, error) {
	system, _, err := activation.RestrictToScope(scope)
	if err != nil {
		return nil, err
	}
	template, err := activation.OrganizationTemplateForScope(scope)
	if err != nil {
		return nil, err
	}
	return &pdp.Document{Root: system.Root, Version: system.Version,
		Policies: append(append([]pdp.Policy(nil), system.Policies...), template.Policies...)}, nil
}
