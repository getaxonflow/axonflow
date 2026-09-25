// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// AN ORGANIZATION CONTROL THAT READS A REGISTRY DETECTOR BINDS ONLY WHERE THE
// DETECTOR RUNS (#4249 row 5674230432).
//
// Before the arm, such a control was carried on every scope, and on a scope
// that runs no registry detector - the orchestrator request plane, the workflow
// step gate, the multi-agent plane - the detector was UNKNOWN on every request,
// so the control withheld all of them as unknown_constraint. These cells
// activate a real published document on each scope.

const dropTablePath = "signal.detector.drop__table__prevention"

// detectorControlDocument is the baseline pack plus one organization
// constraint over where, reading the detector paths it names.
func detectorControlDocument(t *testing.T, w *digestWorld, id string, where pdp.Condition, paths ...string) pdp.Document {
	t.Helper()
	doc := baselineDocument(t, w.snap)
	for _, path := range paths {
		doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{Path: path, Type: pdp.TypeBoolean})
	}
	doc.Policies = append(doc.Policies, pdp.Policy{
		ID: id, Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where: where, Name: id,
	})
	return doc
}

// publishDetectorControl publishes doc, with a fixture in which every detector
// the control reads fired.
func publishDetectorControl(t *testing.T, w *digestWorld, id string, doc pdp.Document, paths ...string) *authoring.Artifact {
	t.Helper()
	fixture := authoring.Fixture{Name: "the detector fired", Attributes: contract.AttributeSet{}, Expect: map[string]pdp.Verdict{id: pdp.VerdictMatch}}
	for _, path := range paths {
		fixture.Attributes[path] = contract.Known(true, contract.NamespaceOf(path).DefaultProvenance(), 1, digestNow)
	}
	base := baselineDocument(t, w.snap)
	return w.publish(t, id, doc, append(fixturesFor(&base), fixture))
}

func unboundIDs(act *activation.Activation) []string {
	var out []string
	for _, c := range act.DetectorUnboundControls {
		out = append(out, c.ID)
	}
	return out
}

func TestAnOrganizationControlReadingARegistryDetectorBindsOnlyWhereTheDetectorRuns(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	const id = "org.no-drop-table"
	art := publishDetectorControl(t, w, id, detectorControlDocument(t, w, id, pdp.Compare(dropTablePath, pdp.OpEq, true), dropTablePath), dropTablePath)

	// PREMISE: the census runs the detector on proxy_request and on no
	// orchestrator plane. A census that moved would make every cell below
	// about something else.
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	var planes []string
	for _, r := range rows {
		if r.PolicyID == "drop_table_prevention" {
			planes = r.Planes
		}
	}
	if !slices.Contains(planes, "proxy_request") || slices.Contains(planes, "orchestrator_request") || slices.Contains(planes, "wcp") || slices.Contains(planes, "map") {
		t.Fatalf("PREMISE: drop_table_prevention runs on %v", planes)
	}

	t.Run("proxy_request runs it, so the control is carried", func(t *testing.T) {
		act := w.activateOn(t, art, legacycompile.PlaneProxyRequest, "")
		if _, ok := act.Policy(id); !ok {
			t.Fatalf("%s is not carried on proxy_request, where its detector runs", id)
		}
		if len(act.DetectorUnboundControls) != 0 {
			t.Fatalf("DetectorUnboundControls = %+v on a scope that runs the detector", act.DetectorUnboundControls)
		}
		// It FIRES there: a matching request is refused by it, a clean one is not.
		if d := decideWithSignals(t, act, "llm.completion", map[string]bool{"drop_table_prevention": true}); d.State != contract.StateDeny || !slices.Contains(d.Determining.MatchedConstraints, id) {
			t.Fatalf("a DROP TABLE on proxy_request: %s %s, matched %v; want DENY by %s", d.State, d.Reason, d.Determining.MatchedConstraints, id)
		}
		if d := decideWithSignals(t, act, "llm.completion", map[string]bool{"drop_table_prevention": false}); d.State != contract.StateAllow {
			t.Fatalf("a clean request on proxy_request: %s %s; want ALLOW", d.State, d.Reason)
		}
	})
	t.Run("the route plane decides a request with no detector stated, as the route presents it", func(t *testing.T) {
		// THE ROW'S DEFECT, FROM THE CALLER'S SEAT: /api/v1/process states no
		// registry detector. Before the arm this request was withheld as
		// unknown_constraint naming the control; now it is decided.
		act := w.activateOn(t, art, legacycompile.PlaneOrchestratorRequest, "")
		req := request(t, act, "llm.completion")
		// The route states no registry detector: request() fills every signal
		// known-false (cleanSignals), which is the one statement the route must
		// not make, so the detector is taken out.
		if _, stated := req.Attributes[dropTablePath]; !stated {
			t.Fatalf("PREMISE: request() does not state %s, so removing it below would prove nothing", dropTablePath)
		}
		delete(req.Attributes, dropTablePath)
		d, err := act.Engine.Decide(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if d.State != contract.StateAllow || d.Reason == contract.ReasonUnknownConstraint {
			t.Fatalf("a request on orchestrator_request: %s %s, unknown %v; want ALLOW, not withheld as %s", d.State, d.Reason, d.Determining.Unknown, contract.ReasonUnknownConstraint)
		}
	})
	for _, plane := range []legacycompile.Plane{legacycompile.PlaneOrchestratorRequest, legacycompile.PlaneWCP, legacycompile.PlaneMAP} {
		t.Run(string(plane)+" runs none, so the control is left off and recorded", func(t *testing.T) {
			act := w.activateOn(t, art, plane, "")
			if _, ok := act.Policy(id); ok {
				t.Fatalf("%s is carried on %s, which runs no registry detector: it would decide UNKNOWN on every request", id, plane)
			}
			if len(act.DetectorUnboundControls) != 1 {
				t.Fatalf("DetectorUnboundControls = %+v, want exactly %s", act.DetectorUnboundControls, id)
			}
			// Nor is it an effect: the compliance readers count PolicyEffects
			// (activationinputs.ActiveEffects), so a control left off a scope
			// is excluded from every report by construction.
			for _, e := range act.PolicyEffects() {
				if e.PolicyID == id {
					t.Fatalf("%s is listed as an effect on %s, which runs no registry detector: %+v", id, plane, e)
				}
			}
			got := act.DetectorUnboundControls[0]
			if got.ID != id || got.Detector != dropTablePath || got.Arm != string(legacycompile.DetectorArmLoad) || strings.Join(got.Planes, ",") != strings.Join(planes, ",") {
				t.Errorf("recorded %+v; want id %s, detector %s, arm load, planes %v", got, id, dropTablePath, planes)
			}
			if !strings.Contains(act.Restriction, "1 of the organization document's controls read a registry detector") {
				t.Errorf("the restriction reason does not count it: %s", act.Restriction)
			}
			if slices.Contains(act.ScopeUnboundControls, id) {
				t.Errorf("%s is listed as binds_on-unbound too; it has no binds_on", id)
			}
		})
	}
}

// ON THE AGENT PLANES NOTHING MOVES (master's ruling on row 5674230432). decide
// loads DROP TABLE and passes no dangerous_queries category, so the shipped
// corpus's copy is dropped there, but an ORGANIZATION control reading it stays
// carried and recorded nowhere: the organization arm applies only where no
// registry detector runs. (Whether it should also be left off decide is a
// separate #4249 row.)
func TestAnOrganizationControlOnAnAgentPlaneIsCarriedAsBefore(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	const id = "org.no-drop-table"
	art := publishDetectorControl(t, w, id, detectorControlDocument(t, w, id, pdp.Compare(dropTablePath, pdp.OpEq, true), dropTablePath), dropTablePath)
	for _, plane := range []legacycompile.Plane{legacycompile.PlaneDecide, legacycompile.PlaneOrchestratorResponse} {
		act := w.activateOn(t, art, plane, "")
		if _, ok := act.Policy(id); !ok || len(act.DetectorUnboundControls) != 0 {
			t.Fatalf("%s: carried=%v detector-unbound=%+v; want carried and nothing recorded", plane, ok, act.DetectorUnboundControls)
		}
	}
}

// A control the document confines with binds_on is off a scope for its author's
// reason and is recorded there once, never also as detector-unbound.
func TestABindsOnUnboundControlIsNotAlsoDetectorUnbound(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	const id = "org.no-drop-table.proxy-only"
	doc := detectorControlDocument(t, w, id, pdp.Compare(dropTablePath, pdp.OpEq, true), dropTablePath)
	binds := []string{"proxy_request"}
	doc.Policies[len(doc.Policies)-1].BindsOn = &binds
	art := publishDetectorControl(t, w, id, doc, dropTablePath)
	act := w.activateOn(t, art, legacycompile.PlaneWCP, "")
	if !slices.Contains(act.ScopeUnboundControls, id) || slices.Contains(unboundIDs(act), id) {
		t.Fatalf("scope-unbound %v, detector-unbound %v; want %s in the first only", act.ScopeUnboundControls, unboundIDs(act), id)
	}
}

// THE ARM NEVER PUTS THE DEPLOYMENT'S OWN POLICY IN PLACE OF A NARROWED ONE
// (R3 self-round, HIGH). Leaving a control off a scope by its binds_on is the
// author's own deletion there, so a pack's or the baseline's policy of that id
// composes in its place (#4371). The detector arm is the PLATFORM's omission,
// and substituting there would answer an organization that NARROWED a
// deployment permission by handing back the deployment's unconfined one.
//
// The document carries the baseline permission for llm.completion under the
// baseline's own id, narrowed to requests the DROP TABLE detector did not flag.
// On proxy_request, which runs that detector, the narrowed permission decides.
// On the routes' plane, which runs none, it is left off and NOTHING takes its
// place: the completion is no longer permitted there, which is the fail-closed
// direction.
func TestTheDetectorArmDoesNotRestoreTheDeploymentsOwnPermission(t *testing.T) {
	w := newDigestWorld(t, registry.EditionEnterprise)
	doc := baselineDocument(t, w.snap)
	id := ""
	for i, p := range doc.Policies {
		if strings.HasSuffix(p.ID, "llm.completion") {
			id = p.ID
			doc.Policies[i].Where = pdp.Compare(dropTablePath, pdp.OpEq, false)
		}
	}
	if id == "" {
		t.Fatal("PREMISE: the baseline pack carries no llm.completion permission to narrow")
	}
	doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{Path: dropTablePath, Type: pdp.TypeBoolean})
	fixtures := fixturesFor(&doc)
	for i := range fixtures {
		fixtures[i].Attributes[dropTablePath] = contract.Known(false, contract.NamespaceOf(dropTablePath).DefaultProvenance(), 1, digestNow)
	}
	art := w.publish(t, "org.narrowed-baseline", doc, fixtures)

	proxy := w.activateOn(t, art, legacycompile.PlaneProxyRequest, "")
	kept, ok := proxy.Policy(id)
	if !ok {
		t.Fatalf("%s is not carried on proxy_request, which runs the detector", id)
	}
	if kept.Where.Kind == pdp.CondTrue {
		t.Fatalf("%s on proxy_request is the deployment's unconfined permission, not the organization's narrowed one", id)
	}

	routes := w.activateOn(t, art, legacycompile.PlaneOrchestratorRequest, "")
	if got, ok := routes.Policy(id); ok {
		t.Fatalf("%s is carried on orchestrator_request as %+v; the organization's narrowed permission was left off, so nothing may take its place", id, got.Where)
	}
	if !slices.Contains(unboundIDs(routes), id) {
		t.Errorf("the routes' activation does not record %s as detector-unbound: %v", id, unboundIDs(routes))
	}
}
