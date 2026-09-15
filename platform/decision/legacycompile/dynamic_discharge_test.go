// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

const dynamicDischargeFixtureRow = "sys_dyn_discharge_fixture"

// dynamicRedactPolicy is the policy a dynamic redact action compiles to
// (dynamicPolicyFor's redact arm): a mandatory requirement carrying one
// mandatory field_redact per field, over the row's content detector.
func dynamicRedactPolicy(fields ...string) pdp.Policy {
	p := pdp.Policy{
		Root: pdp.RootSystem, Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where:     pdp.Compare(DynamicContentDetectorPath(dynamicDischargeFixtureRow), pdp.OpEq, true),
		Authority: contract.AuthorityRequirement, Mandatory: true,
	}
	for _, f := range fields {
		p.Obligations = append(p.Obligations, contract.Obligation{Type: contract.ObFieldRedact, Target: f, Mandatory: true, SchemaVersion: 1})
	}
	return p
}

// dynamicDischargeFixture is a system dynamic row as compileDynamicRow compiles
// one: on every plane that reads dynamic_policies, action[0] as first and
// action[1] as an immutable audit, with the row's comma-joined action list as
// each plane's resolved and enforced action.
func dynamicDischargeFixture(t *testing.T, first pdp.Policy, actions string) (Record, map[string]string) {
	t.Helper()
	const table = "dynamic_policies"
	var rec Record
	rec.Source.Table, rec.Source.PolicyID, rec.Source.OrgScope, rec.Source.Name = table, dynamicDischargeFixtureRow, "global", "Dynamic discharge fixture"
	for _, plane := range PlanesFor(SubstrateDynamic) {
		prefix := PolicyIDFor(table, dynamicDischargeFixtureRow, plane, "")
		action0 := first
		action0.ID = prefix + "#0"
		action0.Obligations = append([]contract.Obligation(nil), first.Obligations...)
		for i := range action0.Obligations {
			action0.Obligations[i].SourcePolicy = action0.ID
		}
		audit := pdp.Policy{
			ID: prefix + "#1", Root: first.Root, Scope: first.Scope, Actions: first.Actions, Where: first.Where,
			Authority: contract.AuthorityRequirement,
			Obligations: []contract.Obligation{{
				Type: contract.ObImmutableAudit, Params: map[string]string{"level": "info", "message": "policy matched"},
				SourcePolicy: prefix + "#1", SchemaVersion: 1,
			}},
		}
		rec.Planes = append(rec.Planes, PlaneResult{
			Plane: plane, ReadPath: ReadPathDynamicRows, ResolvedAction: actions, EnforcedAction: actions,
			Policies: []pdp.Policy{action0, audit},
		})
	}
	return rec, map[string]string{corpusRowKey(table, "global", dynamicDischargeFixtureRow): "system"}
}

// #4254: a dynamic row whose redaction binds only on scopes that cannot carry a
// redaction out ships that redaction as the dynamic substrate's warn, under the
// id the corpus gives it, and says so; its sibling policy is untouched.
func TestADynamicRedactionShipsAsAWarnUnderItsOwnID(t *testing.T) {
	rec, tierOf := dynamicDischargeFixture(t, dynamicRedactPolicy("ssn", "account_number"), "redact,log")
	policies, bindings, divs, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err != nil {
		t.Fatalf("the dynamic row was refused: %v", err)
	}
	control := CorpusPolicyIDFor("dynamic_policies", dynamicDischargeFixtureRow)
	if len(policies) != 2 || policies[0].ID != control+"#1" || policies[1].ID != control+"#2" {
		ids := []string{}
		for _, p := range policies {
			ids = append(ids, p.ID)
		}
		t.Fatalf("the dynamic row emitted %v; want [%s#1 %s#2], the ids the corpus gives it without this rule", ids, control, control)
	}
	warn, audit := policies[0], policies[1]
	if carriesMandatoryFieldRedact(warn) || warn.Mandatory || warn.Authority != contract.AuthorityRequirement ||
		len(warn.Obligations) != 1 || warn.Obligations[0].Type != contract.ObNotification {
		t.Fatalf("%s is not the dynamic warn shape (a requirement carrying one notification, nothing mandatory): %+v", warn.ID, warn)
	}
	if got := warn.Obligations[0].Params; len(got) != 3 || got["kind"] != "warn" || got["severity"] != dynamicNotificationSeverity || got["channel"] != "" {
		t.Errorf("%s's notification records %v; want kind warn, the dynamic default severity and no channel", warn.ID, got)
	}
	if warn.Obligations[0].SourcePolicy != warn.ID {
		t.Errorf("%s's notification is sourced from %q", warn.ID, warn.Obligations[0].SourcePolicy)
	}
	gotWhere, _ := json.Marshal(warn.Where)
	wantWhere, _ := json.Marshal(rec.Planes[0].Policies[0].Where)
	if string(gotWhere) != string(wantWhere) || warn.Name != rec.Source.Name || warn.Root != pdp.RootSystem {
		t.Errorf("%s reads %s named %q on root %q; the warn must read the row's condition under the row's name, on its root", warn.ID, gotWhere, warn.Name, warn.Root)
	}
	if warn.Assurance == "" {
		t.Errorf("%s declares no assurance class", warn.ID)
	}
	if len(audit.Obligations) != 1 || audit.Obligations[0].Type != contract.ObImmutableAudit || audit.Obligations[0].SourcePolicy != audit.ID {
		t.Errorf("the row's audit sibling %s changed: %+v", audit.ID, audit)
	}
	if len(bindings) != 0 {
		t.Errorf("the dynamic row gained scope bindings %v; it binds by substrate", bindings)
	}
	var declared []Divergence
	for _, d := range divs {
		if d.Kind == DivergenceDynamicRedactionShipsAsWarn {
			declared = append(declared, d)
		}
	}
	if len(declared) != 1 {
		t.Fatalf("the row declared %d %s divergences; want exactly one: %+v", len(declared), DivergenceDynamicRedactionShipsAsWarn, divs)
	}
	if declared[0].PolicyID != dynamicDischargeFixtureRow || declared[0].Table != "dynamic_policies" {
		t.Errorf("the divergence names row %q in %q; want the row it was compiled from", declared[0].PolicyID, declared[0].Table)
	}
	// The fields the deployment vocabulary keeps as payload leaves (ruling B).
	if got := strings.Join(declared[0].Fields, ","); got != "account_number,ssn" {
		t.Errorf("the divergence retains fields %q; want the sorted fields the redaction named, account_number,ssn", got)
	}
	for _, want := range []string{"account_number", "ssn", "map", "wcp", "policy_simulation", "policy_test", warn.ID} {
		if !strings.Contains(declared[0].Detail, want) {
			t.Errorf("the divergence detail does not name %q: %s", want, declared[0].Detail)
		}
	}
}

// A dynamic row that does not redact is not touched: the rule reads a mandatory
// field_redact and nothing else.
func TestADynamicRowThatDoesNotRedactIsUnchanged(t *testing.T) {
	block := dynamicRedactPolicy()
	block.Authority, block.Mandatory = contract.AuthorityConstraint, false
	rec, tierOf := dynamicDischargeFixture(t, block, "block,log")
	policies, _, divs, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err != nil {
		t.Fatalf("the row was refused: %v", err)
	}
	if len(policies) != 2 || policies[0].Authority != contract.AuthorityConstraint || len(policies[0].Obligations) != 0 {
		t.Fatalf("a dynamic block row emitted %+v; want its constraint unchanged", policies)
	}
	for _, d := range divs {
		if d.Kind == DivergenceDynamicRedactionShipsAsWarn {
			t.Errorf("a row that does not redact declared %s: %+v", d.Kind, d)
		}
	}
}

// A dynamic redaction bound where a scope CAN carry it out is refused, not
// turned into a warn: the rule applies only where no scope it binds on can.
func TestADynamicRedactionAScopeCouldCarryOutIsRefused(t *testing.T) {
	p := dynamicRedactPolicy("ssn")
	p.ID = CorpusPolicyIDFor("dynamic_policies", dynamicDischargeFixtureRow)
	_, _, _, err := shipDynamicRedactionAsWarn("dynamic_policies", dynamicDischargeFixtureRow, []pdp.Policy{p}, map[string][]string{p.ID: {"decide", "wcp"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "decide can carry it out") {
		t.Fatalf("a dynamic redaction bound on decide was answered %v; want the refusal naming the scope that can carry it out", err)
	}
	// The control: the same policy bound only where nothing can carry it out
	// ships as a warn.
	out, _, divs, err := shipDynamicRedactionAsWarn("dynamic_policies", dynamicDischargeFixtureRow, []pdp.Policy{p}, map[string][]string{p.ID: {"wcp"}}, nil)
	if err != nil || len(out) != 1 || carriesMandatoryFieldRedact(out[0]) || len(divs) != 1 {
		t.Fatalf("bound on wcp alone: err %v, policies %+v, divergences %+v; want one warn and one divergence", err, out, divs)
	}
}

// A dynamic redaction beside an obligation of another type is refused: the warn
// replaces every obligation the policy carries, and dropping one silently is
// not the rule.
func TestADynamicRedactionBesideAnotherObligationIsRefused(t *testing.T) {
	p := dynamicRedactPolicy("ssn")
	p.ID = CorpusPolicyIDFor("dynamic_policies", dynamicDischargeFixtureRow)
	p.Obligations = append(p.Obligations, contract.Obligation{Type: contract.ObImmutableAudit, SchemaVersion: 1})
	_, _, _, err := shipDynamicRedactionAsWarn("dynamic_policies", dynamicDischargeFixtureRow, []pdp.Policy{p}, map[string][]string{}, nil)
	if err == nil || !strings.Contains(err.Error(), "beside an obligation of type "+string(contract.ObImmutableAudit)) {
		t.Fatalf("a redaction beside an immutable audit was answered %v; want the refusal naming the obligation it would drop", err)
	}
}

// An unbound dynamic policy binds on every scope of every plane the plane model
// says reads dynamic_policies, and a bound one on exactly its bindings, each a
// declared scope. It checks dynamicPolicyScopes against the plane model; it does
// not ask activation which scopes it keeps (R3 A-LOW: an internal legacycompile
// test cannot import activation, which imports this package).
func TestADynamicPolicyBindsOnThePlanesThatReadDynamicPolicies(t *testing.T) {
	const id = "corpus:dynamic_policies:fixture"
	scopes, err := dynamicPolicyScopes(id, map[string][]string{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range scopes {
		got = append(got, s.String())
	}
	sort.Strings(got)
	if want := "map,policy_simulation,policy_test,wcp"; strings.Join(got, ",") != want {
		t.Errorf("an unbound dynamic policy binds on %v; want %s, the planes that read dynamic_policies", got, want)
	}
	if _, err := dynamicPolicyScopes(id, map[string][]string{id: {"no_such_scope"}}); err == nil || !strings.Contains(err.Error(), "not a declared enforcement scope") {
		t.Errorf("a binding to an undeclared scope was answered %v; want it refused", err)
	}
	bound, err := dynamicPolicyScopes(id, map[string][]string{id: {"wcp"}})
	if err != nil || len(bound) != 1 || bound[0].String() != "wcp" {
		t.Errorf("a policy bound to wcp resolves to %v, %v; want wcp alone", bound, err)
	}
}

// The dynamic warn arm and the warn a dynamic redaction ships as are one shape:
// dynamicPolicyFor's alert and warn actions compile through
// dynamicNotificationPolicy, with the action's own severity and channel.
func TestTheDynamicWarnArmCompilesThroughTheOneNotificationShape(t *testing.T) {
	row := DynamicRow{PolicyID: dynamicDischargeFixtureRow, Tier: "system"}
	where := pdp.Compare(DynamicContentDetectorPath(dynamicDischargeFixtureRow), pdp.OpEq, true)
	spec := MustSpecFor(PlaneWCP)
	for _, tc := range []struct {
		act               legacyAction
		severity, channel string
	}{
		{legacyAction{Type: "warn"}, dynamicNotificationSeverity, ""},
		{legacyAction{Type: "alert", Config: map[string]any{"severity": "high", "channel": "ops"}}, "high", "ops"},
	} {
		got, reasons := dynamicPolicyFor(row, spec, where, tc.act, 0, Options{})
		if got == nil {
			t.Fatalf("%s compiled to nothing: %v", tc.act.Type, reasons)
		}
		if p := got.Obligations; len(p) != 1 || p[0].Params["kind"] != tc.act.Type || p[0].Params["severity"] != tc.severity || p[0].Params["channel"] != tc.channel {
			t.Errorf("%s compiled to obligations %+v; want one notification of kind %s, severity %s, channel %q", tc.act.Type, got.Obligations, tc.act.Type, tc.severity, tc.channel)
		}
		want := dynamicNotificationPolicy(pdp.Policy{ID: got.ID, Root: got.Root, Scope: got.Scope, Actions: got.Actions, Where: got.Where, Description: got.Description},
			tc.act.Type, tc.severity, tc.channel)
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		if string(g) != string(w) {
			t.Errorf("%s: dynamicPolicyFor compiled\n %s\nwant the one notification shape\n %s", tc.act.Type, g, w)
		}
	}
}
