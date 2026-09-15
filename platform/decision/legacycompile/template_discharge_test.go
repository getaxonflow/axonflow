// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// dischargeScopes and noDischargeScopes are the scopes as measured at #4131:
// a plane profile carrying field_redact@1 (mcp, orchestrator_response,
// cowork_ingest) or a wire that hands it to a declaring caller (decide and the
// gateway pre-check deliver the decision wire), and every other scope. They are
// typed here rather than derived, so the rule is held to the measurement.
var (
	dischargeScopes   = []string{"cowork_ingest", "decide", "gateway_request", "mcp:request", "mcp:response", "orchestrator_response"}
	noDischargeScopes = []string{"map", "openai_compatible", "policy_simulation", "policy_test", "proxy_request", "wcp"}
)

func TestWhichScopesCanDischargeAFieldRedact(t *testing.T) {
	want := map[string]bool{}
	for _, s := range dischargeScopes {
		want[s] = true
	}
	for _, s := range noDischargeScopes {
		want[s] = false
	}
	all := AllScopes()
	if len(all) != len(want) {
		t.Fatalf("the model declares %d scopes and this table classifies %d; classify the new one", len(all), len(want))
	}
	for _, s := range all {
		got, err := ScopeDischarges(s, fieldRedactCapability)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if w, ok := want[s.String()]; !ok || got != w {
			t.Errorf("ScopeDischarges(%s, field_redact@1) = %v; want %v", s, got, w)
		}
	}
}

// An edition that would answer differently from the other is refused: the
// corpus is one artifact for both, so it cannot bind the redaction one way.
func TestAScopeWhoseEditionsDisagreeAboutDischargeIsRefused(t *testing.T) {
	rows := []registry.LegacyPlaneRow{
		{Plane: string(PlaneDecide), Edition: registry.EditionCommunity, Capabilities: []contract.Capability{fieldRedactCapability}},
		{Plane: string(PlaneDecide), Edition: registry.EditionEnterprise},
	}
	_, err := scopeDischarges(rows, nil, MustScopeFor(PlaneDecide, ""), fieldRedactCapability)
	if err == nil || !strings.Contains(err.Error(), "some editions") {
		t.Fatalf("a scope discharging on one edition only was answered %v; want the refusal naming the disagreement", err)
	}
	// The control: both editions agreeing is an answer, not a refusal.
	rows[1].Capabilities = []contract.Capability{fieldRedactCapability}
	if ok, err := scopeDischarges(rows, nil, MustScopeFor(PlaneDecide, ""), fieldRedactCapability); err != nil || !ok {
		t.Fatalf("two editions both discharging answered %v, %v; want true", ok, err)
	}
}

// templateSplitOptions carries the captured row whose category and severity the
// warn half is compiled from.
func templateSplitOptions(category, severity string) CorpusOptions {
	col := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	return CorpusOptions{ContentTarget: DefaultContentTarget, Rows: []RawRow{{
		Table: "static_policies", OrgScope: "global",
		Columns: map[string]json.RawMessage{"policy_id": col("sys_split_fixture"), "category": col(category), "severity": col(severity), "tier": col("tenant")},
	}}}
}

// TestATemplateRedactionIsSplitByDischargeNotByResolution replaces #4046's
// "a template row still collapses" (#4131). A template row is not split by what
// each plane's legacy engine resolved - the organization decides what it
// activates - so it keeps its most restrictive compilation, redact, and declares
// the collapse. That redaction is then bound by DISCHARGE: redact on every
// scope that can carry one out, warn on every scope that cannot.
func TestATemplateRedactionIsSplitByDischargeNotByResolution(t *testing.T) {
	rec, tierOf := splitFixtureRow(t, "tenant", false)
	policies, bindings, divs, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), templateSplitOptions("pii-us", "high"))
	if err != nil {
		t.Fatalf("the template row was refused: %v", err)
	}
	redactID := CorpusVariantIDFor("static_policies", "sys_split_fixture", "redact")
	warnID := CorpusVariantIDFor("static_policies", "sys_split_fixture", "warn")
	if len(policies) != 2 || policies[0].ID != redactID || policies[1].ID != warnID {
		ids := []string{}
		for _, p := range policies {
			ids = append(ids, p.ID)
		}
		t.Fatalf("the template row emitted %v; want [%s %s]", ids, redactID, warnID)
	}
	redact, warn := policies[0], policies[1]
	if !carriesMandatoryFieldRedact(redact) || redact.Root != pdp.RootOrganization {
		t.Errorf("%s does not carry the row's mandatory redaction on the organization root: %+v", redactID, redact)
	}
	if carriesMandatoryFieldRedact(warn) || warn.Mandatory || warn.Authority != contract.AuthorityRequirement ||
		len(warn.Obligations) != 1 || warn.Obligations[0].Type != contract.ObNotification {
		t.Errorf("%s is not the corpus's warn shape (a requirement carrying one notification, nothing mandatory): %+v", warnID, warn)
	}
	if warn.Obligations[0].Params["category"] != "pii-us" || warn.Obligations[0].Params["severity"] != "high" {
		t.Errorf("%s's notification records %v; want the captured row's category and severity", warnID, warn.Obligations[0].Params)
	}
	for _, p := range policies {
		gotWhere, _ := json.Marshal(p.Where)
		wantWhere, _ := json.Marshal(redact.Where)
		if string(gotWhere) != string(wantWhere) || p.Name != redact.Name {
			t.Errorf("%s reads %s named %q; both halves must read the row's detector under the row's name", p.ID, gotWhere, p.Name)
		}
		for _, o := range p.Obligations {
			if o.SourcePolicy != p.ID {
				t.Errorf("%s carries an obligation sourced from %q", p.ID, o.SourcePolicy)
			}
		}
		if p.Assurance == "" {
			t.Errorf("%s declares no assurance class", p.ID)
		}
	}
	if got := strings.Join(bindings[redactID], ","); got != strings.Join(dischargeScopes, ",") {
		t.Errorf("%s is bound to %q; want the scopes that can discharge a redaction, %q", redactID, got, strings.Join(dischargeScopes, ","))
	}
	if got := strings.Join(bindings[warnID], ","); got != strings.Join(noDischargeScopes, ",") {
		t.Errorf("%s is bound to %q; want the scopes that cannot, %q", warnID, got, strings.Join(noDischargeScopes, ","))
	}
	collapsed, declared := false, false
	for _, d := range divs {
		if d.Kind == DivergencePlaneActionCollapsed && d.Chosen == "redact" {
			collapsed = true
		}
		if d.Kind == DivergenceRedactionBoundByDischarge && strings.Contains(d.Detail, "proxy_request") {
			declared = true
		}
	}
	if !collapsed || !declared {
		t.Errorf("the row declared collapse=%v discharge-binding=%v; want both: %+v", collapsed, declared, divs)
	}
}

// A template row that does not redact is not split: the discharge rule reads a
// mandatory field_redact and nothing else.
func TestATemplateRowThatDoesNotRedactIsNotSplit(t *testing.T) {
	const table, rowID = "static_policies", "sys_split_fixture"
	block := pdp.Policy{
		ID: PolicyIDFor(table, rowID, PlaneProxyRequest, ""), Root: pdp.RootSystem, Authority: contract.AuthorityConstraint,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where: pdp.Compare(DetectorSignalPath(rowID), pdp.OpEq, true), Description: "compiled for plane proxy_request",
	}
	var rec Record
	rec.Source.Table, rec.Source.PolicyID, rec.Source.OrgScope = table, rowID, "global"
	rec.Planes = []PlaneResult{{Plane: PlaneProxyRequest, ResolvedAction: "block", EnforcedAction: "block", Policies: []pdp.Policy{block}}}
	tierOf := map[string]string{corpusRowKey(table, "global", rowID): "tenant"}
	policies, bindings, _, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), templateSplitOptions("dangerous_queries", "critical"))
	if err != nil {
		t.Fatalf("the row was refused: %v", err)
	}
	if len(policies) != 1 || policies[0].ID != CorpusPolicyIDFor(table, rowID) || len(bindings) != 0 {
		t.Fatalf("a template block row emitted %d policies and bindings %v; want the one unsplit policy", len(policies), bindings)
	}
}

// The warn half is compiled from the captured row's category and severity; a
// build handed no such row refuses rather than compiling a notification that
// records nothing.
func TestATemplateRedactionWithNoCapturedRowIsRefused(t *testing.T) {
	rec, tierOf := splitFixtureRow(t, "tenant", false)
	_, _, _, err := corpusPolicyFor(rec, tierOf, map[string]bool{}, registry.NewCatalog(time.Now()), CorpusOptions{ContentTarget: DefaultContentTarget})
	if err == nil || !strings.Contains(err.Error(), "category and severity") {
		t.Fatalf("a template redaction with no captured row was answered %v; want the refusal naming the category and severity it needs", err)
	}
}
