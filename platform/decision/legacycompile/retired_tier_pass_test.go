// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/registry"
)

// PlaneSpec.EnforcesRetiredTierPassRead (#4253): /api/request's retired second
// pass read a row's STORED action column, which no surviving plane reads, and
// proxy_request - the plane PRD v11 §1 item 1 says inherits the pass - keeps
// that read in two arms: a system row's stored block, and a template row's
// stored action wherever it outranks the phase resolution. These tests drive
// both arms through the real compiler, each case against a control that
// differs in exactly one fact, and hold the population on the shipped census.

// enforcedOn is the action a plane's request-phase result enforces for a row,
// and the retired-pass reason's detail, "" when the result carries none.
func enforcedOn(t *testing.T, rec Record, p Plane) (string, string) {
	t.Helper()
	for _, pr := range rec.Planes {
		if pr.Plane != p || pr.Phase != PhaseRequest {
			continue
		}
		for _, r := range pr.Reasons {
			if r.Code == ReasonRetiredTierPassAction {
				return pr.EnforcedAction, r.Detail
			}
		}
		return pr.EnforcedAction, ""
	}
	t.Fatalf("%s produced no request-phase result on %s, so nothing was asserted", rec.Source.PolicyID, p)
	return "", ""
}

func compileOneRow(t *testing.T, id string, overrides map[string]any) Record {
	t.Helper()
	rep, err := Compile([]RawRow{staticRow(t, id, overrides)}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return recordFor(t, rep, id)
}

// withOverrides is a shape with one control's difference applied.
func withOverrides(shape, override map[string]any) map[string]any {
	row := map[string]any{}
	for k, v := range shape {
		row[k] = v
	}
	for k, v := range override {
		row[k] = v
	}
	return row
}

func TestAStoredSystemBlockIsEnforcedOnProxyRequestAlone(t *testing.T) {
	// The sys_admin_* shape (core/031): a system row, category security-admin,
	// stored action block, NULL phase columns - so every runtime plane resolves
	// the category fallback, which is not block.
	adminShape := map[string]any{
		"category": "security-admin", "action": "block", "action_request": nil, "action_response": nil,
	}
	rec := compileOneRow(t, "sys_admin_probe", adminShape)

	got, detail := enforcedOn(t, rec, PlaneProxyRequest)
	if got != string(ActionBlock) || !strings.HasPrefix(detail, retiredTierPassSystemBlock+":") {
		t.Fatalf("proxy_request enforces %q (retired-pass reason %q); want block under the %q arm", got, detail, retiredTierPassSystemBlock)
	}
	// CONTROL, the same row on a plane without the flag: the phase fallback,
	// not the stored block, and no reason.
	if decideGot, decideDetail := enforcedOn(t, rec, PlaneDecide); decideGot == string(ActionBlock) || decideDetail != "" {
		t.Fatalf("decide enforces %q (retired-pass reason %q); the stored block is /api/request's alone", decideGot, decideDetail)
	}
	// The retired pass RESOLVED the stored column, so the plane's resolution is
	// the stored block - the corpus's collapse ranks resolutions - and the
	// phase column's resolution stays stated in the reason.
	for _, pr := range rec.Planes {
		if pr.Plane == PlaneProxyRequest && (pr.ResolvedAction != string(ActionBlock) || !strings.Contains(detail, "-phase column resolves")) {
			t.Fatalf("proxy_request resolves %q (reason %q); want block, with the phase column's resolution stated in the reason", pr.ResolvedAction, detail)
		}
	}

	for _, tc := range []struct {
		name     string
		override map[string]any
		why      string
	}{
		{"a stored warn", map[string]any{"action": "warn"},
			"a system row's lesser read was its own proxy_tier-only variant, which leaves the corpus with the plane"},
		{"a phase column that already resolves block", map[string]any{"action_request": "block"},
			"the plane already enforces block, so there is no divergence to state"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, detail := enforcedOn(t, compileOneRow(t, "sys_admin_probe_ctrl", withOverrides(adminShape, tc.override)), PlaneProxyRequest); detail != "" {
				t.Fatalf("the retired-pass rule fired (%s): %s", detail, tc.why)
			}
		})
	}
}

// TestATemplateRowKeepsItsStoredActionOnProxyRequest: the organization
// template's shape - a global tenant-tier row with a stored action and NULL
// phase columns, so every runtime plane resolves the category fallback. The
// corpus collapses such a row to its most restrictive plane compilation, which
// until #4253 was the retired pass's read of its stored column; proxy_request
// keeps that read, so the template's refusals and redactions survive the plane.
func TestATemplateRowKeepsItsStoredActionOnProxyRequest(t *testing.T) {
	templateShape := map[string]any{
		"tier": "tenant", "tenant_id": "global", "org_id": "global",
		"action_request": nil, "action_response": nil,
	}
	for _, tc := range []struct{ name, category, action string }{
		{"the template's block list (drop_table_prevention's shape)", "dangerous_queries", "block"},
		{"the template's redactions (pii_ssn_detection's shape)", "pii_detection", "redact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := compileOneRow(t, "template_probe", withOverrides(templateShape, map[string]any{"category": tc.category, "action": tc.action}))
			got, detail := enforcedOn(t, rec, PlaneProxyRequest)
			if got != tc.action || !strings.HasPrefix(detail, retiredTierPassTemplateAction+":") {
				t.Fatalf("proxy_request enforces %q (retired-pass reason %q); want %q under the %q arm", got, detail, tc.action, retiredTierPassTemplateAction)
			}
			// CONTROL, the same row on a plane without the flag.
			if decideGot, decideDetail := enforcedOn(t, rec, PlaneDecide); decideGot == tc.action || decideDetail != "" {
				t.Fatalf("decide enforces %q (retired-pass reason %q); the stored read is proxy_request's alone", decideGot, decideDetail)
			}
		})
	}

	for _, tc := range []struct {
		name     string
		override map[string]any
		why      string
	}{
		{"a stored action that does not outrank the phase resolution", map[string]any{"category": "pii_detection", "action": "log"},
			"the corpus took the stored read only where it was the most restrictive"},
		{"a phase column that already resolves the stored action", map[string]any{"category": "pii_detection", "action": "redact", "action_request": "redact"},
			"the plane already enforces the stored action, so there is no divergence to state"},
		{"a stored hold (eu_ai_act_high_value_transaction's shape)", map[string]any{"category": "compliance-euaiact", "action": "require_approval"},
			"holds return with the orchestrator's typed approval challenge (#4254); keeping one here would refuse what the retired pass held"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, detail := enforcedOn(t, compileOneRow(t, "template_probe_ctrl", withOverrides(templateShape, tc.override)), PlaneProxyRequest); detail != "" {
				t.Fatalf("the retired-pass rule fired (%s): %s", detail, tc.why)
			}
		})
	}
}

// retiredTierPassPopulation splits the census rows that carry the retired-pass
// reason into the system arm and the template arm, each sorted.
func retiredTierPassPopulation(rows []registry.CensusRow) (system, template []string) {
	for _, r := range rows {
		for _, reason := range r.DispositionReasons {
			if reason != string(ReasonRetiredTierPassAction) {
				continue
			}
			if r.SystemTier() {
				system = append(system, r.PolicyID)
			} else {
				template = append(template, r.PolicyID)
			}
			break
		}
	}
	sort.Strings(system)
	sort.Strings(template)
	return system, template
}

// TestTheRetiredTierPassPopulationIsDerivedAndHeld holds the rule's population
// on the shipped detector census, whose disposition_reasons the census
// generator derives by compiling every captured row: exactly the four
// sys_admin_* rows under the system arm, and the organization template's nine
// rows under the template arm (#4253). A change to either set is a change to
// what /api/request enforces, so it moves here deliberately. The planted rows
// prove the split reads the column: a derivation that could not see the reason
// would report an empty population, and the real sets would then fail as
// missing rather than pass as absent.
func TestTheRetiredTierPassPopulationIsDerivedAndHeld(t *testing.T) {
	planted := []registry.CensusRow{
		{PolicyID: "planted_system", Tier: "system", DispositionReasons: []string{"no_stored_action_for_phase", string(ReasonRetiredTierPassAction)}},
		{PolicyID: "planted_template", Tier: "tenant", DispositionReasons: []string{string(ReasonRetiredTierPassAction)}},
		{PolicyID: "planted_neither", Tier: "system", DispositionReasons: []string{"no_stored_action_for_phase"}},
	}
	if system, template := retiredTierPassPopulation(planted); !reflect.DeepEqual(system, []string{"planted_system"}) || !reflect.DeepEqual(template, []string{"planted_template"}) {
		t.Fatalf("the planted rows split as system %v, template %v; want one per arm, and none for the row without the reason", system, template)
	}

	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	system, template := retiredTierPassPopulation(rows)
	wantSystem := []string{"sys_admin_audit_log", "sys_admin_config_table", "sys_admin_info_schema", "sys_admin_users_table"}
	wantTemplate := []string{
		"drop_table_prevention", "eu_gdpr_credit_card_detection", "eu_gdpr_cross_border_pii", "eu_gdpr_loyalty_number_detection",
		"eu_gdpr_passport_detection", "pii_ssn_detection", "sql_injection_or", "sql_injection_union", "truncate_prevention",
	}
	if !reflect.DeepEqual(system, wantSystem) {
		t.Errorf("the system arm holds %v; want the four sys_admin_* rows %v", system, wantSystem)
	}
	if !reflect.DeepEqual(template, wantTemplate) {
		t.Errorf("the template arm holds %v; want the template's nine rows %v", template, wantTemplate)
	}
}

// TestTheRetiredTierPassRuleIsNotADefectReason: the rule reproduces what the
// retired pass read, so a row it fires on is not preserved_defect for it.
// Counting it as a defect would re-file thirteen faithfully kept controls as
// legacy defects.
func TestTheRetiredTierPassRuleIsNotADefectReason(t *testing.T) {
	if _, isDefect := IsDefectReason(ReasonRetiredTierPassAction); isDefect {
		t.Fatal("retired_tier_pass_action is a defect reason; it is a fidelity rule")
	}
	if IsCompilerGapReason(ReasonRetiredTierPassAction) {
		t.Fatal("retired_tier_pass_action is a compiler-gap reason; the compiler expresses the row")
	}
}

// TestADisplacementNamesTheActionThisPlaneWouldEnforce: an organization's
// category action displaces what a plane would otherwise enforce, and the
// reason names that action. On proxy_request it is the kept stored block (the
// system arm); on decide, a plane without the arm, it is the phase resolution.
// The two differ in exactly one fact, the arm (#4253, R3 round 2).
func TestADisplacementNamesTheActionThisPlaneWouldEnforce(t *testing.T) {
	adminShape := map[string]any{
		"category": "security-admin", "action": "block", "action_request": nil, "action_response": nil,
	}
	opts := testOptions()
	opts.CategoryActions = CategoryActions{"security-admin": LegacyAction("log")}
	rep, err := Compile([]RawRow{staticRow(t, "sys_admin_displaced", adminShape)}, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_admin_displaced")
	displacement := func(p Plane) (string, string) {
		t.Helper()
		for _, pr := range rec.Planes {
			if pr.Plane != p || pr.Phase != PhaseRequest {
				continue
			}
			for _, r := range pr.Reasons {
				if r.Code == ReasonOrgOverrideDisplaces {
					return pr.ResolvedAction, r.Detail
				}
			}
			t.Fatalf("%s carries no displacement reason, so nothing was asserted", p)
		}
		t.Fatalf("%s produced no request-phase result, so nothing was asserted", p)
		return "", ""
	}
	if _, detail := displacement(PlaneProxyRequest); !strings.Contains(detail, `displaces the enforced action "block" with "log"`) {
		t.Fatalf("proxy_request's displacement reads %q; want it to name the kept stored block it displaced", detail)
	}
	decideResolved, detail := displacement(PlaneDecide)
	if decideResolved == string(ActionBlock) {
		t.Fatalf("decide resolves %q; the CONTROL needs a phase resolution other than the stored block", decideResolved)
	}
	if want := `displaces the enforced action "` + decideResolved + `" with "log"`; !strings.Contains(detail, want) {
		t.Fatalf("decide's displacement reads %q; want %q, its phase resolution", detail, want)
	}
}
