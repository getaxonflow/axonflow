// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEveryRowProducesExactlyOneRecord is the zero-silent-drops property, and
// it is asserted over the whole spectrum of rows that can go wrong rather than
// over a happy path: a good row, a soft-deleted row, a disabled row, a row
// with an uncompilable regex, a row with a NULL in a non-nullable scan
// destination, a row whose JSONB will not parse, a row whose capture failed,
// and a row missing columns.
//
// This is the #3397 class stated as an invariant. Every one of those inputs is
// a row a legacy reader silently eats, and a migration tool that ate them too
// would produce a clean-looking report of a policy set nobody is enforcing.
func TestEveryRowProducesExactlyOneRecord(t *testing.T) {
	rows := []RawRow{
		staticRow(t, "sys_ok", nil),
		staticRow(t, "sys_deleted", map[string]any{"deleted_at": "2026-02-02T00:00:00Z"}),
		staticRow(t, "sys_disabled", map[string]any{"enabled": false}),
		staticRow(t, "sys_badregex", map[string]any{"pattern": "("}),
		staticRow(t, "sys_nulltier", map[string]any{"tier": nil}),
		staticRow(t, "sys_nullpriority", map[string]any{"priority": nil}),
		dynamicRow(t, "dyn_ok", nil),
		dynamicRow(t, "dyn_badjson", map[string]any{"conditions": "not-an-array"}),
		dynamicRow(t, "dyn_emptyconds", map[string]any{"conditions": []any{}}),
		{Table: "static_policies", OrgScope: "global", CaptureError: "connection reset during capture"},
		{Table: "static_policies", OrgScope: "global", Columns: map[string]json.RawMessage{"id": col(t, "x")}},
		{Table: "not_a_policy_table", OrgScope: "global", Columns: map[string]json.RawMessage{}},
	}
	rep, err := Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(rep.Records) != len(rows) {
		t.Fatalf("got %d records for %d rows; every row must produce exactly one", len(rep.Records), len(rows))
	}
	if rep.InputRows != len(rows) {
		t.Fatalf("InputRows = %d, want %d", rep.InputRows, len(rows))
	}
	// Reconciliation against an independently obtained count is the half the
	// compiler cannot check on its own.
	if err := rep.Reconcile(map[string]int{"static_policies": 8, "dynamic_policies": 3, "not_a_policy_table": 1}); err != nil {
		t.Fatalf("Reconcile against the true row counts: %v", err)
	}
	if err := rep.Reconcile(map[string]int{"static_policies": 9, "dynamic_policies": 3, "not_a_policy_table": 1}); err == nil {
		t.Fatal("Reconcile accepted a database count that disagrees with the record count; a reconciliation that cannot fail is not one")
	}
}

// TestStatusIsDerivedNotAsserted checks each status arm on a row that provokes
// it, so a refactor that stopped setting a status somewhere shows up as the
// wrong bucket rather than as a silently absent one.
func TestStatusIsDerivedNotAsserted(t *testing.T) {
	cases := []struct {
		name string
		row  RawRow
		want Status
	}{
		{"a soft-deleted row compiles to nothing", staticRow(t, "sys_del", map[string]any{"deleted_at": "2026-02-02T00:00:00Z"}), StatusUncompilable},
		{"a disabled row compiles to nothing", staticRow(t, "sys_dis", map[string]any{"enabled": false}), StatusUncompilable},
		{"an uncompilable regex is a preserved #3397 drop", staticRow(t, "sys_re", map[string]any{"pattern": "("}), StatusPreservedDefect},
		{"a NULL tier is a preserved #3397 scan drop", staticRow(t, "sys_nt", map[string]any{"tier": nil}), StatusPreservedDefect},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Compile([]RawRow{tc.row}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if got := rep.Records[0].Status; got != tc.want {
				t.Fatalf("status = %q, want %q (reasons: %+v)", got, tc.want, rep.Records[0].Reasons)
			}
		})
	}
}

// TestCategoryActionsArePerPlane pins the plane an organization override does not
// reach: cowork_ingest builds its own map and coerces redact (ForcedAction). A
// global translation would be wrong for exactly that plane.
func TestCategoryActionsArePerPlane(t *testing.T) {
	opts := testOptions()
	opts.CategoryActions = CategoryActions{"pii-us": ActionWarn}
	row := staticRow(t, "sys_pii", map[string]any{
		"category": "pii-us", "action": "block", "action_request": "block", "action_response": "block",
	})
	rep, err := Compile([]RawRow{row}, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_pii")

	sawDisplaced, sawUndisplaced := false, false
	for _, pr := range rec.Planes {
		spec := MustSpecFor(pr.Plane)
		displaced, coerced := false, false
		for _, r := range pr.Reasons {
			switch r.Code {
			case ReasonOrgOverrideDisplaces:
				displaced = true
			case ReasonPlaneCoercesAction:
				coerced = true
			}
		}
		_, forces := spec.Forces("pii-us")
		if spec.PassesOrgOverrides && displaced {
			sawDisplaced = true
		}
		// The two reasons are different facts (#3961): an organization override
		// is recorded only where the plane passes the override map, and a
		// plane's own coercion is recorded under its own code.
		if !spec.PassesOrgOverrides && displaced {
			t.Fatalf("plane %q passes no override map, but the compiler recorded an organization-override displacement", pr.Plane)
		}
		if forces && !coerced {
			t.Fatalf("plane %q coerces an action for pii-us and the compiler did not record the coercion", pr.Plane)
		}
		if !forces && coerced {
			t.Fatalf("plane %q coerces nothing, but the compiler recorded a plane coercion", pr.Plane)
		}
		if pr.Plane == PlaneCoworkIngest {
			sawUndisplaced = true
			if displaced {
				t.Fatal("the cowork ingest plane passes its own map, never the organization's overrides; its action must not be displaced")
			}
		}
	}
	if !sawDisplaced {
		t.Fatal("no override-passing plane recorded a displacement; the category actions would then be untested")
	}
	if !sawUndisplaced {
		t.Fatal("the cowork ingest plane produced no result, so the negative half of this test asserted nothing")
	}
}

// TestCategoryFallbackIsRecorded proves a NULL phase column produces the
// category fallback AND says so. The action an operator reads off the row is
// not the action that runs, and a migration that did not report that would be
// hiding the most surprising fact in the substrate.
func TestCategoryFallbackIsRecorded(t *testing.T) {
	row := staticRow(t, "sys_nullphaseact", map[string]any{
		"category": "admin-access", "severity": "low",
		"action_request": nil, "action_response": nil, "action": "block",
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_nullphaseact")
	if !rec.HasReason(ReasonNoStoredActionForPhase) {
		t.Fatal("a NULL phase column resolved through the category fallback with no reason recorded")
	}
	for _, pr := range rec.Planes {
		if pr.ReadPath != ReadPathRuntimePhase {
			continue
		}
		retired := false
		for _, r := range pr.Reasons {
			retired = retired || r.Code == ReasonRetiredTierPassAction
		}
		if retired {
			// proxy_request keeps the retired pass's read of the stored column
			// (#4253), and the category fallback stays stated in that reason.
			continue
		}
		if pr.ResolvedAction != string(ActionWarn) {
			t.Fatalf("admin-access with NULL phase columns resolved %q on %s, want warn", pr.ResolvedAction, pr.Plane)
		}
	}
}

// TestContextFallthroughFieldsCompileLive is #3515 stated correctly. The three
// fields the policy editor offers and the resolver has no explicit case for
// resolve through getFieldValue's default arm - a direct req.Context[field]
// lookup over caller-forwarded context - so a condition over one CAN fire, for
// exactly the requests whose caller supplies the key. The first version of
// this compiler asserted the opposite ("the gateway populates no context key
// of that name"), refused `connector equals X` as never-firing, and cleared it
// out of the coverage denominator: a caller-triggerable block the diff could
// not see. This test is the mutation tripwire for that refusal.
func TestContextFallthroughFieldsCompileLive(t *testing.T) {
	got := ContextOnlyUIFields()
	want := map[string]bool{"connector": true, "response": true, "user.department": true}
	if len(got) != len(want) {
		t.Fatalf("ContextOnlyUIFields() = %v; the editor offers %d fields and the resolver has cases for seven of them", got, len(uiOfferedFields))
	}
	for _, f := range got {
		if !want[f] {
			t.Fatalf("unexpected context-fallthrough field %q", f)
		}
	}

	// The R3's probe row: `connector equals salesforce -> block`. Production
	// blocks any request whose forwarded context carries connector=salesforce,
	// so the row must compile to a LIVE constraint, carry the #3515 reason
	// with the true predicate, and keep its resolved action so it stays in the
	// coverage denominator.
	row := dynamicRow(t, "dyn_connector_block", map[string]any{
		"conditions": []map[string]any{{"field": "connector", "operator": "equals", "value": "salesforce"}},
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "dyn_connector_block")
	if !rec.HasReason(ReasonLegacyDeadConditionField) {
		t.Fatal("a condition over connector recorded no #3515 reason; the caller-suppliable provenance would be invisible")
	}
	detail := reasonDetail(rec, ReasonLegacyDeadConditionField)
	if !strings.Contains(detail, "req.Context") || !strings.Contains(detail, "caller") {
		t.Fatalf("the #3515 reason does not state the true predicate (context fallthrough, caller-suppliable): %q", detail)
	}
	if strings.Contains(detail, "never") || strings.Contains(detail, "populates no context key") {
		t.Fatalf("the #3515 reason still asserts the refuted never-fires predicate: %q", detail)
	}
	if rec.PolicyCount() == 0 {
		t.Fatal("`connector equals X -> block` compiled to nothing; the running system blocks on it and the diff would read the hole as a match")
	}
	for _, p := range PlanesFor(SubstrateDynamic) {
		if !rec.ContributesTo(p) {
			t.Fatalf("the row does not contribute on plane %q; it would drop out of the coverage denominator as unmeasurable", p)
		}
	}
	// The compiled condition must read the SAME path the spelling
	// "context.connector" maps to, because both read req.Context["connector"]
	// in production.
	wantPath := Options{}.AttributePathFor("context.connector")
	found := false
	for _, pr := range rec.Planes {
		for _, pol := range pr.Policies {
			for _, path := range pol.Where.Paths() {
				if path == wantPath {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("no compiled policy reads %q; the two spellings of one context key would compile to two disagreeing paths", wantPath)
	}
}

// TestContentOperatorsCompileAsDetectors proves the four content operators
// compile to a per-row detector reference rather than either of the two wrong
// treatments: a typed string comparison over the raw field (an approximation
// that means something the author did not write) or an outright refusal (which
// left every content-conditioned row enforced in production and absent from
// the compiled set - the unexplained fail-open population the real capture's
// gate run surfaced).
func TestContentOperatorsCompileAsDetectors(t *testing.T) {
	for _, op := range []string{"contains", "not_contains", "contains_any", "regex"} {
		t.Run(op, func(t *testing.T) {
			row := dynamicRow(t, "dyn_"+op, map[string]any{
				"conditions": []map[string]any{{"field": "query", "operator": op, "value": "secret"}},
			})
			rep, err := Compile([]RawRow{row}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := recordFor(t, rep, "dyn_"+op)
			if !rec.HasReason(ReasonPatternNotTypedCondition) {
				t.Fatalf("operator %q compiled without the detector-compilation reason", op)
			}
			if rec.HasReason(ReasonUnsupportedConditionOperator) {
				t.Fatalf("operator %q was ALSO reported unsupported; one condition must land in exactly one bucket", op)
			}
			if rec.PolicyCount() == 0 {
				t.Fatalf("operator %q compiled to nothing; the row is enforced in production and the diff would go blind on it", op)
			}
			wantPath := DynamicContentDetectorPath("dyn_" + op)
			for _, pr := range rec.Planes {
				for _, pol := range pr.Policies {
					paths := pol.Where.Paths()
					sawDetector := false
					for _, path := range paths {
						if path == wantPath {
							sawDetector = true
						}
						// The raw field must NOT be read by the compiled
						// condition: that would be the approximation.
						if path == (Options{}).AttributePathFor("query") {
							t.Fatalf("the compiled policy reads args.query directly for a content operator; that is an approximation, not a detector")
						}
					}
					if !sawDetector {
						t.Fatalf("policy %q does not read detector path %q", pol.ID, wantPath)
					}
				}
			}
		})
	}

	// An operator the legacy evaluator does not implement stays REFUSED: it is
	// not content inspection, and the refusal arm must survive the detector
	// change or a typo'd operator would silently compile.
	row := dynamicRow(t, "dyn_unknown_op", map[string]any{
		"conditions": []map[string]any{{"field": "query", "operator": "matches_glob", "value": "*"}},
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "dyn_unknown_op")
	if !rec.HasReason(ReasonUnsupportedConditionOperator) || rec.PolicyCount() != 0 {
		t.Fatalf("an unimplemented operator compiled (policies=%d, unsupported=%t); the refusal arm is gone",
			rec.PolicyCount(), rec.HasReason(ReasonUnsupportedConditionOperator))
	}
}

// TestRequireApprovalWithoutAPoolIsUncompilable proves the compiler refuses to
// invent an approver set. Inventing one would be a fabricated semantic that
// the shadow diff would then report as agreement.
func TestRequireApprovalWithoutAPoolIsUncompilable(t *testing.T) {
	// A category NO plane coerces, so "no policy was emitted" is a statement
	// about the missing approver pool and not about the cowork plane's forced
	// redact quietly compiling the row into something else.
	row := staticRow(t, "sys_hitl", map[string]any{
		"category": "admin-access",
		"action":   "require_approval", "action_request": "require_approval", "action_response": "require_approval",
	})
	rep, err := Compile([]RawRow{row}, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_hitl")
	if !rec.HasReason(ReasonApprovalPoolNotStored) {
		t.Fatal("require_approval compiled with no pool and no reason recorded")
	}
	if rec.PolicyCount() != 0 {
		t.Fatal("an approval obligation was emitted with an invented pool")
	}

	// With a pool supplied it compiles, which is what makes the refusal above
	// a refusal rather than a missing feature.
	rep2, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if recordFor(t, rep2, "sys_hitl").PolicyCount() == 0 {
		t.Fatal("require_approval did not compile even with an approval pool supplied")
	}
}

// TestInertDynamicActionIsPreserved proves an action type with no arm in the
// orchestrator's switch stays inert. Migration 036's downgraded
// sys_dyn_high_risk_block sat in exactly this state, believed to be warning
// and applying nothing.
func TestInertDynamicActionIsPreserved(t *testing.T) {
	row := dynamicRow(t, "dyn_inert", map[string]any{
		"actions": []map[string]any{{"type": "quarantine", "config": map[string]any{}}},
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "dyn_inert")
	if !rec.HasReason(ReasonInertLegacyAction) {
		t.Fatal("an unknown dynamic action type compiled without an inert-action reason")
	}
	if rec.PolicyCount() != 0 {
		t.Fatal("an action type the engine has no arm for compiled to a live policy")
	}
}

// TestCompiledPolicyIsTraceableToItsSourceRow is #3563's lossless-traceability
// acceptance criterion.
func TestCompiledPolicyIsTraceableToItsSourceRow(t *testing.T) {
	rep, err := Compile([]RawRow{staticRow(t, "sys_trace", nil)}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_trace")
	if rec.Source.RowDigest == "" || rec.Source.RowDigest == "sha256:undigestible" {
		t.Fatalf("row digest is %q; a compiled policy must be traceable to a row VERSION, not just to a row", rec.Source.RowDigest)
	}
	if rec.Source.Version != 1 {
		t.Fatalf("source version = %d, want the row's version column", rec.Source.Version)
	}
	found := false
	for _, pr := range rec.Planes {
		for _, p := range pr.Policies {
			// The id embeds the SANITISED policy id, because policy_id can
			// contain the separator this format splits on.
			if !strings.Contains(p.ID, SanitizePolicyID("sys_trace")) || !strings.Contains(p.ID, string(pr.Plane)) {
				t.Fatalf("policy id %q does not carry its source row and plane", p.ID)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no policies were emitted, so traceability asserted nothing")
	}
}

func reasonDetail(rec Record, code ReasonCode) string {
	for _, r := range rec.Reasons {
		if r.Code == code {
			return r.Detail
		}
	}
	for _, pr := range rec.Planes {
		for _, r := range pr.Reasons {
			if r.Code == code {
				return r.Detail
			}
		}
	}
	return ""
}

// TestOneStaticReadPath: since #4253 every static plane reads the runtime phase
// columns. The stored action column's second read path went with the proxy_tier
// plane, and its one remaining effect on a verdict is
// PlaneSpec.EnforcesRetiredTierPassRead, which acts on the runtime path's result.
func TestOneStaticReadPath(t *testing.T) {
	row := staticRow(t, "sys_one_path", map[string]any{
		"action": "allow", "action_request": "block", "action_response": "block",
	})
	rep, err := Compile([]RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_one_path")
	if len(rec.Planes) == 0 {
		t.Fatal("a static row compiled on no plane, so the read-path check asserted nothing")
	}
	for _, pr := range rec.Planes {
		if pr.ReadPath != ReadPathRuntimePhase {
			t.Errorf("plane %q read %q; the runtime phase columns are the one static read path", pr.Plane, pr.ReadPath)
		}
	}
	for _, p := range PlanesFor(SubstrateStatic) {
		if spec := MustSpecFor(p); spec.StaticReadPath != ReadPathRuntimePhase {
			t.Errorf("plane %q declares read path %q", p, spec.StaticReadPath)
		}
	}
}

// TestANullVersionDropsNothing: the runtime read path never selects version, so
// a NULL there drops the row on no plane. Before #4253 it dropped the row on the
// retired effective path, whose scan destination was an int.
func TestANullVersionDropsNothing(t *testing.T) {
	rep, err := Compile([]RawRow{staticRow(t, "sys_nullversion", map[string]any{"version": nil})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_nullversion")
	if len(rec.Planes) == 0 {
		t.Fatal("the row compiled on no plane, so the absence of a drop asserted nothing")
	}
	for _, pr := range rec.Planes {
		for _, r := range pr.Reasons {
			if r.Code == ReasonLegacyScanDrop {
				t.Fatalf("plane %q dropped the row for a NULL version; no remaining read path selects it: %s", pr.Plane, r.Detail)
			}
		}
	}
}
