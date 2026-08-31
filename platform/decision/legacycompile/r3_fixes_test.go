package legacycompile

import (
	"strings"
	"testing"
)

// TestEffectiveScanModelsBothTimestamps pins the two columns easiest to miss
// in EffectivePolicyRow.
//
// created_at and updated_at scan into `time.Time`, not `sql.NullTime`, and both
// are DEFAULTed-but-NULLable in migrations/core/010. Omitting them from the
// effective read path's scan model made the compiler emit an ADR-065
// constraint on the proxy tier for a row GetEffective never returns: a deny
// with no legacy counterpart, on the one plane an operator is least likely to
// check.
func TestEffectiveScanModelsBothTimestamps(t *testing.T) {
	for _, col := range []string{"created_at", "updated_at"} {
		t.Run("NULL "+col, func(t *testing.T) {
			rep, err := Compile([]RawRow{staticRow(t, "sys_ts", map[string]any{col: nil})}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := recordFor(t, rep, "sys_ts")
			for _, pr := range rec.Planes {
				if pr.ReadPath != ReadPathEffectiveAction {
					continue
				}
				dropped := false
				for _, r := range pr.Reasons {
					if r.Code == ReasonLegacyScanDrop && strings.Contains(r.Detail, col) {
						dropped = true
					}
				}
				if !dropped {
					t.Fatalf("a NULL %s did not drop the row on the effective read path; the compiler would emit policy GetEffective never returns", col)
				}
				if len(pr.Policies) > 0 {
					t.Fatalf("the proxy tier emitted %d policy(ies) for a row its own scan drops", len(pr.Policies))
				}
			}
		})
	}
}

// TestAnInexpressibleRowIsFiledAsAMigrationGap pins the distinction the status
// vocabulary must keep: a row the typed language cannot express may be
// enforcing in production RIGHT NOW, so it is filed uncompilable (the gap a
// reader sizing the backlog needs), while KEEPING its resolved action so the
// coverage denominator and the legacy side of the diff still carry it. The
// reachable inexpressible shapes after the detector change are an operator the
// legacy evaluator does not implement and an in/not_in over a non-list value.
func TestAnInexpressibleRowIsFiledAsAMigrationGap(t *testing.T) {
	gap := dynamicRow(t, "dyn_gap", map[string]any{
		"conditions": []map[string]any{
			// matchInList over a non-list value: `not_in` ALWAYS fires in
			// production, and the compiler refuses to normalise the shape.
			{"field": "user.role", "operator": "not_in", "value": "not-a-list"},
		},
	})
	rep, err := Compile([]RawRow{gap}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	g := recordFor(t, rep, "dyn_gap")
	if !g.HasReason(ReasonUnsupportedConditionOperator) {
		t.Fatal("a row with no typed equivalent was not filed as a migration gap")
	}
	if g.Status != StatusUncompilable {
		t.Fatalf("a compiler gap with zero policies has status %q, want uncompilable; filing it as preserved_defect reports the row as faithfully reproduced and leaves CountsByStatus claiming the backlog is empty", g.Status)
	}
	// The gap must stay in the diff: the legacy engine enforces the row, so
	// its resolved action has to survive the refusal or the two sides agree by
	// both being silent.
	for _, p := range PlanesFor(SubstrateDynamic) {
		if !g.ContributesTo(p) {
			t.Fatalf("the inexpressible row does not contribute on plane %q; a cutover fail-open there would read as a match", p)
		}
	}
}

// TestEveryConditionIsExaminedRegardlessOfOrder pins that reasons are
// collected for every condition. Returning early made the recorded reason set
// depend on the order the operator happened to author the conditions in, so a
// census of "which operators block compilation" undercounted whenever the
// blocking condition came second.
func TestEveryConditionIsExaminedRegardlessOfOrder(t *testing.T) {
	dead := map[string]any{"field": "user.department", "operator": "equals", "value": "compliance"}
	unsup := map[string]any{"field": "query", "operator": "in", "value": "not-a-list"}

	reasonsOf := func(t *testing.T, id string, conds []map[string]any) map[ReasonCode]bool {
		t.Helper()
		rep, err := Compile([]RawRow{dynamicRow(t, id, map[string]any{"conditions": conds})}, testOptions())
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		out := map[ReasonCode]bool{}
		rec := recordFor(t, rep, id)
		for _, r := range rec.Reasons {
			out[r.Code] = true
		}
		return out
	}
	deadFirst := reasonsOf(t, "dyn_dead_first", []map[string]any{dead, unsup})
	unsupFirst := reasonsOf(t, "dyn_unsup_first", []map[string]any{unsup, dead})

	for _, code := range []ReasonCode{ReasonLegacyDeadConditionField, ReasonUnsupportedConditionOperator} {
		if !deadFirst[code] || !unsupFirst[code] {
			t.Fatalf("reason %q present in dead-first=%t unsup-first=%t; the recorded reasons depend on authoring order",
				code, deadFirst[code], unsupFirst[code])
		}
	}
}

// TestReadPathDivergenceReportsAnEmptySide pins that "one path enforces this
// row and the other does not reach it at all" is the MOST divergent a row can
// be, not agreement. Treating an empty side as agreement made the package's
// self-described central finding fail closed to silence.
//
// The reachable trigger is a column the EFFECTIVE path scans and the runtime
// path does not select: version, updated_at, or action. The mirror direction -
// runtime empty, effective resolving - is NOT reachable, because every column
// the runtime scan can drop is also in the effective scan; that asymmetry is
// itself worth knowing, and asserting the reachable direction is what this
// test can honestly do.
func TestReadPathDivergenceReportsAnEmptySide(t *testing.T) {
	for _, col := range []string{"version", "updated_at"} {
		t.Run("NULL "+col, func(t *testing.T) {
			rep, err := Compile([]RawRow{staticRow(t, "sys_eff_dropped", map[string]any{col: nil})}, testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := recordFor(t, rep, "sys_eff_dropped")
			if !rec.HasReason(ReasonReadPathActionDivergence) {
				t.Fatalf("a NULL %s drops the row on the effective path while the runtime path still enforces it, and the record reported read-path agreement; reasons: %+v", col, rec.Reasons)
			}
		})
	}

	// The negative direction: a row that drops on BOTH paths enforces nothing
	// anywhere, and reporting divergence there would make the reason true of
	// every broken row.
	rep, err := Compile([]RawRow{staticRow(t, "sys_both_dropped", map[string]any{"tier": nil})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if recordFor(t, rep, "sys_both_dropped").HasReason(ReasonReadPathActionDivergence) {
		t.Fatal("a row dropped on both read paths was reported as divergent; there is no divergence when neither path reaches it")
	}
}

// TestPhaseExcludedPlanesCarryAReason pins that a plane a row's phase excludes
// produces a RESULT saying so rather than silence. PlaneResult's contract is
// "empty means the row contributes nothing here, and Reasons says why", and a
// plane simply absent from the record cannot carry a reason - so a reader
// cannot tell "not applicable by phase" from "not modelled".
func TestPhaseExcludedPlanesCarryAReason(t *testing.T) {
	rep, err := Compile([]RawRow{staticRow(t, "sys_req_only", map[string]any{"phase": "request"})}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	rec := recordFor(t, rep, "sys_req_only")
	seen := map[Plane]bool{}
	for _, pr := range rec.Planes {
		seen[pr.Plane] = true
	}
	for _, p := range PlanesFor(SubstrateStatic) {
		if !seen[p] {
			t.Fatalf("plane %q produced no result at all for a request-phase row; absence carries no reason", p)
		}
	}
	// And a response-only plane must say WHY it contributes nothing.
	for _, pr := range rec.Planes {
		if pr.Plane != PlaneOrchestratorResponse {
			continue
		}
		if len(pr.Policies) > 0 {
			t.Fatal("a request-phase row compiled a policy on a response-only plane")
		}
		if len(pr.Reasons) == 0 {
			t.Fatal("the response-only plane produced an empty result with no reason")
		}
	}
}

// TestUIFieldListMatchesTheConstant pins the transcription
// ContextOnlyUIFields() derives from.
//
// The first version of uiOfferedFields was wrong on six of ten entries and the
// derived gap still returned the right three, because all six mistakes
// happened to have resolver cases - a derivation producing the right answer
// from the wrong inputs. Asserting the answer would not have caught it; this
// asserts the inputs.
func TestUIFieldListMatchesTheConstant(t *testing.T) {
	// Transcribed from ee/platform/customer-portal-ui/lib/api.ts POLICY_FIELDS,
	// in source order.
	want := []string{
		"query", "response", "user.email", "user.role", "user.department",
		"user.tenant_id", "risk_score", "request_type", "connector", "cost_estimate",
	}
	if len(uiOfferedFields) != len(want) {
		t.Fatalf("uiOfferedFields has %d entries, POLICY_FIELDS has %d", len(uiOfferedFields), len(want))
	}
	for i := range want {
		if uiOfferedFields[i] != want[i] {
			t.Fatalf("uiOfferedFields[%d] = %q, POLICY_FIELDS[%d] = %q", i, uiOfferedFields[i], i, want[i])
		}
	}
	gap := ContextOnlyUIFields()
	if len(gap) != 3 {
		t.Fatalf("ContextOnlyUIFields() = %v; #3515 names three", gap)
	}
	for _, f := range []string{"connector", "response", "user.department"} {
		found := false
		for _, d := range gap {
			if d == f {
				found = true
			}
		}
		if !found {
			t.Fatalf("ContextOnlyUIFields() = %v, missing %q", gap, f)
		}
	}
}

// TestPlaneModelCoversEveryStaticEvaluationSurface pins the two planes the
// first version of the model got wrong, because a plane missing from
// planeSpecs is a plane whose rows are never compiled, never diffed and never
// counted - and AllPlanes is the gate's denominator.
func TestPlaneModelCoversEveryStaticEvaluationSurface(t *testing.T) {
	// MAP reaches the DYNAMIC engine only, through map_hitl_adapter. An
	// earlier version of this model gave it a static substrate on the strength
	// of a stale doc comment in the orchestrator's response processor, whose
	// one caller is processRequestHandler.
	mapSpec := MustSpecFor(PlaneMAP)
	for _, sub := range mapSpec.Substrates {
		if sub == SubstrateStatic {
			t.Fatal("the MAP plane claims the static substrate; its only evaluation call site is EvaluateDynamicPolicies in map_hitl_adapter")
		}
	}
	// /decide passes runDynamicPolicy=false.
	for _, sub := range MustSpecFor(PlaneDecide).Substrates {
		if sub == SubstrateDynamic {
			t.Fatal("the decide plane claims the dynamic substrate; evaluateInputPolicies is called with runDynamicPolicy=false")
		}
	}
	// A plane ADR-065 names but the tree does not implement must be RECORDED,
	// not modelled and not omitted.
	if _, recorded := UnimplementedPlanes["connector_execution"]; !recorded {
		t.Fatal("connector_execution has no evaluation call site in the tree and is not recorded as unimplemented; it would be either invented coverage or an invisible gap")
	}
	if _, modelled := planeSpecs["connector_execution"]; modelled {
		t.Fatal("connector_execution is modelled as a plane despite having no evaluation call site; it would read as coverage of something that does not exist")
	}
	// The cowork ingest plane coerces redact for PII regardless of posture.
	cowork := MustSpecFor(PlaneCoworkIngest)
	if cowork.PostureLever {
		t.Fatal("the cowork ingest plane builds its own override map and never sees the deployment posture")
	}
	if got, does := cowork.Forces("pii-us"); !does || got != ActionRedact {
		t.Fatalf("the cowork plane forces %q for pii-us (does=%t), want redact", got, does)
	}
	if _, does := cowork.Forces("admin-access"); does {
		t.Fatal("the cowork plane's override map is scoped to enabled PII categories; a non-PII row keeps its resolved action")
	}
}

// TestTablesContainOnlyDeclaredCategories is the seen-subset-declared
// direction of the pin. Without it a MISSPELLED category sits in the table
// forever, pinning nothing, and on the lever table it also inflates the
// unlevered count that the anti-vacuity check reads.
func TestTablesContainOnlyDeclaredCategories(t *testing.T) {
	// The one deliberate non-enum row, named so a reader can tell a sentinel
	// from a typo. It exists to pin the fallback for a category the enum does
	// not declare, which is reachable: `category` is a VARCHAR with no CHECK.
	const sentinel = "an-unregistered-category"

	declared := map[string]bool{}
	for _, r := range readTSV(t, "legacy_posture_levers.tsv", []string{"category", "posture_lever"}) {
		declared[r["category"]] = true
	}
	res := readTSV(t, "legacy_resolution.tsv", []string{"category", "severity", "phase", "stored_action", "resolved_action"})
	resCats := map[string]bool{}
	for _, r := range res {
		resCats[r["category"]] = true
	}
	for c := range resCats {
		if !declared[c] {
			t.Fatalf("legacy_resolution.tsv carries category %q, which legacy_posture_levers.tsv does not; the two tables must cover the same population or one of them is pinning a typo", c)
		}
	}
	for c := range declared {
		if !resCats[c] {
			t.Fatalf("legacy_posture_levers.tsv carries category %q, which legacy_resolution.tsv does not", c)
		}
	}
	if !resCats[sentinel] {
		t.Fatalf("the deliberate non-enum sentinel %q is gone; the fallback for an undeclared category is then unpinned", sentinel)
	}
}
