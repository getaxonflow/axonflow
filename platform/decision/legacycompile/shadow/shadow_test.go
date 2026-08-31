package shadow

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// corpusRows is the fixture policy set. It carries one row of every shape the
// compiler has an arm for, because the gate's coverage requirement is
// per-policy-row and a corpus of one row would report full coverage of
// nothing.
func corpusRows(t *testing.T) []legacycompile.RawRow {
	t.Helper()
	return []legacycompile.RawRow{
		staticFixture(t, "sys_pii_ssn", nil),
		staticFixture(t, "sys_redact_resp", map[string]any{
			"phase": "response", "action_request": nil, "action_response": "redact",
			"action": "redact", "category": "pii-eu",
		}),
		// A response-phase PII row that resolves a NON-redact action. The
		// cowork ingest plane COERCES redact for enabled PII categories
		// regardless of the stored action, and both halves of the harness
		// must model the coercion: a row already resolving redact cannot
		// tell a model that forgot it from one that applies it.
		staticFixture(t, "sys_pii_warn_resp", map[string]any{
			"phase": "response", "action_request": nil, "action_response": "warn",
			"action": "warn", "category": "pii-us",
		}),
		staticFixture(t, "sys_hitl", map[string]any{
			"action_request": "require_approval", "action": "require_approval",
			"category": "sensitive-data",
		}),
		staticFixture(t, "sys_logonly", map[string]any{
			"action_request": "log", "action": "log", "category": "admin-access",
		}),
		// The highest-priority row is a LOG, so on the proxy tier the
		// first-match engine picks it and never reaches sys_pii_ssn's block -
		// while ADR-065 combines every matched policy and the block denies.
		// This is EC6's shape, and the corpus must reach every rule or the
		// reachability test cannot vouch for it. It also duplicates
		// sys_logonly's exact audit instruction (same category, same
		// severity), so composition MERGES the two audits on every case both
		// fire in - and an attribution that keeps one source reads the other
		// row's control as missing.
		staticFixture(t, "sys_shadowing_log", map[string]any{
			"priority": 200, "action_request": "log", "action": "log", "category": "admin-access",
		}),
		// A phase='both' row whose two phases resolve DIFFERENT actions. The
		// two-phase mcp plane must compare one phase per case: conflating them
		// hands one verdict both phases' actions, which is the exact shape the
		// real capture's gate run surfaced 62 times.
		staticFixture(t, "sys_both_phases", map[string]any{
			"phase": "both", "action_request": "log", "action_response": "warn",
			"action": "log", "category": "admin-access",
		}),
		dynamicFixture(t, "dyn_intern_block", nil),
		dynamicFixture(t, "dyn_route_eu", map[string]any{
			"conditions": []map[string]any{{"field": "user.region", "operator": "equals", "value": "eu"}},
			"actions": []map[string]any{{"type": "route", "config": map[string]any{
				"preferred_provider": "azure", "allowed_providers": []any{"azure", "bedrock"},
			}}},
		}),
		// A dynamic redact naming FIELD targets. field_redact is a disclosure
		// obligation resolved per payload leaf, so the world's leaf schema has
		// to carry the compiled targets - a fixed content-root schema left
		// every one of these unplaced and silently unapplied on a permit.
		dynamicFixture(t, "dyn_redact_fields", map[string]any{
			"conditions": []map[string]any{{"field": "user.email", "operator": "equals", "value": "pii@example.com"}},
			"actions": []map[string]any{{"type": "redact", "config": map[string]any{
				"fields": []any{"email", "ssn"},
			}}},
		}),
		// A dynamic content condition (regex), compiled as a per-row detector.
		// The pattern deliberately does NOT match its own text: the corpus has
		// to DERIVE a matching example or the fires case reaches neither
		// engine and the gate reports a corpus defect.
		dynamicFixture(t, "dyn_regex_guard", map[string]any{
			"conditions": []map[string]any{{"field": "query", "operator": "regex", "value": `tenant\s*=`}},
			"actions":    []map[string]any{{"type": "block", "config": map[string]any{"reason": "cross-tenant"}}},
		}),
	}
}

func buildRun(t *testing.T, rows []legacycompile.RawRow, opts legacycompile.Options, wopts ...WorldOption) (*legacycompile.Report, *Run) {
	t.Helper()
	rep, err := legacycompile.Compile(rows, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), opts, wopts...)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	return rep, run
}

// TestGatePassesOnAFaithfulCompilation is the green baseline, and it asserts
// the DENOMINATOR as well as the numerator. Zero unexplained differences out
// of zero comparisons is the vacuity-at-zero class, so the test pins that
// every plane ran cases and every compiled row was exercised.
func TestGatePassesOnAFaithfulCompilation(t *testing.T) {
	rows := corpusRows(t)
	rep, run := buildRun(t, rows, testOptions())

	res := Gate(run, GateOptions{RequirePlanes: legacycompile.AllPlanes()})
	if !res.Passed {
		t.Fatalf("the gate failed on a faithful compilation:\n  %s\n%s", strings.Join(res.Failures, "\n  "), res.Summary)
	}
	if len(run.Records) == 0 {
		t.Fatal("zero comparisons: the corpus proved nothing")
	}
	for _, plane := range legacycompile.AllPlanes() {
		cov, ok := run.Coverage[plane]
		if !ok {
			t.Fatalf("plane %q has no coverage entry; a plane missing from the map is a plane nobody measured", plane)
		}
		if len(rep.RowsFor(plane)) == 0 {
			continue
		}
		if cov.Cases == 0 {
			t.Fatalf("plane %q compiled rows but ran no cases", plane)
		}
		if len(cov.UnexercisedRows) > 0 {
			t.Fatalf("plane %q left rows unexercised: %v", plane, cov.UnexercisedRows)
		}
	}
	t.Logf("\n%s", res.Summary)
}

// TestPlantedSemanticChangeIsUnexplainedAndFailsTheGate is the mutation proof
// for the gate itself, in the direction that matters: a compiled constraint
// that stops denying is a control that stopped running, and the gate has to go
// red on it.
//
// The plant is applied to the COMPILED report, which is exactly where a
// compiler defect would land, and the mutant is verified to be a real change
// before the assertion - a mutation nobody applied proves nothing.
func TestPlantedSemanticChangeIsUnexplainedAndFailsTheGate(t *testing.T) {
	rows := corpusRows(t)
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	// PLANT: turn the blocking constraint compiled from sys_pii_ssn into an
	// inspection policy. It still matches, still reports, and no longer denies.
	planted := 0
	for ri := range rep.Records {
		if rep.Records[ri].Source.PolicyID != "sys_pii_ssn" {
			continue
		}
		for pi := range rep.Records[ri].Planes {
			for pj := range rep.Records[ri].Planes[pi].Policies {
				p := &rep.Records[ri].Planes[pi].Policies[pj]
				if p.Authority != contract.AuthorityConstraint {
					continue
				}
				p.Authority = contract.AuthorityInspection
				p.Obligations = []contract.Obligation{{
					Type: contract.ObImmutableAudit, SourcePolicy: p.ID, SchemaVersion: 1,
				}}
				planted++
			}
		}
	}
	if planted == 0 {
		t.Fatal("the plant changed nothing; a mutation that did not apply cannot demonstrate that the gate detects it")
	}

	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), testOptions())
	if err != nil {
		t.Fatalf("RunAll on the mutant: %v", err)
	}
	res := Gate(run, GateOptions{RequirePlanes: legacycompile.AllPlanes()})
	if res.Passed {
		t.Fatalf("the gate PASSED with a blocking constraint turned into an advisory inspection:\n%s", res.Summary)
	}
	unexplained := run.Unexplained()
	if len(unexplained) == 0 {
		t.Fatalf("the planted change produced no UNEXPLAINED record:\n%s", res.Summary)
	}
	sawDangerous := false
	for _, rec := range unexplained {
		if rec.FailOpen == FailOpenNewPermitted {
			sawDangerous = true
		}
	}
	if !sawDangerous {
		t.Fatalf("the planted change permitted where legacy denied, but no record carries the %q direction; "+
			"gate 18 is specifically about fail-open differences and the direction must be recorded, not inferred",
			FailOpenNewPermitted)
	}
}

// TestPlantedObligationChangeIsUnexplained is the second mutation direction:
// executability is unaffected and only the OBLIGATION changes. It is the case
// a gate that only compared allow/deny would sail past, and it is caught by
// the classifier's correspondence table, which is an independent statement of
// the compiler's mapping.
func TestPlantedObligationChangeIsUnexplained(t *testing.T) {
	rows := corpusRows(t)
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	planted := 0
	for ri := range rep.Records {
		if rep.Records[ri].Source.PolicyID != "sys_redact_resp" {
			continue
		}
		for pi := range rep.Records[ri].Planes {
			for pj := range rep.Records[ri].Planes[pi].Policies {
				p := &rep.Records[ri].Planes[pi].Policies[pj]
				for oi := range p.Obligations {
					if p.Obligations[oi].Type != contract.ObFieldRedact {
						continue
					}
					// A redaction quietly becomes a notification: the field is
					// no longer redacted and somebody is told about it instead.
					p.Obligations[oi] = contract.Obligation{
						Type: contract.ObNotification, Mandatory: true,
						SourcePolicy: p.ID, SchemaVersion: 1,
					}
					planted++
				}
			}
		}
	}
	if planted == 0 {
		t.Fatal("no redaction obligation was found to mutate; the fixture no longer covers the redact arm")
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), testOptions())
	if err != nil {
		t.Fatalf("RunAll on the mutant: %v", err)
	}
	res := Gate(run, GateOptions{RequirePlanes: legacycompile.AllPlanes()})
	if res.Passed {
		t.Fatalf("the gate PASSED with a redaction silently turned into a notification:\n%s", res.Summary)
	}
	found := false
	for _, rec := range run.Unexplained() {
		if strings.Contains(rec.Detail, "field_redact") && strings.Contains(rec.Detail, "notification") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the correspondence failure does not name both obligations, so a reader cannot see what changed:\n%s", res.Summary)
	}
}

// TestGateRefusesVacuity pins the denominator in all three of its shapes. Zero
// unexplained out of zero compared is the failure mode that passes forever,
// passes hardest when the corpus is broken, and passes silently.
func TestGateRefusesVacuity(t *testing.T) {
	t.Run("an empty corpus fails", func(t *testing.T) {
		res := Gate(&Run{Coverage: map[legacycompile.Plane]PlaneCoverage{}}, GateOptions{})
		if res.Passed {
			t.Fatal("the gate passed on zero comparisons")
		}
		if !strings.Contains(strings.Join(res.Failures, " "), "zero comparisons") {
			t.Fatalf("the failure does not name the vacuity: %v", res.Failures)
		}
	})

	t.Run("a plane with policy and no cases fails", func(t *testing.T) {
		run := &Run{
			Records: []DiffRecord{{CaseID: "x", Plane: legacycompile.PlaneDecide, Class: ClassMatch}},
			Coverage: map[legacycompile.Plane]PlaneCoverage{
				legacycompile.PlaneDecide: {Cases: 1, CompiledRows: []string{"a"}, ExercisedRows: []string{"a"}},
				legacycompile.PlaneMCP:    {Cases: 0, CompiledRows: []string{"a"}, UnexercisedRows: []string{"a"}},
			},
		}
		res := Gate(run, GateOptions{})
		if res.Passed {
			t.Fatal("the gate passed with a plane that compiled policy and compared nothing")
		}
	})

	t.Run("an unexercised row fails unless explicitly allowed", func(t *testing.T) {
		run := &Run{
			Records: []DiffRecord{{CaseID: "x", Plane: legacycompile.PlaneDecide, Class: ClassMatch}},
			Coverage: map[legacycompile.Plane]PlaneCoverage{
				legacycompile.PlaneDecide: {
					Cases: 1, CompiledRows: []string{"a", "b"},
					ExercisedRows: []string{"a"}, UnexercisedRows: []string{"b"},
				},
			},
		}
		if Gate(run, GateOptions{}).Passed {
			t.Fatal("the gate passed with a compiled row the corpus never reached")
		}
		if !Gate(run, GateOptions{AllowUnexercisedRows: true}).Passed {
			t.Fatal("AllowUnexercisedRows did not permit the run; the escape hatch has to work or nobody will use the gate")
		}
	})

	t.Run("a required plane with no cases fails", func(t *testing.T) {
		run := &Run{
			Records:  []DiffRecord{{CaseID: "x", Plane: legacycompile.PlaneDecide, Class: ClassMatch}},
			Coverage: map[legacycompile.Plane]PlaneCoverage{legacycompile.PlaneDecide: {Cases: 1}},
		}
		if Gate(run, GateOptions{RequirePlanes: []legacycompile.Plane{legacycompile.PlaneWCP}}).Passed {
			t.Fatal("the gate passed with a required plane that ran nothing")
		}
	})
}

// TestAPreservedDefectIsContextAndNeverAnExplanation pins the classifier's
// most important refusal.
//
// A preserved legacy defect makes the two sides behave IDENTICALLY - that is
// what "reproduce, never repair" means - so it can never be the observable
// cause of a difference. An earlier version of this classifier let one explain
// a difference anyway, and independent review showed it silencing a real
// fail-open: two rows differing only in whether action_request was NULL,
// against the same injected defect, classified UNEXPLAINED (gate red) and
// legacy_defect (gate green).
//
// The defect is now recorded as CONTEXT on the record and the difference stays
// unexplained, so a human looks at it.
func TestAPreservedDefectIsContextAndNeverAnExplanation(t *testing.T) {
	deadRow := dynamicFixture(t, "dyn_dept_block", map[string]any{
		"conditions": []map[string]any{{"field": "user.department", "operator": "not_equals", "value": "compliance"}},
	})
	rep, err := legacycompile.Compile([]legacycompile.RawRow{deadRow}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !recordFor(t, rep, "dyn_dept_block").HasReason(legacycompile.ReasonLegacyDeadConditionField) {
		t.Fatal("the fixture row carries no preserved defect, so this test would assert nothing")
	}

	in := ClassifyInput{
		Case: Case{ID: "t", Plane: legacycompile.PlaneWCP},
		Legacy: Verdict{Executable: false, State: contract.StateDeny,
			Determining: []string{RowKeyFor("dynamic_policies", "dyn_dept_block")}},
		New:    Verdict{Executable: true, State: contract.StateAllow},
		Report: rep,
	}
	got := Classify(in)
	if got.Class != ClassUnexplained {
		t.Fatalf("a difference over a row carrying a preserved defect classified %q; a preserved defect is symmetric by "+
			"construction, so it can never be the cause, and letting it explain one silences whatever really was", got.Class)
	}
	if len(got.PreservedDefects) == 0 {
		t.Fatal("the record carries no preserved-defect context; a triager needs to know a row in play is already known broken")
	}
	if !strings.Contains(strings.Join(got.PreservedDefects, " "), "#3515") {
		t.Fatalf("the context does not name the issue: %v", got.PreservedDefects)
	}
	// And the context must not appear where no participating row carries one.
	clean := ClassifyInput{
		Case:   Case{ID: "t", Plane: legacycompile.PlaneWCP},
		Legacy: Verdict{Executable: true, State: contract.StateAllow},
		New:    Verdict{Executable: false, State: contract.StateDeny},
		Report: rep,
	}
	if len(Classify(clean).PreservedDefects) != 0 {
		t.Fatal("preserved-defect context appeared on a comparison in which no row participated; it would then be true of every record and mean nothing")
	}
}

// TestLegacyDefectDoesNotAbsorbAnExpectedChange is the mis-labelling guard. A
// row can carry a preserved defect AND be involved in a difference the
// architecture caused; classifying that as legacy_defect would retire an
// expected change by renaming it.
func TestLegacyDefectDoesNotAbsorbAnExpectedChange(t *testing.T) {
	deadRow := dynamicFixture(t, "dyn_dept_block", map[string]any{
		"conditions": []map[string]any{{"field": "user.department", "operator": "not_equals", "value": "compliance"}},
	})
	rep, err := legacycompile.Compile([]legacycompile.RawRow{deadRow}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Symmetric non-participation: nothing determined the outcome on either
	// side, and the new side is Indeterminate because an attribute was unknown.
	in := ClassifyInput{
		Case:   Case{ID: "t", Plane: legacycompile.PlaneWCP},
		Legacy: Verdict{Executable: true, State: contract.StateAllow},
		New:    Verdict{Executable: false, State: contract.StateError},
		Decision: &contract.Decision{
			Authorization: contract.AuthzIndeterminate,
			Reason:        contract.ReasonUnknownConstraint,
			Determining: contract.Determining{Unknown: []contract.UnknownPolicy{{
				PolicyID: "x", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied,
			}}},
		},
		Report: rep,
	}
	got := Classify(in)
	if got.Class != ClassExpectedChange || got.RuleID != "EC2_UNKNOWN_IS_NOT_FALSE" {
		t.Fatalf("classified %q rule=%q; a defect-carrying row that did not participate must not displace an expected change", got.Class, got.RuleID)
	}
}

// TestEveryExpectedChangeRuleIsFalsifiable proves no rule's predicate is true
// of every difference. A rule that always fires is a rule that explains
// nothing while silencing everything.
func TestEveryExpectedChangeRuleIsFalsifiable(t *testing.T) {
	// A plain disagreement the architecture did not decide: legacy permits,
	// ADR-065 denies by an explicit constraint. No rule may claim it.
	plain := ClassifyInput{
		Case:   Case{ID: "t", Plane: legacycompile.PlaneDecide},
		Legacy: Verdict{Executable: true, State: contract.StateAllow},
		New:    Verdict{Executable: false, State: contract.StateDeny},
		Decision: &contract.Decision{
			Authorization: contract.AuthzDeny, Reason: contract.ReasonExplicitConstraint,
		},
	}
	for _, r := range expectedChangeRules() {
		if r.Applies(plain) {
			t.Fatalf("rule %q claims an ordinary unexplained deny; its predicate is too broad", r.ID)
		}
	}
	// And an outright agreement: no rule may fire on identical verdicts.
	same := ClassifyInput{
		Case:   Case{ID: "t", Plane: legacycompile.PlaneDecide},
		Legacy: Verdict{Executable: true, State: contract.StateAllow},
		New:    Verdict{Executable: true, State: contract.StateAllow},
	}
	for _, r := range expectedChangeRules() {
		if r.Applies(same) {
			t.Fatalf("rule %q fires on two identical verdicts", r.ID)
		}
	}
	if got := Classify(same); got.Class != ClassMatch {
		t.Fatalf("identical verdicts classified %q", got.Class)
	}
}

// TestExpectedChangeRulesAreReachable is the other direction: a rule nothing
// can reach is decorative, and a decorative rule is one nobody notices has
// stopped working.
//
// EC1 is reachable only in the no-baseline-permission mode, which is not a
// test convenience: it is ADR-065's permission-coverage report, and every case
// it lands on is a request the plane would refuse the day it cut over.
func TestExpectedChangeRulesAreReachable(t *testing.T) {
	rows := corpusRows(t)
	_, withBaseline := buildRun(t, rows, testOptions())
	_, noBaseline := buildRun(t, rows, testOptions(), WithoutBaselinePermission())

	fired := map[string]bool{}
	for _, run := range []*Run{withBaseline, noBaseline} {
		for _, rec := range run.Records {
			if rec.Class == ClassExpectedChange {
				fired[rec.RuleID] = true
			}
		}
	}
	for _, id := range ExpectedChangeRuleIDs() {
		if !fired[id] {
			t.Fatalf("expected-change rule %q was never reached by the corpus; a rule nothing exercises cannot be trusted to still work", id)
		}
	}

	// The permission-coverage claim itself: without a baseline permission,
	// EC1 must account for cases the plane would refuse at cutover.
	ec1 := 0
	for _, rec := range noBaseline.Records {
		if rec.RuleID == "EC1_DEFAULT_DENY" {
			ec1++
		}
	}
	if ec1 == 0 {
		t.Fatal("the no-baseline-permission mode reported no default-deny cases, so it is not measuring permission coverage")
	}
	t.Logf("permission coverage: %d case(s) would be refused at cutover with no permissions authored", ec1)
}

// TestCorrespondenceTableCoversEveryActionTheCompilerEmits binds the
// classifier's independent mapping to the compiler's own vocabulary. An action
// the compiler can produce and the table has never heard of would make every
// case touching it unexplained for a reason that is bookkeeping rather than
// semantics.
func TestCorrespondenceTableCoversEveryActionTheCompilerEmits(t *testing.T) {
	for _, a := range append(legacycompile.KnownActions(), legacycompile.ActionRoute, legacycompile.ActionAlert) {
		if _, ok := ExpectedObligationsFor(a); !ok {
			t.Fatalf("legacy action %q has no entry in the correspondence table, so what it should become under ADR-065 has never been decided", a)
		}
	}
	// Falsifiability: an action the table does not know must be reported, not
	// silently treated as producing nothing.
	if _, ok := ExpectedObligationsFor(legacycompile.LegacyAction("quarantine")); ok {
		t.Fatal("the correspondence table claims to know an action that does not exist")
	}
}

// TestLegacyModelRefusesARowItHasNoFactsFor pins the fail-closed direction of
// the model's own input handling. Skipping such a row would shrink the legacy
// side of every comparison and make the diff look clean.
func TestLegacyModelRefusesARowItHasNoFactsFor(t *testing.T) {
	rows := []legacycompile.RawRow{staticFixture(t, "sys_pii_ssn", nil)}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := &ModelEvaluator{Report: rep, Rows: map[string]RowFacts{}, ContentTarget: legacycompile.DefaultContentTarget}
	_, err = m.Evaluate(context.Background(), Case{ID: "t", Plane: legacycompile.PlaneDecide, Org: "global"})
	if err == nil {
		t.Fatal("the legacy model evaluated a row it has no facts for instead of refusing")
	}
	if !strings.Contains(err.Error(), "sys_pii_ssn") {
		t.Fatalf("the refusal does not name the row: %v", err)
	}
}

// TestEmptyAuthorityRootActivates pins the pdp compile fix this work needed: a
// root with no policies - an organization that has authored none, or a plane
// whose rows all compiled to nothing - must still build, sign, verify and
// activate. Before the fix the generated module imported the tri-state helper
// package unconditionally and strict compilation rejected it as unused, so an
// empty authority root failed at engine preparation with a Rego error.
func TestEmptyAuthorityRootActivates(t *testing.T) {
	// Every fixture row is system-tier, so the organization document is empty.
	rows := []legacycompile.RawRow{staticFixture(t, "sys_only", nil)}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	_, org, err := rep.Documents(legacycompile.PlaneDecide, "global")
	if err != nil {
		t.Fatalf("Documents: %v", err)
	}
	if len(org.Policies) != 0 {
		t.Fatalf("the fixture produced %d organization policies, so this test is not exercising the empty root", len(org.Policies))
	}
	if _, err := NewWorld(context.Background(), rep, legacycompile.PlaneDecide, "global"); err != nil {
		t.Fatalf("an authority root with no policies could not be activated: %v", err)
	}
}

func recordFor(t *testing.T, rep *legacycompile.Report, policyID string) legacycompile.Record {
	t.Helper()
	for _, r := range rep.Records {
		if r.Source.PolicyID == policyID {
			return r
		}
	}
	t.Fatalf("no record for %q", policyID)
	return legacycompile.Record{}
}
