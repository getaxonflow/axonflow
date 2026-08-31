package shadow

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
)

// TestUnmigratedRowProducesAnUnexplainedFailOpen is the most important
// property in this package.
//
// A dynamic row the compiler cannot express compiles to NOTHING. It is still
// enforced in production. If the legacy side of the diff also went silent on
// it, the two sides would agree by both saying nothing, the gate would report
// a match, and the plane would cut over dropping a control - the exact
// fail-open gate 18 exists to block, reported as clean.
//
// So the legacy side evaluates every row the legacy READER loads, whether or
// not it compiled, and the difference lands as UNEXPLAINED in the dangerous
// direction. The fixture is a require_approval row compiled WITHOUT an
// approval pool: ADR-065's approval obligation needs an eligible set and a
// quorum, the legacy row stores neither, and the compiler refuses to invent
// one - while the legacy engine refuses the request outright. (The earlier
// fixture used a `contains` condition, which now compiles as a detector
// reference and is no longer a gap.)
func TestUnmigratedRowProducesAnUnexplainedFailOpen(t *testing.T) {
	// No approval pools: that is the point.
	opts := legacycompile.Options{}
	rows := []legacycompile.RawRow{
		staticFixture(t, "sys_pii_ssn", nil),
		dynamicFixture(t, "dyn_unmigrated", map[string]any{
			"actions": []map[string]any{{"type": "require_approval", "config": map[string]any{"reason": "x"}}},
		}),
	}
	rep, err := legacycompile.Compile(rows, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// The row must genuinely have compiled nothing, or this test would be
	// asserting something else entirely.
	for _, rec := range rep.Records {
		if rec.Source.PolicyID == "dyn_unmigrated" && rec.PolicyCount() != 0 {
			t.Fatalf("the fixture row compiled %d policies; it is supposed to be inexpressible", rec.PolicyCount())
		}
	}

	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), opts)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	res := Gate(run, GateOptions{})
	if res.Passed {
		t.Fatalf("the gate PASSED with a row the compiler cannot express and the legacy engine enforces:\n%s", res.Summary)
	}

	var dangerous []DiffRecord
	for _, rec := range run.Unexplained() {
		if rec.FailOpen == FailOpenNewPermitted && strings.Contains(rec.CaseID, "dyn_unmigrated") {
			dangerous = append(dangerous, rec)
		}
	}
	if len(dangerous) == 0 {
		t.Fatalf("no unexplained fail-open difference was reported for the unmigrated row:\n%s", res.Summary)
	}
	// Every plane that evaluates the dynamic substrate must report it, not
	// just one: a per-plane cutover needs a per-plane answer.
	seen := map[legacycompile.Plane]bool{}
	for _, rec := range dangerous {
		seen[rec.Plane] = true
	}
	for _, p := range legacycompile.PlanesFor(legacycompile.SubstrateDynamic) {
		if !seen[p] {
			t.Fatalf("plane %q evaluates dynamic policies and did not report the unmigrated row: %v", p, seen)
		}
	}
	// And the row must be in the coverage denominator, or a later corpus
	// change could make it vanish without the gate noticing.
	for _, p := range legacycompile.PlanesFor(legacycompile.SubstrateDynamic) {
		found := false
		for _, r := range run.Coverage[p].CompiledRows {
			if r == RowKey("dynamic_policies", "dyn_unmigrated") {
				found = true
			}
		}
		if !found {
			t.Fatalf("plane %q coverage does not list the unmigrated row: %v", p, run.Coverage[p].CompiledRows)
		}
	}
}

// TestAPermanentlyAsymmetricRowExplainsNothing pins the removal of the
// legacy_defect arm.
//
// A row can be asymmetric on EVERY case - enforced by the legacy engine and
// absent from the compiled set on every request. When such a row could explain
// a difference, one vacuous-conditions row with an inert action relabelled 21
// of 43 comparisons and retired six real findings. Nothing explains a
// difference on the strength of a preserved defect any more.
func TestAPermanentlyAsymmetricRowExplainsNothing(t *testing.T) {
	defectRow := dynamicFixture(t, "dyn_always_asymmetric", map[string]any{
		"conditions": []map[string]any{{"field": "user.department", "operator": "not_equals", "value": "compliance"}},
	})
	otherRow := dynamicFixture(t, "dyn_other", nil)
	rep, err := legacycompile.Compile([]legacycompile.RawRow{defectRow, otherRow}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !recordFor(t, rep, "dyn_always_asymmetric").HasReason(legacycompile.ReasonLegacyDeadConditionField) {
		t.Fatal("the fixture carries no preserved defect, so this test would assert nothing")
	}

	for _, det := range [][]string{
		{RowKeyFor("dynamic_policies", "dyn_always_asymmetric")},
		{RowKeyFor("dynamic_policies", "dyn_always_asymmetric"), RowKeyFor("dynamic_policies", "dyn_other")},
	} {
		got := Classify(ClassifyInput{
			Case:   Case{ID: "t", Plane: legacycompile.PlaneWCP},
			Legacy: Verdict{Executable: false, State: contract.StateDeny, Determining: det},
			New:    Verdict{Executable: true, State: contract.StateAllow},
			Report: rep,
		})
		if got.Class != ClassUnexplained {
			t.Fatalf("determining=%v classified %q; a fail-open over a defect-carrying row must stay unexplained", det, got.Class)
		}
		if len(got.PreservedDefects) == 0 {
			t.Fatalf("determining=%v carries no preserved-defect context", det)
		}
	}
}

// TestAnExpectedChangeDoesNotLaunderAResidualDifference pins that a rule
// explains the dimension it is about and nothing else.
//
// Before the fix, Classify returned on the first matching predicate without
// checking the rest, so an architectural difference in the outcome could carry
// a real compiler defect in the obligation set past the gate.
func TestAnExpectedChangeDoesNotLaunderAResidualDifference(t *testing.T) {
	// EC3's shape: legacy denies with a require_approval, ADR-065 challenges.
	// Both refuse execution, so the rule applies - but an obligation from a
	// SECOND row has silently vanished on the new side.
	in := ClassifyInput{
		Case: Case{ID: "t", Plane: legacycompile.PlaneDecide},
		Legacy: Verdict{
			Executable: false, State: contract.StateDeny,
			Effects: []string{
				LegacyEffect(RowKeyFor("static_policies", "r1"), string(legacycompile.ActionRequireApproval), ""),
				LegacyEffect(RowKeyFor("static_policies", "r2"), string(legacycompile.ActionRedact), "response.content"),
			},
		},
		New: Verdict{
			Executable: false, State: contract.StateChallenge, ApprovalClauses: 1,
			// r2's redaction is gone.
			Effects: nil,
		},
	}
	got := Classify(in)
	if got.Class == ClassExpectedChange {
		t.Fatalf("rule %q explained a record whose obligation set also disagreed; an architectural change must not launder a dropped control", got.RuleID)
	}
	if got.Class != ClassUnexplained {
		t.Fatalf("classified %q, want UNEXPLAINED", got.Class)
	}
	if !strings.Contains(got.Detail, "EC3") {
		t.Fatalf("the detail does not name the rule that explained the outcome, so a reader cannot see what was and was not accounted for: %s", got.Detail)
	}

	// Positive control: the same shape with the obligation present IS an
	// expected change.
	ok := in
	ok.Legacy.Effects = []string{LegacyEffect(RowKeyFor("static_policies", "r1"), string(legacycompile.ActionRequireApproval), "")}
	if c := Classify(ok); c.Class != ClassExpectedChange || c.RuleID != "EC3_APPROVAL_IS_A_CHALLENGE_NOT_A_DENY" {
		t.Fatalf("the clean approval shape classified %q rule=%q, want EC3", c.Class, c.RuleID)
	}
}

// TestGateRefusesAReportThatCompiledNothing pins the vacuity check in the
// shape the PIPELINE can actually produce.
//
// BuildCorpus emits a baseline case per plane unconditionally, so len(Records)
// is never zero from the real entry point and the empty-corpus check alone is
// unreachable in production. A report that compiled zero rows produces ten
// synthetic baseline comparisons, every one a match, and would otherwise be a
// green gate over no policy at all.
func TestGateRefusesAReportThatCompiledNothing(t *testing.T) {
	rep, err := legacycompile.Compile(nil, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, map[string]RowFacts{}, testOptions())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(run.Records) == 0 {
		t.Fatal("the pipeline produced no comparisons at all, so this test is not exercising the reachable vacuity")
	}
	res := Gate(run, GateOptions{RequirePlanes: legacycompile.AllPlanes()})
	if res.Passed {
		t.Fatalf("the gate PASSED over a report that compiled zero policy rows, having compared %d synthetic baselines:\n%s",
			len(run.Records), res.Summary)
	}
	if !strings.Contains(strings.Join(res.Failures, " "), "zero enforced policy rows") {
		t.Fatalf("the failure does not name the vacuity: %v", res.Failures)
	}
}

// TestRowIdentityIsTableAndPolicyID pins that coverage keys on (table,
// policy_id). policy_id is unique WITHIN each table and the two tables are
// independent, so a shared id would otherwise collapse two rows into one
// coverage entry and exercising either would mark both.
func TestRowIdentityIsTableAndPolicyID(t *testing.T) {
	const shared = "shared_id"
	rows := []legacycompile.RawRow{
		staticFixture(t, shared, nil),
		dynamicFixture(t, shared, nil),
	}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), testOptions())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	// A plane that evaluates BOTH substrates, so both rows land on it.
	cov := run.Coverage[legacycompile.PlanePolicyTest]
	want := map[string]bool{
		RowKey("static_policies", shared):  true,
		RowKey("dynamic_policies", shared): true,
	}
	for _, got := range cov.CompiledRows {
		delete(want, got)
	}
	if len(want) > 0 {
		t.Fatalf("policy_test coverage lists %v; two rows sharing one policy_id collapsed into one entry", cov.CompiledRows)
	}
}

// TestObligationTargetsAndMultiplicityAreCompared pins that an effect key
// carries the target and that identical instructions are not deduplicated.
//
// Three redactions of three different fields are three instructions. Rendering
// them by type alone, or collapsing duplicates, let a compiler that redacted
// one field where the legacy row redacted three correspond cleanly.
func TestObligationTargetsAndMultiplicityAreCompared(t *testing.T) {
	src := RowKey("static_policies", "r1")
	obl := func(target string) contract.Obligation {
		return contract.Obligation{
			Type: contract.ObFieldRedact, Target: target, Mandatory: true,
			SourcePolicy: "legacy:static_policies:r1:decide:request", SchemaVersion: 1,
		}
	}
	three := Verdict{Executable: true, State: contract.StateAllow,
		Effects: []string{NewEffect(obl("a")), NewEffect(obl("b")), NewEffect(obl("c"))}}.Canonical()
	if len(three.Effects) != 3 {
		t.Fatalf("three redactions of three fields canonicalized to %d effect(s): %v", len(three.Effects), three.Effects)
	}
	one := Verdict{Executable: true, State: contract.StateAllow,
		Effects: []string{NewEffect(obl("a"))}}.Canonical()

	legacyThree := Verdict{Executable: true, State: contract.StateAllow, Effects: []string{
		LegacyEffect(src, string(legacycompile.ActionRedact), "a"),
		LegacyEffect(src, string(legacycompile.ActionRedact), "b"),
		LegacyEffect(src, string(legacycompile.ActionRedact), "c"),
	}}.Canonical()

	if err := effectsCorrespond(legacyThree, three); err != nil {
		t.Fatalf("three legacy redactions against three obligations did not correspond: %v", err)
	}
	if err := effectsCorrespond(legacyThree, one); err == nil {
		t.Fatal("three legacy redactions corresponded with ONE obligation; two dropped controls compared as equal")
	}
	// And the direction a type-only comparison misses entirely: the right
	// NUMBER of redactions against the WRONG fields.
	wrongTargets := Verdict{Executable: true, State: contract.StateAllow,
		Effects: []string{NewEffect(obl("x")), NewEffect(obl("y")), NewEffect(obl("z"))}}.Canonical()
	if err := effectsCorrespond(legacyThree, wrongTargets); err == nil {
		t.Fatal("three redactions of the WRONG three fields corresponded; a comparison on obligation type alone " +
			"reports a compiler that redacts the wrong field as a match")
	}
}

// TestApprovalClauseCountMustMatch pins that approvals are compared by count,
// not by a zero/non-zero boundary. Two of three required approvals silently
// disappearing is a governance control shrinking.
func TestApprovalClauseCountMustMatch(t *testing.T) {
	legacy := Verdict{Executable: false, State: contract.StateDeny, Effects: []string{
		LegacyEffect(RowKeyFor("static_policies", "r1"), string(legacycompile.ActionRequireApproval), ""),
	}}
	if err := effectsCorrespond(legacy, Verdict{ApprovalClauses: 1}); err != nil {
		t.Fatalf("one legacy approval against one clause did not correspond: %v", err)
	}
	if err := effectsCorrespond(legacy, Verdict{ApprovalClauses: 0}); err == nil {
		t.Fatal("a legacy require_approval corresponded with zero outstanding clauses")
	}
	if err := effectsCorrespond(legacy, Verdict{ApprovalClauses: 2}); err == nil {
		t.Fatal("one legacy require_approval corresponded with two clauses; a raised approval nothing predicts passed")
	}
}

// TestProxyTierIsFirstMatchWins pins the one plane whose evaluation is not
// "apply everything".
//
// TierAwarePolicyEngine.evaluateFirstMatch RETURNS inside its loop on the first
// pattern match, so at most one non-segment row determines a proxy-tier
// verdict. Modelling it as accumulate-all reported a determining set the
// running system does not produce.
func TestProxyTierIsFirstMatchWins(t *testing.T) {
	rows := []legacycompile.RawRow{
		staticFixture(t, "sys_high", map[string]any{"priority": 200, "action_request": "log", "action": "log"}),
		staticFixture(t, "sys_low", map[string]any{"priority": 10, "action_request": "block", "action": "block"}),
	}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := &ModelEvaluator{Report: rep, Rows: rowFactsFrom(t, rows), ContentTarget: legacycompile.DefaultContentTarget}
	both := map[string]bool{"sys_high": true, "sys_low": true}

	proxy, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneProxyTier, Org: "global", DetectorVerdicts: both,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(proxy.Determining) != 1 {
		t.Fatalf("the proxy tier reported %d determining policies (%v); evaluateFirstMatch returns on the first match",
			len(proxy.Determining), proxy.Determining)
	}
	if proxy.Determining[0] != RowKey("static_policies", "sys_high") {
		t.Fatalf("the proxy tier reported %q; the higher-priority row is evaluated first", proxy.Determining[0])
	}
	// The higher-priority row logs, so the lower-priority BLOCK never runs.
	// That is the legacy behaviour, and getting it wrong would report a deny
	// the running system does not produce.
	if !proxy.Executable {
		t.Fatal("the proxy tier denied; the first match logs and the blocking row is never reached")
	}

	// Every other plane accumulates, so the block DOES apply there.
	gw, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneGatewayRequest, Org: "global", DetectorVerdicts: both,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(gw.Determining) != 2 {
		t.Fatalf("the gateway request plane reported %d determining policies (%v); the shared engine applies every match",
			len(gw.Determining), gw.Determining)
	}
	if gw.Executable {
		t.Fatal("the gateway request plane permitted; one of the two matched rows blocks")
	}
}

// TestACaseThatMissesItsClaimedRowFailsTheGate pins that ExercisesRows is read
// rather than write-only. A corpus whose cases quietly miss their target
// reports clean coverage of whatever it happened to touch.
func TestACaseThatMissesItsClaimedRowFailsTheGate(t *testing.T) {
	rows := []legacycompile.RawRow{staticFixture(t, "sys_pii_ssn", nil)}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	facts := rowFactsFrom(t, rows)
	world, err := NewWorld(context.Background(), rep, legacycompile.PlaneDecide, "global")
	if err != nil {
		t.Fatalf("NewWorld: %v", err)
	}
	// A case that claims a row it cannot reach: the detector never fires.
	bad := Case{
		ID: "claims-what-it-cannot-reach", Plane: legacycompile.PlaneDecide,
		Org: "acme", Principal: "alice", Action: ActionID,
		DetectorVerdicts: map[string]bool{"sys_pii_ssn": false},
		ExercisesRows:    []string{RowKey("static_policies", "sys_pii_ssn")},
	}
	run, err := Execute(context.Background(), []Case{bad},
		&ModelEvaluator{Report: rep, Rows: facts, ContentTarget: legacycompile.DefaultContentTarget}, world.Engine, rep, world.BundleDigest)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(run.UnreachedClaims) == 0 {
		t.Fatal("a case claimed a row and neither engine named it, and the run recorded nothing")
	}
	if Gate(run, GateOptions{AllowUnexercisedRows: true}).Passed {
		t.Fatal("the gate passed with a case that missed the row it claimed")
	}
}
