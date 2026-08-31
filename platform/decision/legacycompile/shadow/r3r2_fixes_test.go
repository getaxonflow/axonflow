package shadow

import (
	"context"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// TestProxyTierOrdersByTierBeforePriority pins the ordering the model got
// wrong.
//
// GetEffective sorts tier ASC (system, organization, tenant), THEN priority
// DESC, then name ASC - and evaluateFirstMatch returns on the first match in
// that order. So a system-tier `log` at priority 1 beats a tenant-tier `block`
// at priority 999. A model that sorted on priority alone reported a deny the
// running system does not produce, on the one plane where order is the whole
// answer.
func TestProxyTierOrdersByTierBeforePriority(t *testing.T) {
	rows := []legacycompile.RawRow{
		staticFixture(t, "sys_low_priority_log", map[string]any{
			"tier": "system", "tenant_id": "global", "org_id": "global",
			"priority": 1, "action_request": "log", "action": "log", "name": "aaa",
		}),
		staticFixture(t, "tenant_high_priority_block", map[string]any{
			"tier": "tenant", "tenant_id": "global", "org_id": "global",
			"priority": 999, "action_request": "block", "action": "block", "name": "zzz",
		}),
	}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := &ModelEvaluator{Report: rep, Rows: rowFactsFrom(t, rows), ContentTarget: legacycompile.DefaultContentTarget}
	both := map[string]bool{"sys_low_priority_log": true, "tenant_high_priority_block": true}

	got, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneProxyTier, Org: "global", DetectorVerdicts: both,
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got.Determining) != 1 {
		t.Fatalf("the proxy tier reported %d determining policies (%v); EvaluatePolicy returns ONE result",
			len(got.Determining), got.Determining)
	}
	if got.Determining[0] != RowKeyFor("static_policies", "sys_low_priority_log") {
		t.Fatalf("the proxy tier reported %q; tier outranks priority, so the system-tier row is evaluated first",
			got.Determining[0])
	}
	if !got.Executable {
		t.Fatal("the proxy tier denied; the first match by TIER order logs, and evaluateFirstMatch returns before " +
			"reaching the higher-priority tenant block")
	}
}

// TestProxyTierReturnsOneResult pins the combiner. The engine takes the first
// non-segment match and the strictest segment match and combines them into ONE
// PolicyEvaluationResult carrying ONE action, ties going to the tier result.
// Returning both made the model name two determining policies and apply two
// actions where the engine names one.
func TestProxyTierReturnsOneResult(t *testing.T) {
	rows := []legacycompile.RawRow{
		staticFixture(t, "tier_log", map[string]any{
			"action_request": "log", "action": "log", "segment_id": nil,
		}),
		staticFixture(t, "seg_block", map[string]any{
			"action_request": "block", "action": "block", "segment_id": "seg-a",
		}),
	}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := &ModelEvaluator{Report: rep, Rows: rowFactsFrom(t, rows), ContentTarget: legacycompile.DefaultContentTarget}
	got, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneProxyTier, Org: "global",
		Groups:           []string{"seg-a"},
		DetectorVerdicts: map[string]bool{"tier_log": true, "seg_block": true},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got.Determining) != 1 {
		t.Fatalf("the proxy tier reported %d determining policies (%v); combineTierAndSegmentResults returns one",
			len(got.Determining), got.Determining)
	}
	// The segment block is strictly more restrictive than the tier log, so it
	// wins - which is ADR-060 Decision 1, additive-restriction-only.
	if got.Determining[0] != RowKeyFor("static_policies", "seg_block") || got.Executable {
		t.Fatalf("the strictest segment match did not win: determining=%v executable=%t", got.Determining, got.Executable)
	}
}

// TestTheModelReadsContextFallthroughFields pins the two halves of this
// package agreeing about #3515, in the direction the production code actually
// has.
//
// getFieldValue's default arm is a direct req.Context[field] lookup over
// caller-forwarded context, so a field outside the resolver's explicit cases
// resolves to whatever the caller supplied - and a `connector equals X ->
// block` row DOES fire for a caller that forwards that key. An earlier version
// of the model refused to read such a field out of the case ("resolves to nil
// no matter what the request carries"), which reported a caller-triggerable
// block as a row production cannot fire; the compiler agreed by refusing the
// row, and the two halves matched on a hole.
func TestTheModelReadsContextFallthroughFields(t *testing.T) {
	row := dynamicFixture(t, "dyn_fallthrough_equals", map[string]any{
		"conditions": []map[string]any{{"field": "user.department", "operator": "equals", "value": "compliance"}},
	})
	rep, err := legacycompile.Compile([]legacycompile.RawRow{row}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := &ModelEvaluator{Report: rep, Rows: rowFactsFrom(t, rows(row)), ContentTarget: legacycompile.DefaultContentTarget}

	// The case supplies the value under the field's name, exactly as a caller
	// forwarding context["user.department"]="compliance" does. The row fires.
	got, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneWCP, Org: "acme",
		Fields: map[string]any{"user.department": "compliance"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got.Determining) != 1 {
		t.Fatalf("the model did not fire a row whose condition reads a caller-forwarded context key: %v; "+
			"getFieldValue's default arm reads req.Context[field], so production fires it", got.Determining)
	}

	// The control: with the key NOT supplied the field resolves to nil,
	// sprintValue(nil) is "<nil>", and equals never matches - so this test is
	// not simply asserting that everything fires.
	got2, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneWCP, Org: "acme",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got2.Determining) != 0 {
		t.Fatalf("the row fired with no context key supplied: %v; an unsupplied key resolves to nil and equals cannot match it", got2.Determining)
	}
}

// TestTheCorpusUsesTheCompilationOptions pins the fail-open that armed the
// moment an operator set the realm the compiler's own documentation tells them
// to set.
//
// The corpus built its request with a zero Options, so a compiled group id of
// `Group::acme_prod:engineering` was matched against a principal closure of
// `Group::legacy_segment:engineering`, the group scope never matched, and every
// segment-scoped CONSTRAINT stopped applying on the ADR-065 side while the
// legacy model still applied it.
func TestTheCorpusUsesTheCompilationOptions(t *testing.T) {
	opts := testOptions()
	opts.Realm = "acme_prod"
	rows := []legacycompile.RawRow{
		staticFixture(t, "seg_block", map[string]any{
			"action_request": "block", "action": "block", "segment_id": "engineering",
		}),
	}
	rep, err := legacycompile.Compile(rows, opts)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), opts)
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	res := Gate(run, GateOptions{})
	for _, rec := range run.Unexplained() {
		if rec.FailOpen == FailOpenNewPermitted {
			t.Fatalf("a segment-scoped constraint stopped applying on the ADR-065 side under a non-default realm "+
				"(%s): the corpus is building its request from options the compiler did not use\n%s", rec.CaseID, res.Summary)
		}
	}
	if !res.Passed {
		t.Fatalf("the gate failed under a non-default realm:\n  %s", strings.Join(res.Failures, "\n  "))
	}
}

// TestOneOrgsPoliciesDoNotReachAnotherOrg pins ADR-065 invariant 1 in the
// compiled output.
//
// The runtime reads static_policies with `WHERE org_id = $1` under
// strict-equality row-level security. An earlier version compiled every
// captured row into ONE organization document with an unconditional
// organization scope, so at cutover every org's policies would have applied to
// every org's requests - and the harness could not see it, because both sides
// were equally org-blind.
func TestOneOrgsPoliciesDoNotReachAnotherOrg(t *testing.T) {
	acme := staticFixture(t, "acme_block", map[string]any{
		"tier": "tenant", "org_id": "acme", "tenant_id": "acme",
		"action_request": "block", "action": "block",
	})
	acme.OrgScope = "acme"
	globex := staticFixture(t, "globex_block", map[string]any{
		"tier": "tenant", "org_id": "globex", "tenant_id": "globex",
		"action_request": "block", "action": "block",
	})
	globex.OrgScope = "globex"

	rep, err := legacycompile.Compile([]legacycompile.RawRow{acme, globex}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := rep.OrgScopes(); len(got) != 2 {
		t.Fatalf("the report reports %v org scopes; the fixture has two", got)
	}
	for _, org := range []string{"acme", "globex"} {
		_, orgDoc, err := rep.Documents(legacycompile.PlaneGatewayRequest, org)
		if err != nil {
			t.Fatalf("Documents(%q): %v", org, err)
		}
		if len(orgDoc.Policies) != 1 {
			t.Fatalf("the %q document carries %d policies; one org's document must carry only that org's rows",
				org, len(orgDoc.Policies))
		}
		if !strings.Contains(orgDoc.Policies[0].ID, org) {
			t.Fatalf("the %q document carries policy %q, which belongs to another org", org, orgDoc.Policies[0].ID)
		}
	}

	// And the legacy model must be org-scoped too, or the two sides would
	// disagree for a reason that is about the harness rather than the
	// migration.
	m := &ModelEvaluator{Report: rep, Rows: rowFactsFrom(t, []legacycompile.RawRow{acme, globex}), ContentTarget: legacycompile.DefaultContentTarget}
	got, err := m.Evaluate(context.Background(), Case{
		ID: "t", Plane: legacycompile.PlaneGatewayRequest, Org: "acme",
		DetectorVerdicts: map[string]bool{"acme_block": true, "globex_block": true},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(got.Determining) != 1 || got.Determining[0] != RowKeyFor("static_policies", "acme_block") {
		t.Fatalf("an acme request was governed by %v; globex's row must not reach it", got.Determining)
	}
}

// TestSanitizedIdentifiersDoNotCollide pins the encoding.
//
// The first version escaped as "x"+hex, which is not self-delimiting against
// its own alphabet: "a.b" and the literal id "ax2eb" produced one detector
// path. Two rows then shared one signal attribute, one overwrote the other in
// Go map order, and the same pinned inputs classified differently between runs.
func TestSanitizedIdentifiersDoNotCollide(t *testing.T) {
	ids := []string{"a.b", "a_b", "ax2eb", "a-b", "acme:ssn", "sys_pii_ssn", "a_2e_b"}
	seen := map[string]string{}
	for _, id := range ids {
		path := legacycompile.DetectorSignalPath(id)
		if prev, dup := seen[path]; dup {
			t.Fatalf("policy ids %q and %q both map to detector path %q", prev, id, path)
		}
		seen[path] = id

		// And the encoding must round-trip, or a diff record would name an id
		// that is not in the database.
		back, ok := legacycompile.UnsanitizePolicyID(legacycompile.SanitizePolicyID(id))
		if !ok || back != id {
			t.Fatalf("policy id %q did not round-trip: got %q ok=%t", id, back, ok)
		}
	}

	// A compiled policy identifier must recover the ORIGINAL id even when it
	// contains the separator the format splits on.
	compiled := legacycompile.PolicyIDFor("static_policies", "acme:ssn", legacycompile.PlaneDecide, legacycompile.PhaseRequest)
	if got := SourcePolicyOf(compiled); got != RowKeyFor("static_policies", "acme:ssn") {
		t.Fatalf("SourcePolicyOf(%q) = %q, want the row key for \"acme:ssn\"", compiled, got)
	}
	// And it must not collide with the row genuinely named "acme".
	plain := legacycompile.PolicyIDFor("static_policies", "acme", legacycompile.PlaneDecide, legacycompile.PhaseRequest)
	if SourcePolicyOf(compiled) == SourcePolicyOf(plain) {
		t.Fatal("the row \"acme:ssn\" and the row \"acme\" recover the same key")
	}
}

// rows is a tiny helper so a single-row fixture reads as a slice.
func rows(r ...legacycompile.RawRow) []legacycompile.RawRow { return r }

// TestUnmeasurableRowsAreReported pins the third category in the coverage
// report.
//
// A dynamic row whose only action is modify_risk, and one whose action type
// the orchestrator's switch has no arm for, both enforce nothing the harness
// can compare. They were not in the exercised fraction and not in the
// unexercised one - they were outside it entirely, so "rows N/N exercised"
// read as "we measured this plane's policy set" while some of the captured
// rows were not in the fraction at all.
func TestUnmeasurableRowsAreReported(t *testing.T) {
	rows := []legacycompile.RawRow{
		dynamicFixture(t, "dyn_measurable", nil),
		dynamicFixture(t, "dyn_risk_only", map[string]any{
			"actions": []map[string]any{{"type": "modify_risk", "config": map[string]any{"add": 0.2}}},
		}),
		dynamicFixture(t, "dyn_unknown_action", map[string]any{
			"actions": []map[string]any{{"type": "quarantine", "config": map[string]any{}}},
		}),
	}
	rep, err := legacycompile.Compile(rows, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	run, err := RunAll(context.Background(), rep, rowFactsFrom(t, rows), testOptions())
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	cov := run.Coverage[legacycompile.PlaneWCP]
	want := map[string]bool{
		RowKeyFor("dynamic_policies", "dyn_risk_only"):      true,
		RowKeyFor("dynamic_policies", "dyn_unknown_action"): true,
	}
	for _, got := range cov.UnmeasurableRows {
		delete(want, got)
	}
	if len(want) > 0 {
		t.Fatalf("wcp reports unmeasurable rows %v; %v are missing and would be outside the N/N fraction with nothing saying so",
			cov.UnmeasurableRows, want)
	}
	// And the measurable one must NOT be listed, or the category would be true
	// of every row and say nothing.
	for _, got := range cov.UnmeasurableRows {
		if got == RowKeyFor("dynamic_policies", "dyn_measurable") {
			t.Fatal("a row the legacy engine enforces was reported as unmeasurable")
		}
	}
	// The summary must print them, because a field nobody sees is not a report.
	if !strings.Contains(Gate(run, GateOptions{}).Summary, "UNMEASURABLE") {
		t.Fatal("the gate summary does not print the unmeasurable rows")
	}
}

// TestTheSummaryStatesItsOwnProvenance pins the line that stops an operator
// reading UNEXPLAINED=0 as "my policy set was diffed".
//
// In CI this harness runs a small fixture corpus; the captured production
// policy set is a local step. Nothing in the counters distinguishes the two,
// and cases are GENERATED from the compiled policy set rather than replayed
// from traffic. The PR that introduced this harness made exactly that mistake
// in its own body, and a reader cannot be expected to be more careful than the
// artifact.
func TestTheSummaryStatesItsOwnProvenance(t *testing.T) {
	rows := corpusRows(t)
	_, run := buildRun(t, rows, testOptions())
	summary := Gate(run, GateOptions{}).Summary
	for _, want := range []string{"GENERATED", "captured row(s)", "org scope(s)"} {
		if !strings.Contains(summary, want) {
			t.Fatalf("the summary does not say %q, so a reader cannot tell a fixture corpus from a captured one:\n%s", want, summary)
		}
	}
	if !strings.HasPrefix(strings.TrimSpace(summary), "corpus:") {
		t.Fatalf("the provenance line is not first in the summary; it is the sentence that qualifies every number below it:\n%s", summary)
	}
}

// TestDynamicRowsAreAlsoScanDropped pins #3397 on the OTHER substrate.
//
// RefreshDynamicPolicies scans positionally into a DynamicPolicyRow and
// logs-and-continues on a scan error, exactly like its static sibling - and
// description, priority and category are all nullable columns landing in
// non-nullable Go destinations. Modelling the defect on one substrate of two
// would have left an undisclosed hole in this package's headline claim.
func TestDynamicRowsAreAlsoScanDropped(t *testing.T) {
	for _, col := range []string{"description", "priority", "category"} {
		t.Run("NULL "+col, func(t *testing.T) {
			rep, err := legacycompile.Compile(
				[]legacycompile.RawRow{dynamicFixture(t, "dyn_dropped", map[string]any{col: nil})},
				testOptions())
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			rec := recordFor(t, rep, "dyn_dropped")
			if !rec.HasReason(legacycompile.ReasonLegacyScanDrop) {
				t.Fatalf("a NULL %s did not drop the dynamic row; the refresh's scan errors and the row never reaches the cache", col)
			}
			if rec.PolicyCount() != 0 {
				t.Fatalf("a row the dynamic refresh drops compiled %d policies", rec.PolicyCount())
			}
			for _, p := range legacycompile.PlanesFor(legacycompile.SubstrateDynamic) {
				if rec.ContributesTo(p) {
					t.Fatalf("a dropped row still contributes on plane %q; the legacy engine never sees it", p)
				}
			}
		})
	}
	// The negative direction: a complete row is not dropped.
	rep, err := legacycompile.Compile([]legacycompile.RawRow{dynamicFixture(t, "dyn_ok", nil)}, testOptions())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if recordFor(t, rep, "dyn_ok").HasReason(legacycompile.ReasonLegacyScanDrop) {
		t.Fatal("a complete dynamic row was reported as scan-dropped; the reason would then be true of every row")
	}
}
