package policy

import (
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"testing"
	"time"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
	"axonflow/platform/shared/planeshadow"
)

// THE NON-INTERFERENCE CONTRACT, AND THE TEST THE MUTATION ROUND AIMS AT.
//
// planeshadow.Observe returns nothing and evaluates off the request path, so
// "the shadow cannot change a decision" is meant to be structural. A structural
// argument still needs a behavioural test, for the reason the mutation harness
// in shadowmutation/ spells out: an assertion that a thing does not happen and
// an implementation that cannot make it happen are indistinguishable from
// outside, and the guarantee here is exactly the kind that would be quietly
// lost by a well-meaning refactor.
//
// So: the SAME inputs are evaluated twice, once with the shadow off and once
// with it on, and EVERY field of the result is compared. Not the block
// decision alone - the redacted content, the matched-policy list, the
// evaluation-error flag and the block reason too, because a shadow that
// perturbed the redaction while leaving Blocked alone would pass a
// coarser test and would be a data-integrity bug rather than an
// authorization one.

// shadowTestEngineOn installs a process observer over a row source that serves
// the same policy rows the engine has, and clears it when the test ends.
func shadowTestObserverOn(t *testing.T) {
	t.Helper()
	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })

	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: shadowOnMode(), SampleRate: 1, QueueDepth: 256, Workers: 2},
		shadowTestRows{},
		planeshadow.MetricsRecorder{},
		planeshadow.WithComponent("noninterference-test"),
	)
	if err != nil {
		t.Fatalf("building the observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	planeshadow.SetProcessObserver(o)
	if !planeshadow.Enabled() {
		t.Fatal("the observer reports it cannot observe; every comparison below would run " +
			"against a shadow that is off on BOTH legs and would pass for the wrong reason")
	}
}

// shadowTestRows serves the raw legacy rows the shadow compiles from.
//
// Deliberately the SAME two rows the engine evaluates, so the shadow really
// builds a bundle and really evaluates - a row source returning nothing would
// make every observation fail to compile, the shadow would do no work, and this
// test would pass while measuring an inert shadow.
type shadowTestRows struct{}

func (shadowTestRows) RawRows(_ context.Context, orgScope string) ([]legacycompile.RawRow, error) {
	return []legacycompile.RawRow{
		shadowTestRawRow("test_block", orgScope, "block", `DROP\s+TABLE`),
		shadowTestRawRow("test_redact", orgScope, "redact", `\d{3}-\d{2}-\d{4}`),
	}, nil
}

func shadowTestRawRow(policyID, orgScope, action, pattern string) legacycompile.RawRow {
	base := map[string]any{
		"id":        "00000000-0000-0000-0000-0000000000" + policyID[len(policyID)-2:],
		"policy_id": policyID, "name": policyID, "category": "pii-us",
		"pattern": pattern, "severity": "high", "tier": "system",
		"tenant_id": orgScope, "org_id": orgScope, "priority": 100, "enabled": true,
		"phase": "both", "action_request": action, "action_response": action, "action": action,
		"segment_id": nil, "version": 1, "metadata": map[string]any{}, "deleted_at": nil,
		"created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
	}
	cols := map[string]json.RawMessage{}
	for k, v := range base {
		b, _ := json.Marshal(v)
		cols[k] = b
	}
	return legacycompile.RawRow{Table: "static_policies", OrgScope: orgScope, Columns: cols}
}

// shadowNoninterferencePolicies is the engine's own policy set, matching the
// rows above.
func shadowNoninterferencePolicies() []CompiledPolicy {
	return []CompiledPolicy{
		{
			ID: "1", PolicyID: "test_block", Name: "test_block",
			Category: CategoryPIIUS, Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`DROP\s+TABLE`), PatternStr: `DROP\s+TABLE`,
			Phase: PhaseBoth, ActionRequest: ActionBlock, ActionResponse: ActionBlock,
			Enabled: true, Priority: 100, TenantID: "test-tenant",
			UpdatedAt: planeshadow.StampKey(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		{
			ID: "2", PolicyID: "test_redact", Name: "test_redact",
			Category: CategoryPIIUS, Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`\d{3}-\d{2}-\d{4}`), PatternStr: `\d{3}-\d{2}-\d{4}`,
			Phase: PhaseBoth, ActionRequest: ActionRedact, ActionResponse: ActionRedact,
			Enabled: true, Priority: 90, TenantID: "test-tenant",
			UpdatedAt: planeshadow.StampKey(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
	}
}

// shadowNoninterferenceInputs spans the outcome classes, because a corpus of
// clean requests would only ever compare two permits.
var shadowNoninterferenceInputs = []struct {
	name  string
	input string
}{
	{"clean", "SELECT name FROM customers"},
	{"blocked", "DROP TABLE customers"},
	{"redactable", "the ssn is 123-45-6789"},
	{"both", "DROP TABLE t WHERE ssn = '123-45-6789'"},
	{"empty", ""},
}

// TestShadowNeverChangesTheRequestOutcome is the request-phase half.
func TestShadowNeverChangesTheRequestOutcome(t *testing.T) {
	ctx := context.Background()
	opts := EvalOptions{
		Plane:    legacycompile.PlaneGatewayRequest,
		TenantID: "test-tenant", OrgID: "test-tenant", UserID: "alice",
	}

	// THE OFF BASELINE MUST ACTUALLY BE OFF. A previous test in the same
	// package leaving a process observer installed would make this leg run
	// WITH the shadow, and every comparison below would then be shadow-vs-
	// shadow: a perfect score for a change that broke non-interference
	// completely.
	if planeshadow.Enabled() {
		t.Fatal("a process observer is already installed, so the 'off' baseline below would " +
			"be taken WITH the shadow running and every assertion in this test would compare " +
			"the shadow against itself")
	}
	off := map[string]*RequestResult{}
	for _, in := range shadowNoninterferenceInputs {
		e := createTestEngine(shadowNoninterferencePolicies())
		off[in.name] = e.EvaluateRequest(ctx, in.input, opts)
	}

	shadowTestObserverOn(t)

	for _, in := range shadowNoninterferenceInputs {
		in := in
		t.Run(in.name, func(t *testing.T) {
			e := createTestEngine(shadowNoninterferencePolicies())
			on := e.EvaluateRequest(ctx, in.input, opts)
			assertRequestResultsIdentical(t, in.name, off[in.name], on)
		})
	}
}

// TestShadowNeverChangesTheResponseOutcome is the response-phase half, and it
// is the one that matters most: the response plane REWRITES CONTENT, so a
// shadow that perturbed it would be a data-integrity defect rather than an
// authorization one, and would be invisible to any test comparing only the
// block decision.
func TestShadowNeverChangesTheResponseOutcome(t *testing.T) {
	ctx := context.Background()
	opts := EvalOptions{
		Plane:    legacycompile.PlaneOrchestratorResponse,
		TenantID: "test-tenant", OrgID: "test-tenant", UserID: "alice",
	}
	content := func() any {
		return []map[string]interface{}{
			{"name": "alice", "ssn": "123-45-6789"},
			{"name": "bob", "note": "DROP TABLE t"},
		}
	}

	e := createTestEngine(shadowNoninterferencePolicies())
	off := e.EvaluateResponse(ctx, content(), opts)

	shadowTestObserverOn(t)

	e2 := createTestEngine(shadowNoninterferencePolicies())
	on := e2.EvaluateResponse(ctx, content(), opts)

	if off.Blocked != on.Blocked {
		t.Errorf("Blocked differs: off=%v on=%v", off.Blocked, on.Blocked)
	}
	if off.Redacted != on.Redacted {
		t.Errorf("Redacted differs: off=%v on=%v", off.Redacted, on.Redacted)
	}
	if off.EvaluationError != on.EvaluationError {
		t.Errorf("EvaluationError differs: off=%v on=%v", off.EvaluationError, on.EvaluationError)
	}
	if off.BlockReason != on.BlockReason {
		t.Errorf("BlockReason differs: off=%q on=%q", off.BlockReason, on.BlockReason)
	}
	if !reflect.DeepEqual(off.Content, on.Content) {
		t.Errorf("THE REDACTED CONTENT DIFFERS. This is the shape a coarser test would miss "+
			"entirely.\n  off: %#v\n  on:  %#v", off.Content, on.Content)
	}
	if !reflect.DeepEqual(off.RedactedFields, on.RedactedFields) {
		t.Errorf("RedactedFields differ:\n  off: %#v\n  on:  %#v", off.RedactedFields, on.RedactedFields)
	}
	if !reflect.DeepEqual(policyIDsOf(off.MatchedPolicies), policyIDsOf(on.MatchedPolicies)) {
		t.Errorf("MatchedPolicies differ:\n  off: %v\n  on:  %v",
			policyIDsOf(off.MatchedPolicies), policyIDsOf(on.MatchedPolicies))
	}
}

// assertRequestResultsIdentical compares every field a caller can observe.
//
// ProcessingTimeMs is EXCLUDED and that is the only exclusion: it is a wall
// clock and would differ between two runs of identical code, so including it
// would make this test fail for a reason that has nothing to do with the
// shadow. Everything else is compared, including the fields a caller is less
// likely to read - a shadow that perturbed PoliciesEvaluated would be
// perturbing the engine's own accounting.
func assertRequestResultsIdentical(t *testing.T, name string, off, on *RequestResult) {
	t.Helper()
	if off.Blocked != on.Blocked {
		t.Errorf("%s: Blocked differs: off=%v on=%v. THE SHADOW CHANGED AN AUTHORIZATION "+
			"DECISION, which is the one thing it structurally must not be able to do.",
			name, off.Blocked, on.Blocked)
	}
	if off.BlockReason != on.BlockReason {
		t.Errorf("%s: BlockReason differs: off=%q on=%q", name, off.BlockReason, on.BlockReason)
	}
	if off.EvaluationError != on.EvaluationError {
		t.Errorf("%s: EvaluationError differs: off=%v on=%v", name, off.EvaluationError, on.EvaluationError)
	}
	if off.PoliciesEvaluated != on.PoliciesEvaluated {
		t.Errorf("%s: PoliciesEvaluated differs: off=%d on=%d", name, off.PoliciesEvaluated, on.PoliciesEvaluated)
	}
	if !reflect.DeepEqual(policyIDsOf(off.MatchedPolicies), policyIDsOf(on.MatchedPolicies)) {
		t.Errorf("%s: MatchedPolicies differ:\n  off: %v\n  on:  %v",
			name, policyIDsOf(off.MatchedPolicies), policyIDsOf(on.MatchedPolicies))
	}
	offBy, onBy := "", ""
	if off.BlockedBy != nil {
		offBy = off.BlockedBy.PolicyID
	}
	if on.BlockedBy != nil {
		onBy = on.BlockedBy.PolicyID
	}
	if offBy != onBy {
		t.Errorf("%s: BlockedBy differs: off=%q on=%q", name, offBy, onBy)
	}
}

func policyIDsOf(ms []PolicyMatch) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.PolicyID+"/"+string(m.Action))
	}
	return out
}

// TestTheShadowActuallyRanInTheNoninterferenceFixture is the ANTI-VACUITY
// FLOOR for both tests above.
//
// Every assertion in this file says two things are the SAME. A shadow that
// never ran satisfies all of them - and that is not a hypothetical: a fixture
// whose row source returns nothing, whose plane is unset, or whose mode
// resolves to off produces exactly that, silently. So this asserts the shadow
// did work.
func TestTheShadowActuallyRanInTheNoninterferenceFixture(t *testing.T) {
	ctx := context.Background()
	rec := &countingRecorder{done: make(chan struct{})}

	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })
	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: shadowOnMode(), SampleRate: 1, QueueDepth: 256, Workers: 2},
		shadowTestRows{}, rec, planeshadow.WithComponent("noninterference-floor"),
	)
	if err != nil {
		t.Fatalf("building the observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = o.Shutdown(ctx)
	})
	planeshadow.SetProcessObserver(o)

	// BOTH PHASES, BECAUSE THEY ARE TWO EMIT SITES AND THIS FILE ASSERTS
	// ABOUT BOTH.
	//
	// EvaluateRequest and EvaluateResponse emit from different points in
	// engine.go and take different branches of observedPhase. A floor that
	// exercised only the request phase would leave every response assertion in
	// this file - including the reflect.DeepEqual on redacted CONTENT, the one
	// its own comment calls the shape a coarser test would miss - free to
	// compare an engine against itself if the response emit ever stopped
	// producing a comparison.
	e := createTestEngine(shadowNoninterferencePolicies())
	e.EvaluateRequest(ctx, "DROP TABLE customers", EvalOptions{
		Plane:    legacycompile.PlaneGatewayRequest,
		TenantID: "test-tenant", OrgID: "test-tenant", UserID: "alice",
	})

	select {
	case <-rec.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the shadow recorded NOTHING for a REQUEST that matched a policy. Every " +
			"request-phase non-interference assertion in this file would then be comparing " +
			"an engine against itself, and would pass however badly the shadow behaved.")
	}

	respRec := &countingRecorder{done: make(chan struct{})}
	oResp, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: shadowOnMode(), SampleRate: 1, QueueDepth: 256, Workers: 2},
		shadowTestRows{}, respRec, planeshadow.WithComponent("noninterference-floor-response"),
	)
	if err != nil {
		t.Fatalf("building the response-phase observer: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = oResp.Shutdown(ctx)
	})
	planeshadow.SetProcessObserver(oResp)

	eResp := createTestEngine(shadowNoninterferencePolicies())
	eResp.EvaluateResponse(ctx, []map[string]interface{}{
		{"name": "alice", "ssn": "123-45-6789"},
		{"name": "bob", "note": "DROP TABLE t"},
	}, EvalOptions{
		Plane:    legacycompile.PlaneOrchestratorResponse,
		TenantID: "test-tenant", OrgID: "test-tenant", UserID: "alice",
	})

	select {
	case <-respRec.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the shadow recorded NOTHING for a RESPONSE that matched a policy. " +
			"TestShadowNeverChangesTheResponseOutcome - including its assertion on the " +
			"redacted CONTENT - would then be comparing an engine against itself.")
	}
}

// countingRecorder closes its channel on the first comparison.
type countingRecorder struct {
	done chan struct{}
	once bool
}

func (c *countingRecorder) RecordComparison(_ context.Context, _ planeshadow.Comparison) {
	if !c.once {
		c.once = true
		close(c.done)
	}
}

// shadowOnMode is the shadow mode, PARSED rather than named.
//
// A fixture that wrote identity.CompatModeShadow directly would keep working
// if the production parser stopped accepting "shadow" - so every test in this
// file would go on measuring a mode no deployment can actually select.
func shadowOnMode() planeshadow.Mode {
	m, err := identity.ParseDecisionShadowMode("shadow")
	if err != nil {
		panic(err)
	}
	return m
}

// TestTheEngineReportsWhichDetectorsActuallyRan is the COLLECTOR half of the
// tri-state, and it is a different property from the translator's half.
//
// The translator turns "did not run" into an absent attribute; this asserts the
// engine tells it which detectors did not run in the first place. Both are
// needed, and a test of either alone leaves the other free to collapse the
// distinction: a collector reporting Ran=true for everything makes a correct
// translator produce known-false verdicts for skipped detectors, which is a
// fail-open on every request a category filter narrowed.
//
// # WHY IT ASSERTS THROUGH THE CLASSIFICATION RATHER THAN THE ROW FACTS
//
// The row facts are an input the engine hands to a package this one imports;
// reading them back would need a test-only seam, and a test that inspects the
// value under test on its way past is asserting against its own fixture. The
// CONSEQUENCE is observable and is the thing that actually matters: a detector
// reported as unrun becomes an UNKNOWN attribute, unknown cannot permit, and
// the classifier names that difference EC2_UNKNOWN_IS_NOT_FALSE. A detector
// reported as run-and-not-matched becomes a known false and produces a
// different classification entirely.
func TestTheEngineReportsWhichDetectorsActuallyRan(t *testing.T) {
	ctx := context.Background()

	filtered := classifyOneRequest(t, "DROP TABLE customers", []PolicyCategory{CategoryComplianceGDPR})
	unfiltered := classifyOneRequest(t, "DROP TABLE customers", nil)

	if filtered.Record.RuleID != "EC2_UNKNOWN_IS_NOT_FALSE" {
		t.Errorf("a request whose detectors were ALL excluded by a category filter classified as "+
			"%q/%q. Every one of those detectors was skipped, so each is an UNKNOWN attribute "+
			"on the ADR-065 side and the difference is EC2_UNKNOWN_IS_NOT_FALSE. Reporting "+
			"them as having run tells the PDP a detector positively did not match when nothing "+
			"looked at it - the exact collapse ADR-065's tri-state exists to prevent.\n"+
			"  detail: %s", filtered.Record.Class, filtered.Record.RuleID, filtered.Record.Detail)
	}
	// The other direction, so the test cannot pass by classifying everything as
	// EC2: with no filter the detectors DO run, and the classification differs.
	if unfiltered.Record.RuleID == "EC2_UNKNOWN_IS_NOT_FALSE" {
		t.Errorf("an UNFILTERED request also classified as EC2_UNKNOWN_IS_NOT_FALSE (%q). Its "+
			"detectors ran, so nothing about it is unknown; a collector reporting Ran=false "+
			"for everything would produce exactly this and would satisfy the first assertion "+
			"for the wrong reason.", unfiltered.Record.Detail)
	}
	_ = ctx
}

// classifyOneRequest runs one request through the engine with the shadow on and
// returns the comparison it produced.
func classifyOneRequest(t *testing.T, input string, cats []PolicyCategory) planeshadow.Comparison {
	t.Helper()
	ctx := context.Background()
	rec := &oneComparisonRecorder{done: make(chan struct{})}

	prior := planeshadow.ProcessObserver()
	t.Cleanup(func() { planeshadow.SetProcessObserver(prior) })
	o, err := planeshadow.NewObserver(
		planeshadow.Config{Mode: shadowOnMode(), SampleRate: 1, QueueDepth: 64, Workers: 1},
		shadowTestRows{}, rec, planeshadow.WithComponent("ran-test"),
	)
	if err != nil {
		t.Fatalf("building the observer: %v", err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = o.Shutdown(c)
	}()
	planeshadow.SetProcessObserver(o)

	e := createTestEngine(shadowNoninterferencePolicies())
	e.EvaluateRequest(ctx, input, EvalOptions{
		Plane:      legacycompile.PlaneGatewayRequest,
		TenantID:   "test-tenant",
		OrgID:      "test-tenant",
		UserID:     "alice",
		Categories: cats,
	})

	select {
	case <-rec.done:
	case <-time.After(30 * time.Second):
		t.Fatal("no comparison reached the recorder; this test would then assert nothing about " +
			"a shadow that never ran")
	}
	return rec.got
}

// oneComparisonRecorder captures the first comparison.
type oneComparisonRecorder struct {
	done chan struct{}
	got  planeshadow.Comparison
	seen bool
}

func (r *oneComparisonRecorder) RecordComparison(_ context.Context, c planeshadow.Comparison) {
	if r.seen {
		return
	}
	r.seen = true
	r.got = c
	close(r.done)
}
