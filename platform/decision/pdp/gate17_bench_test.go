package pdp

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math"
	"sort"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// ADR-065 GATE 17: latency and memory budgets for the decision plane.
//
// The gate was recorded as a GAP in ADR-065-phase-signoff-record.md - "zero
// benchmarks, no published budgets" - and must be green before v11. This file
// is the measuring instrument; ADR-065-gate17-budgets.md is what it publishes.
//
// # WHAT IS MEASURED, AND WHY IT IS THREE THINGS RATHER THAN ONE
//
// A deployment pays ACTIVATION once at boot and pays EVALUATION on every
// request. Folding them into one figure lets a boot-time regression hide inside
// a request budget, and lets an evaluation regression be excused by an
// activation improvement. They are measured separately, and COMPILATION -
// turning a typed document into Rego - is measured separately again, because it
// is what an authoring surface pays when a policy is saved.
//
// Activation here has no warm path to be confused with a cold one: NewRuntime
// runs LintBundleModule and rego.PrepareForEval on every call
// (runtime.go:170-197), with no cache between them. A cached compile reported as
// activation would be the same class of error as reporting the harness.
//
// # THE TWO CONTROLS, WHICH FAIL IN DIFFERENT DIRECTIONS
//
// A benchmark can be wrong by measuring the instrument, and it can be wrong by
// not reaching its subject at all - and the second produces a beautifully
// stable number, which is the worse failure because it looks like a good
// result.
//
//   - THE FLOOR: benchmarkTimerFloor measures the instrumentation around an
//     empty operation. Any figure below a small multiple of it is a statement
//     about time.Now(), not about the decision plane.
//   - THE SUBJECT: TestGate17BenchmarksReachTheirSubject evaluates 25 policies
//     and 200 and requires the larger to be measurably slower. A fixture that
//     stopped scaling with its size argument reports a lovely flat line at
//     every N, and nothing else in the output says so. It is deliberately NOT a
//     check that the policies APPLY - see the note on the test.
//
// # PERCENTILES, NOT ONLY MEANS
//
// Go reports ns/op, which is a MEAN over b.N. A mean cannot answer the question
// a latency budget asks, because the tail is what a request feels and what a
// timeout is set against. Each benchmark below therefore records every
// iteration's duration and reports p50/p95/p99 as custom metrics, alongside the
// SAMPLE COUNT and the standard deviation - because a p99 taken from a handful
// of iterations is one unlucky sample with a decimal point, and Go will print
// it without complaint.

// gate17PolicyCounts are the scale points. 0 is the floor: a bundle with no
// policies still pays request marshalling, the Rego call and the Go combiner,
// so the difference between it and a loaded bundle is the part attributable to
// policy work.
var gate17PolicyCounts = []int{0, 1, 10, 100, 500}

// benchDocument builds a document with n policies over a fixed attribute
// schema.
//
// THE POLICIES ARE NOT COPIES OF ONE POLICY. Each carries a distinct id, a
// distinct threshold and alternating shapes (a comparison, a conjunction, an
// attribute-to-attribute comparison), because an evaluator that short-circuits
// on identical rules would report a scale curve that flattens for a reason
// nothing in production shares. They all remain APPLICABLE to the benchmark
// request: a policy whose scope excludes the request is a policy the evaluator
// skips, and a fixture full of them measures skipping.
func benchDocument(n int) *Document {
	d := &Document{
		Root:    RootSystem,
		Version: 1,
		Attributes: []AttributeSchema{
			{Path: "principal.id", Type: TypeString},
			{Path: "principal.groups", Type: TypeArray},
			{Path: "action.id", Type: TypeString},
			{Path: "action.tags", Type: TypeArray},
			{Path: "args.amount_cents", Type: TypeNumber},
			{Path: "resource.owner", Type: TypeString},
		},
	}
	for i := 0; i < n; i++ {
		p := Policy{
			ID:        fmt.Sprintf("BENCH_P%04d", i),
			Authority: contract.AuthorityConstraint,
			Root:      RootSystem,
			Scope:     Scope{Organization: true},
			Actions:   ActionSelector{RequiredTags: []string{"spend"}},
		}
		switch i % 3 {
		case 0:
			p.Where = Compare("args.amount_cents", OpGt, 100000+i)
		case 1:
			p.Where = And(
				Compare("args.amount_cents", OpGt, 50000+i),
				Compare("args.amount_cents", OpLe, 900000+i),
			)
		default:
			p.Where = And(
				AttrEq("resource.owner", "principal.id"),
				Compare("args.amount_cents", OpGt, 10000+i),
			)
		}
		d.Policies = append(d.Policies, p)
	}
	return d
}

// benchEngine assembles a signed, verified engine over a document. It is the
// production path (BuildBundle -> Sign -> NewEngine), not a shortcut, so an
// activation figure includes what a deployment actually pays.
func benchEngine(tb testing.TB, d *Document) *Engine {
	tb.Helper()
	b, err := BuildBundle(d)
	if err != nil {
		tb.Fatalf("BuildBundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		tb.Fatalf("GenerateKey: %v", err)
	}
	if err := b.Sign("k1", priv); err != nil {
		tb.Fatalf("Sign: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(d.Root, "k1", pub)
	e, err := NewEngine(context.Background(), EngineConfig{
		Bundles:       []*Bundle{b},
		Documents:     []*Document{d},
		TrustStore:    ts,
		PayloadLeaves: []string{"response.ssn"},
		PEP:           &contract.PEPProfile{ID: "gate17-bench"},
		Registry:      benchRegistry(),
	})
	if err != nil {
		tb.Fatalf("NewEngine: %v", err)
	}
	return e
}

func benchRegistry() *Registry {
	return &Registry{
		Actions: map[string]ActionEntry{
			"Action::stripe.create_refund": {
				ID:                 contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
				Tags:               []string{"spend"},
				MaxDelegationDepth: 3,
				Arguments:          map[string]ValueType{"amount_cents": TypeNumber},
			},
		},
		Realms: map[string]bool{"realm_ws": true, "jira": true},
	}
}

func benchRequest() *contract.Request {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	identity := contract.AttributeSet{
		"principal.id":     contract.Known("User::realm_ws:alice", contract.ProvAuthentication, 1, now),
		"principal.groups": contract.Known([]any{"Group::realm_ws:support-tier2"}, contract.ProvDirectory, 83, now),
	}
	return &contract.Request{
		RequestID:    "gate17_bench",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::jira:T-1"),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: identity}}},
		Snapshot: contract.Snapshot{
			SchemaVersion: contract.SchemaVersion,
			PolicyBundle:  "sha256:gate17",
		},
		Attributes: contract.AttributeSet{
			"action.id":         contract.Known("Action::stripe.create_refund", contract.ProvPlatform, 18, now),
			"action.tags":       contract.Known([]any{"spend", "irreversible"}, contract.ProvPlatform, 18, now),
			"args.amount_cents": contract.Known(300000, contract.ProvCaller, 0, now),
			"resource.owner":    contract.Known("User::realm_ws:alice", contract.ProvResource, 14, now),
		},
		EvaluatedAt: now,
	}
}

// --- the distribution reporter ---------------------------------------------

// reportDistribution turns per-iteration durations into published metrics.
//
// EVERY FIGURE IT PRINTS IS ACCOMPANIED BY WHAT QUALIFIES IT. The samples count
// and the standard deviation are reported as metrics rather than left in prose,
// because they travel with the number into whatever table or dashboard consumes
// the benchmark output, and a p99 without its sample count is not
// interpretable: at 20 samples it IS the maximum.
func reportDistribution(b *testing.B, samples []time.Duration) {
	b.Helper()
	if len(samples) == 0 {
		b.Fatal("no samples recorded; the benchmark reported percentiles over nothing")
	}
	sorted := append([]time.Duration(nil), samples...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	pct := func(p float64) float64 {
		// Nearest-rank, which is the definition that does not invent a value
		// between two samples. At small n an interpolated p99 is a number no
		// iteration ever took.
		idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return float64(sorted[idx].Nanoseconds()) / 1000
	}

	var sum float64
	for _, s := range sorted {
		sum += float64(s.Nanoseconds())
	}
	mean := sum / float64(len(sorted))
	var variance float64
	for _, s := range sorted {
		d := float64(s.Nanoseconds()) - mean
		variance += d * d
	}
	stddev := math.Sqrt(variance/float64(len(sorted))) / 1000

	b.ReportMetric(pct(50), "p50-us")
	b.ReportMetric(pct(95), "p95-us")
	b.ReportMetric(pct(99), "p99-us")
	b.ReportMetric(float64(sorted[len(sorted)-1].Nanoseconds())/1000, "max-us")
	b.ReportMetric(stddev, "stddev-us")
	b.ReportMetric(float64(len(sorted)), "samples")
}

// --- the benchmarks ---------------------------------------------------------

// decideBench and activateBench are THE MEASURED WORK, returned as functions so
// that the benchmark and its control run THE SAME CODE.
//
// # WHY THIS INDIRECTION EXISTS
//
// The control used to re-implement the measurement in its own closure. That
// makes it a test of a LOOKALIKE: gutting BenchmarkGate17Decide's loop body
// leaves the control green and the smoke printing 250 ns per op at 500
// policies, while the workflow comment promises CI keeps the benchmarks from
// rotting. It cannot promise that about a body it never runs.
//
// Both callers now go through these, and the control invokes them with
// testing.Benchmark, so a change to the loop body is a change to what the
// control measures.
func decideBench(n int) func(*testing.B) {
	return func(b *testing.B) {
		decideLoop(benchEngine(b, benchDocument(n)))(b)
	}
}

// decideLoop is the measured evaluation loop over an ALREADY BUILT engine.
//
// It is split from decideBench so the budget test (gate17_budgets_test.go) can
// build the 500-policy engine ONCE and hand it to testing.Benchmark, which
// otherwise re-runs the function at increasing N and pays the 12-second
// activation on every attempt. The loop body is the same code either way, so
// gutting it still reds the subject control and the budget test alike.
func decideLoop(e *Engine) func(*testing.B) {
	return func(b *testing.B) {
		req := benchRequest()
		ctx := context.Background()
		// One evaluation outside the loop, checked, so a benchmark that errors
		// on every iteration cannot report a fast, meaningless number. An
		// erroring path is usually the fastest path there is.
		if _, err := e.Decide(ctx, req); err != nil {
			b.Fatalf("the benchmarked call fails, so every figure would be the cost of failing: %v", err)
		}
		samples := make([]time.Duration, 0, b.N)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			if _, err := e.Decide(ctx, req); err != nil {
				b.Fatalf("Decide: %v", err)
			}
			samples = append(samples, time.Since(start))
		}
		b.StopTimer()
		reportDistribution(b, samples)
	}
}

func activateBench(n int) func(*testing.B) {
	return func(b *testing.B) {
		d := benchDocument(n)
		bundle, err := BuildBundle(d)
		if err != nil {
			b.Fatalf("BuildBundle: %v", err)
		}
		activateLoop(bundle)(b)
	}
}

// activateLoop is the measured activation loop over an already built bundle;
// see decideLoop for why the build is outside it.
func activateLoop(bundle *Bundle) func(*testing.B) {
	return func(b *testing.B) {
		ctx := context.Background()
		if _, err := NewRuntime(ctx, bundle, DefaultLimits()); err != nil {
			b.Fatalf("the benchmarked call fails: %v", err)
		}
		samples := make([]time.Duration, 0, b.N)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			if _, err := NewRuntime(ctx, bundle, DefaultLimits()); err != nil {
				b.Fatalf("NewRuntime: %v", err)
			}
			samples = append(samples, time.Since(start))
		}
		b.StopTimer()
		reportDistribution(b, samples)
	}
}

// compileLoop is the measured compilation loop, shared by the benchmark and
// the budget test for the same reason as decideLoop.
func compileLoop(d *Document) func(*testing.B) {
	return func(b *testing.B) {
		if _, err := Compile(d); err != nil {
			b.Fatalf("the benchmarked call fails: %v", err)
		}
		samples := make([]time.Duration, 0, b.N)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			if _, err := Compile(d); err != nil {
				b.Fatalf("Compile: %v", err)
			}
			samples = append(samples, time.Since(start))
		}
		b.StopTimer()
		reportDistribution(b, samples)
	}
}

// BenchmarkGate17Decide is the REQUEST-PATH budget: what one governed request
// pays to be decided, by policy count.
func BenchmarkGate17Decide(b *testing.B) {
	for _, n := range gate17PolicyCounts {
		b.Run(fmt.Sprintf("policies=%d", n), decideBench(n))
	}
}

// BenchmarkGate17Activation is the BOOT-PATH budget: what a deployment pays
// once, per bundle root, before it can serve anything.
//
// It is NewRuntime and not the whole engine, so the figure is the compilation
// and lint rather than key generation and signature verification, which are
// measured by their own path and do not scale with policy count.
func BenchmarkGate17Activation(b *testing.B) {
	for _, n := range gate17PolicyCounts {
		b.Run(fmt.Sprintf("policies=%d", n), activateBench(n))
	}
}

// BenchmarkGate17Compile is the AUTHORING-PATH budget: turning a typed document
// into Rego, which is what a policy save pays.
func BenchmarkGate17Compile(b *testing.B) {
	for _, n := range gate17PolicyCounts {
		b.Run(fmt.Sprintf("policies=%d", n), compileLoop(benchDocument(n)))
	}
}

// BenchmarkGate17TimerFloor is THE INSTRUMENT'S OWN COST, measured with the
// same instrumentation as everything above.
//
// It is not a decision-plane figure and is not meant to be read as one. It is
// the number every other number must be compared against before it is believed:
// a percentile within a small multiple of this is a measurement of time.Now()
// and the append beside it.
func BenchmarkGate17TimerFloor(b *testing.B) {
	samples := make([]time.Duration, 0, b.N)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		samples = append(samples, time.Since(start))
	}
	b.StopTimer()
	reportDistribution(b, samples)
}

// TestGate17BenchmarksReachTheirSubject is the control a benchmark cannot
// perform on itself, and it runs in the ordinary test tier so it cannot rot.
//
// # IT RUNS THE BENCHMARKS, IT DOES NOT RE-IMPLEMENT THEM
//
// The first version measured the operation in its own closure. That is a test
// of a LOOKALIKE: gutting BenchmarkGate17Decide's loop body left this green and
// the CI smoke printing 250 ns per op at 500 policies, while the workflow step
// promises CI keeps the benchmarks from rotting. It cannot promise that about a
// body it never runs. Both axes now go through testing.Benchmark over the same
// functions the benchmarks call.
//
// # BOTH AXES, AND ACTIVATION IS THE ONE THAT MATTERS MOST
//
// The evaluation ratio alone left the finding of this whole change unguarded.
// §8 of the artifact proposes caching the prepared runtime by bundle digest as
// one remedy for the superlinear activation curve - and with that cache in
// place the activation benchmark reports 60 ns flat at the timer floor while
// this control, watching only Decide, stayed green. The document's own
// recommended fix would have turned its finding into a non-result with nothing
// noticing.
//
// So activation is asserted to scale too. If a future change makes activation
// cheap - which would be GOOD NEWS - this test fails and forces the artifact to
// be rewritten rather than left standing over a number that is no longer true.
// That is the intended behaviour: a published finding that stops being true
// must not stay published.
//
// # RATIOS, NOT THRESHOLDS
//
// An absolute "must be under N ms" is a machine-specific constant that fails on
// a slow CI runner and passes on a fast one while the fixture is broken in
// both. A ratio is a property of the code's structure and holds on any machine.
func TestGate17BenchmarksReachTheirSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and evaluates real bundles; -short skips it")
	}

	// nsPerOp runs the REAL benchmark function and returns its per-operation
	// cost. A benchmark that fails inside testing.Benchmark returns a zero
	// result rather than failing this test, so the zero is checked.
	nsPerOp := func(t *testing.T, what string, f func(*testing.B)) float64 {
		t.Helper()
		r := testing.Benchmark(f)
		if r.N == 0 || r.NsPerOp() == 0 {
			t.Fatalf("%s reported N=%d ns/op=%d; the benchmark did not run, so every ratio below "+
				"would be a statement about nothing", what, r.N, r.NsPerOp())
		}
		return float64(r.NsPerOp())
	}

	t.Run("evaluation scales with policy count", func(t *testing.T) {
		// 25 AND 200, NOT 20 AND 40, AND THE FIRST DRAFT WAS THE SECOND. It
		// measured 1.19 and failed its own 1.3 bound - not because the fixture
		// was broken, but because the CONSTANT costs (request marshalling, the
		// Rego call, the Go combiner) dominate below about fifty policies. The
		// measured curve is ~333us at 10 and ~2350us at 100. Sizes an order
		// apart make the ratio ~6, which leaves the bound excluding a ratio of
		// 1.0 rather than measuring how close two adjacent points are.
		small := nsPerOp(t, "decide(25)", decideBench(25))
		large := nsPerOp(t, "decide(200)", decideBench(200))
		if large < 1.3*small {
			t.Errorf("evaluating 200 policies cost %.0f ns and 25 cost %.0f (ratio %.2f).\n\n"+
				"Eight times the policy count did not measurably cost more, so the benchmark is not reaching "+
				"the policies: a fixture that ignores its size argument, or a document built empty, produces "+
				"a ratio near 1.0 and reports a beautifully stable number nothing else here would question.\n"+
				"Verified: making benchDocument ignore n gives 0.93 and reds this.\n\n"+
				"WHAT THIS DOES NOT CATCH, said because an earlier comment claimed it did: a fixture whose "+
				"policies do not APPLY still passes, correctly - the rules are in the bundle either way, so the "+
				"evaluator walks them and the cost still scales. Applicability is a CONFORMANCE-corpus property, "+
				"not a scale-benchmark one.", large, small, large/small)
		}
	})

	t.Run("activation scales with policy count", func(t *testing.T) {
		// THE ONE THE FINDING DEPENDS ON. Activation at 10 policies is ~5 ms
		// and at 100 is ~238 ms; the ratio is enormous and this bound is
		// deliberately weak, because the property under test is "the cost is
		// still paid", not "the cost is still 45x".
		//
		// A prepared-runtime cache keyed on bundle digest - the remedy the
		// artifact's own section 8 proposes - collapses this to a flat 60 ns
		// and reds it. That is correct: if activation stops being superlinear,
		// the published finding is no longer true and must be rewritten rather
		// than left standing.
		small := nsPerOp(t, "activate(10)", activateBench(10))
		large := nsPerOp(t, "activate(80)", activateBench(80))
		if large < 1.3*small {
			t.Errorf("activating an 80-policy bundle cost %.0f ns and a 10-policy one cost %.0f "+
				"(ratio %.2f).\n\n"+
				"Activation is no longer measurably scaling with policy count. Two things produce this and "+
				"they need opposite responses:\n"+
				"  * the benchmark stopped reaching NewRuntime - fix the benchmark;\n"+
				"  * activation genuinely became cheap, most likely a prepared-runtime cache keyed on the "+
				"bundle digest, which is exactly what ADR-065-gate17-budgets.md section 8 proposes. Then the "+
				"published finding - 5x the policies for 50x the time, 894 MB at 500 - is NO LONGER TRUE, and "+
				"the artifact and #3693 must be rewritten before this bound is relaxed.\n\n"+
				"Do not delete this assertion to make a cache land. Its whole job is to notice that the "+
				"document has become wrong.", large, small, large/small)
		}
	})

	t.Run("the loaded case is above the empty-bundle floor", func(t *testing.T) {
		// An evaluation indistinguishable from the empty-bundle case would mean
		// the policies cost nothing measurable, which for this evaluator would
		// itself be the defect.
		empty := nsPerOp(t, "decide(0)", decideBench(0))
		small := nsPerOp(t, "decide(25)", decideBench(25))
		if small < 1.3*empty {
			t.Errorf("evaluating 25 policies (%.0f ns) is not measurably above the empty bundle (%.0f ns); "+
				"the difference between them is the part of every published figure attributable to policy "+
				"work, and there is none", small, empty)
		}
	})
}
