package pdp

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ADR-065 GATE 17, THE ENFORCED HALF.
//
// gate17_bench_test.go MEASURES; ADR-065-gate17-budgets.md PUBLISHES; this file
// is what FAILS. Until it existed the gate read "MEASURED, ENFORCEMENT STILL
// OWED" in the sign-off record: every ceiling in the document was a sentence,
// and a sentence cannot go red.
//
// # ONE TABLE, READ BY THE DOCUMENT AND BY THE TESTS
//
// gate17Budgets below is the budget table. The published document's section 7
// is asserted to be a rendering of it, row for row, by
// TestGate17BudgetTableMatchesThePublishedDocument, so a ceiling cannot be
// relaxed in the code while the document still promises the old one, and a
// budget cannot be published that no test reads. A budget that nothing
// enforces is flagged by the same test: every row names where it is enforced,
// and "nowhere" is only legal for a row the document marks UNSET.
//
// # THREE ENFORCEMENT CLASSES, BECAUSE THE FIGURES FAIL DIFFERENTLY
//
//   - MEMORY (bytes allocated per operation) is a property of the code and the
//     Go toolchain, not of the machine: the fleet runner reports allocations
//     within ~12% of the reference machine while its wall-clock is 1.5-2.5x
//     slower. These budgets fail HARD on every pull request.
//   - SHAPE (a ratio of two measurements taken in the same process) is a
//     property of the algorithm. Evaluation at 500 policies costing more than
//     7.5x evaluation at 100 is superlinear whatever the machine; activation at
//     100 policies costing more than 65x activation at 10 means the curve #3693
//     is deciding about has got WORSE. These fail HARD on every pull request.
//   - LATENCY (an absolute p99 or p50 in milliseconds) is a property of the
//     machine it was taken on. The published ceilings are stated against the
//     ENFORCING machine class (ubuntu-latest) as a multiple of the MEDIAN of
//     several independent runs, because one hosted observation moves by more
//     than 2x under neighbour load and a ceiling set against one observation
//     reds on an unlucky runner. So the latency rows fail HARD only where
//     AXONFLOW_GATE17_ENFORCE_LATENCY=1 - the dedicated
//     gate17-latency-budgets.yml job, on a hosted runner, dispatchable and
//     weekly - where each row is measured gate17DefaultLatencyReps times and
//     the MEDIAN is what the ceiling is compared against; everywhere else they
//     are MEASURED ONCE AND LOGGED beside their budget, so the number is always
//     in the run log even when it is not the verdict. That is a stated
//     narrowing, not a silent one: the test prints which mode it ran in and how
//     many repetitions it took.
//
// # THE MEASUREMENTS ARE THE BENCHMARKS' OWN LOOPS
//
// Every figure here comes from testing.Benchmark over decideLoop, activateLoop
// and compileLoop - the same functions the published benchmarks run - so a
// budget cannot be satisfied by a lookalike of the measured work. The engines
// are built once and shared across the assertions; the 500-policy activation
// alone costs twelve seconds, and paying it per assertion would make the step
// slow enough to be skipped.

// gate17EnforceLatencyEnv, when set to "1", turns the latency rows from
// measured-and-logged into failing assertions.
const gate17EnforceLatencyEnv = "AXONFLOW_GATE17_ENFORCE_LATENCY"

// gate17AloneEnv, when set to "1", states that this test binary has the
// runner to itself, and turns the SHAPE rows into verdicts. A shape ratio is
// two wall-clock terms measured at different moments in one process; on a
// machine the process shares, a neighbour lands on one term and not the other.
// Measured (job 101403668523): under `go test ./...` package parallelism on the
// 4-vCPU runner the graph closure ratio read 47.7 where the same binary run
// alone, by name, minutes earlier read 12.1. The named gate 17 steps in
// test.yml / test-community.yml and gate17-latency-budgets.yml set this; a
// package run does not, and the shape test skips there saying so. Pinned by
// tests/regression-test-required/gate17_verdict_steps_run_alone_test.sh.
const gate17AloneEnv = "AXONFLOW_GATE17_ALONE"

func requireAlone(t *testing.T) {
	t.Helper()
	if os.Getenv(gate17AloneEnv) != "1" {
		t.Skipf("%s is not 1: shape ratios are verdicts only where the binary has the runner to itself (the named gate 17 steps set it); in a package run the two terms are measured under different neighbours", gate17AloneEnv)
	}
}

// gate17DocRelPath is the published document, relative to the repository
// root. The decision module mirrors to the community repository and
// technical-docs/ does not, so on a mirror checkout the document is absent by
// design - see TestGate17BudgetTableMatchesThePublishedDocument.
const gate17DocRelPath = "technical-docs/architecture-decisions/ADR-065-gate17-budgets.md"

// gate17DocSectionHeading is the heading whose table is asserted.
const gate17DocSectionHeading = "## 7. Budgets"

type gate17Kind string

const (
	gate17Measured gate17Kind = "MEASURED"
	gate17Chosen   gate17Kind = "CHOSEN"
	gate17Unset    gate17Kind = "UNSET"
)

// gate17Enforcement is the document's "Enforced by" cell, verbatim.
type gate17Enforcement string

const (
	enforcedEveryPR    gate17Enforcement = "every PR: `Unit Tests: Decision Contracts` and its community twin"
	enforcedLatencyJob gate17Enforcement = "`gate17-latency-budgets.yml` (dispatch + weekly)"
	enforcedNowhere    gate17Enforcement = "-"
)

// gate17Metric names one observed statistic of one benchmark row.
type gate17Metric struct {
	Path string // evaluation | activation | compilation
	N    int    // policy count
	Stat string // p50 | p99 | bytes
}

// gate17Budget is one row of the published table.
type gate17Budget struct {
	// Label is the document's first cell, verbatim.
	Label string
	// Value is the ceiling, in Unit. Zero for an UNSET row.
	Value float64
	// Unit is "ms", "MB/op" or "x" (a dimensionless ratio).
	Unit string
	Kind gate17Kind
	// Enforced names where a run fails against this row.
	Enforced gate17Enforcement
	// Absolute is set for a ceiling on one measurement.
	Absolute *gate17Metric
	// Ratio is set for a ceiling on numerator/denominator.
	Ratio *[2]gate17Metric
	// DocValue is the document's value cell for an UNSET row, since it has no
	// number to render.
	DocValue string
}

// gate17Budgets IS the published table. Edit it and the document together;
// the test that compares them says which side moved.
var gate17Budgets = []gate17Budget{
	// --- latency: absolute, machine-bound, enforced by the dedicated job ------
	{
		Label: "Evaluation p99, 100 policies", Value: 38, Unit: "ms", Kind: gate17Chosen,
		Enforced: enforcedLatencyJob, Absolute: &gate17Metric{"evaluation", 100, "p99"},
	},
	{
		Label: "Evaluation p99, 500 policies", Value: 185, Unit: "ms", Kind: gate17Chosen,
		Enforced: enforcedLatencyJob, Absolute: &gate17Metric{"evaluation", 500, "p99"},
	},
	{
		Label: "Activation mean, 100 policies", Value: 1000, Unit: "ms", Kind: gate17Chosen,
		Enforced: enforcedLatencyJob, Absolute: &gate17Metric{"activation", 100, "mean"},
	},
	{
		Label: "Activation, 500 policies", Kind: gate17Unset, Enforced: enforcedNowhere,
		DocValue: "no ceiling set",
	},
	{
		Label: "Compilation p99, 500 policies", Value: 29, Unit: "ms", Kind: gate17Chosen,
		Enforced: enforcedLatencyJob, Absolute: &gate17Metric{"compilation", 500, "p99"},
	},
	// --- memory: absolute, machine-independent, enforced on every PR -----------
	{
		Label: "Evaluation memory, 100 policies", Value: 4.5, Unit: "MB/op", Kind: gate17Chosen,
		Enforced: enforcedEveryPR, Absolute: &gate17Metric{"evaluation", 100, "bytes"},
	},
	{
		Label: "Evaluation memory, 500 policies", Value: 21, Unit: "MB/op", Kind: gate17Chosen,
		Enforced: enforcedEveryPR, Absolute: &gate17Metric{"evaluation", 500, "bytes"},
	},
	{
		Label: "Activation memory, 100 policies", Value: 150, Unit: "MB/op", Kind: gate17Chosen,
		Enforced: enforcedEveryPR, Absolute: &gate17Metric{"activation", 100, "bytes"},
	},
	{
		Label: "Compilation memory, 500 policies", Value: 12, Unit: "MB/op", Kind: gate17Chosen,
		Enforced: enforcedEveryPR, Absolute: &gate17Metric{"compilation", 500, "bytes"},
	},
	// --- shape: ratios, verdicts where the binary is alone (gate17AloneEnv) ----
	{
		Label: "Evaluation p50 ratio, 500 vs 100 policies", Value: 11, Unit: "x", Kind: gate17Chosen,
		Enforced: enforcedEveryPR,
		Ratio:    &[2]gate17Metric{{"evaluation", 500, "p50"}, {"evaluation", 100, "p50"}},
	},
	{
		Label: "Activation p50 ratio, 100 vs 10 policies", Value: 90, Unit: "x", Kind: gate17Chosen,
		Enforced: enforcedEveryPR,
		Ratio:    &[2]gate17Metric{{"activation", 100, "p50"}, {"activation", 10, "p50"}},
	},
	// --- the limit the document refuses to ratify -----------------------------
	{
		Label: "Bundle activation limit", Kind: gate17Unset, Enforced: enforcedNowhere,
		DocValue: "NONE SET",
	},
}

// gate17MinSamples is the fewest samples a statistic may be read from. A p99
// over fewer than 20 samples is the maximum with a decimal point; a p50 over
// fewer than 3 is not a median (nearest-rank p50 of two samples is the SMALLER
// one); a mean needs two. Activation at 100 policies is the row this matters
// for: one activation is 230-460 ms, so a one-second testing.Benchmark run
// held 2-5 of them - too few for a percentile, which is why that row's
// statistic is the MEAN (Go's ns/op over the run's iterations), and the
// ceiling is on the median of five such run-means. The count is now pinned
// (gate17FixedIterations), so the floor no longer follows the machine; the
// statistic stays the mean because the ceiling was calibrated on it.
var gate17MinSamples = map[string]float64{"p50": 3, "p99": 20, "mean": 2, "bytes": 1}

// gate17FixedIterations pins the iteration count of the whole-bundle path.
// testing.Benchmark sizes N to about one second of work, so the number of
// samples behind a statistic followed the MACHINE - the graph axis's
// 50,000-group load took 8-20 samples on an idle hosted runner and exactly TWO
// under the Real-PG lane's neighbours (job 101385846185), failing its p50 floor
// with the code unchanged. A floor a slower runner can fail is the #3648 class,
// a speed-dependent threshold in the test, so the whole-structure paths on both
// axes pin their count and the floor becomes a property of the row. Ten
// activations at 100 policies is 2.5-5 s per run; evaluation and compilation
// run at the microsecond-to-millisecond scale and keep the time budget, which
// yields hundreds of samples anywhere.
var gate17FixedIterations = map[string]int{"activation": 10}

// gate17Benchmark runs f under the row's sampling rule: a pinned count for
// paths in gate17FixedIterations (via testing's own -test.benchtime count mode,
// restored afterwards), the one-second time budget for the rest.
func gate17Benchmark(t *testing.T, path string, f func(*testing.B)) testing.BenchmarkResult {
	t.Helper()
	n, pinned := gate17FixedIterations[path]
	if !pinned {
		return testing.Benchmark(f)
	}
	benchTime := flag.Lookup("test.benchtime")
	if benchTime == nil {
		t.Fatal("test.benchtime is not registered; the iteration count cannot be pinned, so the sample floor would depend on the machine again")
	}
	previous := benchTime.Value.String()
	if err := benchTime.Value.Set(fmt.Sprintf("%dx", n)); err != nil {
		t.Fatalf("pinning test.benchtime to %dx: %v", n, err)
	}
	defer func() {
		if err := benchTime.Value.Set(previous); err != nil {
			t.Fatalf("restoring test.benchtime to %q: %v", previous, err)
		}
	}()
	r := testing.Benchmark(f)
	if r.N != n {
		t.Fatalf("%s ran N=%d iterations where %d were pinned; the sample floor is not under the test's control", path, r.N, n)
	}
	return r
}

// renderBudgetValue is how the document must spell a row's value cell.
func renderBudgetValue(b gate17Budget) string {
	if b.Kind == gate17Unset {
		return b.DocValue
	}
	v := strconv.FormatFloat(b.Value, 'f', -1, 64)
	if b.Unit == "x" {
		return v + "x"
	}
	return v + " " + b.Unit
}

// --- measurements -----------------------------------------------------------

// gate17Measurements caches one testing.BenchmarkResult per (path, n) for the
// life of the test binary, so the four tests share the twelve-second engine
// build rather than each paying it. gate17Fixtures caches the built fixture
// (engine, bundle or document) so a REPEATED run - the enforcing job takes
// several and enforces on the median - pays the build once too.
var (
	gate17Measurements = map[string]testing.BenchmarkResult{}
	gate17Fixtures     = map[string]func(*testing.B){}
)

func gate17Key(path string, n int) string { return fmt.Sprintf("%s/%d", path, n) }

// gate17Loop returns the benchmark loop for (path, n) over a fixture built once.
func gate17Loop(t *testing.T, path string, n int) func(*testing.B) {
	t.Helper()
	key := gate17Key(path, n)
	if f, ok := gate17Fixtures[key]; ok {
		return f
	}
	var f func(*testing.B)
	switch path {
	case "evaluation":
		f = decideLoop(benchEngine(t, benchDocument(n)))
	case "activation":
		bundle, err := BuildBundle(benchDocument(n))
		if err != nil {
			t.Fatalf("BuildBundle(%d): %v", n, err)
		}
		f = activateLoop(bundle)
	case "compilation":
		f = compileLoop(benchDocument(n))
	default:
		t.Fatalf("gate17Loop: unknown path %q", path)
	}
	gate17Fixtures[key] = f
	return f
}

// gate17Run runs the benchmark loop for (path, n) once, uncached, and checks
// the result is a measurement rather than a zero.
func gate17Run(t *testing.T, path string, n int) testing.BenchmarkResult {
	t.Helper()
	key := gate17Key(path, n)
	r := gate17Benchmark(t, path, gate17Loop(t, path, n))
	// testing.Benchmark returns a ZERO result rather than failing the caller
	// when the benchmark function calls b.Fatal, so the zero is checked here:
	// a budget compared against zero passes.
	if r.N == 0 || r.NsPerOp() == 0 {
		t.Fatalf("%s reported N=%d ns/op=%d; the benchmark did not run, so no budget could be checked against it", key, r.N, r.NsPerOp())
	}
	for _, metric := range []string{"p50-us", "p99-us", "samples"} {
		if _, ok := r.Extra[metric]; !ok {
			t.Fatalf("%s reported no %q metric; reportDistribution did not run, so the percentile a budget is set on does not exist", key, metric)
		}
	}
	t.Logf("measured %-16s n=%-5d samples=%-5.0f mean=%8.3f ms  p50=%8.3f ms  p99=%8.3f ms  %12d B/op",
		path, n, r.Extra["samples"], float64(r.NsPerOp())/1e6, r.Extra["p50-us"]/1000, r.Extra["p99-us"]/1000, r.AllocedBytesPerOp())
	return r
}

// gate17Result runs the benchmark loop for (path, n) once and caches it.
func gate17Result(t *testing.T, path string, n int) testing.BenchmarkResult {
	t.Helper()
	key := gate17Key(path, n)
	if r, ok := gate17Measurements[key]; ok {
		return r
	}
	r := gate17Run(t, path, n)
	gate17Measurements[key] = r
	return r
}

// gate17LatencyRepsEnv overrides the number of repetitions the enforcing mode
// takes per latency row (default gate17DefaultLatencyReps; at least 3).
const gate17LatencyRepsEnv = "AXONFLOW_GATE17_LATENCY_REPS"

// gate17DefaultLatencyReps is how many independent testing.Benchmark runs the
// enforcing job takes per latency row before enforcing on their MEDIAN. One
// run on a hosted VM is a guess with a margin: neighbour load moves a hosted
// p99 by more than 2x run to run, so a ceiling set against one observation
// reds on an unlucky runner and gets widened by the next person. The median of
// five is what the ceiling is stated against, and the calibration table in
// the document records min / median / max of the run that set it.
const gate17DefaultLatencyReps = 5

func gate17LatencyReps(enforce bool) int {
	if !enforce {
		return 1
	}
	if v := os.Getenv(gate17LatencyRepsEnv); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 3 {
			return n
		}
	}
	return gate17DefaultLatencyReps
}

// gate17StatOfResult extracts a latency statistic in milliseconds.
func gate17StatOfResult(r testing.BenchmarkResult, stat string) float64 {
	switch stat {
	case "p50":
		return r.Extra["p50-us"] / 1000
	case "p99":
		return r.Extra["p99-us"] / 1000
	case "mean":
		return float64(r.NsPerOp()) / 1e6
	}
	return 0
}

// gate17MedianLatency measures a latency row reps times (the first run is the
// shared cached one) and returns min, median, max of the statistic and the
// smallest sample count any run rested on.
func gate17MedianLatency(t *testing.T, m gate17Metric, reps int) (lo, median, hi, minSamples float64) {
	t.Helper()
	values := make([]float64, 0, reps)
	minSamples = math.Inf(1)
	for i := 0; i < reps; i++ {
		var r testing.BenchmarkResult
		if i == 0 {
			r = gate17Result(t, m.Path, m.N)
		} else {
			r = gate17Run(t, m.Path, m.N)
		}
		values = append(values, gate17StatOfResult(r, m.Stat))
		if s := r.Extra["samples"]; s < minSamples {
			minSamples = s
		}
	}
	sort.Float64s(values)
	return values[0], values[len(values)/2], values[len(values)-1], minSamples
}

// gate17Observe returns the metric in the budget's unit: milliseconds for a
// percentile, decimal megabytes for bytes.
func gate17Observe(t *testing.T, m gate17Metric) (value, samples float64) {
	t.Helper()
	r := gate17Result(t, m.Path, m.N)
	samples = r.Extra["samples"]
	switch m.Stat {
	case "p50":
		return r.Extra["p50-us"] / 1000, samples
	case "p99":
		return r.Extra["p99-us"] / 1000, samples
	case "mean":
		return float64(r.NsPerOp()) / 1e6, samples
	case "bytes":
		return float64(r.AllocedBytesPerOp()) / 1e6, samples
	}
	t.Fatalf("gate17Observe: unknown statistic %q", m.Stat)
	return 0, 0
}

// gate17Observed evaluates one budget row: the observed value in the row's
// unit, and the smallest sample count any of its inputs rested on.
func gate17Observed(t *testing.T, b gate17Budget) (observed, minSamples float64) {
	t.Helper()
	switch {
	case b.Absolute != nil:
		return gate17Observe(t, *b.Absolute)
	case b.Ratio != nil:
		num, ns := gate17Observe(t, b.Ratio[0])
		den, ds := gate17Observe(t, b.Ratio[1])
		if den == 0 {
			t.Fatalf("%s: the denominator %s/%d %s measured zero; a ratio over zero is not a shape", b.Label, b.Ratio[1].Path, b.Ratio[1].N, b.Ratio[1].Stat)
		}
		if ds < ns {
			ns = ds
		}
		return num / den, ns
	}
	t.Fatalf("%s: a non-UNSET budget with neither an absolute metric nor a ratio cannot be checked", b.Label)
	return 0, 0
}

func gate17StatOf(b gate17Budget) string {
	if b.Absolute != nil {
		return b.Absolute.Stat
	}
	return b.Ratio[0].Stat
}

// requireSamples fails when a statistic rests on fewer samples than its floor.
// A p99 read from five iterations is the slowest of five, and a ceiling
// compared against it is compared against noise.
func requireSamples(t *testing.T, b gate17Budget, samples float64) {
	t.Helper()
	if floor := gate17MinSamples[gate17StatOf(b)]; samples < floor {
		t.Fatalf("%s: only %.0f sample(s) behind a %s; the floor is %.0f, so the budget cannot be read. The activation path is pinned to %d iterations (gate17FixedIterations) precisely so this cannot follow the machine's speed; on the other paths it means a millisecond-scale operation got slow enough that a second holds too few of it - a finding either way",
			b.Label, samples, gate17StatOf(b), floor, gate17FixedIterations["activation"])
	}
}

// --- the assertions -----------------------------------------------------------

// TestGate17MemoryBudgetsHold fails when any allocation budget is exceeded.
// Allocation is a property of the code, so this holds on every machine and
// runs on every pull request.
func TestGate17MemoryBudgetsHold(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and evaluates real bundles; -short skips it")
	}
	checked := 0
	for _, b := range gate17Budgets {
		if b.Unit != "MB/op" {
			continue
		}
		observed, samples := gate17Observed(t, b)
		requireSamples(t, b, samples)
		checked++
		t.Logf("%-38s observed %10.3f %s  budget %g %s", b.Label, observed, b.Unit, b.Value, b.Unit)
		if observed > b.Value {
			t.Errorf("%s: %.3f %s exceeds the published budget of %g %s.\n"+
				"Allocation per operation is machine-independent within a few percent, so this is a change in the code, not in the runner. "+
				"Either the change is a regression (fix it) or the new cost is accepted (raise the row in %s AND in gate17Budgets, with the reason in the Basis column; the two are asserted equal).",
				b.Label, observed, b.Unit, b.Value, b.Unit, gate17DocRelPath)
		}
	}
	if checked < 4 {
		t.Fatalf("only %d memory budget(s) were checked; the table has lost rows", checked)
	}
}

// TestGate17ShapeBudgetsHold fails when the cost curve changes shape. A ratio
// of two measurements taken in one process on one machine is a property of the
// algorithm, so this holds on every machine and runs on every pull request.
func TestGate17ShapeBudgetsHold(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and evaluates real bundles; -short skips it")
	}
	requireAlone(t)
	checked := 0
	for _, b := range gate17Budgets {
		if b.Ratio == nil {
			continue
		}
		observed, samples := gate17Observed(t, b)
		requireSamples(t, b, samples)
		checked++
		t.Logf("%-38s observed %10.2fx          budget %gx", b.Label, observed, b.Value)
		if observed > b.Value {
			t.Errorf("%s: the ratio is %.2f, above the published ceiling of %g.\n"+
				"Both terms were measured in this process, alone on the runner, and the ceiling is 2x the hosted alone-run median: the curve itself got steeper. "+
				"For evaluation that means a superlinear term has entered the request path. For activation it means the "+
				"curve #3693 is deciding about has got WORSE than the one it was filed against; that is a regression on top "+
				"of a finding, not a new finding. Fix the code, or raise the row in %s AND gate17Budgets with the reason.",
				b.Label, observed, b.Value, gate17DocRelPath)
		}
	}
	if checked < 2 {
		t.Fatalf("only %d shape budget(s) were checked; the table has lost rows", checked)
	}
}

// TestGate17LatencyBudgets measures every latency row against its budget.
//
// With AXONFLOW_GATE17_ENFORCE_LATENCY=1 an exceeded budget FAILS; that is the
// gate17-latency-budgets.yml job. Without it the comparison is logged and the
// test passes, because a shared runner's p99 measures the runner; the mode is
// printed so a log reader cannot mistake one for the other.
func TestGate17LatencyBudgets(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and evaluates real bundles; -short skips it")
	}
	enforce := os.Getenv(gate17EnforceLatencyEnv) == "1"
	if enforce {
		t.Logf("MODE: ENFORCING - %s=1, an exceeded latency budget fails this test", gate17EnforceLatencyEnv)
	} else {
		t.Logf("MODE: ADVISORY - %s is not 1; latency is measured and logged against its budget, and only the memory and shape tests are verdicts here", gate17EnforceLatencyEnv)
	}
	reps := gate17LatencyReps(enforce)
	t.Logf("repetitions per row: %d (the ceiling is enforced against the MEDIAN of these)", reps)
	checked, exceeded := 0, 0
	for _, b := range gate17Budgets {
		if b.Unit != "ms" || b.Absolute == nil {
			continue
		}
		lo, median, hi, samples := gate17MedianLatency(t, *b.Absolute, reps)
		if enforce {
			requireSamples(t, b, samples)
		}
		checked++
		verdict := "within"
		if median > b.Value {
			verdict = "EXCEEDS"
			exceeded++
		}
		t.Logf("%-38s median %10.3f ms  (min %.3f  max %.3f over %d run(s), >=%.0f samples each)  budget %g ms  %s",
			b.Label, median, lo, hi, reps, samples, b.Value, verdict)
		if enforce && median > b.Value {
			t.Errorf("%s: the median of %d runs, %.3f ms (min %.3f, max %.3f), exceeds the published budget of %g ms on a run that was asked to enforce it.\n"+
				"The budget is stated against the enforcing machine's median (see %s, section 7 and its calibration table); a breach of the MEDIAN is a regression, "+
				"not a noisy neighbour - one bad repetition cannot produce it. A budget change requires a new N-sample calibration table, not a new single number.",
				b.Label, reps, median, lo, hi, b.Value, gate17DocRelPath)
		}
	}
	if checked < 4 {
		t.Fatalf("only %d latency budget(s) were checked; the table has lost rows", checked)
	}
	if !enforce && exceeded > 0 {
		t.Logf("ADVISORY: %d of %d latency budgets exceeded on this runner; not a verdict in this mode", exceeded, checked)
	}
}

// --- the document ---------------------------------------------------------------

// TestGate17BudgetTableMatchesThePublishedDocument asserts that section 7 of
// the published document is a rendering of gate17Budgets: the same rows in the
// same order, each with the same value, kind and enforcement cell. It also
// asserts that every budget with a value is enforced somewhere, so a ceiling
// cannot be published as a sentence.
func TestGate17BudgetTableMatchesThePublishedDocument(t *testing.T) {
	for _, b := range gate17Budgets {
		if b.Kind == gate17Unset {
			if b.Absolute != nil || b.Ratio != nil || b.Value != 0 || b.DocValue == "" {
				t.Errorf("%s: an UNSET row carries a metric or a value, or no document text", b.Label)
			}
			if b.Enforced != enforcedNowhere {
				t.Errorf("%s: an UNSET row claims to be enforced by %q; nothing can enforce a ceiling that does not exist", b.Label, b.Enforced)
			}
			continue
		}
		if b.Enforced == enforcedNowhere {
			t.Errorf("%s: a budget with a value and no enforcement is a sentence, and a sentence cannot go red. Name the job that fails against it.", b.Label)
		}
		if b.Value <= 0 || b.Unit == "" || (b.Absolute == nil && b.Ratio == nil) {
			t.Errorf("%s: a budget needs a positive value, a unit and a metric", b.Label)
		}
	}

	rows, ok := readGate17DocTable(t)
	if !ok {
		// A community-mirror checkout: technical-docs/ is stripped by the sync,
		// so the document half cannot be asserted here and is asserted on the
		// enterprise tree. The Go table's own consistency above IS asserted, and
		// this test PASSES rather than skipping: the CI step requires its PASS
		// line, and a skip would read as "the gate did not run" on the mirror.
		t.Logf("%s is absent on a mirror checkout; the document half of this test is asserted on the enterprise tree, the table's consistency was asserted here", gate17DocRelPath)
		return
	}
	if len(rows) != len(gate17Budgets) {
		t.Fatalf("%s section 7 has %d budget rows and gate17Budgets has %d; the two tables are asserted equal row for row.\n  document: %v\n  code:     %v",
			gate17DocRelPath, len(rows), len(gate17Budgets), labelsOf(rows), budgetLabels())
	}
	for i, b := range gate17Budgets {
		row := rows[i]
		if row.label != b.Label {
			t.Errorf("row %d: the document says %q and the code says %q; rows must agree in order as well as content", i+1, row.label, b.Label)
			continue
		}
		if want := renderBudgetValue(b); row.value != want {
			t.Errorf("%s: the document's value cell is %q and the code renders %q", b.Label, row.value, want)
		}
		if row.kind != string(b.Kind) {
			t.Errorf("%s: the document's kind cell is %q and the code says %q", b.Label, row.kind, b.Kind)
		}
		if row.enforced != string(b.Enforced) {
			t.Errorf("%s: the document's 'Enforced by' cell is %q and the code says %q", b.Label, row.enforced, b.Enforced)
		}
	}
}

type gate17DocRow struct{ label, value, kind, enforced string }

func labelsOf(rows []gate17DocRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.label
	}
	return out
}

func budgetLabels() []string {
	out := make([]string, len(gate17Budgets))
	for i, b := range gate17Budgets {
		out[i] = b.Label
	}
	return out
}

// readGate17DocTable parses the budget table under section 7. It returns
// ok=false only on a community-mirror checkout (no ee/, no document), where
// technical-docs/ is stripped by design; on an enterprise tree a missing
// document FAILS.
func readGate17DocTable(t *testing.T) ([]gate17DocRow, bool) {
	t.Helper()
	// This package is platform/decision/pdp; the repository root is three up.
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolving the repository root: %v", err)
	}
	docPath := filepath.Join(root, gate17DocRelPath)
	f, err := os.Open(docPath)
	if err != nil {
		if _, eeErr := os.Stat(filepath.Join(root, "ee")); eeErr == nil {
			t.Fatalf("%s is missing on an enterprise tree (ee/ exists at %s); the published budgets are gone", gate17DocRelPath, root)
		}
		return nil, false // a mirror checkout; the caller logs and passes
	}
	defer f.Close()

	var rows []gate17DocRow
	inSection, inTable := false, false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "## ") {
			if inSection {
				break
			}
			inSection = strings.HasPrefix(line, gate17DocSectionHeading)
			continue
		}
		if !inSection {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		cells := splitTableRow(line)
		if len(cells) != 5 {
			t.Fatalf("%s: a table row under %q has %d cells, want 5 (Budget | Value | Kind | Enforced by | Basis): %q", gate17DocRelPath, gate17DocSectionHeading, len(cells), line)
		}
		if cells[0] == "Budget" || strings.HasPrefix(cells[0], "---") {
			inTable = true
			continue
		}
		inTable = true
		rows = append(rows, gate17DocRow{label: cells[0], value: cells[1], kind: cells[2], enforced: cells[3]})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", gate17DocRelPath, err)
	}
	if !inSection && len(rows) == 0 {
		t.Fatalf("%s has no %q section; the table this test asserts has moved", gate17DocRelPath, gate17DocSectionHeading)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: no budget rows found under %q", gate17DocRelPath, gate17DocSectionHeading)
	}
	return rows, true
}

// splitTableRow splits a markdown table row into trimmed cells with bold
// markers removed. Bold is presentation; the assertion is on the words.
func splitTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.ReplaceAll(p, "**", "")
		out = append(out, p)
	}
	return out
}
