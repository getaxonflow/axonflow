// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/legacycompile/shadow"
	"axonflow/platform/shared/identity"
	"axonflow/platform/shared/metricdomain"
)

// ---------------------------------------------------------------------------
// THE LABEL-DOMAIN CENSUS FOR THE DECISION-SHADOW COUNTERS (#3817).
//
// # WHY IT LIVES HERE AND NOT IN platform/agent's GUARDED SET
//
// #3704's disposition names platform/agent's label-domain guard as the pattern,
// and this is that pattern - the same platform/shared/metricdomain package, the
// same two halves that fail for different reasons. What it is NOT is a copy of
// that guard extended to reach across a package boundary, and the reason is
// mechanical rather than stylistic: the vectors below are UNEXPORTED, so a
// census in package agent could neither hand them to metricdomain.Check nor
// drive Observe's real write sites with the queue and worker this package owns.
// It would have had to gather the default registry and match by metric name,
// which is a second mechanism with a different failure mode - exactly the
// redundancy this session is supposed to refuse.
//
// The two halves, restated because they fail for different reasons:
//
//	CENSUS       every label of every metric vector DECLARED IN metrics.go has a
//	             declared domain, and every declared domain names a live label.
//	             Derived from the SOURCE, so a new metric or a new label position
//	             fails here until somebody decides what bounds it.
//	BEHAVIOURAL  the real write sites are DRIVEN and every emitted value must
//	             land inside its declared domain.
//
// Neither is sufficient alone. The census cannot see a value; the behavioural
// half cannot see a metric nobody drove. #3817's own change is the case in
// point: adding `synthetic` to three vectors passes any list-vs-list test the
// moment both lists are edited, and it is the EDIT that needed a decision.
// ---------------------------------------------------------------------------

// shadowMetricDomains declares, per metric and per label, what bounds the value.
//
// Every Why says WHERE THE VALUE COMES FROM and WHAT COLLAPSES IT. The value
// list alone is a set of strings the next reader has to re-derive from the call
// sites, which is the work the declaration exists to save.
//
// Every vocabulary is DERIVED from the package that owns it - ImplementedPlanes,
// AllDispositions, shadow's own constants, identity.DecisionShadowModeNames -
// and never hand-copied. A hand-written list beside the declaration can only
// fail if somebody edits one of two adjacent lists, which is the shape #3720
// says is blind.
func shadowMetricDomains() map[string]map[string]metricdomain.Domain {
	plane := metricdomain.Closed(
		"legacycompile.Plane, funnelled through Observation.Validate - which REFUSES a plane "+
			"that is not in the declared census - and then through planeLabel, which folds the "+
			"empty plane onto the literal \"unattributed\" rather than inventing one. No caller "+
			"string reaches this label: the plane comes from EvalOptions.Plane, a typed constant "+
			"set at the observation site.",
		append(planeLabelValues(), planeLabelUnattributed)...)

	synthetic := metricdomain.Closed(
		"syntheticLabel(bool), whose input is identity.SyntheticProbeFromContext - a context "+
			"value stamped by ONE middleware from IsSyntheticProbeHeader, itself a positive "+
			"membership test on two spellings. A Go bool has two values, so the label cannot "+
			"carry a caller string even if the header did (#3817).",
		SyntheticFalse, SyntheticTrue)

	classification := metricdomain.Closed(
		"shadow.DiffRecord.Class, set by shadow.Classify on one of three branches; there is no "+
			"fall-through that carries an input string",
		string(shadow.ClassMatch), string(shadow.ClassExpectedChange), string(shadow.ClassUnexplained))

	return map[string]map[string]metricdomain.Domain{
		MetricShadowObservations: {
			"plane": plane,
			"disposition": metricdomain.Closed(
				"one of the dispositionXxx constants at every increment site; they are constants "+
					"precisely because a dashboard and an alert are written against these strings",
				AllDispositions()...),
			LabelSynthetic: synthetic,
		},
		MetricShadowComparisons: {
			"plane":          plane,
			"classification": classification,
			LabelSynthetic:   synthetic,
		},
		MetricShadowFailOpen: {
			"plane":          plane,
			"classification": classification,
			LabelSynthetic:   synthetic,
			"direction": metricdomain.Closed(
				"shadow.DiffRecord.FailOpen, derived from the two admissions rather than from any "+
					"input; the three directions are the whole product of that derivation",
				string(shadow.FailOpenNone), string(shadow.FailOpenLegacyPermitted),
				string(shadow.FailOpenNewPermitted)),
		},
		MetricShadowMode: {
			"plane": plane,
			"component": metricdomain.Closed(
				"the component name Bootstrap is called with, one per binary. It is a build-time "+
					"literal at the two call sites, never a request value.",
				"agent", "orchestrator"),
			"mode": metricdomain.Closed(
				"identity.DecisionShadowModeNames(), the closed vocabulary of this axis, iterated "+
					"in publishMode; a mode outside it cannot be published because the loop is over "+
					"the vocabulary itself",
				identity.DecisionShadowModeNames()...),
		},
		"axonflow_decision_shadow_bundle_builds_total": {
			"plane": plane,
			"outcome": metricdomain.Closed(
				"a literal at each of the three increment sites in Observer.evaluate",
				"ok", "error", "not_comparable"),
		},
		"axonflow_decision_shadow_evaluation_seconds": {
			"plane": plane,
		},
		"axonflow_decision_shadow_enqueue_seconds": {
			"plane": plane,
			"recorded": metricdomain.Closed(
				"a literal at each of the two Observe sites: \"false\" for the population whose "+
					"resolved mode does not record and \"true\" for the one that enqueued",
				"false", "true"),
		},
	}
}

// planeLabelUnattributed is planeLabel's fold for the empty plane. Spelled here
// as the literal the label carries, because that is what a dashboard matches.
const planeLabelUnattributed = "unattributed"

func planeLabelValues() []string {
	planes := ImplementedPlanes()
	out := make([]string, 0, len(planes))
	for _, p := range planes {
		out = append(out, string(p))
	}
	return out
}

// TestEveryShadowMetricLabelHasADeclaredDomain is the CENSUS half, derived from
// metrics.go's source rather than from a list of metrics.
//
// A new metric vector in metrics.go, or a new label position on an existing one,
// fails here until somebody states what bounds it. That is the forcing function
// a list-vs-list test cannot provide.
func TestEveryShadowMetricLabelHasADeclaredDomain(t *testing.T) {
	derived := deriveShadowMetrics(t)
	domains := shadowMetricDomains()

	// ANTI-VACUITY. A parse that found nothing satisfies every loop below, and
	// a broken extraction reports a fully declared package.
	if len(derived) == 0 {
		t.Fatal("the census derived zero metric vectors from this package; the extraction, not " +
			"the code, is broken - and a broken extraction reports a fully declared package")
	}

	declared := map[string]bool{}
	for _, m := range derived {
		declared[m.name] = true
		byLabel, ok := domains[m.name]
		if !ok {
			t.Errorf("%s:%d declares %s with labels %v and no domain declaration.\n\n"+
				"Every label is a cardinality decision. State where each value comes from and what "+
				"collapses an out-of-domain one, in shadowMetricDomains().",
				m.file, m.line, m.name, m.labels)
			continue
		}
		for _, label := range m.labels {
			if _, ok := byLabel[label]; !ok {
				t.Errorf("%s:%d declares %s with label %q, which has no declared domain",
					m.file, m.line, m.name, label)
			}
		}
		for label := range byLabel {
			if !contains(m.labels, label) {
				t.Errorf("shadowMetricDomains() declares a domain for %s label %q, which the metric "+
					"does not carry. A domain for a dead label is a claim nothing can violate, and it "+
					"is how a declaration outlives the thing it described.", m.name, label)
			}
		}
	}
	for name := range domains {
		if !declared[name] {
			t.Errorf("shadowMetricDomains() declares domains for %q, which NO non-test file in "+
				"this package declares. Either the metric was renamed - in which case its real "+
				"labels are now unguarded - or this entry is stale.", name)
		}
	}
}

// TestTheDrivenShadowWriteSitesEmitOnlyDeclaredValues is the BEHAVIOURAL half.
//
// It drives the REAL write sites - Observe, its refusal and not-comparable
// helpers, the worker and MetricsRecorder - with the inputs a caller can
// actually influence, and asserts every emitted label value lands inside its
// declared domain. The census above cannot see a value; this cannot see a metric
// nobody drove; metricdomain.Check refuses a collector with no series for
// exactly that reason.
//
// The hostile inputs are the ones a REQUEST can move: the synthetic header (the
// only new caller-assertable channel in #3817) and the plane a call site names.
// A tenant cannot choose a disposition, a classification or a fail-open
// direction - those are derived - so the interesting question for them is the
// census one, and it is asked above.
func TestTheDrivenShadowWriteSitesEmitOnlyDeclaredValues(t *testing.T) {
	rec := newCapturingRecorder(2)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow),
		withMetricsBarrier(rec, MetricsRecorder{}))

	// (1) A synthetic comparison and (2) an organic one, through the whole path.
	o.Observe(identity.ContextWithSyntheticProbe(context.Background(), true), fixtureObservation(true, false))
	o.Observe(identity.ContextWithSyntheticProbe(context.Background(), false), fixtureObservation(false, true))
	rec.wait(t)

	// (3) The refusal and not-comparable helpers, on both synthetic values, and
	// (4) the unattributed fold - a call site that named NO plane, which is the
	// one input that reaches planeLabel's else branch.
	for _, synthetic := range []bool{true, false} {
		ctx := identity.ContextWithSyntheticProbe(context.Background(), synthetic)
		NoteRefused(ctx, legacycompile.PlaneMCP, "driver: a refusal from a site that named a plane")
		NoteRefused(ctx, "", "driver: a refusal from a site that named NO plane")
		NoteNotComparable(ctx, legacycompile.PlaneWCP, "driver: an ordinary incomparable pair")
	}

	// (5) The mode gauge, for both components, which publishMode writes at boot.
	for _, component := range []string{"agent", "orchestrator"} {
		publishMode(component, func(legacycompile.Plane) bool { return true }, identity.CompatModeShadow)
	}

	domains := shadowMetricDomains()
	for name, collector := range map[string]prometheus.Collector{
		MetricShadowObservations:                       shadowObservations,
		MetricShadowComparisons:                        shadowComparisons,
		MetricShadowFailOpen:                           shadowFailOpen,
		MetricShadowMode:                               shadowMode,
		"axonflow_decision_shadow_bundle_builds_total": shadowBundleBuilds,
		"axonflow_decision_shadow_evaluation_seconds":  shadowLatency,
		"axonflow_decision_shadow_enqueue_seconds":     shadowEnqueueLatency,
	} {
		byLabel, ok := domains[name]
		if !ok {
			t.Errorf("no declared domain for %s; the census half should have caught this first", name)
			continue
		}
		for _, problem := range metricdomain.Check(name, collector, byLabel) {
			t.Error(problem)
		}
	}

	// ── the anti-vacuity floor, on the driver that just ran ────────────────
	//
	// metricdomain.Check refuses a collector with NO series, but it cannot know
	// that a driver reached only HALF of a two-valued label - and a driver that
	// only ever emitted synthetic="false" would report the whole domain as
	// satisfied while saying nothing about the value #3817 exists to add.
	//
	// IT READS `refused`, NOT `compared`, AND IT LIVES HERE RATHER THAN IN ITS
	// OWN TEST. Both were R3 round 1 findings on the first version (F2):
	//
	//   - `compared` has BOTH synthetic children pre-created at init for all
	//     twelve planes, so a floor over it was satisfied before any driver ran.
	//     Deleting every driver call above would have left it green - precisely
	//     the case it claims to catch. `refused` is pre-created for nothing, so
	//     its children exist only because the driver called NoteRefused on both
	//     values. Its presence IS the driver's signature.
	//   - and as a SEPARATE test it passed only when this one had already run,
	//     which makes `go test -run` on it alone fail and makes its verdict a
	//     statement about test ordering. A floor on a driver belongs in the test
	//     that drives.
	seen := map[string]bool{}
	ch := make(chan prometheus.Metric, 4096)
	go func() { shadowObservations.Collect(ch); close(ch) }()
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("writing a collected metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		if labels["disposition"] == dispositionRefused {
			seen[labels[LabelSynthetic]] = true
		}
	}
	for _, want := range bothSyntheticValues() {
		if !seen[want] {
			t.Errorf("no %s series with disposition=%q carries synthetic=%q.\n\n"+
				"That disposition is pre-created for NOTHING, so its children exist only because "+
				"the driver above called NoteRefused on that synthetic value. Its absence means the "+
				"driver stopped reaching that half of the label - and a domain checked against one "+
				"half of a two-valued label admits whatever the other half does.",
				MetricShadowObservations, dispositionRefused, want)
		}
	}
}

// --- extraction ---

type shadowMetricDecl struct {
	name   string
	labels []string
	file   string
	line   int
}

// deriveShadowMetrics parses metrics.go and returns every prometheus/promauto
// *Vec it declares, with its label names.
//
// The selector is matched on the METHOD name first and the receiver second,
// because the receiver is the part a future author varies: promauto.With(reg).
// NewCounterVec(...) has a CallExpr receiver, and requiring the identifier
// `promauto` would skip it SILENTLY - the hole #3720's R3 round found by adding
// exactly that form with an unbounded label.
func deriveShadowMetrics(t *testing.T) []shadowMetricDecl {
	t.Helper()

	// EVERY NON-TEST FILE IN THE PACKAGE, not metrics.go alone (R3 round 1, F6).
	//
	// The first version parsed metrics.go by name. A promauto.NewCounterVec
	// declared in observer.go, recorder.go or a new orgmode_metrics.go would
	// have been INVISIBLE: absent from `derived`, absent from
	// shadowMetricDomains(), and nothing would fail - the "a domain for a metric
	// metrics.go does not declare" branch only catches the other direction. All
	// nine vecs happen to live in metrics.go today, so the hole was latent, and
	// "they all live in one file" is a convention nothing enforced.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	consts := map[string]string{}
	var files []*ast.File
	var names []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(fset, name, nil, 0)
		if parseErr != nil {
			t.Fatalf("parse %s: %v", name, parseErr)
		}
		files = append(files, f)
		names = append(names, name)
		// The const table is PACKAGE-wide, because a metric declared in one file
		// may name a constant declared in another - which is exactly what a
		// per-file table would silently fail to resolve.
		for k, v := range stringConstsOf(f) {
			consts[k] = v
		}
	}
	if len(files) == 0 {
		t.Fatal("parsed zero non-test Go files; the census would derive nothing and report a " +
			"fully declared package")
	}

	var out []shadowMetricDecl
	for i, f := range files {
		file := names[i]
		out = append(out, deriveFromFile(t, fset, f, file, consts)...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

func deriveFromFile(t *testing.T, fset *token.FileSet, f *ast.File, file string, consts map[string]string) []shadowMetricDecl {
	t.Helper()
	var out []shadowMetricDecl
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !strings.HasPrefix(sel.Sel.Name, "New") || !strings.HasSuffix(sel.Sel.Name, "Vec") {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if len(call.Args) != 2 {
			// REPORTED, NEVER SKIPPED. A declaration this extraction cannot
			// read is a metric with no declared domain and no sign of it.
			t.Errorf("%s:%d declares %s with %d arguments; this census reads (opts, labels) "+
				"and cannot read this form", file, line, sel.Sel.Name, len(call.Args))
			return true
		}
		name, ok := metricNameFromOpts(call.Args[0], consts)
		if !ok {
			t.Errorf("%s:%d declares %s and this census could not extract its Name; a "+
				"declaration it cannot read is a metric with no declared domain", file, line, sel.Sel.Name)
			return true
		}
		labels, ok := stringSliceLiteral(call.Args[1], consts)
		if !ok {
			t.Errorf("%s:%d declares %s and this census could not extract its label names",
				file, line, name)
			return true
		}
		out = append(out, shadowMetricDecl{name: name, labels: labels, file: file, line: line})
		return true
	})
	return out
}

// stringConstsOf collects the file's untyped string constants, so a metric
// declared with `Name: MetricShadowObservations` resolves to its literal.
func stringConstsOf(f *ast.File) map[string]string {
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if i >= len(spec.Values) {
				continue
			}
			if s, ok := stringLiteral(spec.Values[i]); ok {
				out[name.Name] = s
			}
		}
		return true
	})
	return out
}

// metricNameFromOpts pulls Name out of a prometheus.XxxOpts composite literal.
func metricNameFromOpts(arg ast.Expr, consts map[string]string) (string, bool) {
	lit, ok := arg.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Name" {
			continue
		}
		if s, ok := stringLiteral(kv.Value); ok {
			return s, true
		}
		if id, ok := kv.Value.(*ast.Ident); ok {
			if s, ok := consts[id.Name]; ok {
				return s, true
			}
		}
		return "", false
	}
	return "", false
}

// stringSliceLiteral reads a []string{...} of literals and identifiers.
// stringSliceLiteral reads a []string{...} of literals and identifiers,
// resolving an identifier through the FILE'S OWN const table.
//
// It used to special-case the single name `LabelSynthetic`, defended as "an
// unrecognised identifier must FAIL rather than be guessed at". Resolving
// through `consts` is not a guess - it is the same resolution metricNameFromOpts
// is already trusted with, two functions up - and the fail-closed behaviour is
// preserved for free: a name not in the table still returns false, which the
// caller reports (R3 round 1, F5). The special case only created work for the
// next author who introduces a second label constant.
func stringSliceLiteral(arg ast.Expr, consts map[string]string) ([]string, bool) {
	lit, ok := arg.(*ast.CompositeLit)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		if s, ok := stringLiteral(elt); ok {
			out = append(out, s)
			continue
		}
		if id, ok := elt.(*ast.Ident); ok {
			if s, ok := consts[id.Name]; ok {
				out = append(out, s)
				continue
			}
		}
		return nil, false
	}
	return out, true
}

func stringLiteral(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
