// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// TestTheSyntheticLabelIsResolvedFromTheSharedHeaderContract is the whole point
// of #3817 stated as one assertion: a comparison's `synthetic` label comes from
// the identity axis's header contract and from nothing else.
//
// The alternative every review of this change has to rule out is a
// tenant-NAME prefix, or a source IP, or a dedicated canary organization. Each
// of those can be read off a request too, and each is worse in the same
// direction: it lets a deployment MANUFACTURE coverage by naming a tenant
// `synthetic-*`, and it puts a second definition of one word beside the
// identity axis's. The header contract's forgery direction only ever EXCLUDES
// the forger's own traffic from a volume floor, which makes the gate harder to
// satisfy - see identity.LegacyAuth.Synthetic.
func TestTheSyntheticLabelIsResolvedFromTheSharedHeaderContract(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		set    bool
		want   bool
	}{
		{"the canary's spelling", "1", true, true},
		{"the canary's other spelling", "true", true, true},
		{"mixed case and padding, as a proxy may rewrite it", "  TRUE  ", true, true},
		{"a caller turning it OFF explicitly", "0", true, false},
		{"the word false", "false", true, false},
		{"a proxy echoing an empty value", "", true, false},
		{"an arbitrary value", "yes-please", true, false},
		{"no header at all - the ORGANIC default", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", strings.NewReader("{}"))
			if tc.set {
				r.Header.Set(identity.SyntheticProbeHeader, tc.header)
			}

			var got bool
			identity.SyntheticProbeMiddleware(http.HandlerFunc(
				func(_ http.ResponseWriter, inner *http.Request) {
					got = identity.SyntheticProbeFromContext(inner.Context())
				})).ServeHTTP(httptest.NewRecorder(), r)

			if got != tc.want {
				t.Fatalf("header %q (set=%v) resolved to synthetic=%v, want %v. The label the "+
					"ADR-065 volume floor is read on is this value; a spelling that resolves the "+
					"wrong way moves traffic between the organic and the canary bucket with "+
					"nothing else changing.", tc.header, tc.set, got, tc.want)
			}
		})
	}
}

// TestASyntheticObservationLandsInTheSyntheticSeriesEndToEnd drives the REAL
// path - middleware, context, Observe, worker, recorder, counters - and reads
// the counters back.
//
// It is deliberately not a unit test of syntheticLabel. The failure this change
// exists to prevent is a THREAD that breaks somewhere between the request and
// the series, and every individual link can be correct while the chain is not:
// the worker runs under a context.Background() of its own, so a recorder that
// re-read the context instead of the observation would file 100% of the canary
// as organic and every unit test would stay green.
func TestASyntheticObservationLandsInTheSyntheticSeriesEndToEnd(t *testing.T) {
	rec := newCapturingRecorder(2)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow),
		withMetricsBarrier(rec, MetricsRecorder{}))

	plane := legacycompile.PlaneGatewayRequest
	beforeSynthetic := comparedCount(t, plane, SyntheticTrue)
	beforeOrganic := comparedCount(t, plane, SyntheticFalse)
	// DELTAS, not absolutes. The default registry is shared with every other
	// test in this package, several of which now drive synthetic comparisons of
	// their own, so `> 0` on the recorder's counters could be satisfied by a
	// neighbour and would let the hard-coded-label mutant survive again.
	beforeCmpSynthetic := comparisonClassTotal(t, plane, SyntheticTrue)
	beforeCmpOrganic := comparisonClassTotal(t, plane, SyntheticFalse)
	beforeFOSynthetic := failOpenTotal(t, plane, SyntheticTrue)
	beforeFOOrganic := failOpenTotal(t, plane, SyntheticFalse)

	// The synthetic one, stamped exactly as the middleware stamps it.
	o.Observe(identity.ContextWithSyntheticProbe(context.Background(), true), fixtureObservation(true, false))
	// The organic one, from a context nobody stamped.
	o.Observe(context.Background(), fixtureObservation(true, false))

	got := rec.wait(t)
	if len(got) != 2 {
		t.Fatalf("expected two comparisons, got %d", len(got))
	}
	var sawSynthetic, sawOrganic bool
	for _, c := range got {
		if c.Synthetic {
			sawSynthetic = true
		} else {
			sawOrganic = true
		}
	}
	if !sawSynthetic {
		t.Error("no comparison carried Synthetic=true; the fact did not survive the queue, so " +
			"every canary comparison would be recorded as tenant traffic and the ADR-065 volume " +
			"floor would be read off our own probe (#3817)")
	}
	if !sawOrganic {
		t.Error("no comparison carried Synthetic=false; the stamp is being applied to everything, " +
			"which empties the organic denominator the floor is stated in - the opposite defect " +
			"and equally unreadable")
	}

	if afterSynthetic := comparedCount(t, plane, SyntheticTrue); afterSynthetic <= beforeSynthetic {
		t.Errorf("observations_total{disposition=compared,synthetic=true} did not move (%v -> %v)",
			beforeSynthetic, afterSynthetic)
	}
	if afterOrganic := comparedCount(t, plane, SyntheticFalse); afterOrganic <= beforeOrganic {
		t.Errorf("observations_total{disposition=compared,synthetic=false} did not move (%v -> %v)",
			beforeOrganic, afterOrganic)
	}

	// AND THE OTHER TWO COUNTERS, which are written by a DIFFERENT function
	// (MetricsRecorder.RecordComparison, on the worker) from a DIFFERENT source
	// (the Comparison rather than the Observation).
	//
	// The mutation gate found this gap by hard-coding the recorder's label to
	// false: the assertions above all still passed, because none of them reads a
	// series the recorder writes. Two write sites resolving one fact separately
	// is exactly where a thread breaks in half, so both are read here.
	cmpSynthetic := comparisonClassTotal(t, plane, SyntheticTrue)
	cmpOrganic := comparisonClassTotal(t, plane, SyntheticFalse)
	foSynthetic := failOpenTotal(t, plane, SyntheticTrue)
	foOrganic := failOpenTotal(t, plane, SyntheticFalse)

	if cmpSynthetic != beforeCmpSynthetic+1 {
		t.Errorf("comparisons_total{plane=%q,synthetic=true} went %v -> %v, want exactly one more. "+
			"%s. If it is the labelling: the recorder filed the canary's comparison as organic, so "+
			"the ADR-065 volume floor would be read off our own probe",
			plane, beforeCmpSynthetic, cmpSynthetic,
			deltaDiagnosis(cmpSynthetic-beforeCmpSynthetic, cmpOrganic-beforeCmpOrganic))
	}
	if foSynthetic != beforeFOSynthetic+1 {
		t.Errorf("fail_open_total{plane=%q,synthetic=true} went %v -> %v, want exactly one more. "+
			"%s. If it is the labelling: the gate-18 numerator cannot be split "+
			"organic-from-canary, so a fail-open the canary provokes would be reported as a "+
			"finding about tenant traffic",
			plane, beforeFOSynthetic, foSynthetic,
			deltaDiagnosis(foSynthetic-beforeFOSynthetic, foOrganic-beforeFOOrganic))
	}
	if cmpOrganic != beforeCmpOrganic+1 {
		t.Errorf("comparisons_total{plane=%q,synthetic=false} went %v -> %v, want exactly one more. "+
			"%s. If it is the labelling: the recorder is filing everything as synthetic, which "+
			"empties the organic denominator",
			plane, beforeCmpOrganic, cmpOrganic,
			deltaDiagnosis(cmpOrganic-beforeCmpOrganic, cmpSynthetic-beforeCmpSynthetic))
	}
}

// deltaDiagnosis names what a wrong delta on a shared counter can MEAN, because
// the message this test used to print asserted one cause while observing a
// symptom three causes share (#3858).
//
// The CI failure it was written for read
// `comparisons_total{plane="gateway_request",synthetic=false} went 65 -> 65 ...
// the recorder is filing everything as synthetic`. The recorder was doing no
// such thing: the read had raced the write. A message that names a cause it
// cannot distinguish sends the next reader to the wrong file, and this package
// is the one whose red board an operator has to be able to trust.
//
// `other` is the delta on the SAME counter's opposite synthetic value, which is
// what separates a mislabelling from everything else: a comparison filed under
// the wrong label is missing here and present there.
func deltaDiagnosis(delta, other float64) string {
	switch {
	case delta == 0 && other >= 2:
		return "This series did not move and its opposite moved twice, so a comparison was " +
			"filed under the WRONG synthetic value - a labelling defect"
	case delta == 0:
		return "NOTHING reached this series before it was read, and the opposite series did " +
			"not absorb it either, so this is not a mislabelling. Either the recorder does not " +
			"write this series at all, or the read raced the write - withMetricsBarrier is what " +
			"makes the second impossible, so check that this test still uses it"
	case delta >= 2 && other == 0:
		// THE GAINING SIDE OF THE SAME MISLABELLING. Case 1 sees it from the
		// series that LOST a comparison; this is the series that gained one, and
		// the first version of this function called it "another writer" - naming
		// a cause it cannot distinguish, in the arm added to stop exactly that.
		// A recorder filing everything under one label produces delta=2, other=0
		// here; so does a stray writer that happens to hit only this series. Both
		// are named, because both are consistent with what was observed.
		return "BOTH of this test's comparisons landed in this series and NONE in its " +
			"opposite, which is what a recorder filing everything under one label " +
			"produces - most likely a labelling defect, seen from the side that gained. " +
			"A stray writer hitting only this series produces the same numbers; the " +
			"opposite series' delta is what tells them apart, and it is 0"
	case delta > 1:
		return "ANOTHER WRITER moved this counter: the delta exceeds this test's own " +
			"contribution AND the opposite series also moved, so a sibling test or a " +
			"still-draining worker wrote the same series"
	default:
		return "The counter moved by an amount this test did not produce"
	}
}

// comparisonClassTotal sums comparisons_total for one plane and one synthetic
// value across every classification.
//
// SUMMED rather than read at one classification, because the class a fixture
// comparison lands in is decided by the classifier and is not this test's
// subject: pinning one would make the assertion fail whenever the translation
// improved, which is the mistake the mutation gate's own history records
// ("the mutant was keyed on a value the code under test can legitimately move").
func comparisonClassTotal(t *testing.T, plane legacycompile.Plane, synthetic string) float64 {
	t.Helper()
	return sumSeries(t, shadowComparisons, map[string]string{
		"plane": string(plane), LabelSynthetic: synthetic,
	})
}

// failOpenTotal is comparisonClassTotal for the fail-open counter, summed across
// every direction and classification for the same reason.
func failOpenTotal(t *testing.T, plane legacycompile.Plane, synthetic string) float64 {
	t.Helper()
	return sumSeries(t, shadowFailOpen, map[string]string{
		"plane": string(plane), LabelSynthetic: synthetic,
	})
}

// sumSeries collects a vector and sums every child whose labels match `want`.
//
// It COLLECTS rather than probing with WithLabelValues, because a probe
// materialises the child it asks for: a test that read a series into existence
// and then found it at zero would be reporting on its own probe. Same argument
// as vacuity_metrics_test.go's gather.
func sumSeries(t *testing.T, c prometheus.Collector, want map[string]string) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 4096)
	go func() { c.Collect(ch); close(ch) }()
	total := 0.0
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("writing a collected metric: %v", err)
		}
		labels := map[string]string{}
		for _, lp := range d.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
				break
			}
		}
		if match {
			total += d.GetCounter().GetValue()
		}
	}
	return total
}

// TestEveryDispositionCarriesTheSyntheticLabel proves the label is on the WHOLE
// counter and not only on the compared child.
//
// A hole in the denominator is attributed to whoever produced it. A canary
// whose observations are all `sampled_out` or `dropped`, counted as ORGANIC,
// would tell an operator that TENANT traffic is being lost on that plane - and
// send the investigation to the tenant instead of to the probe's rate.
func TestEveryDispositionCarriesTheSyntheticLabel(t *testing.T) {
	dispositions := AllDispositions()
	if len(dispositions) == 0 {
		t.Fatal("AllDispositions() is empty; this test would pass over nothing")
	}
	plane := legacycompile.PlaneGatewayRequest
	for _, d := range dispositions {
		for _, synthetic := range bothSyntheticValues() {
			// WithLabelValues panics on an arity mismatch, which is the whole
			// assertion: the vector must accept (plane, disposition, synthetic).
			shadowObservations.WithLabelValues(string(plane), d, synthetic)
		}
	}
}

// TestAnUnstampedContextIsOrganicAndNotUnknown pins the DIRECTION of the
// default, which is the only judgement call in the whole label.
//
// A request that never met the stamping middleware - an internal caller, a test
// harness, a route added tomorrow that bypasses the root wrap - resolves to
// ORGANIC. That over-reports tenant volume, which is conservative for a FLOOR:
// an operator reads more evidence than exists and waits longer. The opposite
// default would move real tenant traffic OUT of the volume being measured, so a
// forgotten stamp would make the floor easier to clear, silently.
func TestAnUnstampedContextIsOrganicAndNotUnknown(t *testing.T) {
	if identity.SyntheticProbeFromContext(context.Background()) {
		t.Fatal("an unstamped context resolved to synthetic; a forgotten stamp would then move " +
			"tenant traffic out of the volume floor")
	}
	//nolint:staticcheck // SA1012: a nil context is exactly the degenerate input under test.
	if identity.SyntheticProbeFromContext(nil) {
		t.Fatal("a nil context resolved to synthetic")
	}
	if syntheticLabel(false) != "false" || syntheticLabel(true) != "true" {
		t.Fatalf("syntheticLabel renders %q/%q; identity's compat_metrics.go boolLabel renders "+
			"\"false\"/\"true\", and a rule filtering synthetic=\"false\" against a series "+
			"spelling it \"0\" matches nothing and reports a vacuous window as healthy",
			syntheticLabel(false), syntheticLabel(true))
	}
}

// TestAnObservationCannotAssertItsOwnSyntheticFlag proves the field is stamped
// by Observe rather than supplied by the call site.
//
// An exported field would be nineteen call sites able to claim the canary
// bucket, and the one that got it wrong would be invisible: a comparison filed
// as synthetic is a comparison SUBTRACTED from the volume floor, so a plane
// could be talked out of its own evidence.
func TestAnObservationCannotAssertItsOwnSyntheticFlag(t *testing.T) {
	obs := fixtureObservation(true, false)
	if obs.Synthetic() {
		t.Fatal("a freshly constructed Observation claims to be synthetic")
	}

	rec := newCapturingRecorder(1)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), rec)
	// The context says organic. If the call site could assert the flag, this is
	// where it would win.
	o.Observe(context.Background(), obs)
	if got := rec.wait(t); got[0].Synthetic {
		t.Fatal("the comparison is synthetic although the context was not stamped; the call site " +
			"can assert its way into the canary bucket and out of the volume floor")
	}
}

// comparedCount reads one child of the observation counter off the DEFAULT
// registry through the vector itself.
//
// ToFloat64 on a child materialises it, which is safe here and only here: both
// synthetic values of the compared child are pre-created at init, so this probe
// cannot create a series that would not otherwise exist. Every other child is
// read by gathering, in vacuity_metrics_test.go, for exactly that reason.
func comparedCount(t *testing.T, plane legacycompile.Plane, synthetic string) float64 {
	t.Helper()
	c, err := shadowObservations.GetMetricWithLabelValues(string(plane), dispositionCompared, synthetic)
	if err != nil {
		t.Fatalf("reading observations_total{plane=%q,disposition=compared,synthetic=%q}: %v", plane, synthetic, err)
	}
	return testutil.ToFloat64(c)
}

var _ prometheus.Collector = shadowObservations

// TestTheCompletionBarrierWaitsForItsSiblingsNotJustForItself pins the
// happens-before that #3858 was a symptom of.
//
// THE FLAKE, and why it read as a labelling defect. The end-to-end test above
// used `MultiRecorder{rec, MetricsRecorder{}}`. MultiRecorder calls its members
// in order, so the capturing recorder closed its `done` channel on the LAST
// comparison BEFORE MetricsRecorder had recorded that same comparison - and
// `wait` returned with the metric write still outstanding. The counter read
// next then showed the value it had before: `65 -> 65` on CI, always the last
// comparison, always the counter written by the member that ran after the
// barrier. The message blamed the recorder's labelling, which is a different
// defect that produces the same zero delta.
//
// WHY THIS TEST IS DETERMINISTIC AND THE FLAKE WAS NOT. A race reproduces on a
// loaded runner and not on a developer's machine, which is how it survived two
// green local runs at `-count=1`. `slowRecorder` does not change any semantics -
// the ordering was always sequential - it widens the existing window to a size
// the test can observe every time. Swap `withMetricsBarrier` here for
// `MultiRecorder{rec, slowRecorder{MetricsRecorder{}}}` and this fails on every
// run; that is the control, and it is the shape the flake had.
func TestTheCompletionBarrierWaitsForItsSiblingsNotJustForItself(t *testing.T) {
	rec := newCapturingRecorder(2)
	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow),
		withMetricsBarrier(rec, slowRecorder{MetricsRecorder{}}))

	plane := legacycompile.PlaneGatewayRequest
	before := comparisonClassTotal(t, plane, SyntheticFalse)

	o.Observe(identity.ContextWithSyntheticProbe(context.Background(), true), fixtureObservation(true, false))
	o.Observe(context.Background(), fixtureObservation(true, false))
	rec.wait(t)

	if got := comparisonClassTotal(t, plane, SyntheticFalse); got != before+1 {
		t.Fatalf("comparisons_total{plane=%q,synthetic=false} went %v -> %v after wait() "+
			"returned, want exactly one more. The barrier signalled before its sibling "+
			"recorder finished writing, so any counter read after wait() is a read of the "+
			"value before this test's own comparison. %s",
			plane, before, got, deltaDiagnosis(got-before, 0))
	}
}

// slowRecorder is a recorder that has not finished when a barrier beside it
// fires. It exists only to make the window in the test above observable on
// every run instead of on a loaded one.
type slowRecorder struct{ inner Recorder }

func (s slowRecorder) RecordComparison(ctx context.Context, c Comparison) {
	time.Sleep(50 * time.Millisecond)
	s.inner.RecordComparison(ctx, c)
}

// TestDeltaDiagnosisNamesOnlyWhatTheNumbersSupport pins the function that
// exists because the ORIGINAL failure message asserted a cause it could not
// observe. An arm of it that does the same thing is the defect surviving inside
// its own fix, so each arm is driven and read (#3858).
func TestDeltaDiagnosisNamesOnlyWhatTheNumbersSupport(t *testing.T) {
	for _, tc := range []struct {
		name         string
		delta, other float64
		want         string
		refuse       string
	}{
		{"the LOSING side of a mislabelling", 0, 2, "WRONG synthetic value", ""},
		// THE ARM THAT WAS WRONG. delta=2/other=0 is exactly what a recorder
		// filing everything under one label produces, and the first version
		// called it "ANOTHER WRITER" - naming a cause it cannot distinguish.
		{"the GAINING side of the same mislabelling", 2, 0, "labelling defect", "ANOTHER WRITER moved"},
		{"a genuine second writer", 2, 1, "ANOTHER WRITER", "labelling defect"},
		{"nothing recorded before the read", 0, 0, "NOTHING reached this series", "mislabelling defect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deltaDiagnosis(tc.delta, tc.other)
			if !strings.Contains(got, tc.want) {
				t.Errorf("delta=%v other=%v did not say %q: %s", tc.delta, tc.other, tc.want, got)
			}
			if tc.refuse != "" && strings.Contains(got, tc.refuse) {
				t.Errorf("delta=%v other=%v ASSERTED %q, a cause these numbers do not "+
					"distinguish: %s", tc.delta, tc.other, tc.refuse, got)
			}
		})
	}
}
