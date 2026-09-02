// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"sort"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// TestBothGateOperandsAreExportedBeforeAnyTraffic is the regression for the
// half of the vacuity that #3607 fixed on the identity axis and left open
// here.
//
// The fail-open child was pre-created and the compared child was not, so on
// any plane that had been watched and never compared anything, gate 18's
// NUMERATOR existed at zero and its DENOMINATOR did not exist at all. "No
// unexplained fail-open difference for the agreed window" is a statement about
// a ratio; with the divisor absent the expression is not a low reading, it is
// no reading, and a v11 cutover read off these series could be authorised by
// silence.
//
// It gathers the DEFAULT registry, which is the call site: a test that ran
// preCreateGateSeries itself would prove the function correct and say nothing
// about whether init calls it.
//
// It asserts PRESENCE, not a value. Other tests in this package increment
// these counters and the default registry is shared, so an assertion that the
// compared child is exactly zero would be a statement about test ordering.
// preCreateGateSeries' own zero-ness is pinned on a fresh registry below.
func TestBothGateOperandsAreExportedBeforeAnyTraffic(t *testing.T) {
	planes := ImplementedPlanes()
	if len(planes) == 0 {
		t.Fatal("ImplementedPlanes() is empty, so this test would pass over nothing")
	}

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering the default registry: %v", err)
	}
	byName := map[string]*dto.MetricFamily{}
	for _, f := range families {
		byName[f.GetName()] = f
	}

	for _, tc := range []struct {
		metric string
		want   map[string]string
		why    string
	}{
		{
			metric: MetricShadowObservations,
			want:   map[string]string{"disposition": dispositionCompared},
			why:    "gate 18's DENOMINATOR: with no series, 'zero unexplained differences out of N' has no N and the gate evaluates over nothing",
		},
		{
			metric: MetricShadowFailOpen,
			want:   map[string]string{"direction": gateOperandDirection, "classification": gateOperandClass},
			why:    "gate 18's NUMERATOR: an alert on an absent series does not fire, so the gate's promise reads as satisfied because nothing measures it",
		},
	} {
		family := byName[tc.metric]
		if family == nil {
			t.Errorf("%s is not exported at all; a counter vector with no children renders no sample, no # HELP and no # TYPE (%s)", tc.metric, tc.why)
			continue
		}
		seen := map[string]bool{}
		for _, m := range family.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			match := true
			for k, v := range tc.want {
				if labels[k] != v {
					match = false
					break
				}
			}
			if match {
				seen[labels["plane"]] = true
			}
		}
		var missing []string
		for _, p := range planes {
			if !seen[string(p)] {
				missing = append(missing, string(p))
			}
		}
		if len(missing) > 0 {
			t.Errorf("%s%v is not pre-created for plane(s) %v; %s", tc.metric, tc.want, missing, tc.why)
		}
	}
}

// TestPreCreationIsTargetedAtTheGateOperandsOnly runs the pre-creation against
// a FRESH registry, where nothing else has written, and pins both halves of
// what it is supposed to do.
//
// The value half cannot be asserted on the default registry - this package's
// other tests increment the same children - and it is the half that matters:
// the whole mechanism is that a ZERO is a positive statement ("this plane is
// watched and the count is nothing") where an absence is silence.
//
// The negative half is equally load bearing. Pre-creating all nine
// dispositions would pass the presence test above just as well while putting
// eight permanently-zero rows per plane on every dashboard, and permanently
// zero rows are the shape an operator learns to read past.
func TestPreCreationIsTargetedAtTheGateOperandsOnly(t *testing.T) {
	reg := prometheus.NewRegistry()
	observations := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: MetricShadowObservations, Help: "h",
	}, []string{"plane", "disposition"})
	failOpen := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: MetricShadowFailOpen, Help: "h",
	}, []string{"plane", "direction", "classification"})
	reg.MustRegister(observations, failOpen)

	planes := ImplementedPlanes()
	preCreateGateSeries(observations, failOpen, planes)

	// GATHERED, never read back through WithLabelValues: ToFloat64 CREATES the
	// child it is handed, so probing for a disposition that should be absent
	// would materialise it and the assertion would be about the probe. That is
	// the whole failure mode under test, one level up.
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gathering the fresh registry: %v", err)
	}
	got := map[string]float64{}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			key := f.GetName()
			for _, l := range m.GetLabel() {
				key += "|" + l.GetName() + "=" + l.GetValue()
			}
			got[key] = m.GetCounter().GetValue()
		}
	}

	want := map[string]float64{}
	for _, p := range planes {
		// Label order is the GATHERER's, which is alphabetical by label name.
		want[MetricShadowObservations+"|disposition="+dispositionCompared+"|plane="+string(p)] = 0
		want[MetricShadowFailOpen+"|classification="+gateOperandClass+"|direction="+gateOperandDirection+"|plane="+string(p)] = 0
	}
	for key, wantValue := range want {
		gotValue, ok := got[key]
		if !ok {
			t.Errorf("pre-creation did not materialise %s", key)
			continue
		}
		if gotValue != wantValue {
			t.Errorf("%s = %v, want %v; a pre-creation that carries a value invents evidence", key, gotValue, wantValue)
		}
	}
	// EXACTLY these, and nothing else. Pre-creating all nine dispositions
	// would satisfy the loop above just as well; the count is what refuses it.
	for key := range got {
		if _, expected := want[key]; !expected {
			t.Errorf("pre-creation materialised %s, which is not a gate-18 operand; a permanently-zero row is a row an operator learns to read past", key)
		}
	}
}

// TestTheModeGaugeIsPublishedForEveryPlaneAndMode pins the left-hand side of
// the vacuity rule.
//
// A zero denominator is only a defect on a plane that was SUPPOSED to be
// measured. Nothing in the counters can say which those are - a permanently
// zero denominator is correct on a plane the deployment never enabled and is
// the defect on one it did - so the rule needs a published mode to intersect
// with, and it needs it per plane, because the plane list is configurable and
// gate 18 is stated per plane.
func TestTheModeGaugeIsPublishedForEveryPlaneAndMode(t *testing.T) {
	shadowMode.Reset()
	t.Cleanup(shadowMode.Reset)

	planes := ImplementedPlanes()
	if len(planes) < 2 {
		t.Fatalf("this test needs at least two implemented planes to tell a narrowed list from a full one; got %d", len(planes))
	}
	// A NARROWED list, which is the case a component-wide gauge gets wrong: a
	// process in shadow with one plane enabled is watching one plane, and
	// reporting eleven others as watched would make each of them raise a
	// vacuity alert about the plane list rather than about the window.
	only := planes[0]
	cfg := Config{Mode: identity.CompatModeShadow, Planes: map[legacycompile.Plane]bool{only: true}}
	publishMode("agent", cfg.Observes, cfg.Mode)

	modes := identity.DecisionShadowModeNames()
	if want := len(planes) * len(modes); testutil.CollectAndCount(shadowMode) != want {
		t.Fatalf("the gauge has %d series, want %d (every plane x every mode on the axis)",
			testutil.CollectAndCount(shadowMode), want)
	}
	for _, p := range planes {
		expectOn := identity.CompatModeOff.String()
		if p == only {
			expectOn = identity.CompatModeShadow.String()
		}
		for _, m := range modes {
			want := 0.0
			if m == expectOn {
				want = 1.0
			}
			got := testutil.ToFloat64(shadowMode.WithLabelValues("agent", string(p), m))
			if got != want {
				t.Errorf("%s{component=agent,plane=%q,mode=%q} = %v, want %v", MetricShadowMode, p, m, got, want)
			}
		}
	}
}

// TestTheModeGaugeVocabularyIsTheAxisVocabulary pins the emitted mode set
// against the axis's own closed set.
//
// A rule asks `mode="shadow" == 1`. If the gauge stopped emitting a mode the
// axis can hold, that rule would evaluate over an empty vector - the missing
// dimension failure - and if it emitted one the axis cannot hold, it would put
// a permanently-zero row on a dashboard suggesting a posture that is not
// available. Both are silent, so the vocabulary is derived and this is what
// keeps the derivation honest.
func TestTheModeGaugeVocabularyIsTheAxisVocabulary(t *testing.T) {
	shadowMode.Reset()
	t.Cleanup(shadowMode.Reset)

	publishMode("agent", func(legacycompile.Plane) bool { return true }, identity.CompatModeShadow)

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gathering: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range families {
		if f.GetName() != MetricShadowMode {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "mode" {
					seen[l.GetValue()] = true
				}
			}
		}
	}
	got := make([]string, 0, len(seen))
	for m := range seen {
		got = append(got, m)
	}
	sort.Strings(got)
	want := identity.DecisionShadowModeNames()
	if len(got) != len(want) {
		t.Fatalf("the gauge emits modes %v; the axis holds %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the gauge emits modes %v; the axis holds %v", got, want)
		}
	}
	// "enforce" is parseable on the identity axis and REFUSED on this one. A
	// series for it would advertise a posture ParseDecisionShadowMode rejects
	// at boot.
	if seen[identity.CompatModeEnforce.String()] {
		t.Errorf("the gauge emits mode=%q, which %s refuses at boot", identity.CompatModeEnforce, identity.EnvDecisionShadowMode)
	}
}

// TestInstallProcessPublishesTheModeGauge pins the gauge to the INSTALL path,
// which is the only place a running process passes through, and covers the
// nil-observer shape.
//
// A component that publishes nothing has no series for the rule to evaluate
// over, so "this process was never wired" would be indistinguishable from
// "this process is not scraped" and from "the rule file never loaded" - which
// is the same reading-silence-as-good-news failure one level out.
func TestInstallProcessPublishesTheModeGauge(t *testing.T) {
	shadowMode.Reset()
	t.Cleanup(shadowMode.Reset)
	prior := ProcessObserver()
	t.Cleanup(func() { SetProcessObserver(prior) })

	if n := testutil.CollectAndCount(shadowMode); n != 0 {
		t.Fatalf("the gauge carries %d series before install; this test could not tell install from init", n)
	}
	InstallProcess(nil, "orchestrator")

	planes := ImplementedPlanes()
	modes := identity.DecisionShadowModeNames()
	if want := len(planes) * len(modes); testutil.CollectAndCount(shadowMode) != want {
		t.Fatalf("a nil observer published %d series, want %d; an unwired process must still say so positively",
			testutil.CollectAndCount(shadowMode), want)
	}
	for _, p := range planes {
		if got := testutil.ToFloat64(shadowMode.WithLabelValues("orchestrator", string(p), identity.CompatModeOff.String())); got != 1 {
			t.Errorf("plane %q does not report mode=off on an unwired process (got %v)", p, got)
		}
		if got := testutil.ToFloat64(shadowMode.WithLabelValues("orchestrator", string(p), identity.CompatModeShadow.String())); got != 0 {
			t.Errorf("plane %q reports mode=shadow on an unwired process (got %v)", p, got)
		}
	}
}

// TestInstallProcessPublishesTheModeGaugeForAWiredObserver is the OTHER call
// site, and it needs its own test for a reason worth stating.
//
// InstallProcess has two arms, and the nil arm above cannot reach the wired
// one. Testing publishMode directly proves the function correct and says
// nothing about whether either arm calls it - deleting the call from the wired
// arm leaves every process that actually runs a shadow publishing no mode at
// all, which is precisely the deployment the vacuity rule is for, and the
// function-level test would stay green throughout.
func TestInstallProcessPublishesTheModeGaugeForAWiredObserver(t *testing.T) {
	shadowMode.Reset()
	t.Cleanup(shadowMode.Reset)
	prior := ProcessObserver()
	t.Cleanup(func() { SetProcessObserver(prior) })

	o, _ := newFixtureObserver(t, fixtureConfig(identity.CompatModeShadow), MetricsRecorder{})
	if n := testutil.CollectAndCount(shadowMode); n != 0 {
		t.Fatalf("the gauge carries %d series before install; this test could not tell install from construction", n)
	}
	InstallProcess(o, "agent")

	for _, p := range ImplementedPlanes() {
		if got := testutil.ToFloat64(shadowMode.WithLabelValues("agent", string(p), identity.CompatModeShadow.String())); got != 1 {
			t.Errorf("plane %q does not report mode=shadow after a shadow observer was installed (got %v)", p, got)
		}
	}
}
