// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// resetCompatMetrics clears the package's metric vectors so one test's
// increments cannot be read as another's.
//
// The vectors are process-global by design (they register on the default
// registry, which is the one both binaries serve at /prometheus), so a test
// that only ADDED would be reading whatever ran before it. Nothing here calls
// t.Parallel for the same reason.
func resetCompatMetrics(t *testing.T) {
	t.Helper()
	compatComparisons.Reset()
	compatModeGauge.Reset()
	compatOrgModeFailures.Reset()
	compatOrgSettingsReadFailures.Reset()
	compatOrgComparisons.Reset()
	compatBuildInfo.Reset()
	orgLabelState.mu.Lock()
	orgLabelState.seen = nil
	orgLabelState.mu.Unlock()
}

// comparisonCount reads one fully-labelled comparison series.
//
// fail_open, synthetic and version are DERIVED here exactly as the recorder
// derives them, so a caller passing the six semantic labels reads the series
// the recorder actually wrote. Hand-writing the derived values at each call
// site would let a test drift from the recorder and still pass.
func comparisonCount(component, path, mode, legacy, state, divergence string) float64 {
	return comparisonCountFull(component, path, mode, legacy, state, divergence,
		string(Counterfactual{
			LegacyDecision: legacyDecisionFromLabel(legacy),
			IdentityState:  admissionStateFromLabel(state),
		}.FailOpen()), "false")
}

func comparisonCountFull(component, path, mode, legacy, state, divergence, failOpen, synthetic string) float64 {
	return testutil.ToFloat64(compatComparisons.WithLabelValues(
		component, path, mode, legacy, state, divergence, failOpen, synthetic, metricVersion()))
}

// legacyDecisionFromLabel / admissionStateFromLabel invert the String methods
// by MEMBERSHIP. A bare cast would let an unrecognised label silently become a
// declared value, which is the tri-state defect these enums exist to refuse.
func legacyDecisionFromLabel(s string) LegacyDecision {
	switch s {
	case "accepted":
		return LegacyDecisionAccepted
	case "rejected":
		return LegacyDecisionRejected
	default:
		return LegacyDecisionUnspecified
	}
}

func admissionStateFromLabel(s string) AdmissionState {
	switch s {
	case "ACCEPT":
		return AdmissionAccept
	case "DENY":
		return AdmissionDeny
	case "INDETERMINATE":
		return AdmissionIndeterminate
	default:
		return AdmissionUnspecified
	}
}

// TestPrometheusRecorderCountsEveryDivergenceClass drives one record per
// divergence class and asserts each lands on its own series with the labels an
// operator queries by.
//
// The classes are enumerated from the declared vocabulary rather than from a
// hand-picked sample: a class added to CompatDivergence and not handled here
// fails the count at the end, so this cannot silently cover less than the enum
// it is about.
func TestPrometheusRecorderCountsEveryDivergenceClass(t *testing.T) {
	resetCompatMetrics(t)
	rec := PrometheusCounterfactualRecorder{}

	// Every divergence a record can carry. DivergenceNotEvaluated is
	// deliberately absent: Resolve returns before calling the recorder when the
	// mode does not evaluate, so it is unreachable here by construction, and
	// TestModeOffIncrementsNoMetric pins that.
	classes := []struct {
		divergence CompatDivergence
		legacy     LegacyDecision
		state      AdmissionState
	}{
		{DivergenceNone, LegacyDecisionAccepted, AdmissionAccept},
		{DivergenceNone, LegacyDecisionRejected, AdmissionDeny},
		{DivergenceIdentityRefused, LegacyDecisionAccepted, AdmissionDeny},
		{DivergenceIdentityIndeterminate, LegacyDecisionAccepted, AdmissionIndeterminate},
		{DivergenceIdentityAdmittedLegacyRejected, LegacyDecisionRejected, AdmissionAccept},
		{DivergenceAdapterDefect, LegacyDecisionAccepted, AdmissionIndeterminate},
	}
	for _, c := range classes {
		rec.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent", Path: LegacyPathHS256, Mode: CompatModeShadow,
			LegacyDecision: c.legacy, IdentityState: c.state, Divergence: c.divergence,
		})
	}

	for _, c := range classes {
		got := comparisonCount("agent", "hs256", "shadow",
			c.legacy.String(), c.state.String(), string(c.divergence))
		if got != 1 {
			t.Errorf("divergence=%s legacy=%s state=%s: count = %v, want 1",
				c.divergence, c.legacy, c.state, got)
		}
	}

	// The denominator an operator reads is the SUM over every series, so it
	// must equal the number of records - not the number of classes, which
	// would silently pass if two classes collided onto one series.
	if total := testutil.CollectAndCount(compatComparisons); total != len(classes) {
		t.Errorf("distinct series = %d, want %d: two classes are colliding onto one series",
			total, len(classes))
	}
}

// TestPrometheusRecorderTotalsMatchSnapshot is the anti-drift test.
//
// The Prometheus counters and LogCounterfactualRecorder.Snapshot are two
// tallies of the same events, and the reason the metric is NOT derived from
// Snapshot is that a gauge over process memory cannot be rated. That leaves
// the obvious risk: the two disagree. They cannot, because
// MultiCounterfactualRecorder hands both the identical record in one call -
// and this test is what says so out loud.
func TestPrometheusRecorderTotalsMatchSnapshot(t *testing.T) {
	resetCompatMetrics(t)
	logRec := NewLogCounterfactualRecorder(0)
	fanout := MultiCounterfactualRecorder{logRec, PrometheusCounterfactualRecorder{}}

	type shape struct {
		path       LegacyPath
		divergence CompatDivergence
		legacy     LegacyDecision
		state      AdmissionState
		times      int
	}
	shapes := []shape{
		{LegacyPathAPICredential, DivergenceNone, LegacyDecisionAccepted, AdmissionAccept, 7},
		{LegacyPathHS256, DivergenceIdentityRefused, LegacyDecisionAccepted, AdmissionDeny, 3},
		{LegacyPathOIDC, DivergenceIdentityIndeterminate, LegacyDecisionAccepted, AdmissionIndeterminate, 2},
		{LegacyPathTrustedHeader, DivergenceNone, LegacyDecisionRejected, AdmissionDeny, 5},
	}
	for _, s := range shapes {
		for i := 0; i < s.times; i++ {
			fanout.RecordCounterfactual(context.Background(), Counterfactual{
				Component: "agent", Path: s.path, Mode: CompatModeShadow,
				LegacyDecision: s.legacy, IdentityState: s.state, Divergence: s.divergence,
			})
		}
	}

	snap := logRec.Snapshot()
	for _, s := range shapes {
		metric := comparisonCount("agent", string(s.path), "shadow",
			s.legacy.String(), s.state.String(), string(s.divergence))
		if metric != float64(s.times) {
			t.Errorf("path=%s divergence=%s: metric = %v, want %d",
				s.path, s.divergence, metric, s.times)
		}
	}

	// Per divergence class, the two tallies must agree exactly.
	byClass := map[CompatDivergence]int{}
	for _, s := range shapes {
		byClass[s.divergence] += s.times
	}
	for class, want := range byClass {
		if got := snap.ByDivergence[class]; got != uint64(want) {
			t.Fatalf("Snapshot.ByDivergence[%s] = %d, want %d", class, got, want)
		}
		var metric float64
		for _, s := range shapes {
			if s.divergence != class {
				continue
			}
			metric += comparisonCount("agent", string(s.path), "shadow",
				s.legacy.String(), s.state.String(), string(s.divergence))
		}
		if metric != float64(want) {
			t.Fatalf("class %s: prometheus total = %v, snapshot total = %d — the two tallies have drifted",
				class, metric, want)
		}
	}
}

// TestPrometheusRecorderBoundsThePathLabel pins the cardinality guard.
//
// The adapter-defect branch records the path it has just PROVEN invalid, so
// the value arriving at the recorder can be anything a caller constructed. If
// it reached a label value unmodified, one malformed call site would create
// unbounded series on a scrape target. The assertion is on the SERIES COUNT,
// not on the presence of the "invalid" bucket: a version that passed the raw
// value through would also produce an "invalid"-labelled series for the input
// literally spelled "invalid", and would still pass a presence check.
func TestPrometheusRecorderBoundsThePathLabel(t *testing.T) {
	resetCompatMetrics(t)
	rec := PrometheusCounterfactualRecorder{}

	for i := 0; i < 50; i++ {
		rec.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent",
			Path:      LegacyPath(fmt.Sprintf("attacker-supplied-%d", i)),
			Mode:      CompatModeShadow, LegacyDecision: LegacyDecisionAccepted,
			IdentityState: AdmissionIndeterminate, Divergence: DivergenceAdapterDefect,
		})
	}
	if n := testutil.CollectAndCount(compatComparisons); n != 1 {
		t.Fatalf("50 distinct undeclared paths produced %d series, want 1: the path label is not bounded", n)
	}
	if got := comparisonCount("agent", labelInvalidPath, "shadow",
		"accepted", "INDETERMINATE", string(DivergenceAdapterDefect)); got != 50 {
		t.Fatalf("invalid-path bucket = %v, want 50", got)
	}

	// And every DECLARED path keeps its own series, so bounding the label did
	// not flatten the axis an operator actually reads.
	resetCompatMetrics(t)
	for _, p := range legacyPaths {
		rec.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent", Path: p, Mode: CompatModeShadow,
			LegacyDecision: LegacyDecisionAccepted, IdentityState: AdmissionAccept,
			Divergence: DivergenceNone,
		})
	}
	if n := testutil.CollectAndCount(compatComparisons); n != len(legacyPaths) {
		t.Fatalf("the four declared paths produced %d series, want %d", n, len(legacyPaths))
	}
}

// TestCompatModeGaugePublishesEveryDeclaredMode is the missing-dimension test.
//
// The vacuity alert's whole left-hand side is this gauge, because in the
// vacuous case the comparison counter has no series at all. If the gauge
// published only the ACTIVE mode, a PromQL author reading
// `axonflow_identity_compat_mode{mode="shadow"}` against an off process would
// get an empty result rather than a truthful zero, and "no data" and "not in
// shadow" would be the same reading.
func TestCompatModeGaugePublishesEveryDeclaredMode(t *testing.T) {
	for _, active := range []CompatMode{CompatModeOff, CompatModeShadow, CompatModeEnforce} {
		resetCompatMetrics(t)
		publishCompatMode("agent", active)

		if n := testutil.CollectAndCount(compatModeGauge); n != 3 {
			t.Fatalf("mode=%s published %d series, want one per declared mode (3)", active, n)
		}
		ones := 0
		for _, m := range []CompatMode{CompatModeOff, CompatModeShadow, CompatModeEnforce} {
			got := testutil.ToFloat64(compatModeGauge.WithLabelValues("agent", m.String()))
			switch {
			case m == active && got != 1:
				t.Errorf("active mode %s reads %v, want 1", m, got)
			case m != active && got != 0:
				t.Errorf("inactive mode %s reads %v, want 0", m, got)
			}
			if got == 1 {
				ones++
			}
		}
		if ones != 1 {
			t.Errorf("mode=%s: %d series read 1, want exactly 1", active, ones)
		}
	}
}

// TestBootstrapWiresThePrometheusRecorder proves the metric is reachable from
// the ONE assembly both binaries use, not merely from a recorder a test
// constructed.
//
// This is the test that fails if someone reverts the fan-out in BootstrapCompat
// to the bare log recorder: every unit test above would still pass, and the
// fleet would export nothing.
func TestBootstrapWiresThePrometheusRecorder(t *testing.T) {
	resetCompatMetrics(t)
	boot, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode:    "shadow",
		Component:  "agent",
		Deployment: BuiltinRealmDeployment{},
	})
	if err != nil {
		t.Fatalf("BootstrapCompat: %v", err)
	}

	out := boot.Adapter.Resolve(context.Background(),
		HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Divergence == DivergenceNotEvaluated {
		t.Fatalf("the fixture did not evaluate; this test would prove nothing")
	}

	got := comparisonCount("agent", "hs256", "shadow",
		"accepted", out.Subject.Admission.State.String(), string(out.Divergence))
	if got != 1 {
		t.Fatalf("the bootstrap's adapter recorded no metric for %s/%s: got %v, want 1 "+
			"(the Prometheus recorder is not in BootstrapCompat's fan-out)",
			out.Subject.Admission.State, out.Divergence, got)
	}
	// The log recorder still sees it too: the fan-out ADDED a consumer, it did
	// not replace one.
	if total := boot.Recorder.Snapshot().ByDivergence[out.Divergence]; total != 1 {
		t.Fatalf("the log recorder's snapshot lost the record: %d, want 1", total)
	}
}

// TestInstallProcessCompatPublishesTheModeGauge pins the gauge to the install
// path, which is the only place a running process passes through.
func TestInstallProcessCompatPublishesTheModeGauge(t *testing.T) {
	resetCompatMetrics(t)
	prior := ProcessCompatAdapter()
	t.Cleanup(func() { SetProcessCompatAdapter(prior) })

	boot, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode: "shadow", Component: "orchestrator", Deployment: BuiltinRealmDeployment{},
	})
	if err != nil {
		t.Fatalf("BootstrapCompat: %v", err)
	}
	if n := testutil.CollectAndCount(compatModeGauge); n != 0 {
		t.Fatalf("the gauge was published before install: %d series", n)
	}
	boot.InstallProcessCompat("orchestrator")
	if got := testutil.ToFloat64(compatModeGauge.WithLabelValues("orchestrator", "shadow")); got != 1 {
		t.Fatalf("orchestrator/shadow gauge = %v after install, want 1", got)
	}
}

// TestModeOffIncrementsNoMetric holds the flag-off guarantee.
//
// "Mode off changes nothing OBSERVABLE" is the safety argument for shipping
// this on the authentication path, and adding a metrics recorder is exactly the
// kind of change that quietly starts emitting on a deployment that asked for
// nothing. Resolve returns before the recorder is reached, so the assertion is
// on the metric being ABSENT - not zero.
//
// THE CLAIM IS DELIBERATELY NARROWER THAN "off touches nothing". Since #3602
// the agent reads one request header per authenticated request regardless of
// mode (authenticator.go), because the only way to skip it would be a second
// reader of the mode at a call site - the exact shape
// TestCompatModeIsConsultedAtExactlyOneSite exists to forbid. What this test
// pins is the property that matters: under off, nothing is recorded, nothing
// is exported, and no series comes into existence.
func TestModeOffIncrementsNoMetric(t *testing.T) {
	resetCompatMetrics(t)
	boot, err := BootstrapCompat(CompatBootstrapConfig{
		RawMode: "off", Component: "agent", Deployment: BuiltinRealmDeployment{},
	})
	if err != nil {
		t.Fatalf("BootstrapCompat: %v", err)
	}
	for i := 0; i < 25; i++ {
		boot.Adapter.Resolve(context.Background(),
			HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	}
	if n := testutil.CollectAndCount(compatComparisons); n != 0 {
		t.Fatalf("mode off produced %d comparison series; off must touch nothing on the "+
			"authentication path", n)
	}
}

// TestOrgModeFailureIncrementsTheCounter covers the counter that would have
// caught the community-SaaS defect: a per-organization record that could not
// be resolved, so the process mode applied instead.
func TestOrgModeFailureIncrementsTheCounter(t *testing.T) {
	resetCompatMetrics(t)
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{},
		WithCompatOrgModes(failingOrgModeSource{}))

	out := a.Resolve(context.Background(),
		HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Mode != CompatModeShadow {
		t.Fatalf("a failed org-mode read must fall back to the process mode, got %s", out.Mode)
	}
	if got := testutil.ToFloat64(compatOrgModeFailures.WithLabelValues("agent")); got != 1 {
		t.Fatalf("org-mode failure counter = %v, want 1", got)
	}
	// The in-memory diagnostic total still moves: the counter ADDED a reader,
	// it did not replace the accessor OrgModeFailures' callers use.
	if got := a.OrgModeFailures(); got != 1 {
		t.Fatalf("OrgModeFailures() = %d, want 1", got)
	}
}

// TestCompatMetricNamesAreStable pins the exported names.
//
// The Prometheus rule file, the runbook and the runtime-e2e suite all match on
// these strings, and none of them is a Go reference - a rename would leave a
// rule silently matching nothing, which is the same failure mode as having no
// rule at all.
func TestCompatMetricNamesAreStable(t *testing.T) {
	for name, want := range map[string]string{
		MetricCompatComparisons:             "axonflow_identity_compat_comparisons_total",
		MetricCompatMode:                    "axonflow_identity_compat_mode",
		MetricCompatOrgModeFailures:         "axonflow_identity_compat_org_mode_failures_total",
		MetricCompatOrgSettingsReadFailures: "axonflow_identity_compat_org_settings_read_failures_total",
		// Both of these ARE matched by the rule file
		// (identity-compat.rules.yml's per-org volume recording rule and the
		// runbook's reset-boundary query), so a rename leaves a rule silently
		// matching nothing - the exact failure this test's doc names, and one
		// R3 round 1 found the first version of this table missing.
		MetricCompatOrgComparisons: "axonflow_identity_compat_org_comparisons_total",
		MetricCompatBuildInfo:      "axonflow_identity_compat_build_info",
	} {
		if name != want {
			t.Errorf("metric name %q != %q", name, want)
		}
		if !strings.HasPrefix(name, "axonflow_identity_compat_") {
			t.Errorf("metric %q is outside the axonflow_identity_compat_ namespace the rules match on", name)
		}
	}
}

// failingOrgModeSource always reports the record as unreadable.
type failingOrgModeSource struct{}

func (failingOrgModeSource) OrgCompatMode(context.Context, string) (CompatMode, bool, error) {
	return CompatModeUnspecified, false, fmt.Errorf(`pq: relation "identity_org_settings" does not exist`)
}

// --- #3602 scope extension: the fuller metric axes ---

// TestFailOpenDirectionIsDerivedFromBothAdmissions covers the axis gate 18
// names, in every combination of the two inputs.
//
// The table is the PRODUCT of the two axes - two legacy decisions by three
// admission states - not a sample of interesting ones, because the whole
// property is "which way does this difference run" and a sample cannot say
// that. It also pins the spellings against the CI gate's own vocabulary: two
// vocabularies for one property is how a dashboard and a gate come to disagree
// about whether the window is clean.
func TestFailOpenDirectionIsDerivedFromBothAdmissions(t *testing.T) {
	for _, tc := range []struct {
		legacy LegacyDecision
		state  AdmissionState
		want   FailOpenDirection
	}{
		{LegacyDecisionAccepted, AdmissionAccept, FailOpenNone},
		{LegacyDecisionAccepted, AdmissionDeny, FailOpenLegacyPermitted},
		{LegacyDecisionAccepted, AdmissionIndeterminate, FailOpenLegacyPermitted},
		{LegacyDecisionRejected, AdmissionAccept, FailOpenNewPermitted},
		{LegacyDecisionRejected, AdmissionDeny, FailOpenNone},
		{LegacyDecisionRejected, AdmissionIndeterminate, FailOpenNone},
	} {
		got := Counterfactual{LegacyDecision: tc.legacy, IdentityState: tc.state}.FailOpen()
		if got != tc.want {
			t.Errorf("legacy=%s identity=%s: FailOpen() = %q, want %q",
				tc.legacy, tc.state, got, tc.want)
		}
	}

	// INDETERMINATE is NOT an admission. If IsAdmitted were ever loosened to
	// `!= AdmissionDeny`, the second row above would flip to "none" and an
	// outage would start reading as agreement on the fail-open axis too.
	if AdmissionIndeterminate.IsAdmitted() {
		t.Fatal("AdmissionIndeterminate.IsAdmitted() is true; the fail-open axis is now wrong " +
			"in the one direction that matters")
	}
}

// TestFailOpenLabelSplitsTheTwoDirections proves the axis reaches the metric,
// on its own series, rather than only existing as a Go method.
func TestFailOpenLabelSplitsTheTwoDirections(t *testing.T) {
	resetCompatMetrics(t)
	rec := PrometheusCounterfactualRecorder{}

	// The SAFE direction, five times.
	for i := 0; i < 5; i++ {
		rec.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent", Path: LegacyPathHS256, Mode: CompatModeShadow,
			LegacyDecision: LegacyDecisionAccepted, IdentityState: AdmissionDeny,
			Divergence: DivergenceIdentityRefused,
		})
	}
	// The DANGEROUS direction, once.
	rec.RecordCounterfactual(context.Background(), Counterfactual{
		Component: "agent", Path: LegacyPathOIDC, Mode: CompatModeShadow,
		LegacyDecision: LegacyDecisionRejected, IdentityState: AdmissionAccept,
		Divergence: DivergenceIdentityAdmittedLegacyRejected,
	})

	safe := comparisonCountFull("agent", "hs256", "shadow", "accepted", "DENY",
		string(DivergenceIdentityRefused), string(FailOpenLegacyPermitted), "false")
	unsafe := comparisonCountFull("agent", "oidc", "shadow", "rejected", "ACCEPT",
		string(DivergenceIdentityAdmittedLegacyRejected), string(FailOpenNewPermitted), "false")
	if safe != 5 || unsafe != 1 {
		t.Fatalf("fail_open split: safe=%v unsafe=%v, want 5 / 1", safe, unsafe)
	}
	// And the dangerous direction must NOT be reachable by summing the safe
	// one: an alert keyed on the unsafe label must see exactly the one record.
	if got := comparisonCountFull("agent", "hs256", "shadow", "accepted", "DENY",
		string(DivergenceIdentityRefused), string(FailOpenNewPermitted), "false"); got != 0 {
		t.Fatalf("a safe-direction record landed under fail_open=new_permitted_legacy_denied: %v", got)
	}
}

// TestSyntheticLabelSplitsCanaryFromOrganicTraffic covers the coverage-versus-
// volume split: canary comparisons must be countable AND excludable.
func TestSyntheticLabelSplitsCanaryFromOrganicTraffic(t *testing.T) {
	resetCompatMetrics(t)
	rec := PrometheusCounterfactualRecorder{}

	base := Counterfactual{
		Component: "agent", Path: LegacyPathAPICredential, Mode: CompatModeShadow,
		OrgID: "acme", LegacyDecision: LegacyDecisionAccepted,
		IdentityState: AdmissionAccept, Divergence: DivergenceNone,
	}
	for i := 0; i < 3; i++ {
		canary := base
		canary.Synthetic = true
		rec.RecordCounterfactual(context.Background(), canary)
	}
	rec.RecordCounterfactual(context.Background(), base)

	synth := comparisonCountFull("agent", "api_credential", "shadow", "accepted", "ACCEPT",
		string(DivergenceNone), string(FailOpenNone), "true")
	organic := comparisonCountFull("agent", "api_credential", "shadow", "accepted", "ACCEPT",
		string(DivergenceNone), string(FailOpenNone), "false")
	if synth != 3 || organic != 1 {
		t.Fatalf("synthetic split: canary=%v organic=%v, want 3 / 1", synth, organic)
	}
	// The per-organization counter carries the same split, so a volume floor
	// read per tenant can exclude the probe too.
	if got := testutil.ToFloat64(compatOrgComparisons.WithLabelValues("agent", "acme", "true")); got != 3 {
		t.Fatalf("per-org synthetic volume = %v, want 3", got)
	}
	if got := testutil.ToFloat64(compatOrgComparisons.WithLabelValues("agent", "acme", "false")); got != 1 {
		t.Fatalf("per-org organic volume = %v, want 1", got)
	}
}

// TestSyntheticProbeHeaderIsAPositiveMembershipTest pins the header parser.
//
// "Non-empty" would make a proxy that echoes the header, and a caller who set
// it to "false" meaning to turn it OFF, both read as synthetic - which would
// remove that traffic from the organic volume an operator is measuring.
func TestSyntheticProbeHeaderIsAPositiveMembershipTest(t *testing.T) {
	for _, yes := range []string{"1", "true", "TRUE", " true ", "True"} {
		if !IsSyntheticProbeHeader(yes) {
			t.Errorf("IsSyntheticProbeHeader(%q) = false, want true", yes)
		}
	}
	for _, no := range []string{"", "0", "false", "FALSE", "yes", "on", "2", "synthetic", "-1"} {
		if IsSyntheticProbeHeader(no) {
			t.Errorf("IsSyntheticProbeHeader(%q) = true, want false", no)
		}
	}
}

// TestOrgVolumeIsBoundedAtTheCap is the cardinality guard for the axis the
// coverage gate asked for.
//
// An uncapped org label on a counter incremented from the authentication path
// is unbounded BY CONSTRUCTION on this fleet - the community-SaaS register
// endpoint mints a fresh organization on every call. The assertion is on the
// SERIES COUNT rather than on the presence of the overflow bucket: a version
// that passed every org through would also produce a "__over_cap__" series for
// an org literally named that, and would still pass a presence check.
func TestOrgVolumeIsBoundedAtTheCap(t *testing.T) {
	resetCompatMetrics(t)
	rec := PrometheusCounterfactualRecorder{}

	const over = maxOrgLabelValues + 37
	for i := 0; i < over; i++ {
		rec.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent", Path: LegacyPathAPICredential, Mode: CompatModeShadow,
			OrgID: fmt.Sprintf("tenant-%d", i), LegacyDecision: LegacyDecisionAccepted,
			IdentityState: AdmissionAccept, Divergence: DivergenceNone,
		})
	}
	// maxOrgLabelValues named organizations plus exactly one overflow bucket.
	if n := testutil.CollectAndCount(compatOrgComparisons); n != maxOrgLabelValues+1 {
		t.Fatalf("%d organizations produced %d series, want %d (the cap plus one overflow bucket)",
			over, n, maxOrgLabelValues+1)
	}
	if got := testutil.ToFloat64(compatOrgComparisons.WithLabelValues("agent", labelOverflowOrg, "false")); got != over-maxOrgLabelValues {
		t.Fatalf("overflow bucket = %v, want %d", got, over-maxOrgLabelValues)
	}
	// The named ones are the FIRST seen, and they are not evicted: an evicted
	// organization's series would stop moving while its traffic continued,
	// which reads on a dashboard exactly like the path-went-silent condition
	// these metrics exist to detect.
	if got := testutil.ToFloat64(compatOrgComparisons.WithLabelValues("agent", "tenant-0", "false")); got != 1 {
		t.Fatalf("the first organization seen lost its series: %v, want 1", got)
	}

	// A record with no organization gets its own bucket, distinct from the
	// overflow one: "we stopped naming organizations" and "this comparison had
	// no organization to name" are different facts, and the second is a defect
	// for an adapter that is organization-scoped by construction.
	rec.RecordCounterfactual(context.Background(), Counterfactual{
		Component: "agent", Path: LegacyPathAPICredential, Mode: CompatModeShadow,
		OrgID: "  ", LegacyDecision: LegacyDecisionAccepted,
		IdentityState: AdmissionAccept, Divergence: DivergenceNone,
	})
	if got := testutil.ToFloat64(compatOrgComparisons.WithLabelValues("agent", labelUnattributedOrg, "false")); got != 1 {
		t.Fatalf("unattributed bucket = %v, want 1", got)
	}
}

// TestCountersAreNeverSampled pins the property master's scope refinement
// states outright: sampling applies to verbose traces only, never to counters.
//
// AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY exists to keep one log line per
// hundred thousand agreements off the authentication path. If it ever reached
// the counters, the window's denominator would become an estimate - and the
// gate's question is whether anything was compared AT ALL, which an estimate
// scaled from a sample cannot answer honestly.
func TestCountersAreNeverSampled(t *testing.T) {
	resetCompatMetrics(t)
	// A sampling interval that suppresses every agreement log line.
	logRec := NewLogCounterfactualRecorder(1000000)
	fanout := MultiCounterfactualRecorder{logRec, PrometheusCounterfactualRecorder{}}

	const n = 250
	for i := 0; i < n; i++ {
		fanout.RecordCounterfactual(context.Background(), Counterfactual{
			Component: "agent", Path: LegacyPathAPICredential, Mode: CompatModeShadow,
			OrgID: "acme", LegacyDecision: LegacyDecisionAccepted,
			IdentityState: AdmissionAccept, Divergence: DivergenceNone,
		})
	}
	got := comparisonCount("agent", "api_credential", "shadow", "accepted", "ACCEPT", string(DivergenceNone))
	if got != n {
		t.Fatalf("counter = %v after %d agreements under a 1-in-1,000,000 log sampling interval, want %d: "+
			"the sampling interval has reached the counters", got, n, n)
	}
	if snap := logRec.Snapshot().ByDivergence[DivergenceNone]; snap != n {
		t.Fatalf("the log recorder's own tally = %d, want %d", snap, n)
	}
}

// TestBuildInfoNamesTheVersionsAResetWouldBeDetectedBy covers the reset-boundary
// requirement: the observation gate resets on a material semantic change, so
// the data has to say which semantics produced it.
func TestBuildInfoNamesTheVersionsAResetWouldBeDetectedBy(t *testing.T) {
	resetCompatMetrics(t)
	publishCompatMode("agent", CompatModeShadow)

	if n := testutil.CollectAndCount(compatBuildInfo); n != 1 {
		t.Fatalf("build-info series = %d, want exactly 1 per component", n)
	}
	if got := testutil.ToFloat64(compatBuildInfo.WithLabelValues(
		"agent", metricVersion(), AdapterContractVersion)); got != 1 {
		t.Fatalf("build info = %v, want 1 (the always-1 gauge idiom)", got)
	}
	// The contract version is SEPARATE from the platform version on purpose: a
	// gate that reset on every release would never accumulate a window, and
	// one that never reset would average pre- and post-change behaviour into a
	// single verdict.
	if AdapterContractVersion == metricVersion() {
		t.Fatal("the adapter contract version and the platform version are the same string; " +
			"they must be independent or the gate resets on every release")
	}
	// An unbaked build must say so rather than emit an empty label, which
	// PromQL cannot distinguish from the label being absent.
	if strings.TrimSpace(metricVersion()) == "" {
		t.Fatal("metricVersion() is empty; use a named sentinel so PromQL can select on it")
	}
}

// TestResolveCarriesTheSyntheticFlagIntoTheRecord covers the hop from
// LegacyAuth into the Counterfactual, which is the one link in the #3602 tag's
// chain no caller-side test can see.
//
// R3 round 1 on #3607 found it unguarded: hard-coding `Synthetic: false` in
// record() left every test green. The tests that existed built a Counterfactual
// by hand and handed it to the recorder, so they exercised the label renderer
// and nothing that leads to it. This drives Resolve - the real entry point -
// and reads the metric out the far end.
func TestResolveCarriesTheSyntheticFlagIntoTheRecord(t *testing.T) {
	for _, synthetic := range []bool{true, false} {
		resetCompatMetrics(t)
		// The PRODUCTION assembly, not compatFixture's capture-only recorder:
		// the fan-out is what BootstrapCompat wires, and the whole point here
		// is the flag surviving all the way to a label.
		reg := NewRealmRegistry()
		src, srcErr := NewBuiltinRealmSource(reg, BuiltinRealmDeployment{})
		if srcErr != nil {
			t.Fatalf("NewBuiltinRealmSource: %v", srcErr)
		}
		rec := &captureRecorder{}
		a, adapterErr := NewCompatAdapter(CompatModeShadow, reg, src,
			MultiCounterfactualRecorder{rec, PrometheusCounterfactualRecorder{}},
			WithCompatClock(func() time.Time { return fixtureNow }),
			WithCompatComponent("agent"))
		if adapterErr != nil {
			t.Fatalf("NewCompatAdapter: %v", adapterErr)
		}

		in := HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", "")
		in.Synthetic = synthetic
		out := a.Resolve(context.Background(), in)
		if out.Divergence == DivergenceNotEvaluated {
			t.Fatalf("synthetic=%v: the fixture did not evaluate; this proves nothing", synthetic)
		}

		// The record itself.
		if got := rec.last(t).Synthetic; got != synthetic {
			t.Fatalf("Counterfactual.Synthetic = %v, want %v (record() dropped the flag)", got, synthetic)
		}
		// …and the label it becomes. Both, because a record carrying the flag
		// that never reaches a label is just as unreadable as the reverse.
		if got := comparisonCountFull("agent", "hs256", "shadow", "accepted",
			out.Subject.Admission.State.String(), string(out.Divergence),
			string(FailOpenNone), boolLabel(synthetic)); got != 1 {
			t.Fatalf("synthetic=%v: the metric series carries %v, want 1", synthetic, got)
		}
		if got := comparisonCountFull("agent", "hs256", "shadow", "accepted",
			out.Subject.Admission.State.String(), string(out.Divergence),
			string(FailOpenNone), boolLabel(!synthetic)); got != 0 {
			t.Fatalf("synthetic=%v: the OPPOSITE series moved (%v); the flag is not reaching the label",
				synthetic, got)
		}
	}
}
