// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/identity"
)

// The metric names a rule file, a runbook and the runtime-e2e suite all spell
// out. They are constants for identity.MetricCompatComparisons' reason: a
// rename that misses one of those three produces a recording rule that
// silently matches nothing, which is the same silence this package exists to
// make impossible.
const (
	// MetricShadowObservations is the observation counter. The subset with
	// disposition="compared" is ADR-065 gate 18's DENOMINATOR, per plane;
	// every other disposition is a reason an observation did not become one.
	MetricShadowObservations = "axonflow_decision_shadow_observations_total"
	// MetricShadowComparisons is the completed-comparison counter by
	// classification.
	MetricShadowComparisons = "axonflow_decision_shadow_comparisons_total"
	// MetricShadowFailOpen is gate 18's NUMERATOR surface.
	MetricShadowFailOpen = "axonflow_decision_shadow_fail_open_total"
	// MetricShadowMode is the gauge that makes "this plane is being watched"
	// observable WITH NO TRAFFIC AT ALL. See shadowMode.
	MetricShadowMode = "axonflow_decision_shadow_mode"
)

// The shadow's counters, on the DEFAULT registry.
//
// promauto on the default registry is what every other metric in the agent and
// the orchestrator uses (connector refresh, CAEP pushes, segment resolution,
// the policy stored-action displacement counter). A second registry would need
// a second scrape endpoint or a merge, and session v10.3-B's window
// observability reads these alongside the identity compat counters - so one
// surface, and the coordination is that both sessions publish here.
//
// # WHY THE DENOMINATOR HAS FIVE COUNTERS AND NOT ONE
//
// "Zero unexplained differences" is only readable next to "out of how many",
// and every way an observation can fail to become a comparison is a different
// operator action:
//
//	sampled_out       turn the sample rate up
//	dropped           the queue is too shallow or the pool too small
//	not_comparable    a policy edit raced the plane's cache; ordinary in ones
//	                  and twos, a defect in this package if it is the norm
//	evaluation_error  the plane could not evaluate at all; not a policy verdict
//	refused           an observation this package could not act on: OUR defect
//
// Collapsing them into one "skipped" would tell an operator that the window is
// thin and not what to do about it. This is the guard the 2026-08-31
// observation-window read found missing for the identity axis, and the reason
// the v11 clock has not started.
var (
	shadowObservations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricShadowObservations,
		Help: "Plane observations offered to the ADR-065 decision shadow, by plane, disposition and synthetic origin. " +
			"The disposition=\"compared\",synthetic=\"false\" child is gate 18's ORGANIC denominator and is pre-created at zero for every implemented plane.",
	}, []string{"plane", "disposition", LabelSynthetic})

	shadowComparisons = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricShadowComparisons,
		Help: "Completed ADR-065 shadow comparisons, by plane, classification (match, expected_change, UNEXPLAINED) and synthetic origin.",
	}, []string{"plane", "classification", LabelSynthetic})

	// shadowMode is 1 for the mode this process booted in, per plane, and 0
	// for every other mode on the axis.
	//
	// # WHY A GAUGE EXISTS AT ALL, AND WHY IT IS PER PLANE
	//
	// The vacuity case is "this plane is being watched and NOTHING was
	// compared", and in that case the observation counter's compared child
	// carries a zero only because init() below puts one there. That fixes the
	// numerator/denominator asymmetry, but it cannot say WHETHER the plane was
	// supposed to be measured: a permanently-zero denominator on a plane the
	// deployment never enabled is correct, and on a plane it did enable is the
	// defect. Only a published mode can tell those two apart, which is the
	// argument identity-compat.rules.yml makes for its own gauge and the
	// reason a rule needs a left-hand side that exists with zero traffic.
	//
	// PER PLANE because AXONFLOW_DECISION_SHADOW_PLANES narrows which planes
	// observe, and ADR-065 gate 18 is stated per plane. A component-wide gauge
	// would report a process in shadow as watching twelve planes when its
	// operator had narrowed it to one, and the eleven silent planes would then
	// each raise a vacuity alert that is a statement about the plane list
	// rather than about the window.
	//
	// EVERY mode on the axis is emitted, 0 for the ones not in force, so a
	// rule can ask `mode="shadow" == 1` and get a truthful "no" from an off
	// process instead of an empty vector a PromQL author reads as "no data".
	shadowMode = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: MetricShadowMode,
		Help: "1 for the decision-shadow mode this process booted in on this plane, 0 for the others. " +
			"Published at boot so 'this plane is watched' is observable with zero traffic. " +
			"It is the PROCESS mode: a per-organization record can raise a plane this gauge reports as off, " +
			"which is the mode label on the comparison log line and NOT a change to this series.",
	}, []string{"component", "plane", "mode"})

	// The gate's actual operand. A fail-open direction is not derivable from
	// the classification - an expected_change can still be a difference in the
	// dangerous direction - so gate 18's numerator is counted in its own
	// series rather than read off a sentence, which is the same argument
	// DiffRecord.FailOpen makes for being a field.
	shadowFailOpen = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: MetricShadowFailOpen,
		Help: "ADR-065 shadow comparisons by fail-open direction, classification and synthetic origin; UNEXPLAINED with direction new_permitted_legacy_denied is what gate 18 requires to be zero.",
	}, []string{"plane", "direction", "classification", LabelSynthetic})

	shadowBundleBuilds = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "axonflow_decision_shadow_bundle_builds_total",
		Help: "ADR-065 shadow policy-bundle compilations, by plane and outcome.",
	}, []string{"plane", "outcome"})

	shadowLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "axonflow_decision_shadow_evaluation_seconds",
		Help:    "Wall time to build the request, evaluate the PDP and classify one observation, off the request path.",
		Buckets: prometheus.DefBuckets,
	}, []string{"plane"})

	// The SYNCHRONOUS cost, which is the only part a caller waits for. It is
	// measured separately from the evaluation because they are different
	// magnitudes and different decisions: this one is the overhead the PR body
	// has to defend per plane, and the one above is a capacity question.
	shadowEnqueueLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "axonflow_decision_shadow_enqueue_seconds",
		Help: "Wall time Observe spends ON THE REQUEST PATH: resolving the organization's mode (a memoized read, a bounded database round trip on a TTL miss) and offering the observation to the queue. The PDP evaluation is not included and is not on this path.",
		// The top buckets reach past the settings read's 2-second deadline on
		// purpose. An earlier revision stopped at 5ms and described itself as
		// "the only part a caller waits for" - so the one cost worth measuring,
		// a TTL-miss database round trip on the request path, landed entirely
		// in +Inf and was invisible in exactly the metric named after it.
		Buckets: []float64{1e-6, 5e-6, 1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 25e-3, 100e-3, 500e-3, 1, 2, 5},
		// `recorded` SEPARATES THE TWO POPULATIONS, and they must not be
		// averaged. An organization whose resolved mode does not record still
		// pays the mode read - that is the whole synchronous cost for it - and
		// on the documented rollout shape (process mode off, one organization
		// shadowing) it is 99% of requests. Observing only the recorded path
		// made this metric blind to the population paying the most for the
		// feature and getting nothing, which is precisely the number an
		// operator sizing a rollout needs.
	}, []string{"plane", "recorded"})

	// Per-organization mode resolution failures, mirroring
	// CompatAdapter.OrgModeFailures. An operator expecting a per-org shadow
	// who sees this climbing is running that organization in the process mode.
	shadowOrgModeFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_decision_shadow_org_mode_failures_total",
		Help: "Per-organization decision shadow mode reads that failed and fell back to the process-wide mode.",
	})

	// Per-organization PLANE narrowing failures (#3552 gap 3). A SEPARATE
	// counter from the mode's, because the two failures move a window in
	// OPPOSITE directions and an operator reading one series could not tell
	// them apart: a failed MODE read drops an organization out of the window
	// entirely, while a failed PLANE read leaves it measuring MORE planes than
	// its record asks for - an inflated denominator rather than an empty one.
	//
	// AND IT CARRIES NO org LABEL, DELIBERATELY. The organization is in the LOG
	// line beside the raw value and the parser's own message; the counter
	// answers "how often, fleet-wide" and the log answers "which organization".
	//
	// An org label here would be UNBOUNDED CARDINALITY on a path that a caller
	// drives: the resolution runs per observation, so every request for an
	// organization with an unusable record increments it, and the label's value
	// space is whatever org ids reach the deployment. That is a memory lever on
	// the scrape target, and it is the hazard the identity axis has already
	// paid for - see maxOrgLabelValues, labelOverflowOrg and
	// labelUnattributedOrg in identity's compat_metrics.go, which cap the
	// distinct values per process and bucket the rest.
	//
	// If a per-organization breakdown is ever judged worth it, REUSE that
	// capped scheme rather than adding a raw label: two implementations of one
	// cap is two things that must not disagree, and the one that drifted would
	// be the newer one nobody is watching. planeshadow already imports
	// identity, so exporting the helper is the smaller change of the two.
	shadowOrgPlanesFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "axonflow_decision_shadow_org_planes_failures_total",
		Help: "Per-organization decision shadow plane-narrowing reads that failed and fell back to the deployment's plane list. " +
			"The organization is named in the log line rather than in a label, to keep an unbounded label off a per-request path.",
	})
)

// gateOperandDirection and gateOperandClass are the coordinates ADR-065 gate
// 18 is read at: an UNEXPLAINED difference in which the ADR-065 side permitted
// what the legacy plane denied.
//
// They are spelled here as the label VALUES rather than imported from
// shadow.FailOpenNewPermitted / shadow.ClassUnexplained on purpose - see
// TestTheGateOperandSeriesMatchesTheClassifier, which pins these two strings
// against the classifier's own constants. A silent rename there would
// otherwise move the pre-created series off the coordinate an alert queries
// and leave the alert reading `absent` again.
const (
	gateOperandDirection = "new_permitted_legacy_denied"
	gateOperandClass     = "UNEXPLAINED"
)

// LabelSynthetic is the label name, and SyntheticTrue/SyntheticFalse are its
// only two values.
//
// # WHY THE DECISION AXIS NEEDS IT AT ALL (#3817)
//
// decision-shadow.rules.yml's own header, gap 2, wrote this change's
// specification before there was anything to label: "THERE IS NO
// DECISION-SHADOW CANARY, AND WHOEVER ADDS ONE OWES AN ORGANIC TWIN ...
// Deploying one WITHOUT adding a `synthetic` label to
// axonflow_decision_shadow_observations_total and an organic twin of the rule
// below would re-open the exact vacuity this file closes, one level up."
//
// A canary exists to give the window a denominator, so its comparisons MUST
// count toward COVERAGE - a path only the canary exercises is still an
// exercised path. They must be excludable from any VOLUME floor, or "this
// deployment saw 3,000 comparisons" is a statement about our own probe. Both
// readings are needed at once, so the fact is a LABEL and never a filter. The
// identity axis reached the same conclusion first, in
// identity.LegacyAuth.Synthetic, and this is the same fact carried on the same
// channel rather than a second mechanism.
//
// # THE VALUES ARE THE STRINGS boolLabel PRODUCES, AND THEY ARE NOT strconv
//
// "true"/"false" spelled as constants, matched to identity's compat_metrics.go
// boolLabel, so a query written against one axis reads the other. A `%v` or a
// strconv.FormatBool would produce the same two strings today and is one
// refactor away from producing "1"/"0" on one axis only - and a rule filtering
// synthetic="false" against a series spelling it "0" matches nothing and
// reports a vacuous window as healthy, which is this whole file's failure mode.
// EXPORTED FOR THE SAME REASON THE METRIC NAMES ARE. A rule file, a runbook and
// the runtime-e2e suite all spell these out, and none of them is a Go reference
// - so a rename compiles, every Go test using the constant stays green, and the
// recording rules silently match nothing.
//
// They are also read by a test that lives OUTSIDE this package, in
// platform/monitoring, and has to: the rules files are not mirrored to the
// community repo while this package is, so a rules-file test in here FATALs on
// the mirror tree (#3807's class, found by R3 on #3829). Exporting the two
// strings is what lets that test live beside the files it reads.
const (
	LabelSynthetic = "synthetic"
	SyntheticTrue  = "true"
	SyntheticFalse = "false"
)

// syntheticLabel renders the label value.
//
// FALSE IS THE UNSTAMPED ANSWER, and the direction is the point:
// identity.SyntheticProbeFromContext answers false for a context nobody
// stamped, so an observation whose request never reached the stamping
// middleware lands in the ORGANIC bucket. That makes an instrumentation gap
// INFLATE the organic volume, which reads as more tenant evidence than there
// is - conservative in the direction that matters, because the opposite
// default would let a forgotten stamp quietly move real tenant traffic out of
// the volume the gate is read against. There is no third value: a Go bool
// cannot be unknown, which is why this is a bool threaded from one read site
// rather than a string a call site supplies.
func syntheticLabel(synthetic bool) string {
	if synthetic {
		return SyntheticTrue
	}
	return SyntheticFalse
}

// bothSyntheticValues is the pre-creation vocabulary. It is a function rather
// than a slice literal so no caller can append to it.
func bothSyntheticValues() []string { return []string{SyntheticFalse, SyntheticTrue} }

// A COUNTER VEC WITH NO CHILDREN EXPORTS NOTHING AT ALL, NOT EVEN ITS # TYPE.
//
// promauto registers the vector, but promhttp renders a vector by walking its
// children: with none, the scrape carries no `axonflow_decision_shadow_fail_open_total`
// line, no HELP and no TYPE. So on a healthy deployment - the one where no
// comparison has ever failed open, which is the whole point - gate 18's
// operand series DID NOT EXIST. An alert on it evaluates to `absent`, which
// most alerting configurations treat as "no data, nothing to fire on", and the
// gate's central promise reads as satisfied because nobody is measuring it.
//
// That is exactly the vacuity this package was built to make impossible, one
// level down from the denominator it argues about everywhere else, and the
// runtime suite caught it: `axonflow_decision_shadow_fail_open_total is not
// exported`.
//
// The fix is to CREATE the child at zero, at init, for every plane this
// process may observe. A zero-valued series is a positive statement - "this
// plane is watched and the count is nothing" - where an absent one is silence.
// Only the gate's own coordinate is pre-created: the other directions and
// classifications appear when something is actually observed, and pre-creating
// the full cross product would put thirty-odd permanently-zero rows on a
// dashboard for no reading anybody takes.
//
// # THE SAME ARGUMENT APPLIES TO THE DENOMINATOR, AND IT WAS LEFT OPEN
//
// The paragraph above was applied to the NUMERATOR only. The denominator -
// axonflow_decision_shadow_observations_total{plane,disposition="compared"} -
// was left absent-until-first-write, and it is the half gate 18 is read
// against: "no unexplained fail-open difference for the agreed window" is a
// ratio, and a ratio whose divisor does not exist is not a low reading, it is
// no reading. On a plane that was configured, watched and never compared
// anything the whole gate therefore evaluated over nothing and reported
// satisfied - which is the EXACT defect the v10.2.0 identity window turned out
// to have, reproduced on the other axis. v10.3.0 exists because of the first
// one, so the second is not a theoretical hole.
//
// dispositionCompared ONLY. The other eight dispositions are reasons an
// observation did not become a comparison; they are diagnostic, they are not
// operands of any gate, and pre-creating them would put eight permanently-zero
// rows per plane on a dashboard - the cross-product cost the paragraph above
// refuses for the same reason.
// # AND THE SAME ARGUMENT AGAIN, ONE LABEL LOWER (#3817)
//
// Adding `synthetic` re-opens the hole it closes unless BOTH values are
// pre-created. The ORGANIC operand -
// observations_total{disposition="compared",synthetic="false"} - is the one the
// volume floor is stated in, and on a stack where the canary is the only
// traffic that child is written by nothing. Absent, the recording rule
// `axonflow:decision_shadow_organic_comparisons:increase1h` returns an EMPTY
// VECTOR rather than 0, a dashboard renders "no data" rather than a zero, and
// an operator comparing it against a floor of 3,000 has nothing to compare. The
// identity axis demonstrated exactly this: its canary-only unit case asserts
// organic:increase1h yields `exp_samples: []`.
//
// So the pre-creation is the CROSS PRODUCT of the gate coordinate and both
// synthetic values, and it now covers comparisons_total as well - the third
// counter carrying the label. Its coordinate is the gate CLASS, matching
// fail_open's policy of pre-creating the gate operand only: pre-creating every
// classification would put permanently-zero rows on a dashboard for a reading
// nobody takes, and the organic rule sums over classifications anyway, so one
// pre-created class is enough to make the sum a zero instead of an absence.
//
// 12 planes x 2 values = 24 rows per counter, 72 in all, on a process that has
// served nothing. That is the price of the difference between a zero and a
// silence, and this package exists to argue it is worth paying.
func init() {
	preCreateGateSeries(shadowObservations, shadowComparisons, shadowFailOpen, ImplementedPlanes())
}

// preCreateGateSeries materialises gate 18's two operands at zero.
//
// It takes its vectors as arguments so a test can run it against a FRESH
// registry and assert what it does and does not create. That is not the whole
// test: the package registers on the default registry at init, so proving the
// function is correct says nothing about whether init actually calls it - the
// call site needs its own assertion, and TestBothGateOperandsAreExportedBefore
// AnyTraffic on the default gatherer is it.
func preCreateGateSeries(observations, comparisons, failOpen *prometheus.CounterVec, planes []legacycompile.Plane) {
	for _, p := range planes {
		for _, synthetic := range bothSyntheticValues() {
			failOpen.WithLabelValues(string(p), gateOperandDirection, gateOperandClass, synthetic)
			observations.WithLabelValues(string(p), dispositionCompared, synthetic)
			comparisons.WithLabelValues(string(p), gateOperandClass, synthetic)
		}
	}
}

// publishMode publishes the per-plane mode gauge for this component.
//
// Called at INSTALL, before any request, and not on the first observation. A
// process that never serves a governed request is precisely the state the
// window has to be able to name, so the series that says "this plane is
// watched" must exist before any traffic does. Same placement and same reason
// as identity.publishCompatMode.
//
// `observes` decides the per-plane value: a plane the deployment excluded with
// AXONFLOW_DECISION_SHADOW_PLANES is off on that plane whatever the process
// mode is, and reporting it as shadow would make every excluded plane raise a
// vacuity alert that is a statement about the plane list.
//
// The mode vocabulary is DERIVED from identity.DecisionShadowModeNames rather
// than listed here. This axis is a closed two-value set today; a hand-written
// copy would be a third statement of it with nothing pinning it, and the
// failure is silent in both directions - an invented mode is a permanently-zero
// row, and a missing one is a mode no rule can ask about.
func publishMode(component string, observes func(legacycompile.Plane) bool, mode Mode) {
	active := mode.String()
	for _, p := range ImplementedPlanes() {
		effective := active
		if !observes(p) {
			effective = identity.CompatModeOff.String()
		}
		for _, name := range identity.DecisionShadowModeNames() {
			value := 0.0
			if name == effective {
				value = 1.0
			}
			shadowMode.WithLabelValues(component, string(p), name).Set(value)
		}
	}
}

// Dispositions an observation can reach. They are constants because they are
// metric label VALUES: a dashboard and an alert are written against these
// strings, and a typo in one call site would silently create a second series
// that no query sums.
const (
	dispositionCompared       = "compared"
	dispositionSampledOut     = "sampled_out"
	dispositionDropped        = "dropped"
	dispositionNotComparable  = "not_comparable"
	dispositionEvaluationErr  = "evaluation_error"
	dispositionRefused        = "refused"
	dispositionPlaneDisabled  = "plane_disabled"
	dispositionEvaluateFailed = "evaluate_failed"
	// dispositionPanicked is a recovered panic on the worker. It is its own
	// label because "the shadow panicked" and "the shadow could not compile a
	// bundle" send an operator to different places - and because a panic that
	// were folded into evaluate_failed would be indistinguishable from an
	// ordinary compile error on a dashboard, which is the one failure that
	// most needs to be visible.
	dispositionPanicked = "panicked"
)

// AllDispositions returns every disposition, for the test that proves each one
// is reachable. A disposition nothing can produce is a dashboard row that is
// permanently zero and reads as good news.
func AllDispositions() []string {
	return []string{
		dispositionCompared, dispositionSampledOut, dispositionDropped,
		dispositionNotComparable, dispositionEvaluationErr, dispositionRefused,
		dispositionPlaneDisabled, dispositionEvaluateFailed, dispositionPanicked,
	}
}
