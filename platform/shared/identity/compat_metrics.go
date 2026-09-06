// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Prometheus export for the ADR-065 compatibility adapters (#3550, #3602).
//
// # WHY THIS EXISTS: THE SHADOW WINDOW HAD NO DENOMINATOR
//
// v10.2.0 put four services into shadow mode. The first read of that window
// (2026-08-31) found zero divergences AND no way to tell that apart from zero
// comparisons: agreements are sampled at one in a hundred thousand,
// LogCounterfactualRecorder.Snapshot had no runtime consumer, and no metric
// carried compat data at all. "Zero unexplained differences out of zero
// comparisons" is the vacuity-at-zero class that
// platform/decision/legacycompile/shadow/gate.go refuses in CI; production had
// no equivalent, so the gate-18 sentence - "no unexplained fail-open
// difference FOR THE AGREED WINDOW" - could not be evaluated on the fleet at
// all.
//
// # WHY COUNTERS AT THE EVENT, NOT A GAUGE OVER Snapshot
//
// Snapshot returns process-memory totals. Published as a gauge they reset to
// zero on every deploy, every scale-out replaces one series with another, and
// rate() over them is meaningless - which is precisely the read an operator
// needs ("is the window accumulating comparisons RIGHT NOW"). So the export is
// a Prometheus counter incremented at the moment of the record, through the
// ordinary CounterfactualRecorder seam, and Snapshot is left as what it always
// was: an in-process accessor for tests and diagnostics. Nothing here reads or
// resets it; the two tallies cannot drift because both are fed by the same
// MultiCounterfactualRecorder fan-out over the same records, which
// TestPrometheusRecorderTotalsMatchSnapshot pins.
//
// # WHERE THE ORGANIZATION APPEARS, AND WHERE IT DELIBERATELY DOES NOT
//
// The gate's coverage half needs comparison volume PER ORGANIZATION, and an
// unbounded org label would be unbounded by construction on this fleet: the
// community-SaaS register endpoint mints a fresh organization on every call,
// so the hourly canary alone adds ~8,760 of them a year. So the axis exists in
// exactly one place - axonflow_identity_compat_org_comparisons_total, capped
// at maxOrgLabelValues distinct values per process with a named overflow
// bucket - and nowhere else. The main comparison counter carries NO org at
// all, so the class breakdown an operator reads most often can never be the
// thing that fills a scrape target's memory.
//
// Full per-tenant attribution, including the realm detail, stays in the
// [IDENTITY-COMPAT] log line, which carries org= on every record. Metrics
// carry bounded classes; the log carries the tenant. The runbook says so.
//
// # EVERY LABEL VALUE COMES FROM A CLOSED VOCABULARY
//
// Path is the one field an adapter DEFECT can carry an arbitrary value in -
// the adapter records defects with the path it has just proven invalid - so it
// is bounded through LegacyPath.IsValid exactly as the recorder's perPath map
// is. Component is a compile-time literal in each binary (never
// caller-influenced), and mode, legacy decision, identity state and divergence
// are all declared enums whose String methods this file maps by MEMBERSHIP,
// never by a bare cast.
package identity

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/shared/version"
)

// The metric names. They are constants because the runbook, the Prometheus
// rule file and the runtime-e2e suite all name them, and a rename that misses
// one of those produces a rule that silently matches nothing.
const (
	// MetricCompatComparisons is the counter of identity-plane comparisons.
	// Its SUM is the observation window's denominator; the subset with
	// divergence="none" is the agreement count; every other divergence value
	// is a class of the numerator.
	MetricCompatComparisons = "axonflow_identity_compat_comparisons_total"
	// MetricCompatMode is the gauge that makes "this process is in shadow"
	// observable WITH NO TRAFFIC AT ALL. See compatModeGauge.
	MetricCompatMode = "axonflow_identity_compat_mode"
	// MetricCompatOrgModeFailures counts fall-backs from an organization's
	// recorded mode to the process mode.
	MetricCompatOrgModeFailures = "axonflow_identity_compat_org_mode_failures_total"
	// MetricCompatOrgSettingsReadFailures counts failed reads of
	// identity_org_settings.
	MetricCompatOrgSettingsReadFailures = "axonflow_identity_compat_org_settings_read_failures_total"
	// MetricCompatOrgComparisons is the per-ORGANIZATION comparison volume,
	// with a hard cardinality cap. See compatOrgComparisons.
	MetricCompatOrgComparisons = "axonflow_identity_compat_org_comparisons_total"

	// MetricCompatOrgDivergences is the per-organization DIVERGENCE count, the
	// second half of the per-org gate (#3633). It exists because the enforce
	// precondition is per organization and the divergence breakdown on
	// MetricCompatComparisons carries no org label - deliberately, for the
	// cardinality reason above - so the per-org half of a per-org gate had no
	// home at all. Same cap, same buckets, same synthetic split as
	// MetricCompatOrgComparisons, because the two are read together.
	MetricCompatOrgDivergences = "axonflow_identity_compat_org_divergences_total"
	// MetricCompatBuildInfo names the versions a comparison was produced
	// under, so a gate reset boundary is detectable in the data.
	MetricCompatBuildInfo = "axonflow_identity_compat_build_info"
)

// AdapterContractVersion is the version of the COMPARISON SEMANTICS: what the
// adapter compares, how it classifies the result, and which credential
// properties realm verification consults.
//
// # WHY A HAND-BUMPED CONSTANT AND NOT THE BUILD VERSION
//
// The observation gate resets on a material semantic change, and the platform
// version moves on every release whether or not the semantics moved. A gate
// that reset on each release would never accumulate a window; one that never
// reset would average pre- and post-change behaviour into a single verdict and
// call it clean. So the two are separate labels and this one is bumped
// deliberately, by whoever changes the semantics, as part of that change.
//
// BUMP THIS when a change alters what a comparison MEANS - a new divergence
// class, a change to classifyDivergence, a realm property that starts or stops
// being verified. Do NOT bump it for a refactor, a log-wording change, or a
// new metric label.
const AdapterContractVersion = "1"

// maxOrgLabelValues caps how many distinct organizations get their own series
// on the per-organization volume counter.
//
// # WHY THERE IS A CAP AT ALL
//
// The gate requires comparison volume to be measurable per organization, and
// an uncapped org label would be unbounded BY CONSTRUCTION on this fleet: the
// community-SaaS register endpoint mints a fresh organization on every call,
// so the hourly canary alone adds ~8,760 organizations a year, and a load
// generator adds them as fast as it can POST. An unbounded label on a counter
// incremented from the authentication path is a memory lever on the scrape
// target and an outage in the monitoring stack - which is a strictly worse
// failure than the one this metric exists to prevent.
//
// So the axis exists, bounded. The first maxOrgLabelValues organizations seen
// by a process each get a series; every later one is counted under
// labelOverflowOrg, which is itself a reading: a non-zero overflow bucket says
// "this deployment has more organizations than the per-org view can name". The
// unbounded total stays available on
// axonflow_identity_compat_comparisons_total, which carries no org at all.
//
// # WHERE THIS AXIS IS USEFUL, AND WHERE IT IS NOT - SAID PLAINLY
//
// On production-us and on any single-tenant or handful-of-tenants deployment,
// every tenant that matters is named and stays named. On community-SaaS the
// same property that forces the cap - a fresh organization per register call -
// fills the 100 slots within hours, after which every later tenant lands in
// labelOverflowOrg and the per-org view says little beyond "there are many".
// That is a real limit of this axis on that stack, not a bug to be tuned away:
// raising the cap moves the hour it fills, and removing it takes the scrape
// target down. Representative-coverage claims about community-SaaS should be
// made from the synthetic split and the per-PATH breakdown, which are bounded
// and meaningful there. The runbook says so.
const maxOrgLabelValues = 100

// labelOverflowOrg is the bucket every organization past the cap is counted
// under. It is deliberately not a truncation or a hash of the real value:
// either would look like a name and be unusable as one.
const labelOverflowOrg = "__over_cap__"

// labelUnattributedOrg is the bucket for a record carrying no organization. It
// is distinct from the overflow bucket because they mean different things: one
// is "we stopped naming organizations", the other is "this comparison had no
// organization to name", which for an adapter that is organization-scoped by
// construction is a defect worth seeing.
const labelUnattributedOrg = "__none__"

// labelInvalidPath is what a record whose path is not a declared one is
// counted under. It is a single bounded bucket rather than the offending
// value: the value is attacker-adjacent (an adapter defect records whatever it
// was handed) and an unbounded label is a memory lever on the scrape target.
const labelInvalidPath = "invalid"

var (
	// compatComparisons registers on the DEFAULT registry, which is the one
	// both binaries already serve at /prometheus (agent run.go, orchestrator
	// run.go) and the one #3596's CAEP counters use. There is deliberately no
	// second registry: a metric on a registry nothing serves is a metric that
	// does not exist.
	compatComparisons = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricCompatComparisons,
			Help: "ADR-065 identity-plane comparisons performed on the authentication path. " +
				"The total is the shadow window's denominator; divergence=none is agreement. " +
				"Per-tenant attribution is in the [IDENTITY-COMPAT] log line, not here.",
		},
		// EVERY comparison is counted here, with no sampling of any kind.
		// AXONFLOW_IDENTITY_COMPAT_AGREEMENT_LOG_EVERY samples the verbose
		// agreement LOG LINE and nothing else; a sampled counter would make
		// the window's denominator an estimate, and the gate's question is
		// whether anything was compared at all.
		[]string{
			"component", "path", "mode", "legacy", "identity_state",
			"divergence", "fail_open", "synthetic", "version",
		},
	)

	// compatOrgComparisons is the per-organization volume, capped. See
	// maxOrgLabelValues for why the cap exists and what the overflow bucket
	// means. It is a SEPARATE metric rather than an org label on the counter
	// above, so that the unbounded-cardinality risk is confined to one series
	// family an operator can drop wholesale if it ever becomes a problem.
	compatOrgComparisons = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricCompatOrgComparisons,
			Help: "ADR-065 identity-plane comparison volume by organization, for the coverage half of gate 18. " +
				"Capped at " + strconv.Itoa(maxOrgLabelValues) + " distinct organizations per process; the rest are " +
				"counted under " + labelOverflowOrg + ", and a record with no organization under " +
				labelUnattributedOrg + ". The uncapped total is " + MetricCompatComparisons + ".",
		},
		[]string{"component", "org", "synthetic"},
	)

	// compatOrgDivergences is the per-organization divergence volume (#3633),
	// the companion to compatOrgComparisons and read with it.
	//
	// WHY A SEPARATE METRIC RATHER THAN A LABEL ON compatOrgComparisons: the
	// two answer different questions and one is a denominator. Adding a
	// `divergence` label to the volume counter would make every existing
	// query for "how much did this org compare" wrong unless it summed across
	// a new dimension, which is the kind of silent break a dashboard shows a
	// week later.
	//
	// The `divergence` label carries the CLASS, not a boolean, so the gate can
	// distinguish an explained divergence from an unexplained one without a
	// second series - and so an operator reading the gate's refusal can see
	// WHICH class is blocking the organization.
	compatOrgDivergences = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricCompatOrgDivergences,
			Help: "ADR-065 identity-plane divergence volume by organization, the per-org half of the gate 18 " +
				"enforce precondition. Capped and bucketed exactly as " + MetricCompatOrgComparisons + "; read " +
				"TOGETHER with it, because a CounterVec with no children exports no series and an absent " +
				"divergence series therefore proves nothing on its own - only a non-zero organic denominator " +
				"makes an absent divergence count readable as zero.",
		},
		[]string{"component", "org", "synthetic", "divergence"},
	)

	// compatBuildInfo is the standard build-info idiom: a gauge that is always
	// 1, carrying versions as labels, joinable with
	// `* on (component) group_left(version, adapter_contract)`.
	//
	// It is published at boot ALONGSIDE the version label on the comparison
	// counter, and the two answer different questions. The label says which
	// semantics produced a given comparison, which is what makes a reset
	// boundary visible inside the comparison stream itself. This gauge says
	// what the process is running now, including the contract version, which
	// is what an operator reads when the counter has not moved at all.
	compatBuildInfo = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricCompatBuildInfo,
			Help: "Always 1. Names the platform version and the identity-compat contract version this process runs, " +
				"so an observation-window reset boundary is detectable in the data.",
		},
		[]string{"component", "version", "adapter_contract"},
	)

	// compatModeGauge is 1 for the mode this process is configured in and 0
	// for the other two.
	//
	// ALL THREE SERIES ARE EMITTED, and that is the whole point. The vacuity
	// case is "shadow is on and NOTHING was compared", in which the counter
	// above has no series at all - so an alert written only over the counter
	// cannot see the failure it exists to catch. It is the missing-dimension
	// shape: a floor over a vector that does not exist is not a low reading,
	// it is no reading. This gauge is published at install time, before any
	// request, so the alert always has a left-hand side to subtract the
	// counter from.
	compatModeGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: MetricCompatMode,
			Help: "1 for the AXONFLOW_IDENTITY_COMPAT_MODE this process booted in, 0 for the others. " +
				"Published at boot so 'shadow is on' is observable with zero traffic; " +
				"per-organization records can raise or lower the mode a given request runs in, " +
				"which is the mode label on " + MetricCompatComparisons + ".",
		},
		[]string{"component", "mode"},
	)

	compatOrgModeFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricCompatOrgModeFailures,
			Help: "Times an organization's recorded compatibility mode could not be resolved and the process mode was used instead. " +
				"Non-zero means a recorded mode is NOT being honoured.",
		},
		[]string{"component"},
	)

	compatOrgSettingsReadFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: MetricCompatOrgSettingsReadFailures,
			Help: "Failed reads of identity_org_settings, counted whether or not a last-good row masked the failure from the adapter.",
		},
		[]string{"component"},
	)
)

// PrometheusCounterfactualRecorder increments the comparison counter for every
// record.
//
// It is an EMPTY STRUCT WITH A VALUE RECEIVER on purpose. NewCompatAdapter
// refuses recorders that cannot record, and recorderRecordsNothing's own doc
// names this exact shape as the legitimate zero value it must not refuse - a
// stateless recorder emitting counters. Keeping it stateless also means the
// fan-out can be constructed anywhere without an initialisation order.
type PrometheusCounterfactualRecorder struct{}

// RecordCounterfactual implements CounterfactualRecorder.
//
// It reads no context and never blocks on one: this runs on the
// authentication path, and the recorder's contract (compat_bootstrap.go's note
// on cancellation) is that recording survives a cancelled request, or the
// shadow goes blind during exactly the incidents it exists to explain.
func (PrometheusCounterfactualRecorder) RecordCounterfactual(_ context.Context, rec Counterfactual) {
	synthetic := boolLabel(rec.Synthetic)
	compatComparisons.WithLabelValues(
		rec.Component,
		metricPathLabel(rec.Path),
		rec.Mode.String(),
		rec.LegacyDecision.String(),
		rec.IdentityState.String(),
		string(rec.Divergence),
		string(rec.FailOpen()),
		synthetic,
		metricVersion(),
	).Inc()
	org := orgLabel(rec.OrgID)
	compatOrgComparisons.WithLabelValues(rec.Component, org, synthetic).Inc()

	// THE DIVERGENT RECORDS ONLY (#3633), and that is what makes an absent
	// series readable.
	//
	// Counting agreements here too - with divergence="none" - would make the
	// series present for every organization with any traffic, so "no
	// divergences" would have to be read as "the none child is the only
	// child", a sum over an open label set. Counting only divergences means
	// the ABSENCE of a child is the signal, and it is a sound one exactly
	// when the organization was measured at all: the reader pairs it with
	// compatOrgComparisons{synthetic="false"} > 0, because a CounterVec with
	// no children exports no series and absence alone is equally consistent
	// with "nothing diverged" and "nothing ran".
	//
	// DivergenceNotEvaluated is excluded with DivergenceNone: a record the
	// adapter never evaluated is not evidence of agreement, and counting it
	// as a divergence would block an organization for traffic the plane
	// deliberately skipped.
	if rec.Divergence != DivergenceNone && rec.Divergence != DivergenceNotEvaluated {
		compatOrgDivergences.WithLabelValues(rec.Component, org, synthetic, string(rec.Divergence)).Inc()
	}
}

// boolLabel renders a boolean as a bounded label value.
func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// metricVersion is the platform version this binary was built as, or
// "unknown" for an unbaked build.
//
// "unknown" rather than an empty string: an empty label value is
// indistinguishable in PromQL from the label being absent, and "the version is
// not known" is a fact worth being able to select on - it says the binary was
// not built through the release pipeline.
//
// Resolved ONCE. Both of version.Resolve's inputs - the ldflags-baked variable
// and the AXONFLOW_VERSION fallback - are fixed for the life of the process,
// and this label is rendered on the authentication path for every comparison,
// so re-resolving per record spent an env read and a TrimSpace on an answer
// that cannot change.
func metricVersion() string { return metricVersionValue() }

var metricVersionValue = sync.OnceValue(func() string {
	if v := strings.TrimSpace(version.Resolve()); v != "" {
		return v
	}
	return "unknown"
})

// orgLabelState bounds the per-organization label to maxOrgLabelValues
// distinct values per process.
//
// An RWMutex, not a Mutex: this is consulted on the authentication path for
// every comparison, and after the first sighting of an organization the answer
// is a read. On a stack with a handful of tenants the write path is taken a
// handful of times in the process's whole life, and every subsequent request
// takes a shared lock instead of contending on an exclusive one.
var orgLabelState struct {
	mu   sync.RWMutex
	seen map[string]bool
}

// orgLabel returns the label value for an organization, admitting it to the
// bounded set if there is room.
//
// The set is FIRST-COME and never evicted. Eviction would be worse than the
// cap: an organization that lost its slot would have its series stop moving
// while its traffic continued, which reads on a dashboard exactly like the
// path-went-silent condition these metrics exist to detect.
func orgLabel(orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return labelUnattributedOrg
	}
	// The steady-state path: a shared lock and a map read.
	orgLabelState.mu.RLock()
	admitted, full := orgLabelState.seen[orgID], len(orgLabelState.seen) >= maxOrgLabelValues
	orgLabelState.mu.RUnlock()
	if admitted {
		return orgID
	}
	if full {
		return labelOverflowOrg
	}

	orgLabelState.mu.Lock()
	defer orgLabelState.mu.Unlock()
	if orgLabelState.seen == nil {
		orgLabelState.seen = make(map[string]bool, maxOrgLabelValues)
	}
	// RE-CHECKED under the exclusive lock. Between the read and the write
	// another goroutine may have admitted this organization, or filled the last
	// slot; acting on the stale read would admit one past the cap, which is the
	// one thing this function exists to prevent.
	if orgLabelState.seen[orgID] {
		return orgID
	}
	if len(orgLabelState.seen) >= maxOrgLabelValues {
		return labelOverflowOrg
	}
	orgLabelState.seen[orgID] = true
	return orgID
}

// BoundedOrgLabel is orgLabel, exported.
//
// It exists because a SECOND per-organization metric now needs the same cap -
// the decision-proof refusal counters (#3614) - and
// platform/shared/planeshadow/metrics.go already wrote down what to do when
// that happened: "If a per-organization breakdown is ever judged worth it,
// REUSE that capped scheme rather than adding a raw label: two implementations
// of one cap is two things that must not disagree."
//
// One admission set, shared across every per-organization metric in the
// process, is also the only reading of the cap that BOUNDS THE PROCESS rather
// than each metric separately: N metrics each with their own 100-slot set is a
// 100N-organization memory lever on the scrape target, which is what the cap
// exists to prevent.
func BoundedOrgLabel(orgID string) string { return orgLabel(orgID) }

// MaxOrgLabelValues is maxOrgLabelValues, exported so a consumer's Help text
// can state the cap it is subject to. Stating the number is not cosmetic: an
// operator reading a per-organization panel that has silently folded every
// tenant past the hundredth into one bucket needs to know that from the metric
// itself, not from a runbook it has not opened.
const MaxOrgLabelValues = maxOrgLabelValues

// metricPathLabel bounds the path label to the declared vocabulary.
//
// The check is LegacyPath.IsValid - membership on the four declared paths -
// and not "non-empty". The adapter-defect branch records the path it has just
// refused, so the value reaching here can be anything a caller constructed,
// and using it as a label value would let one malformed call site create
// unbounded series on a scrape target.
func metricPathLabel(p LegacyPath) string {
	if !p.IsValid() {
		return labelInvalidPath
	}
	return string(p)
}

// publishCompatMode sets the mode gauge for a component: 1 for the configured
// mode, 0 for every other declared mode.
//
// Setting the others to ZERO rather than leaving them absent is what lets a
// rule say `axonflow_identity_compat_mode{mode="shadow"} == 1` and get a
// truthful "no" from a process in off mode, instead of an empty result that a
// PromQL author will read as "no data" and quietly drop.
func publishCompatMode(component string, mode CompatMode) {
	for _, m := range []CompatMode{CompatModeOff, CompatModeShadow, CompatModeEnforce} {
		value := 0.0
		if m == mode {
			value = 1.0
		}
		compatModeGauge.WithLabelValues(component, m.String()).Set(value)
	}
	compatBuildInfo.WithLabelValues(component, metricVersion(), AdapterContractVersion).Set(1)
}

// observeOrgModeFailure counts one fall-back from an organization's recorded
// mode to the process mode.
func observeOrgModeFailure(component string) {
	compatOrgModeFailures.WithLabelValues(component).Inc()
}

// observeOrgSettingsReadFailure counts one failed read of
// identity_org_settings. It is called from the Enterprise store; the counter
// itself is declared here, untagged, so the metric surface is one file in both
// editions and a community build exports the (permanently zero) series rather
// than omitting it.
//
// CI lints this package WITHOUT the enterprise tag, where this function is
// declared and called nowhere - the community build genuinely has no store to
// call it, by design. That is the mirror image of identity_caep.go's
// situation and takes the same annotation.
//
//nolint:unused // called by dbOrgIdentitySettingsStore.read in compat_org_settings.go (enterprise build)
func observeOrgSettingsReadFailure(component string) {
	compatOrgSettingsReadFailures.WithLabelValues(component).Inc()
}

var _ CounterfactualRecorder = PrometheusCounterfactualRecorder{}
