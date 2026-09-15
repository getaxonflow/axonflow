// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// refusalsTotal is THE refusal observable. Every label value comes from a
// closed set declared in this package (Dimensions, Editions, Reasons); nothing
// from a request reaches a label. Only limited tiers can refuse, and the
// series for those are pre-registered at zero below so the counter is on the
// scrape before the first refusal - a surface that appears only when it
// fires cannot be alerted on for "never fired".
var refusalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_tier_limit_refusals_total",
	Help: "Principal admissions refused by the licence tier's scale limit, by dimension, edition and reason. " +
		"reason=over_limit is the ceiling; reason=dependency_unreachable is the admission ledger being down for a principal never seen before.",
}, []string{"dimension", "edition", "reason"})

// admissionsTotal counts every ALLOWED decision by the branch that answered,
// so an operator can see how often the seen-set, the ledger or the unlimited
// short-circuit decided, and a test can prove a replay is one ledger write.
var admissionsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_tier_admissions_total",
	Help: "Principal admissions allowed, by dimension, edition and the branch that answered " +
		"(unlimited_tier, seen_set, ledger_existing, ledger_admitted).",
}, []string{"dimension", "edition", "source"})

// backgroundDropsTotal counts the background writes this package gives up on:
// an unlimited tier's telemetry record and a refusal's audit row, each either
// refused a concurrency slot or failed outright. Both are dropped by design -
// neither is part of the decision - but a drop leaves a fact unrecorded, and an
// unrecorded fact that nothing counts is invisible.
var backgroundDropsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_tier_admission_background_drops_total",
	Help: "Background writes the tier admission dropped, by dimension and reason " +
		"(at_capacity: the queue was full; write_failed: the store refused it; audit_at_capacity: no room for the audit row; debt_evicted: a retry was forgotten because the bounded debt set overflowed; panicked: a store implementation panicked and the worker survived it; shutting_down: the admitter was closed, which is a shutdown rather than a backlog).",
}, []string{"dimension", "reason"})

// ledgerHealthyGauge is 1 while the ledger answers and 0 after an error until
// the next success. /health carries the same fact in words.
var ledgerHealthyGauge = promauto.NewGauge(prometheus.GaugeOpts{
	Name: "axonflow_tier_admission_ledger_healthy",
	Help: "1 while the principal_admissions ledger answers; 0 after an error until the next success.",
})

// BackgroundDropReasons is the closed reason set for backgroundDropsTotal.
func BackgroundDropReasons() []string {
	return []string{"at_capacity", "write_failed", "audit_at_capacity", "debt_evicted", "panicked", "shutting_down"}
}

// BackgroundDropsCollectorForTest exposes the counter to the label census.
func BackgroundDropsCollectorForTest() prometheus.Collector { return backgroundDropsTotal }

func init() {
	for _, d := range Dimensions() {
		for _, r := range BackgroundDropReasons() {
			backgroundDropsTotal.WithLabelValues(string(d), r).Add(0)
		}
	}
	for _, d := range Dimensions() {
		for _, e := range []string{"community", "evaluation"} {
			for _, r := range Reasons() {
				refusalsTotal.WithLabelValues(string(d), e, r).Add(0)
			}
		}
	}
}

// RefusalsCollectorForTest and AdmissionsCollectorForTest expose the counters
// to platform/agent's metric label-domain census, which measures membership
// of a driven set by counting series. Intended for use in tests only.
func RefusalsCollectorForTest() prometheus.Collector   { return refusalsTotal }
func AdmissionsCollectorForTest() prometheus.Collector { return admissionsTotal }
