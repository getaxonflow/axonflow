// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// NOTHING THE AUDIT QUEUE CANNOT KEEP IS DROPPED SILENTLY (#4249 row
// 5705939628). Every site that discards an entry, or fails to write one it
// cannot retry, increments axonflow_audit_entries_dropped_total under its site
// and logs at most once per auditDropLogInterval per site, with the count
// suppressed since the last line. A per-entry log line is what a full queue
// cannot afford; a counter nobody logs is what an operator never finds.
const (
	// A policy_metrics entry arrived while the 1000-slot metrics channel was full.
	auditDropMetricsQueueFull = "metrics_queue_full"
	// A policy_metrics entry carried no organization: RLS would refuse the row.
	auditDropMetricsNoOrg = "metrics_no_org"
	// The policy_metrics UPSERT failed after its retries.
	auditDropMetricsWriteFailed = "metrics_write_failed"
	// A violation could not be written (compliance mode writes synchronously,
	// so the error reaches the adapter; an entry with no organization is one).
	auditDropViolationWriteFailed = "violation_write_failed"
	// A fallback entry failed recovery on maxFallbackRecoveryAttempts startups
	// and was moved to the dead-letter file (<fallback>.dead.jsonl): counted,
	// kept, no longer retried.
	auditDropRecoveryExhausted = "recovery_exhausted"
	// The fallback file was rewritten at recovery but could not be reopened.
	auditDropFallbackReopenFailed = "fallback_reopen_failed"
	// A queued entry failed its database write and then its fallback file write.
	auditDropFallbackWriteFailed = "fallback_write_failed"
	// A fallback file line could not be parsed at recovery.
	auditDropFallbackUnparseable = "fallback_unparseable"
	// A metrics entry arrived after the queue shut down.
	auditDropMetricsAfterShutdown = "metrics_after_shutdown"
)

// auditDropSites lists every site, so each series exists at zero from boot.
var auditDropSites = []string{
	auditDropMetricsQueueFull,
	auditDropMetricsNoOrg,
	auditDropMetricsWriteFailed,
	auditDropViolationWriteFailed,
	auditDropRecoveryExhausted,
	auditDropFallbackWriteFailed,
	auditDropFallbackUnparseable,
	auditDropMetricsAfterShutdown,
	auditDropFallbackReopenFailed,
}

var auditEntriesDroppedTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "axonflow_audit_entries_dropped_total",
	Help: "Audit entries the agent's audit queue could not keep, by the site that dropped them.",
}, []string{"site"})

// auditDropLogInterval bounds the log lines per site.
const auditDropLogInterval = time.Minute

type auditDropLogState struct {
	last       time.Time
	suppressed int
}

var (
	auditDropLogMu sync.Mutex
	auditDropLog   = map[string]*auditDropLogState{}
	// auditDropNow is the clock, replaceable by a test.
	auditDropNow = time.Now
	// auditDropLogf is the logger, replaceable by a test.
	auditDropLogf = log.Printf
)

func init() {
	for _, site := range auditDropSites {
		auditEntriesDroppedTotal.WithLabelValues(site).Add(0)
	}
}

// recordAuditDrop counts one dropped entry at site and logs it unless a line
// for that site was written within auditDropLogInterval.
func recordAuditDrop(site, format string, args ...interface{}) {
	recordAuditDropN(site, 1, format, args...)
}

// recordAuditDropN counts n dropped entries at site, logged as recordAuditDrop
// logs one.
func recordAuditDropN(site string, n int, format string, args ...interface{}) {
	auditEntriesDroppedTotal.WithLabelValues(site).Add(float64(n))
	logAuditRateLimited(site, "dropped (site=%s): "+format, append([]interface{}{site}, args...)...)
}

// logAuditRateLimited writes a line for key at most once per
// auditDropLogInterval, noting how many it suppressed since the last. It counts
// nothing: a retry that may still succeed is logged through it, not counted.
func logAuditRateLimited(key, format string, args ...interface{}) {
	auditDropLogMu.Lock()
	state, ok := auditDropLog[key]
	if !ok {
		state = &auditDropLogState{}
		auditDropLog[key] = state
	}
	now := auditDropNow()
	if !state.last.IsZero() && now.Sub(state.last) < auditDropLogInterval {
		state.suppressed++
		auditDropLogMu.Unlock()
		return
	}
	suppressed := state.suppressed
	state.last = now
	state.suppressed = 0
	logf := auditDropLogf
	auditDropLogMu.Unlock()

	msg := fmt.Sprintf(format, args...)
	if suppressed > 0 {
		logf("[audit] %s (and %d more since the last line)", msg, suppressed)
		return
	}
	logf("[audit] %s", msg)
}
