//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// V1 SaaS Plugin Pro paid-tier observability metrics (issue #1886).
//
// The plugin-claim Stripe webhook (ee/platform/agent/billing/webhook.go) does
// not currently emit Prometheus counters for license issuance — only log
// lines. To make claims/day, active Pro tenants, and forward-looking MRR
// queryable from Grafana without touching the webhook itself, this file runs
// a low-frequency background poll over plugin_user_licenses and exposes the
// counts as Prometheus gauges.
//
// Why poll vs. instrument-the-webhook:
//   - Webhook is per-checkout (cold path); a counter increment runs at most
//     a few hundred times per day. Active-license counts and revocation lag
//     would still need a poll regardless. One poller is simpler than splitting
//     gauges from a webhook counter.
//   - The poller is read-only (SELECT count(*)) — zero blast radius if it
//     fails (gauges go stale, alerting catches it via the absent() rule).
//   - It runs on every agent replica. With small replica counts (<10) and a
//     60s poll interval, RDS load is negligible (60-600 SELECTs/min).
//
// Why one-minute polling:
//   - Grafana scrapes Prometheus every 15s by default; per-minute updates
//     are well below the noise floor for the metrics we care about (counts,
//     not rates).
//   - Slower polling reduces load if many agent replicas are running.
//   - Fast enough that revocation-lag alerts fire within 60-90s of the row
//     update (matches plugin-claim's <60s revocation requirement per ADR-049
//     section 2).

const (
	// pluginLicenseMetricsPollInterval is how often the gauges are refreshed
	// from plugin_user_licenses. See file comment for tradeoff rationale.
	pluginLicenseMetricsPollInterval = 60 * time.Second

	// pluginLicenseMetricsQueryTimeout caps each SELECT to bound the worst
	// case if RDS is degraded. The five queries are simple counts on indexed
	// columns; under normal load they complete in single-digit milliseconds.
	pluginLicenseMetricsQueryTimeout = 5 * time.Second
)

// Plugin-claim license counts. These are gauges (point-in-time), not counters
// (monotonic), because the underlying values change in both directions —
// e.g. revocation reduces "active" without changing "total".
var (
	pluginLicenseActiveTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_active_total",
			Help: "Number of plugin-claim license rows with revoked_at IS NULL " +
				"and (expires_at IS NULL OR expires_at > NOW()). " +
				"Treated as 'active Pro tenants' for V1 SaaS Plugin Pro reporting.",
		},
	)

	pluginLicenseAllTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_total",
			Help: "Total number of plugin_user_licenses rows ever issued " +
				"(including revoked + expired). Diverges upward only.",
		},
	)

	pluginLicenseIssuedTodayTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_issued_today_total",
			Help: "Number of plugin_user_licenses rows where issued_at::date = " +
				"CURRENT_DATE (UTC). Resets at midnight UTC. Drives the " +
				"V1 SaaS Plugin Pro 'claims/day' panel.",
		},
	)

	pluginLicenseExpiring7dTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_expiring_7d_total",
			Help: "Number of currently-active plugin_user_licenses rows whose " +
				"expires_at falls within the next 7 days. Pro v1 issues " +
				"licenses with NULL expires_at (one-time-purchase, no " +
				"expiry), so this gauge is 0 in V1 — it exists for Premium v2 " +
				"subscription expirations.",
		},
	)

	pluginLicenseRevokedTodayTotal = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_revoked_today_total",
			Help: "Number of plugin_user_licenses rows whose revoked_at falls " +
				"in the current UTC day. Refunds and admin revocations both " +
				"set revoked_at; in V1 (manual refunds via Stripe dashboard) " +
				"this is the closest proxy we have to a refund-rate signal. " +
				"Sustained > 10% of issued_today triggers the refund-rate alert.",
		},
	)

	pluginLicensePollFailuresTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_plugin_licenses_poll_failures_total",
			Help: "Number of plugin-license metric poll attempts that errored " +
				"out (db_error|table_missing|context_canceled). Sustained " +
				"non-zero values indicate the gauges above are stale.",
		},
		[]string{"reason"},
	)

	pluginLicenseLastPollTimestamp = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "axonflow_plugin_licenses_last_poll_timestamp_seconds",
			Help: "Unix timestamp (seconds) of the last successful poll. " +
				"Use absent() or (time() - this) > 300 in alerts to detect " +
				"a wedged poller.",
		},
	)
)

// startPluginLicenseMetricsPoller spins up the background goroutine that
// refreshes the gauges. Returns a cancel func the caller can invoke at
// shutdown — currently agent has no graceful-shutdown sequence so the
// returned func is unused, but it keeps the API testable.
//
// The first poll runs synchronously before the goroutine returns so the
// gauges are populated by the time /prometheus is first scraped (avoids a
// scrape-startup race where Grafana sees zeros for the first poll cycle).
func startPluginLicenseMetricsPoller(db *sql.DB) (cancel func()) {
	if db == nil {
		log.Println("[plugin_license_metrics] DB nil; skipping poller (gauges will read 0)")
		return func() {}
	}

	ctx, cancelFn := context.WithCancel(context.Background())

	// Run one poll synchronously. Errors here are logged but not fatal —
	// the goroutine will retry on the next interval.
	pollPluginLicenseGaugesOnce(ctx, db)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(pluginLicenseMetricsPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pollPluginLicenseGaugesOnce(ctx, db)
			}
		}
	}()

	log.Printf("[plugin_license_metrics] poller started (interval=%s)", pluginLicenseMetricsPollInterval)
	return func() {
		cancelFn()
		wg.Wait()
	}
}

// pollPluginLicenseGaugesOnce runs the five count queries and updates the
// gauges. On any error the gauges are NOT cleared — last-known-good values
// persist, which is what alerting downstream wants (a wedged poller plus a
// fresh-data alarm gives the operator a clear "go look at the agent" signal
// rather than a phantom "MRR went to zero").
func pollPluginLicenseGaugesOnce(parent context.Context, db *sql.DB) {
	ctx, cancel := context.WithTimeout(parent, pluginLicenseMetricsQueryTimeout)
	defer cancel()

	// Active rows — counted as "Pro tenants currently entitled to Pro
	// service". In V1 expires_at is always NULL (no auto-expiry), but the
	// query handles both forms so Premium v2 will work without code change.
	var active int64
	err := db.QueryRowContext(ctx, `
		SELECT count(*)
		  FROM plugin_user_licenses
		 WHERE revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > NOW())`).Scan(&active)
	if err != nil {
		// 42P01 = table doesn't exist; happens on stacks that haven't run
		// migration 077 yet (e.g. self-hosted enterprise without paid Pro).
		// Don't spam logs every minute — categorize-and-bucket via the
		// counter so alerting can distinguish "wedged" from "no schema yet".
		reason := classifyPollError(err)
		pluginLicensePollFailuresTotal.WithLabelValues(reason).Inc()
		// Log once per shape (caller has the full err text for diagnostics).
		log.Printf("[plugin_license_metrics] poll failed (active): %v", err)
		return
	}

	var all int64
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM plugin_user_licenses`).Scan(&all); err != nil {
		pluginLicensePollFailuresTotal.WithLabelValues(classifyPollError(err)).Inc()
		log.Printf("[plugin_license_metrics] poll failed (all): %v", err)
		return
	}

	// CURRENT_DATE in Postgres returns the date in the session timezone.
	// agent connections default to UTC because RDS is created with
	// timezone=UTC and we don't issue a SET timezone — confirmed by reading
	// the existing audit_cleanup queries which do the same.
	var issuedToday int64
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		  FROM plugin_user_licenses
		 WHERE issued_at >= CURRENT_DATE
		   AND issued_at <  CURRENT_DATE + INTERVAL '1 day'`).Scan(&issuedToday); err != nil {
		pluginLicensePollFailuresTotal.WithLabelValues(classifyPollError(err)).Inc()
		log.Printf("[plugin_license_metrics] poll failed (issued_today): %v", err)
		return
	}

	var expiring7d int64
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		  FROM plugin_user_licenses
		 WHERE revoked_at IS NULL
		   AND expires_at IS NOT NULL
		   AND expires_at >  NOW()
		   AND expires_at <= NOW() + INTERVAL '7 days'`).Scan(&expiring7d); err != nil {
		pluginLicensePollFailuresTotal.WithLabelValues(classifyPollError(err)).Inc()
		log.Printf("[plugin_license_metrics] poll failed (expiring_7d): %v", err)
		return
	}

	var revokedToday int64
	if err := db.QueryRowContext(ctx, `
		SELECT count(*)
		  FROM plugin_user_licenses
		 WHERE revoked_at >= CURRENT_DATE
		   AND revoked_at <  CURRENT_DATE + INTERVAL '1 day'`).Scan(&revokedToday); err != nil {
		pluginLicensePollFailuresTotal.WithLabelValues(classifyPollError(err)).Inc()
		log.Printf("[plugin_license_metrics] poll failed (revoked_today): %v", err)
		return
	}

	pluginLicenseActiveTotal.Set(float64(active))
	pluginLicenseAllTotal.Set(float64(all))
	pluginLicenseIssuedTodayTotal.Set(float64(issuedToday))
	pluginLicenseExpiring7dTotal.Set(float64(expiring7d))
	pluginLicenseRevokedTodayTotal.Set(float64(revokedToday))
	pluginLicenseLastPollTimestamp.Set(float64(time.Now().Unix()))
}

// classifyPollError produces a small, bounded label set for the
// poll-failures counter. Cardinality matters here — a label that takes the
// raw error.Error() would balloon the metric series with permutations of
// connection-state strings. Three buckets is enough for alerting.
func classifyPollError(err error) string {
	if err == nil {
		return "ok"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "context canceled"), strings.Contains(msg, "context deadline exceeded"):
		return "context_canceled"
	case strings.Contains(msg, "does not exist"), strings.Contains(msg, "42P01"):
		return "table_missing"
	default:
		return "db_error"
	}
}
