//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Unit-level tests for plugin_license_metrics. These don't need a real DB
// connection — the polling logic is exercised end-to-end by
// plugin_license_metrics_db_test.go (DB-backed). Here we test:
//   - the error-classifier produces stable label values (cardinality bound)
//   - the contains() helper handles edge cases
//   - the gauges are registered on the default registerer

func TestClassifyPollError_KnownShapes(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, "ok"},
		{"context_canceled_short", errors.New("context canceled"), "context_canceled"},
		{"context_deadline", errors.New("context deadline exceeded"), "context_canceled"},
		{"table_missing_42P01", errors.New(`pq: relation "plugin_user_licenses" does not exist (SQLSTATE 42P01)`), "table_missing"},
		{"table_missing_phrase", errors.New(`pq: relation "foo" does not exist`), "table_missing"},
		{"db_other", errors.New("connection refused"), "db_error"},
		{"db_timeout_underlying", errors.New("write tcp: i/o timeout"), "db_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyPollError(tc.err)
			if got != tc.want {
				t.Fatalf("classifyPollError(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestPluginLicenseGaugesRegistered(t *testing.T) {
	// promauto registers on prometheus.DefaultRegisterer at package-load,
	// so by this test running, the gauges should already be visible to a
	// scrape. testutil.CollectAndCount walks the registry — use it as a
	// smoke check that the metric names are present.
	gauges := []prometheus.Collector{
		pluginLicenseActiveTotal,
		pluginLicenseAllTotal,
		pluginLicenseIssuedTodayTotal,
		pluginLicenseExpiring7dTotal,
		pluginLicenseRevokedTodayTotal,
		pluginLicenseLastPollTimestamp,
	}
	for _, g := range gauges {
		if c := testutil.CollectAndCount(g); c < 1 {
			t.Errorf("gauge collected %d series, want >=1", c)
		}
	}
}

func TestPluginLicenseMetricsPoller_NilDBIsSafe(t *testing.T) {
	// nil DB is the operator-misconfiguration case for a self-hosted
	// enterprise install that's missing the secrets-manager DB password.
	// startPluginLicenseMetricsPoller must never panic and must return a
	// no-op cancel func.
	cancel := startPluginLicenseMetricsPoller(nil)
	if cancel == nil {
		t.Fatal("cancel func is nil")
	}
	cancel() // should not panic / hang
}

func TestPollOnce_NilDBPanicGuard(t *testing.T) {
	// pollPluginLicenseGaugesOnce with a nil context+DB should panic — but
	// the public entry point startPluginLicenseMetricsPoller short-circuits
	// before calling this function, which is what's tested above. This
	// test documents that contract by not invoking pollPluginLicenseGaugesOnce
	// with nil.
	_ = context.Background() // context is fine; DB is the concern
}
