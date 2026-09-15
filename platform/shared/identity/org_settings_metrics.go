// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// MetricOrgSettingsReadFailures counts failed reads of identity_org_settings.
// It is a constant so every reader of it - a dashboard, an alert rule - names
// one spelling.
const MetricOrgSettingsReadFailures = "axonflow_identity_org_settings_read_failures_total"

// orgSettingsReadFailures is registered in both editions so the series always
// exists; only the Enterprise store increments it.
//
//nolint:unused // incremented by observeOrgSettingsReadFailure, which the enterprise build's org_settings.go calls
var orgSettingsReadFailures = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: MetricOrgSettingsReadFailures,
		Help: "Failed reads of identity_org_settings, counted whether or not a last-good row masked the failure from the caller.",
	},
	[]string{"component"},
)

// observeOrgSettingsReadFailure counts one failed read of
// identity_org_settings. It is called from the Enterprise store
// (org_settings.go); the counter is declared here, untagged, so the metric
// surface is one file in both editions and a community build exports the
// (permanently zero) series rather than omitting it.
//
// CI lints this package WITHOUT the enterprise tag, where this function is
// declared and called nowhere - the community build genuinely has no store to
// call it, by design.
//
//nolint:unused // called by dbOrgIdentitySettingsStore.read in org_settings.go (enterprise build)
func observeOrgSettingsReadFailure(component string) {
	orgSettingsReadFailures.WithLabelValues(component).Inc()
}
