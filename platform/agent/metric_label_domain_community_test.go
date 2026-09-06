//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// runEnterpriseOnlyDrivers is a no-op in the community build.
//
// The client-version family's vecs are declared in an //go:build enterprise
// file, so they do not exist here at all - which is exactly why
// behaviourallyDrivenMetrics documents that pair as driven only under that tag,
// and why guardedCollectors cannot name them. The membership measurement in
// TestTheDrivenSetIsWhatItClaims therefore does not judge them in this build.
func runEnterpriseOnlyDrivers(t *testing.T) { t.Helper() }

// enterpriseOnlyCollectors is empty here: the client-version vecs are declared
// in an //go:build enterprise file and do not exist in this build.
func enterpriseOnlyCollectors() map[string]prometheus.Collector { return nil }

// unmeasurableInThisBuild names the metrics whose membership this build cannot
// measure, with the reason. Stated rather than silently skipped: a metric that
// is simply absent from the collector map would otherwise look like an
// oversight, and the next reader could not tell the two apart.
func unmeasurableInThisBuild() map[string]string {
	return map[string]string{
		"axonflow_client_version_requests_total": "declared in an enterprise-tagged file; " +
			"driven and measured by the enterprise arm",
		"axonflow_client_version_dropped_total": "declared in an enterprise-tagged file; " +
			"driven and measured by the enterprise arm",
	}
}
