//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Community-build contract for the per-client version telemetry (#2860): the
// recorder is a no-op and — critically — the metric is NOT registered on the
// default Prometheus registry. An always-empty
// axonflow_client_version_requests_total series on a self-hosted community
// deployment would read as "no clients" rather than "not measured" (same
// rationale as plugin_license_metrics_community.go). This runs only in the
// untagged (community) test lane; the enterprise lane has its own capture
// tests. Guards against a future refactor that moves the CounterVec
// declarations into an untagged file.
func TestClientVersionTelemetry_CommunityNoOpAndUnregistered(t *testing.T) {
	// The no-op must be callable with any input without panicking or affecting
	// anything (it takes no lock, registers nothing).
	recordClientVersionTelemetry(PlaneDecision, "mcp-proxy/0.3.0")
	recordClientVersionTelemetry(PlaneMCP, "garbage <script>")
	recordClientVersionTelemetry("", "")

	// Gather the default registry and assert the enterprise-only metric family
	// is absent — proof the counters are not registered on a community build.
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather default registry: %v", err)
	}
	for _, mf := range families {
		if strings.HasPrefix(mf.GetName(), "axonflow_client_version_") {
			t.Errorf("community build registered %q — must be enterprise-only", mf.GetName())
		}
	}
}
