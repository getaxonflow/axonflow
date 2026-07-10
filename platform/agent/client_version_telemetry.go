//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"regexp"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Per-client version-distribution telemetry (#2860).
//
// The X-Axonflow-Client header (ADR-050 §4, "<client>/<version>", e.g.
// "claude-code-plugin/1.9.1", "mcp-proxy/0.3.0", "sdk-go/8.5.0") is today
// consumed on the decide plane ONLY as an input to classifyDecisionOrigin,
// which deliberately strips the version to keep the `origin` metric label a
// closed enum. On community-SaaS the full value additionally rides the CSaaS
// SQS telemetry middleware (community_saas_telemetry.go:362) into the DDB
// distribution table — but that middleware is attached only under
// DEPLOYMENT_MODE=community-saas, so a self-hosted Enterprise deployment has
// ZERO visibility into which client versions its fleet runs. That blind spot
// is exactly how the claude-code plugin's three-releases-in-one-bucket drift
// (its PR #105) went unnoticed, and it is total for the Claude Desktop proxy.
//
// This file closes the gap for Enterprise builds: recordClientVersionTelemetry
// exposes a Prometheus counter
//
//	axonflow_client_version_requests_total{plane, client, client_version}
//
// on the decide + MCP check-output planes, so "is this fleet on the latest
// desktop proxy?" is answerable from Grafana on any self-hosted install.
//
// Edition split (GTM directive): enterprise-only. The community counterpart
// (client_version_telemetry_community.go) is a compile-time no-op and does NOT
// register the metric — an always-empty series on community builds would only
// invite false "no clients" readings (same rationale as
// plugin_license_metrics_community.go).
//
// Fail-open + cardinality contract:
//   - This function is telemetry-only: it never returns an error, never
//     panics on caller-controlled input, and callers MUST NOT gate any
//     decision on it. An absent or malformed header is silently dropped
//     (counted only in the bounded overflow/drop counter).
//   - Header values are SHAPE-VALIDATED before becoming label values (per the
//     classifyDecisionOrigin cardinality/PII note) — an unbounded or
//     structured value can never reach a label. Validation is a shape
//     allowlist, not a client-id allowlist: a well-formed but unrecognized
//     slug (a forward-compat new client) is admitted, bounded by the
//     per-process series cap; past the cap, new pairs are dropped and counted
//     in axonflow_client_version_dropped_total{reason="overflow"}.
const (
	// clientVersionMaxSeries hard-bounds the distinct (plane, client, version)
	// label sets one agent process will ever emit. A cooperating fleet emits a
	// handful (a few clients × a few live versions × 2 planes); the cap only
	// bites an adversarial caller minting synthetic versions, whose goal —
	// unbounded series growth — it defeats.
	clientVersionMaxSeries = 512
)

var (
	clientVersionRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_client_version_requests_total",
			Help: "Requests by validated X-Axonflow-Client client id + version and plane (Enterprise per-client version-distribution telemetry, #2860)",
		},
		[]string{"plane", "client", "client_version"},
	)
	clientVersionDropped = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_client_version_dropped_total",
			Help: "X-Axonflow-Client values not recorded into the version-distribution counter, by reason (absent | invalid | overflow)",
		},
		[]string{"reason"},
	)

	clientVersionSeenMu sync.Mutex
	clientVersionSeen   = make(map[string]struct{}, 64)
)

// clientVersionClientPattern / clientVersionVersionPattern admit only the
// documented ADR-050 §4 shapes. The client id is a lowercase slug
// ("claude-code-plugin", "mcp-proxy", "sdk-go", "openclaw"); the version is a
// semver-ish token ("1.9.1", "0.3.0", "2.4.0-rc1"). Anything else — control
// bytes, HTML, spaces, over-long junk — is dropped as invalid, never emitted
// as a label.
var (
	clientVersionClientPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	clientVersionVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,31}$`)
)

// recordClientVersionTelemetry captures one request's X-Axonflow-Client value
// into the per-client version-distribution counter for the given plane
// (PlaneDecision / PlaneMCP). Telemetry-only: see the fail-open contract in
// the file comment. Community builds compile this to a no-op.
func recordClientVersionTelemetry(plane, clientHeader string) {
	raw := strings.TrimSpace(clientHeader)
	if raw == "" {
		clientVersionDropped.WithLabelValues("absent").Inc()
		return
	}

	// Same split contract as the ingest side's ParseClient
	// (ee/platform/csaas-telemetry-ingest/pkg/ingest/state.go): the LAST "/"
	// separates client id from version; no "/" means an unversioned client id.
	client, version := raw, ""
	if idx := strings.LastIndex(raw, "/"); idx > 0 && idx < len(raw)-1 {
		client, version = raw[:idx], raw[idx+1:]
	}
	client = strings.ToLower(client)
	if version == "" {
		// Unversioned but well-formed client ids (bare "claude-code-plugin")
		// still count — an explicit bucket keeps them visible without letting
		// an empty label hide them.
		version = "unversioned"
	}
	if !clientVersionClientPattern.MatchString(client) || !clientVersionVersionPattern.MatchString(version) {
		clientVersionDropped.WithLabelValues("invalid").Inc()
		return
	}

	key := plane + "\x00" + client + "\x00" + version
	clientVersionSeenMu.Lock()
	if _, ok := clientVersionSeen[key]; !ok {
		if len(clientVersionSeen) >= clientVersionMaxSeries {
			clientVersionSeenMu.Unlock()
			clientVersionDropped.WithLabelValues("overflow").Inc()
			return
		}
		clientVersionSeen[key] = struct{}{}
	}
	clientVersionSeenMu.Unlock()

	clientVersionRequests.WithLabelValues(plane, client, version).Inc()
}
