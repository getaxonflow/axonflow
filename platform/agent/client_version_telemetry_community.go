//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// recordClientVersionTelemetry in community builds is a no-op (#2860).
//
// Per-client version-distribution telemetry is an Enterprise feature (GTM
// directive: new platform features are Enterprise-gated). The Prometheus
// counters are NOT registered on community builds, by design: an always-empty
// axonflow_client_version_requests_total series on a self-hosted community
// deployment would read as "no clients" rather than "not measured" (same
// rationale as plugin_license_metrics_community.go). Community-SaaS
// deployments already capture the full X-Axonflow-Client value through the
// CSaaS SQS telemetry middleware (community_saas_telemetry.go).
//
// The signature matches client_version_telemetry.go exactly so the decide and
// MCP check-output call sites compile unconditionally.
func recordClientVersionTelemetry(_, _ string) {}
