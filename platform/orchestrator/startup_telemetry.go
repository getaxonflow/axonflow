// Package orchestrator — the orchestrator's platform-level startup telemetry
// ping (#2004 PR3, the orchestrator half of the agent+orchestrator pair).
//
// THE EMITTER LIVES IN platform/shared/heartbeat. This file is the
// orchestrator's binding to it. Before #3660 it was a near-verbatim COPY of the
// agent's file, and the copy had drifted in a way that mattered: it omitted
// org_id, so telemetry-filter rules 6 and 7 — the primary internal-vs-external
// classification signal since PR #2236 — could never fire on an orchestrator
// row. AxonFlow-operated orchestrators were classified internal only by the
// legacy rule 8 that digest.go documents as retiring, and would have
// reclassified as external customers on the day it retired. Sharing the emitter
// closes that class: org_id now rides every platform ping because there is one
// place that builds one.
//
// Two orchestrator-specific differences remain, and both are deliberate:
//
//  1. component="orchestrator" — the analytics warehouse uses this dimension to
//     slice deployments by which binaries are running.
//  2. The stamp filename carries an "orchestrator-" prefix so each binary
//     rate-limits independently: a host running both emits ONE ping per binary
//     per 7 days, not one combined ping.
//
// license_tier is still not read from a licence object here, and the field is
// still OMITTED rather than reported as "unknown". The orchestrator resolves
// its tier through a per-Service licenseChecker instance rather than a
// package-level atomic, so a startup-time helper cannot query it without
// coupling to handler initialisation — this binding cannot determine a tier at
// all, which is "not reported", not "reported but unresolved". That is also the
// pre-extraction wire shape, byte for byte: the old payload struct left the
// field empty and omitempty dropped the key. Agent pings from the same
// deployment carry the real tier.
package orchestrator

import (
	"context"
	"os"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

const startupTelemetryComponent = heartbeat.ComponentOrchestrator

// stampFilename — see the package doc for why the prefix matters.
const stampFilename = "orchestrator-startup-telemetry-stamp"

// MaybeSendStartupTelemetry is the single entry point, wired into
// platform/orchestrator/run.go in a goroutine before ListenAndServe. See
// heartbeat.Send for the algorithm, the gates and the privacy commitments.
//
// Returns (sent, error) exactly as heartbeat.Send does.
func MaybeSendStartupTelemetry(ctx context.Context) (bool, error) {
	// AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE is a runtime-e2e bundle hook —
	// production must never set it. It lets a proof script seed a deterministic
	// tier without coupling to per-Service licenseChecker initialisation. Empty
	// (the production case) passes through as empty and omitempty drops the
	// field, which is the pre-extraction wire shape — see the package doc.
	licenseTier := os.Getenv("AXONFLOW_TELEMETRY_LICENSE_TIER_OVERRIDE")

	return heartbeat.Send(ctx, heartbeat.Config{
		Component:        startupTelemetryComponent,
		StampFilename:    stampFilename,
		PlatformVersion:  getPlatformVersion(),
		Edition:          edition.Current,
		LicenseTier:      licenseTier,
		InstanceIDPrefix: startupTelemetryComponent,
	})
}
