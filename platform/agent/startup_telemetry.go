// Package agent — the agent's platform-level startup telemetry ping (#2004 PR2).
//
// THE EMITTER LIVES IN platform/shared/heartbeat. This file is the agent's
// binding to it: which component name, which stamp file, which version, which
// edition, and where the licence tier comes from. Everything else — the stamp
// format, the 7-day rate limit, the opt-out gate, the CI auto-suppress, the
// environment-class detection, the payload shape and the POST — is shared with
// the orchestrator and the gateway adapters, because it was copied between them
// before #3660 and the copies had already drifted (the orchestrator omitted
// org_id, so the receiver's primary internal-classification rule could never
// fire on an orchestrator row).
//
// Two agent-specific differences from the orchestrator binding, both #2004
// amendment-locked:
//
//  1. instance_id is PERSISTED in the stamp file rather than regenerated per
//     startup as the SDKs do, so the 7-day rate limit and the longitudinal
//     analytics property both hold.
//  2. license_tier is read from the package-level atomic the validated-licence
//     path populates, so agent pings carry the real tier.
//
// The community-SaaS emission skip that used to live here is GONE (#3660): it
// made the platform table's deployment-mode column single-valued by
// construction. AxonFlow-operated stacks now report and are classified internal
// by the receiver from their `axonflow-`-prefixed org_id. See the
// platform/shared/heartbeat package doc.
//
// See runtime-e2e/agent_startup_ping/ and
// runtime-e2e/3660_platform_ping_edition_mode/ for the runtime proof bundles.
package agent

import (
	"context"
	"fmt"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
)

// startupTelemetryComponent is the literal "agent" identifier the checkpoint
// validator gates platform pings on. Taken from the shared vocabulary rather
// than spelled here, so a rename is a single-point change.
const startupTelemetryComponent = heartbeat.ComponentAgent

// stampFilename keeps the rate limit per-binary: a host running both the agent
// and the orchestrator emits one ping per binary per 7 days, not one combined
// ping.
const stampFilename = "agent-startup-telemetry-stamp"

// SetLicenseTierForRuntimeTest is the runtime-e2e bundle's hook for forcing a
// deterministic licence tier into the package-level atomic, so a runtime test's
// payload assertions do not depend on whatever the host environment's licence
// loader happened to populate. Production callers MUST NOT use it — the tier is
// set by the validated-licence path inside Run(). It is exported only because
// the runtime-e2e wrappers live in a separate `package main`.
func SetLicenseTierForRuntimeTest(tier string) error {
	if tier == "" {
		return fmt.Errorf("tier must be non-empty")
	}
	licenseTier.Store(tier)
	return nil
}

// MaybeSendStartupTelemetry is the single entry point, called once at agent
// startup after appReady.Store(true). See heartbeat.Send for the full
// algorithm, the gates and the privacy commitments.
//
// Returns (sent, error) exactly as heartbeat.Send does.
func MaybeSendStartupTelemetry(ctx context.Context) (bool, error) {
	return heartbeat.Send(ctx, heartbeat.Config{
		Component:       startupTelemetryComponent,
		StampFilename:   stampFilename,
		PlatformVersion: GetPlatformVersion(),
		// edition.Current is a compile-time constant: this binary knows with
		// certainty which build it is, which is the one thing DEPLOYMENT_MODE,
		// the licence tier and the schema cannot tell you.
		Edition:          edition.Current,
		LicenseTier:      currentLicenseTier(),
		InstanceIDPrefix: startupTelemetryComponent,
	})
}
