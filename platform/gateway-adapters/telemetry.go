// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"context"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"log"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/shared/edition"
	"axonflow/platform/shared/heartbeat"
	"axonflow/platform/shared/version"
)

// THE ADAPTERS WERE INVISIBLE. THIS FILE IS WHY THEY ARE NOT (#3660, #2886).
//
// Before this, `grep -lE 'prometheus|client_version|X-Axonflow-Client'` over
// this package returned NOTHING. The whole agentgateway integration surface —
// three gRPC seams fronting a customer's LLM and MCP traffic — emitted no ping,
// no metric and no client header. It was not measured as adopted, it did not
// appear in any operator digest, and a fleet running it looked identical to a
// fleet that had never deployed it.
//
// Three signals close that, and each answers a different question:
//
//	the startup ping         "does this deployment run the adapters at all?"
//	the X-Axonflow-Client    "which adapter version is calling the engine?"
//	the per-surface counters "which seam is doing the work, and what did it decide?"
//
// # NOTHING HERE CARRIES REQUEST CONTENT
//
// Every label below is drawn from a closed set fixed in this file. No path, no
// method, no host, no model, no tenant, no decision id, and nothing derived
// from a prompt or a body ever becomes a label value. That is not a convention
// to be careful about — the label values are compile-time constants, so there
// is no code path through which caller data could reach one.

// ClientID is the identifier this adapter puts on `X-Axonflow-Client` for every
// engine round-trip, as `<ClientID>/<version>`.
//
// It has to satisfy the agent's shape validator
// (platform/agent/client_version_telemetry.go), which is a SHAPE allowlist
// rather than a list of known ids: a lowercase slug of [a-z0-9._-] up to 64
// bytes is admitted, and a well-formed unrecognised slug is deliberately
// allowed through as forward-compatibility, bounded by that counter's
// per-process series cap. `gateway-adapters` matches, so nothing needs to be
// added to a validator for this header to be counted.
//
// It is deliberately the SAME string as telemetry.ComponentGatewayAdapters and
// heartbeat.ComponentGatewayAdapters: one integration, one name, whether you
// are reading the ping's component dimension or the client-version counter.
const ClientID = heartbeat.ComponentGatewayAdapters

// Edition is what this binary reports as its build, and it is edition.Current:
// whatever THIS compilation actually is.
//
// IT USED TO BE A CONSTANT `edition.Enterprise`, AND THE COMMENT DEFENDING THAT
// IS WHY THIS ONE IS LONG. The argument was: the standalone image is built
// without `-tags enterprise`, so edition.Current reads `community` inside it —
// true of the compilation and false of the artifact — and "there is no community
// edition of this image; the component ships in one edition only". Every clause
// of that was true when written.
//
// Moving this package to a community-syncable location under BSL 1.1 falsified
// its premise. There IS a community edition now: the mirror carries this source,
// a community build compiles it, and the constant would have made every one of
// those deployments report `edition=enterprise` — silently, with no error and
// nothing in a log, inflating the paid share of the adoption split. That is the
// same shape as the org_id defect this file already documents, and the earlier
// comment was written specifically to stop someone changing this line, so it
// would have defended the wrong value rather than merely gone stale.
//
// edition.Current is correct on both sides now BECAUSE the premise changed:
// the enterprise artifact is built with the tag and the community one without,
// so the build tag and the artifact finally agree. If a future image is built
// without the tag but shipped as Enterprise, this becomes wrong again — and the
// fix then is to make the BUILD match the artifact, not to pin the constant
// back. runtime-e2e/2886's client-header leg asserts both editions on the wire.
const Edition = edition.Current

// stampFilename keeps the adapter's 7-day rate limit independent of the agent's
// and the orchestrator's, so a host running all three emits one ping per binary
// rather than one combined ping.
const stampFilename = "gateway-adapters-startup-telemetry-stamp"

// Surfaces — which of the three seams handled the request. A closed set,
// spelled here, never derived from anything a caller sends.
const (
	SurfaceExtAuthz = "ext_authz"
	SurfaceExtProc  = "ext_proc"
	SurfaceExtMcp   = "ext_mcp"
)

// Metric outcome labels. THREE, and the distinction between `deny` and `error`
// is the one that matters operationally:
//
//	allow — the engine returned a verdict and the operation went through.
//	deny  — the engine returned a verdict and it refused. A POLICY result.
//	error — no verdict was obtained: the PDP was unreachable, refused the
//	        adapter's credentials, or the leg was misconfigured. NOT a policy
//	        result, and an operator paging on a deny spike must be able to tell
//	        the two apart — a fail-closed block during a PDP outage looks
//	        exactly like a policy tightening if they are pooled.
//
// NAMED WITH A `Metric` PREFIX BECAUSE THIS PACKAGE ALREADY HAS AN `Outcome*`
// ENUM, and that one is the authority. RequestOutcome's kinds (pdp.go) are what
// the seams actually branch on — five of them, including the
// allow-with-redaction and fail-open cases this three-value label deliberately
// folds together. metricOutcome below is the ONE mapping from that enum onto
// these labels, so the metric cannot acquire an opinion the seams do not have.
const (
	MetricOutcomeAllow = "allow"
	MetricOutcomeDeny  = "deny"
	MetricOutcomeError = "error"
)

// metricOutcome maps the package's own RequestOutcome kind onto the metric
// label. It is the single mapping point: a new kind added to that enum lands
// here as a compile-time-visible gap rather than silently counting as `error`.
//
//   - OutcomeAllow, OutcomeAllowRedacted, OutcomeFailOpen -> allow. The caller's
//     request went through in all three, which is what `allow` reports. A
//     redaction is not a refusal, and a fail-open allow is still an allow from
//     the caller's side; the outage it happened during is visible on `error`
//     from the legs that failed closed, and in the adapter's logs.
//   - OutcomeDeny -> deny. A verdict said no.
//   - OutcomeFailClosed -> error. NO VERDICT WAS OBTAINED. It blocks the
//     caller, but pooling it with `deny` would make a PDP outage read as a
//     policy tightening on the graph an operator pages from.
func metricOutcome(kind int) string {
	switch kind {
	case OutcomeAllow, OutcomeAllowRedacted, OutcomeFailOpen:
		return MetricOutcomeAllow
	case OutcomeDeny:
		return MetricOutcomeDeny
	case OutcomeFailClosed:
		return MetricOutcomeError
	default:
		// An unrecognised kind is a bug in this mapping, not a verdict. Count
		// it as error rather than silently as allow: an over-count on the
		// alerting series is recoverable, an under-count is not.
		return MetricOutcomeError
	}
}

var (
	// surfaceOutcomes is the per-seam verdict distribution. Bounded by
	// construction at 3 surfaces x 3 outcomes = 9 series, for the life of the
	// process: both label values come from the constants above and there is no
	// path by which a request can introduce a tenth.
	surfaceOutcomes = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_adapter_decisions_total",
			Help: "Governed operations by adapter surface (ext_authz | ext_proc | ext_mcp) and outcome (allow | deny | error). `deny` is a POLICY refusal; `error` means no verdict was obtained at all, so a fail-closed block during a PDP outage is never counted as a policy tightening. No request content, path, method, model or tenant appears in any label (#3660, #2886)",
		},
		[]string{"surface", "outcome"},
	)
)

// blockOutcomeForStatus maps a locally-generated block status onto the
// deny/error split, for every seam that answers with an HTTP-ish status.
//
// ONE FUNCTION, BECAUSE TWO COPIES OF THIS SWITCH ALREADY DISAGREED. ext_proc
// listed PayloadTooLarge as `error` and gave the reason — "counting it as a
// policy deny would make a body-size misconfiguration look like a policy
// tightening" — while ext_authz's otherwise identical switch omitted the case
// entirely, so the SAME condition, a body too large for this adapter to scan,
// was counted as a policy refusal on one seam and a failure on the other.
// ext_mcp agrees with ext_proc through its own vocabulary (RESOURCE_EXHAUSTED),
// which made ext_authz the single outlier of three.
//
// It is `error` on all of them, and the reason is what the operator does next:
// none of these blocks carries a verdict from the engine. A deny graph is read
// as "policy is refusing traffic" and an error graph as "the governance path is
// failing" — and raising MaxBodyBytes, not editing a policy, is what fixes this
// one.
//
// Fixing only the seam that was reported would have left two paths disagreeing
// in a NEW way, which is why both now read from here.
func blockOutcomeForStatus(code typev3.StatusCode) string {
	switch code {
	case typev3.StatusCode_ServiceUnavailable,
		typev3.StatusCode_InternalServerError,
		typev3.StatusCode_PayloadTooLarge:
		return MetricOutcomeError
	}
	return MetricOutcomeDeny
}

// recordOutcome counts one governed operation.
//
// Telemetry-only, and it must stay that way: it never returns an error, never
// panics, and no caller may branch on it. It takes only values from the closed
// sets above — the signature carries strings, but every call site in this
// package passes a constant, and the test suite asserts the emitted label set
// is exactly the 3x3 product.
func recordOutcome(surface, outcome string) {
	surfaceOutcomes.WithLabelValues(surface, outcome).Inc()
}

// MaybeSendStartupTelemetry fires the adapter's platform-class heartbeat.
//
// It goes through platform/shared/heartbeat — the ONE emitter the agent and the
// orchestrator also use — rather than a third copy of the stamp file, the rate
// limit, the opt-out gate, the CI auto-suppress and the POST. Extracting that
// in #3660 is what made this file eleven lines instead of four hundred, and it
// means a fix to any of those lands here automatically.
//
// # WHAT EACH IDENTITY FIELD ON THIS BINARY'S ROW ACTUALLY MEANS
//
// org_id — PASSED EXPLICITLY from cfg.OrgID, and it must be. The shared
// emitter's env fallback reads ORG_ID; this binary's entire configuration
// surface is AXONFLOW_-prefixed and it reads AXONFLOW_ORG_ID. Before the
// parameter below existed, the adapters' ping therefore carried NO org_id in
// every deployment — and the classifier reads a missing org as "not one of
// ours", so every AxonFlow-operated deployment of this component counted as
// EXTERNAL adoption. That is the identical defect #3662 fixed on the
// orchestrator, reintroduced from the other side one PR later.
//
// license_tier — deliberately NOT set. This binary holds a licence key to
// AUTHENTICATE to the PDP; it does not validate one, so it cannot report a
// runtime-effective tier. An empty tier is OMITTED from the payload — "not
// reported", which is the honest claim, and a different one from "unknown"
// ("reports the dimension, had not resolved it"). The agent in the same
// deployment carries the real tier.
//
// platform_deployment_mode — read from DEPLOYMENT_MODE by the shared emitter,
// a variable THIS BINARY DOES NOT OTHERWISE READ. In the shipped shape the
// adapters run in the same task definition as the agent and inherit it; where
// they do not, PlatformDeploymentMode() returns "" and the field is OMITTED.
// That is the correct outcome and the reason it must stay a fallback rather
// than a default: an absent mode says "not reported", which is true, whereas
// defaulting it would state a configuration this process never observed.
//
// deployment_mode (topology) — `self_hosted` on every row this binary emits,
// because TopologyDeploymentMode() answers `community_saas` only when
// DEPLOYMENT_MODE is exactly that, and Community-SaaS does not deploy gateway
// adapters. The value is therefore right, but it is right by CONSTRUCTION and
// not by measurement, so read it as "this component only ships self-hosted"
// and not as evidence about the deployment. TestTopologyIsConstantForThisBinary
// pins that reading; if adapters ever ship in the SaaS, it goes red.
//
// Fire-and-forget: errors are logged and never fail startup.
func MaybeSendStartupTelemetry(ctx context.Context, cfg Config) (bool, error) {
	return heartbeat.Send(ctx, heartbeat.Config{
		Component:     heartbeat.ComponentGatewayAdapters,
		StampFilename: stampFilename,
		// The receiver REJECTS a platform-class ping with no platform_version,
		// so an unbaked binary's ping would be dropped with HTTP 400 and this
		// emitter would swallow the non-2xx. The Dockerfile bakes the version
		// via -ldflags for exactly this reason.
		PlatformVersion:  version.Resolve(),
		Edition:          Edition,
		OrgID:            cfg.OrgID,
		InstanceIDPrefix: heartbeat.ComponentGatewayAdapters,
	})
}

// StartTelemetry runs the heartbeat in the background, logging the outcome.
// Called once from main after the server is constructed.
func StartTelemetry(ctx context.Context, cfg Config) {
	go func() {
		sent, err := MaybeSendStartupTelemetry(ctx, cfg)
		switch {
		case err != nil:
			log.Printf("[gateway-adapters] startup telemetry: %v", err)
		case sent:
			log.Printf("[gateway-adapters] startup telemetry: ping delivered")
		}
	}()
}
