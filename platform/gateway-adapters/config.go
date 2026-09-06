// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// Fail-mode values for the REQUEST plane. The response plane has no posture
// knob for RUNTIME failures — it is unconditionally fail-closed (see package
// doc). Whether a leg has a response plane at all is a separate, static,
// adapter-side choice: ExtProcResponseGovernance below.
const (
	FailModeClosed = "closed"
	FailModeOpen   = "open"
)

// ExtProc response-governance postures (AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE).
//
// This is NOT a fail-mode. It decides which gateway-advertised response body
// modes the ext_proc seam will ACCEPT, and it is deliberately adapter-side:
// the gateway config alone must never be able to turn response governance off.
const (
	// ExtProcResponseGovernanceBuffered (default) requires every ext_proc leg
	// to hand this adapter the whole response body, so every response is
	// scanned. A leg advertising any other response mode is rejected
	// fail-closed.
	ExtProcResponseGovernanceBuffered = "buffered"

	// ExtProcResponseGovernanceOff additionally accepts a leg that advertises
	// responseBodyMode: none — the gateway never shows this adapter the
	// response body, so THE RESPONSE IS NOT GOVERNED on that leg: no
	// check-output scan, no response redaction, no response-plane block.
	//
	// This exists for streaming (SSE) completions, where the response cannot
	// be buffered without destroying the stream. It buys inline REQUEST
	// redaction — the prompt is still decided and engine-redacted before it
	// reaches the provider — at the price of the response plane. Use the MCP
	// seam or a buffered leg when responses must be governed.
	//
	// The knob is process-wide: with it set, ANY ext_proc route on this
	// adapter may drop response governance by advertising none. Run a
	// separate adapter process for legs that must keep it.
	ExtProcResponseGovernanceOff = "off"
)

// envExtProcResponseGovernance is named in the rejection message a
// misconfigured leg receives, so the fix is discoverable from the error alone.
const envExtProcResponseGovernance = "AXONFLOW_EXTPROC_RESPONSE_GOVERNANCE"

// Default limits. maxBodyBytes mirrors the pep client's check-output bound: a
// payload the engine cannot scan must not be forwarded.
const (
	defaultListenAddr     = ":9090"
	defaultRequestTimeout = 10 * time.Second
	defaultMaxBodyBytes   = 8 << 20 // 8 MB
	defaultBreakerTrips   = 5
	defaultBreakerCool    = 30 * time.Second
)

// Config configures the adapter server. All adapters share one PDP client,
// one posture, and one listener.
type Config struct {
	// ListenAddr is the gRPC listen address for all three services.
	ListenAddr string

	// AxonFlowEndpoint is the PDP base URL, e.g. "http://agent:8080".
	AxonFlowEndpoint string

	// OrgID + LicenseKey are the HTTP Basic credentials (org:license-key) the
	// enterprise PDP authenticates. All-or-nothing.
	OrgID      string
	LicenseKey string

	// TenantID scopes decisions + fulfillment.
	TenantID string

	// GatewayID is the caller_identity.gateway_id stamped on every decide —
	// it attributes the decision to this gateway layer in the audit trail.
	GatewayID string

	// ConnectorTag is the connector_type the fulfillment endpoints record
	// (a synthetic origin tag; the engine is connector-agnostic for gateways).
	ConnectorTag string

	// DefaultStage is the decide stage for the HTTP seams (ext_authz,
	// ext_proc) when the GATEWAY CONFIG does not override it per route —
	// ext_authz via the "axonflow-stage" context extension, ext_proc via the
	// metadataContext key axonflow.stage. Overrides are honored only from
	// those gateway-controlled channels, never from client request headers.
	// One of "llm", "tool", "agent". The ExtMcp seam always uses stage
	// "tool".
	DefaultStage string

	// FailMode is the REQUEST-plane posture when the PDP is unreachable:
	// FailModeClosed (default) blocks, FailModeOpen forwards. A PDP 4xx
	// rejection or an unfulfillable obligation blocks regardless.
	FailMode string

	// RequestTimeout bounds every engine call (the defensive-timeout half of
	// the circuit posture; a hung engine can never wedge a callout past it).
	RequestTimeout time.Duration

	// PEPAudience opts this process into the ADR-065 capability handshake
	// (#3704) and names the audience it expects decision proofs to be bound to.
	//
	// SET AS `AXONFLOW_PEP_AUDIENCE`. Both names are load bearing in different
	// places - the environment variable is what an operator sets, this field is
	// what a reader of the code finds - so anything documenting one should name
	// the other, or a brief names one spelling and the operator searches for
	// the other.
	//
	// EMPTY IS THE DEFAULT AND MEANS NO HANDSHAKE, and the transition it gates
	// is ALLOW -> DENY rather than the block-to-block one an earlier version of
	// this comment claimed.
	//
	// TODAY, with no handshake: the headers-only seam declares
	// request_header_mutation on #2958's axis, the PDP SUPPRESSES the
	// request-body redaction it cannot discharge, and the organization's
	// obligation-fallback posture decides. That posture's documented default is
	// `log`, so the request is ALLOWED, minus the obligation, with the
	// suppression on the audit row. ObligationBackstop does not fire - it
	// cannot, because the obligation was already withheld, which is exactly why
	// it is documented as never-firing.
	//
	// WITH THIS SET, AGAINST AN ENTERPRISE DEPLOYMENT: the seam's honest
	// ADR-065 declaration is an EMPTY capability set, so the platform answers
	// CapabilityDeclaredNone and DENIES before the seam gate runs. A deployment
	// that acquired the header without asking would therefore start refusing
	// every PII-matching request through the ext_authz seam and ext_proc's
	// bodyless leg.
	//
	// AGAINST A COMMUNITY DEPLOYMENT, NOTHING CHANGES AT ALL. The capability
	// deny is physically absent from a community build, so the declaration is
	// read, bound and counted and then acted on by nothing. An operator on a
	// community deployment who reads only the paragraph above would expect
	// every PII-matching request to start being refused, and would get no
	// change.
	//
	// That may well be the posture an operator wants - it is the ADR-065
	// invariant-8 answer, reached before the content is held rather than after -
	// but it is a change in what callers see, so it is opt-in and stated here
	// rather than discovered in production. An organization whose
	// obligation-fallback posture is already `block` sees no change.
	//
	// THE VALUE MUST BE 1-128 bytes matching `^[A-Za-z0-9][A-Za-z0-9._:/-]*$` -
	// a URI, a URN or a bare name all fit. A value outside it makes NewPDP
	// return an error, so the adapter refuses to start rather than silently
	// sending nothing: a half-configured enforcement point that looks
	// configured is worse than one that will not boot. The error names the
	// audience, not the handshake.
	//
	// There is no PEP NAME setting: the two seams name themselves, because
	// their identity is a property of the call path rather than of the
	// deployment, and letting an operator rename them would let two deployments
	// report the same capability set under different enforcement points.
	PEPAudience string

	// MaxBodyBytes bounds any single governed payload (MCP params/result,
	// HTTP request/response body). Oversized payloads fail closed.
	MaxBodyBytes int

	// BreakerThreshold consecutive PDP-transport failures open the circuit;
	// while open, calls fail fast per posture until BreakerCooldown elapses.
	BreakerThreshold int
	BreakerCooldown  time.Duration

	// TrustIdentityHeaders controls whether inbound X-User-Email /
	// X-Session-Id headers are forwarded on the response-governance call.
	// Default FALSE: those headers are client-assertable, and agentgateway
	// applies route header modifiers AFTER the ext_proc callout (upstream
	// httpproxy.rs apply_request_policies), so no gateway config can strip
	// a forged value before this adapter sees it. Enable ONLY when the
	// deployment guarantees a hop upstream of agentgateway re-sets both
	// headers from a validated source (e.g. a jwtAuth claim).
	//
	// NOTE: the engine's check-output currently derives audit identity
	// from the PDP-validated user_token and IGNORES these headers (a
	// reserved, forward-compat channel — see pep.CheckOutput); the gate
	// exists so that a future engine-side wiring cannot be spoofed by
	// deployments that copied the reference config. Bearer-token identity
	// is unaffected either way.
	TrustIdentityHeaders bool

	// ExtProcResponseGovernance is the adapter-side opt-in deciding whether an
	// ext_proc leg may run with its response plane ungoverned — one of
	// ExtProcResponseGovernanceBuffered (default) or
	// ExtProcResponseGovernanceOff. See those constants for the threat model.
	//
	// The zero value means buffered: it can only arise from a Config literal
	// (ConfigFromEnv always substitutes the default), and it resolves to the
	// SAFE posture, so a caller that never heard of this field keeps full
	// response governance.
	ExtProcResponseGovernance string
}

// responseGovernanceOff reports whether this adapter accepts ext_proc legs
// that advertise responseBodyMode: none. Exact-string match, mirroring the
// AXONFLOW_TRUST_IDENTITY_HEADERS contract (#2896): only the precise opt-in
// value turns governance off; anything else Validate has not already rejected
// stays governed.
func (c *Config) responseGovernanceOff() bool {
	return c.ExtProcResponseGovernance == ExtProcResponseGovernanceOff
}

// ConfigFromEnv builds a Config from AXONFLOW_* environment variables
// (the same convention as the reference Decision Mode adapters).
func ConfigFromEnv() Config {
	return Config{
		ListenAddr:           envOr("GATEWAY_ADAPTERS_LISTEN", defaultListenAddr),
		AxonFlowEndpoint:     os.Getenv("AXONFLOW_ENDPOINT"),
		OrgID:                os.Getenv("AXONFLOW_ORG_ID"),
		LicenseKey:           os.Getenv("AXONFLOW_LICENSE_KEY"),
		TenantID:             os.Getenv("AXONFLOW_TENANT_ID"),
		GatewayID:            envOr("AXONFLOW_GATEWAY_ID", "agentgateway"),
		ConnectorTag:         envOr("AXONFLOW_CONNECTOR_TAG", "agentgateway"),
		PEPAudience:          envOr("AXONFLOW_PEP_AUDIENCE", ""),
		DefaultStage:         envOr("AXONFLOW_DEFAULT_STAGE", "llm"),
		FailMode:             envOr("AXONFLOW_FAIL_MODE", FailModeClosed),
		RequestTimeout:       envDurationOr("AXONFLOW_REQUEST_TIMEOUT", defaultRequestTimeout),
		MaxBodyBytes:         envIntOr("AXONFLOW_MAX_BODY_BYTES", defaultMaxBodyBytes),
		BreakerThreshold:     envIntOr("AXONFLOW_BREAKER_THRESHOLD", defaultBreakerTrips),
		BreakerCooldown:      envDurationOr("AXONFLOW_BREAKER_COOLDOWN", defaultBreakerCool),
		TrustIdentityHeaders: trustIdentityFromEnv(),
		ExtProcResponseGovernance: envOr(envExtProcResponseGovernance,
			ExtProcResponseGovernanceBuffered),
	}
}

// trustIdentityFromEnv parses AXONFLOW_TRUST_IDENTITY_HEADERS fail-safe via
// the shared contract (platform/shared/identity — also read by the platform
// governance planes, #2896): only the exact string "true" opts in; any other
// non-empty value stays untrusted but is logged loudly so a "1"/"TRUE" typo
// cannot silently downgrade the operator's intent without a trace.
func trustIdentityFromEnv() bool {
	trusted, recognized := sharedidentity.FromEnv()
	if !recognized {
		log.Printf("[gateway-adapters] %s=%q is not \"true\"/\"false\" — treating as false (identity headers stay untrusted)",
			sharedidentity.EnvVar, os.Getenv(sharedidentity.EnvVar))
	}
	return trusted
}

// Validate rejects configurations that would silently weaken enforcement.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.AxonFlowEndpoint) == "" {
		return fmt.Errorf("AXONFLOW_ENDPOINT is required")
	}
	switch c.FailMode {
	case FailModeClosed, FailModeOpen:
	default:
		return fmt.Errorf("AXONFLOW_FAIL_MODE must be %q or %q, got %q", FailModeClosed, FailModeOpen, c.FailMode)
	}
	if !isValidStage(c.DefaultStage) {
		return fmt.Errorf("AXONFLOW_DEFAULT_STAGE must be one of llm|tool|agent, got %q", c.DefaultStage)
	}
	if c.RequestTimeout <= 0 {
		return fmt.Errorf("AXONFLOW_REQUEST_TIMEOUT must be positive")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("AXONFLOW_MAX_BODY_BYTES must be positive")
	}
	if c.BreakerThreshold <= 0 || c.BreakerCooldown <= 0 {
		return fmt.Errorf("breaker threshold and cooldown must be positive")
	}
	// Exact-string, no case folding: a value we do not recognise must never be
	// guessed at. Refusing to boot is safe here BECAUSE the default is the
	// governed posture — a typo ("Off", "none", "false") stops the process
	// loudly instead of silently resolving to either posture.
	switch c.ExtProcResponseGovernance {
	case "", ExtProcResponseGovernanceBuffered, ExtProcResponseGovernanceOff:
	default:
		return fmt.Errorf("%s must be %q or %q, got %q",
			envExtProcResponseGovernance, ExtProcResponseGovernanceBuffered,
			ExtProcResponseGovernanceOff, c.ExtProcResponseGovernance)
	}
	return nil
}

// isValidStage mirrors the PDP's ADR-056 stage gate (decision_handler.go
// isValidStage) so a misconfigured stage is caught at the adapter boundary
// instead of surfacing as a per-request PDP 400.
func isValidStage(s string) bool {
	switch s {
	case StageLLM, StageTool, StageAgent:
		return true
	default:
		return false
	}
}

// Decide stages (ADR-056 layers; pinned server-side by isValidStage in
// platform/agent/decision_handler.go).
const (
	StageLLM   = "llm"
	StageTool  = "tool"
	StageAgent = "agent"
)

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDurationOr(key string, def time.Duration) time.Duration {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
