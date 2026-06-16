// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"axonflow/platform/path_template"
)

const (
	// telemetryEventBufferSize is the capacity of the event channel.
	// Events are dropped if the buffer is full (telemetry is best-effort).
	telemetryEventBufferSize = 1024

	// telemetryWorkers is the number of goroutines draining the event channel.
	telemetryWorkers = 2

	// telemetryCanaryTimeout bounds the startup write used to verify SQS
	// permissions. Kept short so a transient AWS slowdown at startup
	// does not delay agent readiness.
	telemetryCanaryTimeout = 5 * time.Second
)

// telemetrySendsTotal counts SQS SendMessage outcomes so silent-failure
// periods (e.g. missing sqs:SendMessage on the task role) are visible
// in Grafana and can be alerted on. The label distinguishes "success",
// "failure", and the canary equivalents for the startup probe.
//
// Pre-#2010 this counter was named axonflow_community_saas_telemetry_writes_total
// and tracked DDB PutItem outcomes. Renaming follows the cutover from
// direct-DDB writes to SQS+ingest-Lambda; the dimension semantics stay
// identical (success/failure plus canary_*).
var telemetrySendsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_community_saas_telemetry_sends_total",
		Help: "Total community SaaS telemetry SQS-send attempts by outcome.",
	},
	[]string{"result"},
)

// telemetryInitFailuresTotal is incremented when the startup canary
// SendMessage fails. A nonzero value after an agent restart means the
// task cannot enqueue telemetry — almost always an IAM policy drift on
// the task role (missing sqs:SendMessage on the queue ARN).
var telemetryInitFailuresTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "axonflow_community_saas_telemetry_init_failures_total",
		Help: "Count of community SaaS telemetry startup canary SendMessage failures.",
	},
)

// sqsSender is the minimal surface of the SQS client this package
// needs. Narrowing the dependency lets tests inject a fake without
// pulling the full SDK Client.
type sqsSender interface {
	SendMessage(ctx context.Context, input *sqs.SendMessageInput, opts ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
}

// CommunitySaaSTelemetry records per-request usage events to the
// community-SaaS telemetry SQS queue. Active only when
// DEPLOYMENT_MODE=community-saas AND COMMUNITY_SAAS_TELEMETRY_SQS_URL
// is set.
//
// Records: tenant_id, endpoint (OpenAPI-templated path), method,
// status_code, platform_version, correlation_id (UUIDv4),
// source ("community-saas"), timestamp, source_ip (raw — operational
// class per ADR-051 §2.7 + §3.5; salt-hashed and persisted by the
// ingest Lambda), conditional client + limit_type + trace_id. The
// downstream ingest Lambda (ee/platform/csaas-telemetry-ingest) is the
// SOLE writer to the DDB table; it consumes from the same queue and
// PutItems with byte-identical column shape.
//
// Does NOT record: request/response body, query params, auth headers.
type CommunitySaaSTelemetry struct {
	client    sqsSender
	queueURL  string
	version   string
	enabled   bool
	eventChan chan telemetryEvent
	// agentEnv mirrors the AXONFLOW_AGENT_ENVIRONMENT env var read at
	// construction. Forwarded on every wire event so the ingest Lambda
	// (and any future cross-environment-aware reader) can classify
	// non-production traffic at write time. See issue #2172 — the
	// defense-in-depth half of staging→prod SQS isolation. Empty when
	// the env var is unset (legacy / prod-default behavior).
	agentEnv string
}

type telemetryEvent struct {
	// correlationID is minted at enqueue time (not at SQS-send time) so
	// each event has a stable identity across retries — and so the FIFO
	// queue's content-based dedup hash includes a unique field per real
	// event. Keeps the table HASH-key invariant intact through the SQS
	// hop.
	correlationID string
	// timestamp is also minted at enqueue time so the recorded value is
	// the request-completion moment, not the moment the SQS-send (or
	// downstream PutItem) happens.
	timestamp  time.Time
	tenantID   string
	endpoint   string
	method     string
	statusCode int
	// client is the X-Axonflow-Client header value (e.g. "openclaw/2.1.0",
	// "sdk-typescript/7.0.0"). Empty when the caller didn't set the header.
	// Captured per ADR-050 §4 for per-plugin distribution analysis on the
	// telemetry table.
	client string
	// limitType is the X-Axonflow-Tier-Limit response header value, set by
	// the rate-limit envelope writer in community_saas_ratelimit_response.go
	// when the response is a tier-cap 429. Empty for non-rate-limited
	// responses. The aggregator emits a ratelimit:* dimension row keyed on
	// this value (#2022 producer-side fix). One of LimitType* constants
	// from community_saas_ratelimit_response.go.
	limitType string
	// traceID is the X-Amzn-Trace-Id header value (set by ALB on every
	// inbound request). Captured for ALB-log↔A row correlation per
	// epic #2047 sub-task 1: the prior approach (timestamp+path
	// heuristic) is fuzzy under concurrent requests; persisting trace_id
	// gives a tight join key. Empty when the request didn't traverse
	// the ALB (e.g. local dev hitting the agent directly).
	traceID string
	// sourceIP is the client IP extracted via the same XFF-last-entry
	// + RemoteAddr path used by extractClientIP elsewhere in this
	// package. The ingest Lambda salt-hashes it before persistence
	// (#2053 / iphash package); the agent never persists the raw
	// value itself. Empty when both XFF and RemoteAddr are absent
	// (e.g. tests with no socket address).
	sourceIP string
}

// telemetryWireEvent is the JSON shape on the SQS message body. Keep
// in lockstep with the matching struct in
// ee/platform/csaas-telemetry-ingest/pkg/ingest/handler.go — the
// ingest Lambda decodes this exact shape.
//
// SourceIP is the raw client IP captured by the middleware at request
// time. System A (community-saas-telemetry-events) is an operational
// store class per ADR-051 §2.7 + §3.5 — same framing as ALB access
// logs — so the agent forwards the raw value to the ingest Lambda,
// which is the SOLE writer to the DDB table and salt-hashes the IP
// (#2053 / iphash package) plus enriches it via the ipapi path
// (#2047 P2b) before PutItem. The agent never persists the raw IP
// itself.
type telemetryWireEvent struct {
	CorrelationID   string `json:"correlation_id"`
	Timestamp       string `json:"timestamp"`
	TenantID        string `json:"tenant_id"`
	Endpoint        string `json:"endpoint"`
	Method          string `json:"method"`
	StatusCode      int    `json:"status_code"`
	PlatformVersion string `json:"platform_version"`
	Client          string `json:"client,omitempty"`
	LimitType       string `json:"limit_type,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	// TraceID is the X-Amzn-Trace-Id header value captured by the
	// agent middleware for ALB-log↔A row correlation per epic #2047
	// sub-task 1. omitempty so legacy agents (and local-dev requests
	// that didn't traverse the ALB) round-trip without the field.
	TraceID string `json:"trace_id,omitempty"`
	// AgentEnv is the AXONFLOW_AGENT_ENVIRONMENT env var read once at
	// telemetry construction. Empty (omitempty) for the legacy default
	// and for prod tasks that don't set the var. The ingest Lambda's
	// Layer 1 filter (issue #2172) treats any value other than
	// "production" — e.g. "staging", "dev", "test" — as internal traffic
	// and drops the row. Defense-in-depth half of the staging→prod SQS
	// isolation; primary isolation is the staging task def's empty
	// COMMUNITY_SAAS_TELEMETRY_SQS_URL.
	AgentEnv string `json:"agent_env,omitempty"`
}

// NewCommunitySaaSTelemetry creates a new telemetry middleware.
// Returns a no-op instance if queueURL is empty (local dev without
// SQS, or before the SoX cutover CFN has populated the env var).
// Starts a bounded worker pool for sending events to SQS.
//
// On successful construction, runs a synchronous canary SendMessage to
// verify the SQS+IAM permission chain end-to-end. The canary failure
// is logged at ERROR and surfaced through the init-failures Prometheus
// counter, but never blocks agent startup — telemetry is best-effort
// by design.
func NewCommunitySaaSTelemetry(queueURL, platformVersion string) *CommunitySaaSTelemetry {
	if queueURL == "" {
		log.Println("[CSAAS-TELEMETRY] Disabled (COMMUNITY_SAAS_TELEMETRY_SQS_URL is empty)")
		return &CommunitySaaSTelemetry{enabled: false}
	}

	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "us-east-1"
	}
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
	)
	if err != nil {
		log.Printf("[CSAAS-TELEMETRY] Failed to load AWS config, telemetry disabled: %v", err)
		return &CommunitySaaSTelemetry{enabled: false}
	}

	client := sqs.NewFromConfig(cfg)
	return newWithClient(client, queueURL, platformVersion)
}

// newWithClient assembles the struct and starts workers, separated from
// NewCommunitySaaSTelemetry so tests can inject a fake sqsSender.
func newWithClient(client sqsSender, queueURL, platformVersion string) *CommunitySaaSTelemetry {
	eventChan := make(chan telemetryEvent, telemetryEventBufferSize)

	t := &CommunitySaaSTelemetry{
		client:    client,
		queueURL:  queueURL,
		version:   platformVersion,
		enabled:   true,
		eventChan: eventChan,
		agentEnv:  os.Getenv("AXONFLOW_AGENT_ENVIRONMENT"),
	}

	for i := 0; i < telemetryWorkers; i++ {
		go t.worker()
	}

	log.Printf("[CSAAS-TELEMETRY] Enabled — sending to SQS queue %s (%d workers)", queueURL, telemetryWorkers)

	// Synchronous startup probe. Runs inline so the first line of CloudWatch
	// after "[CSAAS-TELEMETRY] Enabled —" is either a success confirmation or
	// a loud failure. Never blocks on error — agent keeps running.
	t.runStartupCanary(context.Background())

	return t
}

// runStartupCanary sends a synthetic telemetry message to verify the
// full SQS + IAM chain at startup. A failure here means subsequent
// real sends will also fail, and should trigger an oncall alert
// through the init-failures counter.
//
// Does not block or unwind on failure: telemetry stays "enabled" so
// the app does not crash, but the operator-visible signal (log +
// counter) catches the misconfiguration within seconds of deploy.
func (t *CommunitySaaSTelemetry) runStartupCanary(ctx context.Context) {
	canaryCtx, cancel := context.WithTimeout(ctx, telemetryCanaryTimeout)
	defer cancel()

	now := time.Now().UTC()
	wire := telemetryWireEvent{
		CorrelationID:   "canary-" + uuid.NewString(),
		Timestamp:       now.Format(time.RFC3339),
		TenantID:        "__canary__",
		Endpoint:        "__startup_canary__",
		Method:          "CANARY",
		StatusCode:      0,
		PlatformVersion: t.version,
		AgentEnv:        t.agentEnv,
	}

	if err := t.send(canaryCtx, wire); err != nil {
		log.Printf("[CSAAS-TELEMETRY] STARTUP CANARY FAILED — real telemetry sends will also fail. "+
			"Check task role has sqs:SendMessage on the queue ARN. Error: %v", err)
		telemetryInitFailuresTotal.Inc()
		telemetrySendsTotal.WithLabelValues("canary_failure").Inc()
		return
	}

	log.Printf("[CSAAS-TELEMETRY] Startup canary OK — SQS + IAM permissions verified")
	telemetrySendsTotal.WithLabelValues("canary_success").Inc()
}

// worker drains the event channel and sends to SQS.
// Runs as a long-lived goroutine (one per worker).
func (t *CommunitySaaSTelemetry) worker() {
	for event := range t.eventChan {
		t.sendEvent(event)
	}
}

// telemetryIdentity is a mutable container placed in request context by the
// telemetry middleware (outer) so that auth middleware (inner) can populate it.
// This solves the Go context propagation problem: r.WithContext() creates a new
// *http.Request, so the outer middleware's `r` never sees context values set by
// inner middleware. By using a shared mutable pointer, the outer middleware can
// read values set by inner middleware after next.ServeHTTP returns.
type telemetryIdentity struct {
	TenantID string
}

// telemetryIdentityKey is the context key for the mutable telemetry identity container.
var telemetryIdentityKey = authContextKey("telemetry_identity")

// SetTelemetryTenantID populates the telemetry identity container in the request
// context, if present. Called by auth middleware after determining tenant identity.
func SetTelemetryTenantID(ctx context.Context, tenantID string) {
	if id, ok := ctx.Value(telemetryIdentityKey).(*telemetryIdentity); ok {
		id.TenantID = tenantID
	}
}

// Middleware returns an http.Handler middleware that records usage events.
// It captures the response status code after the inner handler completes,
// then enqueues an SQS message via the bounded worker pool.
//
// This middleware runs on the global router (outer), while auth middleware runs
// on sub-routers (inner). To bridge context across the middleware boundary, it
// places a mutable *telemetryIdentity in the request context. Auth middleware
// calls SetTelemetryTenantID() to fill it, and this middleware reads it after
// the inner handler returns.
func (t *CommunitySaaSTelemetry) Middleware(next http.Handler) http.Handler {
	if !t.enabled {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Place mutable identity container in context for auth middleware to fill
		id := &telemetryIdentity{}
		r = r.WithContext(context.WithValue(r.Context(), telemetryIdentityKey, id))

		// Wrap response writer to capture status code
		sw := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(sw, r)

		// Read tenant from the mutable container (populated by auth middleware)
		if id.TenantID == "" {
			// Skip unauthenticated requests (e.g., /health, /api/v1/register)
			return
		}

		// Enqueue event via bounded channel — drop if full (best-effort).
		// CorrelationID and timestamp are minted here (not at SQS-send
		// time) so retries through SQS preserve the original event
		// identity and the FIFO content-dedup hash includes a unique
		// field per real event.
		select {
		case t.eventChan <- telemetryEvent{
			correlationID: uuid.NewString(),
			timestamp:     time.Now().UTC(),
			tenantID:      id.TenantID,
			// epic #2047 sub-task 2: normalize the request path to its
			// OpenAPI template form at write time. Cuts row cardinality
			// massively for /{id}-style paths (one-row-per-tenant-id
			// rolled up to one-row-per-endpoint) and gives the analytics
			// view a closed-cardinality vocabulary. Unknown paths return
			// as-is — fail-closed by design.
			endpoint: path_template.Normalize(r.URL.Path), // Path only — no query params (defense in depth against PII)
			method:        r.Method,
			statusCode:    sw.statusCode,
			// ADR-050 §4: capture the X-Axonflow-Client identity directly
			// from the request — no auth-middleware plumbing needed since
			// the header is independent of the credential chain.
			client: r.Header.Get("X-Axonflow-Client"),
			// #2022 producer-side fix: capture the rate-limit envelope's
			// X-Axonflow-Tier-Limit header set by writeRateLimitError /
			// writeMCPGateError. The header is already set on the wrapped
			// response writer by the time this middleware reads it; no new
			// context plumbing required. Empty string for non-rate-limited
			// responses; the wire-event emission omits the column so the
			// ingest Lambda's PutItem keeps it absent on the row.
			limitType: sw.Header().Get("X-Axonflow-Tier-Limit"),
			// epic #2047 sub-task 1: ALB sets X-Amzn-Trace-Id on every
			// inbound request. Capturing it here gives downstream
			// analytics a tight ALB-log↔A row join key.
			traceID: r.Header.Get("X-Amzn-Trace-Id"),
			// epic #2047 P2a: capture the client IP via the same
			// extractClientIP path used elsewhere in this package
			// (community_saas_register.go) — XFF-last-entry-wins
			// under the single-hop ALB topology, RemoteAddr fallback
			// with port stripped. canonicalizeSourceIP normalizes
			// IPv6 forms before the value crosses the wire so P2b's
			// ipapi/Scarf enrichment receives a parseable literal.
			// The ingest Lambda salt-hashes the value before
			// persistence.
			sourceIP: canonicalizeSourceIP(extractClientIP(r)),
		}:
		default:
			// Channel full — drop event silently (telemetry is non-critical)
		}
	})
}

// sendEvent SQS-sends a single usage event.
// Errors are logged but never propagated — telemetry must not affect request flow.
// Every call bumps the sends_total counter so silent failures surface in metrics.
func (t *CommunitySaaSTelemetry) sendEvent(event telemetryEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	wire := telemetryWireEvent{
		CorrelationID:   event.correlationID,
		Timestamp:       event.timestamp.Format(time.RFC3339),
		TenantID:        event.tenantID,
		Endpoint:        event.endpoint,
		Method:          event.method,
		StatusCode:      event.statusCode,
		PlatformVersion: t.version,
		Client:          event.client,
		LimitType:       event.limitType,
		SourceIP:        event.sourceIP,
		TraceID:         event.traceID,
		AgentEnv:        t.agentEnv,
	}

	if err := t.send(ctx, wire); err != nil {
		log.Printf("[CSAAS-TELEMETRY] SQS SendMessage failed (non-fatal): %v", err)
		telemetrySendsTotal.WithLabelValues("failure").Inc()
		return
	}
	telemetrySendsTotal.WithLabelValues("success").Inc()
}

// send marshals + SQS-sends one wire event. The MessageGroupId is
// tenant_id so per-tenant ordering is preserved in the FIFO queue;
// content-based dedup is enabled at the queue level and the body
// already contains a unique correlation_id, so the dedup hash
// distinguishes every real event.
func (t *CommunitySaaSTelemetry) send(ctx context.Context, wire telemetryWireEvent) error {
	body, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	_, err = t.client.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:       aws.String(t.queueURL),
		MessageBody:    aws.String(string(body)),
		MessageGroupId: aws.String(wire.TenantID),
	})
	return err
}

// canonicalizeSourceIP strips matched brackets from IPv6 forms
// returned by extractClientIP's RemoteAddr-fallback path.
// extractClientIP keeps brackets on IPv6 because its port-strip uses
// LastIndexByte rather than net.SplitHostPort — a quirk pinned by
// TestExtractClientIP_IPv6RemoteAddr at
// community_saas_register_test.go:324. That bracketed form ("[::1]")
// is consistent enough for rate-limit-key uses elsewhere in this
// package, but it is not a valid IP literal: net.ParseIP rejects it,
// and ipapi / Scarf enrichment under #2047 P2b will need to call
// net.ParseIP on the wire value. Normalize at the telemetry boundary
// so the SQS contract becomes the canonical literal before the
// downstream enrichment path is built on it.
//
// IPv4 inputs, plain IPv6 (already bracket-free), and the "unknown"
// sentinel returned by extractClientIP all pass through unchanged.
func canonicalizeSourceIP(ip string) string {
	if len(ip) >= 2 && ip[0] == '[' && ip[len(ip)-1] == ']' {
		return ip[1 : len(ip)-1]
	}
	return ip
}

// statusWriter wraps http.ResponseWriter to capture the status code.
// Delegates Flush() to the underlying writer for streaming compatibility.
type statusWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.written {
		sw.statusCode = code
		sw.written = true
	}
	// Defense-in-depth: telemetry endpoints emit application/json; nosniff
	// stops a browser from MIME-sniffing a reflected value as HTML.
	sw.ResponseWriter.Header().Set("X-Content-Type-Options", "nosniff")
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.written {
		sw.written = true
	}
	sw.ResponseWriter.Header().Set("X-Content-Type-Options", "nosniff")
	return sw.ResponseWriter.Write(b)
}

// Flush delegates to the underlying ResponseWriter if it implements http.Flusher.
// This is required for SSE/streaming handlers (e.g., MCP server protocol).
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
