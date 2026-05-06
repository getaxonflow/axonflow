// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	// telemetryEventBufferSize is the capacity of the event channel.
	// Events are dropped if the buffer is full (telemetry is best-effort).
	telemetryEventBufferSize = 1024

	// telemetryWorkers is the number of goroutines draining the event channel.
	telemetryWorkers = 2

	// telemetryTTLDays is the TTL for telemetry events in DynamoDB.
	telemetryTTLDays = 30

	// telemetryCanaryTimeout bounds the startup write used to verify DynamoDB
	// + KMS permissions. Kept short so a transient AWS slowdown at startup
	// does not delay agent readiness.
	telemetryCanaryTimeout = 5 * time.Second
)

// telemetryWritesTotal counts DynamoDB PutItem outcomes so silent-failure
// periods (e.g. missing kms:Decrypt on the task role) are visible in Grafana
// and can be alerted on. The label distinguishes "success", "failure", and
// the canary equivalents for the startup probe.
var telemetryWritesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_community_saas_telemetry_writes_total",
		Help: "Total community SaaS telemetry write attempts by outcome.",
	},
	[]string{"result"},
)

// telemetryInitFailuresTotal is incremented when the startup canary PutItem
// fails. A nonzero value after an agent restart means the task cannot write
// telemetry — almost always an IAM/KMS policy drift on the task role.
var telemetryInitFailuresTotal = promauto.NewCounter(
	prometheus.CounterOpts{
		Name: "axonflow_community_saas_telemetry_init_failures_total",
		Help: "Count of community SaaS telemetry startup canary PutItem failures.",
	},
)

// dynamodbPutter is the minimal surface of the DynamoDB client this package
// needs. Narrowing the dependency lets tests inject a fake without pulling
// the full SDK Client.
type dynamodbPutter interface {
	PutItem(ctx context.Context, input *dynamodb.PutItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
}

// CommunitySaaSTelemetry records per-request usage events to DynamoDB.
// Active only when DEPLOYMENT_MODE=community-saas AND COMMUNITY_SAAS_TELEMETRY_TABLE is set.
//
// Records: tenant_id, endpoint (path only), method, status_code, platform_version,
// correlation_id (UUIDv4), source ("community-saas"), timestamp, TTL (30 days).
//
// Does NOT record: request/response body, query params, IP addresses, auth headers.
type CommunitySaaSTelemetry struct {
	client    dynamodbPutter
	tableName string
	version   string
	enabled   bool
	eventChan chan telemetryEvent
}

type telemetryEvent struct {
	tenantID   string
	endpoint   string
	method     string
	statusCode int
	// client is the X-Axonflow-Client header value (e.g. "openclaw/2.1.0",
	// "sdk-typescript/7.0.0"). Empty when the caller didn't set the header.
	// Captured per ADR-050 §4 for per-plugin distribution analysis on the
	// telemetry table.
	client string
}

// NewCommunitySaaSTelemetry creates a new telemetry middleware.
// Returns a no-op instance if tableName is empty (local dev without DynamoDB).
// Starts a bounded worker pool for writing events to DynamoDB.
//
// On successful construction, runs a synchronous canary PutItem to verify the
// DynamoDB + KMS permission chain end-to-end. The canary failure is logged at
// ERROR and surfaced through the init-failures Prometheus counter, but never
// blocks agent startup — telemetry is best-effort by design.
func NewCommunitySaaSTelemetry(tableName, platformVersion string) *CommunitySaaSTelemetry {
	if tableName == "" {
		log.Println("[CSAAS-TELEMETRY] Disabled (COMMUNITY_SAAS_TELEMETRY_TABLE is empty)")
		return &CommunitySaaSTelemetry{enabled: false}
	}

	// Load AWS config from environment (uses ECS task role credentials in production)
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

	client := dynamodb.NewFromConfig(cfg)
	return newWithClient(client, tableName, platformVersion)
}

// newWithClient assembles the struct and starts workers, separated from
// NewCommunitySaaSTelemetry so tests can inject a fake dynamodbPutter.
func newWithClient(client dynamodbPutter, tableName, platformVersion string) *CommunitySaaSTelemetry {
	eventChan := make(chan telemetryEvent, telemetryEventBufferSize)

	t := &CommunitySaaSTelemetry{
		client:    client,
		tableName: tableName,
		version:   platformVersion,
		enabled:   true,
		eventChan: eventChan,
	}

	// Start bounded worker pool
	for i := 0; i < telemetryWorkers; i++ {
		go t.worker()
	}

	log.Printf("[CSAAS-TELEMETRY] Enabled — writing to table %s (%d workers)", tableName, telemetryWorkers)

	// Synchronous startup probe. Runs inline so the first line of CloudWatch
	// after "[CSAAS-TELEMETRY] Enabled —" is either a success confirmation or
	// a loud failure. Never blocks on error — agent keeps running.
	t.runStartupCanary(context.Background())

	return t
}

// runStartupCanary writes a synthetic telemetry record to verify the full
// DynamoDB + KMS + IAM chain at startup. A failure here means subsequent
// real writes will also fail, and should trigger an oncall alert through
// the init-failures counter.
//
// Does not block or unwind on failure: telemetry stays "enabled" so the app
// does not crash, but the operator-visible signal (log + counter) catches
// the misconfiguration within seconds of deploy.
func (t *CommunitySaaSTelemetry) runStartupCanary(ctx context.Context) {
	canaryCtx, cancel := context.WithTimeout(ctx, telemetryCanaryTimeout)
	defer cancel()

	now := time.Now().UTC()
	correlationID := "canary-" + uuid.NewString()
	ttl := now.Add(telemetryTTLDays * 24 * time.Hour).Unix()

	item := map[string]types.AttributeValue{
		"correlation_id":   &types.AttributeValueMemberS{Value: correlationID},
		"timestamp":        &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
		"tenant_id":        &types.AttributeValueMemberS{Value: "__canary__"},
		"endpoint":         &types.AttributeValueMemberS{Value: "__startup_canary__"},
		"method":           &types.AttributeValueMemberS{Value: "CANARY"},
		"status_code":      &types.AttributeValueMemberN{Value: "0"},
		"platform_version": &types.AttributeValueMemberS{Value: t.version},
		"source":           &types.AttributeValueMemberS{Value: "community-saas"},
		"ttl":              &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)},
	}

	_, err := t.client.PutItem(canaryCtx, &dynamodb.PutItemInput{
		TableName: aws.String(t.tableName),
		Item:      item,
	})
	if err != nil {
		log.Printf("[CSAAS-TELEMETRY] STARTUP CANARY FAILED — real telemetry writes will also fail. "+
			"Check task role has kms:Decrypt + kms:GenerateDataKey on the telemetry table's KMS key. Error: %v", err)
		telemetryInitFailuresTotal.Inc()
		telemetryWritesTotal.WithLabelValues("canary_failure").Inc()
		return
	}

	log.Printf("[CSAAS-TELEMETRY] Startup canary OK — DynamoDB + KMS permissions verified")
	telemetryWritesTotal.WithLabelValues("canary_success").Inc()
}

// worker drains the event channel and writes to DynamoDB.
// Runs as a long-lived goroutine (one per worker).
func (t *CommunitySaaSTelemetry) worker() {
	for event := range t.eventChan {
		t.writeEvent(event)
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
// then enqueues a DynamoDB write via the bounded worker pool.
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

		// Enqueue event via bounded channel — drop if full (best-effort)
		select {
		case t.eventChan <- telemetryEvent{
			tenantID:   id.TenantID,
			endpoint:   r.URL.Path, // Path only — no query params (defense in depth against PII)
			method:     r.Method,
			statusCode: sw.statusCode,
			// ADR-050 §4: capture the X-Axonflow-Client identity directly
			// from the request — no auth-middleware plumbing needed since
			// the header is independent of the credential chain.
			client: r.Header.Get("X-Axonflow-Client"),
		}:
		default:
			// Channel full — drop event silently (telemetry is non-critical)
		}
	})
}

// writeEvent writes a single usage event to DynamoDB.
// Errors are logged but never propagated — telemetry must not affect request flow.
// Every call bumps the writes_total counter so silent failures surface in metrics.
func (t *CommunitySaaSTelemetry) writeEvent(event telemetryEvent) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	now := time.Now().UTC()
	correlationID := uuid.NewString()
	ttl := now.Add(telemetryTTLDays * 24 * time.Hour).Unix()

	item := map[string]types.AttributeValue{
		"correlation_id":   &types.AttributeValueMemberS{Value: correlationID},
		"timestamp":        &types.AttributeValueMemberS{Value: now.Format(time.RFC3339)},
		"tenant_id":        &types.AttributeValueMemberS{Value: event.tenantID},
		"endpoint":         &types.AttributeValueMemberS{Value: event.endpoint},
		"method":           &types.AttributeValueMemberS{Value: event.method},
		"status_code":      &types.AttributeValueMemberN{Value: strconv.Itoa(event.statusCode)},
		"platform_version": &types.AttributeValueMemberS{Value: t.version},
		"source":           &types.AttributeValueMemberS{Value: "community-saas"},
		"ttl":              &types.AttributeValueMemberN{Value: strconv.FormatInt(ttl, 10)},
	}
	// ADR-050 §4: per-plugin distribution analysis. Only emit the column when
	// the request actually carried the header so absent-header rows don't
	// pollute the dimension.
	if event.client != "" {
		item["client"] = &types.AttributeValueMemberS{Value: event.client}
	}

	_, err := t.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(t.tableName),
		Item:      item,
	})
	if err != nil {
		log.Printf("[CSAAS-TELEMETRY] DynamoDB PutItem failed (non-fatal): %v", err)
		telemetryWritesTotal.WithLabelValues("failure").Inc()
		return
	}
	telemetryWritesTotal.WithLabelValues("success").Inc()
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
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.written {
		sw.written = true
	}
	return sw.ResponseWriter.Write(b)
}

// Flush delegates to the underlying ResponseWriter if it implements http.Flusher.
// This is required for SSE/streaming handlers (e.g., MCP server protocol).
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
