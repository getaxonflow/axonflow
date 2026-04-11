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
)

const (
	// telemetryEventBufferSize is the capacity of the event channel.
	// Events are dropped if the buffer is full (telemetry is best-effort).
	telemetryEventBufferSize = 1024

	// telemetryWorkers is the number of goroutines draining the event channel.
	telemetryWorkers = 2

	// telemetryTTLDays is the TTL for telemetry events in DynamoDB.
	telemetryTTLDays = 30
)

// CommunitySaaSTelemetry records per-request usage events to DynamoDB.
// Active only when DEPLOYMENT_MODE=community-saas AND COMMUNITY_SAAS_TELEMETRY_TABLE is set.
//
// Records: tenant_id, endpoint (path only), method, status_code, platform_version,
// correlation_id (UUIDv4), source ("community-saas"), timestamp, TTL (30 days).
//
// Does NOT record: request/response body, query params, IP addresses, auth headers.
type CommunitySaaSTelemetry struct {
	client    *dynamodb.Client
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
}

// NewCommunitySaaSTelemetry creates a new telemetry middleware.
// Returns a no-op instance if tableName is empty (local dev without DynamoDB).
// Starts a bounded worker pool for writing events to DynamoDB.
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
	return t
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
		}:
		default:
			// Channel full — drop event silently (telemetry is non-critical)
		}
	})
}

// writeEvent writes a single usage event to DynamoDB.
// Errors are logged but never propagated — telemetry must not affect request flow.
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

	_, err := t.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(t.tableName),
		Item:      item,
	})
	if err != nil {
		log.Printf("[CSAAS-TELEMETRY] DynamoDB PutItem failed (non-fatal): %v", err)
	}
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
