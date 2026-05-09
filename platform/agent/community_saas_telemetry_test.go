// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeSender is a test double for sqsSender. It records every SendMessage
// call and returns err (if set) on every call.
type fakeSender struct {
	calls []*sqs.SendMessageInput
	err   error
}

func (f *fakeSender) SendMessage(_ context.Context, input *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.calls = append(f.calls, input)
	if f.err != nil {
		return nil, f.err
	}
	return &sqs.SendMessageOutput{}, nil
}

// decodeBody json-decodes the most-recent SendMessage body to a wire event.
// All assertions on the per-event shape go through this helper so tests
// stay in lockstep with the wire shape the ingest Lambda expects.
func decodeBody(t *testing.T, in *sqs.SendMessageInput) telemetryWireEvent {
	t.Helper()
	if in.MessageBody == nil {
		t.Fatalf("SendMessage called with nil MessageBody")
	}
	var w telemetryWireEvent
	if err := json.Unmarshal([]byte(*in.MessageBody), &w); err != nil {
		t.Fatalf("decodeBody: %v", err)
	}
	return w
}

func TestNewCommunitySaaSTelemetry_Disabled(t *testing.T) {
	tel := NewCommunitySaaSTelemetry("", "6.2.0")
	if tel.enabled {
		t.Error("Telemetry should be disabled when queue URL is empty")
	}
}

func TestNewCommunitySaaSTelemetry_DisabledReturnsNoOpMiddleware(t *testing.T) {
	tel := NewCommunitySaaSTelemetry("", "6.2.0")

	handlerCalled := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("GET", "/test", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if !handlerCalled {
		t.Error("Inner handler should have been called even with disabled telemetry")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", rr.Code)
	}
}

func TestTelemetryMiddleware_SkipsUnauthenticatedRequests(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "6.2.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if len(tel.eventChan) != 0 {
		t.Errorf("Expected no events for unauthenticated request, got %d", len(tel.eventChan))
	}
}

func TestTelemetryMiddleware_CapturesStatusCode(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "6.2.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_test-tenant")
		w.WriteHeader(http.StatusNotFound)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("POST", "/api/request", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if len(tel.eventChan) != 1 {
		t.Fatalf("Expected 1 event, got %d", len(tel.eventChan))
	}

	event := <-tel.eventChan
	if event.statusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", event.statusCode)
	}
	if event.tenantID != "cs_test-tenant" {
		t.Errorf("Expected tenant cs_test-tenant, got %s", event.tenantID)
	}
	if event.endpoint != "/api/request" {
		t.Errorf("Expected endpoint /api/request, got %s", event.endpoint)
	}
	if event.method != "POST" {
		t.Errorf("Expected method POST, got %s", event.method)
	}
	if event.correlationID == "" {
		t.Error("correlation_id must be minted at enqueue time, got empty string")
	}
	if event.timestamp.IsZero() {
		t.Error("timestamp must be minted at enqueue time, got zero value")
	}
}

func TestTelemetryMiddleware_DropsWhenChannelFull(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 1),
		version:   "6.2.0",
	}

	tel.eventChan <- telemetryEvent{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_overflow")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("GET", "/test", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 even when channel full, got %d", rr.Code)
	}
	if len(tel.eventChan) != 1 {
		t.Errorf("Expected 1 event in channel (dropped), got %d", len(tel.eventChan))
	}
}

// TestTelemetryMiddleware_Captures429FromRateLimit asserts the contract that
// the B0 fix relies on: if any middleware populates the telemetry identity
// BEFORE writing a 429 (which `writeRateLimitError` does when the daily-cap
// is hit), the outer telemetry middleware records the rate-limit event with
// the right tenant_id.
//
// Pre-B0 the auth, proxy, and MCP middleware each called SetTelemetryTenantID
// AFTER the daily-cap check; 429 responses terminated the chain before the
// telemetry container was populated, and the telemetry table never saw
// rate-limit hits at all. The fix had to be applied at THREE call sites:
//   - apiAuthMiddleware in auth.go             (B0 first PR — #2014)
//   - proxyAuthMiddleware in proxy.go          (B0 extension — staging-found gap)
//   - handleMCPToolsCall in mcp_server_handler.go  (same B0 extension)
//
// The check-input / check-output paths in mcp_handler.go already had the
// populate step before their cap-check call, so they were unaffected.
//
// This test pins the post-fix CONTRACT (populate-before-write); regressions
// at any of the three call sites would still be caught by an integration
// test that drives that specific path. Future refactors should add such an
// integration test if a fourth call site is introduced.
func TestTelemetryMiddleware_Captures429FromRateLimit(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "7.8.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_rate_limited_tenant")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"daily_quota_exceeded"}`))
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 written to response, got %d", rr.Code)
	}
	if len(tel.eventChan) != 1 {
		t.Fatalf("expected 1 telemetry event for the 429 (regression: pre-B0 this was 0), got %d", len(tel.eventChan))
	}
	event := <-tel.eventChan
	if event.statusCode != http.StatusTooManyRequests {
		t.Errorf("event.statusCode = %d, want 429", event.statusCode)
	}
	if event.tenantID != "cs_rate_limited_tenant" {
		t.Errorf("event.tenantID = %q, want cs_rate_limited_tenant (the rate-limited tenant must be attributed)", event.tenantID)
	}
	if event.endpoint != "/api/v1/audit/tool-call" {
		t.Errorf("event.endpoint = %q, want /api/v1/audit/tool-call", event.endpoint)
	}
	if event.limitType != "" {
		t.Errorf("event.limitType = %q, want empty (no X-Axonflow-Tier-Limit header was set)", event.limitType)
	}
}

func TestTelemetryMiddleware_CapturesLimitType(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "7.8.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_capped_tenant")
		w.Header().Set("X-Axonflow-Tier-Limit", "daily_quota")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"daily_quota_exceeded"}`))
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 written to response, got %d", rr.Code)
	}
	if len(tel.eventChan) != 1 {
		t.Fatalf("expected 1 telemetry event for the 429, got %d", len(tel.eventChan))
	}
	event := <-tel.eventChan
	if event.limitType != "daily_quota" {
		t.Errorf("event.limitType = %q, want %q (the X-Axonflow-Tier-Limit header value the rate-limit envelope writer set)", event.limitType, "daily_quota")
	}
	if event.statusCode != http.StatusTooManyRequests {
		t.Errorf("event.statusCode = %d, want 429", event.statusCode)
	}
}

// TestTelemetryMiddleware_CapturesTraceID verifies that the X-Amzn-Trace-Id
// header set by ALB on every inbound request is captured into the
// telemetry event for downstream ALB-log↔A row correlation (epic #2047
// sub-task 1). Empty header → empty event.traceID (round-trips as a
// missing wire field via omitempty).
func TestTelemetryMiddleware_CapturesTraceID(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "7.9.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_trace_tenant")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", nil)
	// Realistic ALB trace header shape: Self/Root/Lineage triplet.
	req.Header.Set("X-Amzn-Trace-Id", "Root=1-67ed7ab5-0123456789abcdef0123456789")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if len(tel.eventChan) != 1 {
		t.Fatalf("expected 1 telemetry event, got %d", len(tel.eventChan))
	}
	ev := <-tel.eventChan
	if ev.traceID != "Root=1-67ed7ab5-0123456789abcdef0123456789" {
		t.Errorf("event.traceID = %q, want exact ALB header echo", ev.traceID)
	}
}

// TestSendEvent_EmitsTraceIDWhenSet verifies the wire-shape lockstep
// contract: when telemetryEvent carries a non-empty traceID, the SQS
// message body must include trace_id. Empty traceID must be omitted (no
// JSON field, no DDB column on the ingest side).
func TestSendEvent_EmitsTraceIDWhenSet(t *testing.T) {
	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.9.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{
		correlationID: "c-1",
		tenantID:      "cs_x",
		endpoint:      "/api/v1/audit/tool-call",
		method:        "POST",
		statusCode:    200,
		traceID:       "Root=1-abc-def",
	})

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 SendMessage call, got %d", len(fake.calls))
	}
	wire := decodeBody(t, fake.calls[0])
	if wire.TraceID != "Root=1-abc-def" {
		t.Errorf("wire.TraceID want %q, got %q", "Root=1-abc-def", wire.TraceID)
	}
}

// TestSendEvent_OmitsTraceIDWhenEmpty is a regression guard: traceID is
// `omitempty` on the wire struct, so the JSON body must not contain a
// "trace_id" key when the header was absent (e.g., local-dev requests).
func TestSendEvent_OmitsTraceIDWhenEmpty(t *testing.T) {
	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.9.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{
		correlationID: "c-1",
		tenantID:      "cs_x",
		endpoint:      "/api/v1/audit/tool-call",
		method:        "POST",
		statusCode:    200,
	})

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 SendMessage call, got %d", len(fake.calls))
	}
	body := *fake.calls[0].MessageBody
	if strings.Contains(body, `"trace_id"`) {
		t.Errorf("body should omit trace_id when empty; got %q", body)
	}
}

func TestStatusWriter_CapturesStatusCode(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	sw.WriteHeader(http.StatusCreated)
	if sw.statusCode != http.StatusCreated {
		t.Errorf("Expected 201, got %d", sw.statusCode)
	}
}

func TestStatusWriter_OnlyFirstWriteHeaderWins(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	sw.WriteHeader(http.StatusCreated)
	sw.WriteHeader(http.StatusNotFound)

	if sw.statusCode != http.StatusCreated {
		t.Errorf("Expected 201 (first call), got %d", sw.statusCode)
	}
}

func TestStatusWriter_Flush(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	sw.Flush()
	if !rr.Flushed {
		t.Error("Expected underlying recorder to be flushed")
	}
}

func TestStatusWriter_Write(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	n, err := sw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write error: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected 5 bytes written, got %d", n)
	}
	if !sw.written {
		t.Error("Expected written=true after Write()")
	}
	if rr.Body.String() != "hello" {
		t.Errorf("Expected body 'hello', got %q", rr.Body.String())
	}
}

func TestTelemetryMiddleware_CapturesEndpointPath(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "6.2.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_test")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)

	req := httptest.NewRequest("GET", "/api/request?query=secret_data&token=abc123", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	event := <-tel.eventChan
	if event.endpoint != "/api/request" {
		t.Errorf("Expected path-only endpoint, got %q", event.endpoint)
	}
}

// TestTelemetryMiddleware_NormalizesEndpointPath exercises the
// path_template integration (epic #2047 sub-task 2): tenant-scoped
// concrete paths must be persisted as their OpenAPI template form so
// analytics rows roll up by endpoint, not by tenant. Unknown paths
// fail-closed (returned as-is).
func TestTelemetryMiddleware_NormalizesEndpointPath(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "8.0.0",
	}

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "tenant-id segment normalized",
			raw:  "/api/v1/static-policies/sp_abc123",
			want: "/api/v1/static-policies",
		},
		{
			name: "literal-trailing action keeps mid-path id",
			raw:  "/api/v1/conformity/assessments/asmt_42/start",
			want: "/api/v1/conformity/assessments/{id}/start",
		},
		{
			name: "unknown path fail-closed (as-is)",
			raw:  "/api/v1/unmapped/fancy-thing",
			want: "/api/v1/unmapped/fancy-thing",
		},
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_norm")
		w.WriteHeader(http.StatusOK)
	})
	wrapped := tel.Middleware(inner)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.raw, nil)
			rr := httptest.NewRecorder()
			wrapped.ServeHTTP(rr, req)

			ev := <-tel.eventChan
			if ev.endpoint != tc.want {
				t.Errorf("Normalize(%q) → event.endpoint = %q, want %q", tc.raw, ev.endpoint, tc.want)
			}
		})
	}
}

func TestTelemetryMiddleware_DefaultStatusCode(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "6.2.0",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_test")
		w.Write([]byte("ok"))
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("GET", "/test", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	event := <-tel.eventChan
	if event.statusCode != http.StatusOK {
		t.Errorf("Expected default 200 status, got %d", event.statusCode)
	}
}

func TestNewCommunitySaaSTelemetry_WithInvalidAWSConfig(t *testing.T) {
	tel := NewCommunitySaaSTelemetry("https://sqs.us-east-1.amazonaws.com/000/test", "6.2.0")
	if tel == nil {
		t.Fatal("NewCommunitySaaSTelemetry should never return nil")
	}
}

func TestSetTelemetryTenantID_WithContainer(t *testing.T) {
	id := &telemetryIdentity{}
	ctx := context.WithValue(context.Background(), telemetryIdentityKey, id)
	SetTelemetryTenantID(ctx, "test-tenant")
	if id.TenantID != "test-tenant" {
		t.Errorf("expected TenantID 'test-tenant', got %q", id.TenantID)
	}
}

func TestSetTelemetryTenantID_WithoutContainer(t *testing.T) {
	ctx := context.Background()
	SetTelemetryTenantID(ctx, "test-tenant") // should not panic
}

func TestStartupCanary_Success(t *testing.T) {
	before := testutil.ToFloat64(telemetryInitFailuresTotal)
	beforeSuccess := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("canary_success"))

	fake := &fakeSender{}
	tel := newWithClient(fake, "https://sqs.us-east-1.amazonaws.com/000/test", "7.1.0")
	defer close(tel.eventChan)

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 canary SendMessage, got %d", len(fake.calls))
	}
	if v := testutil.ToFloat64(telemetryInitFailuresTotal); v != before {
		t.Errorf("init-failures counter moved on success: was %v, now %v", before, v)
	}
	if v := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("canary_success")); v != beforeSuccess+1 {
		t.Errorf("canary_success counter did not bump: was %v, now %v", beforeSuccess, v)
	}
}

func TestStartupCanary_FailureSurfacesInMetrics(t *testing.T) {
	beforeInit := testutil.ToFloat64(telemetryInitFailuresTotal)
	beforeFail := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("canary_failure"))

	fake := &fakeSender{err: errors.New("AccessDeniedException: sqs:SendMessage not authorized")}
	tel := newWithClient(fake, "https://sqs.us-east-1.amazonaws.com/000/test", "7.1.0")
	defer close(tel.eventChan)

	if !tel.enabled {
		t.Error("canary failure must NOT disable telemetry (best-effort design)")
	}
	if v := testutil.ToFloat64(telemetryInitFailuresTotal); v != beforeInit+1 {
		t.Errorf("init-failures counter did not bump on canary failure: was %v, now %v", beforeInit, v)
	}
	if v := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("canary_failure")); v != beforeFail+1 {
		t.Errorf("canary_failure counter did not bump: was %v, now %v", beforeFail, v)
	}
}

func TestSendEvent_SuccessBumpsCounter(t *testing.T) {
	before := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("success"))

	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{correlationID: "c-1", tenantID: "cs_x", endpoint: "/api/request", method: "POST", statusCode: 200})

	if v := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("success")); v != before+1 {
		t.Errorf("success counter did not bump: was %v, now %v", before, v)
	}
}

func TestSendEvent_EmitsLimitTypeWhenSet(t *testing.T) {
	// #2022 producer-side fix: when telemetryEvent carries a non-empty
	// limitType, the wire body must include limit_type so the ingest
	// Lambda emits the column. Empty string must be omitted (no column).
	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{
		correlationID: "c-1",
		tenantID:      "cs_capped",
		endpoint:      "/api/v1/audit/tool-call",
		method:        "POST",
		statusCode:    429,
		limitType:     "daily_quota",
	})

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 SendMessage call, got %d", len(fake.calls))
	}
	wire := decodeBody(t, fake.calls[0])
	if wire.LimitType != "daily_quota" {
		t.Errorf("wire.LimitType want %q, got %q", "daily_quota", wire.LimitType)
	}
}

func TestSendEvent_OmitsLimitTypeWhenEmpty(t *testing.T) {
	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{
		correlationID: "c-1",
		tenantID:      "cs_ok",
		endpoint:      "/api/v1/audit/tool-call",
		method:        "POST",
		statusCode:    200,
	})

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 SendMessage call, got %d", len(fake.calls))
	}
	body := *fake.calls[0].MessageBody
	if strings.Contains(body, `"limit_type"`) {
		t.Errorf("body should omit limit_type when empty; got %q", body)
	}
}

func TestSendEvent_FailureBumpsCounter(t *testing.T) {
	before := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("failure"))

	fake := &fakeSender{err: errors.New("ThrottlingException")}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{correlationID: "c-1", tenantID: "cs_x", endpoint: "/api/request", method: "POST", statusCode: 200})

	if v := testutil.ToFloat64(telemetrySendsTotal.WithLabelValues("failure")); v != before+1 {
		t.Errorf("failure counter did not bump: was %v, now %v", before, v)
	}
}

func TestStartupCanary_RecordShape(t *testing.T) {
	// The canary record must be identifiable so reporting can exclude it
	// from real-usage counts: tenant_id="__canary__", correlation_id prefixed
	// with "canary-", method="CANARY", endpoint="__startup_canary__".
	fake := &fakeSender{}
	tel := newWithClient(fake, "https://sqs.us-east-1.amazonaws.com/000/test", "7.1.0")
	defer close(tel.eventChan)

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 canary call, got %d", len(fake.calls))
	}
	wire := decodeBody(t, fake.calls[0])

	if !strings.HasPrefix(wire.CorrelationID, "canary-") {
		t.Errorf("correlation_id should start with canary-, got %q", wire.CorrelationID)
	}
	if wire.TenantID != "__canary__" {
		t.Errorf("tenant_id want __canary__, got %q", wire.TenantID)
	}
	if wire.Method != "CANARY" {
		t.Errorf("method want CANARY, got %q", wire.Method)
	}
	if wire.Endpoint != "__startup_canary__" {
		t.Errorf("endpoint want __startup_canary__, got %q", wire.Endpoint)
	}
}

func TestSend_MessageGroupIDIsTenantID(t *testing.T) {
	// FIFO requires a MessageGroupId. The brief locks per-tenant ordering
	// (group key = tenant_id); regressions to a static group would
	// serialize all tenant traffic onto one SQS partition and choke
	// throughput.
	fake := &fakeSender{}
	tel := &CommunitySaaSTelemetry{client: fake, queueURL: "https://sqs.us-east-1.amazonaws.com/000/test", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.sendEvent(telemetryEvent{correlationID: "c-1", tenantID: "cs_alpha", endpoint: "/x", method: "GET", statusCode: 200})
	tel.sendEvent(telemetryEvent{correlationID: "c-2", tenantID: "cs_beta", endpoint: "/x", method: "GET", statusCode: 200})

	if len(fake.calls) != 2 {
		t.Fatalf("expected 2 SendMessage calls, got %d", len(fake.calls))
	}
	if got := *fake.calls[0].MessageGroupId; got != "cs_alpha" {
		t.Errorf("call[0].MessageGroupId = %q, want %q", got, "cs_alpha")
	}
	if got := *fake.calls[1].MessageGroupId; got != "cs_beta" {
		t.Errorf("call[1].MessageGroupId = %q, want %q", got, "cs_beta")
	}
}

func TestTelemetryMiddleware_ContextPropagation(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "7.0.1",
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_propagated-tenant")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("POST", "/api/request", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if len(tel.eventChan) != 1 {
		t.Fatalf("Expected 1 event from context propagation, got %d", len(tel.eventChan))
	}

	event := <-tel.eventChan
	if event.tenantID != "cs_propagated-tenant" {
		t.Errorf("Expected tenant 'cs_propagated-tenant', got %q", event.tenantID)
	}
}
