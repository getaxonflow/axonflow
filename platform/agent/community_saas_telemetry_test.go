// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakePutter is a test double for dynamodbPutter. It records every PutItem
// call and returns err (if set) on every call.
type fakePutter struct {
	calls []*dynamodb.PutItemInput
	err   error
}

func (f *fakePutter) PutItem(_ context.Context, input *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	f.calls = append(f.calls, input)
	if f.err != nil {
		return nil, f.err
	}
	return &dynamodb.PutItemOutput{}, nil
}

func TestNewCommunitySaaSTelemetry_Disabled(t *testing.T) {
	tel := NewCommunitySaaSTelemetry("", "6.2.0")
	if tel.enabled {
		t.Error("Telemetry should be disabled when table name is empty")
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
	// Even if enabled, no event should be enqueued for requests without tenant_id in context
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
	// No tenant_id in context
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

	// Inner handler simulates what auth middleware does: populate the
	// mutable telemetry identity container via SetTelemetryTenantID.
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
}

func TestTelemetryMiddleware_DropsWhenChannelFull(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 1), // Tiny buffer
		version:   "6.2.0",
	}

	// Fill the channel
	tel.eventChan <- telemetryEvent{}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTelemetryTenantID(r.Context(), "cs_overflow")
		w.WriteHeader(http.StatusOK)
	})

	wrapped := tel.Middleware(inner)
	req := httptest.NewRequest("GET", "/test", nil)

	rr := httptest.NewRecorder()
	// Should not block
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected 200 even when channel full, got %d", rr.Code)
	}
	// Channel should still have only 1 event (the one we pre-loaded)
	if len(tel.eventChan) != 1 {
		t.Errorf("Expected 1 event in channel (dropped), got %d", len(tel.eventChan))
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
	sw.WriteHeader(http.StatusNotFound) // Second call — ignored

	if sw.statusCode != http.StatusCreated {
		t.Errorf("Expected 201 (first call), got %d", sw.statusCode)
	}
}

func TestStatusWriter_Flush(t *testing.T) {
	rr := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rr, statusCode: http.StatusOK}

	// httptest.ResponseRecorder implements http.Flusher
	sw.Flush() // Should not panic
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

	// Test that query params are NOT captured (path only)
	req := httptest.NewRequest("GET", "/api/request?query=secret_data&token=abc123", nil)

	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	event := <-tel.eventChan
	if event.endpoint != "/api/request" {
		t.Errorf("Expected path-only endpoint, got %q", event.endpoint)
	}
}

func TestTelemetryMiddleware_DefaultStatusCode(t *testing.T) {
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "6.2.0",
	}

	// Handler that writes body without explicit WriteHeader
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
	// When AWS config fails, telemetry should be disabled gracefully
	// This test exercises the AWS config loading path
	tel := NewCommunitySaaSTelemetry("test-table", "6.2.0")
	// In test env without proper AWS credentials, it may succeed (uses default chain)
	// or fail gracefully — either way it should not panic
	if tel == nil {
		t.Fatal("NewCommunitySaaSTelemetry should never return nil")
	}
}

func TestSetTelemetryTenantID_WithContainer(t *testing.T) {
	// Verify SetTelemetryTenantID populates the mutable container
	id := &telemetryIdentity{}
	ctx := context.WithValue(context.Background(), telemetryIdentityKey, id)
	SetTelemetryTenantID(ctx, "test-tenant")
	if id.TenantID != "test-tenant" {
		t.Errorf("expected TenantID 'test-tenant', got %q", id.TenantID)
	}
}

func TestSetTelemetryTenantID_WithoutContainer(t *testing.T) {
	// SetTelemetryTenantID should be a no-op when no container in context
	ctx := context.Background()
	SetTelemetryTenantID(ctx, "test-tenant") // should not panic
}

// getStringAttr extracts a string value from an aws-sdk-go-v2 DynamoDB item map.
// Fails the test if the field is missing or not of type AttributeValueMemberS.
func getStringAttr(t *testing.T, item map[string]types.AttributeValue, field string) string {
	t.Helper()
	v, ok := item[field]
	if !ok {
		t.Fatalf("missing field %q in item", field)
	}
	s, ok := v.(*types.AttributeValueMemberS)
	if !ok {
		t.Fatalf("field %q is not a string attribute, got %T", field, v)
	}
	return s.Value
}

func TestStartupCanary_Success(t *testing.T) {
	before := testutil.ToFloat64(telemetryInitFailuresTotal)
	beforeSuccess := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("canary_success"))

	fake := &fakePutter{}
	tel := newWithClient(fake, "test-table", "7.1.0")
	defer close(tel.eventChan)

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 canary PutItem, got %d", len(fake.calls))
	}
	if v := testutil.ToFloat64(telemetryInitFailuresTotal); v != before {
		t.Errorf("init-failures counter moved on success: was %v, now %v", before, v)
	}
	if v := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("canary_success")); v != beforeSuccess+1 {
		t.Errorf("canary_success counter did not bump: was %v, now %v", beforeSuccess, v)
	}
}

func TestStartupCanary_FailureSurfacesInMetrics(t *testing.T) {
	// A PutItem error at startup must bump both init-failures and
	// canary_failure counters, and the agent must still come up (enabled=true).
	beforeInit := testutil.ToFloat64(telemetryInitFailuresTotal)
	beforeFail := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("canary_failure"))

	fake := &fakePutter{err: errors.New("AccessDeniedException: kms:Decrypt not authorized")}
	tel := newWithClient(fake, "test-table", "7.1.0")
	defer close(tel.eventChan)

	if !tel.enabled {
		t.Error("canary failure must NOT disable telemetry (best-effort design)")
	}
	if v := testutil.ToFloat64(telemetryInitFailuresTotal); v != beforeInit+1 {
		t.Errorf("init-failures counter did not bump on canary failure: was %v, now %v", beforeInit, v)
	}
	if v := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("canary_failure")); v != beforeFail+1 {
		t.Errorf("canary_failure counter did not bump: was %v, now %v", beforeFail, v)
	}
}

func TestWriteEvent_SuccessBumpsCounter(t *testing.T) {
	before := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("success"))

	fake := &fakePutter{}
	tel := &CommunitySaaSTelemetry{client: fake, tableName: "test-table", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.writeEvent(telemetryEvent{tenantID: "cs_x", endpoint: "/api/request", method: "POST", statusCode: 200})

	if v := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("success")); v != before+1 {
		t.Errorf("success counter did not bump: was %v, now %v", before, v)
	}
}

func TestWriteEvent_FailureBumpsCounter(t *testing.T) {
	before := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("failure"))

	fake := &fakePutter{err: errors.New("ThrottlingException")}
	tel := &CommunitySaaSTelemetry{client: fake, tableName: "test-table", version: "7.1.0", enabled: true, eventChan: make(chan telemetryEvent, 1)}
	tel.writeEvent(telemetryEvent{tenantID: "cs_x", endpoint: "/api/request", method: "POST", statusCode: 200})

	if v := testutil.ToFloat64(telemetryWritesTotal.WithLabelValues("failure")); v != before+1 {
		t.Errorf("failure counter did not bump: was %v, now %v", before, v)
	}
}

func TestStartupCanary_RecordShape(t *testing.T) {
	// The canary record must be identifiable so reporting can exclude it
	// from real-usage counts: tenant_id="__canary__", correlation_id prefixed
	// with "canary-", method="CANARY", endpoint="__startup_canary__".
	fake := &fakePutter{}
	tel := newWithClient(fake, "test-table", "7.1.0")
	defer close(tel.eventChan)

	if len(fake.calls) != 1 {
		t.Fatalf("expected 1 canary call, got %d", len(fake.calls))
	}
	item := fake.calls[0].Item

	if id := getStringAttr(t, item, "correlation_id"); !strings.HasPrefix(id, "canary-") {
		t.Errorf("correlation_id should start with canary-, got %q", id)
	}
	if v := getStringAttr(t, item, "tenant_id"); v != "__canary__" {
		t.Errorf("tenant_id want __canary__, got %q", v)
	}
	if v := getStringAttr(t, item, "method"); v != "CANARY" {
		t.Errorf("method want CANARY, got %q", v)
	}
	if v := getStringAttr(t, item, "endpoint"); v != "__startup_canary__" {
		t.Errorf("endpoint want __startup_canary__, got %q", v)
	}
	if v := getStringAttr(t, item, "source"); v != "community-saas" {
		t.Errorf("source want community-saas, got %q", v)
	}
}

func TestTelemetryMiddleware_ContextPropagation(t *testing.T) {
	// End-to-end test: telemetry middleware (outer) → auth-like handler (inner)
	// that calls SetTelemetryTenantID, simulating the real middleware chain.
	tel := &CommunitySaaSTelemetry{
		enabled:   true,
		eventChan: make(chan telemetryEvent, 10),
		version:   "7.0.1",
	}

	// Inner handler simulates apiAuthMiddleware: sets tenant via SetTelemetryTenantID
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is what auth middleware does after authentication
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
