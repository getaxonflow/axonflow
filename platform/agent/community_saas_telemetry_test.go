// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

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
