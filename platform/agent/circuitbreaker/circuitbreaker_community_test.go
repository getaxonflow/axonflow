// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package circuitbreaker

import (
	"context"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewRepository(t *testing.T) {
	repo := NewRepository(nil)
	if repo == nil {
		t.Error("expected non-nil repository")
	}
}

func TestNew(t *testing.T) {
	repo := NewRepository(nil)
	config := Config{}
	cb := New(repo, config)
	if cb == nil {
		t.Error("expected non-nil circuit breaker")
	}
}

func TestNewHandler(t *testing.T) {
	cb := New(nil, Config{})
	handler := NewHandler(cb)
	if handler == nil {
		t.Error("expected non-nil handler")
	}
}

func TestHandler_RegisterRoutes(t *testing.T) {
	handler := NewHandler(nil)
	router := mux.NewRouter()

	// Should not panic - community edition is a no-op
	handler.RegisterRoutes(router)

	// Verify no routes were registered (community edition)
	routeCount := 0
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routeCount++
		return nil
	})

	if routeCount != 0 {
		t.Errorf("expected 0 routes in community edition, got %d", routeCount)
	}
}

func TestCheck_AlwaysAllowed(t *testing.T) {
	cb := New(nil, Config{})
	result, err := cb.Check(context.Background(), CheckInput{
		OrgID:    "test-org",
		TenantID: "test-tenant",
		ClientID: "test-client",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("community edition should always allow requests")
	}
}

func TestIsAllowed_AlwaysTrue(t *testing.T) {
	cb := New(nil, Config{})
	if !cb.IsAllowed(context.Background(), "org", "tenant", "client") {
		t.Error("community edition should always return true")
	}
}

func TestRecordError_NoOp(t *testing.T) {
	cb := New(nil, Config{})
	if err := cb.RecordError(context.Background(), "org", "tenant", "client"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRecordPolicyViolation_NoOp(t *testing.T) {
	cb := New(nil, Config{})
	if err := cb.RecordPolicyViolation(context.Background(), "org", "tenant", "client", "policy"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadCircuits_NoOp(t *testing.T) {
	cb := New(nil, Config{})
	if err := cb.LoadCircuits(context.Background(), "org"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExpireCircuits_NoOp(t *testing.T) {
	cb := New(nil, Config{})
	if err := cb.ExpireCircuits(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
