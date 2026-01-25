// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package circuitbreaker

import (
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
