// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build !enterprise

package hitl

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewRepository(t *testing.T) {
	repo := NewRepository(nil)
	if repo == nil {
		t.Error("expected non-nil repository")
	}
}

func TestNewService(t *testing.T) {
	repo := NewRepository(nil)
	config := ServiceConfig{}
	service := NewService(repo, config)
	if service == nil {
		t.Error("expected non-nil service")
	}
}

func TestNewHandler(t *testing.T) {
	service := NewService(nil, ServiceConfig{})
	handler := NewHandler(service)
	if handler == nil {
		t.Error("expected non-nil handler")
	}
}

func TestHandler_RegisterRoutes(t *testing.T) {
	handler := NewHandler(nil)
	router := mux.NewRouter()

	// Should not panic
	handler.RegisterRoutes(router)

	// Community edition registers the status endpoint only
	routeCount := 0
	router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routeCount++
		return nil
	})

	if routeCount != 1 {
		t.Errorf("expected 1 route in community edition (status endpoint), got %d", routeCount)
	}
}

func TestHandler_GetStatus(t *testing.T) {
	handler := NewHandler(nil)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/api/v1/hitl/status", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["enabled"] != false {
		t.Errorf("expected enabled=false, got %v", resp["enabled"])
	}
	if resp["mode"] != "community" {
		t.Errorf("expected mode=community, got %v", resp["mode"])
	}
}

func TestService_ExpireStaleRequests(t *testing.T) {
	service := NewService(nil, ServiceConfig{})
	count, err := service.ExpireStaleRequests(nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 expired, got %d", count)
	}
}
