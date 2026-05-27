//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"net/http"
	"testing"

	"github.com/gorilla/mux"
)

func TestNewOJKModule_NilDB(t *testing.T) {
	config := OJKModuleConfig{DB: nil}
	module, err := NewOJKModule(config)
	if err != nil {
		t.Fatalf("NewOJKModule() error = %v", err)
	}
	if module == nil {
		t.Fatal("module should not be nil")
	}
	if module.IsHealthy() {
		t.Error("module with nil DB should not be healthy")
	}
}

func TestOJKModule_HealthCheck_NoService(t *testing.T) {
	module := &OJKModule{}
	status := module.HealthCheck()
	if status["audit_export"] != "unavailable" {
		t.Errorf("HealthCheck = %v, want unavailable", status["audit_export"])
	}
}

func TestOJKModule_HealthCheck_WithService(t *testing.T) {
	module := &OJKModule{
		AuditService: &mockOJKService{},
	}
	status := module.HealthCheck()
	if status["audit_export"] != "healthy" {
		t.Errorf("HealthCheck = %v, want healthy", status["audit_export"])
	}
	if !module.IsHealthy() {
		t.Error("module with service should be healthy")
	}
}

func TestOJKModule_RegisterRoutes_NoHandler(t *testing.T) {
	module := &OJKModule{}
	mux := http.NewServeMux()
	module.RegisterRoutes(mux) // should not panic
}

func TestOJKModule_RegisterRoutesWithMux_NoHandler(t *testing.T) {
	module := &OJKModule{}
	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r) // should not panic
}

func TestOJKModule_RegisterRoutesWithMux_WithHandler(t *testing.T) {
	svc := &mockOJKService{}
	module := &OJKModule{
		AuditService: svc,
		AuditHandler: NewOJKAuditExportHandler(svc),
	}
	r := mux.NewRouter()
	module.RegisterRoutesWithMux(r) // should register all 6 routes

	// Verify routes are registered by checking route count
	routeCount := 0
	_ = r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		routeCount++
		return nil
	})

	// 6 endpoints + 1 CORS catch-all = 7 routes
	if routeCount < 6 {
		t.Errorf("expected at least 6 routes, got %d", routeCount)
	}
}
