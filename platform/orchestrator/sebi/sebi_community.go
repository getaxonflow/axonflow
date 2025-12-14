//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package sebi provides SEBI AI/ML Guidelines compliance functionality.
// This is the OSS stub - SEBI compliance is an Enterprise feature for Indian markets.
package sebi

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// SEBIModule contains all SEBI compliance services and handlers.
// OSS stub: No-op implementation - SEBI compliance is disabled in OSS mode.
type SEBIModule struct {
	// No fields needed for OSS stub
}

// SEBIModuleConfig holds configuration for the SEBI module.
// OSS stub: Configuration is ignored.
type SEBIModuleConfig struct {
	DB *sql.DB
}

// NewSEBIModule creates a new SEBI compliance module.
// OSS stub: Returns a no-op module. SEBI compliance is an enterprise feature.
func NewSEBIModule(config SEBIModuleConfig) (*SEBIModule, error) {
	return &SEBIModule{}, nil
}

// RegisterRoutes registers all SEBI API routes on a standard http.ServeMux.
// OSS stub: No-op - no routes are registered in OSS mode.
func (m *SEBIModule) RegisterRoutes(mux *http.ServeMux) {
	// No-op in OSS mode - SEBI compliance is an enterprise feature
}

// RegisterRoutesWithMux registers all SEBI API routes on a gorilla/mux Router.
// OSS stub: No-op - no routes are registered in OSS mode.
func (m *SEBIModule) RegisterRoutesWithMux(r *mux.Router) {
	// No-op in OSS mode - SEBI compliance is an enterprise feature
}

// HealthCheck returns the health status of all SEBI services.
// OSS stub: Returns "disabled" for all components.
func (m *SEBIModule) HealthCheck() map[string]string {
	return map[string]string{
		"audit_export": "disabled",
	}
}

// IsHealthy returns true if all SEBI services are healthy.
// OSS stub: Always returns false (feature not available).
func (m *SEBIModule) IsHealthy() bool {
	return false
}
