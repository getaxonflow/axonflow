//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package euaiact provides EU AI Act compliance functionality.
// This is the Community stub - EU AI Act compliance is an Enterprise feature.
package euaiact

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// Module is the EU AI Act compliance module.
// Community stub: No-op implementation - EU AI Act compliance is disabled in Community builds.
type Module struct {
	// No fields needed for Community stub
}

// ModuleConfig contains configuration for the EU AI Act module.
// Community stub: Configuration is ignored.
type ModuleConfig struct {
	DB                   *sql.DB
	DefaultAccuracyMin   float64
	DefaultBiasMax       float64
	AlertCooldownMinutes int
}

// NewModule creates a new EU AI Act compliance module.
// Community stub: Returns a no-op module. EU AI Act compliance is an enterprise feature.
func NewModule(config ModuleConfig) (*Module, error) {
	return &Module{}, nil
}

// RegisterRoutes registers all EU AI Act routes on a standard http.ServeMux.
// Community stub: No-op - no routes are registered in Community builds.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// No-op in Community builds - EU AI Act compliance is an enterprise feature
}

// RegisterRoutesWithMux registers all EU AI Act routes on a gorilla/mux Router.
// Community stub: No-op - no routes are registered in Community builds.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {
	// No-op in Community builds - EU AI Act compliance is an enterprise feature
}

// HealthCheck returns the health status of all EU AI Act services.
// Community stub: Returns "disabled" for all components.
func (m *Module) HealthCheck() map[string]string {
	return map[string]string{
		"export":     "disabled",
		"conformity": "disabled",
		"accuracy":   "disabled",
	}
}

// IsHealthy returns true if all EU AI Act services are healthy.
// Community stub: Always returns false (feature not available).
func (m *Module) IsHealthy() bool {
	return false
}
