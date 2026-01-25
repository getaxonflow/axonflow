//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package masfeat provides MAS FEAT (Singapore) compliance functionality.
// This is the Community stub - MAS FEAT compliance is an Enterprise feature.
package masfeat

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// Module is the MAS FEAT compliance module.
// Community stub: No-op implementation - MAS FEAT compliance is disabled in Community builds.
type Module struct {
	// No fields needed for Community stub
}

// ModuleConfig contains configuration for the MAS FEAT module.
// Community stub: Configuration is ignored.
type ModuleConfig struct {
	DB                              *sql.DB
	DefaultBiasThreshold            float64
	DefaultAssessmentValidityMonths int
}

// NewModule creates a new MAS FEAT compliance module.
// Community stub: Returns a no-op module. MAS FEAT compliance is an enterprise feature.
func NewModule(config ModuleConfig) (*Module, error) {
	return &Module{}, nil
}

// RegisterRoutes registers all MAS FEAT routes on a standard http.ServeMux.
// Community stub: No-op - no routes are registered in Community builds.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// No-op in Community builds - MAS FEAT compliance is an enterprise feature
}

// RegisterRoutesWithMux registers all MAS FEAT routes on a gorilla/mux Router.
// Community stub: No-op - no routes are registered in Community builds.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {
	// No-op in Community builds - MAS FEAT compliance is an enterprise feature
}

// HealthCheck returns the health status of all MAS FEAT services.
// Community stub: Returns "disabled" for all components.
func (m *Module) HealthCheck() map[string]string {
	return map[string]string{
		"registry":    "disabled",
		"assessments": "disabled",
		"killswitch":  "disabled",
	}
}

// IsHealthy returns true if all MAS FEAT services are healthy.
// Community stub: Always returns false (feature not available).
func (m *Module) IsHealthy() bool {
	return false
}
