//go:build !enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package rbi provides RBI FREE-AI Framework compliance functionality.
// This is the Community stub - RBI compliance is an Enterprise feature for Indian banking.
package rbi

import (
	"database/sql"
	"net/http"

	"github.com/gorilla/mux"
)

// RBIModule contains all RBI FREE-AI compliance services and handlers.
// Community stub: No-op implementation - RBI compliance is disabled in Community mode.
type RBIModule struct {
	// No fields needed for Community stub
}

// RBIModuleConfig holds configuration for the RBI module.
// Community stub: Configuration is ignored.
type RBIModuleConfig struct {
	// Database connection
	DB *sql.DB

	// Export base path for audit exports
	ExportBasePath string

	// PII detection settings (unused in Community)
	PIIContextWindow    int
	PIIMinConfidence    float64
	PIIEnableValidation bool
}

// DefaultConfig returns a default configuration.
// Community stub: Returns empty config since feature is disabled.
func DefaultConfig() RBIModuleConfig {
	return RBIModuleConfig{}
}

// NewRBIModule creates a new RBI FREE-AI compliance module.
// Community stub: Returns a no-op module. RBI compliance is an enterprise feature.
func NewRBIModule(_ RBIModuleConfig) (*RBIModule, error) {
	return &RBIModule{}, nil
}

// RegisterRoutes registers all RBI API routes on a standard http.ServeMux.
// Community stub: No-op - no routes are registered in Community mode.
func (m *RBIModule) RegisterRoutes(_ *http.ServeMux) {
	// No-op in Community mode - RBI compliance is an enterprise feature
}

// RegisterRoutesWithMux registers all RBI API routes on a gorilla/mux Router.
// Community stub: No-op - no routes are registered in Community mode.
func (m *RBIModule) RegisterRoutesWithMux(_ *mux.Router) {
	// No-op in Community mode - RBI compliance is an enterprise feature
}

// HealthCheck returns the health status of all RBI services.
// Community stub: Returns "disabled" for all components.
func (m *RBIModule) HealthCheck() map[string]string {
	return map[string]string{
		"ai_system_registry":  "disabled",
		"model_validation":    "disabled",
		"incident_management": "disabled",
		"kill_switch":         "disabled",
		"board_reporting":     "disabled",
		"audit_export":        "disabled",
		"pii_detector":        "disabled",
	}
}

// IsHealthy returns true if all RBI services are healthy.
// Community stub: Always returns false (feature not available).
func (m *RBIModule) IsHealthy() bool {
	return false
}
