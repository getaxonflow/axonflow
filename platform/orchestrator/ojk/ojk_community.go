//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"database/sql"
	"net/http"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/gorilla/mux"
)

// OJKModule is the community stub for the OJK compliance module.
type OJKModule struct{}

// OJKModuleConfig is accepted but ignored in community mode.
type OJKModuleConfig struct {
	DB             *sql.DB
	StorageBackend cloudstorage.StorageBackend
}

// NewOJKModule returns an empty module in community mode.
func NewOJKModule(config OJKModuleConfig) (*OJKModule, error) {
	return &OJKModule{}, nil
}

// RegisterRoutes is a no-op in community mode.
func (m *OJKModule) RegisterRoutes(mux *http.ServeMux) {}

// RegisterRoutesWithMux is a no-op in community mode.
func (m *OJKModule) RegisterRoutesWithMux(r *mux.Router) {}

// HealthCheck returns disabled status in community mode.
func (m *OJKModule) HealthCheck() map[string]string {
	return map[string]string{
		"audit_export": "disabled",
	}
}

// IsHealthy returns false in community mode.
func (m *OJKModule) IsHealthy() bool {
	return false
}
