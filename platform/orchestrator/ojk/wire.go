//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"database/sql"
	"log"
	"net/http"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/gorilla/mux"
)

// OJKModule is the enterprise OJK compliance module.
type OJKModule struct {
	AuditService OJKAuditExportService
	AuditHandler *OJKAuditExportHandler
}

// OJKModuleConfig configures the OJK module.
type OJKModuleConfig struct {
	DB             *sql.DB
	StorageBackend cloudstorage.StorageBackend
}

// NewOJKModule creates a new OJK compliance module.
func NewOJKModule(config OJKModuleConfig) (*OJKModule, error) {
	module := &OJKModule{}
	if config.DB != nil {
		module.AuditService = NewOJKAuditExportService(config.DB, config.StorageBackend)
	}
	if module.AuditService != nil {
		module.AuditHandler = NewOJKAuditExportHandler(module.AuditService)
	}
	return module, nil
}

// RegisterRoutes registers OJK routes on a standard http.ServeMux.
func (m *OJKModule) RegisterRoutes(mux *http.ServeMux) {
	if m.AuditHandler != nil {
		m.AuditHandler.RegisterRoutes(mux)
	}
}

// RegisterRoutesWithMux registers OJK routes on a gorilla/mux Router.
func (m *OJKModule) RegisterRoutesWithMux(r *mux.Router) {
	if m.AuditHandler == nil {
		log.Println("OJK Module: No handler available, skipping route registration")
		return
	}

	// Audit export
	r.HandleFunc("/api/v1/ojk/audit/export", m.AuditHandler.handleExport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/ojk/audit/export/{id}", m.AuditHandler.handleExportByIDWithMux).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/ojk/audit/retention", m.AuditHandler.handleRetentionStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/ojk/audit/readiness", m.AuditHandler.handleComplianceReadiness).Methods("GET", "OPTIONS")

	// UU PDP breach notification
	r.HandleFunc("/api/v1/ojk/breach/notify", m.AuditHandler.handleBreachNotify).Methods("POST", "OPTIONS")

	// Dashboard
	r.HandleFunc("/api/v1/ojk/dashboard", m.AuditHandler.handleDashboard).Methods("GET", "OPTIONS")

	// CORS pre-flight for all OJK routes
	r.PathPrefix("/api/v1/ojk/").HandlerFunc(handleOJKModuleCORS).Methods("OPTIONS")
}

// HealthCheck returns the module health status.
func (m *OJKModule) HealthCheck() map[string]string {
	status := make(map[string]string)
	if m.AuditService != nil {
		status["audit_export"] = "healthy"
	} else {
		status["audit_export"] = "unavailable"
	}
	return status
}

// IsHealthy returns true if the module is fully operational.
func (m *OJKModule) IsHealthy() bool {
	return m.AuditService != nil
}

func handleOJKModuleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedCORSOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Tenant-ID, X-Org-ID, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
	}
	w.WriteHeader(http.StatusNoContent)
}
