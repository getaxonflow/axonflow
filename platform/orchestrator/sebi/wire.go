// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package sebi

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/gorilla/mux"
)

// SEBIModule contains all SEBI compliance services and handlers
type SEBIModule struct {
	// Service
	AuditService SEBIAuditExportService

	// Handler
	AuditHandler *SEBIAuditExportHandler
}

// SEBIModuleConfig holds configuration for the SEBI module
type SEBIModuleConfig struct {
	// Database connection
	DB *sql.DB

	// StorageBackend is the cloud storage backend for large audit exports
	StorageBackend cloudstorage.StorageBackend
}

// NewSEBIModule creates a new SEBI compliance module with all services wired together
func NewSEBIModule(config SEBIModuleConfig) (*SEBIModule, error) {
	module := &SEBIModule{}

	// Initialize service
	if config.DB != nil {
		module.AuditService = NewSEBIAuditExportService(config.DB, config.StorageBackend)
	}

	// Initialize handler
	if module.AuditService != nil {
		module.AuditHandler = NewSEBIAuditExportHandler(module.AuditService)
	}

	return module, nil
}

// RegisterRoutes registers all SEBI API routes on a standard http.ServeMux
func (m *SEBIModule) RegisterRoutes(mux *http.ServeMux) {
	if m.AuditHandler != nil {
		m.AuditHandler.RegisterRoutes(mux)
	}
}

// RegisterRoutesWithMux registers all SEBI API routes on a gorilla/mux Router
// This adapts the http.ServeMux style handlers for use with gorilla/mux
func (m *SEBIModule) RegisterRoutesWithMux(r *mux.Router) {
	if m.AuditHandler == nil {
		return
	}

	// SEBI Audit Export endpoints
	// POST /api/v1/sebi/audit/export - Export audit data
	r.HandleFunc("/api/v1/sebi/audit/export", m.AuditHandler.handleExport).Methods("POST", "OPTIONS")

	// GET /api/v1/sebi/audit/export/{id} - Get export status
	r.HandleFunc("/api/v1/sebi/audit/export/{id}", m.handleExportByIDWithMux).Methods("GET", "OPTIONS")

	// GET /api/v1/sebi/audit/retention - Get retention status
	r.HandleFunc("/api/v1/sebi/audit/retention", m.AuditHandler.handleRetentionStatus).Methods("GET", "OPTIONS")

	// GET /api/v1/sebi/audit/readiness - Check compliance readiness
	r.HandleFunc("/api/v1/sebi/audit/readiness", m.AuditHandler.handleComplianceReadiness).Methods("GET", "OPTIONS")

	// Dashboard endpoint (convenience)
	r.HandleFunc("/api/v1/sebi/dashboard", m.handleDashboard).Methods("GET", "OPTIONS")
}

// handleExportByIDWithMux adapts the handler to extract {id} from gorilla/mux vars
func (m *SEBIModule) handleExportByIDWithMux(w http.ResponseWriter, r *http.Request) {
	// gorilla/mux extracts {id} into vars, we need to set the path for the handler
	vars := mux.Vars(r)
	exportID := vars["id"]
	// Rewrite the URL path to match what handleExportByID expects
	r.URL.Path = "/api/v1/sebi/audit/export/" + exportID
	m.AuditHandler.handleExportByID(w, r)
}

// handleDashboard returns a combined dashboard view of SEBI compliance status
func (m *SEBIModule) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		handleSEBIModuleCORS(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeModuleError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	// Check handler availability
	if m.AuditHandler == nil {
		writeModuleError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "SEBI compliance module not available")
		return
	}

	// Return compliance readiness as the dashboard for now
	m.AuditHandler.handleComplianceReadiness(w, r)
}

// HealthCheck returns the health status of all SEBI services
func (m *SEBIModule) HealthCheck() map[string]string {
	status := make(map[string]string)

	// Check service availability
	if m.AuditService != nil {
		status["audit_export"] = "ok"
	} else {
		status["audit_export"] = "unavailable"
	}

	return status
}

// IsHealthy returns true if all SEBI services are healthy
func (m *SEBIModule) IsHealthy() bool {
	return m.AuditService != nil
}

// sebiModuleAllowedOrigins defines permitted CORS origins
var sebiModuleAllowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
}

// handleSEBIModuleCORS sets CORS headers for OPTIONS requests
func handleSEBIModuleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && sebiModuleAllowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// moduleAPIError is the error response format for module-level errors
type moduleAPIError struct {
	Error moduleAPIErrorDetail `json:"error"`
}

type moduleAPIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeModuleError writes a JSON error response
func writeModuleError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(moduleAPIError{
		Error: moduleAPIErrorDetail{Code: code, Message: message},
	})
}
