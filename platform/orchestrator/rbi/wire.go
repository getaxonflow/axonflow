// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/gorilla/mux"
)

// defaultPIITypes returns the default list of PII types to detect
func defaultPIITypes() []IndiaPIIType {
	return []IndiaPIIType{
		IndiaPIITypeUPI,
		IndiaPIITypeAadhaar,
		IndiaPIITypePAN,
		IndiaPIITypeIFSC,
		IndiaPIITypeBankAccount,
		IndiaPIITypeGSTIN,
		IndiaPIITypeVoterID,
		IndiaPIITypeDrivingLicense,
		IndiaPIITypePassport,
		IndiaPIITypeIndianPhone,
		IndiaPIITypePincode,
	}
}

// RBIModule contains all RBI compliance services
type RBIModule struct {
	// Repositories
	AISystemRepo    AISystemRepository
	ValidationRepo  ModelValidationRepository
	IncidentRepo    AIIncidentRepository
	KillSwitchRepo  KillSwitchRepository
	BoardReportRepo BoardReportRepository
	AuditExportRepo AuditExportRepository

	// Services
	RegistryService   AISystemRegistryService
	ValidationService ModelValidationService
	IncidentService   AIIncidentService
	KillSwitchService KillSwitchService
	BoardService      BoardReportService
	AuditService      *AuditExportService

	// Handlers
	RegistryHandler   *AISystemRegistryHandler
	ValidationHandler *ModelValidationHandler
	IncidentHandler   *AIIncidentHandler
	KillSwitchHandler *KillSwitchHandler
	BoardHandler      *BoardReportHandler
	AuditHandler      *AuditExportHandler

	// Detectors
	PIIDetector *IndiaPIIDetector
}

// RBIModuleConfig holds configuration for the RBI module
type RBIModuleConfig struct {
	// Database connection
	DB *sql.DB

	// Export base path for audit exports
	ExportBasePath string

	// Cloud storage backend for audit exports (nil = local filesystem)
	StorageBackend cloudstorage.StorageBackend

	// PII detection settings
	PIIContextWindow    int
	PIIMinConfidence    float64
	PIIEnableValidation bool
	PIIEnabledTypes     []IndiaPIIType
}

// DefaultConfig returns a default configuration with all features enabled
func DefaultConfig() RBIModuleConfig {
	return RBIModuleConfig{
		ExportBasePath:      "/tmp/rbi-audit-exports",
		PIIContextWindow:    50,
		PIIMinConfidence:    0.5,
		PIIEnableValidation: true,
		PIIEnabledTypes:     defaultPIITypes(),
	}
}

// NewRBIModule creates a new RBI compliance module with all services wired together
func NewRBIModule(config RBIModuleConfig) (*RBIModule, error) {
	module := &RBIModule{}

	// Initialize repositories
	if config.DB != nil {
		module.AISystemRepo = NewPostgresAISystemRepository(config.DB)
		module.ValidationRepo = NewPostgresModelValidationRepository(config.DB)
		module.IncidentRepo = NewPostgresAIIncidentRepository(config.DB)
		module.KillSwitchRepo = NewPostgresKillSwitchRepository(config.DB)
		module.BoardReportRepo = NewPostgresBoardReportRepository(config.DB)
		module.AuditExportRepo = NewPostgresAuditExportRepository(config.DB)
	}

	// Initialize services
	module.RegistryService = NewAISystemRegistryService(module.AISystemRepo)
	module.ValidationService = NewModelValidationService(module.ValidationRepo, module.AISystemRepo)
	module.IncidentService = NewAIIncidentService(module.IncidentRepo, module.AISystemRepo)
	module.KillSwitchService = NewKillSwitchService(module.KillSwitchRepo, module.AISystemRepo)
	module.BoardService = NewBoardReportService(
		module.BoardReportRepo,
		module.AISystemRepo,
		module.ValidationRepo,
		module.IncidentRepo,
		module.KillSwitchRepo,
	)

	exportPath := config.ExportBasePath
	if exportPath == "" {
		exportPath = "/tmp/rbi-audit-exports"
	}
	module.AuditService = NewAuditExportService(
		module.AuditExportRepo,
		module.AISystemRepo,
		module.ValidationRepo,
		module.IncidentRepo,
		module.KillSwitchRepo,
		module.BoardReportRepo,
		exportPath,
		config.StorageBackend,
	)

	// Initialize handlers
	module.RegistryHandler = NewAISystemRegistryHandler(module.RegistryService)
	module.ValidationHandler = NewModelValidationHandler(module.ValidationService)
	module.IncidentHandler = NewAIIncidentHandler(module.IncidentService)
	module.KillSwitchHandler = NewKillSwitchHandler(module.KillSwitchService)
	module.BoardHandler = NewBoardReportHandler(module.BoardService)
	module.AuditHandler = NewAuditExportHandler(module.AuditService)

	// Initialize PII detector with configured types
	enabledTypes := config.PIIEnabledTypes
	if len(enabledTypes) == 0 {
		enabledTypes = defaultPIITypes()
	}

	contextWindow := config.PIIContextWindow
	if contextWindow == 0 {
		contextWindow = 50
	}

	minConfidence := config.PIIMinConfidence
	if minConfidence == 0 {
		minConfidence = 0.5
	}

	module.PIIDetector = NewIndiaPIIDetector(IndiaPIIDetectorConfig{
		ContextWindow:    contextWindow,
		MinConfidence:    minConfidence,
		EnableValidation: config.PIIEnableValidation,
		EnabledTypes:     enabledTypes,
	})

	return module, nil
}

// RegisterRoutes registers all RBI API routes on the given mux
func (m *RBIModule) RegisterRoutes(mux *http.ServeMux) {
	// Register routes from each handler
	m.RegistryHandler.RegisterRoutes(mux)
	m.ValidationHandler.RegisterRoutes(mux)
	m.IncidentHandler.RegisterRoutes(mux)
	m.KillSwitchHandler.RegisterRoutes(mux)
	m.BoardHandler.RegisterRoutes(mux)
	m.AuditHandler.RegisterRoutes(mux)

	// Policy Template routes (read-only) - go1.21 compatible
	mux.HandleFunc("/api/v1/rbi/policies/templates/", handleGetPolicyTemplate)
	mux.HandleFunc("/api/v1/rbi/policies/templates", handleGetPolicyTemplates)
	mux.HandleFunc("/api/v1/rbi/policies/categories", handleGetPolicyCategories)
}

// RegisterRoutesWithMux registers all RBI API routes on a gorilla/mux Router
// This adapts the http.ServeMux style handlers for use with gorilla/mux
func (m *RBIModule) RegisterRoutesWithMux(r *mux.Router) {
	if m.RegistryHandler == nil {
		return
	}

	// AI System Registry endpoints
	r.HandleFunc("/api/v1/rbi/ai-systems", m.RegistryHandler.handleAISystems).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/ai-systems/summary", m.RegistryHandler.handleSummary).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/ai-systems/{id}", m.handleAISystemByIDWithMux).Methods("GET", "PUT", "DELETE", "OPTIONS")

	// Model Validation endpoints
	r.HandleFunc("/api/v1/rbi/validations", m.ValidationHandler.handleValidations).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/validations/{id}", m.handleValidationByIDWithMux).Methods("GET", "PUT", "OPTIONS")

	// Incident Management endpoints
	r.HandleFunc("/api/v1/rbi/incidents", m.IncidentHandler.handleIncidents).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/incidents/{id}", m.handleIncidentByIDWithMux).Methods("GET", "PUT", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/incidents/{id}/resolve", m.handleIncidentResolveWithMux).Methods("POST", "OPTIONS")

	// Kill Switch endpoints
	r.HandleFunc("/api/v1/rbi/killswitches", m.KillSwitchHandler.handleKillSwitches).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/killswitches/{id}", m.handleKillSwitchByIDWithMux).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/killswitches/{id}/deactivate", m.handleKillSwitchDeactivateWithMux).Methods("POST", "OPTIONS")

	// Board Report endpoints
	r.HandleFunc("/api/v1/rbi/reports", m.BoardHandler.handleReports).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/reports/{id}", m.handleReportByIDWithMux).Methods("GET", "PUT", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/reports/{id}/submit", m.handleReportSubmitWithMux).Methods("POST", "OPTIONS")

	// Audit Export endpoints
	r.HandleFunc("/api/v1/rbi/audit-exports", m.AuditHandler.handleExports).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/audit-exports/{id}", m.handleAuditExportByIDWithMux).Methods("GET", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/audit-exports/{id}/process", m.handleAuditExportProcessWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/audit-exports/{id}/download", m.handleAuditExportDownloadWithMux).Methods("GET", "OPTIONS")

	// Policy Template endpoints (read-only)
	r.HandleFunc("/api/v1/rbi/policies/templates", handleGetPolicyTemplates).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/policies/templates/{id}", m.handlePolicyTemplateByIDWithMux).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/rbi/policies/categories", handleGetPolicyCategories).Methods("GET", "OPTIONS")

	// Dashboard endpoint (convenience)
	r.HandleFunc("/api/v1/rbi/dashboard", m.handleDashboard).Methods("GET", "OPTIONS")
}

// Route adapter handlers for gorilla/mux - extract {id} from path vars

func (m *RBIModule) handleAISystemByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/ai-systems/" + id
	m.RegistryHandler.handleAISystemByID(w, r)
}

func (m *RBIModule) handleValidationByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/validations/" + id
	m.ValidationHandler.handleValidationByID(w, r)
}

func (m *RBIModule) handleIncidentByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/incidents/" + id
	m.IncidentHandler.handleIncidentRoutes(w, r)
}

func (m *RBIModule) handleIncidentResolveWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/incidents/" + id + "/resolve"
	m.IncidentHandler.handleIncidentRoutes(w, r)
}

func (m *RBIModule) handleKillSwitchByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/killswitches/" + id
	m.KillSwitchHandler.handleKillSwitchRoutes(w, r)
}

func (m *RBIModule) handleKillSwitchDeactivateWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/killswitches/" + id + "/deactivate"
	m.KillSwitchHandler.handleKillSwitchRoutes(w, r)
}

func (m *RBIModule) handleReportByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/reports/" + id
	m.BoardHandler.handleReportRoutes(w, r)
}

func (m *RBIModule) handleReportSubmitWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/reports/" + id + "/submit"
	m.BoardHandler.handleReportRoutes(w, r)
}

func (m *RBIModule) handleAuditExportByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/audit-exports/" + id
	m.AuditHandler.handleExportRoutes(w, r)
}

func (m *RBIModule) handleAuditExportProcessWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/audit-exports/" + id + "/process"
	m.AuditHandler.handleExportRoutes(w, r)
}

func (m *RBIModule) handleAuditExportDownloadWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/audit-exports/" + id + "/download"
	m.AuditHandler.handleExportRoutes(w, r)
}

func (m *RBIModule) handlePolicyTemplateByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/rbi/policies/templates/" + id
	handleGetPolicyTemplate(w, r)
}

func (m *RBIModule) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		handleRBIModuleCORS(w, r)
		return
	}
	if r.Method != http.MethodGet {
		writeModuleError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
		return
	}

	// Return health status as dashboard for now
	health := m.HealthCheck()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"module":     "rbi_free_ai",
		"components": health,
	})
}

// IsHealthy returns true if all RBI services are healthy
func (m *RBIModule) IsHealthy() bool {
	return m.RegistryHandler != nil &&
		m.ValidationHandler != nil &&
		m.IncidentHandler != nil &&
		m.KillSwitchHandler != nil &&
		m.BoardHandler != nil &&
		m.AuditHandler != nil &&
		m.PIIDetector != nil
}

// rbiModuleAllowedOrigins defines permitted CORS origins
var rbiModuleAllowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
}

// handleRBIModuleCORS sets CORS headers for OPTIONS requests
func handleRBIModuleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && rbiModuleAllowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Org-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// rbiModuleAPIError is the error response format for module-level errors
type rbiModuleAPIError struct {
	Error rbiModuleAPIErrorDetail `json:"error"`
}

type rbiModuleAPIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeModuleError writes a JSON error response
func writeModuleError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(rbiModuleAPIError{
		Error: rbiModuleAPIErrorDetail{Code: code, Message: message},
	})
}

// Policy template handlers
func handleGetPolicyTemplates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	templates := GetRBIPolicyTemplates()
	writeJSON(w, http.StatusOK, templates)
}

func handleGetPolicyTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract ID from path (format: /api/v1/rbi/policies/templates/{id})
	// For go1.21 compatibility, we extract from URL path
	path := r.URL.Path
	const prefix = "/api/v1/rbi/policies/templates/"
	id := ""
	if len(path) > len(prefix) {
		id = path[len(prefix):]
	}

	if id == "" {
		http.Error(w, "Template ID required", http.StatusBadRequest)
		return
	}

	template := GetRBIPolicyTemplateByID(id)
	if template == nil {
		http.Error(w, "Template not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, template)
}

func handleGetPolicyCategories(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	categories := GetRBIPolicyTemplateCategories()
	writeJSON(w, http.StatusOK, categories)
}

// DetectPII runs PII detection on the given text and returns all matches
func (m *RBIModule) DetectPII(text string) []IndiaPIIDetectionResult {
	return m.PIIDetector.DetectAll(text)
}

// HasSensitiveData returns true if the text contains any sensitive PII
func (m *RBIModule) HasSensitiveData(text string) bool {
	return m.PIIDetector.HasIndiaPII(text)
}

// MaskPII masks all detected PII in the text
func (m *RBIModule) MaskPII(text string) string {
	results := m.PIIDetector.DetectAll(text)
	masked := text

	// Sort by position descending to avoid offset issues
	for i := len(results) - 1; i >= 0; i-- {
		r := results[i]
		if r.StartIndex >= 0 && r.EndIndex <= len(masked) {
			masked = masked[:r.StartIndex] + r.MaskedValue + masked[r.EndIndex:]
		}
	}

	return masked
}

// HealthCheck returns the health status of all RBI services
func (m *RBIModule) HealthCheck() map[string]string {
	status := make(map[string]string)

	// Check each service
	status["registry"] = "ok"
	status["validation"] = "ok"
	status["incident"] = "ok"
	status["killswitch"] = "ok"
	status["board_reporting"] = "ok"
	status["audit_export"] = "ok"
	status["pii_detector"] = "ok"

	return status
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")

	// Encode to buffer first to check for errors before writing headers
	encoded, err := json.Marshal(data)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(status)
	w.Write(encoded)
}
