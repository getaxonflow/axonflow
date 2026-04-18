// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"database/sql"
	"log"
	"net/http"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/gorilla/mux"
)

// ModuleConfig contains configuration for the EU AI Act module.
type ModuleConfig struct {
	// DB is the database connection.
	DB *sql.DB

	// StorageBackend is the cloud storage backend for export files.
	// If nil, exports will only use local file paths.
	StorageBackend cloudstorage.StorageBackend

	// DefaultAccuracyMin is the minimum accuracy threshold (default: 0.80).
	DefaultAccuracyMin float64

	// DefaultBiasMax is the maximum allowed bias score (default: 0.10).
	DefaultBiasMax float64

	// AlertCooldownMinutes is the cooldown period between alerts (default: 15).
	AlertCooldownMinutes int
}

// Module is the EU AI Act compliance module.
type Module struct {
	// Repositories
	ExportRepo      ExportRepository
	ConformityRepo  ConformityRepository
	AccuracyRepo    AccuracyRepository

	// Services
	ExportService     *ExportService
	ConformityService *ConformityService
	AccuracyService   *AccuracyService

	// Handlers
	ExportHandler     *ExportHandler
	ConformityHandler *ConformityHandler
	AccuracyHandler   *AccuracyHandler
}

// NewModule creates a new EU AI Act compliance module.
func NewModule(config ModuleConfig) (*Module, error) {
	// Create repositories
	exportRepo := NewPostgresExportRepository(config.DB)
	conformityRepo := NewPostgresConformityRepository(config.DB)
	accuracyRepo := NewPostgresAccuracyRepository(config.DB)

	// Create services
	exportService := NewExportService(exportRepo, config.StorageBackend)
	conformityService := NewConformityService(conformityRepo)
	accuracyService := NewAccuracyService(accuracyRepo, AccuracyServiceConfig{
		DefaultAccuracyMin:   config.DefaultAccuracyMin,
		DefaultBiasMax:       config.DefaultBiasMax,
		AlertCooldownMinutes: config.AlertCooldownMinutes,
	})

	// Create handlers
	exportHandler := NewExportHandler(exportService)
	conformityHandler := NewConformityHandler(conformityService)
	accuracyHandler := NewAccuracyHandler(accuracyService)

	return &Module{
		ExportRepo:        exportRepo,
		ConformityRepo:    conformityRepo,
		AccuracyRepo:      accuracyRepo,
		ExportService:     exportService,
		ConformityService: conformityService,
		AccuracyService:   accuracyService,
		ExportHandler:     exportHandler,
		ConformityHandler: conformityHandler,
		AccuracyHandler:   accuracyHandler,
	}, nil
}

// RegisterRoutes registers all EU AI Act routes on the given http.ServeMux.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// Export routes
	m.ExportHandler.RegisterRoutes(mux)

	// Conformity assessment routes
	m.ConformityHandler.RegisterRoutes(mux)

	// Accuracy tracking routes
	m.AccuracyHandler.RegisterRoutes(mux)
}

// RegisterRoutesWithMux registers all EU AI Act routes on a gorilla/mux Router.
// This adapts the http.ServeMux style handlers for use with gorilla/mux.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {
	if r == nil {
		log.Println("⚠️ EU AI Act: cannot register routes - router is nil")
		return
	}

	// Export routes
	// POST /api/v1/euaiact/export - Create export request
	// GET /api/v1/euaiact/export - List exports
	r.HandleFunc("/api/v1/euaiact/export", m.ExportHandler.handleExport).Methods("GET", "POST", "OPTIONS")

	// GET /api/v1/euaiact/export/{id} - Get export by ID
	r.HandleFunc("/api/v1/euaiact/export/{id}", m.handleExportByIDWithMux).Methods("GET", "OPTIONS")

	// GET /api/v1/euaiact/export/{id}/download - Download export
	r.HandleFunc("/api/v1/euaiact/export/{id}/download", m.handleExportDownloadWithMux).Methods("GET", "OPTIONS")

	// Conformity routes
	// POST /api/v1/euaiact/conformity - Create conformity assessment
	// GET /api/v1/euaiact/conformity - List conformity assessments
	r.HandleFunc("/api/v1/euaiact/conformity", m.ConformityHandler.handleConformity).Methods("GET", "POST", "OPTIONS")

	// GET /api/v1/euaiact/conformity/{id} - Get conformity assessment by ID
	// PUT /api/v1/euaiact/conformity/{id} - Update conformity assessment
	r.HandleFunc("/api/v1/euaiact/conformity/{id}", m.handleConformityByIDWithMux).Methods("GET", "PUT", "OPTIONS")

	// POST /api/v1/euaiact/conformity/{id}/submit - Submit for review
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/submit", m.handleConformityActionWithMux).Methods("POST", "OPTIONS")

	// POST /api/v1/euaiact/conformity/{id}/approve - Approve assessment
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/approve", m.handleConformityActionWithMux).Methods("POST", "OPTIONS")

	// POST /api/v1/euaiact/conformity/{id}/reject - Reject assessment
	r.HandleFunc("/api/v1/euaiact/conformity/{id}/reject", m.handleConformityActionWithMux).Methods("POST", "OPTIONS")

	// Accuracy routes
	// GET /api/v1/euaiact/accuracy - Get accuracy metrics
	r.HandleFunc("/api/v1/euaiact/accuracy", m.AccuracyHandler.handleAccuracy).Methods("GET", "OPTIONS")

	// POST /api/v1/euaiact/accuracy/record - Record accuracy metric
	r.HandleFunc("/api/v1/euaiact/accuracy/record", m.AccuracyHandler.handleRecordMetric).Methods("POST", "OPTIONS")

	// POST /api/v1/euaiact/accuracy/bias - Record bias metric
	r.HandleFunc("/api/v1/euaiact/accuracy/bias", m.AccuracyHandler.handleRecordBias).Methods("POST", "OPTIONS")

	// GET /api/v1/euaiact/accuracy/history - Get historical accuracy
	r.HandleFunc("/api/v1/euaiact/accuracy/history", m.AccuracyHandler.handleAccuracyHistory).Methods("GET", "OPTIONS")

	// GET /api/v1/euaiact/accuracy/alerts - List alerts
	r.HandleFunc("/api/v1/euaiact/accuracy/alerts", m.AccuracyHandler.handleAlerts).Methods("GET", "OPTIONS")

	// GET /api/v1/euaiact/accuracy/alerts/{id} - Get alert by ID
	// PUT /api/v1/euaiact/accuracy/alerts/{id} - Update alert (acknowledge)
	r.HandleFunc("/api/v1/euaiact/accuracy/alerts/{id}", m.handleAlertByIDWithMux).Methods("GET", "PUT", "OPTIONS")

	log.Println("✅ EU AI Act routes registered:")
	log.Println("   - POST/GET /api/v1/euaiact/export")
	log.Println("   - GET /api/v1/euaiact/export/{id}")
	log.Println("   - POST/GET /api/v1/euaiact/conformity")
	log.Println("   - GET/PUT /api/v1/euaiact/conformity/{id}")
	log.Println("   - POST /api/v1/euaiact/conformity/{id}/submit|approve|reject")
	log.Println("   - GET /api/v1/euaiact/accuracy")
	log.Println("   - POST /api/v1/euaiact/accuracy/record|bias")
	log.Println("   - GET /api/v1/euaiact/accuracy/history|alerts")
}

// handleExportByIDWithMux adapts the handler to extract {id} from gorilla/mux vars.
func (m *Module) handleExportByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	exportID := vars["id"]
	// Rewrite the URL path to match what handleExportByID expects
	r.URL.Path = "/api/v1/euaiact/export/" + exportID
	m.ExportHandler.handleExportByID(w, r)
}

// handleExportDownloadWithMux adapts the download handler to extract {id} from gorilla/mux vars.
func (m *Module) handleExportDownloadWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	exportID := vars["id"]
	// Rewrite the URL path to match what handleExportByID expects (includes /download)
	r.URL.Path = "/api/v1/euaiact/export/" + exportID + "/download"
	m.ExportHandler.handleExportByID(w, r)
}

// handleConformityByIDWithMux adapts the handler to extract {id} from gorilla/mux vars.
func (m *Module) handleConformityByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assessmentID := vars["id"]
	// Rewrite the URL path to match what handleConformityByID expects
	r.URL.Path = "/api/v1/euaiact/conformity/" + assessmentID
	m.ConformityHandler.handleConformityByID(w, r)
}

// handleConformityActionWithMux adapts conformity action handlers (submit/approve/reject).
func (m *Module) handleConformityActionWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assessmentID := vars["id"]
	// Extract the action from the path (submit, approve, reject)
	// The original handler expects the full path
	r.URL.Path = "/api/v1/euaiact/conformity/" + assessmentID + "/" + extractAction(r.URL.Path)
	m.ConformityHandler.handleConformityByID(w, r)
}

// handleAlertByIDWithMux adapts the handler to extract {id} from gorilla/mux vars.
func (m *Module) handleAlertByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	alertID := vars["id"]
	// Rewrite the URL path to match what handleAlertByID expects
	r.URL.Path = "/api/v1/euaiact/accuracy/alerts/" + alertID
	m.AccuracyHandler.handleAlertByID(w, r)
}

// extractAction extracts the action (submit, approve, reject) from a path like
// /api/v1/euaiact/conformity/{id}/submit
func extractAction(path string) string {
	// Find last path segment
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return ""
}

// IsHealthy returns true if the EU AI Act module is properly initialized.
func (m *Module) IsHealthy() bool {
	return m.ExportHandler != nil && m.ConformityHandler != nil && m.AccuracyHandler != nil
}

// HealthCheck returns detailed health status of EU AI Act services.
func (m *Module) HealthCheck() map[string]string {
	status := make(map[string]string)

	if m.ExportHandler != nil {
		status["export"] = "ok"
	} else {
		status["export"] = "unavailable"
	}

	if m.ConformityHandler != nil {
		status["conformity"] = "ok"
	} else {
		status["conformity"] = "unavailable"
	}

	if m.AccuracyHandler != nil {
		status["accuracy"] = "ok"
	} else {
		status["accuracy"] = "unavailable"
	}

	return status
}
