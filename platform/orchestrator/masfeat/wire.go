// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

// ModuleConfig contains configuration for the MAS FEAT module.
type ModuleConfig struct {
	// DB is the database connection.
	DB *sql.DB

	// DefaultBiasThreshold is the maximum allowed bias score (default: 0.10).
	DefaultBiasThreshold float64

	// DefaultAssessmentValidityMonths is the default validity period for assessments (default: 12).
	DefaultAssessmentValidityMonths int
}

// Module is the MAS FEAT compliance module.
type Module struct {
	// Repositories
	RegistryRepo   RegistryRepository
	AssessmentRepo AssessmentRepository
	KillSwitchRepo KillSwitchRepository

	// Services
	RegistryService   *RegistryService
	AssessmentService *AssessmentService
	KillSwitchService *KillSwitchService

	// Handlers
	RegistryHandler   *RegistryHandler
	AssessmentHandler *AssessmentHandler
	KillSwitchHandler *KillSwitchHandler
}

// NewModule creates a new MAS FEAT compliance module.
func NewModule(config ModuleConfig) (*Module, error) {
	// Set defaults
	if config.DefaultBiasThreshold == 0 {
		config.DefaultBiasThreshold = DefaultBiasMaxThreshold
	}
	if config.DefaultAssessmentValidityMonths == 0 {
		config.DefaultAssessmentValidityMonths = 12
	}

	// Create repositories
	registryRepo := NewPostgresRegistryRepository(config.DB)
	assessmentRepo := NewPostgresAssessmentRepository(config.DB)
	killSwitchRepo := NewPostgresKillSwitchRepository(config.DB)

	// Create services
	registryService := NewRegistryService(registryRepo)
	assessmentService := NewAssessmentService(assessmentRepo, registryRepo, config.DefaultAssessmentValidityMonths)
	killSwitchService := NewKillSwitchService(killSwitchRepo, config.DefaultBiasThreshold)

	// Create handlers
	registryHandler := NewRegistryHandler(registryService)
	assessmentHandler := NewAssessmentHandler(assessmentService)
	killSwitchHandler := NewKillSwitchHandler(killSwitchService)

	return &Module{
		RegistryRepo:      registryRepo,
		AssessmentRepo:    assessmentRepo,
		KillSwitchRepo:    killSwitchRepo,
		RegistryService:   registryService,
		AssessmentService: assessmentService,
		KillSwitchService: killSwitchService,
		RegistryHandler:   registryHandler,
		AssessmentHandler: assessmentHandler,
		KillSwitchHandler: killSwitchHandler,
	}, nil
}

// RegisterRoutes registers all MAS FEAT routes on the given http.ServeMux.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	// Registry routes
	m.RegistryHandler.RegisterRoutes(mux)

	// Assessment routes
	m.AssessmentHandler.RegisterRoutes(mux)

	// Kill Switch routes
	m.KillSwitchHandler.RegisterRoutes(mux)
}

// RegisterRoutesWithMux registers all MAS FEAT routes on a gorilla/mux Router.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {
	if r == nil {
		log.Println("⚠️ MAS FEAT: cannot register routes - router is nil")
		return
	}

	// Registry routes
	r.HandleFunc("/api/v1/masfeat/registry", m.RegistryHandler.handleRegistry).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/registry/summary", m.RegistryHandler.handleRegistrySummary).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/registry/{id}", m.handleRegistryByIDWithMux).Methods("GET", "PUT", "DELETE", "OPTIONS")

	// Assessment routes
	r.HandleFunc("/api/v1/masfeat/assessments", m.AssessmentHandler.handleAssessments).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/assessments/{id}", m.handleAssessmentByIDWithMux).Methods("GET", "PUT", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/assessments/{id}/submit", m.handleAssessmentActionWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/assessments/{id}/approve", m.handleAssessmentActionWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/assessments/{id}/reject", m.handleAssessmentActionWithMux).Methods("POST", "OPTIONS")

	// Kill Switch routes
	r.HandleFunc("/api/v1/masfeat/killswitch/{system_id}", m.handleKillSwitchByIDWithMux).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/configure", m.handleKillSwitchConfigureWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/trigger", m.handleKillSwitchTriggerWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/restore", m.handleKillSwitchRestoreWithMux).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/masfeat/killswitch/{system_id}/history", m.handleKillSwitchHistoryWithMux).Methods("GET", "OPTIONS")

	log.Println("✅ MAS FEAT routes registered:")
	log.Println("   - POST/GET /api/v1/masfeat/registry")
	log.Println("   - GET /api/v1/masfeat/registry/summary")
	log.Println("   - GET/PUT/DELETE /api/v1/masfeat/registry/{id}")
	log.Println("   - POST/GET /api/v1/masfeat/assessments")
	log.Println("   - GET/PUT /api/v1/masfeat/assessments/{id}")
	log.Println("   - POST /api/v1/masfeat/assessments/{id}/submit|approve|reject")
	log.Println("   - GET /api/v1/masfeat/killswitch/{system_id}")
	log.Println("   - POST /api/v1/masfeat/killswitch/{system_id}/configure|trigger|restore")
	log.Println("   - GET /api/v1/masfeat/killswitch/{system_id}/history")
}

// Mux adapter functions

func (m *Module) handleRegistryByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/masfeat/registry/" + id
	m.RegistryHandler.handleRegistryByID(w, r)
}

func (m *Module) handleAssessmentByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	r.URL.Path = "/api/v1/masfeat/assessments/" + id
	m.AssessmentHandler.handleAssessmentByID(w, r)
}

func (m *Module) handleAssessmentActionWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	action := extractAction(r.URL.Path)
	r.URL.Path = "/api/v1/masfeat/assessments/" + id + "/" + action
	m.AssessmentHandler.handleAssessmentByID(w, r)
}

func (m *Module) handleKillSwitchByIDWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	systemID := vars["system_id"]
	r.URL.Path = "/api/v1/masfeat/killswitch/" + systemID
	m.KillSwitchHandler.handleKillSwitch(w, r)
}

func (m *Module) handleKillSwitchConfigureWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	systemID := vars["system_id"]
	r.URL.Path = "/api/v1/masfeat/killswitch/" + systemID + "/configure"
	m.KillSwitchHandler.handleKillSwitchConfigure(w, r)
}

func (m *Module) handleKillSwitchTriggerWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	systemID := vars["system_id"]
	r.URL.Path = "/api/v1/masfeat/killswitch/" + systemID + "/trigger"
	m.KillSwitchHandler.handleKillSwitchTrigger(w, r)
}

func (m *Module) handleKillSwitchRestoreWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	systemID := vars["system_id"]
	r.URL.Path = "/api/v1/masfeat/killswitch/" + systemID + "/restore"
	m.KillSwitchHandler.handleKillSwitchRestore(w, r)
}

func (m *Module) handleKillSwitchHistoryWithMux(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	systemID := vars["system_id"]
	r.URL.Path = "/api/v1/masfeat/killswitch/" + systemID + "/history"
	m.KillSwitchHandler.handleKillSwitchHistory(w, r)
}

// extractAction extracts the action from a path like /api/v1/masfeat/assessments/{id}/submit
func extractAction(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return ""
}

// IsHealthy returns true if the MAS FEAT module is properly initialized.
func (m *Module) IsHealthy() bool {
	return m.RegistryHandler != nil && m.AssessmentHandler != nil && m.KillSwitchHandler != nil
}

// HealthCheck returns detailed health status of MAS FEAT services.
func (m *Module) HealthCheck() map[string]string {
	status := make(map[string]string)

	if m.RegistryHandler != nil {
		status["registry"] = "ok"
	} else {
		status["registry"] = "unavailable"
	}

	if m.AssessmentHandler != nil {
		status["assessments"] = "ok"
	} else {
		status["assessments"] = "unavailable"
	}

	if m.KillSwitchHandler != nil {
		status["killswitch"] = "ok"
	} else {
		status["killswitch"] = "unavailable"
	}

	return status
}
