// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"database/sql"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/cloudstorage"
	"axonflow/platform/orchestrator/euaiact"
	"axonflow/platform/orchestrator/masfeat"
	"axonflow/platform/orchestrator/ojk"
	"axonflow/platform/orchestrator/rbi"
	"axonflow/platform/orchestrator/sebi"
)

// ModuleConfig wires the compliance report facade.
//
// The five module pointers are the LIVE modules the orchestrator already
// constructed. Passing the modules (rather than re-constructing repositories
// here) is what makes the providers read-only consumers of the existing
// services, and it means a module that failed to initialize arrives as nil and
// its regulator answers `not_available` with no special case anywhere.
type ModuleConfig struct {
	DB             *sql.DB
	StorageBackend cloudstorage.StorageBackend
	Licenses       LicenseGate

	EUAIAct *euaiact.Module
	SEBI    *sebi.SEBIModule
	RBI     *rbi.RBIModule
	MASFEAT *masfeat.Module
	OJK     *ojk.OJKModule
}

// Module is the compliance report facade module.
type Module struct {
	Repo     Repository
	Registry *Registry
	Service  *Service
	Handler  *Handler
}

// NewModule constructs the facade.
//
// A nil DB yields a module with no service: the routes still register (the
// established pattern - route registration is unconditional and the edition
// gate is the build tag, see run.go), and every request answers 503 with a
// cause instead of panicking on a nil handle.
func NewModule(config ModuleConfig) (*Module, error) {
	m := &Module{}
	m.Registry = NewRegistry(
		newEUAIActProvider(config.EUAIAct),
		newSEBIProvider(config.SEBI),
		newRBIProvider(config.RBI),
		newMASFEATProvider(config.MASFEAT),
		newOJKProvider(config.OJK),
	)
	if config.DB == nil {
		log.Println("⚠️  Compliance Report facade: no database handle - the routes still register and will answer 503 with a cause; no report can be created, polled or downloaded until DATABASE_URL is set")
		return m, nil
	}
	m.Repo = NewPostgresRepository(config.DB)
	m.Service = NewService(ServiceConfig{
		Repo:     m.Repo,
		Registry: m.Registry,
		Storage:  config.StorageBackend,
		Licenses: config.Licenses,
	})
	m.Handler = NewHandler(m.Service)
	return m, nil
}

// RegisterRoutesWithMux registers the facade routes on a gorilla/mux Router.
//
// Registration is UNCONDITIONAL, matching every sibling compliance module:
// IsHealthy() gates nothing here either, and the edition gate is the
// `//go:build enterprise` tag plus the community no-op stub. A route that
// exists but has no service answers 503 with a cause, which is strictly more
// debuggable than a 404 that looks like a wrong URL.
func (m *Module) RegisterRoutesWithMux(r *mux.Router) {
	if r == nil {
		log.Println("⚠️ Compliance Report facade: cannot register routes - router is nil")
		return
	}
	// The paths are written as STRING LITERALS rather than as BasePath /
	// ByIDPath / DownloadPath deliberately. The portal's route census
	// (ee/platform/customer-portal/orchestrator_proxy_census_test.go) and the
	// policy-gate census AST-walk this file; neither resolves a constant, and
	// both fail loudly on a non-literal path precisely because an unresolvable
	// path could hide a proxy-reachable or ungated route from the census.
	//
	// Drift between these literals and the constants is what
	// TestRegisteredPathsMatchTheExportedConstants pins.
	r.HandleFunc("/api/v1/compliance/reports", m.handleCollection).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/compliance/reports/{id}", m.handleByID).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/compliance/reports/{id}/download", m.handleDownload).Methods("GET", "OPTIONS")

	log.Println("✅ Compliance Report facade routes registered:")
	log.Println("   - POST " + BasePath)
	log.Println("   - GET  " + ByIDPath)
	log.Println("   - GET  " + DownloadPath)
}

// RegisterRoutes registers the facade on a standard http.ServeMux, mirroring
// the sibling modules' dual registration surface.
func (m *Module) RegisterRoutes(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	// String literals for the same census reason as RegisterRoutesWithMux above.
	mux.HandleFunc("/api/v1/compliance/reports", m.handleCollection)
	mux.HandleFunc("/api/v1/compliance/reports/", m.handleByIDPathStyle)
}

func (m *Module) handleCollection(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if !m.ready(w) {
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, ErrCodeInvalidBody, "method not allowed", "")
		return
	}
	m.Handler.createReport(w, r)
}

func (m *Module) handleByID(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if !m.ready(w) {
		return
	}
	m.Handler.getReport(w, r, mux.Vars(r)["id"])
}

func (m *Module) handleDownload(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if !m.ready(w) {
		return
	}
	m.Handler.downloadReport(w, r, mux.Vars(r)["id"])
}

// handleByIDPathStyle is the http.ServeMux adapter: ServeMux has no path
// variables, so the id and the optional /download suffix are parsed from the
// path.
//
// METHOD FILTERING (M6/M7 of the #3241 round-2 record). The gorilla routes
// restrict the by-id and download routes to GET; ServeMux has no equivalent, so
// this adapter has to do it itself. It did not, which meant the comment here
// claiming the two surfaces "cannot diverge in what they authorize" was false:
// a POST or DELETE to /api/v1/compliance/reports/{id} was accepted on the
// ServeMux plane and refused on the gorilla one.
//
// Nothing exploitable followed from it - both by-id handlers are reads and
// ignore the method - but a claim of equivalence that is not enforced is the
// thing that makes the NEXT handler, added by someone trusting the comment,
// method-blind on one plane only.
func (m *Module) handleByIDPathStyle(w http.ResponseWriter, r *http.Request) {
	if handlePreflight(w, r) {
		return
	}
	if !m.ready(w) {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, ErrCodeInvalidBody,
			"method not allowed: the compliance report poll and download routes are GET-only", "")
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, BasePath+"/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, ErrCodeNotFound, "report id is required", "")
		return
	}
	if len(parts) > 1 && parts[1] == "download" {
		m.Handler.downloadReport(w, r, parts[0])
		return
	}
	if len(parts) > 1 {
		writeError(w, http.StatusNotFound, ErrCodeNotFound, "unknown compliance report route", "")
		return
	}
	m.Handler.getReport(w, r, parts[0])
}

// handlePreflight answers a CORS preflight and reports whether it did.
func handlePreflight(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodOptions {
		return false
	}
	w.WriteHeader(http.StatusOK)
	return true
}

// ready reports whether the module has a live service, writing a 503 with a
// cause when it does not.
func (m *Module) ready(w http.ResponseWriter) bool {
	if m == nil || m.Handler == nil {
		writeError(w, http.StatusServiceUnavailable, ErrCodeInternal,
			"the compliance report service is not initialized (the orchestrator has no database connection)", "")
		return false
	}
	return true
}

// IsHealthy reports whether the facade can serve requests.
//
// As with every sibling module, this gates NOTHING at route-registration time
// (see RegisterRoutesWithMux); it exists for the health payload only.
func (m *Module) IsHealthy() bool {
	return m != nil && m.Handler != nil && m.Service != nil
}

// HealthCheck reports per-regulator availability, which is exactly the
// three-state `not_available` answer expressed as a health map.
func (m *Module) HealthCheck() map[string]string {
	status := make(map[string]string, len(AllRegulators())+1)
	if m.IsHealthy() {
		status["report_facade"] = "ok"
	} else {
		status["report_facade"] = "unavailable"
	}
	for _, r := range AllRegulators() {
		if m != nil && m.Registry != nil && m.Registry.Get(r) != nil {
			status["provider_"+string(r)] = "ok"
		} else {
			status["provider_"+string(r)] = "not_available"
		}
	}
	return status
}
