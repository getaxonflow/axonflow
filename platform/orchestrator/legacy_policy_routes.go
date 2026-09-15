// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"github.com/gorilla/mux"

	"axonflow/platform/shared/policypath"
)

// registerLegacyPolicyRoutes registers the orchestrator's half of the v11
// deprecated export surface (PRD §1.11) on one subrouter that stamps every
// response with the deprecation signal policypath.StampDeprecation writes:
//
//   - /api/v1/policies*: CRUD, test, versions, import/export, the two
//     pre-#1431 dynamic-policy routes, and simulation where the licence
//     enables it;
//   - /api/v1/templates*;
//   - /api/v1/dynamic-policies* and its #1431 spelling /api/v1/tenant-policies*.
//
// Reads keep working, so an organization can see and export its legacy rows
// after upgrading and the SDKs that still call these routes keep working until
// v11.1; writes answer 409 through platform/shared/legacyfreeze.
//
// ONE REGISTRAR, BECAUSE THE STAMP IS A PROPERTY OF WHERE A ROUTE IS
// REGISTERED. These routes were registered from four places in Run, and seven
// of them carried the signal. A route registered here carries it whatever its
// handler answers - a 200, a 401, a 409 or a 503 - and a legacy-family route
// registered anywhere else in this binary is refused by
// TestNoLegacyPolicyRouteIsRegisteredOutsideAStampedRegistrar
// (platform/shared/policypath).
//
// The subrouter has no matcher of its own, so it changes nothing about which
// request reaches which handler: gorilla/mux tries the routes below in order,
// and a request that matches none of them falls through to the rest of the
// root router as before. The order is the order Run used, and it matters as it
// always did: the literal suffixes precede "/{id}", and simulation follows the
// CRUD block.
//
// tenant is nil where the database is unavailable and simulation is nil below
// the Evaluation licence; each registers nothing then, as in Run before.
func registerLegacyPolicyRoutes(r *mux.Router, tenant *DynamicPolicyAPIHandler, simulation *PolicySimulationHandler) {
	legacy := r.NewRoute().Subrouter()
	legacy.Use(policypath.DeprecateLegacy)
	stamped := legacyRouter{legacy}

	// The pre-#1431 dynamic-policy list and pattern test, served by the
	// policy engine rather than the policy service.
	legacy.HandleFunc("/api/v1/policies/dynamic", listDynamicPoliciesHandler).Methods("GET")
	legacy.HandleFunc("/api/v1/policies/test", testPolicyHandler).Methods("POST")

	// Policy CRUD (Track A).
	legacy.HandleFunc("/api/v1/policies", policyAPIListCreateHandler).Methods("GET", "POST", "OPTIONS")
	legacy.HandleFunc("/api/v1/policies/import", policyAPIImportHandler).Methods("POST", "OPTIONS")
	legacy.HandleFunc("/api/v1/policies/export", policyAPIExportHandler).Methods("GET", "OPTIONS")
	legacy.HandleFunc("/api/v1/policies/{id}", policyAPIGetUpdateDeleteHandler).Methods("GET", "PUT", "DELETE", "OPTIONS")
	legacy.HandleFunc("/api/v1/policies/{id}/test", policyAPITestHandler).Methods("POST", "OPTIONS")
	legacy.HandleFunc("/api/v1/policies/{id}/versions", policyAPIVersionsHandler).Methods("GET", "OPTIONS")
	// NOTE: per-policy override is system/static-only (per the #2753 override
	// decision; #2768 closed the dynamic variant). Overrides are handled by the
	// agent static-policy override path; dynamic/tenant policies use edit/delete.

	// Policy templates (Track D).
	legacy.HandleFunc("/api/v1/templates", templateAPIListHandler).Methods("GET", "OPTIONS")
	legacy.HandleFunc("/api/v1/templates/categories", templateAPICategoriesHandler).Methods("GET", "OPTIONS")
	legacy.HandleFunc("/api/v1/templates/stats", templateAPIStatsHandler).Methods("GET", "OPTIONS")
	legacy.HandleFunc("/api/v1/templates/{id}", templateAPIGetHandler).Methods("GET", "OPTIONS")
	legacy.HandleFunc("/api/v1/templates/{id}/apply", templateAPIApplyHandler).Methods("POST", "OPTIONS")

	// Tenant policy API, both #1431 spellings (ADR-024: the agent proxies
	// them here, so this is where the signal is written for both hops).
	if tenant != nil {
		tenant.RegisterRoutes(stamped)
	}

	// Policy simulation, impact report and conflict detection (Evaluation+).
	if simulation != nil {
		simulation.RegisterRoutes(stamped)
	}
}

// legacyRouter is the stamped subrouter registerLegacyPolicyRoutes builds.
//
// The tenant and simulation registrars take it instead of a *mux.Router so the
// compiler refuses to call them on a router that does not stamp: the one value
// of this type in shipping code is constructed above, and the registrar census
// (platform/shared/policypath) reds on a second construction.
type legacyRouter struct{ *mux.Router }
