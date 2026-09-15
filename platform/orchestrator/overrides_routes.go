// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "github.com/gorilla/mux"

// registerOverrideRoutes registers the session-override family (ADR-044).
//
// The writes are retired in v11.0.0 (#4252): create and revoke answer the
// unconditional 409 LEGACY_POLICY_WRITE_FROZEN naming the typed document. They
// stay registered so a caller receives that refusal, and the reads stay. These
// statements moved out of Run unchanged, so that this file's references to the
// family are one disposition and run.go's are another.
func registerOverrideRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/overrides", createOverrideHandler).Methods("POST")
	r.HandleFunc("/api/v1/overrides", listOverridesHandler).Methods("GET")
	r.HandleFunc("/api/v1/overrides/{id}", getOverrideHandler).Methods("GET")
	r.HandleFunc("/api/v1/overrides/{id}", revokeOverrideHandler).Methods("DELETE")
}
