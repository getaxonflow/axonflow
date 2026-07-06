//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Community-edition stub for the Cowork / Claude Code OTEL ingest plane
// (#2760 / WS-6). The OTEL reporting plane is an Enterprise feature; the
// community build mounts a route that returns 501 so callers get a clear signal
// rather than a 404. The enterprise implementation lives in
// cowork_otel_ingest.go (//go:build enterprise).
package agent

import (
	"net/http"

	"github.com/gorilla/mux"
)

// registerCoworkOTELIngest (community) mounts 501 stubs at POST /v1/logs and
// POST /v1/metrics.
func registerCoworkOTELIngest(r *mux.Router) {
	stub := func(w http.ResponseWriter, _ *http.Request) {
		writeJSONError(w, "Cowork OTEL ingest is an Enterprise feature", http.StatusNotImplemented)
	}
	r.HandleFunc("/v1/logs", stub).Methods(http.MethodPost)
	r.HandleFunc("/v1/metrics", stub).Methods(http.MethodPost)
}
