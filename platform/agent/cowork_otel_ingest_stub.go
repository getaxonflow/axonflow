// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"

	"github.com/gorilla/mux"
)

// coworkOTELIngestUnavailable is the one answer a process whose plane set has
// no cowork ingest plane gives the OTLP ingest routes: the community build
// always, and the Enterprise build in a core-only deployment mode, where
// deploymode.PlaneEdition is Community and registry/legacy_plane_peps.tsv
// registers no cowork_ingest plane (#4259). Both mount it through
// mountCoworkOTELIngestStub, so the two answers cannot drift apart.
const coworkOTELIngestUnavailable = "Cowork OTEL ingest is an Enterprise feature"

// mountCoworkOTELIngestStub mounts 501 stubs at POST /v1/logs and POST
// /v1/metrics, so a caller gets a clear signal rather than a 404.
func mountCoworkOTELIngestStub(r *mux.Router) {
	stub := func(w http.ResponseWriter, _ *http.Request) {
		writeJSONError(w, coworkOTELIngestUnavailable, http.StatusNotImplemented)
	}
	r.HandleFunc("/v1/logs", stub).Methods(http.MethodPost)
	r.HandleFunc("/v1/metrics", stub).Methods(http.MethodPost)
}
