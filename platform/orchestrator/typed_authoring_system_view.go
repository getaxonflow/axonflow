// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"

	"axonflow/platform/decision/authoring"
)

// handleSystem serves the shipped system corpus, read-only (#3884).
//
// It answers GET only. The route registers no write verb, so a POST, PUT or
// DELETE on this path reaches handleUnenumerated and is refused: the system
// root's one authority is the corpus this binary shipped, and no transport
// writes it (SYSTEM_ROOT_SIGNING_AUTHORITY.md).
//
// IT DOES NOT REQUIRE A CONFIGURED VOCABULARY, unlike the authoring endpoints
// beside it. The corpus is embedded in the binary and is enforced beneath every
// organization document whether or not this deployment authors typed policy,
// so "which controls does the platform enforce" has an answer on a deployment
// that declares no catalog. It does require a gateway-stamped caller, like
// every read on this surface.
func (h *TypedAuthoringRouteHandler) handleSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		typedAuthoringCORS(w, r)
		return
	}
	if _, _, ok := h.callerIdentity(w, r); !ok {
		return
	}
	view, err := authoring.ShippedSystemCorpusView()
	if err != nil {
		typedAuthoringJSON(w, http.StatusInternalServerError, map[string]any{
			"success": false, "reason": "system_corpus_unavailable", "error": err.Error(),
		})
		return
	}
	typedAuthoringJSON(w, http.StatusOK, map[string]any{"success": true, "system": view})
}
