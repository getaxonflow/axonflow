//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"

	"github.com/gorilla/mux"
)

func registerAgentCapabilities(router *mux.Router) {
	router.PathPrefix("/api/v1/capabilities").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONError(w, "Agent capabilities require Enterprise", http.StatusNotImplemented)
	})
}
