//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestCommunityAgentCapabilitiesReturn501(t *testing.T) {
	router := mux.NewRouter()
	registerAgentCapabilities(router)
	for _, path := range []string{"/api/v1/capabilities", "/api/v1/capabilities/example/invoke"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotImplemented {
			t.Fatalf("%s returned %d, want 501", path, response.Code)
		}
	}
}
