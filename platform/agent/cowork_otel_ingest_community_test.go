//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// The community build mounts explicit 501 stubs on BOTH OTLP ingest paths so a
// misconfigured community exporter gets a clear "Enterprise feature" signal
// instead of a 404 (#2760 logs, #2832/#2835 metrics).
func TestCoworkOTELIngest_CommunityStubs501(t *testing.T) {
	router := mux.NewRouter()
	registerCoworkOTELIngest(router)

	for _, path := range []string{"/v1/logs", "/v1/metrics"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("x"))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != http.StatusNotImplemented {
			t.Errorf("POST %s: got %d want 501", path, w.Code)
		}
		if !strings.Contains(w.Body.String(), "Enterprise") {
			t.Errorf("POST %s: body should say Enterprise feature, got %q", path, w.Body.String())
		}
	}
}
