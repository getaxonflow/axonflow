//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSessionSummaryHandler_Community_Returns501(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/session-summary?start_date=2026-06-01&end_date=2026-07-01", nil)
	req.Header.Set("X-Tenant-ID", "acme")
	rr := httptest.NewRecorder()
	sessionSummaryHandler(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("want 501, got %d", rr.Code)
	}
}
