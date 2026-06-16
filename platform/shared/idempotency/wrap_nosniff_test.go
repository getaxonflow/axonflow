// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package idempotency

import (
	"net/http/httptest"
	"testing"
)

// TestResponseRecorderSetsNoSniff verifies the idempotency passthrough recorder
// sets X-Content-Type-Options: nosniff as defense-in-depth against MIME-sniffing
// a reflected value as HTML (go/reflected-xss on wrap.go).
func TestResponseRecorderSetsNoSniff(t *testing.T) {
	rec := httptest.NewRecorder()
	rr := &responseRecorder{ResponseWriter: rec, status: 200}
	rr.WriteHeader(201)
	if _, err := rr.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff, got %q", got)
	}
	if rr.status != 201 {
		t.Fatalf("expected recorded status 201, got %d", rr.status)
	}
}
