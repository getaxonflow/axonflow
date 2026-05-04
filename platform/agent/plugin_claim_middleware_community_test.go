//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// In community builds the plugin-claim middleware is a no-op pass-through.
// This test guards against accidental regression: if someone wires real
// behaviour into the community stub by mistake, this test breaks.

func TestPluginClaimMiddleware_Community_NoOpEvenWithToken(t *testing.T) {
	mw := PluginClaimMiddleware(nil)
	innerRan := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan = true
		if PluginClaimFromContext(r.Context()) != nil {
			t.Errorf("community PluginClaimFromContext should always return nil")
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("X-License-Token", "AXON-anything.anything")
	rec := httptest.NewRecorder()
	mw(inner).ServeHTTP(rec, req)

	if !innerRan {
		t.Fatal("inner handler never ran — community middleware should pass through")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestPluginClaimFromContext_Community_AlwaysNil(t *testing.T) {
	if got := PluginClaimFromContext(context.Background()); got != nil {
		t.Errorf("expected nil in community build, got %+v", got)
	}
}
