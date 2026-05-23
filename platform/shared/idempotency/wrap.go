// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package idempotency

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"strings"
)

// HeaderName is the HTTP header consulted on every request.
const HeaderName = "Idempotency-Key"

// Wrap runs handler() with the response captured. On entry, if r carries a
// valid Idempotency-Key header and a non-expired cached response exists for
// (orgID, tenantID, key, endpoint), the cached body + status is written to w
// and handler() is NOT invoked. On a miss, handler() runs against a buffered
// ResponseWriter; if the response status is 2xx or 4xx the envelope is
// stored. 5xx responses are NOT cached so the caller can retry.
//
// Invariants:
//   - Wrap NEVER blocks the request on store/lookup failure. A DB error is
//     logged and the request falls through to handler() (cache-miss-shaped).
//   - The store write happens AFTER the response is flushed to the client,
//     so a slow DB never adds latency to the user-visible path.
//   - When no Idempotency-Key header is present, Wrap is a transparent
//     pass-through to handler().
//
// Why a helper rather than mux.Middleware: the agent's /api/v1/mcp/check-input
// + the orchestrator's /api/v1/audit/tool-call handlers both do auth inside
// the handler body (not via apiAuthMiddleware), so tenant_id is only known
// AFTER the auth call. Callers invoke Wrap once they have a resolved
// tenant_id/org_id.
//
// Header replay: only the response status code + body are cached. On a
// cache hit Wrap emits Content-Type: application/json + Idempotent-Replayed:
// true; ALL other handler-set headers are dropped. The current three target
// endpoints (mcp/check-input, audit/tool-call, hitl/queue) set no headers
// beyond Content-Type so this is safe today. Any future handler wrapped by
// this helper that sets Location, Retry-After, X-RateLimit-*, etc. MUST
// either be excluded from the wrap OR migration 115's schema must be
// extended with a response_headers JSONB column + Lookup/Store updated to
// roundtrip it. ADR-055 §Consequences names this trade-off.
func Wrap(
	w http.ResponseWriter,
	r *http.Request,
	store *Store,
	orgID, tenantID, endpoint string,
	handler func(http.ResponseWriter, *http.Request),
) {
	key := strings.TrimSpace(r.Header.Get(HeaderName))
	if key == "" || store == nil || !store.Enabled() {
		handler(w, r)
		return
	}
	if err := ValidateKey(key); err != nil {
		http.Error(w, "invalid Idempotency-Key: "+err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if cached, err := store.Lookup(ctx, orgID, tenantID, key, endpoint); err != nil {
		log.Printf("[Idempotency] lookup error endpoint=%s key=%s err=%v — falling through to handler", endpoint, redactKey(key), err)
	} else if cached != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Idempotent-Replayed", "true")
		w.WriteHeader(cached.StatusCode)
		if _, err := w.Write(cached.Body); err != nil {
			log.Printf("[Idempotency] write cached body err=%v", err)
		}
		return
	}

	rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
	handler(rec, r)

	if !rec.shouldCache() {
		return
	}
	// Use a fresh context for the post-flush write so a client disconnect
	// (which cancels r.Context()) doesn't abort the cache persist. The
	// write is bounded by appDB's pool timeout.
	bgCtx := context.WithoutCancel(ctx)
	if err := store.Store(bgCtx, orgID, tenantID, key, endpoint, rec.status, rec.buf.Bytes(), DefaultTTL); err != nil {
		log.Printf("[Idempotency] store error endpoint=%s key=%s err=%v", endpoint, redactKey(key), err)
	}
}

// responseRecorder buffers the body so we can both flush to the client and
// persist to the cache.
type responseRecorder struct {
	http.ResponseWriter
	status        int
	buf           bytes.Buffer
	wroteHeader   bool
	writeBodyErr  error
}

func (rr *responseRecorder) WriteHeader(code int) {
	if rr.wroteHeader {
		return
	}
	rr.status = code
	rr.wroteHeader = true
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(p []byte) (int, error) {
	if !rr.wroteHeader {
		rr.WriteHeader(http.StatusOK)
	}
	rr.buf.Write(p)
	n, err := rr.ResponseWriter.Write(p)
	if err != nil {
		rr.writeBodyErr = err
	}
	return n, err
}

// shouldCache returns true for 2xx + 4xx responses. 5xx is treated as
// transient and skipped so the caller's retry can hit a fresh attempt.
// A body-write error also skips caching (the cached body would be partial).
//
// Per #2420: deterministic deny responses (400/403/404/409/429) ARE cached
// because they're the legitimate idempotent answer for the same input — a
// retry with a corrected body changes the input and should use a new key.
func (rr *responseRecorder) shouldCache() bool {
	if rr.writeBodyErr != nil {
		return false
	}
	return rr.status >= 200 && rr.status < 500
}

// redactKey trims a key for log output so verbose IDs don't bloat lines.
func redactKey(k string) string {
	if len(k) <= 32 {
		return k
	}
	return k[:16] + "..." + k[len(k)-8:]
}
