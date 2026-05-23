// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package idempotency

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestWrap_PassthroughWithoutKey covers the no-header case — Wrap is a
// transparent pass-through to handler() and never touches the store.
func TestWrap_PassthroughWithoutKey(t *testing.T) {
	called := false
	handler := func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
	req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	rr := httptest.NewRecorder()
	// nil store, no header — Wrap should still invoke handler.
	Wrap(rr, req, nil, "org", "tenant", "ep", handler)
	if !called {
		t.Fatal("handler was not invoked on pass-through")
	}
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("unexpected response code=%d body=%q", rr.Code, rr.Body.String())
	}
}

// TestWrap_InvalidKeyReturns400 covers the validation gate. A key with
// shell metachars must produce a 400 before the handler runs.
func TestWrap_InvalidKeyReturns400(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	store := NewStore(db, nil)
	handler := func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not be invoked on invalid key")
	}
	req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	req.Header.Set(HeaderName, "bad;key")
	rr := httptest.NewRecorder()
	Wrap(rr, req, store, "org", "tenant", "ep", handler)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rr.Code)
	}
}

// TestWrap_CachedResponseShortCircuits covers the cache-hit path: the
// cached body is written and the handler is NOT invoked.
func TestWrap_CachedResponseShortCircuits(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	store := NewStore(db, nil)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WithArgs("k1", "tenant", "ep").
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}).
			AddRow(201, []byte(`{"cached":true}`), time.Now().Add(-1*time.Hour), time.Now().Add(23*time.Hour)))
	mock.ExpectCommit()

	handlerCalls := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalls++
		w.WriteHeader(500)
	}
	req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	req.Header.Set(HeaderName, "k1")
	rr := httptest.NewRecorder()
	Wrap(rr, req, store, "org", "tenant", "ep", handler)

	if handlerCalls != 0 {
		t.Fatalf("handler called %d times, want 0 on cache hit", handlerCalls)
	}
	if rr.Code != 201 {
		t.Fatalf("status=%d want 201", rr.Code)
	}
	if rr.Body.String() != `{"cached":true}` {
		t.Fatalf("body=%q want cached body", rr.Body.String())
	}
	if rr.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatal("missing Idempotent-Replayed header")
	}
}

// TestWrap_5xxNotCached covers the must-not-cache rule for 500-class
// responses (caller can safely retry).
func TestWrap_5xxNotCached(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	store := NewStore(db, nil)

	// Initial lookup miss.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}))
	mock.ExpectCommit()
	// No subsequent INSERT — 5xx is not cached.

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("oops"))
	}
	req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	req.Header.Set(HeaderName, "k1")
	rr := httptest.NewRecorder()
	Wrap(rr, req, store, "org", "tenant", "ep", handler)
	if rr.Code != 500 {
		t.Fatalf("status=%d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock: %v", err)
	}
}

// TestWrap_400IsCachedAsLegitimateDenialResponse covers the design rule
// that deterministic 4xx denies ARE cached.
func TestWrap_400IsCachedAsLegitimateDenialResponse(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	store := NewStore(db, nil)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}))
	mock.ExpectCommit()

	// Expect the INSERT to fire (cache the 400).
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO idempotency_keys`).
		WithArgs("k1", "tenant", "ep", 400, []byte("bad"), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte("bad"))
	}
	req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
	req.Header.Set(HeaderName, "k1")
	rr := httptest.NewRecorder()
	Wrap(rr, req, store, "org", "tenant", "ep", handler)
	if rr.Code != 400 {
		t.Fatalf("status=%d", rr.Code)
	}
	// Drain the body so go test doesn't complain about an unread response.
	_, _ = io.Copy(io.Discard, rr.Body)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock: %v", err)
	}
}

// TestWrap_RedactKey covers the log redaction path.
func TestWrap_RedactKey(t *testing.T) {
	short := "abc"
	if redactKey(short) != "abc" {
		t.Fatal("short key should round-trip")
	}
	long := strings.Repeat("x", 60)
	got := redactKey(long)
	if !strings.Contains(got, "...") {
		t.Fatalf("long key not redacted: %q", got)
	}
	if len(got) >= len(long) {
		t.Fatalf("redacted key not shorter")
	}
}

// failingWriter mimics a client disconnect mid-write so the recorder's
// writeBodyErr path engages.
type failingWriter struct {
	hdr http.Header
}

func (f *failingWriter) Header() http.Header {
	if f.hdr == nil {
		f.hdr = make(http.Header)
	}
	return f.hdr
}
func (f *failingWriter) WriteHeader(_ int) {}
func (f *failingWriter) Write(_ []byte) (int, error) {
	return 0, http.ErrAbortHandler
}

// TestResponseRecorder_WriteErrorSkipsCache covers R3 R2 LOW-2 — a mid-
// write failure must NOT cache a partial body.
func TestResponseRecorder_WriteErrorSkipsCache(t *testing.T) {
	rec := &responseRecorder{ResponseWriter: &failingWriter{}, status: http.StatusOK}
	rec.WriteHeader(201)
	_, _ = rec.Write([]byte("partial"))
	if rec.shouldCache() {
		t.Fatal("shouldCache must return false after a write error (partial body would be cached)")
	}
}

