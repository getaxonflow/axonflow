// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package idempotency

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// An answer the handler marks `Cache-Control: no-store` is not cached (#4370).
// The key is not the body, so an answer that belongs to ONE request - an
// approval spent for exactly one call, a pending approval a person may
// approve a minute later - must never be replayed for another request under
// the same key. The control (the same answer without the header) IS cached,
// so the cell can tell a store that was skipped from one that never ran.
func TestWrap_AnAnswerMarkedNoStoreIsNotCached(t *testing.T) {
	run := func(t *testing.T, noStore bool) error {
		db, mock, _ := sqlmock.New()
		defer db.Close()
		store := NewStore(db, nil)
		scope := func() {
			mock.ExpectBegin()
			mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).WithArgs("org").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).WithArgs("tenant").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).WithArgs("tenant").WillReturnResult(sqlmock.NewResult(0, 0))
		}
		scope()
		mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
			WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}))
		mock.ExpectCommit()
		scope()
		mock.ExpectExec(`INSERT INTO idempotency_keys`).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		handler := func(w http.ResponseWriter, r *http.Request) {
			if noStore {
				w.Header().Set("Cache-Control", "no-store")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"allowed":true,"approval_id":"a1"}`))
		}
		req := httptest.NewRequest("POST", "/x", strings.NewReader(""))
		req.Header.Set(HeaderName, "k1")
		Wrap(httptest.NewRecorder(), req, store, "org", "tenant", "ep", handler)
		return mock.ExpectationsWereMet()
	}
	if err := run(t, false); err != nil {
		t.Fatalf("CONTROL: an answer without no-store was not cached (%v); the cell cannot tell a skipped store from a broken one", err)
	}
	// Marked no-store: the lookup runs, and the store's transaction never
	// begins, so its expectations stay unmet.
	if err := run(t, true); err == nil {
		t.Fatalf("an answer marked no-store was cached (unmet expectations: %v)", err)
	}
}
