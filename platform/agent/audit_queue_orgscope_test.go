// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit tests for execWithRetryOrgScope — the v9 Phase 8 B2 RLS-aware wrapper
// around the BeginTx + set_config + Exec + Commit retry path. These tests use
// sqlmock to verify the transaction sequencing without needing a real Postgres
// connection.

import (
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestExecWithRetryOrgScope_EmptyOrgID — explicit guard. The helper must
// reject empty orgID with a clear error (cross-org work belongs on the admin
// role, not silently disabling RLS).
func TestExecWithRetryOrgScope_EmptyOrgID(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	err = execWithRetryOrgScope(db, "", "INSERT INTO whatever VALUES ($1)", "x")
	if err == nil {
		t.Fatal("expected error for empty orgID")
	}
	if got := err.Error(); got != "execWithRetryOrgScope: orgID must be non-empty for RLS-enforced audit tables" {
		t.Errorf("unexpected error message: %q", got)
	}
}

// TestExecWithRetryOrgScope_HappyPath — BeginTx + set_config + INSERT + Commit
// all match expectations. Verifies the transaction shape is byte-correct for
// downstream RLS-enforced tables.
func TestExecWithRetryOrgScope_HappyPath(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-x").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO test_table").
		WithArgs(42).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = execWithRetryOrgScope(db, "org-x", "INSERT INTO test_table VALUES ($1)", 42)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestExecWithRetryOrgScope_BeginTxFails — when BeginTx itself errors on every
// retry, the helper exhausts retries and returns the BeginTx error (not a
// misleading "INSERT failed"). Hostile-review of #2282 flagged this path as
// uncovered.
func TestExecWithRetryOrgScope_BeginTxFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	beginErr := errors.New("simulated BeginTx failure (connection pool exhausted)")
	for i := 0; i < 3; i++ {
		mock.ExpectBegin().WillReturnError(beginErr)
	}

	err = execWithRetryOrgScope(db, "org-x", "INSERT INTO test_table VALUES ($1)", 42)
	if err == nil {
		t.Fatal("expected error after 3 BeginTx failures, got nil")
	}
	// Returned error should mention BeginTx (via WithOrgScope's "begin txn: ..." prefix),
	// not be a misleading INSERT-failed error.
	if got := err.Error(); !strings.Contains(got, "begin txn") {
		t.Errorf("expected error to mention BeginTx failure, got: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestExecWithRetryOrgScope_RetryOnFailure — when the INSERT fails on the first
// attempt, the helper retries by opening a fresh txn. This verifies the retry
// loop's tx-isolation (each retry is a clean BeginTx + set_config + INSERT +
// Commit, not a reused tx).
func TestExecWithRetryOrgScope_RetryOnFailure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// Attempt 1: INSERT errors → Rollback.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-x").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO test_table").
		WithArgs(42).
		WillReturnError(errors.New("transient DB error"))
	mock.ExpectRollback()

	// Attempt 2: clean txn, succeeds.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-x").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO test_table").
		WithArgs(42).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = execWithRetryOrgScope(db, "org-x", "INSERT INTO test_table VALUES ($1)", 42)
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
