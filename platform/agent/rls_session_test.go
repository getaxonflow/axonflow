// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit-test the three rls package re-exports so the alias surface stays
// covered. The canonical implementations live in axonflow/platform/agent/rls
// and have their own end-to-end tests; here we only verify the re-export
// thin layer compiles, dispatches, and propagates errors.

import (
	"context"
	"database/sql"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestRlsSessionReExports_WithOrgScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("o1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	called := false
	err = WithOrgScope(context.Background(), db, "o1", func(tx *sql.Tx) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithOrgScope: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked under the wrap")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRlsSessionReExports_WithOrgAndTenantScope(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("o1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id', \$1, true\)`).
		WithArgs("t1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id', \$1, true\)`).
		WithArgs("t1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	called := false
	err = WithOrgAndTenantScope(context.Background(), db, "o1", "t1", func(tx *sql.Tx) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("WithOrgAndTenantScope: %v", err)
	}
	if !called {
		t.Fatal("fn was not invoked under the dual-key wrap")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestRlsSessionReExports_CurrentOrgIDInTx(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"current_setting"}).AddRow("o1")
	mock.ExpectQuery(`SELECT current_setting\('app.current_org_id', true\)`).
		WillReturnRows(rows)
	mock.ExpectCommit()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("db.Begin: %v", err)
	}
	got, err := CurrentOrgIDInTx(context.Background(), tx)
	if err != nil {
		t.Fatalf("CurrentOrgIDInTx: %v", err)
	}
	if got != "o1" {
		t.Errorf("want %q, got %q", "o1", got)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("tx.Commit: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
