// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestVerifyHostedCustomerDataRLS(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range hostedCustomerDataTables {
		mock.ExpectQuery(`SELECT c.relrowsecurity`).WithArgs(table).
			WillReturnRows(safeHostedGuardRow())
	}
	mock.ExpectQuery(`SELECT c.relname, c.relrowsecurity`).
		WillReturnRows(hostedCensusRows())
	if err := verifyHostedCustomerDataRLS(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyHostedCustomerDataRLSRejectsUncataloguedUnsafeTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, table := range hostedCustomerDataTables {
		mock.ExpectQuery(`SELECT c.relrowsecurity`).WithArgs(table).
			WillReturnRows(safeHostedGuardRow())
	}
	mock.ExpectQuery(`SELECT c.relname, c.relrowsecurity`).
		WillReturnRows(hostedCensusRows().AddRow("future_customer_table", true, true, true, true,
			"org_id", "org_id = current_setting('app.current_org_id', true)", "true"))
	err = verifyHostedCustomerDataRLS(context.Background(), db)
	if err == nil || !strings.Contains(err.Error(), "future_customer_table") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyHostedCustomerDataRLSRejectsUnsafeTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery(`SELECT c.relrowsecurity`).WithArgs(hostedCustomerDataTables[0]).
		WillReturnRows(sqlmock.NewRows(hostedGuardColumns()).AddRow(true, false, true, true,
			"org_id", "org_id = current_setting('app.current_org_id', true)", "org_id = current_setting('app.current_org_id', true)"))
	err = verifyHostedCustomerDataRLS(context.Background(), db)
	if err == nil || !strings.Contains(err.Error(), "unsafe") {
		t.Fatalf("got %v", err)
	}
}

func hostedGuardColumns() []string {
	return []string{"enabled", "forced", "permissive", "restrictive", "key_column", "guard_using", "guard_check"}
}

func safeHostedGuardRow() *sqlmock.Rows {
	expr := "org_id = current_setting('app.current_org_id', true)"
	return sqlmock.NewRows(hostedGuardColumns()).AddRow(true, true, true, true, "org_id", expr, expr)
}

func hostedCensusRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{"table_name", "enabled", "forced", "permissive", "restrictive", "key_column", "guard_using", "guard_check"})
}

func TestValidHostedGuardExpressionRejectsTautology(t *testing.T) {
	tautology := `current_setting('app.current_org_id', true) = current_setting('app.current_org_id', true)`
	if validHostedGuardExpression("audit_logs", "org_id", tautology, tautology) {
		t.Fatal("accepted a tenant-GUC self-comparison that binds no row column")
	}
	bound := `org_id::text = current_setting('app.current_org_id', true)`
	if !validHostedGuardExpression("audit_logs", "org_id", bound, bound) {
		t.Fatal("rejected the exact direct tenant-key guard")
	}
}
