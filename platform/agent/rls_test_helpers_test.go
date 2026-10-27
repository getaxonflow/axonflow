// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql/driver"

	"github.com/DATA-DOG/go-sqlmock"
)

// expectOrgScopedExec describes one successful rls.WithOrgScope write. Keeping
// the transaction skeleton here makes audit-writer tests assert the production
// boundary without repeating four expectations at every payload-focused test.
func expectOrgScopedExec(mock sqlmock.Sqlmock, org driver.Value, query string) *sqlmock.ExpectedExec {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	exec := mock.ExpectExec(query)
	mock.ExpectCommit()
	return exec
}

// expectOrgScopedExecError is the rollback form for a write whose SQL
// expectation is configured with WillReturnError by the caller.
func expectOrgScopedExecError(mock sqlmock.Sqlmock, org driver.Value, query string) *sqlmock.ExpectedExec {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	exec := mock.ExpectExec(query)
	mock.ExpectRollback()
	return exec
}

// expectOrgScopedQuery describes a successful transaction-scoped read.
func expectOrgScopedQuery(mock sqlmock.Sqlmock, org driver.Value, query string) *sqlmock.ExpectedQuery {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	q := mock.ExpectQuery(query)
	mock.ExpectCommit()
	return q
}

// expectOrgScopedQueryError is the rollback form for a read returning an
// error. sql.ErrNoRows is still a QueryRow Scan error and therefore rolls back.
func expectOrgScopedQueryError(mock sqlmock.Sqlmock, org driver.Value, query string) *sqlmock.ExpectedQuery {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
	q := mock.ExpectQuery(query)
	mock.ExpectRollback()
	return q
}

// expectActedPolicyVersionLookups describes the best-effort enrichment an
// acted (blocked/redacted/approval) audit row performs before its INSERT. The
// writer reads the caller partition and the global system-policy partition.
func expectActedPolicyVersionLookups(mock sqlmock.Sqlmock, org driver.Value) {
	for _, scope := range []driver.Value{org, GlobalOrgSentinel} {
		expectOrgScopedQuery(mock, scope, `SELECT policy_id, version`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(sqlmock.NewRows([]string{"policy_id", "version"}))
	}
}

func expectIndonesiaPIIDetectionEvent(mock sqlmock.Sqlmock) {
	// The persistence hook exists only in an enterprise-tagged build. The
	// untagged Community lane still exercises the same detection and audit
	// paths, but no indonesia_pii_detection_events writer is compiled there,
	// so installing an INSERT expectation would make every such test fail on a
	// database call production cannot make in that edition.
	if persistIndonesiaPIIEvents == nil {
		return
	}
	args := make([]driver.Value, 13)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	expectOrgScopedExec(mock, sqlmock.AnyArg(), "INSERT INTO indonesia_pii_detection_events").
		WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
}
