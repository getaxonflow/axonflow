// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package policytest provides sqlmock helpers for tests that drive a real
// UnifiedPolicyEngine over a mocked database.
//
// #3048 changed the loader's read shape: static_policies is RLS-enabled, so
// loadFromDatabase now performs TWO transaction-scoped passes (SET LOCAL
// app.current_org_id per pass) — the tenant scope with tenant_id = $1 and the
// 'global' scope with tenant_id = 'global' — instead of one bare query, and
// the SELECT list carries created_at for the in-memory merge sort. Every
// sqlmock engine fixture needs the same plumbing; this package is the single
// place that encodes it so the next loader change is a one-file update.
package policytest

import (
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// LoaderCols is the loader's SELECT column list (loadFromDatabase), in scan
// order. Includes created_at (#3048 merge-sort key).
func LoaderCols() []string {
	return []string{
		"id", "policy_id", "name", "category", "tier", "pattern", "severity",
		"description", "phase", "action_request", "action_response",
		"enabled", "priority", "tenant_id", "organization_id", "metadata",
		"created_at",
	}
}

// SystemPolicyRow appends a minimal enabled system-tier policy row (the shape
// mig 010/031 seeds) to rows. The loader FAILS CLOSED when a load returns
// zero system-tier policies (ErrEmptySystemPolicySet, #3048 item 10), so
// every fixture's global pass must include at least one such row.
func SystemPolicyRow(rows *sqlmock.Rows, id, policyID, category, pattern, severity, phase, actionRequest string, priority int) *sqlmock.Rows {
	return rows.AddRow(
		id, policyID, "Test policy "+policyID, category, "system", pattern, severity,
		nil, phase, actionRequest, nil,
		true, priority, "global", nil, []byte(`{}`),
		time.Now().UTC(),
	)
}

// ExpectScopedLoad registers the sqlmock expectations for ONE loader
// loadFromDatabase call: the tenant-scope pass (returning tenantRows) then
// the 'global'-scope pass (returning globalRows), each wrapped in the
// BEGIN / SELECT set_config('app.current_org_id', …) / COMMIT transaction
// rls.WithOrgScope opens. queryRE matches the loader SELECT; pass fresh Rows
// per call (sqlmock rows are consumed).
func ExpectScopedLoad(mock sqlmock.Sqlmock, queryRE string, tenantRows, globalRows *sqlmock.Rows) {
	for _, rows := range []*sqlmock.Rows{tenantRows, globalRows} {
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_org_id'`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery(queryRE).WillReturnRows(rows)
		mock.ExpectCommit()
	}
}

// ScopedTxPlumbing registers n spare BEGIN/set_config/COMMIT/ROLLBACK
// expectation sets for UNORDERED mocks (MatchExpectationsInOrder(false))
// whose tests assert on responses rather than ExpectationsWereMet. The
// spares absorb the scoped-transaction traffic of however many WithOrgScope
// wraps the code under test opens; unconsumed spares are harmless.
func ScopedTxPlumbing(mock sqlmock.Sqlmock, n int) {
	for i := 0; i < n; i++ {
		mock.ExpectBegin()
		mock.ExpectExec(`SELECT set_config\('app\.current_org_id'`).
			WithArgs(sqlmock.AnyArg()).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		mock.ExpectRollback()
	}
}
