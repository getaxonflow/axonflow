// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// #3319/#3293: RefreshDynamicPolicies and CountAllDynamicPolicies are the
// relocated verdict-path dynamic_policies reads
// DatabaseDynamicPolicyEngine.refreshPolicies / seedDefaultData
// (platform/orchestrator/db_dynamic_policies.go) now call instead of
// issuing "FROM dynamic_policies" themselves.

func dynamicPolicyTestColsWithSegment() []string {
	return []string{
		"id", "name", "description", "conditions", "actions", "tenant_id",
		"org_id", "priority", "policy_id", "policy_type", "category",
		"risk_level", "allow_override", "created_at", "segment_id",
	}
}

func dynamicPolicyTestColsWithoutSegment() []string {
	return []string{
		"id", "name", "description", "conditions", "actions", "tenant_id",
		"org_id", "priority", "policy_id", "policy_type", "category",
		"risk_level", "allow_override", "created_at",
	}
}

// TestRefreshDynamicPolicies_WithSegment_ScansAllColumns proves every column
// (including segment_id, ADR-060 #2989 P3b) round-trips through
// DynamicPolicyRow.
func TestRefreshDynamicPolicies_WithSegment_ScansAllColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	wantCreatedAt := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	mock.ExpectQuery("FROM dynamic_policies").
		WillReturnRows(sqlmock.NewRows(dynamicPolicyTestColsWithSegment()).
			AddRow("id-1", "policy one", "desc", `[{"field":"x"}]`, `[{"type":"block"}]`,
				"tenant-1", "org-1", 10, "pol-1", "content", "custom", "high", true, wantCreatedAt, "seg-1"))

	rows, err := RefreshDynamicPolicies(context.Background(), db, true)
	if err != nil {
		t.Fatalf("RefreshDynamicPolicies: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	got := rows[0]
	if got.ID != "id-1" || got.PolicyID != "pol-1" || got.Name != "policy one" {
		t.Errorf("unexpected identity fields: %+v", got)
	}
	if !got.OrgID.Valid || got.OrgID.String != "org-1" {
		t.Errorf("expected org_id = org-1, got %+v", got.OrgID)
	}
	if !got.SegmentID.Valid || got.SegmentID.String != "seg-1" {
		t.Errorf("expected segment_id = seg-1, got %+v", got.SegmentID)
	}
	if !got.AllowOverride || got.RiskLevel != "high" {
		t.Errorf("expected allow_override=true risk_level=high, got %+v", got)
	}
	if !got.CreatedAt.Valid || !got.CreatedAt.Time.Equal(wantCreatedAt) {
		t.Errorf("expected created_at = %v, got %+v", wantCreatedAt, got.CreatedAt)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestRefreshDynamicPolicies_WithoutSegment_LeavesSegmentIDInvalid covers the
// segment-less retry shape (pre-migration-159): SegmentID must be the zero
// value, not accidentally populated from a stale scan.
func TestRefreshDynamicPolicies_WithoutSegment_LeavesSegmentIDInvalid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("FROM dynamic_policies").
		WillReturnRows(sqlmock.NewRows(dynamicPolicyTestColsWithoutSegment()).
			AddRow("id-2", "policy two", "", `[]`, `[]`, "tenant-2", "org-2", 5, "pol-2", "content", "", "medium", false, time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)))

	rows, err := RefreshDynamicPolicies(context.Background(), db, false)
	if err != nil {
		t.Fatalf("RefreshDynamicPolicies: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].SegmentID.Valid {
		t.Errorf("expected SegmentID.Valid=false on a segment-less query, got %+v", rows[0].SegmentID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestRefreshDynamicPolicies_QueryError_UnwrappedForMissingColumnRetry proves
// a query-time failure (e.g. Postgres 42703 "column does not exist") comes
// back UNWRAPPED, so the caller's errors.As(err, *pq.Error) /
// isMissingColumnError check (platform/orchestrator/db_dynamic_policies.go,
// segment_column_probe.go) still works after the SQL moved into this
// package.
func TestRefreshDynamicPolicies_QueryError_UnwrappedForMissingColumnRetry(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("FROM dynamic_policies").
		WillReturnError(&pq.Error{Code: "42703", Message: `column "segment_id" does not exist`})

	_, err = RefreshDynamicPolicies(context.Background(), db, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) {
		t.Fatalf("expected the raw *pq.Error to be recoverable via errors.As, got %T: %v", err, err)
	}
	if pqErr.Code != "42703" {
		t.Errorf("expected SQLSTATE 42703, got %v", pqErr.Code)
	}
	var riErr *RowIterationError
	if errors.As(err, &riErr) {
		t.Fatal("a query-time failure must not be classified as a RowIterationError")
	}
}

// TestRefreshDynamicPolicies_RowIterationError_DistinguishableFromQueryError
// proves a rows.Err() failure AFTER a successful Query comes back wrapped in
// RowIterationError, so DatabaseDynamicPolicyEngine.refreshPolicies can
// route it to reasonRowIterationFailed instead of reasonQueryFailed (two
// distinct axonflow_policy_refresh_failures_total label values).
func TestRefreshDynamicPolicies_RowIterationError_DistinguishableFromQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	rowErr := errors.New("row decode exploded")
	mock.ExpectQuery("FROM dynamic_policies").
		WillReturnRows(sqlmock.NewRows(dynamicPolicyTestColsWithSegment()).
			AddRow("id-1", "policy one", "", `[]`, `[]`, "tenant-1", "org-1", 1, "pol-1", "content", "", "medium", false, nil, nil).
			RowError(0, rowErr))

	_, err = RefreshDynamicPolicies(context.Background(), db, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	var riErr *RowIterationError
	if !errors.As(err, &riErr) {
		t.Fatalf("expected a *RowIterationError, got %T: %v", err, err)
	}
	if !errors.Is(riErr.Unwrap(), rowErr) && riErr.Unwrap().Error() != rowErr.Error() {
		t.Errorf("expected Unwrap() to surface the underlying rows.Err(), got %v", riErr.Unwrap())
	}
}

// TestCountAllDynamicPolicies_Success / _Error cover the orchestrator's
// boot-time seed-check read (seedDefaultData): an unscoped, all-tenants
// COUNT(*) with no WHERE clause and no rls.WithOrgScope wrap — the caller is
// responsible for passing a BYPASSRLS connection (see the function's doc).
func TestCountAllDynamicPolicies_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(7))

	count, err := CountAllDynamicPolicies(context.Background(), db)
	if err != nil {
		t.Fatalf("CountAllDynamicPolicies: %v", err)
	}
	if count != 7 {
		t.Errorf("expected count=7, got %d", count)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

func TestCountAllDynamicPolicies_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM dynamic_policies").
		WillReturnError(errors.New("connection reset"))

	if _, err := CountAllDynamicPolicies(context.Background(), db); err == nil {
		t.Fatal("expected an error")
	}
}
