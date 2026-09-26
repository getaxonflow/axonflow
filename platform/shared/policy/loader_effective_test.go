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

// #3296 Slice 2 Step B tests: ScanEffectivePolicyRows (the single
// static_policies reader for StaticPolicyRepository.GetEffective). Step E's
// CountActive went with the quota it backed (#4249 row 5667510887).

func effectivePolicyTestCols() []string {
	return []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id", "segment_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}
}

// TestScanEffectivePolicyRows_ScansAllColumns proves every column round-trips
// through EffectivePolicyRow, including the nullable ones GetEffective's
// pre-#3296 inline scan handled (segment_id/tags/metadata/created_by/
// updated_by via sql.NullString). #3334 retired organization_id, whose
// Ptr-to-Ptr NULL scan this test also used to cover.
func TestScanEffectivePolicyRows_ScansAllColumns(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Now()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT.*FROM static_policies sp`).
		WithArgs("tenant-1", "org-1", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows(effectivePolicyTestCols()).
			AddRow(
				"pol-1", "custom_1", "Custom Policy", "pii-global", `\bSSN\b`, "high",
				"a description", "block", "tenant", 80, true,
				"tenant-1", "org-1", "finance",
				`["a","b"]`, `{"k":"v"}`, 3,
				now, now, "alice", "bob",
			))
	mock.ExpectCommit()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	rows, err := ScanEffectivePolicyRows(context.Background(), tx, "sp.tier = 'tenant'", "tenant-1", "org-1", pq.Array([]string{}))
	if err != nil {
		t.Fatalf("ScanEffectivePolicyRows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row.ID != "pol-1" || row.PolicyID != "custom_1" || row.Name != "Custom Policy" {
		t.Errorf("unexpected identity fields: %+v", row)
	}
	if row.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, want tenant-1", row.TenantID)
	}
	if !row.SegmentID.Valid || row.SegmentID.String != "finance" {
		t.Errorf("SegmentID = %+v, want finance", row.SegmentID)
	}
	if !row.Description.Valid || row.Description.String != "a description" {
		t.Errorf("Description = %+v", row.Description)
	}
	if row.Version != 3 {
		t.Errorf("Version = %d, want 3", row.Version)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestScanEffectivePolicyRows_NullOrgID proves the org_id
// NULL case (tenant-tier rows, which do not carry an organization_id) scans
// to a nil *string rather than a pointer to an empty string.
func TestScanEffectivePolicyRows_NullOrgID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	now := time.Now()
	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT.*FROM static_policies sp`).
		WillReturnRows(sqlmock.NewRows(effectivePolicyTestCols()).
			AddRow(
				"pol-2", "custom_2", "Tenant-only Policy", "pii-global", `\bSSN\b`, "high",
				nil, "block", "tenant", 80, true,
				"tenant-1", nil, nil,
				nil, nil, 1,
				now, now, nil, nil,
			))
	mock.ExpectCommit()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	rows, err := ScanEffectivePolicyRows(context.Background(), tx, "sp.tier = 'tenant'")
	if err != nil {
		t.Fatalf("ScanEffectivePolicyRows: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].OrgID.Valid {
		t.Errorf("expected OrgID NULL, got %+v", rows[0].OrgID)
	}
	if rows[0].SegmentID.Valid {
		t.Errorf("expected SegmentID NULL, got %+v", rows[0].SegmentID)
	}
}

// TestScanEffectivePolicyRows_QueryError propagates the underlying query
// error rather than silently returning an empty set — GetEffective's callers
// must see a load failure, not "zero effective policies."
func TestScanEffectivePolicyRows_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()

	mock.ExpectBegin()
	mock.ExpectQuery(`SELECT.*FROM static_policies sp`).
		WillReturnError(errTestScan)
	mock.ExpectRollback()

	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	if _, err := ScanEffectivePolicyRows(context.Background(), tx, "sp.tier = 'system'"); err == nil {
		t.Fatal("expected an error from ScanEffectivePolicyRows, got nil")
	}
	_ = tx.Rollback()
}

var errTestScan = errors.New("simulated query error")
