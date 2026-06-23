//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Unit tests for the UU PDP Pasal 56 cross-border transfer export path. These
// use sqlmock to exercise the real query + the verbatim surfacing contract
// without a live Postgres. After #2718 the export reads the canonical audit_logs
// table (a plain QueryContext, no withOrgScope transaction, mirrors the SEBI
// pattern). Round-trip against a real DB is covered by the DATABASE_URL-gated
// integration test and the orchestrator-package end-to-end test.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

var (
	cbStart = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cbEnd   = time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)
	cbRowTS = time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)
)

// TestQueryCrossBorderTransfers_SurfacesTransferBasisVerbatim is the core
// guarantee: pasal_56b_dpa and safeguards are both surfaced exactly as stored,
// never auto-translated to one another, so an auditor sees the Pasal 56(b)
// value recorded at decision time.
func TestQueryCrossBorderTransfers_SurfacesTransferBasisVerbatim(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}).
		AddRow("audit-101", cbRowTS, "US", "pasal_56b_dpa").
		AddRow("audit-102", cbRowTS, "SG", "safeguards")
	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-buku", cbStart, cbEnd).
		WillReturnRows(rows)

	svc := &ojkAuditExportServiceImpl{db: db}
	records, count, err := svc.queryCrossBorderTransfers(context.Background(), "org-buku", cbStart, cbEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 || len(records) != 2 {
		t.Fatalf("expected 2 records, got count=%d len=%d", count, len(records))
	}

	if records[0].TransferBasis != "pasal_56b_dpa" {
		t.Errorf("record[0].transfer_basis = %q, want pasal_56b_dpa (verbatim, no translation)", records[0].TransferBasis)
	}
	if records[1].TransferBasis != "safeguards" {
		t.Errorf("record[1].transfer_basis = %q, want safeguards (verbatim, no translation)", records[1].TransferBasis)
	}
	if records[0].ID != "audit-101" {
		t.Errorf("record[0].id = %q, want audit-101", records[0].ID)
	}
	if records[0].DataResidency != "US" || records[0].DestinationCountry != "US" {
		t.Errorf("record[0] residency/destination = %q/%q, want US/US", records[0].DataResidency, records[0].DestinationCountry)
	}
	if !records[0].Timestamp.Equal(cbRowTS) {
		t.Errorf("record[0].timestamp = %v, want %v", records[0].Timestamp, cbRowTS)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestQueryCrossBorderTransfers_Empty verifies the no-rows path returns an
// empty (non-nil) slice and zero count.
func TestQueryCrossBorderTransfers_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-empty", cbStart, cbEnd).
		WillReturnRows(sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}))

	svc := &ojkAuditExportServiceImpl{db: db}
	records, count, err := svc.queryCrossBorderTransfers(context.Background(), "org-empty", cbStart, cbEnd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
	if records == nil {
		t.Error("records must be non-nil empty slice, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestQueryCrossBorderTransfers_QueryError propagates a SELECT failure.
func TestQueryCrossBorderTransfers_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-boom", cbStart, cbEnd).
		WillReturnError(errors.New("connection reset"))

	svc := &ojkAuditExportServiceImpl{db: db}
	_, _, err = svc.queryCrossBorderTransfers(context.Background(), "org-boom", cbStart, cbEnd)
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

// TestQueryCrossBorderTransfers_ScanError surfaces a row whose timestamp cannot
// be scanned into time.Time, exercising the scan-error branch.
func TestQueryCrossBorderTransfers_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}).
		AddRow("audit-1", "not-a-timestamp", "US", "pasal_56b_dpa")
	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-scan", cbStart, cbEnd).
		WillReturnRows(rows)

	svc := &ojkAuditExportServiceImpl{db: db}
	_, _, err = svc.queryCrossBorderTransfers(context.Background(), "org-scan", cbStart, cbEnd)
	if err == nil {
		t.Fatal("expected scan error to propagate")
	}
}

// TestExportAuditData_CrossBorderRoundTrip exercises the full ExportAuditData
// switch wiring for the cross_border_transfers data type: the response Data
// must carry the record and the summary must count it.
func TestExportAuditData_CrossBorderRoundTrip(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	rows := sqlmock.NewRows([]string{"id", "timestamp", "data_residency", "transfer_basis"}).
		AddRow("audit-7", cbRowTS, "US", "pasal_56b_dpa")
	mock.ExpectQuery(`FROM audit_logs`).
		WithArgs("org-buku", cbStart, cbEnd).
		WillReturnRows(rows)

	svc := &ojkAuditExportServiceImpl{db: db}
	resp, err := svc.ExportAuditData(context.Background(), "org-buku", &OJKAuditExportRequest{
		StartDate: "2026-01-01",
		EndDate:   "2026-12-31",
		DataTypes: []OJKAuditDataType{OJKDataTypeCrossBorder},
	})
	if err != nil {
		t.Fatalf("ExportAuditData failed: %v", err)
	}
	if resp.Data == nil || len(resp.Data.CrossBorder) != 1 {
		t.Fatalf("expected 1 cross-border record in response data, got %+v", resp.Data)
	}
	if resp.Data.CrossBorder[0].TransferBasis != "pasal_56b_dpa" {
		t.Errorf("exported transfer_basis = %q, want pasal_56b_dpa", resp.Data.CrossBorder[0].TransferBasis)
	}
	if resp.Summary == nil || resp.Summary.RecordsByType["cross_border_transfers"] != 1 {
		t.Errorf("summary records_by_type[cross_border_transfers] = %v, want 1", resp.Summary)
	}
	if resp.Summary.TotalRecords != 1 {
		t.Errorf("summary total_records = %d, want 1", resp.Summary.TotalRecords)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}
