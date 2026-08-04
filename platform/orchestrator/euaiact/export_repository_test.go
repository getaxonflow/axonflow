// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var exportColumns = []string{
	"id", "org_id", "export_type", "format", "status", "progress",
	"file_path", "file_size", "record_count", "date_from", "date_to",
	"model_ids", "filters", "error", "requested_by", "created_at",
	"started_at", "completed_at", "download_url", "storage_type", "storage_key",
}

func sampleExportRow(id, orgID string) []driver.Value {
	now := time.Now().UTC()
	dateFrom := now.Add(-30 * 24 * time.Hour)
	dateTo := now
	startedAt := now.Add(-10 * time.Minute)
	completedAt := now.Add(-5 * time.Minute)
	return []driver.Value{
		id, orgID, string(ExportTypeFullAudit), string(ExportFormatJSON),
		string(ExportStatusCompleted), 100,
		"/exports/audit-001.json", int64(1024000), 5000,
		sql.NullTime{Time: dateFrom, Valid: true},
		sql.NullTime{Time: dateTo, Valid: true},
		pq.StringArray{"model-001", "model-002"},
		[]byte(`{"include_metadata":true}`),
		"", "admin@example.com", now,
		&startedAt, &completedAt,
		sql.NullString{String: "https://s3.example.com/export.json", Valid: true},
		sql.NullString{String: "s3", Valid: true},
		sql.NullString{String: "exports/org-001/audit-001.json", Valid: true},
	}
}

// expectOrgScope sets up the transaction preamble rls.WithOrgScope emits before
// every statement these repositories issue: BEGIN, then
// `SELECT set_config('app.current_org_id', $1, true)` as a transaction-local.
//
// It is asserted rather than skipped: the wrap is what makes these queries
// return rows at all under axonflow_app_role (the #3039 blind-read class), so a
// test that tolerated its absence would go green on a repository that reads
// nothing in production.
func expectOrgScope(mock sqlmock.Sqlmock, orgID string) {
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(`SELECT set_config('app.current_org_id', $1, true)`)).
		WithArgs(orgID).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func TestExportRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	dateFrom := now.Add(-30 * 24 * time.Hour)
	dateTo := now
	export := &Export{
		ID:          "exp-001",
		OrgID:       "org-001",
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		Progress:    0,
		DateFrom:    dateFrom,
		DateTo:      dateTo,
		ModelIDs:    []string{"model-001", "model-002"},
		Filters:     map[string]interface{}{"include_metadata": true},
		RequestedBy: "admin@example.com",
		CreatedAt:   now,
	}

	expectOrgScope(mock, export.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_exports`)).
		WithArgs(
			export.ID, export.OrgID, export.ExportType, export.Format,
			export.Status, export.Progress, export.FilePath, export.FileSize,
			export.RecordCount,
			sql.NullTime{Time: dateFrom, Valid: true},
			sql.NullTime{Time: dateTo, Valid: true},
			pq.Array(export.ModelIDs),
			sqlmock.AnyArg(), // filters JSON
			export.Error, export.RequestedBy, export.CreatedAt,
			export.StartedAt, export.CompletedAt,
			sql.NullString{}, sql.NullString{}, sql.NullString{}, // download_url, storage_type, storage_key
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Create_ZeroDates(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	export := &Export{
		ID:          "exp-002",
		OrgID:       "org-001",
		ExportType:  ExportTypeAccuracyMetrics,
		Format:      ExportFormatCSV,
		Status:      ExportStatusPending,
		RequestedBy: "admin@example.com",
		CreatedAt:   time.Now().UTC(),
	}

	expectOrgScope(mock, export.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_exports`)).
		WithArgs(
			export.ID, export.OrgID, export.ExportType, export.Format,
			export.Status, export.Progress, export.FilePath, export.FileSize,
			export.RecordCount,
			sql.NullTime{}, // date_from zero
			sql.NullTime{}, // date_to zero
			pq.Array(export.ModelIDs),
			sqlmock.AnyArg(), // filters JSON
			export.Error, export.RequestedBy, export.CreatedAt,
			export.StartedAt, export.CompletedAt,
			sql.NullString{}, sql.NullString{}, sql.NullString{}, // download_url, storage_type, storage_key
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	export := &Export{
		ID:          "exp-001",
		OrgID:       "org-001",
		ExportType:  ExportTypeFullAudit,
		Format:      ExportFormatJSON,
		Status:      ExportStatusPending,
		RequestedBy: "admin@example.com",
		CreatedAt:   time.Now().UTC(),
	}

	expectOrgScope(mock, export.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_exports`)).
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	err = repo.Create(ctx, export)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_GetByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(exportColumns).
		AddRow(sampleExportRow("exp-001", "org-001")...)

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("exp-001", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	export, err := repo.GetByID(ctx, "org-001", "exp-001")
	require.NoError(t, err)
	assert.Equal(t, "exp-001", export.ID)
	assert.Equal(t, "org-001", export.OrgID)
	assert.Equal(t, ExportTypeFullAudit, export.ExportType)
	assert.Equal(t, ExportFormatJSON, export.Format)
	assert.Equal(t, ExportStatusCompleted, export.Status)
	assert.Equal(t, 100, export.Progress)
	assert.Equal(t, "/exports/audit-001.json", export.FilePath)
	assert.Equal(t, int64(1024000), export.FileSize)
	assert.Equal(t, 5000, export.RecordCount)
	assert.False(t, export.DateFrom.IsZero())
	assert.False(t, export.DateTo.IsZero())
	assert.Len(t, export.ModelIDs, 2)
	assert.Equal(t, "model-001", export.ModelIDs[0])
	assert.NotEmpty(t, export.Filters)
	assert.Equal(t, "admin@example.com", export.RequestedBy)
	assert.NotNil(t, export.StartedAt)
	assert.NotNil(t, export.CompletedAt)
	assert.Equal(t, "https://s3.example.com/export.json", export.DownloadURL)
	assert.Equal(t, "s3", export.StorageType)
	assert.Equal(t, "exports/org-001/audit-001.json", export.StorageKey)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_GetByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	// Post-#3241 a miss is ErrExportNotFound, not (nil, nil): the handler needs
	// a value it can map to 404, and "no rows" and "another organization's row"
	// must be the SAME answer so the endpoint is not an existence oracle.
	export, err := repo.GetByID(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrExportNotFound)
	assert.Nil(t, export)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_GetByID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("exp-001", "org-001").
		WillReturnError(fmt.Errorf("connection lost"))
	mock.ExpectRollback()

	export, err := repo.GetByID(ctx, "org-001", "exp-001")
	assert.Nil(t, export)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	// Count query
	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM euaiact_exports WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Data query
	dataRows := sqlmock.NewRows(exportColumns).
		AddRow(sampleExportRow("exp-001", "org-001")...).
		AddRow(sampleExportRow("exp-002", "org-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports`)).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	exports, total, err := repo.List(ctx, "org-001", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, exports, 2)
	assert.Equal(t, "exp-001", exports[0].ID)
	assert.Equal(t, "exp-002", exports[1].ID)
	// Verify download_url, storage_type, storage_key were scanned
	assert.NotEmpty(t, exports[0].DownloadURL)
	assert.NotEmpty(t, exports[0].StorageType)
	assert.NotEmpty(t, exports[0].StorageKey)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_List_DefaultLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM euaiact_exports WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports`)).
		WithArgs("org-001", DefaultListLimit, 0).
		WillReturnRows(sqlmock.NewRows(exportColumns))
	mock.ExpectCommit()

	exports, total, err := repo.List(ctx, "org-001", 0, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, exports)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_List_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM euaiact_exports WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table not found"))
	mock.ExpectRollback()

	_, _, err = repo.List(ctx, "org-001", 10, 0)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_List_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM euaiact_exports WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports`)).
		WithArgs("org-001", 10, 0).
		WillReturnError(fmt.Errorf("query timeout"))
	mock.ExpectRollback()

	_, _, err = repo.List(ctx, "org-001", 10, 0)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	completedAt := now
	export := &Export{
		ID:          "exp-001",
		OrgID:       "org-001",
		Status:      ExportStatusCompleted,
		Progress:    100,
		FilePath:    "/exports/audit-001.json",
		FileSize:    1024000,
		RecordCount: 5000,
		CompletedAt: &completedAt,
		DownloadURL: "https://s3.example.com/export.json",
		StorageType: "s3",
		StorageKey:  "exports/org-001/audit-001.json",
	}

	expectOrgScope(mock, export.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE euaiact_exports`)).
		WithArgs(
			export.ID, export.Status, export.Progress, export.FilePath, export.FileSize,
			export.RecordCount, export.Error, export.StartedAt, export.CompletedAt,
			export.DownloadURL, export.StorageType, export.StorageKey, export.OrgID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, export)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Update_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	export := &Export{
		ID:     "exp-001",
		OrgID:  "org-001",
		Status: ExportStatusFailed,
		Error:  "processing failed",
	}

	expectOrgScope(mock, export.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE euaiact_exports`)).
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	err = repo.Update(ctx, export)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("exp-001", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "exp-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestExportRepository_Delete_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("exp-001", "org-001").
		WillReturnError(fmt.Errorf("database error"))
	mock.ExpectRollback()

	err = repo.Delete(ctx, "org-001", "exp-001")
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestNullTime_Helper(t *testing.T) {
	// Test zero time
	result := nullTime(time.Time{})
	assert.False(t, result.Valid)

	// Test valid time
	now := time.Now().UTC()
	result = nullTime(now)
	assert.True(t, result.Valid)
	assert.Equal(t, now, result.Time)
}

func TestExportRepository_GetByID_NullOptionalFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	rows := sqlmock.NewRows(exportColumns).
		AddRow(
			"exp-minimal", "org-001", string(ExportTypePolicyViolations), string(ExportFormatCSV),
			string(ExportStatusPending), 0,
			"", int64(0), 0,
			sql.NullTime{},
			sql.NullTime{},
			pq.StringArray{},
			[]byte(`{}`),
			"", "admin@example.com", now,
			nil, nil,
			sql.NullString{},
			sql.NullString{},
			sql.NullString{},
		)

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_exports WHERE id = $1 AND org_id = $2`)).
		WithArgs("exp-minimal", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	export, err := repo.GetByID(ctx, "org-001", "exp-minimal")
	require.NoError(t, err)
	assert.Equal(t, "exp-minimal", export.ID)
	assert.True(t, export.DateFrom.IsZero())
	assert.True(t, export.DateTo.IsZero())
	assert.Empty(t, export.ModelIDs)
	assert.Empty(t, export.DownloadURL)
	assert.Empty(t, export.StorageType)
	assert.Empty(t, export.StorageKey)
	assert.Nil(t, export.StartedAt)
	assert.Nil(t, export.CompletedAt)
	assert.NoError(t, mock.ExpectationsWereMet())
}
