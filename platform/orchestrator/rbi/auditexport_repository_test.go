// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditExportColumns defines the 27 columns returned by SELECT queries in the audit export repository.
var auditExportColumns = []string{
	"id", "org_id", "export_type", "format", "start_date", "end_date",
	"system_ids", "risk_categories", "include_archived",
	"status", "error_message", "requested_by", "requested_by_email", "purpose",
	"started_at", "completed_at", "file_path", "file_size_bytes", "file_checksum",
	"record_count", "summary", "expires_at",
	"download_url", "storage_type", "storage_key",
	"created_at", "updated_at",
}

// newTestAuditExport returns a fully populated AuditExport for testing.
func newTestAuditExport() *AuditExport {
	now := time.Now().UTC().Truncate(time.Microsecond)
	startDate := now.Add(-24 * time.Hour)
	endDate := now
	startedAt := now.Add(-1 * time.Hour)
	completedAt := now.Add(-30 * time.Minute)
	expiresAt := now.Add(7 * 24 * time.Hour)

	return &AuditExport{
		ID:               "export-001",
		OrgID:            "org-001",
		ExportType:       AuditExportTypeFull,
		Format:           AuditExportFormatJSON,
		StartDate:        &startDate,
		EndDate:          &endDate,
		SystemIDs:        []string{"sys-1", "sys-2"},
		RiskCategories:   []string{"high", "medium"},
		IncludeArchived:  true,
		Status:           AuditExportStatusCompleted,
		ErrorMessage:     "",
		RequestedBy:      "user-001",
		RequestedByEmail: "user@example.com",
		Purpose:          "Quarterly compliance audit",
		StartedAt:        &startedAt,
		CompletedAt:      &completedAt,
		FilePath:         "/exports/org-001/export-001.json",
		FileSizeBytes:    1048576,
		FileChecksum:     "sha256:abc123def456",
		RecordCount:      500,
		Summary: &AuditExportSummary{
			TotalSystems:     10,
			TotalValidations: 5,
			TotalIncidents:   2,
		},
		ExpiresAt:   &expiresAt,
		DownloadURL: "https://storage.example.com/export-001.json",
		StorageType: "s3",
		StorageKey:  "exports/org-001/export-001.json",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// addAuditExportRow adds a fully populated row to the sqlmock rows builder.
func addAuditExportRow(rows *sqlmock.Rows, export *AuditExport) *sqlmock.Rows {
	var startDate, endDate, startedAt, completedAt, expiresAt interface{}
	if export.StartDate != nil {
		startDate = *export.StartDate
	}
	if export.EndDate != nil {
		endDate = *export.EndDate
	}
	if export.StartedAt != nil {
		startedAt = *export.StartedAt
	}
	if export.CompletedAt != nil {
		completedAt = *export.CompletedAt
	}
	if export.ExpiresAt != nil {
		expiresAt = *export.ExpiresAt
	}

	var errorMsg, requestedBy, requestedByEmail, purpose interface{}
	var filePath, fileChecksum, downloadURL, storageType, storageKey interface{}

	if export.ErrorMessage != "" {
		errorMsg = export.ErrorMessage
	}
	if export.RequestedBy != "" {
		requestedBy = export.RequestedBy
	}
	if export.RequestedByEmail != "" {
		requestedByEmail = export.RequestedByEmail
	}
	if export.Purpose != "" {
		purpose = export.Purpose
	}
	if export.FilePath != "" {
		filePath = export.FilePath
	}
	if export.FileChecksum != "" {
		fileChecksum = export.FileChecksum
	}
	if export.DownloadURL != "" {
		downloadURL = export.DownloadURL
	}
	if export.StorageType != "" {
		storageType = export.StorageType
	}
	if export.StorageKey != "" {
		storageKey = export.StorageKey
	}

	summaryJSON := []byte("{}")
	if export.Summary != nil {
		summaryJSON = []byte(`{"total_systems":10,"total_validations":5,"total_incidents":2}`)
	}

	return rows.AddRow(
		export.ID, export.OrgID, string(export.ExportType), string(export.Format),
		startDate, endDate,
		pq.Array(export.SystemIDs), pq.Array(export.RiskCategories),
		export.IncludeArchived,
		string(export.Status), errorMsg, requestedBy, requestedByEmail, purpose,
		startedAt, completedAt, filePath, export.FileSizeBytes, fileChecksum,
		export.RecordCount, summaryJSON, expiresAt,
		downloadURL, storageType, storageKey,
		export.CreatedAt, export.UpdatedAt,
	)
}

func TestNewPostgresAuditExportRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	require.NotNil(t, repo)
	assert.Equal(t, db, repo.db)
}

func TestPostgresAuditExportRepository_Create(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()
	export.ID = "pre-set-id"

	insertQuery := `
		INSERT INTO rbi_audit_exports (
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
			$15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27
		)
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(insertQuery)).
		WithArgs(
			export.ID,
			export.OrgID,
			string(export.ExportType),
			string(export.Format),
			sqlmock.AnyArg(), // start_date (NullTime)
			sqlmock.AnyArg(), // end_date (NullTime)
			sqlmock.AnyArg(), // system_ids (pq.Array)
			sqlmock.AnyArg(), // risk_categories (pq.Array)
			export.IncludeArchived,
			string(export.Status),
			sqlmock.AnyArg(), // error_message (NullString)
			sqlmock.AnyArg(), // requested_by (NullString)
			sqlmock.AnyArg(), // requested_by_email (NullString)
			sqlmock.AnyArg(), // purpose (NullString)
			sqlmock.AnyArg(), // started_at (NullTime)
			sqlmock.AnyArg(), // completed_at (NullTime)
			sqlmock.AnyArg(), // file_path (NullString)
			export.FileSizeBytes,
			sqlmock.AnyArg(), // file_checksum (NullString)
			export.RecordCount,
			sqlmock.AnyArg(), // summary (JSON bytes)
			sqlmock.AnyArg(), // expires_at (NullTime)
			sqlmock.AnyArg(), // download_url (NullString)
			sqlmock.AnyArg(), // storage_type (NullString)
			sqlmock.AnyArg(), // storage_key (NullString)
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	require.NoError(t, err)
	assert.Equal(t, "pre-set-id", export.ID)
	assert.False(t, export.CreatedAt.IsZero())
	assert.False(t, export.UpdatedAt.IsZero())
	assert.Equal(t, export.CreatedAt, export.UpdatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Create_GeneratesID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()
	export.ID = "" // Empty ID should trigger UUID generation

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_audit_exports").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	require.NoError(t, err)
	assert.NotEmpty(t, export.ID, "ID should be auto-generated when empty")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Create_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_audit_exports").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("connection refused"))

	mock.ExpectRollback()

	err = repo.Create(ctx, export)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create audit export")
	assert.Contains(t, err.Error(), "connection refused")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	rows := sqlmock.NewRows(auditExportColumns)
	addAuditExportRow(rows, export)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs(export.ID, export.OrgID).
		WillReturnRows(rows)

	mock.ExpectCommit()

	result, err := repo.Get(ctx, export.OrgID, export.ID)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, export.ID, result.ID)
	assert.Equal(t, export.OrgID, result.OrgID)
	assert.Equal(t, export.ExportType, result.ExportType)
	assert.Equal(t, export.Format, result.Format)
	assert.NotNil(t, result.StartDate)
	assert.NotNil(t, result.EndDate)
	assert.Equal(t, export.SystemIDs, result.SystemIDs)
	assert.Equal(t, export.RiskCategories, result.RiskCategories)
	assert.Equal(t, export.IncludeArchived, result.IncludeArchived)
	assert.Equal(t, export.Status, result.Status)
	assert.Equal(t, export.RequestedBy, result.RequestedBy)
	assert.Equal(t, export.RequestedByEmail, result.RequestedByEmail)
	assert.Equal(t, export.Purpose, result.Purpose)
	assert.NotNil(t, result.StartedAt)
	assert.NotNil(t, result.CompletedAt)
	assert.Equal(t, export.FilePath, result.FilePath)
	assert.Equal(t, export.FileSizeBytes, result.FileSizeBytes)
	assert.Equal(t, export.FileChecksum, result.FileChecksum)
	assert.Equal(t, export.RecordCount, result.RecordCount)
	assert.NotNil(t, result.Summary)
	assert.NotNil(t, result.ExpiresAt)
	assert.Equal(t, export.DownloadURL, result.DownloadURL)
	assert.Equal(t, export.StorageType, result.StorageType)
	assert.Equal(t, export.StorageKey, result.StorageKey)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get_NullableFieldsNil(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"export-002", "org-001", "incidents", "csv",
		nil, nil, // start_date, end_date nil
		pq.Array([]string{}), pq.Array([]string{}),
		false,
		"pending", nil, nil, nil, nil, // error_message, requested_by, requested_by_email, purpose nil
		nil, nil, nil, int64(0), nil, // started_at, completed_at, file_path, file_size_bytes, file_checksum nil
		0, []byte("{}"), nil, // record_count, summary empty, expires_at nil
		nil, nil, nil, // download_url, storage_type, storage_key nil
		now, now,
	)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("export-002", "org-001").
		WillReturnRows(rows)

	mock.ExpectCommit()

	result, err := repo.Get(ctx, "org-001", "export-002")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "export-002", result.ID)
	assert.Nil(t, result.StartDate)
	assert.Nil(t, result.EndDate)
	assert.Empty(t, result.ErrorMessage)
	assert.Empty(t, result.RequestedBy)
	assert.Empty(t, result.RequestedByEmail)
	assert.Empty(t, result.Purpose)
	assert.Nil(t, result.StartedAt)
	assert.Nil(t, result.CompletedAt)
	assert.Empty(t, result.FilePath)
	assert.Empty(t, result.FileChecksum)
	assert.Nil(t, result.ExpiresAt)
	assert.Empty(t, result.DownloadURL)
	assert.Empty(t, result.StorageType)
	assert.Empty(t, result.StorageKey)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("nonexistent-id", "org-001").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectRollback()

	result, err := repo.Get(ctx, "org-001", "nonexistent-id")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditExportNotFound))

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("export-001", "org-001").
		WillReturnError(fmt.Errorf("database connection lost"))

	mock.ExpectRollback()

	result, err := repo.Get(ctx, "org-001", "export-001")
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to scan audit export")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()

	// Default params: no filters, limit defaults to 50
	params := &ListAuditExportsParams{}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows := sqlmock.NewRows(auditExportColumns)
	addAuditExportRow(rows, export)

	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", 50, 0).
		WillReturnRows(rows)

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, results, 1)
	assert.Equal(t, export.ID, results[0].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", 50, 0).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	startDate := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	endDate := time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)
	params := &ListAuditExportsParams{
		ExportType: "full",
		Status:     "completed",
		StartDate:  &startDate,
		EndDate:    &endDate,
		Limit:      25,
		Offset:     10,
	}

	// With all four filters, the WHERE clause has 5 conditions and args $1..$5
	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1 AND export_type = $2 AND status = $3 AND created_at >= $4 AND created_at <= $5"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001", "full", "completed", startDate, endDate).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	listQuery := fmt.Sprintf(`
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1 AND export_type = $2 AND status = $3 AND created_at >= $4 AND created_at <= $5
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, 6, 7)

	export := newTestAuditExport()
	rows := sqlmock.NewRows(auditExportColumns)
	addAuditExportRow(rows, export)

	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", "full", "completed", startDate, endDate, 25, 10).
		WillReturnRows(rows)

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Len(t, results, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_LimitClamping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	// Limit > 100 should be clamped to 100
	params := &ListAuditExportsParams{
		Limit: 500,
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", 100, 0). // 500 clamped to 100
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	params := &ListAuditExportsParams{}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("connection timeout"))

	mock.ExpectRollback()

	results, total, err := repo.List(ctx, "org-001", params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to count audit exports")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	params := &ListAuditExportsParams{}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", 50, 0).
		WillReturnError(fmt.Errorf("query execution failed"))

	mock.ExpectRollback()

	results, total, err := repo.List(ctx, "org-001", params)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list audit exports")
	assert.Nil(t, results)
	assert.Equal(t, 0, total)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_WithExportTypeFilterOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	params := &ListAuditExportsParams{
		ExportType: "incidents",
		Limit:      10,
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1 AND export_type = $2"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001", "incidents").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1 AND export_type = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", "incidents", 10, 0).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_WithStatusFilterOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	params := &ListAuditExportsParams{
		Status: "pending",
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1 AND status = $2"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001", "pending").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1 AND status = $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`

	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"export-a", "org-001", "full", "json",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false,
			"pending", nil, nil, nil, nil,
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now, now,
		).
		AddRow(
			"export-b", "org-001", "incidents", "csv",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false,
			"pending", nil, nil, nil, nil,
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now, now,
		)

	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", "pending", 50, 0).
		WillReturnRows(rows)

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, results, 2)
	assert.Equal(t, "export-a", results[0].ID)
	assert.Equal(t, "export-b", results[1].ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Update(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()

	updateQuery := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(updateQuery)).
		WithArgs(
			export.ID,
			export.OrgID,
			string(export.Status),
			sqlmock.AnyArg(), // error_message
			sqlmock.AnyArg(), // started_at
			sqlmock.AnyArg(), // completed_at
			sqlmock.AnyArg(), // file_path
			export.FileSizeBytes,
			sqlmock.AnyArg(), // file_checksum
			export.RecordCount,
			sqlmock.AnyArg(), // summary JSON
			sqlmock.AnyArg(), // expires_at
			sqlmock.AnyArg(), // download_url
			sqlmock.AnyArg(), // storage_type
			sqlmock.AnyArg(), // storage_key
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Update(ctx, export)
	require.NoError(t, err)
	assert.False(t, export.UpdatedAt.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()
	export.ID = "nonexistent-id"

	updateQuery := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(updateQuery)).
		WithArgs(
			export.ID,
			export.OrgID,
			string(export.Status),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), export.FileSizeBytes, sqlmock.AnyArg(),
			export.RecordCount, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows affected

	mock.ExpectCommit()

	err = repo.Update(ctx, export)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditExportNotFound))

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Update_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := newTestAuditExport()

	updateQuery := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(updateQuery)).
		WithArgs(
			export.ID,
			export.OrgID,
			string(export.Status),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), export.FileSizeBytes, sqlmock.AnyArg(),
			export.RecordCount, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("deadlock detected"))

	mock.ExpectRollback()

	err = repo.Update(ctx, export)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update audit export")
	assert.Contains(t, err.Error(), "deadlock detected")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Delete(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	deleteQuery := "DELETE FROM rbi_audit_exports WHERE id = $1 AND org_id = $2"

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(deleteQuery)).
		WithArgs("export-001", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "export-001")
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	deleteQuery := "DELETE FROM rbi_audit_exports WHERE id = $1 AND org_id = $2"

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(deleteQuery)).
		WithArgs("nonexistent-id", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows affected

	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "nonexistent-id")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrAuditExportNotFound))

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Delete_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	deleteQuery := "DELETE FROM rbi_audit_exports WHERE id = $1 AND org_id = $2"

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(deleteQuery)).
		WithArgs("export-001", "org-001").
		WillReturnError(fmt.Errorf("permission denied"))

	mock.ExpectRollback()

	err = repo.Delete(ctx, "org-001", "export-001")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete audit export")
	assert.Contains(t, err.Error(), "permission denied")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	pendingQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 10
	`

	now := time.Now().UTC().Truncate(time.Microsecond)
	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"pending-1", "org-001", "full", "json",
			nil, nil,
			pq.Array([]string{"sys-1"}), pq.Array([]string{"high"}),
			false,
			"pending", nil, "user-1", "user1@example.com", "Compliance review",
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now.Add(-2*time.Hour), now.Add(-2*time.Hour),
		).
		AddRow(
			"pending-2", "org-002", "incidents", "csv",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false,
			"pending", nil, "user-2", nil, nil,
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now.Add(-1*time.Hour), now.Add(-1*time.Hour),
		)

	mock.ExpectQuery(regexp.QuoteMeta(pendingQuery)).
		WillReturnRows(rows)

	results, err := repo.GetPending(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2)
	assert.Equal(t, "pending-1", results[0].ID)
	assert.Equal(t, "org-001", results[0].OrgID)
	assert.Equal(t, AuditExportStatusPending, results[0].Status)
	assert.Equal(t, "user-1", results[0].RequestedBy)
	assert.Equal(t, "pending-2", results[1].ID)
	assert.Equal(t, "org-002", results[1].OrgID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetPending_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	pendingQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 10
	`

	mock.ExpectQuery(regexp.QuoteMeta(pendingQuery)).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	results, err := repo.GetPending(ctx)
	require.NoError(t, err)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetPending_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	pendingQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 10
	`

	mock.ExpectQuery(regexp.QuoteMeta(pendingQuery)).
		WillReturnError(fmt.Errorf("table does not exist"))

	results, err := repo.GetPending(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get pending exports")
	assert.Nil(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	expiredQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE expires_at < NOW() AND status = 'completed'
		ORDER BY expires_at ASC
	`

	now := time.Now().UTC().Truncate(time.Microsecond)
	expiredAt := now.Add(-24 * time.Hour)
	startedAt := now.Add(-72 * time.Hour)
	completedAt := now.Add(-71 * time.Hour)

	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"expired-1", "org-001", "full", "json",
			now.Add(-30*24*time.Hour), now.Add(-1*24*time.Hour),
			pq.Array([]string{"sys-1", "sys-2"}), pq.Array([]string{"high"}),
			true,
			"completed", nil, "admin", "admin@example.com", "Monthly audit",
			startedAt, completedAt,
			"/exports/expired-1.json", int64(2048000), "sha256:expired123",
			250, []byte(`{"total_systems":5}`), expiredAt,
			"https://s3.example.com/expired-1.json", "s3", "exports/expired-1.json",
			now.Add(-72*time.Hour), now.Add(-71*time.Hour),
		)

	mock.ExpectQuery(regexp.QuoteMeta(expiredQuery)).
		WillReturnRows(rows)

	results, err := repo.GetExpired(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "expired-1", results[0].ID)
	assert.Equal(t, "org-001", results[0].OrgID)
	assert.Equal(t, AuditExportTypeFull, results[0].ExportType)
	assert.Equal(t, AuditExportFormatJSON, results[0].Format)
	assert.Equal(t, AuditExportStatusCompleted, results[0].Status)
	assert.NotNil(t, results[0].StartDate)
	assert.NotNil(t, results[0].EndDate)
	assert.Equal(t, []string{"sys-1", "sys-2"}, results[0].SystemIDs)
	assert.Equal(t, []string{"high"}, results[0].RiskCategories)
	assert.True(t, results[0].IncludeArchived)
	assert.Equal(t, "admin", results[0].RequestedBy)
	assert.Equal(t, "admin@example.com", results[0].RequestedByEmail)
	assert.Equal(t, "Monthly audit", results[0].Purpose)
	assert.NotNil(t, results[0].StartedAt)
	assert.NotNil(t, results[0].CompletedAt)
	assert.Equal(t, "/exports/expired-1.json", results[0].FilePath)
	assert.Equal(t, int64(2048000), results[0].FileSizeBytes)
	assert.Equal(t, "sha256:expired123", results[0].FileChecksum)
	assert.Equal(t, 250, results[0].RecordCount)
	assert.NotNil(t, results[0].Summary)
	assert.NotNil(t, results[0].ExpiresAt)
	assert.Equal(t, "https://s3.example.com/expired-1.json", results[0].DownloadURL)
	assert.Equal(t, "s3", results[0].StorageType)
	assert.Equal(t, "exports/expired-1.json", results[0].StorageKey)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetExpired_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	expiredQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE expires_at < NOW() AND status = 'completed'
		ORDER BY expires_at ASC
	`

	mock.ExpectQuery(regexp.QuoteMeta(expiredQuery)).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	results, err := repo.GetExpired(ctx)
	require.NoError(t, err)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetExpired_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	expiredQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE expires_at < NOW() AND status = 'completed'
		ORDER BY expires_at ASC
	`

	mock.ExpectQuery(regexp.QuoteMeta(expiredQuery)).
		WillReturnError(fmt.Errorf("disk I/O error"))

	results, err := repo.GetExpired(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get expired exports")
	assert.Nil(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Create_NilSummary(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := &AuditExport{
		ID:         "export-nil-summary",
		OrgID:      "org-001",
		ExportType: AuditExportTypeIncidents,
		Format:     AuditExportFormatCSV,
		Status:     AuditExportStatusPending,
		Summary:    nil,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_audit_exports").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Update_NilSummary(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := &AuditExport{
		ID:      "export-nil-summary",
		OrgID:   "org-001",
		Status:  AuditExportStatusProcessing,
		Summary: nil,
	}

	updateQuery := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(updateQuery)).
		WithArgs(
			export.ID, export.OrgID,
			string(export.Status),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), int64(0), sqlmock.AnyArg(),
			0, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Update(ctx, export)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get_SummaryDeserialization(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	summaryJSON := []byte(`{"total_systems":15,"total_validations":8,"total_incidents":3,"total_kill_switches":1,"total_reports":4}`)

	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"export-summary", "org-001", "comprehensive", "json",
		nil, nil,
		pq.Array([]string{}), pq.Array([]string{}),
		false,
		"completed", nil, nil, nil, nil,
		nil, nil, nil, int64(0), nil,
		0, summaryJSON, nil,
		nil, nil, nil,
		now, now,
	)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("export-summary", "org-001").
		WillReturnRows(rows)

	mock.ExpectCommit()

	result, err := repo.Get(ctx, "org-001", "export-summary")
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Summary)
	assert.Equal(t, 15, result.Summary.TotalSystems)
	assert.Equal(t, 8, result.Summary.TotalValidations)
	assert.Equal(t, 3, result.Summary.TotalIncidents)
	assert.Equal(t, 1, result.Summary.TotalKillSwitches)
	assert.Equal(t, 4, result.Summary.TotalReports)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Get_EmptySummary(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)

	selectQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE id = $1 AND org_id = $2
	`

	// Empty summary JSON (zero-length byte slice)
	rows := sqlmock.NewRows(auditExportColumns).AddRow(
		"export-empty-sum", "org-001", "systems", "csv",
		nil, nil,
		pq.Array([]string{}), pq.Array([]string{}),
		false,
		"pending", nil, nil, nil, nil,
		nil, nil, nil, int64(0), nil,
		0, []byte{}, nil,
		nil, nil, nil,
		now, now,
	)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(selectQuery)).
		WithArgs("export-empty-sum", "org-001").
		WillReturnRows(rows)

	mock.ExpectCommit()

	result, err := repo.Get(ctx, "org-001", "export-empty-sum")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.Summary)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_MultipleResults(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)

	params := &ListAuditExportsParams{
		Limit:  10,
		Offset: 0,
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"export-1", "org-001", "full", "json",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false, "completed", nil, nil, nil, nil,
			nil, nil, nil, int64(1024), nil,
			100, []byte("{}"), nil,
			nil, nil, nil,
			now.Add(-3*time.Hour), now.Add(-3*time.Hour),
		).
		AddRow(
			"export-2", "org-001", "incidents", "csv",
			nil, nil,
			pq.Array([]string{"sys-1"}), pq.Array([]string{"high", "medium"}),
			true, "processing", nil, nil, nil, nil,
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now.Add(-2*time.Hour), now.Add(-2*time.Hour),
		).
		AddRow(
			"export-3", "org-001", "systems", "json",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false, "pending", nil, nil, nil, nil,
			nil, nil, nil, int64(0), nil,
			0, []byte("{}"), nil,
			nil, nil, nil,
			now.Add(-1*time.Hour), now.Add(-1*time.Hour),
		)

	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", 10, 0).
		WillReturnRows(rows)

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Len(t, results, 3)
	assert.Equal(t, "export-1", results[0].ID)
	assert.Equal(t, AuditExportStatusCompleted, results[0].Status)
	assert.Equal(t, "export-2", results[1].ID)
	assert.Equal(t, AuditExportStatusProcessing, results[1].Status)
	assert.Equal(t, []string{"sys-1"}, results[1].SystemIDs)
	assert.Equal(t, []string{"high", "medium"}, results[1].RiskCategories)
	assert.True(t, results[1].IncludeArchived)
	assert.Equal(t, "export-3", results[2].ID)
	assert.Equal(t, AuditExportStatusPending, results[2].Status)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetPending_WithMultipleRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	pendingQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE status = 'pending'
		ORDER BY created_at ASC
		LIMIT 10
	`

	now := time.Now().UTC().Truncate(time.Microsecond)
	startDate := now.Add(-30 * 24 * time.Hour)
	endDate := now

	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"pending-a", "org-a", "full", "json",
			startDate, endDate,
			pq.Array([]string{"sys-x", "sys-y", "sys-z"}), pq.Array([]string{"high", "medium", "low"}),
			true,
			"pending", nil, "compliance-officer", "compliance@bank.com", "RBI quarterly submission",
			nil, nil, nil, int64(0), nil,
			0, []byte(`{"total_systems":42}`), nil,
			nil, nil, nil,
			now.Add(-5*time.Minute), now.Add(-5*time.Minute),
		)

	mock.ExpectQuery(regexp.QuoteMeta(pendingQuery)).
		WillReturnRows(rows)

	results, err := repo.GetPending(ctx)
	require.NoError(t, err)
	require.Len(t, results, 1)

	r := results[0]
	assert.Equal(t, "pending-a", r.ID)
	assert.Equal(t, "org-a", r.OrgID)
	assert.Equal(t, AuditExportTypeFull, r.ExportType)
	assert.Equal(t, AuditExportFormatJSON, r.Format)
	assert.NotNil(t, r.StartDate)
	assert.NotNil(t, r.EndDate)
	assert.Equal(t, []string{"sys-x", "sys-y", "sys-z"}, r.SystemIDs)
	assert.Equal(t, []string{"high", "medium", "low"}, r.RiskCategories)
	assert.True(t, r.IncludeArchived)
	assert.Equal(t, AuditExportStatusPending, r.Status)
	assert.Equal(t, "compliance-officer", r.RequestedBy)
	assert.Equal(t, "compliance@bank.com", r.RequestedByEmail)
	assert.Equal(t, "RBI quarterly submission", r.Purpose)
	assert.Nil(t, r.StartedAt)
	assert.Nil(t, r.CompletedAt)
	assert.NotNil(t, r.Summary)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_StartDateFilterOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	startDate := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	params := &ListAuditExportsParams{
		StartDate: &startDate,
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1 AND created_at >= $2"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001", startDate).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1 AND created_at >= $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", startDate, 50, 0).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_List_EndDateFilterOnly(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	endDate := time.Date(2026, 3, 31, 23, 59, 59, 0, time.UTC)
	params := &ListAuditExportsParams{
		EndDate: &endDate,
	}

	countQuery := "SELECT COUNT(*) FROM rbi_audit_exports WHERE org_id = $1 AND created_at <= $2"
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(countQuery)).
		WithArgs("org-001", endDate).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	listQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE org_id = $1 AND created_at <= $2
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4
	`
	mock.ExpectQuery(regexp.QuoteMeta(listQuery)).
		WithArgs("org-001", endDate, 50, 0).
		WillReturnRows(sqlmock.NewRows(auditExportColumns))

	mock.ExpectCommit()

	results, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, results)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Create_EmptySlices(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := &AuditExport{
		ID:             "export-empty-slices",
		OrgID:          "org-001",
		ExportType:     AuditExportTypeSystems,
		Format:         AuditExportFormatCSV,
		SystemIDs:      []string{},
		RiskCategories: []string{},
		Status:         AuditExportStatusPending,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_audit_exports").
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, export)
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_Update_WithErrorMessage(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	export := &AuditExport{
		ID:           "export-failed",
		OrgID:        "org-001",
		Status:       AuditExportStatusFailed,
		ErrorMessage: "Failed to generate report: insufficient data",
	}

	updateQuery := `
		UPDATE rbi_audit_exports SET
			status = $3, error_message = $4, started_at = $5, completed_at = $6,
			file_path = $7, file_size_bytes = $8, file_checksum = $9,
			record_count = $10, summary = $11, expires_at = $12,
			download_url = $13, storage_type = $14, storage_key = $15,
			updated_at = $16
		WHERE id = $1 AND org_id = $2
	`

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(updateQuery)).
		WithArgs(
			"export-failed", "org-001",
			"failed",
			sqlmock.AnyArg(), // error_message (NullString with value)
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), int64(0), sqlmock.AnyArg(),
			0, sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Update(ctx, export)
	require.NoError(t, err)
	assert.False(t, export.UpdatedAt.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestPostgresAuditExportRepository_GetExpired_MultipleRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAuditExportRepository(db)
	ctx := context.Background()

	expiredQuery := `
		SELECT
			id, org_id, export_type, format, start_date, end_date,
			system_ids, risk_categories, include_archived,
			status, error_message, requested_by, requested_by_email, purpose,
			started_at, completed_at, file_path, file_size_bytes, file_checksum,
			record_count, summary, expires_at,
			download_url, storage_type, storage_key,
			created_at, updated_at
		FROM rbi_audit_exports
		WHERE expires_at < NOW() AND status = 'completed'
		ORDER BY expires_at ASC
	`

	now := time.Now().UTC().Truncate(time.Microsecond)
	expired1 := now.Add(-48 * time.Hour)
	expired2 := now.Add(-24 * time.Hour)

	rows := sqlmock.NewRows(auditExportColumns).
		AddRow(
			"expired-a", "org-001", "full", "json",
			nil, nil,
			pq.Array([]string{}), pq.Array([]string{}),
			false, "completed", nil, nil, nil, nil,
			nil, nil, nil, int64(512000), nil,
			100, []byte("{}"), expired1,
			nil, "local", nil,
			now.Add(-72*time.Hour), now.Add(-48*time.Hour),
		).
		AddRow(
			"expired-b", "org-002", "incidents", "csv",
			nil, nil,
			pq.Array([]string{"sys-a"}), pq.Array([]string{"medium"}),
			false, "completed", nil, nil, nil, nil,
			nil, nil, nil, int64(256000), nil,
			50, []byte("{}"), expired2,
			nil, "s3", "exports/expired-b.csv",
			now.Add(-48*time.Hour), now.Add(-24*time.Hour),
		)

	mock.ExpectQuery(regexp.QuoteMeta(expiredQuery)).
		WillReturnRows(rows)

	results, err := repo.GetExpired(ctx)
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.Equal(t, "expired-a", results[0].ID)
	assert.Equal(t, "org-001", results[0].OrgID)
	assert.Equal(t, int64(512000), results[0].FileSizeBytes)
	assert.Equal(t, 100, results[0].RecordCount)
	assert.Equal(t, "local", results[0].StorageType)

	assert.Equal(t, "expired-b", results[1].ID)
	assert.Equal(t, "org-002", results[1].OrgID)
	assert.Equal(t, []string{"sys-a"}, results[1].SystemIDs)
	assert.Equal(t, "s3", results[1].StorageType)
	assert.Equal(t, "exports/expired-b.csv", results[1].StorageKey)

	require.NoError(t, mock.ExpectationsWereMet())
}
