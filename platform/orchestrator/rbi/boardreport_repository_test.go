// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var boardReportColumns = []string{
	"id", "org_id", "report_type", "report_period_start", "report_period_end", "report_quarter",
	"total_ai_systems", "systems_by_risk", "systems_by_status", "new_systems_deployed", "systems_deprecated",
	"total_validations", "validations_by_type", "validations_by_recommendation", "overdue_validations",
	"total_incidents", "incidents_by_severity", "incidents_by_type", "incidents_resolved", "incidents_open",
	"average_resolution_time_hours", "key_metrics", "compliance_score", "compliance_issues",
	"corrective_actions", "kill_switch_activations", "kill_switch_details",
	"generated_by", "generated_by_email", "generated_at", "generation_method",
	"approval_status", "approved_by", "approved_by_email", "approved_at", "approval_notes",
	"file_path", "file_format", "file_size_bytes", "file_checksum",
	"created_at", "updated_at",
}

func sampleBoardReportRow(id, orgID string) []driver.Value {
	now := time.Now().UTC()
	periodStart := now.Add(-90 * 24 * time.Hour)
	periodEnd := now
	approvedAt := now.Add(-1 * 24 * time.Hour)

	return []driver.Value{
		id, orgID, string(ReportTypeQuarterly),
		sql.NullTime{Time: periodStart, Valid: true},
		sql.NullTime{Time: periodEnd, Valid: true},
		sql.NullString{String: "Q4-2025", Valid: true},
		15,
		[]byte(`{"high":3,"medium":7,"low":5}`),
		[]byte(`{"production":10,"development":5}`),
		2, 1,
		8,
		[]byte(`{"independent":5,"development":3}`),
		[]byte(`{"approve":6,"conditional":2}`),
		1,
		3,
		[]byte(`{"critical":1,"high":2}`),
		[]byte(`{"model_failure":2,"bias_detected":1}`),
		2, 1,
		24.5,
		[]byte(`{"avg_accuracy":0.95,"models_monitored":15}`),
		92.5,
		[]byte(`[{"category":"validation","description":"Overdue validation","severity":"medium"}]`),
		[]byte(`[{"id":"ca-1","action":"Complete overdue validation","priority":"high","status":"pending"}]`),
		2,
		[]byte(`{"global_activations":1,"system_activations":1}`),
		sql.NullString{String: "compliance-officer", Valid: true},
		sql.NullString{String: "officer@example.com", Valid: true},
		now,
		sql.NullString{String: "automatic", Valid: true},
		string(ReportApprovalApproved),
		sql.NullString{String: "board-chair", Valid: true},
		sql.NullString{String: "chair@example.com", Valid: true},
		sql.NullTime{Time: approvedAt, Valid: true},
		sql.NullString{String: "Approved with minor observations", Valid: true},
		sql.NullString{String: "/reports/q4-2025.pdf", Valid: true},
		sql.NullString{String: "pdf", Valid: true},
		int64(1024000),
		sql.NullString{String: "sha256:abc123", Valid: true},
		now, now,
	}
}

func TestBoardReportRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	periodStart := time.Now().UTC().Add(-90 * 24 * time.Hour)
	periodEnd := time.Now().UTC()
	report := &BoardReport{
		OrgID:             "org-001",
		ReportType:        ReportTypeQuarterly,
		ReportPeriodStart: &periodStart,
		ReportPeriodEnd:   &periodEnd,
		ReportQuarter:     "Q4-2025",
		TotalAISystems:    15,
		SystemsByRisk:     map[string]int{"high": 3, "medium": 7, "low": 5},
		SystemsByStatus:   map[string]int{"production": 10, "development": 5},
		TotalIncidents:    3,
		ComplianceScore:   92.5,
		ApprovalStatus:    ReportApprovalDraft,
		GeneratedAt:       time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_board_reports`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Create(ctx, report)
	assert.NoError(t, err)
	assert.NotEmpty(t, report.ID)
	assert.False(t, report.CreatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Create_PresetID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	report := &BoardReport{
		ID:             "preset-report-id",
		OrgID:          "org-001",
		ReportType:     ReportTypeAdhoc,
		ApprovalStatus: ReportApprovalDraft,
		GeneratedAt:    time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_board_reports`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = repo.Create(ctx, report)
	assert.NoError(t, err)
	assert.Equal(t, "preset-report-id", report.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	report := &BoardReport{
		OrgID:          "org-001",
		ReportType:     ReportTypeQuarterly,
		ApprovalStatus: ReportApprovalDraft,
		GeneratedAt:    time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_board_reports`)).
		WillReturnError(fmt.Errorf("connection refused"))

	err = repo.Create(ctx, report)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create board report")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Get_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-001", "org-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE id = $1 AND org_id = $2`)).
		WithArgs("report-001", "org-001").
		WillReturnRows(rows)

	report, err := repo.Get(ctx, "org-001", "report-001")
	require.NoError(t, err)
	assert.Equal(t, "report-001", report.ID)
	assert.Equal(t, "org-001", report.OrgID)
	assert.Equal(t, ReportType("quarterly"), report.ReportType)
	assert.Equal(t, "Q4-2025", report.ReportQuarter)
	assert.Equal(t, 15, report.TotalAISystems)
	assert.NotNil(t, report.ReportPeriodStart)
	assert.NotNil(t, report.ReportPeriodEnd)
	assert.Equal(t, 3, report.SystemsByRisk["high"])
	assert.Equal(t, 10, report.SystemsByStatus["production"])
	assert.Equal(t, 3, report.TotalIncidents)
	assert.Equal(t, 92.5, report.ComplianceScore)
	assert.Equal(t, ReportApprovalStatus("approved"), report.ApprovalStatus)
	assert.Equal(t, "board-chair", report.ApprovedBy)
	assert.NotNil(t, report.ApprovedAt)
	assert.Equal(t, "/reports/q4-2025.pdf", report.FilePath)
	assert.Equal(t, "pdf", report.FileFormat)
	assert.Equal(t, int64(1024000), report.FileSizeBytes)
	assert.NotEmpty(t, report.ComplianceIssues)
	assert.NotEmpty(t, report.CorrectiveActions)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(sql.ErrNoRows)

	report, err := repo.Get(ctx, "org-001", "nonexistent")
	assert.Nil(t, report)
	assert.ErrorIs(t, err, ErrBoardReportNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	params := &ListBoardReportsParams{Limit: 10, Offset: 0}

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	dataRows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-001", "org-001")...).
		AddRow(sampleBoardReportRow("report-002", "org-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)

	reports, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, reports, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	params := &ListBoardReportsParams{
		ReportType:     "quarterly",
		Quarter:        "Q4-2025",
		ApprovalStatus: "approved",
		Limit:          20,
	}

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "quarterly", "Q4-2025", "approved").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-001", "org-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "quarterly", "Q4-2025", "approved", 20, 0).
		WillReturnRows(dataRows)

	reports, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, reports, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 50, 0).
		WillReturnRows(sqlmock.NewRows(boardReportColumns))

	reports, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, reports)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_List_LimitCapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	params := &ListBoardReportsParams{Limit: 500}

	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 100, 0).
		WillReturnRows(sqlmock.NewRows(boardReportColumns))

	_, _, err = repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_ListByQuarter_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-001", "org-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND report_quarter = $2`)).
		WithArgs("org-001", "Q4-2025").
		WillReturnRows(dataRows)

	reports, err := repo.ListByQuarter(ctx, "org-001", "Q4-2025")
	require.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_ListByQuarter_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND report_quarter = $2`)).
		WithArgs("org-001", "Q1-2026").
		WillReturnRows(sqlmock.NewRows(boardReportColumns))

	reports, err := repo.ListByQuarter(ctx, "org-001", "Q1-2026")
	require.NoError(t, err)
	assert.Empty(t, reports)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	report := &BoardReport{
		ID:              "report-001",
		OrgID:           "org-001",
		ReportType:      ReportTypeQuarterly,
		TotalAISystems:  20,
		ComplianceScore: 95.0,
		ApprovalStatus:  ReportApprovalApproved,
		SystemsByRisk:   map[string]int{"high": 5},
		SystemsByStatus: map[string]int{"production": 15},
		GeneratedAt:     time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_board_reports SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Update(ctx, report)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	report := &BoardReport{
		ID:             "nonexistent",
		OrgID:          "org-001",
		ReportType:     ReportTypeQuarterly,
		ApprovalStatus: ReportApprovalDraft,
		GeneratedAt:    time.Now().UTC(),
	}

	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_board_reports SET`)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.Update(ctx, report)
	assert.ErrorIs(t, err, ErrBoardReportNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_board_reports WHERE id = $1 AND org_id = $2`)).
		WithArgs("report-001", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Delete(ctx, "org-001", "report-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_board_reports WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrBoardReportNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_GetLatest_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-latest", "org-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND report_type = $2`)).
		WithArgs("org-001", string(ReportTypeQuarterly)).
		WillReturnRows(rows)

	report, err := repo.GetLatest(ctx, "org-001", ReportTypeQuarterly)
	require.NoError(t, err)
	assert.Equal(t, "report-latest", report.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_GetLatest_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND report_type = $2`)).
		WithArgs("org-001", string(ReportTypeAnnual)).
		WillReturnError(sql.ErrNoRows)

	report, err := repo.GetLatest(ctx, "org-001", ReportTypeAnnual)
	assert.Nil(t, report)
	assert.ErrorIs(t, err, ErrBoardReportNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_GetPendingApproval_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(boardReportColumns).
		AddRow(sampleBoardReportRow("report-001", "org-001")...).
		AddRow(sampleBoardReportRow("report-002", "org-001")...)

	mock.ExpectQuery(regexp.QuoteMeta(`approval_status = 'pending_review'`)).
		WithArgs("org-001").
		WillReturnRows(dataRows)

	reports, err := repo.GetPendingApproval(ctx, "org-001")
	require.NoError(t, err)
	assert.Len(t, reports, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_GetPendingApproval_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`approval_status = 'pending_review'`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows(boardReportColumns))

	reports, err := repo.GetPendingApproval(ctx, "org-001")
	require.NoError(t, err)
	assert.Empty(t, reports)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestBoardReportRepository_Get_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresBoardReportRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta(`WHERE id = $1 AND org_id = $2`)).
		WithArgs("report-001", "org-001").
		WillReturnError(fmt.Errorf("connection dropped"))

	report, err := repo.Get(ctx, "org-001", "report-001")
	assert.Nil(t, report)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to scan board report")
	assert.NoError(t, mock.ExpectationsWereMet())
}
