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

// incidentColumns returns the column names for the rbi_ai_incidents table scan order.
var incidentColumns = []string{
	"id", "org_id", "incident_id", "system_id",
	"incident_type", "severity",
	"detected_at", "detected_by", "detection_details",
	"title", "description", "root_cause",
	"affected_customers_count", "affected_transactions_count",
	"financial_impact_inr", "reputational_impact",
	"remediation_actions", "immediate_action_taken", "long_term_fix",
	"status", "resolved_at", "resolution_summary", "lessons_learned",
	"board_notification_required", "board_notified",
	"board_notification_date", "board_notification_reference",
	"rbi_notification_required", "rbi_notified",
	"rbi_notification_date", "rbi_notification_reference", "rbi_response",
	"evidence_files", "tags", "metadata",
	"created_at", "updated_at",
}

func sampleIncidentRow(id, orgID, incidentID string) []driver.Value {
	now := time.Now().UTC()
	affected := 100
	transactions := 500
	financial := 50000.50
	return []driver.Value{
		id, orgID, incidentID,
		sql.NullString{String: "sys-001", Valid: true},
		"model_failure", "critical",
		now, "automated_monitoring",
		sql.NullString{String: "Automated detection details", Valid: true},
		"Test Incident", "Description of incident",
		sql.NullString{String: "Root cause analysis", Valid: true},
		sql.NullInt64{Int64: int64(affected), Valid: true},
		sql.NullInt64{Int64: int64(transactions), Valid: true},
		sql.NullFloat64{Float64: financial, Valid: true},
		sql.NullString{String: "low", Valid: true},
		[]byte(`[{"id":"act-1","action":"restart","status":"completed"}]`),
		sql.NullString{String: "Service restarted", Valid: true},
		sql.NullString{String: "Deploy fix v2", Valid: true},
		"investigating",
		sql.NullTime{},
		sql.NullString{},
		sql.NullString{},
		true, false,
		sql.NullTime{},
		sql.NullString{},
		true, false,
		sql.NullTime{},
		sql.NullString{},
		sql.NullString{},
		[]byte(`["evidence1.pdf"]`),
		[]byte(`["production","critical"]`),
		[]byte(`{"source":"monitoring"}`),
		now, now,
	}
}

func TestIncidentRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incident := &AIIncident{
		OrgID:        "org-001",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Model failure in production",
		Description:  "The model stopped responding",
		Status:       IncidentStatusOpen,
		Tags:         []string{"production"},
		Metadata:     map[string]interface{}{"env": "prod"},
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_incidents`)).
		WithArgs(
			sqlmock.AnyArg(), // id
			incident.OrgID,
			sqlmock.AnyArg(), // incident_id
			sql.NullString{},
			string(incident.IncidentType),
			string(incident.Severity),
			sqlmock.AnyArg(), // detected_at
			string(incident.DetectedBy),
			sql.NullString{},
			incident.Title,
			incident.Description,
			sql.NullString{},
			sql.NullInt64{},
			sql.NullInt64{},
			sql.NullFloat64{},
			sql.NullString{},
			sqlmock.AnyArg(), // remediation_actions JSON
			sql.NullString{},
			sql.NullString{},
			string(incident.Status),
			sql.NullTime{},
			sql.NullString{},
			sql.NullString{},
			// board_notification_required / rbi_notification_required are
			// GENERATED columns and are NOT in the INSERT arg list.
			false,            // board_notified
			sql.NullTime{},   // board_notification_date
			sql.NullString{}, // board_notification_reference
			false,            // rbi_notified
			sql.NullTime{},   // rbi_notification_date
			sql.NullString{}, // rbi_notification_reference
			sql.NullString{}, // rbi_response
			sqlmock.AnyArg(), // evidence_files JSON
			sqlmock.AnyArg(), // tags JSON
			sqlmock.AnyArg(), // metadata JSON
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, incident)
	assert.NoError(t, err)
	assert.NotEmpty(t, incident.ID)
	assert.NotEmpty(t, incident.IncidentID)
	assert.False(t, incident.CreatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incident := &AIIncident{
		OrgID:        "org-001",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Test",
		Description:  "Test",
		Status:       IncidentStatusOpen,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_incidents`)).
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	err = repo.Create(ctx, incident)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create incident")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Get_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-id-1", "org-001", "INC-abc12345")...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("inc-id-1", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	incident, err := repo.Get(ctx, "org-001", "inc-id-1")
	require.NoError(t, err)
	assert.Equal(t, "inc-id-1", incident.ID)
	assert.Equal(t, "org-001", incident.OrgID)
	assert.Equal(t, "INC-abc12345", incident.IncidentID)
	assert.Equal(t, "sys-001", incident.SystemID)
	assert.Equal(t, IncidentTypeModelFailure, incident.IncidentType)
	assert.Equal(t, IncidentSeverityCritical, incident.Severity)
	assert.Equal(t, "Test Incident", incident.Title)
	assert.NotNil(t, incident.AffectedCustomersCount)
	assert.Equal(t, 100, *incident.AffectedCustomersCount)
	assert.NotNil(t, incident.FinancialImpactINR)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	incident, err := repo.Get(ctx, "org-001", "nonexistent")
	assert.Nil(t, incident)
	assert.ErrorIs(t, err, ErrIncidentNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetByIncidentID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-id-1", "org-001", "INC-abc12345")...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("INC-abc12345", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	incident, err := repo.GetByIncidentID(ctx, "org-001", "INC-abc12345")
	require.NoError(t, err)
	assert.Equal(t, "INC-abc12345", incident.IncidentID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	params := &ListIncidentsParams{
		Limit:  10,
		Offset: 0,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Count query
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM rbi_ai_incidents WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Data query
	dataRows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-1", "org-001", "INC-001")...).
		AddRow(sampleIncidentRow("inc-2", "org-001", "INC-002")...)

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	incidents, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, incidents, 2)
	assert.Equal(t, "inc-1", incidents[0].ID)
	assert.Equal(t, "inc-2", incidents[1].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	boardNotified := false
	params := &ListIncidentsParams{
		SystemID:      "sys-001",
		IncidentType:  "model_failure",
		Severity:      "critical",
		Status:        "open",
		BoardNotified: &boardNotified,
		Limit:         20,
		Offset:        0,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Count query with filters
	mock.ExpectQuery(`SELECT COUNT\(\*\) FROM rbi_ai_incidents WHERE`).
		WithArgs("org-001", "sys-001", "model_failure", "critical", "open", false).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Data query with filters
	dataRows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-1", "org-001", "INC-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "sys-001", "model_failure", "critical", "open", false, 20, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	incidents, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, incidents, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 50, 0).
		WillReturnRows(sqlmock.NewRows(incidentColumns))
	mock.ExpectCommit()

	incidents, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, incidents)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_List_LimitCapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	params := &ListIncidentsParams{Limit: 999}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 100, 0).
		WillReturnRows(sqlmock.NewRows(incidentColumns))
	mock.ExpectCommit()

	_, _, err = repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_ListBySystem_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-1", "org-001", "INC-001")...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	incidents, err := repo.ListBySystem(ctx, "org-001", "sys-001")
	require.NoError(t, err)
	assert.Len(t, incidents, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incident := &AIIncident{
		ID:           "inc-id-1",
		OrgID:        "org-001",
		SystemID:     "sys-001",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Updated title",
		Description:  "Updated description",
		Status:       IncidentStatusResolved,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_incidents SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, incident)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incident := &AIIncident{
		ID:           "nonexistent",
		OrgID:        "org-001",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityLow,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Test",
		Description:  "Test",
		Status:       IncidentStatusOpen,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_incidents SET`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	err = repo.Update(ctx, incident)
	assert.ErrorIs(t, err, ErrIncidentNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_ai_incidents WHERE id = $1 AND org_id = $2`)).
		WithArgs("inc-id-1", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "inc-id-1")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_ai_incidents WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrIncidentNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetOpenIncidents_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-1", "org-001", "INC-001")...).
		AddRow(sampleIncidentRow("inc-2", "org-001", "INC-002")...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	incidents, err := repo.GetOpenIncidents(ctx, "org-001")
	require.NoError(t, err)
	assert.Len(t, incidents, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetOpenIncidents_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows(incidentColumns))
	mock.ExpectCommit()

	incidents, err := repo.GetOpenIncidents(ctx, "org-001")
	require.NoError(t, err)
	assert.Empty(t, incidents)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetPendingNotifications_Board(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(incidentColumns).
		AddRow(sampleIncidentRow("inc-1", "org-001", "INC-001")...)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`board_notification_required = true AND board_notified = false`)).
		WithArgs("org-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	incidents, err := repo.GetPendingNotifications(ctx, "org-001", "board")
	require.NoError(t, err)
	assert.Len(t, incidents, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetPendingNotifications_RBI(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`rbi_notification_required = true AND rbi_notified = false`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows(incidentColumns))
	mock.ExpectCommit()

	incidents, err := repo.GetPendingNotifications(ctx, "org-001", "rbi")
	require.NoError(t, err)
	assert.Empty(t, incidents)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_GetPendingNotifications_InvalidType(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incidents, err := repo.GetPendingNotifications(ctx, "org-001", "invalid")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid notification type")
	assert.Nil(t, incidents)
}

func TestIncidentRepository_Get_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("inc-id-1", "org-001").
		WillReturnError(fmt.Errorf("connection closed"))
	mock.ExpectRollback()

	incident, err := repo.Get(ctx, "org-001", "inc-id-1")
	assert.Nil(t, incident)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to scan incident")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestIncidentRepository_Create_PresetIDAndIncidentID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAIIncidentRepository(db)
	ctx := context.Background()

	incident := &AIIncident{
		ID:           "preset-id",
		IncidentID:   "INC-preset",
		OrgID:        "org-001",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityLow,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "Test",
		Description:  "Test",
		Status:       IncidentStatusOpen,
	}

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_incidents`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, incident)
	assert.NoError(t, err)
	assert.Equal(t, "preset-id", incident.ID)
	assert.Equal(t, "INC-preset", incident.IncidentID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

// execSQLCapture builds a sqlmock whose query matcher records the executed SQL
// into the returned pointer (it always matches), so a test can assert the built
// INSERT/UPDATE statement does NOT write a GENERATED column. WithArgs still
// validates the argument count/shape independently of the SQL text.
func execSQLCapture(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *string) {
	t.Helper()
	captured := new(string)
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(
		sqlmock.QueryMatcherFunc(func(_, actualSQL string) error {
			*captured = actualSQL
			return nil
		}),
	))
	require.NoError(t, err)
	return db, mock, captured
}

// anyArgs returns n AnyArg matchers. WithArgs(anyArgs(n)...) asserts the
// statement was executed with EXACTLY n arguments — re-adding a column shifts
// the count and fails the expectation — without pinning each concrete value.
func anyArgs(n int) []driver.Value {
	a := make([]driver.Value, n)
	for i := range a {
		a[i] = sqlmock.AnyArg()
	}
	return a
}

// TestIncidentRepository_Create_OmitsGeneratedColumns guards #2640: the INSERT
// must NOT write the GENERATED ALWAYS columns board_notification_required /
// rbi_notification_required (migration 301 — Postgres rejects a direct write),
// and must pass exactly 35 arguments. PG-free; runs in CI. Red-on-revert:
// re-adding either column makes the SQL contain it AND pushes the arg count to
// 37, so both the NotContains and the WithArgs(35) expectation fail.
func TestIncidentRepository_Create_OmitsGeneratedColumns(t *testing.T) {
	db, mock, sqlText := execSQLCapture(t)
	defer db.Close()
	repo := NewPostgresAIIncidentRepository(db)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_ai_incidents").
		WithArgs(anyArgs(35)...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err := repo.Create(context.Background(), &AIIncident{
		OrgID:        "org-1",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "t",
		Description:  "d",
		Status:       IncidentStatusOpen,
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	assert.NotContains(t, *sqlText, "board_notification_required",
		"incident INSERT must not write the GENERATED board_notification_required column")
	assert.NotContains(t, *sqlText, "rbi_notification_required",
		"incident INSERT must not write the GENERATED rbi_notification_required column")
}

// TestIncidentRepository_Update_OmitsGeneratedColumns is the UPDATE counterpart
// (exactly 33 arguments; the SET clause must omit both GENERATED columns).
func TestIncidentRepository_Update_OmitsGeneratedColumns(t *testing.T) {
	db, mock, sqlText := execSQLCapture(t)
	defer db.Close()
	repo := NewPostgresAIIncidentRepository(db)

	// #3103: every statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE rbi_ai_incidents").
		WithArgs(anyArgs(33)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err := repo.Update(context.Background(), &AIIncident{
		ID:           "inc-1",
		OrgID:        "org-1",
		IncidentType: IncidentTypeModelFailure,
		Severity:     IncidentSeverityCritical,
		DetectedAt:   time.Now().UTC(),
		DetectedBy:   DetectionMethodAutomated,
		Title:        "t",
		Description:  "d",
		Status:       IncidentStatusResolved,
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	assert.NotContains(t, *sqlText, "board_notification_required",
		"incident UPDATE must not write the GENERATED board_notification_required column")
	assert.NotContains(t, *sqlText, "rbi_notification_required",
		"incident UPDATE must not write the GENERATED rbi_notification_required column")
}
