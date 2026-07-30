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

var registryColumns = []string{
	"id", "org_id", "system_id", "system_name", "system_version", "description",
	"risk_category", "deployment_status", "model_type", "model_provider",
	"use_case", "use_case_description", "data_sources", "sensitive_data_categories",
	"data_residency", "owner_id", "owner_name", "owner_department", "owner_email",
	"board_approval_required", "board_approval_status", "board_approval_date",
	"board_approval_reference", "board_approver_name", "board_approval_notes",
	"last_validation_date", "next_validation_due", "validation_frequency_days",
	"tags", "metadata", "created_at", "updated_at", "deprecated_at",
}

func sampleSystemRow(id, orgID, systemID string) []driver.Value {
	now := time.Now().UTC()
	boardDate := now.Add(-30 * 24 * time.Hour)
	lastVal := now.Add(-60 * 24 * time.Hour)
	nextVal := now.Add(30 * 24 * time.Hour)
	return []driver.Value{
		id, orgID, systemID, "Credit Scoring Model",
		sql.NullString{String: "2.1.0", Valid: true},
		sql.NullString{String: "AI model for credit scoring", Valid: true},
		"high", "production",
		sql.NullString{String: "neural_network", Valid: true},
		sql.NullString{String: "internal", Valid: true},
		sql.NullString{String: "credit_scoring", Valid: true},
		sql.NullString{String: "Automated credit scoring for retail banking", Valid: true},
		[]byte(`["transaction_history","credit_bureau"]`),
		[]byte(`["pii","financial"]`),
		sql.NullString{String: "india", Valid: true},
		sql.NullString{String: "owner-001", Valid: true},
		sql.NullString{String: "Priya Sharma", Valid: true},
		sql.NullString{String: "Risk Management", Valid: true},
		sql.NullString{String: "priya@example.com", Valid: true},
		true, "approved",
		sql.NullTime{Time: boardDate, Valid: true},
		sql.NullString{String: "BA-2025-001", Valid: true},
		sql.NullString{String: "Board Chair", Valid: true},
		sql.NullString{String: "Approved with conditions", Valid: true},
		sql.NullTime{Time: lastVal, Valid: true},
		sql.NullTime{Time: nextVal, Valid: true},
		sql.NullInt32{Int32: 90, Valid: true},
		[]byte(`["production","critical"]`),
		[]byte(`{"regulatory_class":"tier1"}`),
		now, now,
		sql.NullTime{},
	}
}

func TestRegistryRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	system := &AISystem{
		OrgID:        "org-001",
		SystemID:     "sys-credit-001",
		SystemName:   "Credit Scoring Model",
		RiskCategory: RiskCategoryHigh,
		DataSources:  []string{"transaction_history"},
		Tags:         []string{"production"},
		Metadata:     map[string]interface{}{"env": "prod"},
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_system_registry`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, system)
	assert.NoError(t, err)
	assert.NotEmpty(t, system.ID)
	assert.False(t, system.CreatedAt.IsZero())
	assert.Equal(t, DeploymentStatusDevelopment, system.DeploymentStatus)
	assert.True(t, system.BoardApprovalRequired)
	assert.Equal(t, BoardApprovalPending, system.BoardApprovalStatus)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Create_LowRisk(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	system := &AISystem{
		OrgID:        "org-001",
		SystemID:     "sys-chatbot-001",
		SystemName:   "FAQ Chatbot",
		RiskCategory: RiskCategoryLow,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_system_registry`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, system)
	assert.NoError(t, err)
	assert.False(t, system.BoardApprovalRequired)
	assert.Equal(t, BoardApprovalNotRequired, system.BoardApprovalStatus)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Create_DuplicateKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	system := &AISystem{
		OrgID:        "org-001",
		SystemID:     "sys-credit-001",
		SystemName:   "Credit Model",
		RiskCategory: RiskCategoryHigh,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_system_registry`)).
		WillReturnError(fmt.Errorf("pq: duplicate key value violates unique constraint"))

	mock.ExpectRollback()

	err = repo.Create(ctx, system)
	assert.ErrorIs(t, err, ErrSystemAlreadyExists)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Create_PresetID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	system := &AISystem{
		ID:           "preset-id",
		OrgID:        "org-001",
		SystemID:     "sys-001",
		SystemName:   "Test System",
		RiskCategory: RiskCategoryLow,
		CreatedAt:    now,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_ai_system_registry`)).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err = repo.Create(ctx, system)
	assert.NoError(t, err)
	assert.Equal(t, "preset-id", system.ID)
	assert.Equal(t, now, system.CreatedAt)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Get_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(registryColumns).
		AddRow(sampleSystemRow("id-001", "org-001", "sys-credit-001")...)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "id-001").
		WillReturnRows(rows)

	mock.ExpectCommit()

	system, err := repo.Get(ctx, "org-001", "id-001")
	require.NoError(t, err)
	assert.Equal(t, "id-001", system.ID)
	assert.Equal(t, "org-001", system.OrgID)
	assert.Equal(t, "sys-credit-001", system.SystemID)
	assert.Equal(t, "Credit Scoring Model", system.SystemName)
	assert.Equal(t, "2.1.0", system.Version)
	assert.Equal(t, RiskCategory("high"), system.RiskCategory)
	assert.Equal(t, DeploymentStatus("production"), system.DeploymentStatus)
	assert.Equal(t, "neural_network", system.ModelType)
	assert.Equal(t, "internal", system.ModelProvider)
	assert.True(t, system.BoardApprovalRequired)
	assert.NotNil(t, system.BoardApprovalDate)
	assert.Equal(t, "BA-2025-001", system.BoardApprovalReference)
	assert.NotNil(t, system.LastValidationDate)
	assert.NotNil(t, system.NextValidationDue)
	assert.Equal(t, 90, system.ValidationFrequencyDays)
	assert.NotEmpty(t, system.DataSources)
	assert.NotEmpty(t, system.SensitiveDataCategories)
	assert.NotEmpty(t, system.Tags)
	assert.NotEmpty(t, system.Metadata)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "nonexistent").
		WillReturnError(sql.ErrNoRows)

	mock.ExpectRollback()

	system, err := repo.Get(ctx, "org-001", "nonexistent")
	assert.Nil(t, system)
	assert.ErrorIs(t, err, ErrSystemNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetBySystemID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(registryColumns).
		AddRow(sampleSystemRow("id-001", "org-001", "sys-credit-001")...)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND system_id = $2`)).
		WithArgs("org-001", "sys-credit-001").
		WillReturnRows(rows)

	mock.ExpectCommit()

	system, err := repo.GetBySystemID(ctx, "org-001", "sys-credit-001")
	require.NoError(t, err)
	assert.Equal(t, "sys-credit-001", system.SystemID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	params := &ListAISystemsParams{Limit: 10, Offset: 0}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	dataRows := sqlmock.NewRows(registryColumns).
		AddRow(sampleSystemRow("id-001", "org-001", "sys-001")...).
		AddRow(sampleSystemRow("id-002", "org-001", "sys-002")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)

	mock.ExpectCommit()

	systems, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, systems, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	params := &ListAISystemsParams{
		RiskCategory:        "high",
		DeploymentStatus:    "production",
		BoardApprovalStatus: "approved",
		OwnerDepartment:     "Risk Management",
		Limit:               20,
		Offset:              0,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "high", "production", "approved", "Risk Management").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(registryColumns).
		AddRow(sampleSystemRow("id-001", "org-001", "sys-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "high", "production", "approved", "Risk Management", 20, 0).
		WillReturnRows(dataRows)

	mock.ExpectCommit()

	systems, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, systems, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 20, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns))

	mock.ExpectCommit()

	systems, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, systems)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_LimitCapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	params := &ListAISystemsParams{Limit: 200}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 100, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns))

	mock.ExpectCommit()

	_, _, err = repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	system := &AISystem{
		ID:               "id-001",
		OrgID:            "org-001",
		SystemID:         "sys-001",
		SystemName:       "Updated Model",
		RiskCategory:     RiskCategoryHigh,
		DeploymentStatus: DeploymentStatusProduction,
		DataSources:      []string{"source1"},
		Tags:             []string{"updated"},
		Metadata:         map[string]interface{}{"version": 2},
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_system_registry SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Update(ctx, system)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	system := &AISystem{
		ID:           "nonexistent",
		OrgID:        "org-001",
		SystemID:     "sys-001",
		SystemName:   "Test",
		RiskCategory: RiskCategoryLow,
	}

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_system_registry SET`)).
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectCommit()

	err = repo.Update(ctx, system)
	assert.ErrorIs(t, err, ErrSystemNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_system_registry`)).
		WithArgs(string(DeploymentStatusDeprecated), sqlmock.AnyArg(), "org-001", "id-001").
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "id-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_ai_system_registry`)).
		WithArgs(string(DeploymentStatusDeprecated), sqlmock.AnyArg(), "org-001", "nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))

	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrSystemNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetSummary_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// Total count
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM rbi_ai_system_registry WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	// By risk category
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT risk_category, COUNT(*)`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"risk_category", "count"}).
			AddRow("high", 2).
			AddRow("medium", 2).
			AddRow("low", 1))

	// By deployment status
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT deployment_status, COUNT(*)`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"deployment_status", "count"}).
			AddRow("production", 3).
			AddRow("development", 2))

	// Pending approval count
	mock.ExpectQuery(regexp.QuoteMeta(`board_approval_status = 'pending'`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	// Overdue validation count
	mock.ExpectQuery(regexp.QuoteMeta(`next_validation_due < NOW()`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	mock.ExpectCommit()

	summary, err := repo.GetSummary(ctx, "org-001")
	require.NoError(t, err)
	assert.Equal(t, 5, summary.TotalSystems)
	assert.Equal(t, 2, summary.SystemsByRisk["high"])
	assert.Equal(t, 2, summary.SystemsByRisk["medium"])
	assert.Equal(t, 1, summary.SystemsByRisk["low"])
	assert.Equal(t, 3, summary.SystemsByStatus["production"])
	assert.Equal(t, 2, summary.SystemsByStatus["development"])
	assert.Equal(t, 1, summary.SystemsPendingApproval)
	assert.Equal(t, 2, summary.SystemsOverdueValidation)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetSummary_TotalCountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM rbi_ai_system_registry WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table not found"))

	mock.ExpectRollback()

	summary, err := repo.GetSummary(ctx, "org-001")
	assert.Nil(t, summary)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count total systems")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetSummary_RiskCountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAISystemRepository(db)
	ctx := context.Background()

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT COUNT(*) FROM rbi_ai_system_registry WHERE org_id = $1`)).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	mock.ExpectQuery(regexp.QuoteMeta(`SELECT risk_category, COUNT(*)`)).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("query error"))

	mock.ExpectRollback()

	summary, err := repo.GetSummary(ctx, "org-001")
	assert.Nil(t, summary)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count by risk")
	assert.NoError(t, mock.ExpectationsWereMet())
}

// TestRegistryRepository_Create_OmitsGeneratedColumn guards #2640: the INSERT
// must NOT write the GENERATED ALWAYS column board_approval_required (migration
// 301 — Postgres rejects a direct write), and must pass exactly 31 arguments.
// PG-free; runs in CI. Red-on-revert: re-adding the column makes the SQL
// contain it AND pushes the arg count to 32, so both assertions fail.
// (execSQLCapture / anyArgs are defined in incident_repository_test.go.)
func TestRegistryRepository_Create_OmitsGeneratedColumn(t *testing.T) {
	db, mock, sqlText := execSQLCapture(t)
	defer db.Close()
	repo := NewPostgresAISystemRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO rbi_ai_system_registry").
		WithArgs(anyArgs(31)...).
		WillReturnResult(sqlmock.NewResult(1, 1))

	mock.ExpectCommit()

	err := repo.Create(context.Background(), &AISystem{
		OrgID:        "org-1",
		SystemID:     "sys-1",
		SystemName:   "n",
		RiskCategory: RiskCategoryHigh,
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	assert.NotContains(t, *sqlText, "board_approval_required",
		"registry INSERT must not write the GENERATED board_approval_required column")
}

// TestRegistryRepository_Update_OmitsGeneratedColumn is the UPDATE counterpart
// (exactly 30 arguments; the SET clause must omit board_approval_required).
func TestRegistryRepository_Update_OmitsGeneratedColumn(t *testing.T) {
	db, mock, sqlText := execSQLCapture(t)
	defer db.Close()
	repo := NewPostgresAISystemRepository(db)

	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("UPDATE rbi_ai_system_registry").
		WithArgs(anyArgs(30)...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	mock.ExpectCommit()

	err := repo.Update(context.Background(), &AISystem{
		ID:           "id-1",
		OrgID:        "org-1",
		SystemID:     "sys-1",
		SystemName:   "n",
		RiskCategory: RiskCategoryHigh,
	})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
	assert.NotContains(t, *sqlText, "board_approval_required",
		"registry UPDATE must not write the GENERATED board_approval_required column")
}
