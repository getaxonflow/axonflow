// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewPostgresRegistryRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	require.NotNil(t, repo)
	assert.Equal(t, db, repo.db)
}

func TestNewPostgresRegistryRepository_NilDB(t *testing.T) {
	repo := NewPostgresRegistryRepository(nil)
	require.NotNil(t, repo)
	assert.Nil(t, repo.db)
}

// =============================================================================
// Create Tests
// =============================================================================

func TestRegistryRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	system := &AISystemRegistry{
		OrgID:                "org-1",
		SystemID:             "sys-credit-score",
		SystemName:           "Credit Scoring Model",
		Description:          "Automated credit scoring",
		UseCase:              UseCaseCreditScoring,
		Status:               SystemStatusActive,
		RiskRatingImpact:     4,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   5,
		OwnerTeam:            "Risk Engineering",
		OwnerEmail:           "risk@bank.com",
		DataSources:          []string{"credit_bureau", "transaction_history"},
		ModelType:            "gradient_boosting",
		Version:              "2.1.0",
		Metadata:             map[string]interface{}{"region": "singapore"},
		CreatedBy:            "admin@bank.com",
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_ai_system_registry")).
		WithArgs(
			sqlmock.AnyArg(), // id (generated)
			system.OrgID, system.SystemID, system.SystemName, system.Description,
			system.UseCase, system.Status,
			system.RiskRatingImpact, system.RiskRatingComplexity, system.RiskRatingReliance,
			sqlmock.AnyArg(), // materiality_classification (calculated)
			system.OwnerTeam, system.OwnerEmail,
			sqlmock.AnyArg(), // data_sources JSON
			system.ModelType, system.Version, system.DeploymentDate,
			sqlmock.AnyArg(), // metadata JSON
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
			system.CreatedBy,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, system)
	require.NoError(t, err)

	assert.NotEmpty(t, system.ID)
	assert.False(t, system.CreatedAt.IsZero())
	assert.Equal(t, system.CreatedAt, system.UpdatedAt)
	// Impact(4) + Complexity(3) + Reliance(5) = 12 -> high
	assert.Equal(t, MaterialityHigh, system.MaterialityClassification)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Create_WithExistingID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	system := &AISystemRegistry{
		ID:                   "pre-existing-id",
		OrgID:                "org-1",
		SystemID:             "sys-1",
		SystemName:           "Test System",
		UseCase:              UseCaseOther,
		Status:               SystemStatusDraft,
		RiskRatingImpact:     1,
		RiskRatingComplexity: 1,
		RiskRatingReliance:   1,
		OwnerTeam:            "team-a",
		OwnerEmail:           "team@test.com",
		CreatedBy:            "user-1",
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_ai_system_registry")).
		WithArgs(
			"pre-existing-id", // Should use existing ID
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, system)
	require.NoError(t, err)
	assert.Equal(t, "pre-existing-id", system.ID)
	// 1+1+1=3 < 8 -> low
	assert.Equal(t, MaterialityLow, system.MaterialityClassification)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	system := &AISystemRegistry{
		OrgID:      "org-1",
		SystemID:   "sys-1",
		SystemName: "Test",
		UseCase:    UseCaseOther,
		Status:     SystemStatusDraft,
		OwnerTeam:  "team",
		OwnerEmail: "a@b.com",
		CreatedBy:  "u",
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_ai_system_registry")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("unique constraint violation"))
	mock.ExpectRollback()

	err = repo.Create(ctx, system)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to insert AI system")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetByID Tests
// =============================================================================

func registryColumns() []string {
	return []string{
		"id", "org_id", "system_id", "system_name", "description", "use_case", "status",
		"risk_rating_impact", "risk_rating_complexity", "risk_rating_reliance",
		"materiality_classification", "owner_team", "owner_email", "data_sources",
		"model_type", "version", "deployment_date", "last_assessment_date",
		"next_assessment_due", "metadata", "created_at", "updated_at", "created_by", "updated_by",
	}
}

func TestRegistryRepository_GetByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	deployDate := now.Add(-30 * 24 * time.Hour)

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id, system_name")).
		WithArgs("org-1", "id-1").
		WillReturnRows(sqlmock.NewRows(registryColumns()).AddRow(
			"id-1", "org-1", "sys-1", "Credit Scorer", "A credit scoring model",
			UseCaseCreditScoring, SystemStatusActive,
			4, 3, 5, MaterialityHigh, "Risk Team", "risk@bank.com",
			[]byte(`["credit_bureau","transactions"]`),
			"xgboost", "1.0.0", deployDate, nil, nil,
			[]byte(`{"region":"sg"}`),
			now, now, "admin", "editor",
		))
	mock.ExpectCommit()

	system, err := repo.GetByID(ctx, "org-1", "id-1")
	require.NoError(t, err)
	require.NotNil(t, system)

	assert.Equal(t, "id-1", system.ID)
	assert.Equal(t, "org-1", system.OrgID)
	assert.Equal(t, "Credit Scorer", system.SystemName)
	assert.Equal(t, "A credit scoring model", system.Description)
	assert.Equal(t, UseCaseCreditScoring, system.UseCase)
	assert.Equal(t, SystemStatusActive, system.Status)
	assert.Equal(t, 4, system.RiskRatingImpact)
	assert.Equal(t, MaterialityHigh, system.MaterialityClassification)
	assert.Equal(t, "xgboost", system.ModelType)
	assert.Equal(t, "1.0.0", system.Version)
	assert.Equal(t, "editor", system.UpdatedBy)
	require.NotNil(t, system.DeploymentDate)
	assert.Nil(t, system.LastAssessmentDate)
	assert.Nil(t, system.NextAssessmentDue)
	assert.Len(t, system.DataSources, 2)
	assert.Equal(t, "sg", system.Metadata["region"])

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id, system_name")).
		WithArgs("org-1", "nonexistent").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	system, err := repo.GetByID(ctx, "org-1", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, system)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetByID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "id-1").
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	system, err := repo.GetByID(ctx, "org-1", "id-1")
	assert.Error(t, err)
	assert.Nil(t, system)
	assert.Contains(t, err.Error(), "failed to get AI system")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetByID_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// All nullable fields are nil
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "id-1").
		WillReturnRows(sqlmock.NewRows(registryColumns()).AddRow(
			"id-1", "org-1", "sys-1", "Minimal System", nil,
			UseCaseOther, SystemStatusDraft,
			1, 1, 1, MaterialityLow, "team", "t@t.com",
			nil, nil, nil, nil, nil, nil, nil,
			now, now, "admin", nil,
		))
	mock.ExpectCommit()

	system, err := repo.GetByID(ctx, "org-1", "id-1")
	require.NoError(t, err)
	require.NotNil(t, system)

	assert.Empty(t, system.Description)
	assert.Empty(t, system.ModelType)
	assert.Empty(t, system.Version)
	assert.Empty(t, system.UpdatedBy)
	assert.Nil(t, system.DeploymentDate)
	assert.Nil(t, system.LastAssessmentDate)
	assert.Nil(t, system.NextAssessmentDue)
	assert.Nil(t, system.DataSources)
	assert.Nil(t, system.Metadata)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetBySystemID Tests
// =============================================================================

func TestRegistryRepository_GetBySystemID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// First query: look up ID by system_id
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_ai_system_registry WHERE org_id = $1 AND system_id = $2")).
		WithArgs("org-1", "sys-credit").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("uuid-1"))
	mock.ExpectCommit()

	// Second query: GetByID
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "uuid-1").
		WillReturnRows(sqlmock.NewRows(registryColumns()).AddRow(
			"uuid-1", "org-1", "sys-credit", "Credit Model", "desc",
			UseCaseCreditScoring, SystemStatusActive,
			3, 3, 3, MaterialityMedium, "team", "t@t.com",
			nil, nil, nil, nil, nil, nil, nil,
			now, now, "admin", nil,
		))
	mock.ExpectCommit()

	system, err := repo.GetBySystemID(ctx, "org-1", "sys-credit")
	require.NoError(t, err)
	require.NotNil(t, system)
	assert.Equal(t, "uuid-1", system.ID)
	assert.Equal(t, "sys-credit", system.SystemID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetBySystemID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_ai_system_registry WHERE org_id = $1 AND system_id = $2")).
		WithArgs("org-1", "nonexistent").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	system, err := repo.GetBySystemID(ctx, "org-1", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, system)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetBySystemID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_ai_system_registry")).
		WithArgs("org-1", "sys-1").
		WillReturnError(fmt.Errorf("connection error"))
	mock.ExpectRollback()

	system, err := repo.GetBySystemID(ctx, "org-1", "sys-1")
	assert.Error(t, err)
	assert.Nil(t, system)
	assert.Contains(t, err.Error(), "failed to get AI system by system_id")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// List Tests
// =============================================================================

func TestRegistryRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id, system_name")).
		WithArgs("org-1", 50, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns()).
			AddRow("id-1", "org-1", "sys-1", "System A", "Description A",
				UseCaseCreditScoring, SystemStatusActive,
				4, 4, 4, MaterialityHigh, "team-a", "a@b.com",
				[]byte(`["source1"]`), "xgboost", "1.0", now, nil, nil,
				[]byte(`{}`), now, now, "admin", nil).
			AddRow("id-2", "org-1", "sys-2", "System B", nil,
				UseCaseFraudDetection, SystemStatusDraft,
				2, 2, 2, MaterialityLow, "team-b", "b@b.com",
				nil, nil, nil, nil, nil, nil, nil,
				now, now, "admin", nil))
	mock.ExpectCommit()

	systems, err := repo.List(ctx, "org-1", ListParams{})
	require.NoError(t, err)
	require.Len(t, systems, 2)

	assert.Equal(t, "id-1", systems[0].ID)
	assert.Equal(t, "System A", systems[0].SystemName)
	assert.Equal(t, "Description A", systems[0].Description)
	assert.Len(t, systems[0].DataSources, 1)

	assert.Equal(t, "id-2", systems[1].ID)
	assert.Empty(t, systems[1].Description) // null -> empty
	assert.Nil(t, systems[1].DataSources)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_WithStatusFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("AND status = $2")).
		WithArgs("org-1", "active", 10, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns()).
			AddRow("id-1", "org-1", "sys-1", "Active System", nil,
				UseCaseOther, SystemStatusActive,
				2, 2, 2, MaterialityLow, "team", "t@t.com",
				nil, nil, nil, nil, nil, nil, nil,
				now, now, "admin", nil))
	mock.ExpectCommit()

	systems, err := repo.List(ctx, "org-1", ListParams{
		Limit:  10,
		Status: "active",
	})
	require.NoError(t, err)
	require.Len(t, systems, 1)
	assert.Equal(t, "Active System", systems[0].SystemName)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_WithPagination(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("LIMIT $2 OFFSET $3")).
		WithArgs("org-1", 5, 10).
		WillReturnRows(sqlmock.NewRows(registryColumns()))
	mock.ExpectCommit()

	systems, err := repo.List(ctx, "org-1", ListParams{Limit: 5, Offset: 10})
	require.NoError(t, err)
	assert.Len(t, systems, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_LimitClamping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// Limit > MaxListLimit (1000) should be clamped
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", MaxListLimit, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns()))
	mock.ExpectCommit()

	systems, err := repo.List(ctx, "org-1", ListParams{Limit: 5000})
	require.NoError(t, err)
	assert.Len(t, systems, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_NegativeLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// Negative limit should default to DefaultListLimit (50)
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", DefaultListLimit, 0).
		WillReturnRows(sqlmock.NewRows(registryColumns()))
	mock.ExpectCommit()

	systems, err := repo.List(ctx, "org-1", ListParams{Limit: -1})
	require.NoError(t, err)
	assert.Len(t, systems, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_List_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", DefaultListLimit, 0).
		WillReturnError(fmt.Errorf("connection timeout"))
	mock.ExpectRollback()

	systems, err := repo.List(ctx, "org-1", ListParams{})
	assert.Error(t, err)
	assert.Nil(t, systems)
	assert.Contains(t, err.Error(), "failed to list AI systems")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// Update Tests
// =============================================================================

func TestRegistryRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	deployDate := time.Now().UTC()
	system := &AISystemRegistry{
		ID:                   "id-1",
		OrgID:                "org-1",
		SystemName:           "Updated System",
		Description:          "Updated description",
		UseCase:              UseCaseFraudDetection,
		Status:               SystemStatusActive,
		RiskRatingImpact:     5,
		RiskRatingComplexity: 4,
		RiskRatingReliance:   4,
		OwnerTeam:            "New Team",
		OwnerEmail:           "new@team.com",
		DataSources:          []string{"source1", "source2"},
		ModelType:            "neural_net",
		Version:              "3.0.0",
		DeploymentDate:       &deployDate,
		Metadata:             map[string]interface{}{"updated": true},
		UpdatedBy:            "editor@bank.com",
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_ai_system_registry SET")).
		WithArgs(
			system.SystemName, system.Description, system.UseCase, system.Status,
			system.RiskRatingImpact, system.RiskRatingComplexity, system.RiskRatingReliance,
			sqlmock.AnyArg(), // materiality_classification
			system.OwnerTeam, system.OwnerEmail,
			sqlmock.AnyArg(), // data_sources JSON
			system.ModelType, system.Version, system.DeploymentDate,
			sqlmock.AnyArg(), // metadata JSON
			sqlmock.AnyArg(), // updated_at
			system.UpdatedBy,
			system.OrgID, system.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, system)
	require.NoError(t, err)

	assert.False(t, system.UpdatedAt.IsZero())
	// 5+4+4 = 13 >= 12 -> high
	assert.Equal(t, MaterialityHigh, system.MaterialityClassification)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Update_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	system := &AISystemRegistry{
		ID:    "id-1",
		OrgID: "org-1",
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_ai_system_registry SET")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"org-1", "id-1",
		).
		WillReturnError(fmt.Errorf("deadlock detected"))
	mock.ExpectRollback()

	err = repo.Update(ctx, system)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update AI system")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Update_MaterialityMedium(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	system := &AISystemRegistry{
		ID:                   "id-1",
		OrgID:                "org-1",
		RiskRatingImpact:     3,
		RiskRatingComplexity: 3,
		RiskRatingReliance:   2,
	}

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_ai_system_registry SET")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"org-1", "id-1",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, system)
	require.NoError(t, err)
	// 3+3+2=8 -> medium
	assert.Equal(t, MaterialityMedium, system.MaterialityClassification)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// Delete Tests
// =============================================================================

func TestRegistryRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_ai_system_registry")).
		WithArgs(SystemStatusRetired, sqlmock.AnyArg(), "org-1", "id-1").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-1", "id-1")
	require.NoError(t, err)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_Delete_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_ai_system_registry")).
		WithArgs(SystemStatusRetired, sqlmock.AnyArg(), "org-1", "id-1").
		WillReturnError(fmt.Errorf("foreign key violation"))
	mock.ExpectRollback()

	err = repo.Delete(ctx, "org-1", "id-1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to delete AI system")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetSummary Tests
// =============================================================================

func TestRegistryRepository_GetSummary_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT\n\t\t\tCOUNT(*) as total")).
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "active", "high_mat", "medium_mat", "low_mat", "assessments_due",
		}).AddRow(10, 7, 2, 5, 3, 1))
	mock.ExpectCommit()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM mas_kill_switches")).
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	mock.ExpectCommit()

	summary, err := repo.GetSummary(ctx, "org-1")
	require.NoError(t, err)
	require.NotNil(t, summary)

	assert.Equal(t, "org-1", summary.OrgID)
	assert.Equal(t, 10, summary.TotalSystems)
	assert.Equal(t, 7, summary.ActiveSystems)
	assert.Equal(t, 2, summary.HighMateriality)
	assert.Equal(t, 5, summary.MediumMateriality)
	assert.Equal(t, 3, summary.LowMateriality)
	assert.Equal(t, 1, summary.AssessmentsDue)
	assert.Equal(t, 1, summary.KillSwitchesTriggered)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetSummary_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT\n\t\t\tCOUNT(*)")).
		WithArgs("org-1").
		WillReturnError(fmt.Errorf("connection lost"))
	mock.ExpectRollback()

	summary, err := repo.GetSummary(ctx, "org-1")
	assert.Error(t, err)
	assert.Nil(t, summary)
	assert.Contains(t, err.Error(), "failed to get registry summary")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_GetSummary_KillSwitchQueryFails(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT\n\t\t\tCOUNT(*) as total")).
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{
			"total", "active", "high_mat", "medium_mat", "low_mat", "assessments_due",
		}).AddRow(5, 3, 1, 2, 2, 0))
	mock.ExpectCommit()

	// Kill switch query fails (non-fatal in the code -- Scan error is ignored)
	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT COUNT(*) FROM mas_kill_switches")).
		WithArgs("org-1").
		WillReturnError(fmt.Errorf("table not found"))
	mock.ExpectRollback()

	summary, err := repo.GetSummary(ctx, "org-1")
	require.NoError(t, err)
	require.NotNil(t, summary)
	assert.Equal(t, 5, summary.TotalSystems)
	assert.Equal(t, 0, summary.KillSwitchesTriggered) // Default zero on error

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// CountByStatus Tests
// =============================================================================

func TestRegistryRepository_CountByStatus_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT status, COUNT(*) as count FROM mas_ai_system_registry")).
		WithArgs("org-1").
		WillReturnRows(sqlmock.NewRows([]string{"status", "count"}).
			AddRow(SystemStatusActive, 5).
			AddRow(SystemStatusDraft, 2).
			AddRow(SystemStatusRetired, 1))
	mock.ExpectCommit()

	counts, err := repo.CountByStatus(ctx, "org-1")
	require.NoError(t, err)
	require.NotNil(t, counts)

	assert.Equal(t, 5, counts[SystemStatusActive])
	assert.Equal(t, 2, counts[SystemStatusDraft])
	assert.Equal(t, 1, counts[SystemStatusRetired])
	assert.Equal(t, 0, counts[SystemStatusSuspended])

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_CountByStatus_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-empty").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT status, COUNT(*) as count")).
		WithArgs("org-empty").
		WillReturnRows(sqlmock.NewRows([]string{"status", "count"}))
	mock.ExpectCommit()

	counts, err := repo.CountByStatus(ctx, "org-empty")
	require.NoError(t, err)
	assert.Len(t, counts, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestRegistryRepository_CountByStatus_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresRegistryRepository(db)
	ctx := context.Background()

	// #3133: the statement now runs inside rls.WithOrgScope, which BEGINs
	// and pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-1").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT status, COUNT(*)")).
		WithArgs("org-1").
		WillReturnError(fmt.Errorf("query cancelled"))
	mock.ExpectRollback()

	counts, err := repo.CountByStatus(ctx, "org-1")
	assert.Error(t, err)
	assert.Nil(t, counts)
	assert.Contains(t, err.Error(), "failed to count by status")

	require.NoError(t, mock.ExpectationsWereMet())
}
