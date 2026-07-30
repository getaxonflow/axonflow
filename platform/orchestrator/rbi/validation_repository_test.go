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

var validationColumns = []string{
	"id", "org_id", "system_id", "validation_type", "validator_type",
	"validator_name", "validator_organization", "validator_credentials",
	"validation_date", "validation_period_start", "validation_period_end",
	"dataset_description", "dataset_size", "dataset_characteristics",
	"methodology", "test_scenarios", "findings", "accuracy_metrics",
	"bias_assessment", "bias_categories_tested", "stress_test_results",
	"stress_test_passed", "recommendation", "conditions",
	"next_review_date", "remediation_required", "remediation_deadline",
	"report_file_path", "report_file_checksum", "created_at", "updated_at",
}

func sampleValidationRow(id, orgID, systemID string) []driver.Value {
	now := time.Now().UTC()
	periodStart := now.Add(-30 * 24 * time.Hour)
	periodEnd := now
	nextReview := now.Add(90 * 24 * time.Hour)
	stressPassed := true
	return []driver.Value{
		id, orgID, systemID,
		"independent", "external_auditor",
		"John Auditor",
		sql.NullString{String: "Big4 Audit Firm", Valid: true},
		sql.NullString{String: "CISA, CRISC", Valid: true},
		now,
		sql.NullTime{Time: periodStart, Valid: true},
		sql.NullTime{Time: periodEnd, Valid: true},
		sql.NullString{String: "Production transactions", Valid: true},
		sql.NullInt32{Int32: 10000, Valid: true},
		[]byte(`{"demographic_coverage":"95%"}`),
		sql.NullString{String: "Statistical sampling", Valid: true},
		[]byte(`["scenario1","scenario2"]`),
		[]byte(`[{"id":"f1","category":"bias","severity":"medium","title":"Gender bias found"}]`),
		[]byte(`{"accuracy":0.95,"precision":0.92}`),
		[]byte(`{"gender":0.03,"age":0.05}`),
		[]byte(`["gender","age","income"]`),
		[]byte(`{"peak_load":"passed","failover":"passed"}`),
		sql.NullBool{Bool: stressPassed, Valid: true},
		"approve",
		sql.NullString{String: "Minor remediation needed", Valid: true},
		sql.NullTime{Time: nextReview, Valid: true},
		true,
		sql.NullTime{Time: now.Add(30 * 24 * time.Hour), Valid: true},
		sql.NullString{String: "/reports/validation-001.pdf", Valid: true},
		sql.NullString{String: "sha256:abcdef1234567890", Valid: true},
		now, now,
	}
}

func TestValidationRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	validation := &ModelValidation{
		OrgID:          "org-001",
		SystemID:       "sys-001",
		ValidationType: ValidationTypeIndependent,
		ValidatorType:  ValidatorTypeExternalAuditor,
		ValidatorName:  "John Auditor",
		ValidationDate: time.Now().UTC(),
		Recommendation: ValidationRecommendationApprove,
		Findings: []ValidationFinding{
			{ID: "f1", Category: "bias", Severity: "low", Title: "Minor issue"},
		},
		AccuracyMetrics: map[string]float64{"accuracy": 0.95},
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_model_validations`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, validation)
	assert.NoError(t, err)
	assert.NotEmpty(t, validation.ID)
	assert.False(t, validation.CreatedAt.IsZero())
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Create_PresetID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	validation := &ModelValidation{
		ID:             "preset-val-id",
		OrgID:          "org-001",
		SystemID:       "sys-001",
		ValidationType: ValidationTypeDevelopment,
		ValidatorType:  ValidatorTypeInternal,
		ValidatorName:  "Dev Team",
		ValidationDate: time.Now().UTC(),
		Recommendation: ValidationRecommendationApprove,
		CreatedAt:      time.Now().UTC(),
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_model_validations`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, validation)
	assert.NoError(t, err)
	assert.Equal(t, "preset-val-id", validation.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	validation := &ModelValidation{
		OrgID:          "org-001",
		SystemID:       "sys-001",
		ValidationType: ValidationTypeDevelopment,
		ValidatorType:  ValidatorTypeInternal,
		ValidatorName:  "Dev Team",
		ValidationDate: time.Now().UTC(),
		Recommendation: ValidationRecommendationApprove,
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO rbi_model_validations`)).
		WillReturnError(fmt.Errorf("duplicate key"))
	// The statement errors out of the closure, so the wrap ROLLBACKs.
	mock.ExpectRollback()

	err = repo.Create(ctx, validation)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insert validation")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Get_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-001", "org-001", "sys-001")...)

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "val-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	v, err := repo.Get(ctx, "org-001", "val-001")
	require.NoError(t, err)
	assert.Equal(t, "val-001", v.ID)
	assert.Equal(t, "org-001", v.OrgID)
	assert.Equal(t, "sys-001", v.SystemID)
	assert.Equal(t, ValidationType("independent"), v.ValidationType)
	assert.Equal(t, ValidatorType("external_auditor"), v.ValidatorType)
	assert.Equal(t, "John Auditor", v.ValidatorName)
	assert.Equal(t, "Big4 Audit Firm", v.ValidatorOrganization)
	assert.Equal(t, "CISA, CRISC", v.ValidatorCredentials)
	assert.Equal(t, 10000, v.DatasetSize)
	assert.Equal(t, "Statistical sampling", v.Methodology)
	assert.NotNil(t, v.StressTestPassed)
	assert.True(t, *v.StressTestPassed)
	assert.Equal(t, ValidationRecommendation("approve"), v.Recommendation)
	assert.True(t, v.RemediationRequired)
	assert.NotNil(t, v.ValidationPeriodStart)
	assert.NotNil(t, v.NextReviewDate)
	assert.NotNil(t, v.RemediationDeadline)
	assert.NotEmpty(t, v.ReportFilePath)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Get_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "nonexistent").
		WillReturnError(sql.ErrNoRows)
	// The statement errors out of the closure, so the wrap ROLLBACKs.
	mock.ExpectRollback()

	v, err := repo.Get(ctx, "org-001", "nonexistent")
	assert.Nil(t, v)
	assert.ErrorIs(t, err, ErrValidationNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Get_ScanError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "val-001").
		WillReturnError(fmt.Errorf("connection reset"))
	// The statement errors out of the closure, so the wrap ROLLBACKs.
	mock.ExpectRollback()

	v, err := repo.Get(ctx, "org-001", "val-001")
	assert.Nil(t, v)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "scan validation")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	params := &ListValidationsParams{
		Limit:  10,
		Offset: 0,
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	dataRows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-001", "org-001", "sys-001")...).
		AddRow(sampleValidationRow("val-002", "org-001", "sys-002")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	validations, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, validations, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_List_WithFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	params := &ListValidationsParams{
		SystemID:       "sys-001",
		ValidationType: "independent",
		ValidatorType:  "external_auditor",
		Recommendation: "approve",
		Limit:          20,
		Offset:         5,
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "sys-001", "independent", "external_auditor", "approve").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-001", "org-001", "sys-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "sys-001", "independent", "external_auditor", "approve", 20, 5).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	validations, total, err := repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, validations, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_List_NilParams(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", 20, 0).
		WillReturnRows(sqlmock.NewRows(validationColumns))
	mock.ExpectCommit()

	validations, total, err := repo.List(ctx, "org-001", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, validations)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_List_LimitCapping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	params := &ListValidationsParams{Limit: 500}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
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
		WillReturnRows(sqlmock.NewRows(validationColumns))
	mock.ExpectCommit()

	_, _, err = repo.List(ctx, "org-001", params)
	require.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_List_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table not found"))
	// The statement errors out of the closure, so the wrap ROLLBACKs.
	mock.ExpectRollback()

	_, _, err = repo.List(ctx, "org-001", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "count validations")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_ListBySystem_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// ListBySystem calls List internally
	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", "sys-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-001", "org-001", "sys-001")...)

	mock.ExpectQuery(`SELECT`).
		WithArgs("org-001", "sys-001", 100, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	validations, err := repo.ListBySystem(ctx, "org-001", "sys-001")
	require.NoError(t, err)
	assert.Len(t, validations, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	validation := &ModelValidation{
		ID:             "val-001",
		OrgID:          "org-001",
		SystemID:       "sys-001",
		ValidationType: ValidationTypeIndependent,
		ValidatorType:  ValidatorTypeExternalAuditor,
		ValidatorName:  "Updated Auditor",
		ValidationDate: time.Now().UTC(),
		Recommendation: ValidationRecommendationConditional,
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_model_validations SET`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, validation)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Update_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	validation := &ModelValidation{
		ID:             "nonexistent",
		OrgID:          "org-001",
		SystemID:       "sys-001",
		ValidationType: ValidationTypeDevelopment,
		ValidatorType:  ValidatorTypeInternal,
		ValidatorName:  "Test",
		ValidationDate: time.Now().UTC(),
		Recommendation: ValidationRecommendationApprove,
	}

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE rbi_model_validations SET`)).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// RowsAffected() == 0 is not a statement error: the wrap COMMITs and the
	// not-found verdict is decided above the transaction.
	mock.ExpectCommit()

	err = repo.Update(ctx, validation)
	assert.ErrorIs(t, err, ErrValidationNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_model_validations WHERE org_id = $1 AND id = $2`)).
		WithArgs("org-001", "val-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "val-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_Delete_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM rbi_model_validations WHERE org_id = $1 AND id = $2`)).
		WithArgs("org-001", "nonexistent").
		WillReturnResult(sqlmock.NewResult(0, 0))
	// RowsAffected() == 0 is not a statement error: the wrap COMMITs and the
	// not-found verdict is decided above the transaction.
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrValidationNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_GetLatestBySystem_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-latest", "org-001", "sys-001")...)

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "sys-001", string(ValidationTypeIndependent)).
		WillReturnRows(rows)
	mock.ExpectCommit()

	v, err := repo.GetLatestBySystem(ctx, "org-001", "sys-001", ValidationTypeIndependent)
	require.NoError(t, err)
	assert.Equal(t, "val-latest", v.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_GetLatestBySystem_EmptyType(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(validationColumns).
		AddRow(sampleValidationRow("val-latest", "org-001", "sys-001")...)

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	v, err := repo.GetLatestBySystem(ctx, "org-001", "sys-001", "")
	require.NoError(t, err)
	assert.Equal(t, "val-latest", v.ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestValidationRepository_GetLatestBySystem_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresModelValidationRepository(db)
	ctx := context.Background()

	// #3103: the statement runs inside rls.WithOrgScope, which BEGINs and
	// pins app.current_org_id before the real SQL.
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs("org-001").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(regexp.QuoteMeta(`SELECT`)).
		WithArgs("org-001", "sys-001", string(ValidationTypeStressTest)).
		WillReturnError(sql.ErrNoRows)
	// The statement errors out of the closure, so the wrap ROLLBACKs.
	mock.ExpectRollback()

	v, err := repo.GetLatestBySystem(ctx, "org-001", "sys-001", ValidationTypeStressTest)
	assert.Nil(t, v)
	assert.ErrorIs(t, err, ErrValidationNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}
