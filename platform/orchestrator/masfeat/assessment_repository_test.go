// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"encoding/json"
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

func TestNewPostgresAssessmentRepository(t *testing.T) {
	db, _, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	require.NotNil(t, repo)
	assert.Equal(t, db, repo.db)
}

func TestNewPostgresAssessmentRepository_NilDB(t *testing.T) {
	repo := NewPostgresAssessmentRepository(nil)
	require.NotNil(t, repo)
	assert.Nil(t, repo.db)
}

// =============================================================================
// Create Tests
// =============================================================================

func TestAssessmentRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	fairnessScore := 85.0
	ethicsScore := 90.0
	accountabilityScore := 78.0
	transparencyScore := 88.0
	overallScore := 85.25

	validUntil := time.Now().Add(365 * 24 * time.Hour)
	assessment := &FEATAssessment{
		OrgID:               "org-1",
		SystemID:            "sys-1",
		AssessmentType:      "initial",
		Status:              FEATStatusPending,
		AssessmentDate:      time.Now().UTC(),
		ValidUntil:          &validUntil,
		FairnessScore:       &fairnessScore,
		EthicsScore:         &ethicsScore,
		AccountabilityScore: &accountabilityScore,
		TransparencyScore:   &transparencyScore,
		OverallScore:        &overallScore,
		Findings: []Finding{
			{ID: "f-1", Pillar: PillarFairness, Severity: "minor", Description: "Minor bias detected"},
		},
		Recommendations: []string{"Increase sample diversity"},
		Assessors:       []string{"assessor@bank.com"},
		CreatedBy:       "admin@bank.com",
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_feat_assessments")).
		WithArgs(
			sqlmock.AnyArg(), // id
			assessment.OrgID, assessment.SystemID, assessment.AssessmentType,
			assessment.Status, 1, // version
			assessment.AssessmentDate, assessment.ValidUntil,
			assessment.FairnessScore, assessment.EthicsScore,
			assessment.AccountabilityScore, assessment.TransparencyScore,
			assessment.OverallScore,
			sqlmock.AnyArg(), // findings JSON
			sqlmock.AnyArg(), // recommendations JSON
			sqlmock.AnyArg(), // assessors JSON
			assessment.CreatedBy,
			sqlmock.AnyArg(), // created_at
			sqlmock.AnyArg(), // updated_at
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Create(ctx, assessment)
	require.NoError(t, err)

	assert.NotEmpty(t, assessment.ID)
	assert.Equal(t, 1, assessment.Version)
	assert.False(t, assessment.CreatedAt.IsZero())
	assert.Equal(t, assessment.CreatedAt, assessment.UpdatedAt)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_Create_WithExistingID(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	assessment := &FEATAssessment{
		ID:             "pre-set-id",
		OrgID:          "org-1",
		SystemID:       "sys-1",
		AssessmentType: "periodic",
		Status:         FEATStatusInProgress,
		AssessmentDate: time.Now().UTC(),
		Assessors:      []string{},
		CreatedBy:      "admin",
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_feat_assessments")).
		WithArgs(
			"pre-set-id",
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Create(ctx, assessment)
	require.NoError(t, err)
	assert.Equal(t, "pre-set-id", assessment.ID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	assessment := &FEATAssessment{
		OrgID:          "org-1",
		SystemID:       "sys-1",
		AssessmentType: "initial",
		Status:         FEATStatusPending,
		AssessmentDate: time.Now().UTC(),
		Assessors:      []string{},
		CreatedBy:      "admin",
	}

	mock.ExpectExec(regexp.QuoteMeta("INSERT INTO mas_feat_assessments")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnError(fmt.Errorf("foreign key constraint: system_id not found"))

	err = repo.Create(ctx, assessment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to insert FEAT assessment")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetByID Tests
// =============================================================================

func assessmentColumns() []string {
	return []string{
		"id", "org_id", "system_id", "assessment_type", "status", "version",
		"assessment_date", "valid_until", "fairness_score", "ethics_score",
		"accountability_score", "transparency_score", "overall_score",
		"findings", "recommendations", "assessors", "created_by", "created_at", "updated_at",
		"submitted_at", "submitted_by", "approved_at", "approved_by",
		"rejected_at", "rejected_by", "rejection_reason",
	}
}

func TestAssessmentRepository_GetByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	validUntil := now.Add(365 * 24 * time.Hour)
	submittedAt := now.Add(-24 * time.Hour)
	approvedAt := now.Add(-1 * time.Hour)

	findingsJSON, _ := json.Marshal([]Finding{
		{ID: "f-1", Pillar: PillarFairness, Severity: "minor", Description: "Test finding"},
	})
	recommendationsJSON, _ := json.Marshal([]string{"Rec 1", "Rec 2"})
	assessorsJSON, _ := json.Marshal([]string{"assessor@bank.com"})

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "asmt-1").
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).AddRow(
			"asmt-1", "org-1", "sys-1", "initial", FEATStatusApproved, 2,
			now, validUntil, 85.0, 90.0, 78.0, 88.0, 85.25,
			findingsJSON, recommendationsJSON, assessorsJSON, "admin",
			now, now, submittedAt, "submitter@bank.com",
			approvedAt, "approver@bank.com", nil, nil, nil,
		))

	assessment, err := repo.GetByID(ctx, "org-1", "asmt-1")
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Equal(t, "asmt-1", assessment.ID)
	assert.Equal(t, "org-1", assessment.OrgID)
	assert.Equal(t, "sys-1", assessment.SystemID)
	assert.Equal(t, "initial", assessment.AssessmentType)
	assert.Equal(t, FEATStatusApproved, assessment.Status)
	assert.Equal(t, 2, assessment.Version)
	require.NotNil(t, assessment.ValidUntil)
	require.NotNil(t, assessment.FairnessScore)
	assert.Equal(t, 85.0, *assessment.FairnessScore)
	require.NotNil(t, assessment.EthicsScore)
	assert.Equal(t, 90.0, *assessment.EthicsScore)
	require.NotNil(t, assessment.AccountabilityScore)
	assert.Equal(t, 78.0, *assessment.AccountabilityScore)
	require.NotNil(t, assessment.TransparencyScore)
	assert.Equal(t, 88.0, *assessment.TransparencyScore)
	require.NotNil(t, assessment.OverallScore)
	assert.Equal(t, 85.25, *assessment.OverallScore)
	assert.Len(t, assessment.Findings, 1)
	assert.Len(t, assessment.Recommendations, 2)
	assert.Len(t, assessment.Assessors, 1)
	require.NotNil(t, assessment.SubmittedAt)
	assert.Equal(t, "submitter@bank.com", assessment.SubmittedBy)
	require.NotNil(t, assessment.ApprovedAt)
	assert.Equal(t, "approver@bank.com", assessment.ApprovedBy)
	assert.Nil(t, assessment.RejectedAt)
	assert.Empty(t, assessment.RejectedBy)
	assert.Empty(t, assessment.RejectionReason)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", "nonexistent").
		WillReturnError(sql.ErrNoRows)

	assessment, err := repo.GetByID(ctx, "org-1", "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, assessment)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetByID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id")).
		WithArgs("org-1", "asmt-1").
		WillReturnError(fmt.Errorf("connection refused"))

	assessment, err := repo.GetByID(ctx, "org-1", "asmt-1")
	assert.Error(t, err)
	assert.Nil(t, assessment)
	assert.Contains(t, err.Error(), "failed to get FEAT assessment")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetByID_NullableFields(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// All nullable fields are nil
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id")).
		WithArgs("org-1", "asmt-1").
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).AddRow(
			"asmt-1", "org-1", "sys-1", "ad_hoc", FEATStatusPending, 1,
			now, nil, nil, nil, nil, nil, nil,
			nil, nil, nil, "admin",
			now, now, nil, nil, nil, nil, nil, nil, nil,
		))

	assessment, err := repo.GetByID(ctx, "org-1", "asmt-1")
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Nil(t, assessment.ValidUntil)
	assert.Nil(t, assessment.FairnessScore)
	assert.Nil(t, assessment.EthicsScore)
	assert.Nil(t, assessment.AccountabilityScore)
	assert.Nil(t, assessment.TransparencyScore)
	assert.Nil(t, assessment.OverallScore)
	assert.Nil(t, assessment.Findings)
	assert.Nil(t, assessment.Recommendations)
	assert.Nil(t, assessment.Assessors)
	assert.Nil(t, assessment.SubmittedAt)
	assert.Empty(t, assessment.SubmittedBy)
	assert.Nil(t, assessment.ApprovedAt)
	assert.Empty(t, assessment.ApprovedBy)
	assert.Nil(t, assessment.RejectedAt)
	assert.Empty(t, assessment.RejectedBy)
	assert.Empty(t, assessment.RejectionReason)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetByID_RejectedAssessment(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()
	rejectedAt := now.Add(-2 * time.Hour)

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id")).
		WithArgs("org-1", "asmt-1").
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).AddRow(
			"asmt-1", "org-1", "sys-1", "periodic", FEATStatusRejected, 3,
			now, nil, 50.0, 60.0, 40.0, 55.0, 51.25,
			nil, nil, nil, "admin",
			now, now, nil, nil, nil, nil,
			rejectedAt, "reviewer@bank.com", "Insufficient evidence for fairness claims",
		))

	assessment, err := repo.GetByID(ctx, "org-1", "asmt-1")
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Equal(t, FEATStatusRejected, assessment.Status)
	require.NotNil(t, assessment.RejectedAt)
	assert.Equal(t, "reviewer@bank.com", assessment.RejectedBy)
	assert.Equal(t, "Insufficient evidence for fairness claims", assessment.RejectionReason)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// List Tests
// =============================================================================

func TestAssessmentRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id, system_id")).
		WithArgs("org-1", 50, 0).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).
			AddRow(
				"asmt-1", "org-1", "sys-1", "initial", FEATStatusCompleted, 1,
				now, nil, 85.0, 90.0, 78.0, 88.0, 85.25,
				nil, nil, nil, "admin",
				now, now, nil, nil, nil, nil, nil, nil, nil,
			).
			AddRow(
				"asmt-2", "org-1", "sys-2", "periodic", FEATStatusPending, 1,
				now, nil, nil, nil, nil, nil, nil,
				nil, nil, nil, "admin",
				now, now, nil, nil, nil, nil, nil, nil, nil,
			))

	assessments, err := repo.List(ctx, "org-1", ListParams{})
	require.NoError(t, err)
	require.Len(t, assessments, 2)

	assert.Equal(t, "asmt-1", assessments[0].ID)
	assert.Equal(t, FEATStatusCompleted, assessments[0].Status)
	require.NotNil(t, assessments[0].FairnessScore)

	assert.Equal(t, "asmt-2", assessments[1].ID)
	assert.Equal(t, FEATStatusPending, assessments[1].Status)
	assert.Nil(t, assessments[1].FairnessScore)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_WithStatusFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("AND status = $2")).
		WithArgs("org-1", "completed", 20, 0).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).
			AddRow(
				"asmt-1", "org-1", "sys-1", "initial", FEATStatusCompleted, 1,
				now, nil, 85.0, 90.0, 78.0, 88.0, 85.25,
				nil, nil, nil, "admin",
				now, now, nil, nil, nil, nil, nil, nil, nil,
			))

	assessments, err := repo.List(ctx, "org-1", ListParams{
		Limit:  20,
		Status: "completed",
	})
	require.NoError(t, err)
	require.Len(t, assessments, 1)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_WithSystemIDFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	mock.ExpectQuery(regexp.QuoteMeta("AND system_id = $2")).
		WithArgs("org-1", "sys-credit", 50, 0).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).
			AddRow(
				"asmt-1", "org-1", "sys-credit", "initial", FEATStatusApproved, 2,
				now, nil, 92.0, 95.0, 88.0, 91.0, 91.5,
				nil, nil, nil, "admin",
				now, now, nil, nil, nil, nil, nil, nil, nil,
			))

	assessments, err := repo.List(ctx, "org-1", ListParams{
		SystemID: "sys-credit",
	})
	require.NoError(t, err)
	require.Len(t, assessments, 1)
	assert.Equal(t, "sys-credit", assessments[0].SystemID)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_WithStatusAndSystemIDFilters(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	// When both status and system_id filters are provided
	mock.ExpectQuery(regexp.QuoteMeta("AND status = $2")).
		WithArgs("org-1", "approved", "sys-1", 10, 5).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()))

	assessments, err := repo.List(ctx, "org-1", ListParams{
		Limit:    10,
		Offset:   5,
		Status:   "approved",
		SystemID: "sys-1",
	})
	require.NoError(t, err)
	assert.Len(t, assessments, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_LimitClamping(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	// Limit > MaxListLimit should be clamped
	mock.ExpectQuery("SELECT").
		WithArgs("org-1", MaxListLimit, 0).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()))

	assessments, err := repo.List(ctx, "org-1", ListParams{Limit: 9999})
	require.NoError(t, err)
	assert.Len(t, assessments, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_NegativeLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", DefaultListLimit, 0).
		WillReturnRows(sqlmock.NewRows(assessmentColumns()))

	assessments, err := repo.List(ctx, "org-1", ListParams{Limit: -5})
	require.NoError(t, err)
	assert.Len(t, assessments, 0)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_List_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery("SELECT").
		WithArgs("org-1", DefaultListLimit, 0).
		WillReturnError(fmt.Errorf("permission denied"))

	assessments, err := repo.List(ctx, "org-1", ListParams{})
	assert.Error(t, err)
	assert.Nil(t, assessments)
	assert.Contains(t, err.Error(), "failed to list FEAT assessments")

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// Update Tests
// =============================================================================

func TestAssessmentRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	fairnessScore := 92.0
	submittedAt := time.Now().UTC()
	assessment := &FEATAssessment{
		ID:              "asmt-1",
		OrgID:           "org-1",
		Status:          FEATStatusCompleted,
		Version:         1,
		FairnessScore:   &fairnessScore,
		Findings:        []Finding{{ID: "f-1", Pillar: PillarFairness, Severity: "observation"}},
		Recommendations: []string{"Continue monitoring"},
		Assessors:       []string{"assessor@bank.com"},
		SubmittedAt:     &submittedAt,
		SubmittedBy:     "submitter@bank.com",
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_feat_assessments SET")).
		WithArgs(
			assessment.Status, 2, // version incremented
			assessment.ValidUntil,
			assessment.FairnessScore, assessment.EthicsScore,
			assessment.AccountabilityScore, assessment.TransparencyScore,
			assessment.OverallScore,
			sqlmock.AnyArg(), // findings JSON
			sqlmock.AnyArg(), // recommendations JSON
			sqlmock.AnyArg(), // assessors JSON
			sqlmock.AnyArg(), // updated_at
			assessment.SubmittedAt, assessment.SubmittedBy,
			assessment.ApprovedAt, assessment.ApprovedBy,
			assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason,
			assessment.OrgID, assessment.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Update(ctx, assessment)
	require.NoError(t, err)

	assert.Equal(t, 2, assessment.Version)
	assert.False(t, assessment.UpdatedAt.IsZero())

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_Update_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	assessment := &FEATAssessment{
		ID:        "asmt-1",
		OrgID:     "org-1",
		Status:    FEATStatusCompleted,
		Version:   1,
		Assessors: []string{},
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_feat_assessments SET")).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"org-1", "asmt-1",
		).
		WillReturnError(fmt.Errorf("deadlock detected"))

	err = repo.Update(ctx, assessment)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to update FEAT assessment")

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_Update_VersionIncrement(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	assessment := &FEATAssessment{
		ID:        "asmt-1",
		OrgID:     "org-1",
		Version:   5,
		Assessors: []string{},
	}

	mock.ExpectExec(regexp.QuoteMeta("UPDATE mas_feat_assessments SET")).
		WithArgs(
			sqlmock.AnyArg(), 6, // version 5 -> 6
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			"org-1", "asmt-1",
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err = repo.Update(ctx, assessment)
	require.NoError(t, err)
	assert.Equal(t, 6, assessment.Version)

	require.NoError(t, mock.ExpectationsWereMet())
}

// =============================================================================
// GetLatestForSystem Tests
// =============================================================================

func TestAssessmentRepository_GetLatestForSystem_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// First query: get ID of latest assessment
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_feat_assessments WHERE org_id = $1 AND system_id = $2 ORDER BY created_at DESC LIMIT 1")).
		WithArgs("org-1", "sys-1").
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow("asmt-latest"))

	// Second query: GetByID
	mock.ExpectQuery(regexp.QuoteMeta("SELECT id, org_id")).
		WithArgs("org-1", "asmt-latest").
		WillReturnRows(sqlmock.NewRows(assessmentColumns()).AddRow(
			"asmt-latest", "org-1", "sys-1", "periodic", FEATStatusCompleted, 3,
			now, nil, 95.0, 92.0, 88.0, 90.0, 91.25,
			nil, nil, nil, "admin",
			now, now, nil, nil, nil, nil, nil, nil, nil,
		))

	assessment, err := repo.GetLatestForSystem(ctx, "org-1", "sys-1")
	require.NoError(t, err)
	require.NotNil(t, assessment)

	assert.Equal(t, "asmt-latest", assessment.ID)
	assert.Equal(t, 3, assessment.Version)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetLatestForSystem_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_feat_assessments WHERE org_id = $1 AND system_id = $2")).
		WithArgs("org-1", "sys-new").
		WillReturnError(sql.ErrNoRows)

	assessment, err := repo.GetLatestForSystem(ctx, "org-1", "sys-new")
	require.NoError(t, err)
	assert.Nil(t, assessment)

	require.NoError(t, mock.ExpectationsWereMet())
}

func TestAssessmentRepository_GetLatestForSystem_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresAssessmentRepository(db)
	ctx := context.Background()

	mock.ExpectQuery(regexp.QuoteMeta("SELECT id FROM mas_feat_assessments")).
		WithArgs("org-1", "sys-1").
		WillReturnError(fmt.Errorf("connection reset"))

	assessment, err := repo.GetLatestForSystem(ctx, "org-1", "sys-1")
	assert.Error(t, err)
	assert.Nil(t, assessment)
	assert.Contains(t, err.Error(), "failed to get latest assessment")

	require.NoError(t, mock.ExpectationsWereMet())
}
