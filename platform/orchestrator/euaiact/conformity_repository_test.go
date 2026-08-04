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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var conformityColumns = []string{
	"id", "org_id", "system_id", "system_name", "risk_category", "status", "version",
	"assessment_date", "valid_until", "assessors", "requirements", "evidence",
	"findings", "risk_mitigation", "recommendations", "created_by", "created_at",
	"updated_at", "submitted_at", "submitted_by", "approved_at", "approved_by",
	"rejected_at", "rejected_by", "rejection_reason",
}

func sampleConformityRow(id, orgID string) []driver.Value {
	now := time.Now().UTC()
	validUntil := now.Add(365 * 24 * time.Hour)
	submittedAt := now.Add(-7 * 24 * time.Hour)
	return []driver.Value{
		id, orgID, "sys-001", "Credit Scoring System",
		string(RiskCategoryHighRisk), string(AssessmentStatusSubmitted), 1,
		now, &validUntil,
		[]byte(`["assessor1@example.com","assessor2@example.com"]`),
		[]byte(`[{"requirement_id":"R1","article":"Art.9","description":"Data governance","status":"compliant"}]`),
		[]byte(`[{"id":"ev1","type":"document","title":"Data governance policy"}]`),
		[]byte(`[{"id":"f1","severity":"minor","category":"documentation","description":"Incomplete logs"}]`),
		[]byte(`{"risk_acceptance":"approved","mitigation_plan":"Quarterly reviews"}`),
		[]byte(`["Improve logging","Enhance monitoring"]`),
		"creator@example.com", now, now,
		&submittedAt, "submitter@example.com",
		nil, "",
		nil, "", "",
	}
}

func TestConformityRepository_Create_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	assessment := &ConformityAssessment{
		ID:             "assess-001",
		OrgID:          "org-001",
		SystemID:       "sys-001",
		SystemName:     "Credit Scoring System",
		RiskCategory:   RiskCategoryHighRisk,
		Status:         AssessmentStatusDraft,
		Version:        1,
		AssessmentDate: now,
		Assessors:      []string{"assessor1@example.com"},
		Requirements: []RequirementStatus{
			{RequirementID: "R1", Article: "Art.9", Status: "compliant"},
		},
		Evidence: []EvidenceItem{
			{ID: "ev1", Type: "document", Title: "Policy doc"},
		},
		Findings: []Finding{
			{ID: "f1", Severity: "minor", Description: "Minor finding"},
		},
		RiskMitigation:  map[string]interface{}{"plan": "review"},
		Recommendations: []string{"Improve logging"},
		CreatedBy:       "creator@example.com",
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	expectOrgScope(mock, assessment.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_conformity_assessments`)).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	err = repo.Create(ctx, assessment)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_Create_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	assessment := &ConformityAssessment{
		ID:             "assess-001",
		OrgID:          "org-001",
		SystemID:       "sys-001",
		SystemName:     "Test",
		RiskCategory:   RiskCategoryMinimal,
		Status:         AssessmentStatusDraft,
		Version:        1,
		AssessmentDate: time.Now().UTC(),
		CreatedBy:      "test",
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	expectOrgScope(mock, assessment.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`INSERT INTO euaiact_conformity_assessments`)).
		WillReturnError(fmt.Errorf("duplicate key"))
	mock.ExpectRollback()

	err = repo.Create(ctx, assessment)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetByID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	rows := sqlmock.NewRows(conformityColumns).
		AddRow(sampleConformityRow("assess-001", "org-001")...)

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments
		WHERE id = $1 AND org_id = $2`)).
		WithArgs("assess-001", "org-001").
		WillReturnRows(rows)
	mock.ExpectCommit()

	assessment, err := repo.GetByID(ctx, "org-001", "assess-001")
	require.NoError(t, err)
	assert.Equal(t, "assess-001", assessment.ID)
	assert.Equal(t, "org-001", assessment.OrgID)
	assert.Equal(t, "sys-001", assessment.SystemID)
	assert.Equal(t, "Credit Scoring System", assessment.SystemName)
	assert.Equal(t, RiskCategoryHighRisk, assessment.RiskCategory)
	assert.Equal(t, AssessmentStatusSubmitted, assessment.Status)
	assert.Equal(t, 1, assessment.Version)
	assert.NotNil(t, assessment.ValidUntil)
	assert.Len(t, assessment.Assessors, 2)
	assert.NotEmpty(t, assessment.Requirements)
	assert.NotEmpty(t, assessment.Evidence)
	assert.NotEmpty(t, assessment.Findings)
	assert.NotEmpty(t, assessment.RiskMitigation)
	assert.NotEmpty(t, assessment.Recommendations)
	assert.Equal(t, "creator@example.com", assessment.CreatedBy)
	assert.NotNil(t, assessment.SubmittedAt)
	assert.Equal(t, "submitter@example.com", assessment.SubmittedBy)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetByID_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	// Post-#3241 a miss is ErrAssessmentNotFound, not (nil, nil): "no such id"
	// and "another organization's id" must be the SAME answer on the wire.
	assessment, err := repo.GetByID(ctx, "org-001", "nonexistent")
	assert.ErrorIs(t, err, ErrAssessmentNotFound)
	assert.Nil(t, assessment)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetByID_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`FROM euaiact_conformity_assessments`)).
		WithArgs("assess-001", "org-001").
		WillReturnError(fmt.Errorf("connection lost"))
	mock.ExpectRollback()

	assessment, err := repo.GetByID(ctx, "org-001", "assess-001")
	assert.Nil(t, assessment)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_List_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	// Count query
	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))

	// Data query
	dataRows := sqlmock.NewRows(conformityColumns).
		AddRow(sampleConformityRow("assess-001", "org-001")...).
		AddRow(sampleConformityRow("assess-002", "org-001")...)

	mock.ExpectQuery(`SELECT id, org_id`).
		WithArgs("org-001", 10, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	assessments, total, err := repo.List(ctx, "org-001", "", 10, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(2), total)
	assert.Len(t, assessments, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_List_WithStatusFilter(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001", AssessmentStatusSubmitted).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	dataRows := sqlmock.NewRows(conformityColumns).
		AddRow(sampleConformityRow("assess-001", "org-001")...)

	mock.ExpectQuery(`SELECT id, org_id`).
		WithArgs("org-001", AssessmentStatusSubmitted, 50, 0).
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	assessments, total, err := repo.List(ctx, "org-001", AssessmentStatusSubmitted, 50, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), total)
	assert.Len(t, assessments, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_List_DefaultLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))

	mock.ExpectQuery(`SELECT id, org_id`).
		WithArgs("org-001", 50, 0).
		WillReturnRows(sqlmock.NewRows(conformityColumns))
	mock.ExpectCommit()

	assessments, total, err := repo.List(ctx, "org-001", "", 0, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Empty(t, assessments)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_List_CountError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(`SELECT COUNT`).
		WithArgs("org-001").
		WillReturnError(fmt.Errorf("table missing"))
	mock.ExpectRollback()

	_, _, err = repo.List(ctx, "org-001", "", 10, 0)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_Update_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	now := time.Now().UTC()
	assessment := &ConformityAssessment{
		ID:           "assess-001",
		OrgID:        "org-001",
		SystemName:   "Updated System",
		RiskCategory: RiskCategoryHighRisk,
		Status:       AssessmentStatusApproved,
		Version:      2,
		Assessors:    []string{"updated-assessor"},
		Requirements: []RequirementStatus{
			{RequirementID: "R1", Status: "compliant"},
		},
		Evidence:        []EvidenceItem{},
		Findings:        []Finding{},
		RiskMitigation:  map[string]interface{}{},
		Recommendations: []string{},
		ApprovedAt:      &now,
		ApprovedBy:      "approver",
	}

	expectOrgScope(mock, assessment.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE euaiact_conformity_assessments`)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Update(ctx, assessment)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_Update_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	assessment := &ConformityAssessment{
		ID:           "assess-001",
		OrgID:        "org-001",
		SystemName:   "Test",
		RiskCategory: RiskCategoryMinimal,
		Status:       AssessmentStatusDraft,
		Version:      1,
	}

	expectOrgScope(mock, assessment.OrgID)
	mock.ExpectExec(regexp.QuoteMeta(`UPDATE euaiact_conformity_assessments`)).
		WillReturnError(fmt.Errorf("connection refused"))
	mock.ExpectRollback()

	err = repo.Update(ctx, assessment)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_Delete_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM euaiact_conformity_assessments WHERE id = $1 AND org_id = $2`)).
		WithArgs("assess-001", "org-001").
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	err = repo.Delete(ctx, "org-001", "assess-001")
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_Delete_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectExec(regexp.QuoteMeta(`DELETE FROM euaiact_conformity_assessments WHERE id = $1 AND org_id = $2`)).
		WithArgs("nonexistent", "org-001").
		WillReturnError(fmt.Errorf("database error"))
	mock.ExpectRollback()

	err = repo.Delete(ctx, "org-001", "nonexistent")
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetBySystemID_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	dataRows := sqlmock.NewRows(conformityColumns).
		AddRow(sampleConformityRow("assess-001", "org-001")...).
		AddRow(sampleConformityRow("assess-002", "org-001")...)

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND system_id = $2`)).
		WithArgs("org-001", "sys-001").
		WillReturnRows(dataRows)
	mock.ExpectCommit()

	assessments, err := repo.GetBySystemID(ctx, "org-001", "sys-001")
	require.NoError(t, err)
	assert.Len(t, assessments, 2)
	assert.Equal(t, "assess-001", assessments[0].ID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetBySystemID_Empty(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND system_id = $2`)).
		WithArgs("org-001", "sys-nonexistent").
		WillReturnRows(sqlmock.NewRows(conformityColumns))
	mock.ExpectCommit()

	assessments, err := repo.GetBySystemID(ctx, "org-001", "sys-nonexistent")
	require.NoError(t, err)
	assert.Empty(t, assessments)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestConformityRepository_GetBySystemID_QueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	repo := NewPostgresConformityRepository(db)
	ctx := context.Background()

	expectOrgScope(mock, "org-001")
	mock.ExpectQuery(regexp.QuoteMeta(`WHERE org_id = $1 AND system_id = $2`)).
		WithArgs("org-001", "sys-001").
		WillReturnError(fmt.Errorf("timeout"))
	mock.ExpectRollback()

	assessments, err := repo.GetBySystemID(ctx, "org-001", "sys-001")
	assert.Nil(t, assessments)
	assert.Error(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}
