// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"axonflow/platform/agent/rls"
)

// #3133. Migration 400 RLS-gates mas_feat_assessments with `FOR ALL USING
// (org_id = get_current_org_id()) WITH CHECK (org_id = get_current_org_id())`,
// but this package never set app.current_org_id. Every statement below now
// runs inside rls.WithOrgScope; the hand-written `WHERE org_id = $n`
// predicates are KEPT as an additive backstop. See the fuller note in
// killswitch_repository.go.

// AssessmentRepository defines the interface for FEAT assessment data access.
type AssessmentRepository interface {
	// Create creates a new FEAT assessment.
	Create(ctx context.Context, assessment *FEATAssessment) error

	// GetByID retrieves a FEAT assessment by ID.
	GetByID(ctx context.Context, orgID, id string) (*FEATAssessment, error)

	// List lists FEAT assessments for an organization.
	List(ctx context.Context, orgID string, params ListParams) ([]*FEATAssessment, error)

	// Update updates a FEAT assessment.
	Update(ctx context.Context, assessment *FEATAssessment) error

	// GetLatestForSystem gets the latest assessment for a system.
	GetLatestForSystem(ctx context.Context, orgID, systemID string) (*FEATAssessment, error)
}

// PostgresAssessmentRepository implements AssessmentRepository using PostgreSQL.
type PostgresAssessmentRepository struct {
	db *sql.DB
}

// NewPostgresAssessmentRepository creates a new PostgreSQL assessment repository.
func NewPostgresAssessmentRepository(db *sql.DB) *PostgresAssessmentRepository {
	return &PostgresAssessmentRepository{db: db}
}

// Create creates a new FEAT assessment.
func (r *PostgresAssessmentRepository) Create(ctx context.Context, assessment *FEATAssessment) error {
	if assessment.ID == "" {
		assessment.ID = uuid.New().String()
	}
	assessment.CreatedAt = time.Now().UTC()
	assessment.UpdatedAt = assessment.CreatedAt
	assessment.Version = 1

	findingsJSON, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	recommendationsJSON, err := json.Marshal(assessment.Recommendations)
	if err != nil {
		return fmt.Errorf("failed to marshal recommendations: %w", err)
	}

	assessorsJSON, err := json.Marshal(assessment.Assessors)
	if err != nil {
		return fmt.Errorf("failed to marshal assessors: %w", err)
	}

	query := `
		INSERT INTO mas_feat_assessments (
			id, org_id, system_id, assessment_type, status, version,
			assessment_date, valid_until, fairness_score, ethics_score,
			accountability_score, transparency_score, overall_score,
			findings, recommendations, assessors, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
		)
	`

	err = rls.WithOrgScope(ctx, r.db, assessment.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			assessment.ID, assessment.OrgID, assessment.SystemID, assessment.AssessmentType,
			assessment.Status, assessment.Version, assessment.AssessmentDate, assessment.ValidUntil,
			assessment.FairnessScore, assessment.EthicsScore, assessment.AccountabilityScore,
			assessment.TransparencyScore, assessment.OverallScore, findingsJSON, recommendationsJSON,
			assessorsJSON, assessment.CreatedBy, assessment.CreatedAt, assessment.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to insert FEAT assessment: %w", err)
	}

	return nil
}

// GetByID retrieves a FEAT assessment by ID.
func (r *PostgresAssessmentRepository) GetByID(ctx context.Context, orgID, id string) (*FEATAssessment, error) {
	query := `
		SELECT id, org_id, system_id, assessment_type, status, version,
			assessment_date, valid_until, fairness_score, ethics_score,
			accountability_score, transparency_score, overall_score,
			findings, recommendations, assessors, created_by, created_at, updated_at,
			submitted_at, submitted_by, approved_at, approved_by,
			rejected_at, rejected_by, rejection_reason
		FROM mas_feat_assessments
		WHERE org_id = $1 AND id = $2
	`

	assessment := &FEATAssessment{}
	var findingsJSON, recommendationsJSON, assessorsJSON []byte
	var validUntil, submittedAt, approvedAt, rejectedAt sql.NullTime
	var submittedBy, approvedBy, rejectedBy, rejectionReason sql.NullString
	var fairnessScore, ethicsScore, accountabilityScore, transparencyScore, overallScore sql.NullFloat64

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, id).Scan(
			&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.AssessmentType,
			&assessment.Status, &assessment.Version, &assessment.AssessmentDate, &validUntil,
			&fairnessScore, &ethicsScore, &accountabilityScore, &transparencyScore, &overallScore,
			&findingsJSON, &recommendationsJSON, &assessorsJSON, &assessment.CreatedBy,
			&assessment.CreatedAt, &assessment.UpdatedAt, &submittedAt, &submittedBy,
			&approvedAt, &approvedBy, &rejectedAt, &rejectedBy, &rejectionReason,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get FEAT assessment: %w", err)
	}

	// Handle nullable fields
	if validUntil.Valid {
		assessment.ValidUntil = &validUntil.Time
	}
	if fairnessScore.Valid {
		assessment.FairnessScore = &fairnessScore.Float64
	}
	if ethicsScore.Valid {
		assessment.EthicsScore = &ethicsScore.Float64
	}
	if accountabilityScore.Valid {
		assessment.AccountabilityScore = &accountabilityScore.Float64
	}
	if transparencyScore.Valid {
		assessment.TransparencyScore = &transparencyScore.Float64
	}
	if overallScore.Valid {
		assessment.OverallScore = &overallScore.Float64
	}
	if submittedAt.Valid {
		assessment.SubmittedAt = &submittedAt.Time
	}
	if submittedBy.Valid {
		assessment.SubmittedBy = submittedBy.String
	}
	if approvedAt.Valid {
		assessment.ApprovedAt = &approvedAt.Time
	}
	if approvedBy.Valid {
		assessment.ApprovedBy = approvedBy.String
	}
	if rejectedAt.Valid {
		assessment.RejectedAt = &rejectedAt.Time
	}
	if rejectedBy.Valid {
		assessment.RejectedBy = rejectedBy.String
	}
	if rejectionReason.Valid {
		assessment.RejectionReason = rejectionReason.String
	}

	// Unmarshal JSON fields
	if len(findingsJSON) > 0 {
		json.Unmarshal(findingsJSON, &assessment.Findings)
	}
	if len(recommendationsJSON) > 0 {
		json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
	}
	if len(assessorsJSON) > 0 {
		json.Unmarshal(assessorsJSON, &assessment.Assessors)
	}

	return assessment, nil
}

// List lists FEAT assessments for an organization.
func (r *PostgresAssessmentRepository) List(ctx context.Context, orgID string, params ListParams) ([]*FEATAssessment, error) {
	if params.Limit <= 0 {
		params.Limit = DefaultListLimit
	}
	if params.Limit > MaxListLimit {
		params.Limit = MaxListLimit
	}

	query := `
		SELECT id, org_id, system_id, assessment_type, status, version,
			assessment_date, valid_until, fairness_score, ethics_score,
			accountability_score, transparency_score, overall_score,
			findings, recommendations, assessors, created_by, created_at, updated_at,
			submitted_at, submitted_by, approved_at, approved_by,
			rejected_at, rejected_by, rejection_reason
		FROM mas_feat_assessments
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if params.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, params.Status)
		argIdx++
	}
	if params.SystemID != "" {
		query += fmt.Sprintf(" AND system_id = $%d", argIdx)
		args = append(args, params.SystemID)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	var assessments []*FEATAssessment
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to list FEAT assessments: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			assessment := &FEATAssessment{}
			var findingsJSON, recommendationsJSON, assessorsJSON []byte
			var validUntil, submittedAt, approvedAt, rejectedAt sql.NullTime
			var submittedBy, approvedBy, rejectedBy, rejectionReason sql.NullString
			var fairnessScore, ethicsScore, accountabilityScore, transparencyScore, overallScore sql.NullFloat64

			if scanErr := rows.Scan(
				&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.AssessmentType,
				&assessment.Status, &assessment.Version, &assessment.AssessmentDate, &validUntil,
				&fairnessScore, &ethicsScore, &accountabilityScore, &transparencyScore, &overallScore,
				&findingsJSON, &recommendationsJSON, &assessorsJSON, &assessment.CreatedBy,
				&assessment.CreatedAt, &assessment.UpdatedAt, &submittedAt, &submittedBy,
				&approvedAt, &approvedBy, &rejectedAt, &rejectedBy, &rejectionReason,
			); scanErr != nil {
				return fmt.Errorf("failed to scan FEAT assessment: %w", scanErr)
			}

			// Handle nullable fields
			if validUntil.Valid {
				assessment.ValidUntil = &validUntil.Time
			}
			if fairnessScore.Valid {
				assessment.FairnessScore = &fairnessScore.Float64
			}
			if ethicsScore.Valid {
				assessment.EthicsScore = &ethicsScore.Float64
			}
			if accountabilityScore.Valid {
				assessment.AccountabilityScore = &accountabilityScore.Float64
			}
			if transparencyScore.Valid {
				assessment.TransparencyScore = &transparencyScore.Float64
			}
			if overallScore.Valid {
				assessment.OverallScore = &overallScore.Float64
			}
			if submittedAt.Valid {
				assessment.SubmittedAt = &submittedAt.Time
			}
			if submittedBy.Valid {
				assessment.SubmittedBy = submittedBy.String
			}
			if approvedAt.Valid {
				assessment.ApprovedAt = &approvedAt.Time
			}
			if approvedBy.Valid {
				assessment.ApprovedBy = approvedBy.String
			}
			if rejectedAt.Valid {
				assessment.RejectedAt = &rejectedAt.Time
			}
			if rejectedBy.Valid {
				assessment.RejectedBy = rejectedBy.String
			}
			if rejectionReason.Valid {
				assessment.RejectionReason = rejectionReason.String
			}

			if len(findingsJSON) > 0 {
				json.Unmarshal(findingsJSON, &assessment.Findings)
			}
			if len(recommendationsJSON) > 0 {
				json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
			}
			if len(assessorsJSON) > 0 {
				json.Unmarshal(assessorsJSON, &assessment.Assessors)
			}

			assessments = append(assessments, assessment)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return assessments, nil
}

// Update updates a FEAT assessment.
func (r *PostgresAssessmentRepository) Update(ctx context.Context, assessment *FEATAssessment) error {
	assessment.UpdatedAt = time.Now().UTC()
	assessment.Version++

	findingsJSON, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	recommendationsJSON, err := json.Marshal(assessment.Recommendations)
	if err != nil {
		return fmt.Errorf("failed to marshal recommendations: %w", err)
	}

	assessorsJSON, err := json.Marshal(assessment.Assessors)
	if err != nil {
		return fmt.Errorf("failed to marshal assessors: %w", err)
	}

	query := `
		UPDATE mas_feat_assessments SET
			status = $1, version = $2, valid_until = $3,
			fairness_score = $4, ethics_score = $5, accountability_score = $6,
			transparency_score = $7, overall_score = $8, findings = $9,
			recommendations = $10, assessors = $11, updated_at = $12,
			submitted_at = $13, submitted_by = $14, approved_at = $15, approved_by = $16,
			rejected_at = $17, rejected_by = $18, rejection_reason = $19
		WHERE org_id = $20 AND id = $21
	`

	err = rls.WithOrgScope(ctx, r.db, assessment.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			assessment.Status, assessment.Version, assessment.ValidUntil,
			assessment.FairnessScore, assessment.EthicsScore, assessment.AccountabilityScore,
			assessment.TransparencyScore, assessment.OverallScore, findingsJSON,
			recommendationsJSON, assessorsJSON, assessment.UpdatedAt,
			assessment.SubmittedAt, assessment.SubmittedBy, assessment.ApprovedAt, assessment.ApprovedBy,
			assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason,
			assessment.OrgID, assessment.ID,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to update FEAT assessment: %w", err)
	}

	return nil
}

// GetLatestForSystem gets the latest assessment for a system.
func (r *PostgresAssessmentRepository) GetLatestForSystem(ctx context.Context, orgID, systemID string) (*FEATAssessment, error) {
	query := `
		SELECT id FROM mas_feat_assessments
		WHERE org_id = $1 AND system_id = $2
		ORDER BY created_at DESC
		LIMIT 1
	`

	var id string
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, systemID).Scan(&id)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get latest assessment: %w", err)
	}

	// GetByID opens its own wrap. Sequential, not nested: the transaction above
	// has already committed by the time this runs.
	return r.GetByID(ctx, orgID, id)
}
