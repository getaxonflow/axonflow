// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ConformityRepository defines the interface for conformity assessment persistence.
type ConformityRepository interface {
	// Create creates a new conformity assessment.
	Create(ctx context.Context, assessment *ConformityAssessment) error

	// GetByID retrieves an assessment by ID.
	GetByID(ctx context.Context, id string) (*ConformityAssessment, error)

	// List retrieves assessments for an organization.
	List(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error)

	// Update updates an assessment.
	Update(ctx context.Context, assessment *ConformityAssessment) error

	// Delete deletes an assessment.
	Delete(ctx context.Context, id string) error

	// GetBySystemID retrieves assessments for a specific AI system.
	GetBySystemID(ctx context.Context, orgID, systemID string) ([]*ConformityAssessment, error)
}

// PostgresConformityRepository implements ConformityRepository using PostgreSQL.
type PostgresConformityRepository struct {
	db *sql.DB
}

// NewPostgresConformityRepository creates a new PostgreSQL conformity repository.
func NewPostgresConformityRepository(db *sql.DB) *PostgresConformityRepository {
	return &PostgresConformityRepository{db: db}
}

// Create creates a new conformity assessment.
func (r *PostgresConformityRepository) Create(ctx context.Context, assessment *ConformityAssessment) error {
	query := `
		INSERT INTO euaiact_conformity_assessments (
			id, org_id, system_id, system_name, risk_category, status, version,
			assessment_date, valid_until, assessors, requirements, evidence,
			findings, risk_mitigation, recommendations, created_by, created_at,
			updated_at, submitted_at, submitted_by, approved_at, approved_by,
			rejected_at, rejected_by, rejection_reason
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25)`

	assessorsJSON, err := json.Marshal(assessment.Assessors)
	if err != nil {
		return fmt.Errorf("marshal assessors: %w", err)
	}
	requirementsJSON, err := json.Marshal(assessment.Requirements)
	if err != nil {
		return fmt.Errorf("marshal requirements: %w", err)
	}
	evidenceJSON, err := json.Marshal(assessment.Evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	findingsJSON, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	mitigationJSON, err := json.Marshal(assessment.RiskMitigation)
	if err != nil {
		return fmt.Errorf("marshal risk_mitigation: %w", err)
	}
	recommendationsJSON, err := json.Marshal(assessment.Recommendations)
	if err != nil {
		return fmt.Errorf("marshal recommendations: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		assessment.ID, assessment.OrgID, assessment.SystemID, assessment.SystemName,
		assessment.RiskCategory, assessment.Status, assessment.Version, assessment.AssessmentDate,
		assessment.ValidUntil, assessorsJSON, requirementsJSON, evidenceJSON,
		findingsJSON, mitigationJSON, recommendationsJSON, assessment.CreatedBy, assessment.CreatedAt,
		assessment.UpdatedAt, assessment.SubmittedAt, assessment.SubmittedBy, assessment.ApprovedAt, assessment.ApprovedBy,
		assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason,
	)
	return err
}

// GetByID retrieves an assessment by ID.
func (r *PostgresConformityRepository) GetByID(ctx context.Context, id string) (*ConformityAssessment, error) {
	query := `
		SELECT id, org_id, system_id, system_name, risk_category, status, version,
			assessment_date, valid_until, assessors, requirements, evidence,
			findings, risk_mitigation, recommendations, created_by, created_at,
			updated_at, submitted_at, submitted_by, approved_at, approved_by,
			rejected_at, rejected_by, rejection_reason
		FROM euaiact_conformity_assessments
		WHERE id = $1`

	assessment := &ConformityAssessment{}
	var assessorsJSON, requirementsJSON, evidenceJSON, findingsJSON, mitigationJSON, recommendationsJSON []byte

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.SystemName,
		&assessment.RiskCategory, &assessment.Status, &assessment.Version, &assessment.AssessmentDate,
		&assessment.ValidUntil, &assessorsJSON, &requirementsJSON, &evidenceJSON,
		&findingsJSON, &mitigationJSON, &recommendationsJSON, &assessment.CreatedBy, &assessment.CreatedAt,
		&assessment.UpdatedAt, &assessment.SubmittedAt, &assessment.SubmittedBy, &assessment.ApprovedAt, &assessment.ApprovedBy,
		&assessment.RejectedAt, &assessment.RejectedBy, &assessment.RejectionReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON fields
	if len(assessorsJSON) > 0 {
		json.Unmarshal(assessorsJSON, &assessment.Assessors)
	}
	if len(requirementsJSON) > 0 {
		json.Unmarshal(requirementsJSON, &assessment.Requirements)
	}
	if len(evidenceJSON) > 0 {
		json.Unmarshal(evidenceJSON, &assessment.Evidence)
	}
	if len(findingsJSON) > 0 {
		json.Unmarshal(findingsJSON, &assessment.Findings)
	}
	if len(mitigationJSON) > 0 {
		json.Unmarshal(mitigationJSON, &assessment.RiskMitigation)
	}
	if len(recommendationsJSON) > 0 {
		json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
	}

	return assessment, nil
}

// List retrieves assessments for an organization.
func (r *PostgresConformityRepository) List(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error) {
	// Build query with optional status filter
	baseQuery := `FROM euaiact_conformity_assessments WHERE org_id = $1`
	args := []interface{}{orgID}
	argIndex := 2

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	// Count query
	var total int64
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Data query
	if limit <= 0 {
		limit = 50
	}
	dataQuery := `SELECT id, org_id, system_id, system_name, risk_category, status, version,
		assessment_date, valid_until, assessors, requirements, evidence,
		findings, risk_mitigation, recommendations, created_by, created_at,
		updated_at, submitted_at, submitted_by, approved_at, approved_by,
		rejected_at, rejected_by, rejection_reason ` + baseQuery + ` ORDER BY updated_at DESC`
	dataQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var assessments []*ConformityAssessment
	for rows.Next() {
		assessment := &ConformityAssessment{}
		var assessorsJSON, requirementsJSON, evidenceJSON, findingsJSON, mitigationJSON, recommendationsJSON []byte

		if err := rows.Scan(
			&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.SystemName,
			&assessment.RiskCategory, &assessment.Status, &assessment.Version, &assessment.AssessmentDate,
			&assessment.ValidUntil, &assessorsJSON, &requirementsJSON, &evidenceJSON,
			&findingsJSON, &mitigationJSON, &recommendationsJSON, &assessment.CreatedBy, &assessment.CreatedAt,
			&assessment.UpdatedAt, &assessment.SubmittedAt, &assessment.SubmittedBy, &assessment.ApprovedAt, &assessment.ApprovedBy,
			&assessment.RejectedAt, &assessment.RejectedBy, &assessment.RejectionReason,
		); err != nil {
			return nil, 0, err
		}

		// Unmarshal JSON fields
		if len(assessorsJSON) > 0 {
			json.Unmarshal(assessorsJSON, &assessment.Assessors)
		}
		if len(requirementsJSON) > 0 {
			json.Unmarshal(requirementsJSON, &assessment.Requirements)
		}
		if len(evidenceJSON) > 0 {
			json.Unmarshal(evidenceJSON, &assessment.Evidence)
		}
		if len(findingsJSON) > 0 {
			json.Unmarshal(findingsJSON, &assessment.Findings)
		}
		if len(mitigationJSON) > 0 {
			json.Unmarshal(mitigationJSON, &assessment.RiskMitigation)
		}
		if len(recommendationsJSON) > 0 {
			json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
		}

		assessments = append(assessments, assessment)
	}

	return assessments, total, rows.Err()
}

// Update updates an assessment.
func (r *PostgresConformityRepository) Update(ctx context.Context, assessment *ConformityAssessment) error {
	query := `
		UPDATE euaiact_conformity_assessments
		SET system_name = $2, risk_category = $3, status = $4, version = $5,
			valid_until = $6, assessors = $7, requirements = $8, evidence = $9,
			findings = $10, risk_mitigation = $11, recommendations = $12, updated_at = $13,
			submitted_at = $14, submitted_by = $15, approved_at = $16, approved_by = $17,
			rejected_at = $18, rejected_by = $19, rejection_reason = $20
		WHERE id = $1`

	assessorsJSON, err := json.Marshal(assessment.Assessors)
	if err != nil {
		return fmt.Errorf("marshal assessors: %w", err)
	}
	requirementsJSON, err := json.Marshal(assessment.Requirements)
	if err != nil {
		return fmt.Errorf("marshal requirements: %w", err)
	}
	evidenceJSON, err := json.Marshal(assessment.Evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}
	findingsJSON, err := json.Marshal(assessment.Findings)
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	mitigationJSON, err := json.Marshal(assessment.RiskMitigation)
	if err != nil {
		return fmt.Errorf("marshal risk_mitigation: %w", err)
	}
	recommendationsJSON, err := json.Marshal(assessment.Recommendations)
	if err != nil {
		return fmt.Errorf("marshal recommendations: %w", err)
	}

	_, err = r.db.ExecContext(ctx, query,
		assessment.ID, assessment.SystemName, assessment.RiskCategory, assessment.Status, assessment.Version,
		assessment.ValidUntil, assessorsJSON, requirementsJSON, evidenceJSON,
		findingsJSON, mitigationJSON, recommendationsJSON, time.Now().UTC(),
		assessment.SubmittedAt, assessment.SubmittedBy, assessment.ApprovedAt, assessment.ApprovedBy,
		assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason,
	)
	return err
}

// Delete deletes an assessment.
func (r *PostgresConformityRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM euaiact_conformity_assessments WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

// GetBySystemID retrieves assessments for a specific AI system.
func (r *PostgresConformityRepository) GetBySystemID(ctx context.Context, orgID, systemID string) ([]*ConformityAssessment, error) {
	query := `
		SELECT id, org_id, system_id, system_name, risk_category, status, version,
			assessment_date, valid_until, assessors, requirements, evidence,
			findings, risk_mitigation, recommendations, created_by, created_at,
			updated_at, submitted_at, submitted_by, approved_at, approved_by,
			rejected_at, rejected_by, rejection_reason
		FROM euaiact_conformity_assessments
		WHERE org_id = $1 AND system_id = $2
		ORDER BY version DESC`

	rows, err := r.db.QueryContext(ctx, query, orgID, systemID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var assessments []*ConformityAssessment
	for rows.Next() {
		assessment := &ConformityAssessment{}
		var assessorsJSON, requirementsJSON, evidenceJSON, findingsJSON, mitigationJSON, recommendationsJSON []byte

		if err := rows.Scan(
			&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.SystemName,
			&assessment.RiskCategory, &assessment.Status, &assessment.Version, &assessment.AssessmentDate,
			&assessment.ValidUntil, &assessorsJSON, &requirementsJSON, &evidenceJSON,
			&findingsJSON, &mitigationJSON, &recommendationsJSON, &assessment.CreatedBy, &assessment.CreatedAt,
			&assessment.UpdatedAt, &assessment.SubmittedAt, &assessment.SubmittedBy, &assessment.ApprovedAt, &assessment.ApprovedBy,
			&assessment.RejectedAt, &assessment.RejectedBy, &assessment.RejectionReason,
		); err != nil {
			return nil, err
		}

		// Unmarshal JSON fields
		if len(assessorsJSON) > 0 {
			json.Unmarshal(assessorsJSON, &assessment.Assessors)
		}
		if len(requirementsJSON) > 0 {
			json.Unmarshal(requirementsJSON, &assessment.Requirements)
		}
		if len(evidenceJSON) > 0 {
			json.Unmarshal(evidenceJSON, &assessment.Evidence)
		}
		if len(findingsJSON) > 0 {
			json.Unmarshal(findingsJSON, &assessment.Findings)
		}
		if len(mitigationJSON) > 0 {
			json.Unmarshal(mitigationJSON, &assessment.RiskMitigation)
		}
		if len(recommendationsJSON) > 0 {
			json.Unmarshal(recommendationsJSON, &assessment.Recommendations)
		}

		assessments = append(assessments, assessment)
	}

	return assessments, rows.Err()
}
