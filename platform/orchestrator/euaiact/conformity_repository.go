// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"axonflow/platform/agent/rls"
)

// ErrAssessmentNotFound is returned when no conformity assessment matches the
// id WITHIN the caller's organization. Handlers map it to 404, never 403 - see
// ErrExportNotFound for the reasoning.
var ErrAssessmentNotFound = errors.New("euaiact: conformity assessment not found")

// ConformityRepository defines the interface for conformity assessment persistence.
//
// Organization scoping: see the ExportRepository doc comment. The same #3241
// fix applies here, and here it was worse - a foreign organization could not
// merely READ another company's Article 43 assessment, it could rewrite,
// submit, approve or reject it. An approval anyone can grant is not evidence of
// approval.
type ConformityRepository interface {
	// Create creates a new conformity assessment.
	Create(ctx context.Context, assessment *ConformityAssessment) error

	// GetByID retrieves an assessment by ID within an organization.
	// Returns ErrAssessmentNotFound when the id does not exist in that org.
	GetByID(ctx context.Context, orgID, id string) (*ConformityAssessment, error)

	// List retrieves assessments for an organization.
	List(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error)

	// Update updates an assessment. The record's own OrgID is the scope.
	Update(ctx context.Context, assessment *ConformityAssessment) error

	// Delete deletes an assessment within an organization.
	Delete(ctx context.Context, orgID, id string) error

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

// conformitySelectColumns is the single column list every conformity read uses.
const conformitySelectColumns = `id, org_id, system_id, system_name, risk_category, status, version,
		assessment_date, valid_until, assessors, requirements, evidence,
		findings, risk_mitigation, recommendations, created_by, created_at,
		updated_at, submitted_at, submitted_by, approved_at, approved_by,
		rejected_at, rejected_by, rejection_reason`

// scanConformity materializes one assessment row.
//
// The workflow columns (submitted_by / approved_by / rejected_by /
// rejection_reason) are NULLABLE with no default in migration 116 and were
// scanned into plain strings, so any row with a NULL there failed the whole
// read with `converting NULL to string is unsupported` - the assessment became
// permanently unreadable through the API. Create writes an empty string, so
// this never fired in normal use, which is why it went unnoticed.
func scanConformity(row interface{ Scan(...interface{}) error }) (*ConformityAssessment, error) {
	assessment := &ConformityAssessment{}
	var assessorsJSON, requirementsJSON, evidenceJSON, findingsJSON, mitigationJSON, recommendationsJSON []byte
	var submittedBy, approvedBy, rejectedBy, rejectionReason sql.NullString

	err := row.Scan(
		&assessment.ID, &assessment.OrgID, &assessment.SystemID, &assessment.SystemName,
		&assessment.RiskCategory, &assessment.Status, &assessment.Version, &assessment.AssessmentDate,
		&assessment.ValidUntil, &assessorsJSON, &requirementsJSON, &evidenceJSON,
		&findingsJSON, &mitigationJSON, &recommendationsJSON, &assessment.CreatedBy, &assessment.CreatedAt,
		&assessment.UpdatedAt, &assessment.SubmittedAt, &submittedBy, &assessment.ApprovedAt, &approvedBy,
		&assessment.RejectedAt, &rejectedBy, &rejectionReason,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAssessmentNotFound
	}
	if err != nil {
		return nil, err
	}
	assessment.SubmittedBy = submittedBy.String
	assessment.ApprovedBy = approvedBy.String
	assessment.RejectedBy = rejectedBy.String
	assessment.RejectionReason = rejectionReason.String

	// Unmarshal JSON fields. Errors are surfaced rather than dropped: a
	// silently-ignored unmarshal turns corrupt evidence into an assessment that
	// reads as having no findings, which on an Article 43 record is a claim.
	for _, f := range []struct {
		name string
		raw  []byte
		dst  interface{}
	}{
		{"assessors", assessorsJSON, &assessment.Assessors},
		{"requirements", requirementsJSON, &assessment.Requirements},
		{"evidence", evidenceJSON, &assessment.Evidence},
		{"findings", findingsJSON, &assessment.Findings},
		{"risk_mitigation", mitigationJSON, &assessment.RiskMitigation},
		{"recommendations", recommendationsJSON, &assessment.Recommendations},
	} {
		if len(f.raw) == 0 {
			continue
		}
		if err := json.Unmarshal(f.raw, f.dst); err != nil {
			return nil, fmt.Errorf("unmarshal %s: %w", f.name, err)
		}
	}
	return assessment, nil
}

// Create creates a new conformity assessment.
func (r *PostgresConformityRepository) Create(ctx context.Context, assessment *ConformityAssessment) error {
	if assessment == nil {
		return fmt.Errorf("euaiact: assessment is nil")
	}
	if strings.TrimSpace(assessment.OrgID) == "" {
		return fmt.Errorf("euaiact: refusing to create an assessment with no organization")
	}
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

	return rls.WithOrgScope(ctx, r.db, assessment.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			assessment.ID, assessment.OrgID, assessment.SystemID, assessment.SystemName,
			assessment.RiskCategory, assessment.Status, assessment.Version, assessment.AssessmentDate,
			assessment.ValidUntil, assessorsJSON, requirementsJSON, evidenceJSON,
			findingsJSON, mitigationJSON, recommendationsJSON, assessment.CreatedBy, assessment.CreatedAt,
			assessment.UpdatedAt, assessment.SubmittedAt, assessment.SubmittedBy, assessment.ApprovedAt, assessment.ApprovedBy,
			assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason,
		)
		return execErr
	})
}

// GetByID retrieves an assessment by ID within an organization.
func (r *PostgresConformityRepository) GetByID(ctx context.Context, orgID, id string) (*ConformityAssessment, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, ErrAssessmentNotFound
	}
	query := `SELECT ` + conformitySelectColumns + `
		FROM euaiact_conformity_assessments
		WHERE id = $1 AND org_id = $2`

	var assessment *ConformityAssessment
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		a, scanErr := scanConformity(tx.QueryRowContext(ctx, query, id, orgID))
		if scanErr != nil {
			return scanErr
		}
		assessment = a
		return nil
	})
	if err != nil {
		return nil, err
	}
	return assessment, nil
}

// List retrieves assessments for an organization.
func (r *PostgresConformityRepository) List(ctx context.Context, orgID string, status AssessmentStatus, limit, offset int) ([]*ConformityAssessment, int64, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, 0, fmt.Errorf("euaiact: refusing to list assessments with no organization")
	}
	// Build query with optional status filter
	baseQuery := `FROM euaiact_conformity_assessments WHERE org_id = $1`
	args := []interface{}{orgID}
	argIndex := 2

	if status != "" {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, status)
		argIndex++
	}

	countQuery := "SELECT COUNT(*) " + baseQuery

	if limit <= 0 {
		limit = 50
	}
	dataQuery := `SELECT ` + conformitySelectColumns + ` ` + baseQuery + ` ORDER BY updated_at DESC`
	dataQuery += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	dataArgs := append(append([]interface{}{}, args...), limit, offset)

	var (
		total       int64
		assessments []*ConformityAssessment
	)
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, dataQuery, dataArgs...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			assessment, scanErr := scanConformity(rows)
			if scanErr != nil {
				return scanErr
			}
			assessments = append(assessments, assessment)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return assessments, total, nil
}

// Update updates an assessment within its own organization.
//
// The org predicate is in the WHERE clause, not merely implied by the caller:
// pre-#3241 this was `WHERE id = $1`, which is what let another organization
// rewrite, submit and approve a victim's Article 43 assessment.
func (r *PostgresConformityRepository) Update(ctx context.Context, assessment *ConformityAssessment) error {
	if assessment == nil {
		return fmt.Errorf("euaiact: assessment is nil")
	}
	orgID := strings.TrimSpace(assessment.OrgID)
	if orgID == "" {
		return fmt.Errorf("euaiact: refusing to update an assessment with no organization")
	}
	query := `
		UPDATE euaiact_conformity_assessments
		SET system_name = $2, risk_category = $3, status = $4, version = $5,
			valid_until = $6, assessors = $7, requirements = $8, evidence = $9,
			findings = $10, risk_mitigation = $11, recommendations = $12, updated_at = $13,
			submitted_at = $14, submitted_by = $15, approved_at = $16, approved_by = $17,
			rejected_at = $18, rejected_by = $19, rejection_reason = $20
		WHERE id = $1 AND org_id = $21`

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

	return rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		res, execErr := tx.ExecContext(ctx, query,
			assessment.ID, assessment.SystemName, assessment.RiskCategory, assessment.Status, assessment.Version,
			assessment.ValidUntil, assessorsJSON, requirementsJSON, evidenceJSON,
			findingsJSON, mitigationJSON, recommendationsJSON, time.Now().UTC(),
			assessment.SubmittedAt, assessment.SubmittedBy, assessment.ApprovedAt, assessment.ApprovedBy,
			assessment.RejectedAt, assessment.RejectedBy, assessment.RejectionReason, orgID,
		)
		if execErr != nil {
			return execErr
		}
		n, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if n == 0 {
			return ErrAssessmentNotFound
		}
		return nil
	})
}

// Delete deletes an assessment within an organization.
func (r *PostgresConformityRepository) Delete(ctx context.Context, orgID, id string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return fmt.Errorf("euaiact: refusing to delete an assessment with no organization")
	}
	query := `DELETE FROM euaiact_conformity_assessments WHERE id = $1 AND org_id = $2`
	return rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, query, id, orgID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return ErrAssessmentNotFound
		}
		return nil
	})
}

// GetBySystemID retrieves assessments for a specific AI system.
func (r *PostgresConformityRepository) GetBySystemID(ctx context.Context, orgID, systemID string) ([]*ConformityAssessment, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil, fmt.Errorf("euaiact: refusing to read assessments with no organization")
	}
	query := `SELECT ` + conformitySelectColumns + `
		FROM euaiact_conformity_assessments
		WHERE org_id = $1 AND system_id = $2
		ORDER BY version DESC`

	var assessments []*ConformityAssessment
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID, systemID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			assessment, scanErr := scanConformity(rows)
			if scanErr != nil {
				return scanErr
			}
			assessments = append(assessments, assessment)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return assessments, nil
}
