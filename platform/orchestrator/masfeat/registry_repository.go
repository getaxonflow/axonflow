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

// #3133. Migration 400 RLS-gates mas_ai_system_registry with `FOR ALL USING
// (org_id = get_current_org_id()) WITH CHECK (org_id = get_current_org_id())`,
// but this package never set app.current_org_id. Every statement below now
// runs inside rls.WithOrgScope; the hand-written `WHERE org_id = $n`
// predicates are KEPT as an additive backstop. See the fuller note in
// killswitch_repository.go.

// RegistryRepository defines the interface for AI system registry data access.
type RegistryRepository interface {
	// Create creates a new AI system registration.
	Create(ctx context.Context, system *AISystemRegistry) error

	// GetByID retrieves an AI system by ID.
	GetByID(ctx context.Context, orgID, id string) (*AISystemRegistry, error)

	// GetBySystemID retrieves an AI system by system ID.
	GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystemRegistry, error)

	// List lists AI systems for an organization.
	List(ctx context.Context, orgID string, params ListParams) ([]*AISystemRegistry, error)

	// Update updates an AI system registration.
	Update(ctx context.Context, system *AISystemRegistry) error

	// Delete soft-deletes an AI system (sets status to retired).
	Delete(ctx context.Context, orgID, id string) error

	// GetSummary returns a summary of registered AI systems.
	GetSummary(ctx context.Context, orgID string) (*RegistrySummary, error)

	// CountByStatus returns the count of systems by status.
	CountByStatus(ctx context.Context, orgID string) (map[SystemStatus]int, error)
}

// PostgresRegistryRepository implements RegistryRepository using PostgreSQL.
type PostgresRegistryRepository struct {
	db *sql.DB
}

// NewPostgresRegistryRepository creates a new PostgreSQL registry repository.
func NewPostgresRegistryRepository(db *sql.DB) *PostgresRegistryRepository {
	return &PostgresRegistryRepository{db: db}
}

// Create creates a new AI system registration.
func (r *PostgresRegistryRepository) Create(ctx context.Context, system *AISystemRegistry) error {
	if system.ID == "" {
		system.ID = uuid.New().String()
	}
	system.CreatedAt = time.Now().UTC()
	system.UpdatedAt = system.CreatedAt

	// Calculate materiality
	system.MaterialityClassification = calculateMateriality(
		system.RiskRatingImpact,
		system.RiskRatingComplexity,
		system.RiskRatingReliance,
	)

	metadataJSON, err := json.Marshal(system.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	dataSourcesJSON, err := json.Marshal(system.DataSources)
	if err != nil {
		return fmt.Errorf("failed to marshal data sources: %w", err)
	}

	query := `
		INSERT INTO mas_ai_system_registry (
			id, org_id, system_id, system_name, description, use_case, status,
			risk_rating_impact, risk_rating_complexity, risk_rating_reliance,
			materiality_classification, owner_team, owner_email, data_sources,
			model_type, version, deployment_date, metadata, created_at, updated_at, created_by
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
	`

	err = rls.WithOrgScope(ctx, r.db, system.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			system.ID, system.OrgID, system.SystemID, system.SystemName, system.Description,
			system.UseCase, system.Status, system.RiskRatingImpact, system.RiskRatingComplexity,
			system.RiskRatingReliance, system.MaterialityClassification, system.OwnerTeam,
			system.OwnerEmail, dataSourcesJSON, system.ModelType, system.Version,
			system.DeploymentDate, metadataJSON, system.CreatedAt, system.UpdatedAt, system.CreatedBy,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to insert AI system: %w", err)
	}

	return nil
}

// GetByID retrieves an AI system by ID.
func (r *PostgresRegistryRepository) GetByID(ctx context.Context, orgID, id string) (*AISystemRegistry, error) {
	query := `
		SELECT id, org_id, system_id, system_name, description, use_case, status,
			risk_rating_impact, risk_rating_complexity, risk_rating_reliance,
			materiality_classification, owner_team, owner_email, data_sources,
			model_type, version, deployment_date, last_assessment_date,
			next_assessment_due, metadata, created_at, updated_at, created_by, updated_by
		FROM mas_ai_system_registry
		WHERE org_id = $1 AND id = $2
	`

	system := &AISystemRegistry{}
	var metadataJSON, dataSourcesJSON []byte
	var deploymentDate, lastAssessment, nextAssessment sql.NullTime
	var description, modelType, version, updatedBy sql.NullString

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, id).Scan(
			&system.ID, &system.OrgID, &system.SystemID, &system.SystemName, &description,
			&system.UseCase, &system.Status, &system.RiskRatingImpact, &system.RiskRatingComplexity,
			&system.RiskRatingReliance, &system.MaterialityClassification, &system.OwnerTeam,
			&system.OwnerEmail, &dataSourcesJSON, &modelType, &version, &deploymentDate,
			&lastAssessment, &nextAssessment, &metadataJSON, &system.CreatedAt, &system.UpdatedAt,
			&system.CreatedBy, &updatedBy,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get AI system: %w", err)
	}

	// Handle nullable fields
	if description.Valid {
		system.Description = description.String
	}
	if modelType.Valid {
		system.ModelType = modelType.String
	}
	if version.Valid {
		system.Version = version.String
	}
	if updatedBy.Valid {
		system.UpdatedBy = updatedBy.String
	}
	if deploymentDate.Valid {
		system.DeploymentDate = &deploymentDate.Time
	}
	if lastAssessment.Valid {
		system.LastAssessmentDate = &lastAssessment.Time
	}
	if nextAssessment.Valid {
		system.NextAssessmentDue = &nextAssessment.Time
	}

	// Unmarshal JSON fields
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &system.Metadata)
	}
	if len(dataSourcesJSON) > 0 {
		json.Unmarshal(dataSourcesJSON, &system.DataSources)
	}

	return system, nil
}

// GetBySystemID retrieves an AI system by system ID.
func (r *PostgresRegistryRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*AISystemRegistry, error) {
	query := `
		SELECT id FROM mas_ai_system_registry
		WHERE org_id = $1 AND system_id = $2
	`

	var id string
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, systemID).Scan(&id)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get AI system by system_id: %w", err)
	}

	// GetByID opens its own wrap. Sequential, not nested: the transaction above
	// has already committed by the time this runs.
	return r.GetByID(ctx, orgID, id)
}

// List lists AI systems for an organization.
func (r *PostgresRegistryRepository) List(ctx context.Context, orgID string, params ListParams) ([]*AISystemRegistry, error) {
	if params.Limit <= 0 {
		params.Limit = DefaultListLimit
	}
	if params.Limit > MaxListLimit {
		params.Limit = MaxListLimit
	}

	query := `
		SELECT id, org_id, system_id, system_name, description, use_case, status,
			risk_rating_impact, risk_rating_complexity, risk_rating_reliance,
			materiality_classification, owner_team, owner_email, data_sources,
			model_type, version, deployment_date, last_assessment_date,
			next_assessment_due, metadata, created_at, updated_at, created_by, updated_by
		FROM mas_ai_system_registry
		WHERE org_id = $1
	`
	args := []interface{}{orgID}
	argIdx := 2

	if params.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, params.Status)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	var systems []*AISystemRegistry
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to list AI systems: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			system := &AISystemRegistry{}
			var metadataJSON, dataSourcesJSON []byte
			var deploymentDate, lastAssessment, nextAssessment sql.NullTime
			var description, modelType, version, updatedBy sql.NullString

			if scanErr := rows.Scan(
				&system.ID, &system.OrgID, &system.SystemID, &system.SystemName, &description,
				&system.UseCase, &system.Status, &system.RiskRatingImpact, &system.RiskRatingComplexity,
				&system.RiskRatingReliance, &system.MaterialityClassification, &system.OwnerTeam,
				&system.OwnerEmail, &dataSourcesJSON, &modelType, &version, &deploymentDate,
				&lastAssessment, &nextAssessment, &metadataJSON, &system.CreatedAt, &system.UpdatedAt,
				&system.CreatedBy, &updatedBy,
			); scanErr != nil {
				return fmt.Errorf("failed to scan AI system: %w", scanErr)
			}

			// Handle nullable fields
			if description.Valid {
				system.Description = description.String
			}
			if modelType.Valid {
				system.ModelType = modelType.String
			}
			if version.Valid {
				system.Version = version.String
			}
			if updatedBy.Valid {
				system.UpdatedBy = updatedBy.String
			}
			if deploymentDate.Valid {
				system.DeploymentDate = &deploymentDate.Time
			}
			if lastAssessment.Valid {
				system.LastAssessmentDate = &lastAssessment.Time
			}
			if nextAssessment.Valid {
				system.NextAssessmentDue = &nextAssessment.Time
			}

			if len(metadataJSON) > 0 {
				json.Unmarshal(metadataJSON, &system.Metadata)
			}
			if len(dataSourcesJSON) > 0 {
				json.Unmarshal(dataSourcesJSON, &system.DataSources)
			}

			systems = append(systems, system)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return systems, nil
}

// Update updates an AI system registration.
func (r *PostgresRegistryRepository) Update(ctx context.Context, system *AISystemRegistry) error {
	system.UpdatedAt = time.Now().UTC()

	// Recalculate materiality
	system.MaterialityClassification = calculateMateriality(
		system.RiskRatingImpact,
		system.RiskRatingComplexity,
		system.RiskRatingReliance,
	)

	metadataJSON, err := json.Marshal(system.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	dataSourcesJSON, err := json.Marshal(system.DataSources)
	if err != nil {
		return fmt.Errorf("failed to marshal data sources: %w", err)
	}

	query := `
		UPDATE mas_ai_system_registry SET
			system_name = $1, description = $2, use_case = $3, status = $4,
			risk_rating_impact = $5, risk_rating_complexity = $6, risk_rating_reliance = $7,
			materiality_classification = $8, owner_team = $9, owner_email = $10,
			data_sources = $11, model_type = $12, version = $13, deployment_date = $14,
			metadata = $15, updated_at = $16, updated_by = $17
		WHERE org_id = $18 AND id = $19
	`

	err = rls.WithOrgScope(ctx, r.db, system.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			system.SystemName, system.Description, system.UseCase, system.Status,
			system.RiskRatingImpact, system.RiskRatingComplexity, system.RiskRatingReliance,
			system.MaterialityClassification, system.OwnerTeam, system.OwnerEmail,
			dataSourcesJSON, system.ModelType, system.Version, system.DeploymentDate,
			metadataJSON, system.UpdatedAt, system.UpdatedBy, system.OrgID, system.ID,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to update AI system: %w", err)
	}

	return nil
}

// Delete soft-deletes an AI system (sets status to retired).
func (r *PostgresRegistryRepository) Delete(ctx context.Context, orgID, id string) error {
	query := `
		UPDATE mas_ai_system_registry
		SET status = $1, updated_at = $2
		WHERE org_id = $3 AND id = $4
	`

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query, SystemStatusRetired, time.Now().UTC(), orgID, id)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to delete AI system: %w", err)
	}

	return nil
}

// GetSummary returns a summary of registered AI systems.
func (r *PostgresRegistryRepository) GetSummary(ctx context.Context, orgID string) (*RegistrySummary, error) {
	summary := &RegistrySummary{OrgID: orgID}

	// Get total and active counts
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'active') as active,
			COUNT(*) FILTER (WHERE materiality_classification = 'high') as high_mat,
			COUNT(*) FILTER (WHERE materiality_classification = 'medium') as medium_mat,
			COUNT(*) FILTER (WHERE materiality_classification = 'low') as low_mat,
			COUNT(*) FILTER (WHERE next_assessment_due < NOW()) as assessments_due
		FROM mas_ai_system_registry
		WHERE org_id = $1
	`

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID).Scan(
			&summary.TotalSystems, &summary.ActiveSystems,
			&summary.HighMateriality, &summary.MediumMateriality, &summary.LowMateriality,
			&summary.AssessmentsDue,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get registry summary: %w", err)
	}

	// Get kill switches triggered count.
	//
	// This is a SECOND call site, against a DIFFERENT RLS-gated table
	// (mas_kill_switches), and it needs its own scope (#3133). It deliberately
	// gets its own wrap rather than sharing the transaction above: this
	// statement's error has always been ignored — a summary is still returned
	// with KillSwitchesTriggered left at zero — and inside a shared transaction
	// a failure here would abort the txn and turn the whole COMMIT into an
	// error, changing GetSummary's contract. The wrap is additive; the error
	// tolerance is preserved exactly as it was.
	killSwitchQuery := `
		SELECT COUNT(*) FROM mas_kill_switches
		WHERE org_id = $1 AND status = 'triggered'
	`
	_ = rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, killSwitchQuery, orgID).Scan(&summary.KillSwitchesTriggered)
	})

	return summary, nil
}

// CountByStatus returns the count of systems by status.
func (r *PostgresRegistryRepository) CountByStatus(ctx context.Context, orgID string) (map[SystemStatus]int, error) {
	query := `
		SELECT status, COUNT(*) as count
		FROM mas_ai_system_registry
		WHERE org_id = $1
		GROUP BY status
	`

	counts := make(map[SystemStatus]int)
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID)
		if err != nil {
			return fmt.Errorf("failed to count by status: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var status SystemStatus
			var count int
			if scanErr := rows.Scan(&status, &count); scanErr != nil {
				return fmt.Errorf("failed to scan count: %w", scanErr)
			}
			counts[status] = count
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return counts, nil
}
