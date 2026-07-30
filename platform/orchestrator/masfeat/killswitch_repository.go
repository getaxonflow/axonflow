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

// #3133. Migration 400 switches RLS on for all five mas_* tables. Four carry
// `FOR ALL USING (org_id = get_current_org_id()) WITH CHECK (org_id =
// get_current_org_id())`; mas_kill_switch_history has no org_id column and
// resolves its owner through a subquery on mas_kill_switches. This package
// never set app.current_org_id — so on an axonflow_app_role pool every read
// here returned SILENT ZERO ROWS and every write was refused, and on a
// BYPASSRLS pool there was no database backstop at all.
//
// For a kill switch that is the worst possible failure mode: GetBySystemID
// returns nil for a TRIGGERED switch, which KillSwitchService.GetKillSwitch
// spells "kill switch not found for this system" — an RLS-blind read silently
// un-trips a tripped kill switch, a safety control reporting all-clear.
//
// Every statement below therefore runs inside rls.WithOrgScope, which opens a
// transaction and SET LOCALs the GUC the policy reads. The hand-written
// `WHERE org_id = $n` predicates are KEPT: the wrap is an additive backstop,
// not a replacement. Same class and same remedy as #3103/#3127 (rbi_*).
//
// RecordHistory is the one exception to "additive", and it is called out on the
// method: mas_kill_switch_history has no org_id column, so there was no
// application predicate to back up and migration 400's WITH CHECK is inert on a
// BYPASSRLS pool. That INSERT carries its own ownership predicate.

// KillSwitchRepository defines the interface for kill switch data access.
type KillSwitchRepository interface {
	// Create creates a new kill switch configuration.
	Create(ctx context.Context, ks *KillSwitch) error

	// GetBySystemID retrieves a kill switch by system ID.
	GetBySystemID(ctx context.Context, orgID, systemID string) (*KillSwitch, error)

	// Update updates a kill switch configuration.
	Update(ctx context.Context, ks *KillSwitch) error

	// RecordHistory records a kill switch state change.
	//
	// orgID is the owning organization of the parent kill switch. It is an
	// explicit parameter rather than a field on KillSwitchHistory because
	// mas_kill_switch_history genuinely has no org_id column — migration 400
	// resolves the owner through `kill_switch_id IN (SELECT id FROM
	// mas_kill_switches WHERE org_id = get_current_org_id())`. The INSERT
	// therefore cannot clear its WITH CHECK unless the GUC is pinned to the
	// org that owns the parent row, and there is nothing on the entity to
	// derive that from (#3133).
	RecordHistory(ctx context.Context, orgID string, history *KillSwitchHistory) error

	// GetHistory retrieves kill switch history for a system.
	GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*KillSwitchHistory, error)
}

// PostgresKillSwitchRepository implements KillSwitchRepository using PostgreSQL.
type PostgresKillSwitchRepository struct {
	db *sql.DB
}

// NewPostgresKillSwitchRepository creates a new PostgreSQL kill switch repository.
func NewPostgresKillSwitchRepository(db *sql.DB) *PostgresKillSwitchRepository {
	return &PostgresKillSwitchRepository{db: db}
}

// Create creates a new kill switch configuration.
func (r *PostgresKillSwitchRepository) Create(ctx context.Context, ks *KillSwitch) error {
	if ks.ID == "" {
		ks.ID = uuid.New().String()
	}
	ks.CreatedAt = time.Now().UTC()
	ks.UpdatedAt = ks.CreatedAt

	conditionsJSON, err := json.Marshal(ks.TriggerConditions)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger conditions: %w", err)
	}

	query := `
		INSERT INTO mas_kill_switches (
			id, org_id, system_id, status, trigger_reason, trigger_conditions,
			auto_trigger_enabled, accuracy_threshold, bias_threshold,
			error_rate_threshold, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
		)
	`

	err = rls.WithOrgScope(ctx, r.db, ks.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			ks.ID, ks.OrgID, ks.SystemID, ks.Status, ks.TriggerReason, conditionsJSON,
			ks.AutoTriggerEnabled, ks.AccuracyThreshold, ks.BiasThreshold,
			ks.ErrorRateThreshold, ks.CreatedAt, ks.UpdatedAt,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to insert kill switch: %w", err)
	}

	return nil
}

// GetBySystemID retrieves a kill switch by system ID.
func (r *PostgresKillSwitchRepository) GetBySystemID(ctx context.Context, orgID, systemID string) (*KillSwitch, error) {
	query := `
		SELECT id, org_id, system_id, status, trigger_reason, trigger_conditions,
			auto_trigger_enabled, accuracy_threshold, bias_threshold,
			error_rate_threshold, triggered_at, triggered_by, restored_at,
			restored_by, restore_reason, created_at, updated_at
		FROM mas_kill_switches
		WHERE org_id = $1 AND system_id = $2
	`

	ks := &KillSwitch{}
	var conditionsJSON []byte
	var triggerReason, triggeredBy, restoredBy, restoreReason sql.NullString
	var triggeredAt, restoredAt sql.NullTime
	var accuracyThreshold, biasThreshold, errorRateThreshold sql.NullFloat64

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, orgID, systemID).Scan(
			&ks.ID, &ks.OrgID, &ks.SystemID, &ks.Status, &triggerReason, &conditionsJSON,
			&ks.AutoTriggerEnabled, &accuracyThreshold, &biasThreshold, &errorRateThreshold,
			&triggeredAt, &triggeredBy, &restoredAt, &restoredBy, &restoreReason,
			&ks.CreatedAt, &ks.UpdatedAt,
		)
	})
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch: %w", err)
	}

	// Handle nullable fields
	if triggerReason.Valid {
		ks.TriggerReason = triggerReason.String
	}
	if triggeredBy.Valid {
		ks.TriggeredBy = triggeredBy.String
	}
	if restoredBy.Valid {
		ks.RestoredBy = restoredBy.String
	}
	if restoreReason.Valid {
		ks.RestoreReason = restoreReason.String
	}
	if triggeredAt.Valid {
		ks.TriggeredAt = &triggeredAt.Time
	}
	if restoredAt.Valid {
		ks.RestoredAt = &restoredAt.Time
	}
	if accuracyThreshold.Valid {
		ks.AccuracyThreshold = &accuracyThreshold.Float64
	}
	if biasThreshold.Valid {
		ks.BiasThreshold = &biasThreshold.Float64
	}
	if errorRateThreshold.Valid {
		ks.ErrorRateThreshold = &errorRateThreshold.Float64
	}

	if len(conditionsJSON) > 0 {
		json.Unmarshal(conditionsJSON, &ks.TriggerConditions)
	}

	return ks, nil
}

// Update updates a kill switch configuration.
func (r *PostgresKillSwitchRepository) Update(ctx context.Context, ks *KillSwitch) error {
	ks.UpdatedAt = time.Now().UTC()

	conditionsJSON, err := json.Marshal(ks.TriggerConditions)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger conditions: %w", err)
	}

	query := `
		UPDATE mas_kill_switches SET
			status = $1, trigger_reason = $2, trigger_conditions = $3,
			auto_trigger_enabled = $4, accuracy_threshold = $5, bias_threshold = $6,
			error_rate_threshold = $7, triggered_at = $8, triggered_by = $9,
			restored_at = $10, restored_by = $11, restore_reason = $12, updated_at = $13
		WHERE org_id = $14 AND system_id = $15
	`

	err = rls.WithOrgScope(ctx, r.db, ks.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
			ks.Status, ks.TriggerReason, conditionsJSON, ks.AutoTriggerEnabled,
			ks.AccuracyThreshold, ks.BiasThreshold, ks.ErrorRateThreshold,
			ks.TriggeredAt, ks.TriggeredBy, ks.RestoredAt, ks.RestoredBy,
			ks.RestoreReason, ks.UpdatedAt, ks.OrgID, ks.SystemID,
		)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to update kill switch: %w", err)
	}

	return nil
}

// RecordHistory records a kill switch state change.
//
// orgID names the organization that owns the parent kill switch. mas_kill_switch_history
// has no org_id column, so migration 400's policy resolves ownership through
// `kill_switch_id IN (SELECT id FROM mas_kill_switches WHERE org_id = get_current_org_id())`.
// With the GUC unset that inner SELECT is itself empty, so the INSERT's WITH CHECK
// can never be satisfied (#3133).
//
// This is the ONE statement in the package where the wrap is not purely an
// additive backstop over an existing application predicate. Every other statement
// keeps a hand-written `WHERE org_id = $n`; with no org_id column there is nothing
// here to back up, and migration 400's WITH CHECK is inert on any BYPASSRLS pool
// (axonflow_platform_admin, or a master pool on a deployment that has not adopted
// the app role). The kill_switch_id FK only proves the parent EXISTS, not that the
// caller owns it — so a history row could be attached to another organization's
// kill switch wherever RLS does not apply. The INSERT therefore carries its own
// ownership predicate as `INSERT … SELECT … WHERE EXISTS`, which holds on every
// pool rather than only where RLS is enforced. A refused insert affects zero rows
// and is silent at the Exec boundary, so RowsAffected is checked rather than
// assumed. The RBI twin (#3127) needs none of this: rbi_kill_switch_history has an
// org_id column and its INSERT binds it directly.
func (r *PostgresKillSwitchRepository) RecordHistory(ctx context.Context, orgID string, history *KillSwitchHistory) error {
	if history.ID == "" {
		history.ID = uuid.New().String()
	}
	if history.PerformedAt.IsZero() {
		history.PerformedAt = time.Now().UTC()
	}

	query := `
		INSERT INTO mas_kill_switch_history (
			id, kill_switch_id, action, previous_status, new_status,
			reason, performed_by, performed_at
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8
		WHERE EXISTS (
			SELECT 1 FROM mas_kill_switches WHERE id = $9 AND org_id = $10
		)
	`

	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		res, execErr := tx.ExecContext(ctx, query,
			history.ID, history.KillSwitchID, history.Action, history.PreviousStatus,
			history.NewStatus, history.Reason, history.PerformedBy, history.PerformedAt,
			history.KillSwitchID, orgID,
		)
		if execErr != nil {
			return execErr
		}
		affected, raErr := res.RowsAffected()
		if raErr != nil {
			return raErr
		}
		if affected == 0 {
			return fmt.Errorf("kill switch %q is not owned by organization %q", history.KillSwitchID, orgID)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to record kill switch history: %w", err)
	}

	return nil
}

// GetHistory retrieves kill switch history for a system.
func (r *PostgresKillSwitchRepository) GetHistory(ctx context.Context, orgID, systemID string, limit int) ([]*KillSwitchHistory, error) {
	if limit <= 0 {
		limit = DefaultListLimit
	}
	if limit > MaxListLimit {
		limit = MaxListLimit
	}

	query := `
		SELECT h.id, h.kill_switch_id, h.action, h.previous_status, h.new_status,
			h.reason, h.performed_by, h.performed_at
		FROM mas_kill_switch_history h
		INNER JOIN mas_kill_switches ks ON h.kill_switch_id = ks.id
		WHERE ks.org_id = $1 AND ks.system_id = $2
		ORDER BY h.performed_at DESC
		LIMIT $3
	`

	var history []*KillSwitchHistory
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID, systemID, limit)
		if err != nil {
			return fmt.Errorf("failed to get kill switch history: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			h := &KillSwitchHistory{}
			var reason sql.NullString

			if scanErr := rows.Scan(
				&h.ID, &h.KillSwitchID, &h.Action, &h.PreviousStatus,
				&h.NewStatus, &reason, &h.PerformedBy, &h.PerformedAt,
			); scanErr != nil {
				return fmt.Errorf("failed to scan kill switch history: %w", scanErr)
			}

			if reason.Valid {
				h.Reason = reason.String
			}

			history = append(history, h)
		}

		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return history, nil
}
