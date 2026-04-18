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
)

// KillSwitchRepository defines the interface for kill switch data access.
type KillSwitchRepository interface {
	// Create creates a new kill switch configuration.
	Create(ctx context.Context, ks *KillSwitch) error

	// GetBySystemID retrieves a kill switch by system ID.
	GetBySystemID(ctx context.Context, orgID, systemID string) (*KillSwitch, error)

	// Update updates a kill switch configuration.
	Update(ctx context.Context, ks *KillSwitch) error

	// RecordHistory records a kill switch state change.
	RecordHistory(ctx context.Context, history *KillSwitchHistory) error

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

	_, err = r.db.ExecContext(ctx, query,
		ks.ID, ks.OrgID, ks.SystemID, ks.Status, ks.TriggerReason, conditionsJSON,
		ks.AutoTriggerEnabled, ks.AccuracyThreshold, ks.BiasThreshold,
		ks.ErrorRateThreshold, ks.CreatedAt, ks.UpdatedAt,
	)
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

	err := r.db.QueryRowContext(ctx, query, orgID, systemID).Scan(
		&ks.ID, &ks.OrgID, &ks.SystemID, &ks.Status, &triggerReason, &conditionsJSON,
		&ks.AutoTriggerEnabled, &accuracyThreshold, &biasThreshold, &errorRateThreshold,
		&triggeredAt, &triggeredBy, &restoredAt, &restoredBy, &restoreReason,
		&ks.CreatedAt, &ks.UpdatedAt,
	)
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

	_, err = r.db.ExecContext(ctx, query,
		ks.Status, ks.TriggerReason, conditionsJSON, ks.AutoTriggerEnabled,
		ks.AccuracyThreshold, ks.BiasThreshold, ks.ErrorRateThreshold,
		ks.TriggeredAt, ks.TriggeredBy, ks.RestoredAt, ks.RestoredBy,
		ks.RestoreReason, ks.UpdatedAt, ks.OrgID, ks.SystemID,
	)
	if err != nil {
		return fmt.Errorf("failed to update kill switch: %w", err)
	}

	return nil
}

// RecordHistory records a kill switch state change.
func (r *PostgresKillSwitchRepository) RecordHistory(ctx context.Context, history *KillSwitchHistory) error {
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
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8
		)
	`

	_, err := r.db.ExecContext(ctx, query,
		history.ID, history.KillSwitchID, history.Action, history.PreviousStatus,
		history.NewStatus, history.Reason, history.PerformedBy, history.PerformedAt,
	)
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

	rows, err := r.db.QueryContext(ctx, query, orgID, systemID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get kill switch history: %w", err)
	}
	defer rows.Close()

	var history []*KillSwitchHistory
	for rows.Next() {
		h := &KillSwitchHistory{}
		var reason sql.NullString

		err := rows.Scan(
			&h.ID, &h.KillSwitchID, &h.Action, &h.PreviousStatus,
			&h.NewStatus, &reason, &h.PerformedBy, &h.PerformedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan kill switch history: %w", err)
		}

		if reason.Valid {
			h.Reason = reason.String
		}

		history = append(history, h)
	}

	return history, nil
}
