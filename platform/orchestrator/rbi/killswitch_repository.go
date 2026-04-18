// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrKillSwitchNotFound is returned when a kill switch is not found.
var ErrKillSwitchNotFound = errors.New("kill switch not found")

// KillSwitchRepository provides data access for kill switches.
type KillSwitchRepository interface {
	Create(ctx context.Context, ks *KillSwitch) error
	Get(ctx context.Context, orgID, id string) (*KillSwitch, error)
	GetByScope(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitch, error)
	List(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error)
	ListActive(ctx context.Context, orgID string) ([]*KillSwitch, error)
	ListBySystem(ctx context.Context, orgID, systemID string) ([]*KillSwitch, error)
	Update(ctx context.Context, ks *KillSwitch) error
	Delete(ctx context.Context, orgID, id string) error
	AddHistoryEntry(ctx context.Context, entry *KillSwitchHistoryEntry) error
	GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error)
	CheckActive(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (bool, *KillSwitch, error)
}

// ListKillSwitchParams defines filtering parameters for listing kill switches.
type ListKillSwitchParams struct {
	SystemID string
	Scope    string
	IsActive *bool
	Limit    int
	Offset   int
}

// PostgresKillSwitchRepository implements KillSwitchRepository using PostgreSQL.
type PostgresKillSwitchRepository struct {
	db *sql.DB
}

// NewPostgresKillSwitchRepository creates a new PostgreSQL-backed kill switch repository.
func NewPostgresKillSwitchRepository(db *sql.DB) *PostgresKillSwitchRepository {
	return &PostgresKillSwitchRepository{db: db}
}

// Create inserts a new kill switch.
func (r *PostgresKillSwitchRepository) Create(ctx context.Context, ks *KillSwitch) error {
	if ks.ID == "" {
		ks.ID = uuid.New().String()
	}
	ks.CreatedAt = time.Now().UTC()
	ks.UpdatedAt = ks.CreatedAt

	// Serialize JSON fields
	triggerThresholdJSON, err := json.Marshal(ks.TriggerThreshold)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger_threshold: %w", err)
	}
	fallbackConfigJSON, err := json.Marshal(ks.FallbackConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal fallback_config: %w", err)
	}

	query := `
		INSERT INTO rbi_kill_switches (
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
			$11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		ks.ID,
		ks.OrgID,
		string(ks.Scope),
		nullString(ks.SystemID),
		nullString(ks.TargetIdentifier),
		ks.IsActive,
		nullString(ks.ActivatedBy),
		nullString(ks.ActivatedByEmail),
		nullTime(ks.ActivatedAt),
		nullString(ks.ActivationReason),
		ks.AutoTriggered,
		nullString(ks.TriggerCondition),
		triggerThresholdJSON,
		string(ks.FallbackBehavior),
		fallbackConfigJSON,
		nullString(ks.DeactivatedBy),
		nullString(ks.DeactivatedByEmail),
		nullTime(ks.DeactivatedAt),
		nullString(ks.DeactivationReason),
		ks.CreatedAt,
		ks.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create kill switch: %w", err)
	}

	return nil
}

// Get retrieves a kill switch by ID.
func (r *PostgresKillSwitchRepository) Get(ctx context.Context, orgID, id string) (*KillSwitch, error) {
	query := `
		SELECT
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		FROM rbi_kill_switches
		WHERE id = $1 AND org_id = $2
	`
	return r.scanKillSwitch(r.db.QueryRowContext(ctx, query, id, orgID))
}

// GetByScope retrieves a kill switch by scope and target.
func (r *PostgresKillSwitchRepository) GetByScope(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (*KillSwitch, error) {
	var query string
	var args []interface{}

	if scope == KillSwitchScopeGlobal {
		query = `
			SELECT
				id, org_id, scope, system_id, target_identifier,
				is_active, activated_by, activated_by_email, activated_at, activation_reason,
				auto_triggered, trigger_condition, trigger_threshold,
				fallback_behavior, fallback_config,
				deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
				created_at, updated_at
			FROM rbi_kill_switches
			WHERE org_id = $1 AND scope = $2
		`
		args = []interface{}{orgID, string(scope)}
	} else if scope == KillSwitchScopeSystem {
		query = `
			SELECT
				id, org_id, scope, system_id, target_identifier,
				is_active, activated_by, activated_by_email, activated_at, activation_reason,
				auto_triggered, trigger_condition, trigger_threshold,
				fallback_behavior, fallback_config,
				deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
				created_at, updated_at
			FROM rbi_kill_switches
			WHERE org_id = $1 AND scope = $2 AND system_id = $3
		`
		args = []interface{}{orgID, string(scope), systemID}
	} else {
		query = `
			SELECT
				id, org_id, scope, system_id, target_identifier,
				is_active, activated_by, activated_by_email, activated_at, activation_reason,
				auto_triggered, trigger_condition, trigger_threshold,
				fallback_behavior, fallback_config,
				deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
				created_at, updated_at
			FROM rbi_kill_switches
			WHERE org_id = $1 AND scope = $2 AND system_id = $3 AND target_identifier = $4
		`
		args = []interface{}{orgID, string(scope), systemID, targetID}
	}

	return r.scanKillSwitch(r.db.QueryRowContext(ctx, query, args...))
}

// List retrieves kill switches with optional filtering.
func (r *PostgresKillSwitchRepository) List(ctx context.Context, orgID string, params *ListKillSwitchParams) ([]*KillSwitch, int, error) {
	if params == nil {
		params = &ListKillSwitchParams{}
	}
	if params.Limit <= 0 {
		params.Limit = 50
	}
	if params.Limit > 100 {
		params.Limit = 100
	}

	// Build WHERE clause
	conditions := []string{"org_id = $1"}
	args := []interface{}{orgID}
	argIdx := 2

	if params.SystemID != "" {
		conditions = append(conditions, fmt.Sprintf("system_id = $%d", argIdx))
		args = append(args, params.SystemID)
		argIdx++
	}
	if params.Scope != "" {
		conditions = append(conditions, fmt.Sprintf("scope = $%d", argIdx))
		args = append(args, params.Scope)
		argIdx++
	}
	if params.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIdx))
		args = append(args, *params.IsActive)
		argIdx++
	}

	whereClause := strings.Join(conditions, " AND ")

	// Count total
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM rbi_kill_switches WHERE %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count kill switches: %w", err)
	}

	// Fetch records
	query := fmt.Sprintf(`
		SELECT
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		FROM rbi_kill_switches
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIdx, argIdx+1)
	args = append(args, params.Limit, params.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list kill switches: %w", err)
	}
	defer rows.Close()

	var switches []*KillSwitch
	for rows.Next() {
		ks, err := r.scanKillSwitchRows(rows)
		if err != nil {
			return nil, 0, err
		}
		switches = append(switches, ks)
	}

	return switches, total, rows.Err()
}

// ListActive retrieves all active kill switches.
func (r *PostgresKillSwitchRepository) ListActive(ctx context.Context, orgID string) ([]*KillSwitch, error) {
	query := `
		SELECT
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		FROM rbi_kill_switches
		WHERE org_id = $1 AND is_active = true
		ORDER BY scope, system_id
	`

	rows, err := r.db.QueryContext(ctx, query, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active kill switches: %w", err)
	}
	defer rows.Close()

	var switches []*KillSwitch
	for rows.Next() {
		ks, err := r.scanKillSwitchRows(rows)
		if err != nil {
			return nil, err
		}
		switches = append(switches, ks)
	}

	return switches, rows.Err()
}

// ListBySystem retrieves all kill switches for a specific system.
func (r *PostgresKillSwitchRepository) ListBySystem(ctx context.Context, orgID, systemID string) ([]*KillSwitch, error) {
	query := `
		SELECT
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		FROM rbi_kill_switches
		WHERE org_id = $1 AND system_id = $2
		ORDER BY scope, created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, orgID, systemID)
	if err != nil {
		return nil, fmt.Errorf("failed to list kill switches by system: %w", err)
	}
	defer rows.Close()

	var switches []*KillSwitch
	for rows.Next() {
		ks, err := r.scanKillSwitchRows(rows)
		if err != nil {
			return nil, err
		}
		switches = append(switches, ks)
	}

	return switches, rows.Err()
}

// Update updates an existing kill switch.
func (r *PostgresKillSwitchRepository) Update(ctx context.Context, ks *KillSwitch) error {
	ks.UpdatedAt = time.Now().UTC()

	// Serialize JSON fields
	triggerThresholdJSON, err := json.Marshal(ks.TriggerThreshold)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger_threshold: %w", err)
	}
	fallbackConfigJSON, err := json.Marshal(ks.FallbackConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal fallback_config: %w", err)
	}

	query := `
		UPDATE rbi_kill_switches SET
			scope = $3, system_id = $4, target_identifier = $5,
			is_active = $6, activated_by = $7, activated_by_email = $8,
			activated_at = $9, activation_reason = $10,
			auto_triggered = $11, trigger_condition = $12, trigger_threshold = $13,
			fallback_behavior = $14, fallback_config = $15,
			deactivated_by = $16, deactivated_by_email = $17,
			deactivated_at = $18, deactivation_reason = $19,
			updated_at = $20
		WHERE id = $1 AND org_id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		ks.ID,
		ks.OrgID,
		string(ks.Scope),
		nullString(ks.SystemID),
		nullString(ks.TargetIdentifier),
		ks.IsActive,
		nullString(ks.ActivatedBy),
		nullString(ks.ActivatedByEmail),
		nullTime(ks.ActivatedAt),
		nullString(ks.ActivationReason),
		ks.AutoTriggered,
		nullString(ks.TriggerCondition),
		triggerThresholdJSON,
		string(ks.FallbackBehavior),
		fallbackConfigJSON,
		nullString(ks.DeactivatedBy),
		nullString(ks.DeactivatedByEmail),
		nullTime(ks.DeactivatedAt),
		nullString(ks.DeactivationReason),
		ks.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update kill switch: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrKillSwitchNotFound
	}

	return nil
}

// Delete removes a kill switch.
func (r *PostgresKillSwitchRepository) Delete(ctx context.Context, orgID, id string) error {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM rbi_kill_switches WHERE id = $1 AND org_id = $2",
		id, orgID,
	)
	if err != nil {
		return fmt.Errorf("failed to delete kill switch: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrKillSwitchNotFound
	}

	return nil
}

// AddHistoryEntry adds a history entry for audit trail.
func (r *PostgresKillSwitchRepository) AddHistoryEntry(ctx context.Context, entry *KillSwitchHistoryEntry) error {
	entry.CreatedAt = time.Now().UTC()

	previousStateJSON, err := json.Marshal(entry.PreviousState)
	if err != nil {
		return fmt.Errorf("failed to marshal previous_state: %w", err)
	}
	newStateJSON, err := json.Marshal(entry.NewState)
	if err != nil {
		return fmt.Errorf("failed to marshal new_state: %w", err)
	}
	metadataJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbi_kill_switch_history (
			org_id, kill_switch_id, action, actor_id, actor_email, actor_role,
			actor_ip, reason, previous_state, new_state, metadata, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id
	`

	err = r.db.QueryRowContext(ctx, query,
		entry.OrgID,
		entry.KillSwitchID,
		string(entry.Action),
		entry.ActorID,
		nullString(entry.ActorEmail),
		nullString(entry.ActorRole),
		nullString(entry.ActorIP),
		nullString(entry.Reason),
		previousStateJSON,
		newStateJSON,
		metadataJSON,
		entry.CreatedAt,
	).Scan(&entry.ID)
	if err != nil {
		return fmt.Errorf("failed to add history entry: %w", err)
	}

	return nil
}

// GetHistory retrieves history entries for a kill switch.
func (r *PostgresKillSwitchRepository) GetHistory(ctx context.Context, orgID, killSwitchID string, limit int) ([]*KillSwitchHistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	query := `
		SELECT
			id, org_id, kill_switch_id, action, actor_id, actor_email, actor_role,
			actor_ip, reason, previous_state, new_state, metadata, created_at
		FROM rbi_kill_switch_history
		WHERE org_id = $1 AND kill_switch_id = $2
		ORDER BY created_at DESC
		LIMIT $3
	`

	rows, err := r.db.QueryContext(ctx, query, orgID, killSwitchID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get history: %w", err)
	}
	defer rows.Close()

	var entries []*KillSwitchHistoryEntry
	for rows.Next() {
		entry, err := r.scanHistoryEntry(rows)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}

	return entries, rows.Err()
}

// CheckActive checks if any active kill switch applies to the given scope.
func (r *PostgresKillSwitchRepository) CheckActive(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (bool, *KillSwitch, error) {
	// Check in order of priority: global > system > specific

	// Check global kill switch first
	globalQuery := `
		SELECT
			id, org_id, scope, system_id, target_identifier,
			is_active, activated_by, activated_by_email, activated_at, activation_reason,
			auto_triggered, trigger_condition, trigger_threshold,
			fallback_behavior, fallback_config,
			deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
			created_at, updated_at
		FROM rbi_kill_switches
		WHERE org_id = $1 AND scope = 'global' AND is_active = true
		LIMIT 1
	`
	ks, err := r.scanKillSwitch(r.db.QueryRowContext(ctx, globalQuery, orgID))
	if err == nil {
		return true, ks, nil
	}
	if err != ErrKillSwitchNotFound {
		return false, nil, err
	}

	// Check system-level kill switch
	if systemID != "" {
		systemQuery := `
			SELECT
				id, org_id, scope, system_id, target_identifier,
				is_active, activated_by, activated_by_email, activated_at, activation_reason,
				auto_triggered, trigger_condition, trigger_threshold,
				fallback_behavior, fallback_config,
				deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
				created_at, updated_at
			FROM rbi_kill_switches
			WHERE org_id = $1 AND scope = 'system' AND system_id = $2 AND is_active = true
			LIMIT 1
		`
		ks, err = r.scanKillSwitch(r.db.QueryRowContext(ctx, systemQuery, orgID, systemID))
		if err == nil {
			return true, ks, nil
		}
		if err != ErrKillSwitchNotFound {
			return false, nil, err
		}
	}

	// Check specific scope
	if systemID != "" && targetID != "" && scope != KillSwitchScopeGlobal && scope != KillSwitchScopeSystem {
		specificQuery := `
			SELECT
				id, org_id, scope, system_id, target_identifier,
				is_active, activated_by, activated_by_email, activated_at, activation_reason,
				auto_triggered, trigger_condition, trigger_threshold,
				fallback_behavior, fallback_config,
				deactivated_by, deactivated_by_email, deactivated_at, deactivation_reason,
				created_at, updated_at
			FROM rbi_kill_switches
			WHERE org_id = $1 AND scope = $2 AND system_id = $3 AND target_identifier = $4 AND is_active = true
			LIMIT 1
		`
		ks, err = r.scanKillSwitch(r.db.QueryRowContext(ctx, specificQuery, orgID, string(scope), systemID, targetID))
		if err == nil {
			return true, ks, nil
		}
		if err != ErrKillSwitchNotFound {
			return false, nil, err
		}
	}

	return false, nil, nil
}

// scanKillSwitch scans a single row into a KillSwitch.
func (r *PostgresKillSwitchRepository) scanKillSwitch(row *sql.Row) (*KillSwitch, error) {
	var ks KillSwitch
	var systemID, targetIdentifier sql.NullString
	var activatedBy, activatedByEmail, activationReason sql.NullString
	var triggerCondition sql.NullString
	var deactivatedBy, deactivatedByEmail, deactivationReason sql.NullString
	var activatedAt, deactivatedAt sql.NullTime
	var triggerThresholdJSON, fallbackConfigJSON []byte

	err := row.Scan(
		&ks.ID, &ks.OrgID, &ks.Scope, &systemID, &targetIdentifier,
		&ks.IsActive, &activatedBy, &activatedByEmail, &activatedAt, &activationReason,
		&ks.AutoTriggered, &triggerCondition, &triggerThresholdJSON,
		&ks.FallbackBehavior, &fallbackConfigJSON,
		&deactivatedBy, &deactivatedByEmail, &deactivatedAt, &deactivationReason,
		&ks.CreatedAt, &ks.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrKillSwitchNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan kill switch: %w", err)
	}

	// Handle nullable fields
	if systemID.Valid {
		ks.SystemID = systemID.String
	}
	if targetIdentifier.Valid {
		ks.TargetIdentifier = targetIdentifier.String
	}
	if activatedBy.Valid {
		ks.ActivatedBy = activatedBy.String
	}
	if activatedByEmail.Valid {
		ks.ActivatedByEmail = activatedByEmail.String
	}
	if activatedAt.Valid {
		ks.ActivatedAt = &activatedAt.Time
	}
	if activationReason.Valid {
		ks.ActivationReason = activationReason.String
	}
	if triggerCondition.Valid {
		ks.TriggerCondition = triggerCondition.String
	}
	if deactivatedBy.Valid {
		ks.DeactivatedBy = deactivatedBy.String
	}
	if deactivatedByEmail.Valid {
		ks.DeactivatedByEmail = deactivatedByEmail.String
	}
	if deactivatedAt.Valid {
		ks.DeactivatedAt = &deactivatedAt.Time
	}
	if deactivationReason.Valid {
		ks.DeactivationReason = deactivationReason.String
	}

	// Unmarshal JSON
	if len(triggerThresholdJSON) > 0 {
		json.Unmarshal(triggerThresholdJSON, &ks.TriggerThreshold)
	}
	if len(fallbackConfigJSON) > 0 {
		json.Unmarshal(fallbackConfigJSON, &ks.FallbackConfig)
	}

	return &ks, nil
}

// scanKillSwitchRows scans a row from rows into a KillSwitch.
func (r *PostgresKillSwitchRepository) scanKillSwitchRows(rows *sql.Rows) (*KillSwitch, error) {
	var ks KillSwitch
	var systemID, targetIdentifier sql.NullString
	var activatedBy, activatedByEmail, activationReason sql.NullString
	var triggerCondition sql.NullString
	var deactivatedBy, deactivatedByEmail, deactivationReason sql.NullString
	var activatedAt, deactivatedAt sql.NullTime
	var triggerThresholdJSON, fallbackConfigJSON []byte

	err := rows.Scan(
		&ks.ID, &ks.OrgID, &ks.Scope, &systemID, &targetIdentifier,
		&ks.IsActive, &activatedBy, &activatedByEmail, &activatedAt, &activationReason,
		&ks.AutoTriggered, &triggerCondition, &triggerThresholdJSON,
		&ks.FallbackBehavior, &fallbackConfigJSON,
		&deactivatedBy, &deactivatedByEmail, &deactivatedAt, &deactivationReason,
		&ks.CreatedAt, &ks.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan kill switch row: %w", err)
	}

	// Handle nullable fields
	if systemID.Valid {
		ks.SystemID = systemID.String
	}
	if targetIdentifier.Valid {
		ks.TargetIdentifier = targetIdentifier.String
	}
	if activatedBy.Valid {
		ks.ActivatedBy = activatedBy.String
	}
	if activatedByEmail.Valid {
		ks.ActivatedByEmail = activatedByEmail.String
	}
	if activatedAt.Valid {
		ks.ActivatedAt = &activatedAt.Time
	}
	if activationReason.Valid {
		ks.ActivationReason = activationReason.String
	}
	if triggerCondition.Valid {
		ks.TriggerCondition = triggerCondition.String
	}
	if deactivatedBy.Valid {
		ks.DeactivatedBy = deactivatedBy.String
	}
	if deactivatedByEmail.Valid {
		ks.DeactivatedByEmail = deactivatedByEmail.String
	}
	if deactivatedAt.Valid {
		ks.DeactivatedAt = &deactivatedAt.Time
	}
	if deactivationReason.Valid {
		ks.DeactivationReason = deactivationReason.String
	}

	// Unmarshal JSON
	if len(triggerThresholdJSON) > 0 {
		json.Unmarshal(triggerThresholdJSON, &ks.TriggerThreshold)
	}
	if len(fallbackConfigJSON) > 0 {
		json.Unmarshal(fallbackConfigJSON, &ks.FallbackConfig)
	}

	return &ks, nil
}

// scanHistoryEntry scans a row from rows into a KillSwitchHistoryEntry.
func (r *PostgresKillSwitchRepository) scanHistoryEntry(rows *sql.Rows) (*KillSwitchHistoryEntry, error) {
	var entry KillSwitchHistoryEntry
	var actorEmail, actorRole, actorIP, reason sql.NullString
	var previousStateJSON, newStateJSON, metadataJSON []byte

	err := rows.Scan(
		&entry.ID, &entry.OrgID, &entry.KillSwitchID, &entry.Action,
		&entry.ActorID, &actorEmail, &actorRole, &actorIP, &reason,
		&previousStateJSON, &newStateJSON, &metadataJSON,
		&entry.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan history entry: %w", err)
	}

	if actorEmail.Valid {
		entry.ActorEmail = actorEmail.String
	}
	if actorRole.Valid {
		entry.ActorRole = actorRole.String
	}
	if actorIP.Valid {
		entry.ActorIP = actorIP.String
	}
	if reason.Valid {
		entry.Reason = reason.String
	}

	if len(previousStateJSON) > 0 {
		json.Unmarshal(previousStateJSON, &entry.PreviousState)
	}
	if len(newStateJSON) > 0 {
		json.Unmarshal(newStateJSON, &entry.NewState)
	}
	if len(metadataJSON) > 0 {
		json.Unmarshal(metadataJSON, &entry.Metadata)
	}

	return &entry, nil
}
