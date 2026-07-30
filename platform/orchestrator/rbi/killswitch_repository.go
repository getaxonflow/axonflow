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

	"axonflow/platform/agent/rls"
)

// #3103. Migration 301 switches RLS on for all seven rbi_* tables with a
// `FOR ALL USING (org_id = get_current_org_id())` policy, but this package
// never set app.current_org_id — so on an axonflow_app_role pool every read
// here returned SILENT ZERO ROWS and every write failed closed. For a kill
// switch that is the worst possible failure mode: CheckActive would report
// "no kill switch active" for an org that had one engaged. Every statement
// below therefore runs inside rls.WithOrgScope, which opens a transaction and
// SET LOCALs the GUC the policy reads. The hand-written `WHERE org_id = $n`
// predicates are KEPT: the wrap is a backstop, not a replacement. See the
// fuller note in auditexport_repository.go.

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

	err = rls.WithOrgScope(ctx, r.db, ks.OrgID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, query,
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
		return execErr
	})
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
	var ks *KillSwitch
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		ks, scanErr = r.scanKillSwitch(tx.QueryRowContext(ctx, query, id, orgID))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return ks, nil
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

	var ks *KillSwitch
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var scanErr error
		ks, scanErr = r.scanKillSwitch(tx.QueryRowContext(ctx, query, args...))
		return scanErr
	}); err != nil {
		return nil, err
	}
	return ks, nil
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
	// countArgs must be captured BEFORE the LIMIT/OFFSET append, and the append
	// must not write through the shared backing array — otherwise the count
	// would run with the page args spliced in.
	countArgs := args
	args = append(append([]interface{}{}, args...), params.Limit, params.Offset)

	// One wrap for BOTH statements: the count and the page are separate call
	// sites and each had to be scoped, and sharing the transaction also makes
	// total and rows a consistent snapshot.
	var switches []*KillSwitch
	var total int
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
			return fmt.Errorf("failed to count kill switches: %w", err)
		}

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to list kill switches: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			ks, scanErr := r.scanKillSwitchRows(rows)
			if scanErr != nil {
				return scanErr
			}
			switches = append(switches, ks)
		}
		return rows.Err()
	}); err != nil {
		return nil, 0, err
	}

	return switches, total, nil
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

	var switches []*KillSwitch
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID)
		if err != nil {
			return fmt.Errorf("failed to list active kill switches: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			ks, scanErr := r.scanKillSwitchRows(rows)
			if scanErr != nil {
				return scanErr
			}
			switches = append(switches, ks)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return switches, nil
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

	var switches []*KillSwitch
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID, systemID)
		if err != nil {
			return fmt.Errorf("failed to list kill switches by system: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			ks, scanErr := r.scanKillSwitchRows(rows)
			if scanErr != nil {
				return scanErr
			}
			switches = append(switches, ks)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return switches, nil
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

	var result sql.Result
	err = rls.WithOrgScope(ctx, r.db, ks.OrgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx, query,
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
		return execErr
	})
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
	var result sql.Result
	err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		var execErr error
		result, execErr = tx.ExecContext(ctx,
			"DELETE FROM rbi_kill_switches WHERE id = $1 AND org_id = $2",
			id, orgID,
		)
		return execErr
	})
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

	// This is a WRITE with the shape of a read (INSERT ... RETURNING id), so it
	// needs the org scope for the policy's WITH CHECK, not just for visibility.
	err = rls.WithOrgScope(ctx, r.db, entry.OrgID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query,
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
	})
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

	var entries []*KillSwitchHistoryEntry
	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, orgID, killSwitchID, limit)
		if err != nil {
			return fmt.Errorf("failed to get history: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			entry, scanErr := r.scanHistoryEntry(rows)
			if scanErr != nil {
				return scanErr
			}
			entries = append(entries, entry)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}

	return entries, nil
}

// CheckActive checks if any active kill switch applies to the given scope.
func (r *PostgresKillSwitchRepository) CheckActive(ctx context.Context, orgID string, scope KillSwitchScope, systemID, targetID string) (bool, *KillSwitch, error) {
	// Check in order of priority: global > system > specific.
	//
	// All three probes share ONE rls.WithOrgScope, so they see a consistent
	// snapshot as well as the org GUC. ErrKillSwitchNotFound is NOT an error
	// here — it means "keep looking", and ultimately "no kill switch active" —
	// so it must never be returned out of the closure: WithOrgScope propagates
	// the closure's error verbatim, which would turn a benign miss into a
	// hard error. The verdict is carried out in `active` / `match` instead.
	var active bool
	var match *KillSwitch

	if err := rls.WithOrgScope(ctx, r.db, orgID, func(tx *sql.Tx) error {
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
		ks, err := r.scanKillSwitch(tx.QueryRowContext(ctx, globalQuery, orgID))
		if err == nil {
			active, match = true, ks
			return nil
		}
		if err != ErrKillSwitchNotFound {
			return err
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
			ks, err = r.scanKillSwitch(tx.QueryRowContext(ctx, systemQuery, orgID, systemID))
			if err == nil {
				active, match = true, ks
				return nil
			}
			if err != ErrKillSwitchNotFound {
				return err
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
			ks, err = r.scanKillSwitch(tx.QueryRowContext(ctx, specificQuery, orgID, string(scope), systemID, targetID))
			if err == nil {
				active, match = true, ks
				return nil
			}
			if err != ErrKillSwitchNotFound {
				return err
			}
		}

		return nil
	}); err != nil {
		return false, nil, err
	}

	return active, match, nil
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
