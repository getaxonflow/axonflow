// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"axonflow/platform/agent/rls"
)

// Common errors
var (
	ErrExecutionNotFound = errors.New("execution not found")
	ErrInvalidExecution  = errors.New("invalid execution")
	// ErrMissingOrgID is returned by writers when ExecutionStatus.OrgID is
	// empty. Under v9 Phase 8 axonflow_app_role + ENABLE-RLS on
	// execution_history (mig 042), an empty org_id makes the INSERT/UPDATE
	// WITH CHECK predicate fail; surface this as a loud error rather than
	// silently swallowing the row.
	ErrMissingOrgID = errors.New("execution: OrgID must be non-empty (RLS on execution_history)")
)

// PostgresRepository implements ExecutionRepository for PostgreSQL.
type PostgresRepository struct {
	db *sql.DB
	// lookupDB serves the by-id/by-metadata DISCOVERY reads (Get,
	// GetByPlanID, GetByMetadata): the row is what establishes which tenant
	// an execution belongs to, so no tenant GUC can be set beforehand —
	// under axonflow_app_role the bare read matches 0 rows through mig 042's
	// RLS and every lookup returns ErrExecutionNotFound (#3039). Callers
	// post-authorize the result (the unified handler rejects tenant/org
	// mismatch; the tracker uses the row's own org/tenant to scope its
	// follow-up writes), so a BYPASSRLS pool here is the same trust shape as
	// the SECURITY DEFINER portal_session_lookup (mig 118). Falls back to db
	// when unset (tests, non-app-role deployments where db sees everything).
	lookupDB *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository.
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// SetCrossOrgDB installs a BYPASSRLS (axonflow_platform_admin) pool for the
// repository's discovery reads. See the lookupDB field comment (#3039).
func (r *PostgresRepository) SetCrossOrgDB(db *sql.DB) {
	r.lookupDB = db
}

func (r *PostgresRepository) lookup() *sql.DB {
	if r.lookupDB != nil {
		return r.lookupDB
	}
	return r.db
}

// Create inserts a new execution record.
//
// v9 Phase 8 #2384 PR-C1: execution_history is ENABLE-RLS (mig 042) and
// its USING/WITH CHECK predicate is keyed on the legacy app.current_tenant_id
// session variable, not the v9 app.current_org_id used by mig 099+ FORCE-RLS
// tables. We wrap the INSERT in WithOrgAndTenantScope so BOTH session
// variables are pinned for the lifetime of the txn; under app_role this
// is the only combination that satisfies the policy.
func (r *PostgresRepository) Create(ctx context.Context, exec *ExecutionStatus) error {
	if exec == nil {
		return ErrInvalidExecution
	}
	if exec.OrgID == "" || exec.TenantID == "" {
		return ErrMissingOrgID
	}

	stepsJSON, err := json.Marshal(exec.Steps)
	if err != nil {
		return fmt.Errorf("failed to marshal steps: %w", err)
	}

	metadataJSON, err := json.Marshal(exec.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO execution_history (
			id, execution_type, external_id, name, source,
			tenant_id, org_id, user_id, client_id,
			status, current_step_index, total_steps,
			started_at, estimated_cost_usd, actual_cost_usd,
			steps, metadata, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12,
			$13, $14, $15,
			$16, $17, $18, $19
		)
	`

	err = rls.WithOrgAndTenantScope(ctx, r.db, exec.OrgID, exec.TenantID, func(tx *sql.Tx) error {
		_, exErr := tx.ExecContext(ctx, query,
			exec.ExecutionID, exec.ExecutionType, exec.ExecutionID, exec.Name, exec.Source,
			nullableString(exec.TenantID), nullableString(exec.OrgID), nullableString(exec.UserID), nullableString(exec.ClientID),
			exec.Status, exec.CurrentStepIndex, exec.TotalSteps,
			exec.StartedAt, exec.EstimatedCostUSD, exec.ActualCostUSD,
			stepsJSON, metadataJSON, exec.CreatedAt, exec.UpdatedAt,
		)
		return exErr
	})
	if err != nil {
		return fmt.Errorf("failed to create execution: %w", err)
	}

	return nil
}

// Get retrieves an execution by ID.
func (r *PostgresRepository) Get(ctx context.Context, executionID string) (*ExecutionStatus, error) {
	query := `
		SELECT
			id, execution_type, name, source,
			tenant_id, org_id, user_id, client_id,
			status, current_step_index, total_steps,
			started_at, completed_at, estimated_cost_usd, actual_cost_usd,
			steps, error_message, metadata, created_at, updated_at
		FROM execution_history
		WHERE id = $1
	`

	var exec ExecutionStatus
	var source, tenantID, orgID, userID, clientID sql.NullString
	var completedAt sql.NullTime
	var estimatedCost, actualCost sql.NullFloat64
	var stepsJSON, metadataJSON []byte
	var errorMsg sql.NullString

	// Discovery read — runs on the lookup pool (see lookupDB field comment).
	err := r.lookup().QueryRowContext(ctx, query, executionID).Scan(
		&exec.ExecutionID, &exec.ExecutionType, &exec.Name, &source,
		&tenantID, &orgID, &userID, &clientID,
		&exec.Status, &exec.CurrentStepIndex, &exec.TotalSteps,
		&exec.StartedAt, &completedAt, &estimatedCost, &actualCost,
		&stepsJSON, &errorMsg, &metadataJSON, &exec.CreatedAt, &exec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrExecutionNotFound
		}
		return nil, fmt.Errorf("failed to get execution: %w", err)
	}

	// Convert nullable fields
	exec.Source = source.String
	exec.TenantID = tenantID.String
	exec.OrgID = orgID.String
	exec.UserID = userID.String
	exec.ClientID = clientID.String
	if completedAt.Valid {
		exec.CompletedAt = &completedAt.Time
	}
	if estimatedCost.Valid {
		exec.EstimatedCostUSD = &estimatedCost.Float64
	}
	if actualCost.Valid {
		exec.ActualCostUSD = &actualCost.Float64
	}
	if errorMsg.Valid {
		exec.Error = errorMsg.String
	}

	// Unmarshal JSON fields
	if len(stepsJSON) > 0 {
		if err := json.Unmarshal(stepsJSON, &exec.Steps); err != nil {
			return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &exec.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &exec, nil
}

// Update updates an execution record.
//
// v9 Phase 8 #2384 PR-C1: UPDATE on execution_history is gated by mig 042's
// tenant_isolation policy under app_role. exec carries TenantID+OrgID (set
// by the caller at Create time and round-tripped through Get); we use
// WithOrgAndTenantScope to pin both session variables for the UPDATE.
func (r *PostgresRepository) Update(ctx context.Context, exec *ExecutionStatus) error {
	if exec == nil {
		return ErrInvalidExecution
	}
	if exec.OrgID == "" || exec.TenantID == "" {
		return ErrMissingOrgID
	}

	stepsJSON, err := json.Marshal(exec.Steps)
	if err != nil {
		return fmt.Errorf("failed to marshal steps: %w", err)
	}

	metadataJSON, err := json.Marshal(exec.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE execution_history SET
			status = $2,
			current_step_index = $3,
			total_steps = $4,
			completed_at = $5,
			estimated_cost_usd = $6,
			actual_cost_usd = $7,
			steps = $8,
			error_message = $9,
			metadata = $10,
			updated_at = $11
		WHERE id = $1
	`

	var rows int64
	err = rls.WithOrgAndTenantScope(ctx, r.db, exec.OrgID, exec.TenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query,
			exec.ExecutionID,
			exec.Status,
			exec.CurrentStepIndex,
			exec.TotalSteps,
			exec.CompletedAt,
			exec.EstimatedCostUSD,
			exec.ActualCostUSD,
			stepsJSON,
			nullableString(exec.Error),
			metadataJSON,
			exec.UpdatedAt,
		)
		if exErr != nil {
			return fmt.Errorf("failed to update execution: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// List returns executions matching the filters.
func (r *PostgresRepository) List(ctx context.Context, req ListExecutionsRequest) ([]ExecutionStatus, int, error) {
	// Build the query with filters
	baseQuery := `FROM execution_history WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if req.ExecutionType != nil {
		baseQuery += fmt.Sprintf(" AND execution_type = $%d", argIdx)
		args = append(args, *req.ExecutionType)
		argIdx++
	}
	if req.Status != nil {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIdx)
		args = append(args, *req.Status)
		argIdx++
	}
	if req.TenantID != "" {
		baseQuery += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, req.TenantID)
		argIdx++
	}
	if req.OrgID != "" {
		baseQuery += fmt.Sprintf(" AND org_id = $%d", argIdx)
		args = append(args, req.OrgID)
		argIdx++
	}

	// mig 042's RLS keys execution_history on app.current_tenant_id — the
	// bare reads matched 0 rows under axonflow_app_role, so the portal
	// Executions page and /unified/executions listed nothing for orgs with
	// live workflows (#3039). Writers were wrapped in PR-C1; wrap the readers
	// with the same dual-key scope whenever the caller supplied a tenant/org
	// filter. A filterless call is a deliberate cross-tenant listing
	// (ops/admin path) and keeps the legacy bare read.
	scopeOrg, scopeTenant := req.OrgID, req.TenantID
	if scopeOrg == "" {
		scopeOrg = scopeTenant
	}
	if scopeTenant == "" {
		scopeTenant = scopeOrg
	}
	runQuery := func(fn func(q queryer) error) error {
		if scopeOrg == "" {
			return fn(r.db)
		}
		return rls.WithOrgAndTenantScope(ctx, r.db, scopeOrg, scopeTenant, func(tx *sql.Tx) error {
			return fn(tx)
		})
	}

	countQuery := "SELECT COUNT(*) " + baseQuery
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	selectQuery := `
		SELECT
			id, execution_type, name, source,
			tenant_id, org_id, user_id, client_id,
			status, current_step_index, total_steps,
			started_at, completed_at, estimated_cost_usd, actual_cost_usd,
			steps, error_message, metadata, created_at, updated_at
		` + baseQuery + " ORDER BY created_at DESC"

	if req.Limit > 0 {
		selectQuery += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, req.Limit)
		argIdx++
	}
	if req.Offset > 0 {
		selectQuery += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, req.Offset)
	}

	// Count + select in one scope so both see the same GUC transaction.
	var total int
	var executions []ExecutionStatus
	if err := runQuery(func(q queryer) error {
		if cErr := q.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); cErr != nil {
			return fmt.Errorf("failed to count executions: %w", cErr)
		}
		rows, qErr := q.QueryContext(ctx, selectQuery, args...)
		if qErr != nil {
			return fmt.Errorf("failed to list executions: %w", qErr)
		}
		defer rows.Close()
		var scanErr error
		executions, scanErr = scanExecutionRows(rows)
		return scanErr
	}); err != nil {
		return nil, 0, err
	}

	return executions, total, nil
}

// queryer is the subset of *sql.DB / *sql.Tx the List reads need, so the
// same closure can run bare (legacy cross-tenant path) or scope-wrapped.
type queryer interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
}

// scanExecutionRows converts result rows into ExecutionStatus values.
func scanExecutionRows(rows *sql.Rows) ([]ExecutionStatus, error) {
	var executions []ExecutionStatus
	for rows.Next() {
		var exec ExecutionStatus
		var source, tenantID, orgID, userID, clientID sql.NullString
		var completedAt sql.NullTime
		var estimatedCost, actualCost sql.NullFloat64
		var stepsJSON, metadataJSON []byte
		var errorMsg sql.NullString

		err := rows.Scan(
			&exec.ExecutionID, &exec.ExecutionType, &exec.Name, &source,
			&tenantID, &orgID, &userID, &clientID,
			&exec.Status, &exec.CurrentStepIndex, &exec.TotalSteps,
			&exec.StartedAt, &completedAt, &estimatedCost, &actualCost,
			&stepsJSON, &errorMsg, &metadataJSON, &exec.CreatedAt, &exec.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan execution: %w", err)
		}

		exec.Source = source.String
		exec.TenantID = tenantID.String
		exec.OrgID = orgID.String
		exec.UserID = userID.String
		exec.ClientID = clientID.String
		if completedAt.Valid {
			exec.CompletedAt = &completedAt.Time
		}
		if estimatedCost.Valid {
			exec.EstimatedCostUSD = &estimatedCost.Float64
		}
		if actualCost.Valid {
			exec.ActualCostUSD = &actualCost.Float64
		}
		if errorMsg.Valid {
			exec.Error = errorMsg.String
		}

		if len(stepsJSON) > 0 {
			if err := json.Unmarshal(stepsJSON, &exec.Steps); err != nil {
				return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
			}
		}
		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &exec.Metadata); err != nil {
				return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
			}
		}

		executions = append(executions, exec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return executions, nil
}

// Delete removes an execution record.
//
// v9 Phase 8 #2384 PR-C1: DELETE on execution_history is gated by mig 042's
// tenant_isolation policy under app_role. The caller MUST pass orgID and
// tenantID — they're available on the *ExecutionStatus returned by a
// prior Get (or stored in the caller's request context). Empty values
// are rejected so cross-tenant deletes never accidentally route through
// this method.
func (r *PostgresRepository) Delete(ctx context.Context, orgID, tenantID, executionID string) error {
	if orgID == "" || tenantID == "" {
		return ErrMissingOrgID
	}
	query := `DELETE FROM execution_history WHERE id = $1`
	var rows int64
	err := rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query, executionID)
		if exErr != nil {
			return fmt.Errorf("failed to delete execution: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// UpdateStatus updates just the status fields.
//
// v9 Phase 8 #2384 PR-C1: scope-wrap rationale identical to Update — see
// that method's doc.
func (r *PostgresRepository) UpdateStatus(ctx context.Context, orgID, tenantID, executionID string, status ExecutionStatusValue, completedAt *time.Time, errorMsg string) error {
	if orgID == "" || tenantID == "" {
		return ErrMissingOrgID
	}
	query := `
		UPDATE execution_history SET
			status = $2,
			completed_at = $3,
			error_message = $4,
			updated_at = $5
		WHERE id = $1
	`

	var rows int64
	err := rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query,
			executionID, status, completedAt, nullableString(errorMsg), time.Now(),
		)
		if exErr != nil {
			return fmt.Errorf("failed to update status: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// UpdateSteps updates just the steps array.
//
// v9 Phase 8 #2384 PR-C1: scope-wrap rationale identical to Update.
func (r *PostgresRepository) UpdateSteps(ctx context.Context, orgID, tenantID, executionID string, steps []StepStatus) error {
	if orgID == "" || tenantID == "" {
		return ErrMissingOrgID
	}
	stepsJSON, err := json.Marshal(steps)
	if err != nil {
		return fmt.Errorf("failed to marshal steps: %w", err)
	}

	query := `
		UPDATE execution_history SET
			steps = $2,
			total_steps = $3,
			updated_at = $4
		WHERE id = $1
	`

	var rows int64
	err = rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query,
			executionID, stepsJSON, len(steps), time.Now(),
		)
		if exErr != nil {
			return fmt.Errorf("failed to update steps: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// UpdateCost updates the cost fields.
//
// v9 Phase 8 #2384 PR-C1: scope-wrap rationale identical to Update.
func (r *PostgresRepository) UpdateCost(ctx context.Context, orgID, tenantID, executionID string, estimatedCost, actualCost *float64) error {
	if orgID == "" || tenantID == "" {
		return ErrMissingOrgID
	}
	query := `
		UPDATE execution_history SET
			estimated_cost_usd = COALESCE($2, estimated_cost_usd),
			actual_cost_usd = COALESCE($3, actual_cost_usd),
			updated_at = $4
		WHERE id = $1
	`

	var rows int64
	err := rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query,
			executionID, estimatedCost, actualCost, time.Now(),
		)
		if exErr != nil {
			return fmt.Errorf("failed to update cost: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// GetByPlanID looks up a single execution by plan_id in metadata.
// Uses the expression index on metadata->>'plan_id' for efficient lookup.
func (r *PostgresRepository) GetByPlanID(ctx context.Context, planID string) (*ExecutionStatus, error) {
	return r.getByMetadataHardcoded(ctx, "plan_id", planID)
}

// GetByMetadata looks up a single execution by a metadata key-value pair.
// Note: Uses parameterized key, so expression indexes may not be used.
// Prefer GetByPlanID for plan_id lookups.
func (r *PostgresRepository) GetByMetadata(ctx context.Context, key, value string) (*ExecutionStatus, error) {
	return r.getByMetadataHardcoded(ctx, key, value)
}

func (r *PostgresRepository) getByMetadataHardcoded(ctx context.Context, key, value string) (*ExecutionStatus, error) {
	// Use hardcoded key in query for plan_id to enable expression index usage
	var query string
	if key == "plan_id" {
		query = `
			SELECT
				id, execution_type, name, source,
				tenant_id, org_id, user_id, client_id,
				status, current_step_index, total_steps,
				started_at, completed_at, estimated_cost_usd, actual_cost_usd,
				steps, error_message, metadata, created_at, updated_at
			FROM execution_history
			WHERE metadata->>'plan_id' = $1
			LIMIT 1
		`
	} else {
		query = `
			SELECT
				id, execution_type, name, source,
				tenant_id, org_id, user_id, client_id,
				status, current_step_index, total_steps,
				started_at, completed_at, estimated_cost_usd, actual_cost_usd,
				steps, error_message, metadata, created_at, updated_at
			FROM execution_history
			WHERE metadata->>$1 = $2
			LIMIT 1
		`
	}

	var exec ExecutionStatus
	var source, tenantID, orgID, userID, clientID sql.NullString
	var completedAt sql.NullTime
	var estimatedCost, actualCost sql.NullFloat64
	var stepsJSON, metadataJSON []byte
	var errorMsg sql.NullString

	// Discovery read — runs on the lookup pool (see lookupDB field comment).
	var row *sql.Row
	if key == "plan_id" {
		row = r.lookup().QueryRowContext(ctx, query, value)
	} else {
		row = r.lookup().QueryRowContext(ctx, query, key, value)
	}
	err := row.Scan(
		&exec.ExecutionID, &exec.ExecutionType, &exec.Name, &source,
		&tenantID, &orgID, &userID, &clientID,
		&exec.Status, &exec.CurrentStepIndex, &exec.TotalSteps,
		&exec.StartedAt, &completedAt, &estimatedCost, &actualCost,
		&stepsJSON, &errorMsg, &metadataJSON, &exec.CreatedAt, &exec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrExecutionNotFound
		}
		return nil, fmt.Errorf("failed to get execution by metadata: %w", err)
	}

	exec.Source = source.String
	exec.TenantID = tenantID.String
	exec.OrgID = orgID.String
	exec.UserID = userID.String
	exec.ClientID = clientID.String
	if completedAt.Valid {
		exec.CompletedAt = &completedAt.Time
	}
	if estimatedCost.Valid {
		exec.EstimatedCostUSD = &estimatedCost.Float64
	}
	if actualCost.Valid {
		exec.ActualCostUSD = &actualCost.Float64
	}
	if errorMsg.Valid {
		exec.Error = errorMsg.String
	}

	if len(stepsJSON) > 0 {
		if err := json.Unmarshal(stepsJSON, &exec.Steps); err != nil {
			return nil, fmt.Errorf("failed to unmarshal steps: %w", err)
		}
	}
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &exec.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return &exec, nil
}

// ExpireExecution marks an execution as expired.
//
// v9 Phase 8 #2384 PR-C1: scope-wrap rationale identical to Update.
func (r *PostgresRepository) ExpireExecution(ctx context.Context, orgID, tenantID, executionID string, metadata map[string]interface{}) error {
	if orgID == "" || tenantID == "" {
		return ErrMissingOrgID
	}
	now := time.Now()
	query := `
		UPDATE execution_history SET
			status = 'expired',
			completed_at = $2,
			updated_at = $3
		WHERE id = $1
	`

	var rows int64
	err := rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query, executionID, now, now)
		if exErr != nil {
			return fmt.Errorf("failed to expire execution: %w", exErr)
		}
		rows, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrExecutionNotFound
	}

	return nil
}

// CountActive returns the number of running or pending executions for a tenant.
func (r *PostgresRepository) CountActive(ctx context.Context, tenantID string) (int, error) {
	query := `SELECT COUNT(*) FROM execution_history WHERE tenant_id = $1 AND status IN ('running', 'pending')`
	var count int
	// Tenant-scoped read: mig 042's RLS keys on app.current_tenant_id, so the
	// bare COUNT read 0 under axonflow_app_role and concurrency limits never
	// engaged (#3039). org_id == tenant_id post-Phase-6 at this caller.
	err := rls.WithOrgAndTenantScope(ctx, r.db, tenantID, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID).Scan(&count)
	})
	if err != nil {
		return 0, fmt.Errorf("failed to count active executions: %w", err)
	}
	return count, nil
}

// PurgeOldest removes the oldest execution records beyond keepCount for a tenant.
//
// v9 Phase 8 #2384 PR-C1 DoD-closure D-4: per-tenant cleanup must wrap in
// WithOrgAndTenantScope so mig 042's app.current_tenant_id-keyed USING
// surfaces the rows under axonflow_app_role. Without the wrap the DELETE
// silently zeroes rows-affected (USING returns NULL → predicate fails)
// and the retention cap is never enforced. Signature gained orgID so the
// wrap can pin both GUCs.
func (r *PostgresRepository) PurgeOldest(ctx context.Context, orgID, tenantID string, keepCount int) (int64, error) {
	if orgID == "" || tenantID == "" {
		return 0, ErrMissingOrgID
	}
	query := `
		DELETE FROM execution_history
		WHERE tenant_id = $1
		AND id NOT IN (
			SELECT id FROM execution_history
			WHERE tenant_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		)`
	var rowsAffected int64
	wrapErr := rls.WithOrgAndTenantScope(ctx, r.db, orgID, tenantID, func(tx *sql.Tx) error {
		result, exErr := tx.ExecContext(ctx, query, tenantID, keepCount)
		if exErr != nil {
			return fmt.Errorf("failed to purge oldest executions: %w", exErr)
		}
		var raErr error
		rowsAffected, raErr = result.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("failed to get rows affected: %w", raErr)
		}
		return nil
	})
	if wrapErr != nil {
		return 0, wrapErr
	}
	return rowsAffected, nil
}

// --- Helper Functions ---

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}
