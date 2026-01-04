// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PostgresRepository implements Repository using PostgreSQL
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// CreateBudget creates a new budget
func (r *PostgresRepository) CreateBudget(ctx context.Context, budget *Budget) error {
	thresholds, err := json.Marshal(budget.AlertThresholds)
	if err != nil {
		return fmt.Errorf("failed to marshal alert thresholds: %w", err)
	}

	query := `
		INSERT INTO budgets (
			id, name, description, scope, scope_id, limit_usd, period,
			on_exceed, alert_thresholds, enabled, org_id, tenant_id,
			created_by, updated_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
	`

	_, err = r.db.ExecContext(ctx, query,
		budget.ID, budget.Name, budget.Description, budget.Scope, budget.ScopeID,
		budget.LimitUSD, budget.Period, budget.OnExceed, thresholds, budget.Enabled,
		nullString(budget.OrgID), nullString(budget.TenantID),
		nullString(budget.CreatedBy), nullString(budget.UpdatedBy),
		budget.CreatedAt, budget.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			return ErrBudgetExists
		}
		return fmt.Errorf("failed to create budget: %w", err)
	}

	return nil
}

// GetBudget retrieves a budget by ID
func (r *PostgresRepository) GetBudget(ctx context.Context, id string) (*Budget, error) {
	query := `
		SELECT id, name, description, scope, scope_id, limit_usd, period,
			   on_exceed, alert_thresholds, enabled, org_id, tenant_id,
			   created_by, updated_by, created_at, updated_at
		FROM budgets
		WHERE id = $1
	`

	var budget Budget
	var thresholds []byte
	var description, scopeID, orgID, tenantID, createdBy, updatedBy sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&budget.ID, &budget.Name, &description, &budget.Scope, &scopeID,
		&budget.LimitUSD, &budget.Period, &budget.OnExceed, &thresholds,
		&budget.Enabled, &orgID, &tenantID, &createdBy, &updatedBy,
		&budget.CreatedAt, &budget.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrBudgetNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get budget: %w", err)
	}

	budget.Description = description.String
	budget.ScopeID = scopeID.String
	budget.OrgID = orgID.String
	budget.TenantID = tenantID.String
	budget.CreatedBy = createdBy.String
	budget.UpdatedBy = updatedBy.String

	if err := json.Unmarshal(thresholds, &budget.AlertThresholds); err != nil {
		return nil, fmt.Errorf("failed to unmarshal alert thresholds: %w", err)
	}

	return &budget, nil
}

// UpdateBudget updates an existing budget
func (r *PostgresRepository) UpdateBudget(ctx context.Context, budget *Budget) error {
	thresholds, err := json.Marshal(budget.AlertThresholds)
	if err != nil {
		return fmt.Errorf("failed to marshal alert thresholds: %w", err)
	}

	query := `
		UPDATE budgets SET
			name = $2, description = $3, scope = $4, scope_id = $5,
			limit_usd = $6, period = $7, on_exceed = $8, alert_thresholds = $9,
			enabled = $10, updated_by = $11, updated_at = $12
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		budget.ID, budget.Name, budget.Description, budget.Scope, budget.ScopeID,
		budget.LimitUSD, budget.Period, budget.OnExceed, thresholds,
		budget.Enabled, nullString(budget.UpdatedBy), time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("failed to update budget: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrBudgetNotFound
	}

	return nil
}

// DeleteBudget deletes a budget
func (r *PostgresRepository) DeleteBudget(ctx context.Context, id string) error {
	query := `DELETE FROM budgets WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete budget: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrBudgetNotFound
	}

	return nil
}

// ListBudgets lists budgets with filtering and pagination
func (r *PostgresRepository) ListBudgets(ctx context.Context, opts ListBudgetsOptions) ([]Budget, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIndex))
		args = append(args, opts.OrgID)
		argIndex++
	}
	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}
	if opts.Scope != "" {
		conditions = append(conditions, fmt.Sprintf("scope = $%d", argIndex))
		args = append(args, opts.Scope)
		argIndex++
	}
	if opts.ScopeID != "" {
		conditions = append(conditions, fmt.Sprintf("scope_id = $%d", argIndex))
		args = append(args, opts.ScopeID)
		argIndex++
	}
	if opts.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argIndex))
		args = append(args, *opts.Enabled)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM budgets %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count budgets: %w", err)
	}

	// Get budgets
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, name, description, scope, scope_id, limit_usd, period,
			   on_exceed, alert_thresholds, enabled, org_id, tenant_id,
			   created_by, updated_by, created_at, updated_at
		FROM budgets
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list budgets: %w", err)
	}
	defer rows.Close()

	var budgets []Budget
	for rows.Next() {
		var budget Budget
		var thresholds []byte
		var description, scopeID, orgID, tenantID, createdBy, updatedBy sql.NullString

		if err := rows.Scan(
			&budget.ID, &budget.Name, &description, &budget.Scope, &scopeID,
			&budget.LimitUSD, &budget.Period, &budget.OnExceed, &thresholds,
			&budget.Enabled, &orgID, &tenantID, &createdBy, &updatedBy,
			&budget.CreatedAt, &budget.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan budget: %w", err)
		}

		budget.Description = description.String
		budget.ScopeID = scopeID.String
		budget.OrgID = orgID.String
		budget.TenantID = tenantID.String
		budget.CreatedBy = createdBy.String
		budget.UpdatedBy = updatedBy.String

		if err := json.Unmarshal(thresholds, &budget.AlertThresholds); err != nil {
			return nil, 0, fmt.Errorf("failed to unmarshal thresholds: %w", err)
		}

		budgets = append(budgets, budget)
	}

	return budgets, total, nil
}

// GetBudgetsForScope gets all budgets applicable to a scope
func (r *PostgresRepository) GetBudgetsForScope(ctx context.Context, scope BudgetScope, scopeID string, orgID, tenantID string) ([]Budget, error) {
	query := `
		SELECT id, name, description, scope, scope_id, limit_usd, period,
			   on_exceed, alert_thresholds, enabled, org_id, tenant_id,
			   created_by, updated_by, created_at, updated_at
		FROM budgets
		WHERE enabled = true
		  AND scope = $1
		  AND (scope_id = $2 OR scope_id IS NULL OR scope_id = '')
		  AND (org_id = $3 OR org_id IS NULL OR org_id = '')
		  AND (tenant_id = $4 OR tenant_id IS NULL OR tenant_id = '')
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, scope, scopeID, orgID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get budgets for scope: %w", err)
	}
	defer rows.Close()

	var budgets []Budget
	for rows.Next() {
		var budget Budget
		var thresholds []byte
		var description, sID, oID, tID, createdBy, updatedBy sql.NullString

		if err := rows.Scan(
			&budget.ID, &budget.Name, &description, &budget.Scope, &sID,
			&budget.LimitUSD, &budget.Period, &budget.OnExceed, &thresholds,
			&budget.Enabled, &oID, &tID, &createdBy, &updatedBy,
			&budget.CreatedAt, &budget.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan budget: %w", err)
		}

		budget.Description = description.String
		budget.ScopeID = sID.String
		budget.OrgID = oID.String
		budget.TenantID = tID.String
		budget.CreatedBy = createdBy.String
		budget.UpdatedBy = updatedBy.String

		if err := json.Unmarshal(thresholds, &budget.AlertThresholds); err != nil {
			continue // Skip malformed entries
		}

		budgets = append(budgets, budget)
	}

	return budgets, nil
}

// SaveUsage saves a usage record
func (r *PostgresRepository) SaveUsage(ctx context.Context, record *UsageRecord) error {
	query := `
		INSERT INTO usage_records (
			request_id, timestamp, org_id, tenant_id, team_id, agent_id,
			workflow_id, user_id, provider, model, tokens_in, tokens_out,
			cost_usd, request_type, cached
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		record.RequestID, record.Timestamp,
		nullString(record.OrgID), nullString(record.TenantID),
		nullString(record.TeamID), nullString(record.AgentID),
		nullString(record.WorkflowID), nullString(record.UserID),
		record.Provider, record.Model,
		record.TokensIn, record.TokensOut, record.CostUSD,
		nullString(record.RequestType), record.Cached,
	).Scan(&record.ID)
	if err != nil {
		return fmt.Errorf("failed to save usage: %w", err)
	}

	return nil
}

// GetUsageForPeriod gets total usage cost for a budget period
func (r *PostgresRepository) GetUsageForPeriod(ctx context.Context, scope BudgetScope, scopeID string, periodStart time.Time, orgID, tenantID string) (float64, error) {
	var scopeColumn string
	switch scope {
	case ScopeOrganization:
		scopeColumn = "org_id"
	case ScopeTeam:
		scopeColumn = "team_id"
	case ScopeAgent:
		scopeColumn = "agent_id"
	case ScopeWorkflow:
		scopeColumn = "workflow_id"
	case ScopeUser:
		scopeColumn = "user_id"
	default:
		scopeColumn = "org_id"
	}

	query := fmt.Sprintf(`
		SELECT COALESCE(SUM(cost_usd), 0)
		FROM usage_records
		WHERE %s = $1
		  AND timestamp >= $2
		  AND ($3 = '' OR org_id = $3)
		  AND ($4 = '' OR tenant_id = $4)
	`, scopeColumn)

	var total float64
	err := r.db.QueryRowContext(ctx, query, scopeID, periodStart, orgID, tenantID).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("failed to get usage for period: %w", err)
	}

	return total, nil
}

// GetUsageSummary returns usage summary for a time period
func (r *PostgresRepository) GetUsageSummary(ctx context.Context, opts UsageQueryOptions) (*UsageSummary, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIndex))
		args = append(args, opts.OrgID)
		argIndex++
	}
	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}
	if opts.TeamID != "" {
		conditions = append(conditions, fmt.Sprintf("team_id = $%d", argIndex))
		args = append(args, opts.TeamID)
		argIndex++
	}
	if opts.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIndex))
		args = append(args, opts.AgentID)
		argIndex++
	}
	if opts.Provider != "" {
		conditions = append(conditions, fmt.Sprintf("provider = $%d", argIndex))
		args = append(args, opts.Provider)
		argIndex++
	}
	if opts.Model != "" {
		conditions = append(conditions, fmt.Sprintf("model = $%d", argIndex))
		args = append(args, opts.Model)
		argIndex++
	}
	if !opts.StartTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, opts.StartTime)
		argIndex++
	}
	if !opts.EndTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp < $%d", argIndex))
		args = append(args, opts.EndTime)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := fmt.Sprintf(`
		SELECT
			COALESCE(SUM(cost_usd), 0) as total_cost,
			COALESCE(SUM(tokens_in), 0) as total_tokens_in,
			COALESCE(SUM(tokens_out), 0) as total_tokens_out,
			COUNT(*) as request_count,
			MIN(timestamp) as period_start,
			MAX(timestamp) as period_end
		FROM usage_records
		%s
	`, whereClause)

	summary := &UsageSummary{Period: opts.Period}
	var periodStart, periodEnd sql.NullTime

	err := r.db.QueryRowContext(ctx, query, args...).Scan(
		&summary.TotalCostUSD,
		&summary.TotalTokensIn,
		&summary.TotalTokensOut,
		&summary.TotalRequests,
		&periodStart,
		&periodEnd,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage summary: %w", err)
	}

	if periodStart.Valid {
		summary.PeriodStart = periodStart.Time
	}
	if periodEnd.Valid {
		summary.PeriodEnd = periodEnd.Time
	}
	if summary.TotalRequests > 0 {
		summary.AverageCostPerRequest = summary.TotalCostUSD / float64(summary.TotalRequests)
	}

	return summary, nil
}

// GetUsageBreakdown returns usage breakdown by dimension
func (r *PostgresRepository) GetUsageBreakdown(ctx context.Context, groupBy string, opts UsageQueryOptions) (*UsageBreakdown, error) {
	// Validate groupBy
	validGroupBy := map[string]string{
		"provider": "provider",
		"model":    "model",
		"agent":    "agent_id",
		"team":     "team_id",
		"user":     "user_id",
		"workflow": "workflow_id",
	}

	column, ok := validGroupBy[groupBy]
	if !ok {
		return nil, ErrInvalidGroupBy
	}

	var conditions []string
	var args []interface{}
	argIndex := 1

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIndex))
		args = append(args, opts.OrgID)
		argIndex++
	}
	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}
	if !opts.StartTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, opts.StartTime)
		argIndex++
	}
	if !opts.EndTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp < $%d", argIndex))
		args = append(args, opts.EndTime)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total for percentage calculation
	totalQuery := fmt.Sprintf("SELECT COALESCE(SUM(cost_usd), 0) FROM usage_records %s", whereClause)
	var totalCost float64
	if err := r.db.QueryRowContext(ctx, totalQuery, args...).Scan(&totalCost); err != nil {
		return nil, fmt.Errorf("failed to get total cost: %w", err)
	}

	query := fmt.Sprintf(`
		SELECT
			COALESCE(%s, 'unknown') as group_value,
			SUM(cost_usd) as cost_usd,
			SUM(tokens_in) as tokens_in,
			SUM(tokens_out) as tokens_out,
			COUNT(*) as request_count
		FROM usage_records
		%s
		GROUP BY %s
		ORDER BY cost_usd DESC
	`, column, whereClause, column)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage breakdown: %w", err)
	}
	defer rows.Close()

	breakdown := &UsageBreakdown{
		GroupBy:      groupBy,
		TotalCostUSD: totalCost,
		StartTime:    opts.StartTime,
		EndTime:      opts.EndTime,
		Period:       opts.Period,
	}

	for rows.Next() {
		var item UsageBreakdownItem
		item.GroupBy = groupBy

		if err := rows.Scan(
			&item.GroupValue,
			&item.CostUSD,
			&item.TokensIn,
			&item.TokensOut,
			&item.RequestCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan breakdown item: %w", err)
		}

		if totalCost > 0 {
			item.Percentage = (item.CostUSD / totalCost) * 100
		}

		breakdown.Items = append(breakdown.Items, item)
	}

	return breakdown, nil
}

// ListUsageRecords lists usage records with filtering
func (r *PostgresRepository) ListUsageRecords(ctx context.Context, opts UsageQueryOptions) ([]UsageRecord, int, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	if opts.OrgID != "" {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIndex))
		args = append(args, opts.OrgID)
		argIndex++
	}
	if opts.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, opts.TenantID)
		argIndex++
	}
	if opts.TeamID != "" {
		conditions = append(conditions, fmt.Sprintf("team_id = $%d", argIndex))
		args = append(args, opts.TeamID)
		argIndex++
	}
	if opts.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argIndex))
		args = append(args, opts.AgentID)
		argIndex++
	}
	if opts.Provider != "" {
		conditions = append(conditions, fmt.Sprintf("provider = $%d", argIndex))
		args = append(args, opts.Provider)
		argIndex++
	}
	if opts.Model != "" {
		conditions = append(conditions, fmt.Sprintf("model = $%d", argIndex))
		args = append(args, opts.Model)
		argIndex++
	}
	if !opts.StartTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIndex))
		args = append(args, opts.StartTime)
		argIndex++
	}
	if !opts.EndTime.IsZero() {
		conditions = append(conditions, fmt.Sprintf("timestamp < $%d", argIndex))
		args = append(args, opts.EndTime)
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM usage_records %s", whereClause)
	var total int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count usage records: %w", err)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	query := fmt.Sprintf(`
		SELECT id, request_id, timestamp, org_id, tenant_id, team_id, agent_id,
			   workflow_id, user_id, provider, model, tokens_in, tokens_out,
			   cost_usd, request_type, cached, created_at
		FROM usage_records
		%s
		ORDER BY timestamp DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list usage records: %w", err)
	}
	defer rows.Close()

	var records []UsageRecord
	for rows.Next() {
		var record UsageRecord
		var orgID, tenantID, teamID, agentID, workflowID, userID, requestType sql.NullString

		if err := rows.Scan(
			&record.ID, &record.RequestID, &record.Timestamp,
			&orgID, &tenantID, &teamID, &agentID,
			&workflowID, &userID, &record.Provider, &record.Model,
			&record.TokensIn, &record.TokensOut, &record.CostUSD,
			&requestType, &record.Cached, &record.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("failed to scan usage record: %w", err)
		}

		record.OrgID = orgID.String
		record.TenantID = tenantID.String
		record.TeamID = teamID.String
		record.AgentID = agentID.String
		record.WorkflowID = workflowID.String
		record.UserID = userID.String
		record.RequestType = requestType.String

		records = append(records, record)
	}

	return records, total, nil
}

// UpdateAggregate upserts a usage aggregate
func (r *PostgresRepository) UpdateAggregate(ctx context.Context, agg *UsageAggregate) error {
	query := `
		INSERT INTO usage_aggregates (
			scope, scope_id, period, period_start, total_cost_usd,
			total_tokens_in, total_tokens_out, request_count, org_id, tenant_id, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (scope, scope_id, period, period_start, org_id, tenant_id)
		DO UPDATE SET
			total_cost_usd = usage_aggregates.total_cost_usd + EXCLUDED.total_cost_usd,
			total_tokens_in = usage_aggregates.total_tokens_in + EXCLUDED.total_tokens_in,
			total_tokens_out = usage_aggregates.total_tokens_out + EXCLUDED.total_tokens_out,
			request_count = usage_aggregates.request_count + EXCLUDED.request_count,
			updated_at = EXCLUDED.updated_at
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		agg.Scope, agg.ScopeID, agg.Period, agg.PeriodStart,
		agg.TotalCostUSD, agg.TotalTokensIn, agg.TotalTokensOut,
		agg.RequestCount, nullString(agg.OrgID), nullString(agg.TenantID),
		time.Now().UTC(),
	).Scan(&agg.ID)
	if err != nil {
		return fmt.Errorf("failed to update aggregate: %w", err)
	}

	return nil
}

// GetAggregate gets a specific aggregate
func (r *PostgresRepository) GetAggregate(ctx context.Context, scope, scopeID string, period AggregatePeriod, periodStart time.Time, orgID, tenantID string) (*UsageAggregate, error) {
	query := `
		SELECT id, scope, scope_id, period, period_start, total_cost_usd,
			   total_tokens_in, total_tokens_out, request_count, org_id, tenant_id, updated_at
		FROM usage_aggregates
		WHERE scope = $1 AND scope_id = $2 AND period = $3 AND period_start = $4
		  AND (org_id = $5 OR (org_id IS NULL AND $5 = ''))
		  AND (tenant_id = $6 OR (tenant_id IS NULL AND $6 = ''))
	`

	var agg UsageAggregate
	var oID, tID sql.NullString

	err := r.db.QueryRowContext(ctx, query, scope, scopeID, period, periodStart, orgID, tenantID).Scan(
		&agg.ID, &agg.Scope, &agg.ScopeID, &agg.Period, &agg.PeriodStart,
		&agg.TotalCostUSD, &agg.TotalTokensIn, &agg.TotalTokensOut,
		&agg.RequestCount, &oID, &tID, &agg.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregate: %w", err)
	}

	agg.OrgID = oID.String
	agg.TenantID = tID.String

	return &agg, nil
}

// ListAggregates lists aggregates for a time range
func (r *PostgresRepository) ListAggregates(ctx context.Context, scope, scopeID string, period AggregatePeriod, startTime, endTime time.Time, orgID, tenantID string) ([]UsageAggregate, error) {
	query := `
		SELECT id, scope, scope_id, period, period_start, total_cost_usd,
			   total_tokens_in, total_tokens_out, request_count, org_id, tenant_id, updated_at
		FROM usage_aggregates
		WHERE scope = $1 AND scope_id = $2 AND period = $3
		  AND period_start >= $4 AND period_start < $5
		  AND (org_id = $6 OR (org_id IS NULL AND $6 = ''))
		  AND (tenant_id = $7 OR (tenant_id IS NULL AND $7 = ''))
		ORDER BY period_start ASC
	`

	rows, err := r.db.QueryContext(ctx, query, scope, scopeID, period, startTime, endTime, orgID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list aggregates: %w", err)
	}
	defer rows.Close()

	var aggregates []UsageAggregate
	for rows.Next() {
		var agg UsageAggregate
		var oID, tID sql.NullString

		if err := rows.Scan(
			&agg.ID, &agg.Scope, &agg.ScopeID, &agg.Period, &agg.PeriodStart,
			&agg.TotalCostUSD, &agg.TotalTokensIn, &agg.TotalTokensOut,
			&agg.RequestCount, &oID, &tID, &agg.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan aggregate: %w", err)
		}

		agg.OrgID = oID.String
		agg.TenantID = tID.String
		aggregates = append(aggregates, agg)
	}

	return aggregates, nil
}

// SaveAlert saves a budget alert
func (r *PostgresRepository) SaveAlert(ctx context.Context, alert *BudgetAlert) error {
	query := `
		INSERT INTO budget_alerts (
			budget_id, threshold, percentage_reached, amount_usd,
			alert_type, message, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id
	`

	err := r.db.QueryRowContext(ctx, query,
		alert.BudgetID, alert.Threshold, alert.PercentageReached,
		alert.AmountUSD, alert.AlertType, alert.Message, time.Now().UTC(),
	).Scan(&alert.ID)
	if err != nil {
		return fmt.Errorf("failed to save alert: %w", err)
	}

	return nil
}

// GetUnacknowledgedAlerts gets unacknowledged alerts for a budget
func (r *PostgresRepository) GetUnacknowledgedAlerts(ctx context.Context, budgetID string) ([]BudgetAlert, error) {
	query := `
		SELECT id, budget_id, threshold, percentage_reached, amount_usd,
			   alert_type, message, acknowledged, acknowledged_by, acknowledged_at, created_at
		FROM budget_alerts
		WHERE budget_id = $1 AND acknowledged = false
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, budgetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get unacknowledged alerts: %w", err)
	}
	defer rows.Close()

	return scanAlerts(rows)
}

// AcknowledgeAlert acknowledges an alert
func (r *PostgresRepository) AcknowledgeAlert(ctx context.Context, alertID int64, acknowledgedBy string) error {
	query := `
		UPDATE budget_alerts
		SET acknowledged = true, acknowledged_by = $2, acknowledged_at = $3
		WHERE id = $1
	`

	_, err := r.db.ExecContext(ctx, query, alertID, acknowledgedBy, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	return nil
}

// GetRecentAlerts gets recent alerts for a budget
func (r *PostgresRepository) GetRecentAlerts(ctx context.Context, budgetID string, limit int) ([]BudgetAlert, error) {
	if limit <= 0 {
		limit = 10
	}

	query := `
		SELECT id, budget_id, threshold, percentage_reached, amount_usd,
			   alert_type, message, acknowledged, acknowledged_by, acknowledged_at, created_at
		FROM budget_alerts
		WHERE budget_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, budgetID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent alerts: %w", err)
	}
	defer rows.Close()

	return scanAlerts(rows)
}

// Ping checks database connectivity
func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// Helper functions

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func scanAlerts(rows *sql.Rows) ([]BudgetAlert, error) {
	var alerts []BudgetAlert
	for rows.Next() {
		var alert BudgetAlert
		var acknowledgedBy sql.NullString
		var acknowledgedAt sql.NullTime

		if err := rows.Scan(
			&alert.ID, &alert.BudgetID, &alert.Threshold, &alert.PercentageReached,
			&alert.AmountUSD, &alert.AlertType, &alert.Message, &alert.Acknowledged,
			&acknowledgedBy, &acknowledgedAt, &alert.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan alert: %w", err)
		}

		alert.AcknowledgedBy = acknowledgedBy.String
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}
