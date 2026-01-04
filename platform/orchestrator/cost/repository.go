// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"time"
)

// Repository defines the interface for cost data persistence
type Repository interface {
	// Budget operations
	CreateBudget(ctx context.Context, budget *Budget) error
	GetBudget(ctx context.Context, id string) (*Budget, error)
	UpdateBudget(ctx context.Context, budget *Budget) error
	DeleteBudget(ctx context.Context, id string) error
	ListBudgets(ctx context.Context, opts ListBudgetsOptions) ([]Budget, int, error)
	GetBudgetsForScope(ctx context.Context, scope BudgetScope, scopeID string, orgID, tenantID string) ([]Budget, error)

	// Usage operations
	SaveUsage(ctx context.Context, record *UsageRecord) error
	GetUsageForPeriod(ctx context.Context, scope BudgetScope, scopeID string, periodStart time.Time, orgID, tenantID string) (float64, error)
	GetUsageSummary(ctx context.Context, opts UsageQueryOptions) (*UsageSummary, error)
	GetUsageBreakdown(ctx context.Context, groupBy string, opts UsageQueryOptions) (*UsageBreakdown, error)
	ListUsageRecords(ctx context.Context, opts UsageQueryOptions) ([]UsageRecord, int, error)

	// Aggregate operations
	UpdateAggregate(ctx context.Context, aggregate *UsageAggregate) error
	GetAggregate(ctx context.Context, scope, scopeID string, period AggregatePeriod, periodStart time.Time, orgID, tenantID string) (*UsageAggregate, error)
	ListAggregates(ctx context.Context, scope, scopeID string, period AggregatePeriod, startTime, endTime time.Time, orgID, tenantID string) ([]UsageAggregate, error)

	// Alert operations
	SaveAlert(ctx context.Context, alert *BudgetAlert) error
	GetUnacknowledgedAlerts(ctx context.Context, budgetID string) ([]BudgetAlert, error)
	AcknowledgeAlert(ctx context.Context, alertID int64, acknowledgedBy string) error
	GetRecentAlerts(ctx context.Context, budgetID string, limit int) ([]BudgetAlert, error)

	// Utility
	Ping(ctx context.Context) error
}

// AlertType constants
const (
	AlertTypeThresholdReached = "threshold_reached"
	AlertTypeBudgetExceeded   = "budget_exceeded"
	AlertTypeBudgetBlocked    = "budget_blocked"
)
