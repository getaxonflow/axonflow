// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"axonflow/platform/testutil"

	_ "github.com/lib/pq"
)

// Integration tests for PostgresRepository
// Uses testcontainers if DATABASE_URL is not set

func getTestDB(t *testing.T) *sql.DB {
	t.Helper()

	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		db, err := sql.Open("postgres", dbURL)
		if err != nil {
			t.Fatalf("Failed to open database: %v", err)
		}
		if err := db.Ping(); err != nil {
			t.Fatalf("Failed to ping database: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		return db
	}

	testutil.SkipIfNoDocker(t)
	pg := testutil.StartPostgres(t, testutil.DefaultPostgresConfig())
	pg.RunMigration(t, testutil.CostSchema())
	return pg.DB
}

func cleanupTestBudgets(t *testing.T, db *sql.DB, tenantID string) {
	// Clean up budget alerts first (foreign key)
	_, err := db.Exec("DELETE FROM budget_alerts WHERE budget_id IN (SELECT id FROM budgets WHERE tenant_id = $1)", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup budget_alerts: %v", err)
	}
	// Then clean up budgets
	_, err = db.Exec("DELETE FROM budgets WHERE tenant_id = $1", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup budgets: %v", err)
	}
}

func cleanupTestUsageRecords(t *testing.T, db *sql.DB, tenantID string) {
	_, err := db.Exec("DELETE FROM usage_records WHERE tenant_id = $1", tenantID)
	if err != nil {
		t.Logf("Warning: failed to cleanup usage_records: %v", err)
	}
}

func TestPostgresRepository_Integration_ListBudgets(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-list-%d", time.Now().UnixNano())
	defer cleanupTestBudgets(t, db, tenantID)

	ctx := context.Background()

	// Create test budgets
	for i := 0; i < 3; i++ {
		budget := &Budget{
			ID:              fmt.Sprintf("budget-list-%d-%d", time.Now().UnixNano(), i),
			Name:            fmt.Sprintf("Test Budget %d", i),
			Description:     "Test description",
			Scope:           ScopeOrganization,
			ScopeID:         "org-123",
			LimitUSD:        1000.0 * float64(i+1),
			Period:          PeriodMonthly,
			OnExceed:        OnExceedWarn,
			AlertThresholds: []int{50, 80, 100},
			Enabled:         i != 2, // Third budget is disabled
			OrgID:           "org-123",
			TenantID:        tenantID,
			CreatedBy:       "test-user",
			UpdatedBy:       "test-user",
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		if err := repo.CreateBudget(ctx, budget); err != nil {
			t.Fatalf("Failed to create test budget: %v", err)
		}
	}

	t.Run("list all budgets for tenant", func(t *testing.T) {
		opts := ListBudgetsOptions{
			OrgID:    "org-123",
			TenantID: tenantID,
			Limit:    50,
		}
		budgets, total, err := repo.ListBudgets(ctx, opts)
		if err != nil {
			t.Fatalf("ListBudgets() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(budgets) != 3 {
			t.Errorf("Expected 3 budgets, got %d", len(budgets))
		}
	})

	t.Run("list with enabled filter", func(t *testing.T) {
		enabled := true
		opts := ListBudgetsOptions{
			OrgID:    "org-123",
			TenantID: tenantID,
			Enabled:  &enabled,
			Limit:    50,
		}
		budgets, total, err := repo.ListBudgets(ctx, opts)
		if err != nil {
			t.Fatalf("ListBudgets() error = %v", err)
		}
		if total != 2 {
			t.Errorf("Expected total 2 enabled, got %d", total)
		}
		if len(budgets) != 2 {
			t.Errorf("Expected 2 budgets, got %d", len(budgets))
		}
	})

	t.Run("list with pagination", func(t *testing.T) {
		opts := ListBudgetsOptions{
			OrgID:    "org-123",
			TenantID: tenantID,
			Limit:    2,
			Offset:   0,
		}
		budgets, total, err := repo.ListBudgets(ctx, opts)
		if err != nil {
			t.Fatalf("ListBudgets() error = %v", err)
		}
		if total != 3 {
			t.Errorf("Expected total 3, got %d", total)
		}
		if len(budgets) != 2 {
			t.Errorf("Expected 2 budgets (limited), got %d", len(budgets))
		}
	})

	t.Run("list with scope filter", func(t *testing.T) {
		opts := ListBudgetsOptions{
			OrgID:    "org-123",
			TenantID: tenantID,
			Scope:    ScopeOrganization,
			Limit:    50,
		}
		budgets, _, err := repo.ListBudgets(ctx, opts)
		if err != nil {
			t.Fatalf("ListBudgets() error = %v", err)
		}
		for _, b := range budgets {
			if b.Scope != ScopeOrganization {
				t.Errorf("Expected scope %s, got %s", ScopeOrganization, b.Scope)
			}
		}
	})
}

func TestPostgresRepository_Integration_GetBudgetsForScope(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-scope-%d", time.Now().UnixNano())
	defer cleanupTestBudgets(t, db, tenantID)

	ctx := context.Background()

	// Create test budgets for different scopes
	budgets := []struct {
		scope   BudgetScope
		scopeID string
		enabled bool
	}{
		{ScopeOrganization, "org-123", true},
		{ScopeOrganization, "org-123", true},
		{ScopeTeam, "team-456", true},
		{ScopeOrganization, "org-123", false}, // Disabled
	}

	for i, b := range budgets {
		budget := &Budget{
			ID:              fmt.Sprintf("budget-scope-%d-%d", time.Now().UnixNano(), i),
			Name:            fmt.Sprintf("Scope Budget %d", i),
			Scope:           b.scope,
			ScopeID:         b.scopeID,
			LimitUSD:        1000.0,
			Period:          PeriodMonthly,
			OnExceed:        OnExceedWarn,
			AlertThresholds: []int{80},
			Enabled:         b.enabled,
			OrgID:           "org-123",
			TenantID:        tenantID,
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		}
		if err := repo.CreateBudget(ctx, budget); err != nil {
			t.Fatalf("Failed to create test budget: %v", err)
		}
	}

	t.Run("get budgets for organization scope", func(t *testing.T) {
		result, err := repo.GetBudgetsForScope(ctx, ScopeOrganization, "org-123", "org-123", tenantID)
		if err != nil {
			t.Fatalf("GetBudgetsForScope() error = %v", err)
		}
		// Should only return enabled budgets
		if len(result) != 2 {
			t.Errorf("Expected 2 enabled budgets, got %d", len(result))
		}
	})

	t.Run("get budgets for team scope", func(t *testing.T) {
		result, err := repo.GetBudgetsForScope(ctx, ScopeTeam, "team-456", "org-123", tenantID)
		if err != nil {
			t.Fatalf("GetBudgetsForScope() error = %v", err)
		}
		if len(result) != 1 {
			t.Errorf("Expected 1 budget, got %d", len(result))
		}
	})
}

func TestPostgresRepository_Integration_UsageSummary(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-usage-%d", time.Now().UnixNano())
	defer cleanupTestUsageRecords(t, db, tenantID)

	ctx := context.Background()

	// Create test usage records
	now := time.Now()
	for i := 0; i < 5; i++ {
		record := &UsageRecord{
			RequestID:   fmt.Sprintf("req-%d-%d", now.UnixNano(), i),
			Timestamp:   now.Add(-time.Duration(i) * time.Hour),
			OrgID:       "org-123",
			TenantID:    tenantID,
			TeamID:      "team-456",
			AgentID:     "agent-789",
			UserID:      "user-001",
			Provider:    "openai",
			Model:       "gpt-4",
			TokensIn:    100 * (i + 1),
			TokensOut:   50 * (i + 1),
			CostUSD:     0.01 * float64(i+1),
			RequestType: "completion",
			Cached:      false,
		}
		if err := repo.SaveUsage(ctx, record); err != nil {
			t.Fatalf("Failed to save usage record: %v", err)
		}
	}

	t.Run("get usage summary", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-24 * time.Hour),
			EndTime:   now.Add(time.Hour),
		}
		summary, err := repo.GetUsageSummary(ctx, opts)
		if err != nil {
			t.Fatalf("GetUsageSummary() error = %v", err)
		}
		if summary.TotalCostUSD <= 0 {
			t.Error("Expected positive total cost")
		}
		if summary.TotalTokensIn <= 0 {
			t.Error("Expected positive tokens in")
		}
		if summary.TotalTokensOut <= 0 {
			t.Error("Expected positive tokens out")
		}
	})
}

func TestPostgresRepository_Integration_UsageBreakdown(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-breakdown-%d", time.Now().UnixNano())
	defer cleanupTestUsageRecords(t, db, tenantID)

	ctx := context.Background()

	// Create test usage records with different providers
	now := time.Now()
	providers := []string{"openai", "anthropic", "openai"}
	for i, provider := range providers {
		record := &UsageRecord{
			RequestID:   fmt.Sprintf("req-breakdown-%d-%d", now.UnixNano(), i),
			Timestamp:   now,
			OrgID:       "org-123",
			TenantID:    tenantID,
			Provider:    provider,
			Model:       "model-1",
			TokensIn:    100,
			TokensOut:   50,
			CostUSD:     0.01,
			RequestType: "completion",
		}
		if err := repo.SaveUsage(ctx, record); err != nil {
			t.Fatalf("Failed to save usage record: %v", err)
		}
	}

	t.Run("get usage breakdown by provider", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-time.Hour),
			EndTime:   now.Add(time.Hour),
		}
		breakdown, err := repo.GetUsageBreakdown(ctx, "provider", opts)
		if err != nil {
			t.Fatalf("GetUsageBreakdown() error = %v", err)
		}
		if breakdown == nil {
			t.Fatal("Expected breakdown to be returned")
		}
		if len(breakdown.Items) == 0 {
			t.Error("Expected breakdown items")
		}
		if breakdown.GroupBy != "provider" {
			t.Errorf("Expected GroupBy provider, got %s", breakdown.GroupBy)
		}
	})

	t.Run("get usage breakdown by model", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-time.Hour),
			EndTime:   now.Add(time.Hour),
		}
		breakdown, err := repo.GetUsageBreakdown(ctx, "model", opts)
		if err != nil {
			t.Fatalf("GetUsageBreakdown() error = %v", err)
		}
		if breakdown == nil {
			t.Fatal("Expected breakdown to be returned")
		}
		if len(breakdown.Items) == 0 {
			t.Error("Expected breakdown items")
		}
		if breakdown.GroupBy != "model" {
			t.Errorf("Expected GroupBy model, got %s", breakdown.GroupBy)
		}
	})
}

func TestPostgresRepository_Integration_ListUsageRecords(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-records-%d", time.Now().UnixNano())
	defer cleanupTestUsageRecords(t, db, tenantID)

	ctx := context.Background()

	// Create test usage records
	now := time.Now()
	for i := 0; i < 5; i++ {
		record := &UsageRecord{
			RequestID:   fmt.Sprintf("req-list-%d-%d", now.UnixNano(), i),
			Timestamp:   now.Add(-time.Duration(i) * time.Hour),
			OrgID:       "org-123",
			TenantID:    tenantID,
			Provider:    "openai",
			Model:       "gpt-4",
			TokensIn:    100,
			TokensOut:   50,
			CostUSD:     0.01,
			RequestType: "completion",
		}
		if err := repo.SaveUsage(ctx, record); err != nil {
			t.Fatalf("Failed to save usage record: %v", err)
		}
	}

	t.Run("list usage records", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-24 * time.Hour),
			EndTime:   now.Add(time.Hour),
			Limit:     50,
		}
		records, total, err := repo.ListUsageRecords(ctx, opts)
		if err != nil {
			t.Fatalf("ListUsageRecords() error = %v", err)
		}
		if total != 5 {
			t.Errorf("Expected total 5, got %d", total)
		}
		if len(records) != 5 {
			t.Errorf("Expected 5 records, got %d", len(records))
		}
	})

	t.Run("list usage records with pagination", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-24 * time.Hour),
			EndTime:   now.Add(time.Hour),
			Limit:     2,
			Offset:    0,
		}
		records, total, err := repo.ListUsageRecords(ctx, opts)
		if err != nil {
			t.Fatalf("ListUsageRecords() error = %v", err)
		}
		if total != 5 {
			t.Errorf("Expected total 5, got %d", total)
		}
		if len(records) != 2 {
			t.Errorf("Expected 2 records (limited), got %d", len(records))
		}
	})

	t.Run("list usage records with provider filter", func(t *testing.T) {
		opts := UsageQueryOptions{
			OrgID:     "org-123",
			TenantID:  tenantID,
			StartTime: now.Add(-24 * time.Hour),
			EndTime:   now.Add(time.Hour),
			Provider:  "openai",
			Limit:     50,
		}
		records, _, err := repo.ListUsageRecords(ctx, opts)
		if err != nil {
			t.Fatalf("ListUsageRecords() error = %v", err)
		}
		for _, r := range records {
			if r.Provider != "openai" {
				t.Errorf("Expected provider openai, got %s", r.Provider)
			}
		}
	})
}

func TestPostgresRepository_Integration_Aggregates(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresRepository(db)
	tenantID := fmt.Sprintf("test-tenant-agg-%d", time.Now().UnixNano())

	// Cleanup at the end
	defer func() {
		db.Exec("DELETE FROM usage_aggregates WHERE tenant_id = $1", tenantID)
	}()

	ctx := context.Background()
	periodStart := time.Now().Truncate(24 * time.Hour)

	t.Run("update and get aggregate", func(t *testing.T) {
		agg := &UsageAggregate{
			Scope:          string(ScopeOrganization),
			ScopeID:        "org-123",
			Period:         AggregateDaily,
			PeriodStart:    periodStart,
			OrgID:          "org-123",
			TenantID:       tenantID,
			RequestCount:   10,
			TotalTokensIn:  1000,
			TotalTokensOut: 500,
			TotalCostUSD:   0.50,
		}

		err := repo.UpdateAggregate(ctx, agg)
		if err != nil {
			t.Fatalf("UpdateAggregate() error = %v", err)
		}

		// Get the aggregate back
		result, err := repo.GetAggregate(ctx, agg.Scope, agg.ScopeID, agg.Period, agg.PeriodStart, agg.OrgID, agg.TenantID)
		if err != nil {
			t.Fatalf("GetAggregate() error = %v", err)
		}
		if result == nil {
			t.Fatal("Expected aggregate to be found")
		}
		if result.RequestCount != 10 {
			t.Errorf("Expected RequestCount 10, got %d", result.RequestCount)
		}
	})

	t.Run("list aggregates", func(t *testing.T) {
		aggregates, err := repo.ListAggregates(ctx, string(ScopeOrganization), "org-123", AggregateDaily, periodStart.Add(-24*time.Hour), periodStart.Add(24*time.Hour), "org-123", tenantID)
		if err != nil {
			t.Fatalf("ListAggregates() error = %v", err)
		}
		if len(aggregates) == 0 {
			t.Error("Expected at least one aggregate")
		}
	})
}
