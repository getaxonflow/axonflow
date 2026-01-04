// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// MockRepository implements Repository interface for testing
type MockRepository struct {
	mu sync.RWMutex

	// Storage
	budgets    map[string]*Budget
	usageSum   map[string]float64
	alerts     []BudgetAlert
	aggregates map[string]*UsageAggregate
	records    []UsageRecord

	// Error injection
	saveUsageErr error
	pingErr      error
}

func NewMockRepository() *MockRepository {
	return &MockRepository{
		budgets:    make(map[string]*Budget),
		usageSum:   make(map[string]float64),
		aggregates: make(map[string]*UsageAggregate),
	}
}

func (m *MockRepository) CreateBudget(ctx context.Context, budget *Budget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.budgets[budget.ID]; exists {
		return ErrBudgetExists
	}
	m.budgets[budget.ID] = budget
	return nil
}

func (m *MockRepository) GetBudget(ctx context.Context, id string) (*Budget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if budget, ok := m.budgets[id]; ok {
		return budget, nil
	}
	return nil, ErrBudgetNotFound
}

func (m *MockRepository) UpdateBudget(ctx context.Context, budget *Budget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.budgets[budget.ID]; !exists {
		return ErrBudgetNotFound
	}
	m.budgets[budget.ID] = budget
	return nil
}

func (m *MockRepository) DeleteBudget(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.budgets[id]; !exists {
		return ErrBudgetNotFound
	}
	delete(m.budgets, id)
	return nil
}

func (m *MockRepository) ListBudgets(ctx context.Context, opts ListBudgetsOptions) ([]Budget, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []Budget
	for _, b := range m.budgets {
		if opts.OrgID != "" && b.OrgID != opts.OrgID {
			continue
		}
		if opts.Scope != "" && b.Scope != opts.Scope {
			continue
		}
		result = append(result, *b)
	}
	return result, len(result), nil
}

func (m *MockRepository) GetBudgetsForScope(ctx context.Context, scope BudgetScope, scopeID string, orgID, tenantID string) ([]Budget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []Budget
	for _, b := range m.budgets {
		if b.Scope == scope && b.ScopeID == scopeID && b.Enabled {
			result = append(result, *b)
		}
	}
	return result, nil
}

func (m *MockRepository) SaveUsage(ctx context.Context, record *UsageRecord) error {
	if m.saveUsageErr != nil {
		return m.saveUsageErr
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.records = append(m.records, *record)
	key := record.OrgID + ":" + string(ScopeOrganization) + ":" + record.OrgID
	m.usageSum[key] += record.CostUSD
	return nil
}

func (m *MockRepository) GetUsageForPeriod(ctx context.Context, scope BudgetScope, scopeID string, periodStart time.Time, orgID, tenantID string) (float64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := orgID + ":" + string(scope) + ":" + scopeID
	return m.usageSum[key], nil
}

func (m *MockRepository) GetUsageSummary(ctx context.Context, opts UsageQueryOptions) (*UsageSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var total float64
	var tokensIn, tokensOut, count int
	for _, r := range m.records {
		if opts.OrgID != "" && r.OrgID != opts.OrgID {
			continue
		}
		total += r.CostUSD
		tokensIn += r.TokensIn
		tokensOut += r.TokensOut
		count++
	}

	return &UsageSummary{
		TotalCostUSD:   total,
		TotalTokensIn:  tokensIn,
		TotalTokensOut: tokensOut,
		TotalRequests:  count,
	}, nil
}

func (m *MockRepository) GetUsageBreakdown(ctx context.Context, groupBy string, opts UsageQueryOptions) (*UsageBreakdown, error) {
	if groupBy != "provider" && groupBy != "model" && groupBy != "agent" && groupBy != "team" {
		return nil, ErrInvalidGroupBy
	}

	return &UsageBreakdown{
		GroupBy: groupBy,
		Items:   []UsageBreakdownItem{},
	}, nil
}

func (m *MockRepository) ListUsageRecords(ctx context.Context, opts UsageQueryOptions) ([]UsageRecord, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.records, len(m.records), nil
}

func (m *MockRepository) UpdateAggregate(ctx context.Context, aggregate *UsageAggregate) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := aggregate.Scope + ":" + aggregate.ScopeID + ":" + string(aggregate.Period)
	m.aggregates[key] = aggregate
	return nil
}

func (m *MockRepository) GetAggregate(ctx context.Context, scope, scopeID string, period AggregatePeriod, periodStart time.Time, orgID, tenantID string) (*UsageAggregate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := scope + ":" + scopeID + ":" + string(period)
	if agg, ok := m.aggregates[key]; ok {
		return agg, nil
	}
	return nil, nil
}

func (m *MockRepository) ListAggregates(ctx context.Context, scope, scopeID string, period AggregatePeriod, startTime, endTime time.Time, orgID, tenantID string) ([]UsageAggregate, error) {
	return nil, nil
}

func (m *MockRepository) SaveAlert(ctx context.Context, alert *BudgetAlert) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert.ID = int64(len(m.alerts) + 1)
	alert.CreatedAt = time.Now().UTC()
	m.alerts = append(m.alerts, *alert)
	return nil
}

func (m *MockRepository) GetUnacknowledgedAlerts(ctx context.Context, budgetID string) ([]BudgetAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BudgetAlert
	for _, a := range m.alerts {
		if a.BudgetID == budgetID && !a.Acknowledged {
			result = append(result, a)
		}
	}
	return result, nil
}

func (m *MockRepository) AcknowledgeAlert(ctx context.Context, alertID int64, acknowledgedBy string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.alerts {
		if m.alerts[i].ID == alertID {
			m.alerts[i].Acknowledged = true
			m.alerts[i].AcknowledgedBy = acknowledgedBy
			now := time.Now().UTC()
			m.alerts[i].AcknowledgedAt = &now
			return nil
		}
	}
	return errors.New("alert not found")
}

func (m *MockRepository) GetRecentAlerts(ctx context.Context, budgetID string, limit int) ([]BudgetAlert, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []BudgetAlert
	for _, a := range m.alerts {
		if a.BudgetID == budgetID {
			result = append(result, a)
			if len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

func (m *MockRepository) Ping(ctx context.Context) error {
	return m.pingErr
}

// SetUsageForScope sets usage for testing budget checks
func (m *MockRepository) SetUsageForScope(scope BudgetScope, scopeID, orgID string, amount float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := orgID + ":" + string(scope) + ":" + scopeID
	m.usageSum[key] = amount
}

// Tests

func TestNewService(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)

	if service == nil {
		t.Fatal("expected non-nil service")
	}

	if service.pricing == nil {
		t.Error("expected pricing to be set")
	}
}

func TestNewServiceWithOptions(t *testing.T) {
	repo := NewMockRepository()
	pricing := NewPricingConfig()
	alerter := NewLogAlerter(nil)

	service := NewServiceWithOptions(repo, pricing, alerter, nil)

	if service == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestCreateBudget(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	budget := &Budget{
		ID:       "test-budget-1",
		Name:     "Test Budget",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
		Enabled:  true,
	}

	err := service.CreateBudget(ctx, budget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify budget was created
	got, err := service.GetBudget(ctx, "test-budget-1")
	if err != nil {
		t.Fatalf("failed to get budget: %v", err)
	}

	if got.Name != budget.Name {
		t.Errorf("name = %v, want %v", got.Name, budget.Name)
	}
}

func TestCreateBudgetValidation(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	tests := []struct {
		name    string
		budget  *Budget
		wantErr bool
	}{
		{
			name: "valid budget",
			budget: &Budget{
				ID:       "valid",
				Name:     "Valid",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: false,
		},
		{
			name: "missing ID",
			budget: &Budget{
				Name:     "Missing ID",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "missing name",
			budget: &Budget{
				ID:       "missing-name",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "zero limit",
			budget: &Budget{
				ID:       "zero-limit",
				Name:     "Zero Limit",
				Scope:    ScopeOrganization,
				LimitUSD: 0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "negative limit",
			budget: &Budget{
				ID:       "negative",
				Name:     "Negative",
				Scope:    ScopeOrganization,
				LimitUSD: -100,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.CreateBudget(ctx, tt.budget)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateBudget() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetBudgetNotFound(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	_, err := service.GetBudget(ctx, "nonexistent")
	if !errors.Is(err, ErrBudgetNotFound) {
		t.Errorf("expected ErrBudgetNotFound, got %v", err)
	}
}

func TestUpdateBudget(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Create budget first
	budget := &Budget{
		ID:       "update-test",
		Name:     "Original",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}
	service.CreateBudget(ctx, budget)

	// Update it
	budget.Name = "Updated"
	budget.LimitUSD = 200.0
	err := service.UpdateBudget(ctx, budget)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify
	got, _ := service.GetBudget(ctx, "update-test")
	if got.Name != "Updated" {
		t.Errorf("name = %v, want Updated", got.Name)
	}
	if got.LimitUSD != 200.0 {
		t.Errorf("limit = %v, want 200", got.LimitUSD)
	}
}

func TestDeleteBudget(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Create budget
	budget := &Budget{
		ID:       "delete-test",
		Name:     "To Delete",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}
	service.CreateBudget(ctx, budget)

	// Delete it
	err := service.DeleteBudget(ctx, "delete-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify it's gone
	_, err = service.GetBudget(ctx, "delete-test")
	if !errors.Is(err, ErrBudgetNotFound) {
		t.Errorf("expected ErrBudgetNotFound after delete, got %v", err)
	}
}

func TestRecordUsage(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	record := &UsageRecord{
		RequestID: "req-1",
		Provider:  "anthropic",
		Model:     "claude-sonnet-4",
		TokensIn:  1000,
		TokensOut: 500,
		OrgID:     "org-1",
	}

	err := service.RecordUsage(ctx, record)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Cost should be calculated
	if record.CostUSD == 0 {
		t.Error("expected cost to be calculated")
	}

	// Timestamp should be set
	if record.Timestamp.IsZero() {
		t.Error("expected timestamp to be set")
	}
}

func TestRecordUsageNilRecord(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	err := service.RecordUsage(ctx, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput, got %v", err)
	}
}

func TestRecordUsageSaveError(t *testing.T) {
	repo := NewMockRepository()
	repo.saveUsageErr = errors.New("save failed")
	service := NewService(repo, nil)
	ctx := context.Background()

	record := &UsageRecord{
		RequestID: "req-1",
		Provider:  "anthropic",
		Model:     "claude-sonnet-4",
		TokensIn:  100,
		TokensOut: 50,
	}

	err := service.RecordUsage(ctx, record)
	if err == nil {
		t.Error("expected error when save fails")
	}
}

func TestGetBudgetStatus(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Create budget
	budget := &Budget{
		ID:       "status-test",
		Name:     "Status Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		Enabled:  true,
	}
	service.CreateBudget(ctx, budget)

	// Set some usage
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 50.0)

	status, err := service.GetBudgetStatus(ctx, "status-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if status.UsedUSD != 50.0 {
		t.Errorf("UsedUSD = %v, want 50", status.UsedUSD)
	}

	if status.RemainingUSD != 50.0 {
		t.Errorf("RemainingUSD = %v, want 50", status.RemainingUSD)
	}

	if status.Percentage != 50.0 {
		t.Errorf("Percentage = %v, want 50", status.Percentage)
	}

	if status.IsExceeded {
		t.Error("should not be exceeded at 50%")
	}
}

func TestGetBudgetStatusExceeded(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	budget := &Budget{
		ID:       "exceeded-test",
		Name:     "Exceeded Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		OnExceed: OnExceedBlock,
		Enabled:  true,
	}
	service.CreateBudget(ctx, budget)

	// Set usage over limit
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 150.0)

	status, err := service.GetBudgetStatus(ctx, "exceeded-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !status.IsExceeded {
		t.Error("should be exceeded at 150%")
	}

	if !status.IsBlocked {
		t.Error("should be blocked with OnExceedBlock")
	}
}

func TestCheckBudget(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Create budget with block action
	budget := &Budget{
		ID:       "check-test",
		Name:     "Check Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		OnExceed: OnExceedBlock,
		Enabled:  true,
	}
	service.CreateBudget(ctx, budget)

	// Under budget
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 50.0)
	decision, err := service.CheckBudget(ctx, "org-1", "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Error("should be allowed under budget")
	}

	// Over budget
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 150.0)
	decision, err = service.CheckBudget(ctx, "org-1", "", "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("should be blocked over budget")
	}
	if decision.Action != OnExceedBlock {
		t.Errorf("action = %v, want %v", decision.Action, OnExceedBlock)
	}
}

func TestGetUsageSummary(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Record some usage
	for i := 0; i < 5; i++ {
		record := &UsageRecord{
			RequestID: "req-" + string(rune('0'+i)),
			Provider:  "anthropic",
			Model:     "claude-sonnet-4",
			TokensIn:  100,
			TokensOut: 50,
			OrgID:     "org-1",
		}
		service.RecordUsage(ctx, record)
	}

	// Wait for async operations
	time.Sleep(50 * time.Millisecond)

	summary, err := service.GetUsageSummary(ctx, UsageQueryOptions{
		OrgID:  "org-1",
		Period: "monthly",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if summary.TotalRequests != 5 {
		t.Errorf("TotalRequests = %v, want 5", summary.TotalRequests)
	}
}

func TestGetUsageBreakdown(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	tests := []struct {
		name    string
		groupBy string
		wantErr bool
	}{
		{"by provider", "provider", false},
		{"by model", "model", false},
		{"by agent", "agent", false},
		{"by team", "team", false},
		{"invalid groupBy", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.GetUsageBreakdown(ctx, tt.groupBy, UsageQueryOptions{Period: "monthly"})
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUsageBreakdown() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetPricing(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)

	pricing := service.GetPricing()
	if pricing == nil {
		t.Fatal("expected non-nil pricing")
	}
}

func TestCalculateCostService(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)

	cost := service.CalculateCost("anthropic", "claude-sonnet-4", 1000, 500)
	if cost <= 0 {
		t.Errorf("expected positive cost, got %v", cost)
	}
}

func TestIsHealthy(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Healthy
	if !service.IsHealthy(ctx) {
		t.Error("expected healthy service")
	}

	// Unhealthy
	repo.pingErr = errors.New("connection failed")
	if service.IsHealthy(ctx) {
		t.Error("expected unhealthy service with ping error")
	}
}

func TestResetAlertedThresholds(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)

	// Mark some thresholds as alerted
	service.markAlertedThreshold("budget-1", 50)
	service.markAlertedThreshold("budget-1", 80)

	if !service.hasAlertedThreshold("budget-1", 50) {
		t.Error("should have alerted threshold 50")
	}

	// Reset
	service.ResetAlertedThresholds("budget-1")

	if service.hasAlertedThreshold("budget-1", 50) {
		t.Error("should not have alerted threshold after reset")
	}
}

func TestLogAlerter(t *testing.T) {
	alerter := NewLogAlerter(nil)
	ctx := context.Background()

	event := AlertEvent{
		BudgetID:   "test",
		BudgetName: "Test Budget",
		Threshold:  80,
		Current:    85.5,
		UsedUSD:    85.50,
		LimitUSD:   100.0,
		Message:    "Test message",
		AlertType:  AlertTypeThresholdReached,
		Timestamp:  time.Now().UTC(),
	}

	err := alerter.Alert(ctx, event)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestListBudgets(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	// Create multiple budgets
	for i := 0; i < 5; i++ {
		budget := &Budget{
			ID:       "budget-" + string(rune('0'+i)),
			Name:     "Budget " + string(rune('0'+i)),
			Scope:    ScopeOrganization,
			LimitUSD: 100.0,
			Period:   PeriodMonthly,
			OrgID:    "org-1",
		}
		service.CreateBudget(ctx, budget)
	}

	budgets, total, err := service.ListBudgets(ctx, ListBudgetsOptions{OrgID: "org-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if total != 5 {
		t.Errorf("total = %v, want 5", total)
	}

	if len(budgets) != 5 {
		t.Errorf("len(budgets) = %v, want 5", len(budgets))
	}
}

func TestDuplicateBudget(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()

	budget := &Budget{
		ID:       "duplicate-test",
		Name:     "Original",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}

	// First create should succeed
	err := service.CreateBudget(ctx, budget)
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	// Second create should fail
	err = service.CreateBudget(ctx, budget)
	if !errors.Is(err, ErrBudgetExists) {
		t.Errorf("expected ErrBudgetExists, got %v", err)
	}
}
