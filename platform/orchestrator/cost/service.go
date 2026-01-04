// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// Alerter defines the interface for sending budget alerts
type Alerter interface {
	Alert(ctx context.Context, event AlertEvent) error
}

// AlertEvent represents a budget alert event
type AlertEvent struct {
	BudgetID    string    `json:"budget_id"`
	BudgetName  string    `json:"budget_name"`
	Threshold   int       `json:"threshold"`
	Current     float64   `json:"current_percentage"`
	UsedUSD     float64   `json:"used_usd"`
	LimitUSD    float64   `json:"limit_usd"`
	Message     string    `json:"message"`
	AlertType   string    `json:"alert_type"`
	Timestamp   time.Time `json:"timestamp"`
}

// LogAlerter is a simple alerter that logs to stdout (Phase 1)
type LogAlerter struct {
	logger *log.Logger
}

// NewLogAlerter creates a new log-based alerter
func NewLogAlerter(logger *log.Logger) *LogAlerter {
	if logger == nil {
		logger = log.Default()
	}
	return &LogAlerter{logger: logger}
}

// Alert logs the alert event
func (a *LogAlerter) Alert(ctx context.Context, event AlertEvent) error {
	a.logger.Printf("[COST ALERT] %s: %s (%.1f%% - $%.2f / $%.2f)",
		event.AlertType, event.Message, event.Current, event.UsedUSD, event.LimitUSD)
	return nil
}

// Service provides cost tracking and budget management
type Service struct {
	repo           Repository
	pricing        *PricingConfig
	alerter        Alerter
	logger         *log.Logger
	mu             sync.RWMutex

	// Track which thresholds have been alerted to avoid duplicates
	alertedThresholds map[string]map[int]bool
}

// NewService creates a new cost service
func NewService(repo Repository, pricing *PricingConfig) *Service {
	if pricing == nil {
		pricing = NewPricingConfig()
	}
	return &Service{
		repo:              repo,
		pricing:           pricing,
		alerter:           NewLogAlerter(nil),
		logger:            log.Default(),
		alertedThresholds: make(map[string]map[int]bool),
	}
}

// NewServiceWithOptions creates a service with custom options
func NewServiceWithOptions(repo Repository, pricing *PricingConfig, alerter Alerter, logger *log.Logger) *Service {
	if pricing == nil {
		pricing = NewPricingConfig()
	}
	if alerter == nil {
		alerter = NewLogAlerter(logger)
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Service{
		repo:              repo,
		pricing:           pricing,
		alerter:           alerter,
		logger:            logger,
		alertedThresholds: make(map[string]map[int]bool),
	}
}

// RecordUsage records usage after an LLM call
func (s *Service) RecordUsage(ctx context.Context, record *UsageRecord) error {
	if record == nil {
		return ErrInvalidInput
	}

	// Calculate cost if not provided
	if record.CostUSD == 0 {
		record.CostUSD = s.pricing.CalculateCost(
			record.Provider, record.Model,
			record.TokensIn, record.TokensOut,
		)
	}

	// Set timestamp if not set
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now().UTC()
	}

	// Save usage record
	if err := s.repo.SaveUsage(ctx, record); err != nil {
		s.logger.Printf("[Cost] Failed to save usage: %v", err)
		return fmt.Errorf("failed to save usage: %w", err)
	}

	// Update aggregates asynchronously
	go s.updateAggregates(context.Background(), record)

	// Check budgets asynchronously
	go s.checkBudgetsAsync(context.Background(), record)

	s.logger.Printf("[Cost] Recorded usage: provider=%s model=%s tokens=%d cost=$%.6f",
		record.Provider, record.Model, record.TotalTokens(), record.CostUSD)

	return nil
}

// updateAggregates updates usage aggregates
func (s *Service) updateAggregates(ctx context.Context, record *UsageRecord) {
	now := record.Timestamp

	// Update hourly aggregate
	hourlyStart := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, time.UTC)
	s.updateAggregate(ctx, record, AggregateHourly, hourlyStart)

	// Update daily aggregate
	dailyStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	s.updateAggregate(ctx, record, AggregateDaily, dailyStart)

	// Update monthly aggregate
	monthlyStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	s.updateAggregate(ctx, record, AggregateMonthly, monthlyStart)
}

func (s *Service) updateAggregate(ctx context.Context, record *UsageRecord, period AggregatePeriod, periodStart time.Time) {
	// Update provider aggregate
	if record.Provider != "" {
		agg := &UsageAggregate{
			Scope:          "provider",
			ScopeID:        record.Provider,
			Period:         period,
			PeriodStart:    periodStart,
			TotalCostUSD:   record.CostUSD,
			TotalTokensIn:  record.TokensIn,
			TotalTokensOut: record.TokensOut,
			RequestCount:   1,
			OrgID:          record.OrgID,
			TenantID:       record.TenantID,
		}
		if err := s.repo.UpdateAggregate(ctx, agg); err != nil {
			s.logger.Printf("[Cost] Failed to update provider aggregate: %v", err)
		}
	}

	// Update model aggregate
	if record.Model != "" {
		agg := &UsageAggregate{
			Scope:          "model",
			ScopeID:        record.Model,
			Period:         period,
			PeriodStart:    periodStart,
			TotalCostUSD:   record.CostUSD,
			TotalTokensIn:  record.TokensIn,
			TotalTokensOut: record.TokensOut,
			RequestCount:   1,
			OrgID:          record.OrgID,
			TenantID:       record.TenantID,
		}
		if err := s.repo.UpdateAggregate(ctx, agg); err != nil {
			s.logger.Printf("[Cost] Failed to update model aggregate: %v", err)
		}
	}

	// Update org aggregate
	if record.OrgID != "" {
		agg := &UsageAggregate{
			Scope:          "organization",
			ScopeID:        record.OrgID,
			Period:         period,
			PeriodStart:    periodStart,
			TotalCostUSD:   record.CostUSD,
			TotalTokensIn:  record.TokensIn,
			TotalTokensOut: record.TokensOut,
			RequestCount:   1,
			OrgID:          record.OrgID,
			TenantID:       record.TenantID,
		}
		if err := s.repo.UpdateAggregate(ctx, agg); err != nil {
			s.logger.Printf("[Cost] Failed to update org aggregate: %v", err)
		}
	}

	// Update agent aggregate
	if record.AgentID != "" {
		agg := &UsageAggregate{
			Scope:          "agent",
			ScopeID:        record.AgentID,
			Period:         period,
			PeriodStart:    periodStart,
			TotalCostUSD:   record.CostUSD,
			TotalTokensIn:  record.TokensIn,
			TotalTokensOut: record.TokensOut,
			RequestCount:   1,
			OrgID:          record.OrgID,
			TenantID:       record.TenantID,
		}
		if err := s.repo.UpdateAggregate(ctx, agg); err != nil {
			s.logger.Printf("[Cost] Failed to update agent aggregate: %v", err)
		}
	}
}

// checkBudgetsAsync checks budgets and sends alerts asynchronously
func (s *Service) checkBudgetsAsync(ctx context.Context, record *UsageRecord) {
	// Check organization budget
	if record.OrgID != "" {
		s.checkBudgetForScope(ctx, ScopeOrganization, record.OrgID, record.OrgID, record.TenantID)
	}

	// Check team budget
	if record.TeamID != "" {
		s.checkBudgetForScope(ctx, ScopeTeam, record.TeamID, record.OrgID, record.TenantID)
	}

	// Check agent budget
	if record.AgentID != "" {
		s.checkBudgetForScope(ctx, ScopeAgent, record.AgentID, record.OrgID, record.TenantID)
	}

	// Check user budget
	if record.UserID != "" {
		s.checkBudgetForScope(ctx, ScopeUser, record.UserID, record.OrgID, record.TenantID)
	}
}

func (s *Service) checkBudgetForScope(ctx context.Context, scope BudgetScope, scopeID, orgID, tenantID string) {
	budgets, err := s.repo.GetBudgetsForScope(ctx, scope, scopeID, orgID, tenantID)
	if err != nil {
		s.logger.Printf("[Cost] Failed to get budgets for scope %s/%s: %v", scope, scopeID, err)
		return
	}

	for _, budget := range budgets {
		s.checkSingleBudget(ctx, &budget)
	}
}

func (s *Service) checkSingleBudget(ctx context.Context, budget *Budget) {
	periodStart := s.getPeriodStart(budget.Period)
	used, err := s.repo.GetUsageForPeriod(ctx, budget.Scope, budget.ScopeID, periodStart, budget.OrgID, budget.TenantID)
	if err != nil {
		s.logger.Printf("[Cost] Failed to get usage for budget %s: %v", budget.ID, err)
		return
	}

	percentage := 0.0
	if budget.LimitUSD > 0 {
		percentage = (used / budget.LimitUSD) * 100
	}

	// Check each threshold
	for _, threshold := range budget.AlertThresholds {
		if percentage >= float64(threshold) && !s.hasAlertedThreshold(budget.ID, threshold) {
			s.sendAlert(ctx, budget, threshold, percentage, used)
		}
	}
}

func (s *Service) hasAlertedThreshold(budgetID string, threshold int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if thresholds, ok := s.alertedThresholds[budgetID]; ok {
		return thresholds[threshold]
	}
	return false
}

func (s *Service) markAlertedThreshold(budgetID string, threshold int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.alertedThresholds[budgetID] == nil {
		s.alertedThresholds[budgetID] = make(map[int]bool)
	}
	s.alertedThresholds[budgetID][threshold] = true
}

func (s *Service) sendAlert(ctx context.Context, budget *Budget, threshold int, percentage, used float64) {
	alertType := AlertTypeThresholdReached
	if percentage >= 100 {
		if budget.OnExceed == OnExceedBlock {
			alertType = AlertTypeBudgetBlocked
		} else {
			alertType = AlertTypeBudgetExceeded
		}
	}

	message := fmt.Sprintf("Budget '%s' at %.1f%% ($%.2f / $%.2f)", budget.Name, percentage, used, budget.LimitUSD)

	event := AlertEvent{
		BudgetID:   budget.ID,
		BudgetName: budget.Name,
		Threshold:  threshold,
		Current:    percentage,
		UsedUSD:    used,
		LimitUSD:   budget.LimitUSD,
		Message:    message,
		AlertType:  alertType,
		Timestamp:  time.Now().UTC(),
	}

	// Send alert
	if err := s.alerter.Alert(ctx, event); err != nil {
		s.logger.Printf("[Cost] Failed to send alert: %v", err)
	}

	// Save alert to database
	alert := &BudgetAlert{
		BudgetID:          budget.ID,
		Threshold:         threshold,
		PercentageReached: percentage,
		AmountUSD:         used,
		AlertType:         alertType,
		Message:           message,
	}
	if err := s.repo.SaveAlert(ctx, alert); err != nil {
		s.logger.Printf("[Cost] Failed to save alert: %v", err)
	}

	s.markAlertedThreshold(budget.ID, threshold)
}

// CreateBudget creates a new budget
func (s *Service) CreateBudget(ctx context.Context, budget *Budget) error {
	if err := budget.Validate(); err != nil {
		return err
	}

	budget.CreatedAt = time.Now().UTC()
	budget.UpdatedAt = budget.CreatedAt

	if budget.AlertThresholds == nil {
		budget.AlertThresholds = []int{50, 80, 100}
	}

	return s.repo.CreateBudget(ctx, budget)
}

// GetBudget retrieves a budget by ID
func (s *Service) GetBudget(ctx context.Context, id string) (*Budget, error) {
	return s.repo.GetBudget(ctx, id)
}

// UpdateBudget updates an existing budget
func (s *Service) UpdateBudget(ctx context.Context, budget *Budget) error {
	if err := budget.Validate(); err != nil {
		return err
	}

	budget.UpdatedAt = time.Now().UTC()
	return s.repo.UpdateBudget(ctx, budget)
}

// DeleteBudget deletes a budget
func (s *Service) DeleteBudget(ctx context.Context, id string) error {
	// Clear alerted thresholds
	s.mu.Lock()
	delete(s.alertedThresholds, id)
	s.mu.Unlock()

	return s.repo.DeleteBudget(ctx, id)
}

// ListBudgets lists budgets with filtering
func (s *Service) ListBudgets(ctx context.Context, opts ListBudgetsOptions) ([]Budget, int, error) {
	return s.repo.ListBudgets(ctx, opts)
}

// GetBudgetStatus returns the current status of a budget
func (s *Service) GetBudgetStatus(ctx context.Context, budgetID string) (*BudgetStatus, error) {
	budget, err := s.repo.GetBudget(ctx, budgetID)
	if err != nil {
		return nil, err
	}

	periodStart := s.getPeriodStart(budget.Period)
	periodEnd := s.getPeriodEnd(budget.Period, periodStart)

	used, err := s.repo.GetUsageForPeriod(ctx, budget.Scope, budget.ScopeID, periodStart, budget.OrgID, budget.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get usage: %w", err)
	}

	percentage := 0.0
	if budget.LimitUSD > 0 {
		percentage = (used / budget.LimitUSD) * 100
	}

	return &BudgetStatus{
		Budget:       budget,
		UsedUSD:      used,
		RemainingUSD: budget.LimitUSD - used,
		Percentage:   percentage,
		PeriodStart:  periodStart,
		PeriodEnd:    periodEnd,
		IsExceeded:   used >= budget.LimitUSD,
		IsBlocked:    used >= budget.LimitUSD && budget.OnExceed == OnExceedBlock,
	}, nil
}

// CheckBudget checks if a request should be allowed based on budgets
func (s *Service) CheckBudget(ctx context.Context, orgID, teamID, agentID, userID, tenantID string) (*BudgetDecision, error) {
	decision := &BudgetDecision{Allowed: true}

	// Check budgets in order: agent → team → org → user
	scopes := []struct {
		scope   BudgetScope
		scopeID string
	}{
		{ScopeAgent, agentID},
		{ScopeTeam, teamID},
		{ScopeOrganization, orgID},
		{ScopeUser, userID},
	}

	for _, s2 := range scopes {
		if s2.scopeID == "" {
			continue
		}

		budgets, err := s.repo.GetBudgetsForScope(ctx, s2.scope, s2.scopeID, orgID, tenantID)
		if err != nil {
			continue
		}

		for _, budget := range budgets {
			status, err := s.GetBudgetStatus(ctx, budget.ID)
			if err != nil {
				continue
			}

			if status.IsBlocked {
				return &BudgetDecision{
					Allowed:    false,
					Action:     OnExceedBlock,
					BudgetID:   budget.ID,
					BudgetName: budget.Name,
					UsedUSD:    status.UsedUSD,
					LimitUSD:   budget.LimitUSD,
					Percentage: status.Percentage,
					Message:    fmt.Sprintf("Budget '%s' exceeded - requests blocked", budget.Name),
				}, nil
			}

			if status.IsExceeded {
				decision.Action = budget.OnExceed
				decision.BudgetID = budget.ID
				decision.BudgetName = budget.Name
				decision.UsedUSD = status.UsedUSD
				decision.LimitUSD = budget.LimitUSD
				decision.Percentage = status.Percentage
				decision.Message = fmt.Sprintf("Budget '%s' exceeded - %.1f%%", budget.Name, status.Percentage)
			}
		}
	}

	return decision, nil
}

// GetUsageSummary returns usage summary for a period
func (s *Service) GetUsageSummary(ctx context.Context, opts UsageQueryOptions) (*UsageSummary, error) {
	// Set default time range based on period
	if opts.StartTime.IsZero() && opts.Period != "" {
		opts.StartTime = s.getPeriodStart(BudgetPeriod(opts.Period))
		opts.EndTime = time.Now().UTC()
	}

	return s.repo.GetUsageSummary(ctx, opts)
}

// GetUsageBreakdown returns usage breakdown by dimension
func (s *Service) GetUsageBreakdown(ctx context.Context, groupBy string, opts UsageQueryOptions) (*UsageBreakdown, error) {
	// Set default time range
	if opts.StartTime.IsZero() && opts.Period != "" {
		opts.StartTime = s.getPeriodStart(BudgetPeriod(opts.Period))
		opts.EndTime = time.Now().UTC()
	}

	return s.repo.GetUsageBreakdown(ctx, groupBy, opts)
}

// ListUsageRecords lists usage records
func (s *Service) ListUsageRecords(ctx context.Context, opts UsageQueryOptions) ([]UsageRecord, int, error) {
	return s.repo.ListUsageRecords(ctx, opts)
}

// GetPricing returns the pricing configuration
func (s *Service) GetPricing() *PricingConfig {
	return s.pricing
}

// CalculateCost calculates cost for tokens
func (s *Service) CalculateCost(provider, model string, tokensIn, tokensOut int) float64 {
	return s.pricing.CalculateCost(provider, model, tokensIn, tokensOut)
}

// GetRecentAlerts gets recent alerts for a budget
func (s *Service) GetRecentAlerts(ctx context.Context, budgetID string, limit int) ([]BudgetAlert, error) {
	return s.repo.GetRecentAlerts(ctx, budgetID, limit)
}

// AcknowledgeAlert acknowledges an alert
func (s *Service) AcknowledgeAlert(ctx context.Context, alertID int64, acknowledgedBy string) error {
	return s.repo.AcknowledgeAlert(ctx, alertID, acknowledgedBy)
}

// IsHealthy checks if the service is healthy
func (s *Service) IsHealthy(ctx context.Context) bool {
	return s.repo.Ping(ctx) == nil
}

// getPeriodStart returns the start of the current period
func (s *Service) getPeriodStart(period BudgetPeriod) time.Time {
	now := time.Now().UTC()

	switch period {
	case PeriodDaily:
		return time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	case PeriodWeekly:
		// Start from Monday
		weekday := int(now.Weekday())
		if weekday == 0 {
			weekday = 7
		}
		return time.Date(now.Year(), now.Month(), now.Day()-weekday+1, 0, 0, 0, 0, time.UTC)
	case PeriodMonthly:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	case PeriodQuarterly:
		quarter := (int(now.Month()) - 1) / 3
		return time.Date(now.Year(), time.Month(quarter*3+1), 1, 0, 0, 0, 0, time.UTC)
	case PeriodYearly:
		return time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	default:
		return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	}
}

// getPeriodEnd returns the end of the period
func (s *Service) getPeriodEnd(period BudgetPeriod, start time.Time) time.Time {
	switch period {
	case PeriodDaily:
		return start.AddDate(0, 0, 1)
	case PeriodWeekly:
		return start.AddDate(0, 0, 7)
	case PeriodMonthly:
		return start.AddDate(0, 1, 0)
	case PeriodQuarterly:
		return start.AddDate(0, 3, 0)
	case PeriodYearly:
		return start.AddDate(1, 0, 0)
	default:
		return start.AddDate(0, 1, 0)
	}
}

// ResetAlertedThresholds resets alerted thresholds for a budget (for testing/new period)
func (s *Service) ResetAlertedThresholds(budgetID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.alertedThresholds, budgetID)
}
