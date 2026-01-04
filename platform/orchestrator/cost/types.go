// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package cost provides budget management and cost tracking for LLM usage.
// It supports budget limits, usage tracking, and alerts for cost control.
package cost

import (
	"encoding/json"
	"time"
)

// BudgetScope represents the scope level of a budget
type BudgetScope string

const (
	ScopeOrganization BudgetScope = "organization"
	ScopeTeam         BudgetScope = "team"
	ScopeAgent        BudgetScope = "agent"
	ScopeWorkflow     BudgetScope = "workflow"
	ScopeUser         BudgetScope = "user"
)

// BudgetPeriod represents the time period for a budget
type BudgetPeriod string

const (
	PeriodDaily     BudgetPeriod = "daily"
	PeriodWeekly    BudgetPeriod = "weekly"
	PeriodMonthly   BudgetPeriod = "monthly"
	PeriodQuarterly BudgetPeriod = "quarterly"
	PeriodYearly    BudgetPeriod = "yearly"
)

// OnExceedAction defines what happens when a budget is exceeded
type OnExceedAction string

const (
	OnExceedWarn      OnExceedAction = "warn"
	OnExceedBlock     OnExceedAction = "block"
	OnExceedDowngrade OnExceedAction = "downgrade"
)

// AggregatePeriod represents the aggregation time period
type AggregatePeriod string

const (
	AggregateHourly  AggregatePeriod = "hourly"
	AggregateDaily   AggregatePeriod = "daily"
	AggregateWeekly  AggregatePeriod = "weekly"
	AggregateMonthly AggregatePeriod = "monthly"
)

// Budget represents a cost budget configuration
type Budget struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Description     string          `json:"description,omitempty"`
	Scope           BudgetScope     `json:"scope"`
	ScopeID         string          `json:"scope_id,omitempty"`
	LimitUSD        float64         `json:"limit_usd"`
	Period          BudgetPeriod    `json:"period"`
	OnExceed        OnExceedAction  `json:"on_exceed"`
	AlertThresholds []int           `json:"alert_thresholds"` // e.g., [50, 80, 100]
	Enabled         bool            `json:"enabled"`
	OrgID           string          `json:"org_id,omitempty"`
	TenantID        string          `json:"tenant_id,omitempty"`
	CreatedBy       string          `json:"created_by,omitempty"`
	UpdatedBy       string          `json:"updated_by,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// UsageRecord represents a single LLM usage event
type UsageRecord struct {
	ID          int64     `json:"id,omitempty"`
	RequestID   string    `json:"request_id"`
	Timestamp   time.Time `json:"timestamp"`
	OrgID       string    `json:"org_id,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	TeamID      string    `json:"team_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	WorkflowID  string    `json:"workflow_id,omitempty"`
	UserID      string    `json:"user_id,omitempty"`
	Provider    string    `json:"provider"`
	Model       string    `json:"model"`
	TokensIn    int       `json:"tokens_in"`
	TokensOut   int       `json:"tokens_out"`
	CostUSD     float64   `json:"cost_usd"`
	RequestType string    `json:"request_type,omitempty"`
	Cached      bool      `json:"cached"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// UsageAggregate represents aggregated usage for a time period
type UsageAggregate struct {
	ID            int64           `json:"id,omitempty"`
	Scope         string          `json:"scope"`
	ScopeID       string          `json:"scope_id"`
	Period        AggregatePeriod `json:"period"`
	PeriodStart   time.Time       `json:"period_start"`
	TotalCostUSD  float64         `json:"total_cost_usd"`
	TotalTokensIn int             `json:"total_tokens_in"`
	TotalTokensOut int            `json:"total_tokens_out"`
	RequestCount  int             `json:"request_count"`
	OrgID         string          `json:"org_id,omitempty"`
	TenantID      string          `json:"tenant_id,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at,omitempty"`
}

// BudgetStatus represents the current status of a budget
type BudgetStatus struct {
	Budget      *Budget   `json:"budget"`
	UsedUSD     float64   `json:"used_usd"`
	RemainingUSD float64  `json:"remaining_usd"`
	Percentage  float64   `json:"percentage"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	IsExceeded  bool      `json:"is_exceeded"`
	IsBlocked   bool      `json:"is_blocked"`
}

// BudgetDecision represents the result of a budget check
type BudgetDecision struct {
	Allowed     bool           `json:"allowed"`
	Action      OnExceedAction `json:"action,omitempty"`
	BudgetID    string         `json:"budget_id,omitempty"`
	BudgetName  string         `json:"budget_name,omitempty"`
	UsedUSD     float64        `json:"used_usd,omitempty"`
	LimitUSD    float64        `json:"limit_usd,omitempty"`
	Percentage  float64        `json:"percentage,omitempty"`
	Message     string         `json:"message,omitempty"`
}

// BudgetAlert represents an alert for budget threshold
type BudgetAlert struct {
	ID                int64     `json:"id,omitempty"`
	BudgetID          string    `json:"budget_id"`
	Threshold         int       `json:"threshold"`
	PercentageReached float64   `json:"percentage_reached"`
	AmountUSD         float64   `json:"amount_usd"`
	AlertType         string    `json:"alert_type"`
	Message           string    `json:"message,omitempty"`
	Acknowledged      bool      `json:"acknowledged"`
	AcknowledgedBy    string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt    *time.Time `json:"acknowledged_at,omitempty"`
	CreatedAt         time.Time `json:"created_at,omitempty"`
}

// UsageSummary provides a summary of usage for a period
type UsageSummary struct {
	TotalCostUSD     float64   `json:"total_cost_usd"`
	TotalTokensIn    int       `json:"total_tokens_in"`
	TotalTokensOut   int       `json:"total_tokens_out"`
	TotalRequests    int       `json:"total_requests"`
	Period           string    `json:"period"`
	PeriodStart      time.Time `json:"period_start"`
	PeriodEnd        time.Time `json:"period_end"`
	AverageCostPerRequest float64 `json:"average_cost_per_request"`
}

// UsageBreakdownItem represents a single item in usage breakdown
type UsageBreakdownItem struct {
	GroupBy      string  `json:"group_by"` // The dimension name
	GroupValue   string  `json:"group_value"`
	CostUSD      float64 `json:"cost_usd"`
	TokensIn     int     `json:"tokens_in"`
	TokensOut    int     `json:"tokens_out"`
	RequestCount int     `json:"request_count"`
	Percentage   float64 `json:"percentage"`
}

// UsageBreakdown contains usage breakdown by dimension
type UsageBreakdown struct {
	GroupBy    string               `json:"group_by"`
	TotalCostUSD float64            `json:"total_cost_usd"`
	Items      []UsageBreakdownItem `json:"items"`
	Period     string               `json:"period,omitempty"`
	StartTime  time.Time            `json:"start_time,omitempty"`
	EndTime    time.Time            `json:"end_time,omitempty"`
}

// ListBudgetsOptions for filtering budget queries
type ListBudgetsOptions struct {
	OrgID    string      `json:"org_id,omitempty"`
	TenantID string      `json:"tenant_id,omitempty"`
	Scope    BudgetScope `json:"scope,omitempty"`
	ScopeID  string      `json:"scope_id,omitempty"`
	Enabled  *bool       `json:"enabled,omitempty"`
	Limit    int         `json:"limit,omitempty"`
	Offset   int         `json:"offset,omitempty"`
}

// UsageQueryOptions for filtering usage queries
type UsageQueryOptions struct {
	OrgID      string    `json:"org_id,omitempty"`
	TenantID   string    `json:"tenant_id,omitempty"`
	TeamID     string    `json:"team_id,omitempty"`
	AgentID    string    `json:"agent_id,omitempty"`
	WorkflowID string    `json:"workflow_id,omitempty"`
	UserID     string    `json:"user_id,omitempty"`
	Provider   string    `json:"provider,omitempty"`
	Model      string    `json:"model,omitempty"`
	StartTime  time.Time `json:"start_time,omitempty"`
	EndTime    time.Time `json:"end_time,omitempty"`
	Period     string    `json:"period,omitempty"` // daily, weekly, monthly
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
}

// NewBudget creates a new budget with default values
func NewBudget(id, name string, limitUSD float64, period BudgetPeriod) *Budget {
	return &Budget{
		ID:              id,
		Name:            name,
		LimitUSD:        limitUSD,
		Period:          period,
		Scope:           ScopeOrganization,
		OnExceed:        OnExceedWarn,
		AlertThresholds: []int{50, 80, 100},
		Enabled:         true,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}
}

// NewUsageRecord creates a new usage record
func NewUsageRecord(requestID, provider, model string, tokensIn, tokensOut int, costUSD float64) *UsageRecord {
	return &UsageRecord{
		RequestID: requestID,
		Timestamp: time.Now().UTC(),
		Provider:  provider,
		Model:     model,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
		CostUSD:   costUSD,
	}
}

// MarshalAlertThresholds marshals alert thresholds to JSON
func (b *Budget) MarshalAlertThresholds() ([]byte, error) {
	return json.Marshal(b.AlertThresholds)
}

// UnmarshalAlertThresholds unmarshals alert thresholds from JSON
func (b *Budget) UnmarshalAlertThresholds(data []byte) error {
	return json.Unmarshal(data, &b.AlertThresholds)
}

// TotalTokens returns total tokens used
func (r *UsageRecord) TotalTokens() int {
	return r.TokensIn + r.TokensOut
}

// Validate validates the budget configuration
func (b *Budget) Validate() error {
	if b.ID == "" {
		return ErrInvalidBudgetID
	}
	if b.Name == "" {
		return ErrInvalidBudgetName
	}
	if b.LimitUSD <= 0 {
		return ErrInvalidBudgetLimit
	}
	if !isValidScope(b.Scope) {
		return ErrInvalidBudgetScope
	}
	if !isValidPeriod(b.Period) {
		return ErrInvalidBudgetPeriod
	}
	if !isValidOnExceed(b.OnExceed) {
		return ErrInvalidOnExceed
	}
	return nil
}

func isValidScope(s BudgetScope) bool {
	switch s {
	case ScopeOrganization, ScopeTeam, ScopeAgent, ScopeWorkflow, ScopeUser:
		return true
	}
	return false
}

func isValidPeriod(p BudgetPeriod) bool {
	switch p {
	case PeriodDaily, PeriodWeekly, PeriodMonthly, PeriodQuarterly, PeriodYearly:
		return true
	}
	return false
}

func isValidOnExceed(a OnExceedAction) bool {
	switch a {
	case "", OnExceedWarn, OnExceedBlock, OnExceedDowngrade:
		// Empty string defaults to warn
		return true
	}
	return false
}
