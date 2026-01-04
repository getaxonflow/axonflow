// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"testing"
	"time"
)

func TestBudgetValidate(t *testing.T) {
	tests := []struct {
		name    string
		budget  Budget
		wantErr bool
	}{
		{
			name: "valid budget",
			budget: Budget{
				ID:       "valid-id",
				Name:     "Valid Budget",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: false,
		},
		{
			name: "missing id",
			budget: Budget{
				Name:     "Missing ID",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "missing name",
			budget: Budget{
				ID:       "missing-name",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "zero limit",
			budget: Budget{
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
			budget: Budget{
				ID:       "negative",
				Name:     "Negative",
				Scope:    ScopeOrganization,
				LimitUSD: -50.0,
				Period:   PeriodMonthly,
			},
			wantErr: true,
		},
		{
			name: "invalid on_exceed",
			budget: Budget{
				ID:       "invalid-action",
				Name:     "Invalid Action",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
				OnExceed: "invalid_action",
			},
			wantErr: true,
		},
		{
			name: "valid on_exceed warn",
			budget: Budget{
				ID:       "warn",
				Name:     "Warn",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
				OnExceed: OnExceedWarn,
			},
			wantErr: false,
		},
		{
			name: "valid on_exceed block",
			budget: Budget{
				ID:       "block",
				Name:     "Block",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
				OnExceed: OnExceedBlock,
			},
			wantErr: false,
		},
		{
			name: "valid on_exceed downgrade",
			budget: Budget{
				ID:       "downgrade",
				Name:     "Downgrade",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
				OnExceed: OnExceedDowngrade,
			},
			wantErr: false,
		},
		{
			name: "empty on_exceed (defaults to warn)",
			budget: Budget{
				ID:       "empty-action",
				Name:     "Empty Action",
				Scope:    ScopeOrganization,
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
				OnExceed: "",
			},
			wantErr: false,
		},
		{
			name: "team scope with scope_id",
			budget: Budget{
				ID:       "team-budget",
				Name:     "Team Budget",
				Scope:    ScopeTeam,
				ScopeID:  "team-123",
				LimitUSD: 100.0,
				Period:   PeriodMonthly,
			},
			wantErr: false,
		},
		{
			name: "agent scope",
			budget: Budget{
				ID:       "agent-budget",
				Name:     "Agent Budget",
				Scope:    ScopeAgent,
				ScopeID:  "agent-456",
				LimitUSD: 50.0,
				Period:   PeriodDaily,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.budget.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUsageRecordTotalTokens(t *testing.T) {
	tests := []struct {
		name      string
		tokensIn  int
		tokensOut int
		want      int
	}{
		{"both positive", 100, 200, 300},
		{"only input", 100, 0, 100},
		{"only output", 0, 200, 200},
		{"both zero", 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := UsageRecord{
				TokensIn:  tt.tokensIn,
				TokensOut: tt.tokensOut,
			}
			if got := record.TotalTokens(); got != tt.want {
				t.Errorf("TotalTokens() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBudgetScopeConstants(t *testing.T) {
	scopes := []BudgetScope{
		ScopeOrganization,
		ScopeTeam,
		ScopeAgent,
		ScopeWorkflow,
		ScopeUser,
	}

	for _, scope := range scopes {
		if scope == "" {
			t.Error("scope constant should not be empty")
		}
	}
}

func TestBudgetPeriodConstants(t *testing.T) {
	periods := []BudgetPeriod{
		PeriodDaily,
		PeriodWeekly,
		PeriodMonthly,
		PeriodQuarterly,
		PeriodYearly,
	}

	for _, period := range periods {
		if period == "" {
			t.Error("period constant should not be empty")
		}
	}
}

func TestOnExceedActionConstants(t *testing.T) {
	actions := []OnExceedAction{
		OnExceedWarn,
		OnExceedBlock,
		OnExceedDowngrade,
	}

	for _, action := range actions {
		if action == "" {
			t.Error("action constant should not be empty")
		}
	}
}

func TestAggregatePeriodConstants(t *testing.T) {
	periods := []AggregatePeriod{
		AggregateHourly,
		AggregateDaily,
		AggregateWeekly,
		AggregateMonthly,
	}

	for _, period := range periods {
		if period == "" {
			t.Error("aggregate period constant should not be empty")
		}
	}
}

func TestUsageSummaryStruct(t *testing.T) {
	summary := UsageSummary{
		TotalCostUSD:   100.50,
		TotalTokensIn:  5000,
		TotalTokensOut: 2500,
		TotalRequests:  10,
		PeriodStart:    time.Now().Add(-24 * time.Hour),
		PeriodEnd:      time.Now(),
	}

	if summary.TotalCostUSD != 100.50 {
		t.Errorf("TotalCostUSD = %v, want 100.50", summary.TotalCostUSD)
	}

	if summary.TotalTokensIn != 5000 {
		t.Errorf("TotalTokensIn = %v, want 5000", summary.TotalTokensIn)
	}
}

func TestBudgetStatusStruct(t *testing.T) {
	budget := &Budget{
		ID:       "test",
		Name:     "Test",
		LimitUSD: 100,
	}

	status := BudgetStatus{
		Budget:       budget,
		UsedUSD:      75.0,
		RemainingUSD: 25.0,
		Percentage:   75.0,
		IsExceeded:   false,
		IsBlocked:    false,
	}

	if status.Percentage != 75.0 {
		t.Errorf("Percentage = %v, want 75", status.Percentage)
	}

	if status.IsExceeded {
		t.Error("should not be exceeded at 75%")
	}
}

func TestBudgetDecisionStruct(t *testing.T) {
	decision := BudgetDecision{
		Allowed:    false,
		Action:     OnExceedBlock,
		BudgetID:   "budget-1",
		BudgetName: "Test Budget",
		UsedUSD:    150.0,
		LimitUSD:   100.0,
		Percentage: 150.0,
		Message:    "Budget exceeded",
	}

	if decision.Allowed {
		t.Error("should not be allowed when blocked")
	}

	if decision.Action != OnExceedBlock {
		t.Errorf("Action = %v, want %v", decision.Action, OnExceedBlock)
	}
}

func TestUsageBreakdownStruct(t *testing.T) {
	breakdown := UsageBreakdown{
		GroupBy: "provider",
		Items: []UsageBreakdownItem{
			{
				GroupBy:      "provider",
				GroupValue:   "anthropic",
				CostUSD:      50.0,
				TokensIn:     2500,
				TokensOut:    1000,
				RequestCount: 5,
				Percentage:   50.0,
			},
			{
				GroupBy:      "provider",
				GroupValue:   "openai",
				CostUSD:      50.0,
				TokensIn:     3000,
				TokensOut:    1500,
				RequestCount: 8,
				Percentage:   50.0,
			},
		},
		StartTime: time.Now().Add(-7 * 24 * time.Hour),
		EndTime:   time.Now(),
	}

	if len(breakdown.Items) != 2 {
		t.Errorf("len(Items) = %v, want 2", len(breakdown.Items))
	}

	if breakdown.GroupBy != "provider" {
		t.Errorf("GroupBy = %v, want provider", breakdown.GroupBy)
	}
}

func TestBudgetAlertStruct(t *testing.T) {
	now := time.Now().UTC()
	alert := BudgetAlert{
		ID:                1,
		BudgetID:          "budget-1",
		Threshold:         80,
		PercentageReached: 85.5,
		AmountUSD:         85.50,
		AlertType:         AlertTypeThresholdReached,
		Message:           "Budget at 85.5%",
		CreatedAt:         now,
		Acknowledged:      false,
	}

	if alert.AlertType != AlertTypeThresholdReached {
		t.Errorf("AlertType = %v, want %v", alert.AlertType, AlertTypeThresholdReached)
	}

	if alert.Acknowledged {
		t.Error("should not be acknowledged by default")
	}
}

func TestListBudgetsOptionsStruct(t *testing.T) {
	enabled := true
	opts := ListBudgetsOptions{
		OrgID:    "org-1",
		TenantID: "tenant-1",
		Scope:    ScopeOrganization,
		ScopeID:  "",
		Enabled:  &enabled,
		Limit:    50,
		Offset:   0,
	}

	if opts.OrgID != "org-1" {
		t.Errorf("OrgID = %v, want org-1", opts.OrgID)
	}

	if *opts.Enabled != true {
		t.Error("Enabled should be true")
	}
}

func TestUsageQueryOptionsStruct(t *testing.T) {
	now := time.Now().UTC()
	opts := UsageQueryOptions{
		OrgID:     "org-1",
		TenantID:  "tenant-1",
		TeamID:    "team-1",
		AgentID:   "agent-1",
		Provider:  "anthropic",
		Model:     "claude-sonnet-4",
		Period:    "monthly",
		StartTime: now.Add(-30 * 24 * time.Hour),
		EndTime:   now,
		Limit:     100,
		Offset:    0,
	}

	if opts.Provider != "anthropic" {
		t.Errorf("Provider = %v, want anthropic", opts.Provider)
	}

	if opts.Period != "monthly" {
		t.Errorf("Period = %v, want monthly", opts.Period)
	}
}

func TestUsageAggregateStruct(t *testing.T) {
	now := time.Now().UTC()
	agg := UsageAggregate{
		ID:             1,
		Scope:          "provider",
		ScopeID:        "anthropic",
		Period:         AggregateDaily,
		PeriodStart:    now.Truncate(24 * time.Hour),
		TotalCostUSD:   25.50,
		TotalTokensIn:  10000,
		TotalTokensOut: 5000,
		RequestCount:   20,
		OrgID:          "org-1",
		TenantID:       "tenant-1",
		UpdatedAt:      now,
	}

	if agg.Period != AggregateDaily {
		t.Errorf("Period = %v, want %v", agg.Period, AggregateDaily)
	}

	if agg.RequestCount != 20 {
		t.Errorf("RequestCount = %v, want 20", agg.RequestCount)
	}
}

func TestNewBudget(t *testing.T) {
	budget := NewBudget("test-id", "Test Budget", 100.0, PeriodMonthly)

	if budget.ID != "test-id" {
		t.Errorf("ID = %v, want test-id", budget.ID)
	}
	if budget.Name != "Test Budget" {
		t.Errorf("Name = %v, want Test Budget", budget.Name)
	}
	if budget.LimitUSD != 100.0 {
		t.Errorf("LimitUSD = %v, want 100", budget.LimitUSD)
	}
	if budget.Period != PeriodMonthly {
		t.Errorf("Period = %v, want %v", budget.Period, PeriodMonthly)
	}
	if budget.Scope != ScopeOrganization {
		t.Errorf("Scope = %v, want %v", budget.Scope, ScopeOrganization)
	}
	if budget.OnExceed != OnExceedWarn {
		t.Errorf("OnExceed = %v, want %v", budget.OnExceed, OnExceedWarn)
	}
	if !budget.Enabled {
		t.Error("Enabled should be true by default")
	}
	if len(budget.AlertThresholds) != 3 {
		t.Errorf("AlertThresholds length = %v, want 3", len(budget.AlertThresholds))
	}
}

func TestNewUsageRecord(t *testing.T) {
	record := NewUsageRecord("req-123", "anthropic", "claude-sonnet-4", 1000, 500, 0.015)

	if record.RequestID != "req-123" {
		t.Errorf("RequestID = %v, want req-123", record.RequestID)
	}
	if record.Provider != "anthropic" {
		t.Errorf("Provider = %v, want anthropic", record.Provider)
	}
	if record.Model != "claude-sonnet-4" {
		t.Errorf("Model = %v, want claude-sonnet-4", record.Model)
	}
	if record.TokensIn != 1000 {
		t.Errorf("TokensIn = %v, want 1000", record.TokensIn)
	}
	if record.TokensOut != 500 {
		t.Errorf("TokensOut = %v, want 500", record.TokensOut)
	}
	if record.CostUSD != 0.015 {
		t.Errorf("CostUSD = %v, want 0.015", record.CostUSD)
	}
	if record.Timestamp.IsZero() {
		t.Error("Timestamp should be set")
	}
}

func TestMarshalUnmarshalAlertThresholds(t *testing.T) {
	budget := &Budget{
		AlertThresholds: []int{25, 50, 75, 100},
	}

	// Marshal
	data, err := budget.MarshalAlertThresholds()
	if err != nil {
		t.Fatalf("MarshalAlertThresholds() error = %v", err)
	}

	// Verify JSON
	expected := "[25,50,75,100]"
	if string(data) != expected {
		t.Errorf("MarshalAlertThresholds() = %v, want %v", string(data), expected)
	}

	// Unmarshal into new budget
	budget2 := &Budget{}
	err = budget2.UnmarshalAlertThresholds(data)
	if err != nil {
		t.Fatalf("UnmarshalAlertThresholds() error = %v", err)
	}

	if len(budget2.AlertThresholds) != 4 {
		t.Errorf("AlertThresholds length = %v, want 4", len(budget2.AlertThresholds))
	}
	if budget2.AlertThresholds[0] != 25 {
		t.Errorf("AlertThresholds[0] = %v, want 25", budget2.AlertThresholds[0])
	}
}

func TestValidateAllScopes(t *testing.T) {
	scopes := []BudgetScope{
		ScopeOrganization,
		ScopeTeam,
		ScopeAgent,
		ScopeWorkflow,
		ScopeUser,
	}

	for _, scope := range scopes {
		budget := Budget{
			ID:       "test-" + string(scope),
			Name:     "Test " + string(scope),
			Scope:    scope,
			LimitUSD: 100.0,
			Period:   PeriodMonthly,
		}
		err := budget.Validate()
		if err != nil {
			t.Errorf("Validate() failed for scope %v: %v", scope, err)
		}
	}
}

func TestValidateAllPeriods(t *testing.T) {
	periods := []BudgetPeriod{
		PeriodDaily,
		PeriodWeekly,
		PeriodMonthly,
		PeriodQuarterly,
		PeriodYearly,
	}

	for _, period := range periods {
		budget := Budget{
			ID:       "test-" + string(period),
			Name:     "Test " + string(period),
			Scope:    ScopeOrganization,
			LimitUSD: 100.0,
			Period:   period,
		}
		err := budget.Validate()
		if err != nil {
			t.Errorf("Validate() failed for period %v: %v", period, err)
		}
	}
}

func TestValidateInvalidScope(t *testing.T) {
	budget := Budget{
		ID:       "invalid-scope",
		Name:     "Invalid Scope",
		Scope:    BudgetScope("invalid"),
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}
	err := budget.Validate()
	if err != ErrInvalidBudgetScope {
		t.Errorf("Validate() error = %v, want %v", err, ErrInvalidBudgetScope)
	}
}

func TestValidateInvalidPeriod(t *testing.T) {
	budget := Budget{
		ID:       "invalid-period",
		Name:     "Invalid Period",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   BudgetPeriod("invalid"),
	}
	err := budget.Validate()
	if err != ErrInvalidBudgetPeriod {
		t.Errorf("Validate() error = %v, want %v", err, ErrInvalidBudgetPeriod)
	}
}
