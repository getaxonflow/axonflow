// Package main demonstrates cost controls and budget management with AxonFlow SDK.
//
// This example covers ALL cost control SDK methods:
// - Budget: Create, Get, List, Update, Delete
// - Budget Status and Alerts
// - Budget Check (pre-flight)
// - Usage: Summary, Breakdown, Records
// - Pricing
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Cost Controls - Go SDK (Comprehensive)")
	fmt.Println("================================================")
	fmt.Println()

	ctx := context.Background()

	// Create AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:        getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		OrchestratorURL: getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081"),
	})

	budgetID := fmt.Sprintf("demo-budget-go-%d", time.Now().Unix())

	// ========================================
	// BUDGET MANAGEMENT
	// ========================================

	// 1. CreateBudget
	fmt.Println("1. CreateBudget - Creating a monthly budget...")
	createdBudget, err := client.CreateBudget(ctx, axonflow.CreateBudgetRequest{
		ID:              budgetID,
		Name:            "Demo Budget (Go SDK)",
		Scope:           "organization",
		LimitUSD:        100.0,
		Period:          "monthly",
		OnExceed:        "warn",
		AlertThresholds: []int{50, 80, 100},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
		return
	}
	fmt.Printf("   Created: %s (limit: $%.2f/month)\n\n", createdBudget.ID, createdBudget.LimitUSD)

	// 2. GetBudget
	fmt.Println("2. GetBudget - Retrieving budget by ID...")
	retrievedBudget, err := client.GetBudget(ctx, budgetID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Retrieved: %s (scope: %s, period: %s)\n\n", retrievedBudget.ID, retrievedBudget.Scope, retrievedBudget.Period)
	}

	// 3. ListBudgets
	fmt.Println("3. ListBudgets - Listing all budgets...")
	budgetList, err := client.ListBudgets(ctx, axonflow.ListBudgetsOptions{
		Limit: 10,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Found %d budgets (total: %d)\n", len(budgetList.Budgets), budgetList.Total)
		for i, b := range budgetList.Budgets {
			if i >= 3 {
				fmt.Printf("   ... and %d more\n", len(budgetList.Budgets)-3)
				break
			}
			fmt.Printf("   - %s: $%.2f/%s\n", b.ID, b.LimitUSD, b.Period)
		}
		fmt.Println()
	}

	// 4. UpdateBudget
	fmt.Println("4. UpdateBudget - Updating budget limit...")
	retrievedBudget.LimitUSD = 150.0
	retrievedBudget.Name = "Demo Budget (Go SDK) - Updated"
	updatedBudget, err := client.UpdateBudget(ctx, retrievedBudget)
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Updated: %s (new limit: $%.2f)\n\n", updatedBudget.ID, updatedBudget.LimitUSD)
	}

	// ========================================
	// BUDGET STATUS & ALERTS
	// ========================================

	// 5. GetBudgetStatus
	fmt.Println("5. GetBudgetStatus - Checking current budget status...")
	status, err := client.GetBudgetStatus(ctx, budgetID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Used: $%.2f / $%.2f (%.1f%%)\n", status.UsedUSD, status.Budget.LimitUSD, status.Percentage)
		fmt.Printf("   Remaining: $%.2f\n", status.RemainingUSD)
		fmt.Printf("   Exceeded: %v, Blocked: %v\n\n", status.IsExceeded, status.IsBlocked)
	}

	// 6. GetBudgetAlerts
	fmt.Println("6. GetBudgetAlerts - Getting alerts for budget...")
	alerts, err := client.GetBudgetAlerts(ctx, budgetID, 10)
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Found %d alerts\n", alerts.Count)
		for _, a := range alerts.Alerts {
			fmt.Printf("   - [%s] %s (%.1f%% at $%.2f)\n", a.AlertType, a.Message, a.PercentageReached, a.AmountUSD)
		}
		if alerts.Count == 0 {
			fmt.Println("   (no alerts yet)")
		}
		fmt.Println()
	}

	// 7. CheckBudget
	fmt.Println("7. CheckBudget - Pre-flight budget check...")
	decision, err := client.CheckBudget(ctx, axonflow.CheckBudgetRequest{
		OrgID: "demo-org",
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Allowed: %v\n", decision.Allowed)
		if decision.Action != "" {
			fmt.Printf("   Action: %s\n", decision.Action)
		}
		if decision.Message != "" {
			fmt.Printf("   Message: %s\n", decision.Message)
		}
		fmt.Println()
	}

	// ========================================
	// USAGE TRACKING
	// ========================================

	// 8. GetUsageSummary
	fmt.Println("8. GetUsageSummary - Getting usage summary...")
	summary, err := client.GetUsageSummary(ctx, axonflow.UsageQueryOptions{
		Period: "monthly",
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Total Cost: $%.6f\n", summary.TotalCostUSD)
		fmt.Printf("   Total Requests: %d\n", summary.TotalRequests)
		fmt.Printf("   Tokens: %d in, %d out\n", summary.TotalTokensIn, summary.TotalTokensOut)
		fmt.Printf("   Avg Cost/Request: $%.6f\n\n", summary.AverageCostPerRequest)
	}

	// 9. GetUsageBreakdown
	fmt.Println("9. GetUsageBreakdown - Getting usage breakdown by provider...")
	breakdown, err := client.GetUsageBreakdown(ctx, "provider", axonflow.UsageQueryOptions{
		Period: "monthly",
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Breakdown by: %s (total: $%.6f)\n", breakdown.GroupBy, breakdown.TotalCostUSD)
		for _, item := range breakdown.Items {
			fmt.Printf("   - %s: $%.6f (%.1f%%, %d requests)\n", item.GroupValue, item.CostUSD, item.Percentage, item.RequestCount)
		}
		if len(breakdown.Items) == 0 {
			fmt.Println("   (no usage data yet)")
		}
		fmt.Println()
	}

	// 10. ListUsageRecords
	fmt.Println("10. ListUsageRecords - Listing recent usage records...")
	records, err := client.ListUsageRecords(ctx, axonflow.UsageQueryOptions{
		Limit: 5,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Found %d records (showing up to 5)\n", records.Total)
		for _, r := range records.Records {
			fmt.Printf("   - %s/%s: %d tokens, $%.6f\n", r.Provider, r.Model, r.TokensIn+r.TokensOut, r.CostUSD)
		}
		if len(records.Records) == 0 {
			fmt.Println("   (no usage records yet)")
		}
		fmt.Println()
	}

	// ========================================
	// PRICING
	// ========================================

	// 11. GetPricing
	fmt.Println("11. GetPricing - Getting model pricing...")
	pricing, err := client.GetPricing(ctx, "anthropic", "claude-sonnet-4")
	if err != nil {
		fmt.Printf("   ERROR: %v\n\n", err)
	} else {
		fmt.Printf("   Provider: %s\n", pricing.Provider)
		fmt.Printf("   Model: %s\n", pricing.Model)
		fmt.Printf("   Input: $%.4f/1K tokens\n", pricing.Pricing.InputPer1K)
		fmt.Printf("   Output: $%.4f/1K tokens\n\n", pricing.Pricing.OutputPer1K)
	}

	// ========================================
	// CLEANUP
	// ========================================

	// 12. DeleteBudget
	fmt.Println("12. DeleteBudget - Cleaning up...")
	err = client.DeleteBudget(ctx, budgetID)
	if err != nil {
		fmt.Printf("   WARNING: Failed to delete budget: %v\n\n", err)
	} else {
		fmt.Printf("   Deleted budget: %s\n\n", budgetID)
	}

	fmt.Println("================================================")
	fmt.Println("All 12 Cost Control methods tested!")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
