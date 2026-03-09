// Package main demonstrates budget enforcement in AxonFlow.
//
// This example tests that budget limits are ACTUALLY enforced, not just tracked:
// 1. Create a budget with a low limit ($0.01) and on_exceed=block
// 2. Make LLM requests until the budget is exceeded
// 3. Verify that subsequent requests are blocked with HTTP 402
// 4. Verify that BudgetInfo is included in the response
//
// This addresses Issue #1082 - testing actual functionality, not just API availability.
//
// Prerequisites:
// - AxonFlow Agent running on localhost:8080
// - OpenAI or Anthropic API key configured in AxonFlow
//
// Usage:
//
//	export AXONFLOW_AGENT_URL=http://localhost:8080
//	go run main.go
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   ✓ PASS: %s\n", message)
	} else {
		fmt.Printf("   ❌ FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	fmt.Println("AxonFlow Budget Enforcement Test - Go (Issue #1082)")
	fmt.Println("====================================================")
	fmt.Println()
	fmt.Println("This test verifies that budget limits BLOCK requests, not just track them.")
	fmt.Println()

	ctx := context.Background()

	// Initialize AxonFlow client with caching disabled for budget testing
	// Issue #1082: Need to disable cache so each request hits the server
	// Otherwise cached responses bypass budget enforcement
	// Note: Must set TTL to non-zero to prevent SDK defaults from enabling cache
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-client"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		Cache:        axonflow.CacheConfig{Enabled: false, TTL: time.Nanosecond},
		Debug:        true,
	})

	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	budgetID := fmt.Sprintf("enforcement-test-%d", time.Now().Unix())

	// ========================================
	// SETUP: Create a budget with block action
	// ========================================
	fmt.Println("Step 1: Create a budget with on_exceed=block")
	fmt.Println("--------------------------------------------")

	// Create a budget with a very low limit that will be exceeded quickly
	_, err := client.CreateBudget(ctx, axonflow.CreateBudgetRequest{
		ID:              budgetID,
		Name:            "Enforcement Test Budget",
		Scope:           "organization",
		ScopeID:         "demo-org",
		LimitUSD:        0.01, // $0.01 - will be exceeded by first request
		Period:          "daily",
		OnExceed:        "block", // Key: requests should be BLOCKED when exceeded
		AlertThresholds: []int{50, 80, 100},
	})
	if err != nil {
		fmt.Printf("ERROR: Failed to create budget: %v\n", err)
		fmt.Println()
		fmt.Println("This test requires the cost controls API to be available.")
		fmt.Println("Skipping enforcement test.")
		return
	}
	fmt.Printf("   Created budget: %s (limit: $0.01, action: block)\n\n", budgetID)

	// Cleanup on exit
	defer func() {
		fmt.Println("\nStep 4: Cleanup")
		fmt.Println("---------------")
		if err := client.DeleteBudget(ctx, budgetID); err != nil {
			fmt.Printf("   Warning: Failed to delete budget: %v\n", err)
		} else {
			fmt.Printf("   Deleted budget: %s\n", budgetID)
		}
	}()

	// ========================================
	// TEST: Make requests until blocked
	// ========================================
	fmt.Println("Step 2: Make LLM requests until blocked")
	fmt.Println("----------------------------------------")

	var blockedResponse *axonflow.ClientResponse
	maxRequests := 10 // Safety limit

	for i := 1; i <= maxRequests; i++ {
		fmt.Printf("   Request %d: ", i)

		// Use ProxyLLMCall
		response, err := client.ProxyLLMCall(
			userToken,
			"Say hello in one word",
			"chat",
			map[string]interface{}{"provider": "openai"},
		)

		if err != nil {
			// Check if this is a budget block error
			if isBudgetBlockError(err) {
				fmt.Printf("BLOCKED (budget exceeded) ✓\n")
				blockedResponse = response
				break
			}
			fmt.Printf("ERROR: %v\n", err)
			assertCheck(false, fmt.Sprintf("Request %d completed without error", i))
			continue
		}

		if response.Blocked && response.BlockReason != "" {
			fmt.Printf("BLOCKED - %s ✓\n", response.BlockReason)
			blockedResponse = response
			break
		}

		fmt.Printf("OK (tokens used)\n")
	}

	// ========================================
	// VERIFY: Check blocking behavior
	// ========================================
	fmt.Println()
	fmt.Println("Step 3: Verify enforcement")
	fmt.Println("---------------------------")

	// Test 1: Request was blocked
	assertCheck(blockedResponse != nil, "Request was blocked when budget exceeded")

	// Test 2: BudgetInfo is present in response
	if blockedResponse != nil && blockedResponse.BudgetInfo != nil {
		assertCheck(true, "BudgetInfo is included in blocked response")

		// Test 3: BudgetInfo shows exceeded status
		assertCheck(blockedResponse.BudgetInfo.Exceeded, "BudgetInfo.Exceeded is true")

		// Test 4: Percentage >= 100
		assertCheck(blockedResponse.BudgetInfo.Percentage >= 100,
			fmt.Sprintf("BudgetInfo.Percentage is %.1f%% (>= 100%%)", blockedResponse.BudgetInfo.Percentage))

		// Test 5: Action is "block"
		assertCheck(blockedResponse.BudgetInfo.Action == "block",
			fmt.Sprintf("BudgetInfo.Action is '%s' (expected 'block')", blockedResponse.BudgetInfo.Action))
	} else if blockedResponse != nil {
		assertCheck(false, "BudgetInfo is missing from blocked response")
	}

	// Test 6: Verify budget status via API
	status, err := client.GetBudgetStatus(ctx, budgetID)
	if err != nil {
		assertCheck(false, fmt.Sprintf("Could not get budget status: %v", err))
	} else {
		assertCheck(status.IsBlocked || status.IsExceeded,
			fmt.Sprintf("GetBudgetStatus confirms budget exceeded (IsBlocked=%v, IsExceeded=%v)", status.IsBlocked, status.IsExceeded))
	}

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println()
	fmt.Println("====================================================")
	if len(failures) > 0 {
		fmt.Printf("\n❌ %d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		fmt.Println("Budget enforcement has issues - check the failures above.")
		os.Exit(1)
	}
	fmt.Println("Budget enforcement is working correctly!")
}

// isBudgetBlockError checks if an error is a budget block error (HTTP 402)
func isBudgetBlockError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return containsAny(errStr, "402", "Payment Required", "budget", "exceeded")
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) > 0 && len(sub) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
