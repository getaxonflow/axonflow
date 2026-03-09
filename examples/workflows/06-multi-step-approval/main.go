// Multi-Step Approval Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates a multi-level approval workflow: Manager -> Director -> Finance.
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v4"
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
	fmt.Println("Multi-Step Approval Workflow - Go")
	fmt.Println("==================================")
	fmt.Println()

	// Create AxonFlow client (no auth required for community mode)
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
	})

	// Test 1: Health check
	fmt.Println("Test 1: Health Check")
	fmt.Println("--------------------")
	err := client.HealthCheck()
	assertCheck(err == nil, "Agent is healthy")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Purchase request details
	amount := 15000.00
	item := "10 Dell PowerEdge R750 servers for production deployment"

	fmt.Println("Starting multi-step approval workflow for capital expenditure...")
	fmt.Printf("   Amount: $%.2f\n", amount)
	fmt.Printf("   Item: %s\n", truncate(item, 60))
	fmt.Println()

	approvalSteps := 0

	// Test 2: Manager Approval
	fmt.Println("Test 2: Manager Approval")
	fmt.Println("------------------------")
	managerQuery := fmt.Sprintf("As a manager, would you approve a purchase request for $%.2f to buy: %s? "+
		"Consider budget, necessity, and timing. Respond with APPROVED or REJECTED and brief reasoning.",
		amount, item)
	fmt.Printf("   Query: %s\n", truncate(managerQuery, 70))

	managerResp, err := client.ProxyLLMCall("user-123", managerQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Manager approval request does not return error")
	if err == nil {
		assertCheck(managerResp.Success, "Manager approval response is successful")
		assertCheck(managerResp.Data != nil, "Manager response has data")
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", managerResp.Data), 80))

		// Check for approval (LLM typically responds with APPROVED)
		if strings.Contains(strings.ToUpper(fmt.Sprintf("%v", managerResp.Data)), "APPROVED") {
			approvalSteps++
			fmt.Println("   Status: Manager approval granted")
		} else {
			fmt.Println("   Status: Manager decision received")
			approvalSteps++ // Count as step completed even if not approved
		}
	}
	fmt.Println()

	// Test 3: Director Approval (for amounts > $10K)
	fmt.Println("Test 3: Director Approval (amount > $10K)")
	fmt.Println("-----------------------------------------")
	if amount > 10000 {
		directorQuery := fmt.Sprintf("As a Director, review this purchase: $%.2f for %s. "+
			"Consider strategic alignment and ROI. Respond with APPROVED or REJECTED and reasoning.",
			amount, item)
		fmt.Printf("   Query: %s\n", truncate(directorQuery, 70))

		directorResp, err := client.ProxyLLMCall("user-123", directorQuery, "chat", map[string]interface{}{"provider": "openai"})
		assertCheck(err == nil, "Director approval request does not return error")
		if err == nil {
			assertCheck(directorResp.Success, "Director approval response is successful")
			assertCheck(directorResp.Data != nil, "Director response has data")
			fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", directorResp.Data), 80))

			if strings.Contains(strings.ToUpper(fmt.Sprintf("%v", directorResp.Data)), "APPROVED") {
				approvalSteps++
				fmt.Println("   Status: Director approval granted")
			} else {
				fmt.Println("   Status: Director decision received")
				approvalSteps++ // Count as step completed
			}
		}
	} else {
		fmt.Println("   Skipped: Amount < $10,000, director approval not required")
		approvalSteps++ // Count as step completed (skipped)
	}
	fmt.Println()

	// Test 4: Finance Approval (for amounts > $5K)
	fmt.Println("Test 4: Finance Compliance Check (amount > $5K)")
	fmt.Println("------------------------------------------------")
	if amount > 5000 {
		financeQuery := fmt.Sprintf("As Finance team, perform final compliance check on purchase: "+
			"$%.2f for %s. Verify budget availability and compliance with procurement policies. "+
			"Respond with APPROVED or REJECTED and reasoning.",
			amount, item)
		fmt.Printf("   Query: %s\n", truncate(financeQuery, 70))

		financeResp, err := client.ProxyLLMCall("user-123", financeQuery, "chat", map[string]interface{}{"provider": "openai"})
		assertCheck(err == nil, "Finance approval request does not return error")
		if err == nil {
			assertCheck(financeResp.Success, "Finance approval response is successful")
			assertCheck(financeResp.Data != nil, "Finance response has data")
			fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", financeResp.Data), 80))

			if strings.Contains(strings.ToUpper(fmt.Sprintf("%v", financeResp.Data)), "APPROVED") {
				approvalSteps++
				fmt.Println("   Status: Finance approval granted")
			} else {
				fmt.Println("   Status: Finance decision received")
				approvalSteps++ // Count as step completed
			}
		}
	} else {
		fmt.Println("   Skipped: Amount < $5,000, finance approval not required")
		approvalSteps++ // Count as step completed (skipped)
	}
	fmt.Println()

	// Verify workflow completed all steps
	assertCheck(approvalSteps == 3, fmt.Sprintf("All 3 approval steps completed (got %d)", approvalSteps))

	// Summary
	fmt.Println("==================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Printf("Approval workflow: Manager -> Director -> Finance (%d steps)\n", approvalSteps)
		os.Exit(0)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
