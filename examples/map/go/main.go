// AxonFlow MAP (Multi-Agent Planning) Example - Go SDK (Comprehensive)
//
// This example demonstrates ALL MAP SDK methods:
// - GeneratePlan()   - Create a multi-agent execution plan
// - ExecutePlan()    - Execute a previously generated plan
// - GetPlanStatus()  - Get status of a running or completed plan
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	fmt.Println("AxonFlow MAP (Multi-Agent Planning) - Go SDK")
	fmt.Println("=============================================")
	fmt.Println()

	// Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
	// The Agent proxies orchestrator routes internally.
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        true,
	})

	query := "Create a brief plan to greet a new user and ask how to help them"
	domain := "generic"

	fmt.Printf("Query: %s\n", query)
	fmt.Printf("Domain: %s\n", domain)
	fmt.Println("---------------------------------------------")
	fmt.Println()

	// ========================================
	// 1. GENERATE PLAN
	// ========================================
	fmt.Println("1. GeneratePlan - Creating a multi-agent plan...")
	plan, err := client.GeneratePlan(query, domain)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Plan ID: %s\n", plan.PlanID)
	fmt.Printf("   Domain: %s\n", plan.Domain)
	fmt.Printf("   Steps: %d\n", len(plan.Steps))
	fmt.Println("   Plan Steps:")
	for i, step := range plan.Steps {
		fmt.Printf("     %d. %s (%s)\n", i+1, step.Name, step.Type)
	}
	fmt.Println()

	// ========================================
	// 2. GET PLAN STATUS (before execution)
	// ========================================
	fmt.Println("2. GetPlanStatus - Checking status before execution...")
	status, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		fmt.Printf("   Note: GetPlanStatus may require execution first: %v\n", err)
	} else {
		fmt.Printf("   Status: %s\n", status.Status)
		fmt.Printf("   Completed Steps: %d/%d\n", status.CompletedSteps, status.TotalSteps)
	}
	fmt.Println()

	// ========================================
	// 3. EXECUTE PLAN
	// ========================================
	fmt.Println("3. ExecutePlan - Executing the plan...")
	execution, err := client.ExecutePlan(plan.PlanID)
	if err != nil {
		fmt.Printf("   Note: ExecutePlan may require LLM provider: %v\n", err)
	} else {
		fmt.Printf("   Execution Status: %s\n", execution.Status)
		fmt.Printf("   Completed Steps: %d/%d\n", execution.CompletedSteps, execution.TotalSteps)

		if len(execution.StepResults) > 0 {
			fmt.Println("   Results:")
			for i, result := range execution.StepResults {
				if i >= 3 {
					break
				}
				fmt.Printf("     - %s: %s\n", result.StepName, result.Status)
			}
		}
	}
	fmt.Println()

	// ========================================
	// 4. GET PLAN STATUS (after execution)
	// ========================================
	fmt.Println("4. GetPlanStatus - Checking status after execution...")
	time.Sleep(1 * time.Second) // Brief wait for execution

	finalStatus, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		fmt.Printf("   Note: Status check may fail if plan was not executed: %v\n", err)
	} else {
		fmt.Printf("   Status: %s\n", finalStatus.Status)
		fmt.Printf("   Completed Steps: %d/%d\n", finalStatus.CompletedSteps, finalStatus.TotalSteps)

		if finalStatus.Duration != "" {
			fmt.Printf("   Duration: %s\n", finalStatus.Duration)
		}
	}
	fmt.Println()

	fmt.Println("=============================================")
	fmt.Println("All 3 MAP SDK methods demonstrated!")
	fmt.Println()
	fmt.Println("Methods tested:")
	fmt.Println("  1. GeneratePlan()    - Create execution plan")
	fmt.Println("  2. GetPlanStatus()   - Check plan status (before)")
	fmt.Println("  3. ExecutePlan()     - Execute the plan")
	fmt.Println("  4. GetPlanStatus()   - Check plan status (after)")
}
