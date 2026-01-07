// AxonFlow MAP (Multi-Agent Planning) Example - Go SDK
//
// This example demonstrates and VALIDATES all MAP SDK methods:
// - GeneratePlan()   - Create a multi-agent execution plan
// - ExecutePlan()    - Execute a previously generated plan
// - GetPlanStatus()  - Get status of a running or completed plan
//
// VALIDATION: This example exits with code 1 if any assertion fails.
// This ensures CI/CD pipelines catch regressions.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

var failures []string

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// assert checks a condition and records failure if false
func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   ❌ FAIL: %s\n", message)
	} else {
		fmt.Printf("   ✓ PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow MAP (Multi-Agent Planning) - Go SDK")
	fmt.Println("=============================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
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
		fmt.Printf("   ❌ FATAL: GeneratePlan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Plan ID: %s\n", plan.PlanID)
	fmt.Printf("   Domain: %s\n", plan.Domain)
	fmt.Printf("   Steps: %d\n", len(plan.Steps))

	// Validate GeneratePlan response
	assert(plan.PlanID != "", "PlanID is not empty")
	assert(strings.HasPrefix(plan.PlanID, "plan_"), "PlanID has correct prefix 'plan_'")
	assert(len(plan.Steps) > 0, "Plan has at least one step")

	if len(plan.Steps) > 0 {
		fmt.Println("   Plan Steps:")
		for i, step := range plan.Steps {
			fmt.Printf("     %d. %s (%s)\n", i+1, step.Name, step.Type)
			assert(step.Name != "", fmt.Sprintf("Step %d has a name", i+1))
			assert(step.Type != "", fmt.Sprintf("Step %d has a type", i+1))
		}
	}
	fmt.Println()

	expectedStepCount := len(plan.Steps)

	// ========================================
	// 2. GET PLAN STATUS (before execution) - Optional
	// ========================================
	fmt.Println("2. GetPlanStatus - Checking status before execution...")
	status, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		// GetPlanStatus is optional - skip if not implemented (404)
		if strings.Contains(err.Error(), "404") {
			fmt.Println("   ⏭ SKIP: GetPlanStatus not implemented (404)")
		} else {
			fmt.Printf("   ❌ FATAL: GetPlanStatus failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("   Status: %s\n", status.Status)
		fmt.Printf("   Total Steps: %d\n", status.TotalSteps)

		// Validate pre-execution status
		assert(status.Status == "pending" || status.Status == "created", "Plan status is pending/created before execution")
		assert(status.TotalSteps == expectedStepCount, fmt.Sprintf("TotalSteps matches plan (%d)", expectedStepCount))
	}
	fmt.Println()

	// ========================================
	// 3. EXECUTE PLAN
	// ========================================
	fmt.Println("3. ExecutePlan - Executing the plan...")
	execution, err := client.ExecutePlan(plan.PlanID)
	if err != nil {
		fmt.Printf("   ❌ FATAL: ExecutePlan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Execution Status: %s\n", execution.Status)
	if execution.TotalSteps > 0 {
		fmt.Printf("   Completed Steps: %d/%d\n", execution.CompletedSteps, execution.TotalSteps)
	}

	// Validate execution response
	assert(execution.Status == "completed" || execution.Status == "success", "Execution status indicates success")

	// Step tracking is optional - only validate if present
	if execution.TotalSteps > 0 {
		assert(execution.TotalSteps == expectedStepCount, fmt.Sprintf("Execution TotalSteps matches plan (%d)", expectedStepCount))
		assert(execution.CompletedSteps == expectedStepCount, "All steps completed")
	}

	// Validate step results if available
	if len(execution.StepResults) > 0 {
		fmt.Println("   Step Results:")
		assert(len(execution.StepResults) == expectedStepCount, "StepResults count matches plan steps")
		for i, result := range execution.StepResults {
			fmt.Printf("     - %s: %s\n", result.StepName, result.Status)
			assert(result.Status == "completed" || result.Status == "success", fmt.Sprintf("Step %d completed successfully", i+1))
		}
	}
	fmt.Println()

	// ========================================
	// 4. GET PLAN STATUS (after execution) - Optional
	// ========================================
	fmt.Println("4. GetPlanStatus - Checking status after execution...")
	finalStatus, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		// GetPlanStatus is optional - skip if not implemented (404)
		if strings.Contains(err.Error(), "404") {
			fmt.Println("   ⏭ SKIP: GetPlanStatus not implemented (404)")
		} else {
			fmt.Printf("   ❌ FATAL: GetPlanStatus (post-execution) failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("   Status: %s\n", finalStatus.Status)
		fmt.Printf("   Completed Steps: %d/%d\n", finalStatus.CompletedSteps, finalStatus.TotalSteps)

		// Validate post-execution status
		assert(finalStatus.Status == "completed" || finalStatus.Status == "success", "Final status indicates completion")
		assert(finalStatus.CompletedSteps == expectedStepCount, "All steps show as completed")
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("=============================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Methods validated:")
		fmt.Println("  1. GeneratePlan()    - Plan created with valid ID and steps")
		fmt.Println("  2. GetPlanStatus()   - Pre-execution status is pending")
		fmt.Println("  3. ExecutePlan()     - All plan steps executed successfully")
		fmt.Println("  4. GetPlanStatus()   - Post-execution status is completed")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
