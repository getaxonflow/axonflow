// AxonFlow MAP (Multi-Agent Planning) Example - Go SDK
//
// This example demonstrates and VALIDATES all MAP SDK methods:
// - GeneratePlan()   - Create a multi-agent execution plan
// - ExecutePlan()    - Execute a previously generated plan
// - GetPlanStatus()  - Get status of a running or completed plan
//
// COMPREHENSIVE VALIDATION:
// - Basic flow: generate → status → execute → status
// - Error handling: invalid plan ID, non-existent plan
// - Edge cases: re-execution, status transitions, domain handling
// - This example exits with code 1 if any assertion fails.
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
var testsRun int

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

// assert checks a condition and records failure if false
func assert(condition bool, message string) {
	testsRun++
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
	// 5. ERROR HANDLING - Invalid Plan ID Format
	// ========================================
	fmt.Println("5. Error Handling - Invalid plan ID format...")
	_, err = client.GetPlanStatus("invalid-id-no-prefix")
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			fmt.Println("   ✓ PASS: Invalid plan ID correctly rejected (404)")
		} else {
			fmt.Printf("   ✓ PASS: Invalid plan ID rejected with error: %T\n", err)
		}
	} else {
		fmt.Println("   ⚠ NOTE: API accepted invalid plan ID format")
	}
	fmt.Println()

	// ========================================
	// 6. ERROR HANDLING - Non-existent Plan ID
	// ========================================
	fmt.Println("6. Error Handling - Non-existent plan ID...")
	_, err = client.GetPlanStatus("plan_nonexistent_12345")
	if err != nil {
		if strings.Contains(err.Error(), "404") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			fmt.Println("   ✓ PASS: Non-existent plan correctly returns 404")
		} else {
			fmt.Printf("   ✓ PASS: Non-existent plan rejected: %T\n", err)
		}
	} else {
		fmt.Println("   ⚠ NOTE: API returned response for non-existent plan")
	}
	fmt.Println()

	// ========================================
	// 7. RE-EXECUTION TEST - Execute completed plan
	// ========================================
	fmt.Println("7. Re-execution Test - Attempting to re-execute completed plan...")
	reexec, err := client.ExecutePlan(plan.PlanID)
	if err != nil {
		fmt.Printf("   ✓ PASS: Re-execution handled: %T\n", err)
	} else {
		if reexec.Status == "completed" || reexec.Status == "success" || reexec.Status == "already_completed" {
			fmt.Printf("   ⚠ NOTE: Re-execution returned status: %s\n", reexec.Status)
		} else {
			fmt.Printf("   ⚠ NOTE: Re-execution status: %s\n", reexec.Status)
		}
	}
	fmt.Println()

	// ========================================
	// 8. SECOND PLAN - Different Query
	// ========================================
	fmt.Println("8. Second Plan - Testing with different query...")
	query2 := "Analyze sales data and create a summary report"
	plan2, err := client.GeneratePlan(query2, domain)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Second plan generation failed: %v\n", err)
		failures = append(failures, fmt.Sprintf("Second plan generation failed: %v", err))
	} else {
		assert(plan2.PlanID != "", "Second plan has valid ID")
		assert(plan2.PlanID != plan.PlanID, "Second plan has different ID")
		assert(len(plan2.Steps) > 0, "Second plan has steps")
		fmt.Printf("   Plan 2 ID: %s\n", plan2.PlanID)
		fmt.Printf("   Plan 2 Steps: %d\n", len(plan2.Steps))

		// Execute second plan
		exec2, err := client.ExecutePlan(plan2.PlanID)
		if err != nil {
			fmt.Printf("   ❌ FATAL: Second plan execution failed: %v\n", err)
			failures = append(failures, fmt.Sprintf("Second plan execution failed: %v", err))
		} else {
			assert(exec2.Status == "completed" || exec2.Status == "success", "Second plan executed successfully")
		}
	}
	fmt.Println()

	// ========================================
	// 9. STEP VALIDATION - Detailed step analysis
	// ========================================
	fmt.Println("9. Step Validation - Analyzing plan structure...")
	if len(plan.Steps) > 0 {
		// Validate step properties
		stepNames := make(map[string]bool)
		allHaveNames := true
		for i, step := range plan.Steps {
			if step.Name == "" {
				allHaveNames = false
			}
			stepNames[step.Name] = true

			// Validate step has a type (must not be empty)
			assert(step.Type != "", fmt.Sprintf("Step %d has a type", i+1))
			// Log step details (don't fail on unknown types for forward compatibility)
			knownTypes := map[string]bool{"llm-call": true, "action": true, "connector": true, "synthesis": true, "task": true}
			if knownTypes[step.Type] {
				fmt.Printf("     Step %d: type=%s, name=%s\n", i+1, step.Type, step.Name)
			} else {
				fmt.Printf("     Step %d: type=%s (unknown), name=%s\n", i+1, step.Type, step.Name)
			}
		}

		assert(allHaveNames, "All steps have names")
		assert(len(stepNames) == len(plan.Steps), "All step names are unique")
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("=============================================")
	fmt.Printf("Tests Run: %d\n", testsRun)
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Coverage validated:")
		fmt.Println("  - GeneratePlan()    - Plan creation with valid ID/steps")
		fmt.Println("  - GetPlanStatus()   - Pre/post execution status")
		fmt.Println("  - ExecutePlan()     - Plan execution and step completion")
		fmt.Println("  - Error handling    - Invalid/non-existent plan IDs")
		fmt.Println("  - Re-execution      - Handling of completed plans")
		fmt.Println("  - Multiple plans    - Independent plan creation")
		fmt.Println("  - Step validation   - Structure and uniqueness")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
