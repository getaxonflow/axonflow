// AxonFlow MAP Confirm Mode Example - Go SDK (Enterprise Only)
//
// This example demonstrates the confirm execution mode where every step
// requires explicit approval before execution.
//
// REQUIRES: Enterprise license
//
// Flow:
//  1. Generate plan with execution_mode: "confirm"
//  2. Execute plan -> returns "awaiting_approval"
//  3. Resume plan (approve step) -> executes step, pauses at next
//  4. Repeat until all steps complete
//
// Run with: go run main.go
// Prerequisites: docker compose up -d (enterprise mode)
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v4"
)

var failures []string
var testsRun int

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func assert(condition bool, message string) {
	testsRun++
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow MAP Confirm Mode - Go SDK (Enterprise)")
	fmt.Println("=================================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	userToken := getEnv("AXONFLOW_USER_TOKEN", "")
	domain := "travel"

	// ========================================
	// 1. GENERATE PLAN WITH CONFIRM MODE
	// ========================================
	fmt.Println("1. GeneratePlanWithOptions - Confirm mode...")
	opts := axonflow.GeneratePlanOptions{ExecutionMode: axonflow.ExecutionModeConfirm}
	var plan *axonflow.PlanResponse
	var err error
	if userToken != "" {
		plan, err = client.GeneratePlanWithOptions("Search flights, analyze options, and book the best one", domain, opts, userToken)
	} else {
		plan, err = client.GeneratePlanWithOptions("Search flights, analyze options, and book the best one", domain, opts)
	}
	if err != nil {
		// Confirm mode requires enterprise license
		if strings.Contains(strings.ToLower(err.Error()), "enterprise") ||
			strings.Contains(err.Error(), "403") ||
			strings.Contains(strings.ToLower(err.Error()), "license") {
			fmt.Printf("   SKIP: Confirm mode requires enterprise license: %v\n", err)
			fmt.Println()
			fmt.Println("=================================================")
			fmt.Println("Skipped - enterprise license required")
			return
		}
		fmt.Printf("   FATAL: GeneratePlanWithOptions failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Plan ID: %s\n", plan.PlanID)
	fmt.Printf("   Steps: %d\n", len(plan.Steps))

	assert(plan.PlanID != "", "Confirm mode plan generated")
	assert(len(plan.Steps) > 0, "Plan has steps")
	fmt.Println()

	// ========================================
	// 2. EXECUTE PLAN (should return awaiting_approval)
	// ========================================
	fmt.Println("2. ExecutePlan - Should return awaiting_approval...")
	var execution *axonflow.PlanExecutionResponse
	if userToken != "" {
		execution, err = client.ExecutePlan(plan.PlanID, userToken)
	} else {
		execution, err = client.ExecutePlan(plan.PlanID)
	}
	if err != nil {
		fmt.Printf("   FATAL: ExecutePlan failed: %v\n", err)
		os.Exit(1)
	}

	assert(execution.Status == "awaiting_approval", fmt.Sprintf("Status is awaiting_approval (%s)", execution.Status))
	fmt.Println()

	// ========================================
	// 3-N. RESUME LOOP (approve each step)
	// ========================================
	totalSteps := len(plan.Steps)
	for step := 1; step <= totalSteps; step++ {
		fmt.Printf("%d. ResumePlan - Approve step %d...\n", step+2, step)

		resumeResp, resumeErr := client.ResumePlan(plan.PlanID, true)
		if resumeErr != nil {
			fmt.Printf("   FATAL: ResumePlan failed: %v\n", resumeErr)
			os.Exit(1)
		}

		fmt.Printf("   Status: %s\n", resumeResp.Status)

		if resumeResp.Status == "completed" {
			assert(true, fmt.Sprintf("Plan completed after step %d", step))
			fmt.Println()
			break
		} else if resumeResp.Status == "awaiting_approval" {
			assert(true, fmt.Sprintf("Step %d approved, paused at next step", step))
		} else {
			assert(false, fmt.Sprintf("Unexpected status after resume: %s", resumeResp.Status))
		}
		fmt.Println()
	}

	// ========================================
	// FINAL STATUS CHECK
	// ========================================
	fmt.Println("Final Status Check...")
	finalStatus, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Println("   SKIP: GetPlanStatus not implemented (404)")
		} else {
			fmt.Printf("   FATAL: GetPlanStatus failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		assert(finalStatus.Status == "completed" || finalStatus.Status == "success",
			fmt.Sprintf("Final status is completed (%s)", finalStatus.Status))
	}
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("=================================================")
	fmt.Printf("Tests Run: %d\n", testsRun)
	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Confirm mode flow:")
		fmt.Println("  1. GeneratePlanWithOptions (confirm)")
		fmt.Println("  2. ExecutePlan -> awaiting_approval")
		fmt.Println("  3. ResumePlan (approve) x N steps")
		fmt.Println("  4. GetPlanStatus -> completed")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
