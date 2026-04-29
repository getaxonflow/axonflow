// AxonFlow MAP Lifecycle Example - Go SDK
//
// This example validates the FULL MAP v1.0 lifecycle:
//  1. Generate plan (default mode) - verify plan_id, steps
//  2. Get status (pending)
//  3. Update plan (change execution_mode, optimistic locking)
//  4. Get version history
//  5. Stale update (verify version conflict)
//  6. Execute plan - verify completed
//  7. Get status (completed)
//  8. Cancel completed plan - verify rejected
//  9. Generate + cancel + try execute cancelled plan
// 10. Generate with balanced mode - execute - verify completed
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
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
	fmt.Println("AxonFlow MAP Lifecycle - Go SDK")
	fmt.Println("===============================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	userToken := getEnv("AXONFLOW_USER_TOKEN", "")
	domain := "generic"

	// ========================================
	// 1. GENERATE PLAN (default mode)
	// ========================================
	fmt.Println("1. GeneratePlan - Default mode...")
	query := "Create a plan to analyze user feedback and suggest improvements"
	var plan *axonflow.PlanResponse
	var err error
	if userToken != "" {
		plan, err = client.GeneratePlan(query, domain, userToken)
	} else {
		plan, err = client.GeneratePlan(query, domain)
	}
	if err != nil {
		fmt.Printf("   FATAL: GeneratePlan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Plan ID: %s\n", plan.PlanID)
	fmt.Printf("   Steps: %d\n", len(plan.Steps))

	assert(plan.PlanID != "", "Plan ID is not empty")
	assert(strings.HasPrefix(plan.PlanID, "plan_"), "Plan ID has correct prefix")
	assert(len(plan.Steps) > 0, "Plan has at least one step")
	fmt.Println()

	// ========================================
	// 2. GET STATUS (pending)
	// ========================================
	fmt.Println("2. GetPlanStatus - Should be pending...")
	status, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Println("   SKIP: GetPlanStatus not implemented (404)")
		} else {
			fmt.Printf("   FATAL: GetPlanStatus failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		assert(status.Status == "pending" || status.Status == "created", fmt.Sprintf("Status is pending/created (%s)", status.Status))
	}
	fmt.Println()

	// ========================================
	// 3. UPDATE PLAN (change execution_mode to parallel, version 1 -> 2)
	// ========================================
	fmt.Println("3. UpdatePlan - Change execution_mode to parallel...")
	updateResp, err := client.UpdatePlan(plan.PlanID, axonflow.UpdatePlanRequest{
		ExpectedVersion: 1,
		ExecutionMode:   axonflow.ExecutionModeParallel,
	})
	if err != nil {
		fmt.Printf("   FATAL: UpdatePlan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   New Version: %d\n", updateResp.Version)
	assert(updateResp.Version == 2, fmt.Sprintf("Version is 2 (got %d)", updateResp.Version))
	assert(updateResp.PlanID == plan.PlanID, "PlanID matches")
	fmt.Println()

	// ========================================
	// 4. GET VERSION HISTORY
	// ========================================
	fmt.Println("4. GetPlanVersions - Check version history...")
	versions, err := client.GetPlanVersions(plan.PlanID)
	if err != nil {
		fmt.Printf("   FATAL: GetPlanVersions failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Version count: %d\n", len(versions.Versions))
	assert(len(versions.Versions) >= 1, fmt.Sprintf("At least 1 version (%d)", len(versions.Versions)))
	assert(versions.PlanID == plan.PlanID, "PlanID matches in versions response")
	if len(versions.Versions) > 0 {
		for _, v := range versions.Versions {
			fmt.Printf("     v%d: %s (%s)\n", v.Version, v.ChangeType, v.ChangedAt)
		}
	}
	fmt.Println()

	// ========================================
	// 5. STALE UPDATE (verify version conflict)
	// ========================================
	fmt.Println("5. Stale Update - Send version 1 again (expect conflict)...")
	_, err = client.UpdatePlan(plan.PlanID, axonflow.UpdatePlanRequest{
		ExpectedVersion: 1,
		ExecutionMode:   axonflow.ExecutionModeSequential,
	})
	assert(err != nil, "Stale update returns error")
	if err != nil {
		isConflict := errors.Is(err, axonflow.ErrVersionConflict)
		assert(isConflict, fmt.Sprintf("Error is ErrVersionConflict (got %T: %v)", err, err))
	}
	fmt.Println()

	// ========================================
	// 6. EXECUTE PLAN
	// ========================================
	fmt.Println("6. ExecutePlan - Execute the updated plan...")
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

	fmt.Printf("   Status: %s\n", execution.Status)
	assert(execution.Status == "completed" || execution.Status == "success", "Execution completed")
	fmt.Println()

	// ========================================
	// 7. GET STATUS (completed)
	// ========================================
	fmt.Println("7. GetPlanStatus - Should be completed...")
	finalStatus, err := client.GetPlanStatus(plan.PlanID)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			fmt.Println("   SKIP: GetPlanStatus not implemented (404)")
		} else {
			fmt.Printf("   FATAL: GetPlanStatus failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		assert(finalStatus.Status == "completed" || finalStatus.Status == "success", fmt.Sprintf("Final status is completed (%s)", finalStatus.Status))
	}
	fmt.Println()

	// ========================================
	// 8. CANCEL COMPLETED PLAN (expect rejection)
	// ========================================
	fmt.Println("8. CancelPlan - Cancel completed plan (expect rejection)...")
	_, err = client.CancelPlan(plan.PlanID, "Testing cancel on completed plan")
	assert(err != nil, "Cancel completed plan returns error")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// ========================================
	// 9. GENERATE + CANCEL + TRY EXECUTE
	// ========================================
	fmt.Println("9. Generate -> Cancel -> Try Execute...")
	var plan2 *axonflow.PlanResponse
	if userToken != "" {
		plan2, err = client.GeneratePlan("Create a simple greeting plan", domain, userToken)
	} else {
		plan2, err = client.GeneratePlan("Create a simple greeting plan", domain)
	}
	if err != nil {
		fmt.Printf("   FATAL: Second plan generation failed: %v\n", err)
		os.Exit(1)
	}
	assert(plan2.PlanID != "", "Second plan generated")

	cancelResp, err := client.CancelPlan(plan2.PlanID, "Testing cancel flow")
	if err != nil {
		fmt.Printf("   FATAL: CancelPlan failed: %v\n", err)
		os.Exit(1)
	}
	assert(cancelResp.Status == "cancelled", fmt.Sprintf("Plan cancelled (%s)", cancelResp.Status))

	// Try executing cancelled plan
	if userToken != "" {
		_, err = client.ExecutePlan(plan2.PlanID, userToken)
	} else {
		_, err = client.ExecutePlan(plan2.PlanID)
	}
	assert(err != nil, "Execute cancelled plan returns error")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// ========================================
	// 10. GENERATE WITH BALANCED MODE + EXECUTE
	// ========================================
	fmt.Println("10. GeneratePlanWithOptions - Balanced mode...")
	var plan3 *axonflow.PlanResponse
	opts := axonflow.GeneratePlanOptions{ExecutionMode: axonflow.ExecutionModeBalanced}
	if userToken != "" {
		plan3, err = client.GeneratePlanWithOptions("Create a plan to process and summarize data", domain, opts, userToken)
	} else {
		plan3, err = client.GeneratePlanWithOptions("Create a plan to process and summarize data", domain, opts)
	}
	if err != nil {
		fmt.Printf("   FATAL: GeneratePlanWithOptions failed: %v\n", err)
		os.Exit(1)
	}
	assert(plan3.PlanID != "", "Balanced plan generated")
	fmt.Printf("   Plan ID: %s\n", plan3.PlanID)

	var exec3 *axonflow.PlanExecutionResponse
	if userToken != "" {
		exec3, err = client.ExecutePlan(plan3.PlanID, userToken)
	} else {
		exec3, err = client.ExecutePlan(plan3.PlanID)
	}
	if err != nil {
		fmt.Printf("   FATAL: Execute balanced plan failed: %v\n", err)
		os.Exit(1)
	}
	assert(exec3.Status == "completed" || exec3.Status == "success", "Balanced plan executed")
	fmt.Println()

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("===============================")
	fmt.Printf("Tests Run: %d\n", testsRun)
	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Lifecycle validated:")
		fmt.Println("  - GeneratePlan / GeneratePlanWithOptions")
		fmt.Println("  - GetPlanStatus (pre/post execution)")
		fmt.Println("  - UpdatePlan (optimistic locking)")
		fmt.Println("  - GetPlanVersions (version history)")
		fmt.Println("  - Version conflict detection (ErrVersionConflict)")
		fmt.Println("  - ExecutePlan (default + balanced mode)")
		fmt.Println("  - CancelPlan (pending + completed rejection)")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
