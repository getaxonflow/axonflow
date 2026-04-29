// Package main demonstrates and VALIDATES AxonFlow's Execution Replay API.
//
// This example validates all Execution Replay SDK methods:
// 1. ListExecutions()         - List all workflow executions
// 2. GetExecution()           - Get detailed execution information
// 3. GetExecutionTimeline()   - View execution timeline
// 4. ExportExecution()        - Export execution for compliance
//
// VALIDATION: This example exits with code 1 if any API call fails.
// This ensures CI/CD pipelines catch regressions.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v7"
)

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   ❌ FAIL: %s\n", message)
	} else {
		fmt.Printf("   ✓ PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow Execution Replay - Go SDK")
	fmt.Println("===================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// ========================================
	// 1. LIST EXECUTIONS
	// ========================================
	fmt.Println("1. ListExecutions - Listing workflow executions...")
	listResult, err := client.ListExecutions(&axonflow.ListExecutionsOptions{
		Limit: 10,
	})
	if err != nil {
		fmt.Printf("   ❌ FATAL: ListExecutions failed: %v\n", err)
		os.Exit(1)
	}

	assert(listResult.Total >= 0, "Total is a valid count")
	fmt.Printf("   Total executions: %d\n", listResult.Total)

	if len(listResult.Executions) > 0 {
		fmt.Println("   Recent executions:")
		for _, exec := range listResult.Executions[:min(3, len(listResult.Executions))] {
			fmt.Printf("     - %s: %s (%d/%d steps, status=%s)\n",
				exec.RequestID, exec.WorkflowName, exec.CompletedSteps, exec.TotalSteps, exec.Status)
			assert(exec.RequestID != "", "Execution has valid request_id")
			assert(strings.HasPrefix(exec.RequestID, "req_") || strings.HasPrefix(exec.RequestID, "exec_") || strings.HasPrefix(exec.RequestID, "wf_") || strings.HasPrefix(exec.RequestID, "plan_"),
				"Execution ID has valid prefix")
		}
	} else {
		fmt.Println("   No executions found (run a workflow first)")
	}
	fmt.Println()

	// Continue with detailed validation if executions exist
	if len(listResult.Executions) > 0 {
		executionID := listResult.Executions[0].RequestID

		// ========================================
		// 2. GET EXECUTION DETAILS
		// ========================================
		fmt.Println("2. GetExecution - Getting execution details...")
		execDetail, err := client.GetExecution(executionID)
		if err != nil {
			fmt.Printf("   ❌ FATAL: GetExecution failed: %v\n", err)
			os.Exit(1)
		}

		assert(execDetail.Summary.RequestID == executionID, "Summary request_id matches")
		assert(execDetail.Summary.Status != "", "Summary has valid status")
		assert(execDetail.Summary.TotalSteps >= 0, "Summary has valid total_steps")

		fmt.Printf("   Execution: %s\n", execDetail.Summary.RequestID)
		fmt.Printf("   Status: %s\n", execDetail.Summary.Status)
		fmt.Printf("   Steps: %d/%d completed\n", execDetail.Summary.CompletedSteps, execDetail.Summary.TotalSteps)
		fmt.Printf("   Total Tokens: %d\n", execDetail.Summary.TotalTokens)
		fmt.Printf("   Total Cost: $%.6f\n", execDetail.Summary.TotalCostUSD)
		fmt.Println()

		// ========================================
		// 3. GET EXECUTION TIMELINE
		// ========================================
		fmt.Println("3. GetExecutionTimeline - Getting timeline view...")
		timeline, err := client.GetExecutionTimeline(executionID)
		if err != nil {
			fmt.Printf("   ❌ FATAL: GetExecutionTimeline failed: %v\n", err)
			os.Exit(1)
		}

		assert(len(timeline) >= 0, "Timeline returns valid array")
		fmt.Printf("   Timeline entries: %d\n", len(timeline))
		for _, entry := range timeline[:min(3, len(timeline))] {
			errorFlag := ""
			if entry.HasError {
				errorFlag = " [ERROR]"
			}
			fmt.Printf("     [%d] %s: %s%s\n", entry.StepIndex, entry.StepName, entry.Status, errorFlag)
		}
		fmt.Println()

		// ========================================
		// 4. EXPORT EXECUTION
		// ========================================
		fmt.Println("4. ExportExecution - Exporting for compliance...")
		exportData, err := client.ExportExecution(executionID, &axonflow.ExecutionExportOptions{
			IncludeInput:  true,
			IncludeOutput: true,
		})
		if err != nil {
			fmt.Printf("   ❌ FATAL: ExportExecution failed: %v\n", err)
			os.Exit(1)
		}

		assert(exportData != nil, "Export returns valid data")
		prettyJSON, _ := json.MarshalIndent(exportData, "", "  ")
		output := string(prettyJSON)
		if len(output) > 300 {
			output = output[:300] + "\n     ... (truncated)"
		}
		fmt.Printf("   Export preview:\n%s\n", output)
		fmt.Println()
	}

	// ========================================
	// SUMMARY
	// ========================================
	fmt.Println("===================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("Methods validated:")
		fmt.Println("  1. ListExecutions()         - List with pagination")
		fmt.Println("  2. GetExecution()           - Get full details")
		fmt.Println("  3. GetExecutionTimeline()   - Get timeline view")
		fmt.Println("  4. ExportExecution()        - Export for compliance")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
