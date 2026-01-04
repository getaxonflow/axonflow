// Package main demonstrates AxonFlow's Execution Replay API using the SDK.
//
// This example shows how to use the AxonFlow Go SDK to:
// 1. List all workflow executions
// 2. Get detailed execution information
// 3. View execution timeline
// 4. Export execution for compliance
//
// The Execution Replay feature captures every step of workflow execution
// for debugging, auditing, and compliance purposes.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Execution Replay API - Go SDK")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize the AxonFlow client
	agentURL := getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")
	orchestratorURL := getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:        agentURL,
		OrchestratorURL: orchestratorURL,
		Debug:           true,
	})

	// 1. List all executions
	fmt.Println("Step 1: List Executions")
	fmt.Println("------------------------")

	listResult, err := client.ListExecutions(&axonflow.ListExecutionsOptions{
		Limit: 10,
	})
	if err != nil {
		fmt.Printf("Error listing executions: %v\n", err)
		return
	}

	fmt.Printf("Total executions: %d\n", listResult.Total)
	if len(listResult.Executions) > 0 {
		fmt.Println("Recent executions:")
		for _, exec := range listResult.Executions {
			fmt.Printf("  - %s: %s (%d/%d steps, status=%s)\n",
				exec.RequestID, exec.WorkflowName, exec.CompletedSteps, exec.TotalSteps, exec.Status)
		}
	} else {
		fmt.Println("No executions found. Run a workflow to generate execution data.")
	}
	fmt.Println()

	// 2. Get specific execution (if available)
	if len(listResult.Executions) > 0 {
		executionID := listResult.Executions[0].RequestID

		fmt.Println("Step 2: Get Execution Details")
		fmt.Println("------------------------------")

		execDetail, err := client.GetExecution(executionID)
		if err != nil {
			fmt.Printf("Error getting execution: %v\n", err)
		} else {
			fmt.Printf("Execution: %s\n", execDetail.Summary.RequestID)
			fmt.Printf("  Workflow: %s\n", execDetail.Summary.WorkflowName)
			fmt.Printf("  Status: %s\n", execDetail.Summary.Status)
			fmt.Printf("  Steps: %d/%d completed\n", execDetail.Summary.CompletedSteps, execDetail.Summary.TotalSteps)
			fmt.Printf("  Total Tokens: %d\n", execDetail.Summary.TotalTokens)
			fmt.Printf("  Total Cost: $%.6f\n", execDetail.Summary.TotalCostUSD)
			fmt.Println("  Steps:")
			for _, step := range execDetail.Steps {
				duration := "in progress"
				if step.DurationMs != nil {
					duration = fmt.Sprintf("%dms", *step.DurationMs)
				}
				fmt.Printf("    [%d] %s: %s (%s)\n", step.StepIndex, step.StepName, step.Status, duration)
			}
		}
		fmt.Println()

		// 3. Get execution timeline
		fmt.Println("Step 3: Get Execution Timeline")
		fmt.Println("-------------------------------")

		timeline, err := client.GetExecutionTimeline(executionID)
		if err != nil {
			fmt.Printf("Error getting timeline: %v\n", err)
		} else {
			fmt.Println("Timeline:")
			for _, entry := range timeline {
				errorFlag := ""
				if entry.HasError {
					errorFlag = " [ERROR]"
				}
				approvalFlag := ""
				if entry.HasApproval {
					approvalFlag = " [APPROVAL]"
				}
				fmt.Printf("  [%d] %s: %s%s%s\n", entry.StepIndex, entry.StepName, entry.Status, errorFlag, approvalFlag)
			}
		}
		fmt.Println()

		// 4. Export execution
		fmt.Println("Step 4: Export Execution")
		fmt.Println("-------------------------")

		exportData, err := client.ExportExecution(executionID, &axonflow.ExecutionExportOptions{
			IncludeInput:  true,
			IncludeOutput: true,
		})
		if err != nil {
			fmt.Printf("Error exporting execution: %v\n", err)
		} else {
			// Pretty print the export (truncated)
			prettyJSON, _ := json.MarshalIndent(exportData, "", "  ")
			output := string(prettyJSON)
			if len(output) > 500 {
				output = output[:500] + "\n  ... (truncated)"
			}
			fmt.Printf("Export (truncated):\n%s\n", output)
		}
		fmt.Println()
	}

	fmt.Println("========================================")
	fmt.Println("Execution Replay Demo Complete!")
	fmt.Println()
	fmt.Println("SDK Methods Used:")
	fmt.Println("  client.ListExecutions()         - List executions")
	fmt.Println("  client.GetExecution(id)         - Get execution details")
	fmt.Println("  client.GetExecutionSteps(id)    - Get execution steps")
	fmt.Println("  client.GetExecutionTimeline(id) - Get execution timeline")
	fmt.Println("  client.ExportExecution(id)      - Export execution")
	fmt.Println("  client.DeleteExecution(id)      - Delete execution")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
