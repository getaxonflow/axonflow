// Package main demonstrates the Workflow Control Plane in Go.
//
// "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."
//
// This example shows how to:
// 1. Create a workflow
// 2. Check step gates before each step
// 3. Mark steps as completed
// 4. Complete the workflow
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	fmt.Println("Workflow Control Plane - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "workflow-control-go"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// Step 1: Create a workflow
	fmt.Println("Step 1: Create Workflow")
	fmt.Println("   Creating 'code-review-pipeline' workflow...")

	workflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "code-review-pipeline",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   3,
		Metadata: map[string]interface{}{
			"example": "workflow-control-go",
		},
	})
	if err != nil {
		fmt.Printf("   ERROR: Failed to create workflow: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("   Workflow created!")
	fmt.Printf("   Workflow ID: %s\n\n", workflow.WorkflowID)

	// Step 2: Check gate for first step (Generate Code - LLM call)
	fmt.Println("Step 2: Check Gate - Generate Code")
	fmt.Println("   Checking if 'generate_code' step is allowed...")

	gate1, err := client.StepGate(workflow.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "Generate Code",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "gpt-4",
		Provider: "openai",
		StepInput: map[string]interface{}{
			"prompt": "Write a Python function to sort a list",
		},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
		abortWorkflow(client, workflow.WorkflowID, "Step gate check failed")
		os.Exit(1)
	}

	fmt.Printf("   Decision: %s\n", gate1.Decision)
	if gate1.Reason != "" {
		fmt.Printf("   Reason: %s\n", gate1.Reason)
	}

	if gate1.IsBlocked() {
		fmt.Println("   Workflow blocked by policy. Aborting...")
		abortWorkflow(client, workflow.WorkflowID, gate1.Reason)
		return
	}

	if gate1.RequiresApproval() {
		fmt.Printf("   Approval URL: %s\n", gate1.ApprovalURL)
		fmt.Println("   (Enterprise feature - approval workflow would be triggered)")
		// In production, you would wait for approval here
	}

	// Mark step 1 completed
	if gate1.IsAllowed() {
		err = client.MarkStepCompleted(workflow.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{
				"code": "def sort_list(items): return sorted(items)",
			},
		})
		if err != nil {
			fmt.Printf("   ERROR marking step completed: %v\n", err)
		} else {
			fmt.Println("   Step completed!")
		}
	}
	fmt.Println()

	// Step 3: Check gate for second step (Review Code - Tool call)
	fmt.Println("Step 3: Check Gate - Review Code")
	fmt.Println("   Checking if 'review_code' step is allowed...")

	gate2, err := client.StepGate(workflow.WorkflowID, "step-2", axonflow.StepGateRequest{
		StepName: "Review Code",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"tool": "code_reviewer",
			"code": "def sort_list(items): return sorted(items)",
		},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Decision: %s\n", gate2.Decision)
		if gate2.IsAllowed() {
			client.MarkStepCompleted(workflow.WorkflowID, "step-2", &axonflow.MarkStepCompletedRequest{
				Output: map[string]interface{}{"review": "LGTM"},
			})
			fmt.Println("   Step completed!")
		}
	}
	fmt.Println()

	// Step 4: Check gate for third step (Deploy - Connector call)
	fmt.Println("Step 4: Check Gate - Deploy")
	fmt.Println("   Checking if 'deploy' step is allowed...")

	gate3, err := client.StepGate(workflow.WorkflowID, "step-3", axonflow.StepGateRequest{
		StepName: "Deploy to Production",
		StepType: axonflow.StepTypeConnectorCall,
		StepInput: map[string]interface{}{
			"connector": "github",
			"action":    "create_pr",
		},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Decision: %s\n", gate3.Decision)
		if gate3.IsAllowed() {
			client.MarkStepCompleted(workflow.WorkflowID, "step-3", &axonflow.MarkStepCompletedRequest{
				Output: map[string]interface{}{"pr_url": "https://github.com/example/pr/123"},
			})
			fmt.Println("   Step completed!")
		}
	}
	fmt.Println()

	// Step 5: Complete the workflow
	fmt.Println("Step 5: Complete Workflow")
	err = client.CompleteWorkflow(workflow.WorkflowID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Println("   Workflow completed!")
	}
	fmt.Println()

	// Step 6: Get final workflow status
	fmt.Println("Step 6: Workflow Status")
	status, err := client.GetWorkflow(workflow.WorkflowID)
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		fmt.Printf("   Workflow: %s\n", status.WorkflowName)
		fmt.Printf("   Status: %s\n", status.Status)
		fmt.Printf("   Steps: %d\n", len(status.Steps))
	}
	fmt.Println()

	fmt.Println("========================================")
	fmt.Println("Workflow Control Plane Example Complete!")
	fmt.Println()
	fmt.Println("Key concepts demonstrated:")
	fmt.Println("  1. Create workflow (register with AxonFlow)")
	fmt.Println("  2. Check step gates (policy evaluation)")
	fmt.Println("  3. Mark steps completed (progress tracking)")
	fmt.Println("  4. Complete workflow (lifecycle management)")
}

func abortWorkflow(client *axonflow.Client, workflowID, reason string) {
	err := client.AbortWorkflow(workflowID, reason)
	if err != nil {
		fmt.Printf("   ERROR aborting workflow: %v\n", err)
	} else {
		fmt.Println("   Workflow aborted.")
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
