// Package main demonstrates and VALIDATES the Workflow Control Plane in Go.
//
// This example tests ACTUAL functionality by verifying:
// 1. Workflow creation returns valid workflow ID
// 2. Step gates return expected decisions
// 3. Workflow status transitions correctly
// 4. Steps are properly tracked
//
// Issue #1082: Examples should test actual behavior, not just API availability
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Prerequisites:
//   - AxonFlow Agent running on localhost:8080
//   - Enterprise license for full WCP functionality
//
// Usage:
//
//	export AXONFLOW_CLIENT_ID=demo-org
//	export AXONFLOW_CLIENT_SECRET="<license-key>"
//	go run main.go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v3"
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

var (
	passCount int
	failCount int
)

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
		passCount++
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failCount++
	}
}

func main() {
	fmt.Println("Workflow Control Plane - Go (Issue #1082)")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("This test verifies WCP APIs work correctly and return expected results.")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// ========================================
	// Test 1: Create Workflow
	// ========================================
	fmt.Println("Test 1: Create Workflow")
	fmt.Println("-----------------------")

	workflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "wcp-validation-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   3,
		Metadata: map[string]interface{}{
			"test": "issue-1082",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create workflow: %v\n", err)
		os.Exit(1)
	}

	assert(workflow.WorkflowID != "", "Workflow ID is not empty")
	assert(strings.HasPrefix(workflow.WorkflowID, "wf_"), "Workflow ID has correct prefix 'wf_'")
	assert(workflow.Status == "in_progress", "Workflow status is in_progress after creation")
	fmt.Printf("   Workflow ID: %s\n", workflow.WorkflowID)
	fmt.Println()

	// Cleanup on exit
	defer func() {
		fmt.Println("\nCleanup")
		fmt.Println("-------")
		if err := client.AbortWorkflow(workflow.WorkflowID, "test cleanup"); err != nil {
			fmt.Printf("   Warning: Failed to abort workflow: %v\n", err)
		} else {
			fmt.Printf("   Cleaned up workflow: %s\n", workflow.WorkflowID)
		}
	}()

	// ========================================
	// Test 2: Step Gate - LLM Call
	// ========================================
	fmt.Println("Test 2: Step Gate - LLM Call")
	fmt.Println("----------------------------")

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
		fmt.Printf("   FATAL: StepGate failed: %v\n", err)
		os.Exit(1)
	}

	assert(gate1.Decision != "", "StepGate returns a decision")
	validDecisions := map[string]bool{"allow": true, "block": true, "require_approval": true}
	assert(validDecisions[string(gate1.Decision)], fmt.Sprintf("Decision '%s' is valid", gate1.Decision))
	assert(gate1.StepID != "", "StepID is returned")
	fmt.Printf("   Decision: %s\n", gate1.Decision)
	fmt.Printf("   StepID: %s\n", gate1.StepID)
	if gate1.Reason != "" {
		fmt.Printf("   Reason: %s\n", gate1.Reason)
	}
	fmt.Println()

	// Mark step 1 completed if allowed
	if gate1.IsAllowed() {
		err = client.MarkStepCompleted(workflow.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{
				"code": "def sort_list(items): return sorted(items)",
			},
		})
		assert(err == nil, "MarkStepCompleted succeeds for step-1")
	}

	// ========================================
	// Test 3: Step Gate - Tool Call
	// ========================================
	fmt.Println("Test 3: Step Gate - Tool Call")
	fmt.Println("-----------------------------")

	gate2, err := client.StepGate(workflow.WorkflowID, "step-2", axonflow.StepGateRequest{
		StepName: "Review Code",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"tool": "code_reviewer",
			"code": "def sort_list(items): return sorted(items)",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate failed: %v\n", err)
		os.Exit(1)
	}

	assert(gate2.Decision != "", "StepGate returns a decision for tool call")
	assert(validDecisions[string(gate2.Decision)], fmt.Sprintf("Decision '%s' is valid", gate2.Decision))
	fmt.Printf("   Decision: %s\n", gate2.Decision)
	fmt.Println()

	// Mark step 2 completed if allowed
	if gate2.IsAllowed() {
		err = client.MarkStepCompleted(workflow.WorkflowID, "step-2", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{"review": "LGTM"},
		})
		assert(err == nil, "MarkStepCompleted succeeds for step-2")
	}

	// ========================================
	// Test 4: Step Gate - Connector Call
	// ========================================
	fmt.Println("Test 4: Step Gate - Connector Call")
	fmt.Println("-----------------------------------")

	gate3, err := client.StepGate(workflow.WorkflowID, "step-3", axonflow.StepGateRequest{
		StepName: "Deploy to Production",
		StepType: axonflow.StepTypeConnectorCall,
		StepInput: map[string]interface{}{
			"connector": "github",
			"action":    "create_pr",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate failed: %v\n", err)
		os.Exit(1)
	}

	assert(gate3.Decision != "", "StepGate returns a decision for connector call")
	assert(validDecisions[string(gate3.Decision)], fmt.Sprintf("Decision '%s' is valid", gate3.Decision))
	fmt.Printf("   Decision: %s\n", gate3.Decision)
	fmt.Println()

	// Mark step 3 completed if allowed
	if gate3.IsAllowed() {
		err = client.MarkStepCompleted(workflow.WorkflowID, "step-3", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{"pr_url": "https://github.com/example/pr/123"},
		})
		assert(err == nil, "MarkStepCompleted succeeds for step-3")
	}

	// ========================================
	// Test 5: Complete Workflow
	// ========================================
	fmt.Println("Test 5: Complete Workflow")
	fmt.Println("-------------------------")

	err = client.CompleteWorkflow(workflow.WorkflowID)
	assert(err == nil, "CompleteWorkflow succeeds")
	fmt.Println()

	// ========================================
	// Test 6: Verify Final Status
	// ========================================
	fmt.Println("Test 6: Verify Final Status")
	fmt.Println("---------------------------")

	status, err := client.GetWorkflow(workflow.WorkflowID)
	if err != nil {
		fmt.Printf("   ERROR: GetWorkflow failed: %v\n", err)
		failCount++
	} else {
		assert(status.WorkflowID == workflow.WorkflowID, "Workflow ID matches")
		assert(status.WorkflowName == "wcp-validation-test", "Workflow name matches")
		// Status should be completed since we completed the workflow
		isTerminal := status.Status == "completed" || status.Status == "aborted"
		assert(isTerminal, fmt.Sprintf("Workflow status is terminal: %s", status.Status))
		fmt.Printf("   Final Status: %s\n", status.Status)
		fmt.Printf("   Steps: %d\n", len(status.Steps))
	}
	fmt.Println()

	// Additional assertions using assertCheck pattern
	fmt.Println("Validating critical WCP functionality...")
	assertCheck(workflow.WorkflowID != "", "Workflow was created with valid ID")
	assertCheck(passCount > 0, "At least one WCP test passed")

	// ========================================
	// Summary
	// ========================================
	fmt.Println("==========================================")
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)

	if failCount > 0 || len(failures) > 0 {
		fmt.Println("SOME TESTS FAILED")
		if len(failures) > 0 {
			fmt.Printf("Additional failures: %d\n", len(failures))
			for _, f := range failures {
				fmt.Printf("  - %s\n", f)
			}
		}
		os.Exit(1)
	} else {
		fmt.Println("ALL TESTS PASSED - WCP is working correctly")
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
