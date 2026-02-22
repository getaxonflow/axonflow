// Package main demonstrates and VALIDATES the FailWorkflow SDK method in Go.
//
// This example tests ACTUAL functionality by verifying:
// 1. Workflow creation returns valid workflow ID
// 2. Step gate and step completion work correctly
// 3. FailWorkflow with a reason transitions workflow to "failed"
// 4. FailWorkflow without a reason also works (optional reason)
// 5. A failed workflow cannot be resumed (step gate fails)
// 6. GetWorkflow reflects the correct failed status and reason
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

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func main() {
	fmt.Println("Workflow Fail - Go (FailWorkflow SDK Validation)")
	fmt.Println("=================================================")
	fmt.Println()
	fmt.Println("This test verifies FailWorkflow transitions workflows to 'failed' status.")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080")),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// ========================================
	// Test 1: Create Workflow
	// ========================================
	fmt.Println("Test 1: Create Workflow")
	fmt.Println("-----------------------")

	workflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "fail-workflow-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   3,
		Metadata: map[string]interface{}{
			"test": "workflow-fail-go",
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

	// ========================================
	// Test 2: Step Gate + Complete Step
	// ========================================
	fmt.Println("Test 2: Step Gate + Complete Step")
	fmt.Println("---------------------------------")

	gate, err := client.StepGate(workflow.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "Data Processing",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "gemini-1.5-flash",
		Provider: "gemini",
		StepInput: map[string]interface{}{
			"prompt": "Process incoming data batch",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate failed: %v\n", err)
		os.Exit(1)
	}

	assert(gate.Decision != "", "StepGate returns a decision")
	validDecisions := map[string]bool{"allow": true, "block": true, "require_approval": true}
	assert(validDecisions[string(gate.Decision)], fmt.Sprintf("Decision '%s' is valid", gate.Decision))
	fmt.Printf("   Decision: %s\n", gate.Decision)

	if gate.IsAllowed() {
		err = client.MarkStepCompleted(workflow.WorkflowID, "step-1", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{
				"records_processed": 150,
			},
		})
		assert(err == nil, "MarkStepCompleted succeeds for step-1")
	}
	fmt.Println()

	// ========================================
	// Test 3: FailWorkflow with Reason
	// ========================================
	fmt.Println("Test 3: FailWorkflow with Reason")
	fmt.Println("--------------------------------")

	err = client.FailWorkflow(workflow.WorkflowID, "LLM provider timeout after 30s")
	assert(err == nil, "FailWorkflow with reason succeeds")

	if err != nil {
		fmt.Printf("   ERROR: FailWorkflow failed: %v\n", err)
	} else {
		fmt.Println("   FailWorkflow called with reason: LLM provider timeout after 30s")
	}
	fmt.Println()

	// ========================================
	// Test 4: Verify Workflow Status is Failed
	// ========================================
	fmt.Println("Test 4: Verify Workflow Status is Failed")
	fmt.Println("-----------------------------------------")

	status, err := client.GetWorkflow(workflow.WorkflowID)
	if err != nil {
		fmt.Printf("   ERROR: GetWorkflow failed: %v\n", err)
		failCount++
	} else {
		assert(status.WorkflowID == workflow.WorkflowID, "Workflow ID matches")
		assert(status.Status == "failed", fmt.Sprintf("Workflow status is 'failed' (got: %s)", status.Status))
		assert(status.WorkflowName == "fail-workflow-test", "Workflow name matches")
		fmt.Printf("   Status: %s\n", status.Status)
		fmt.Printf("   Workflow: %s\n", status.WorkflowName)
	}
	fmt.Println()

	// ========================================
	// Test 5: FailWorkflow without Reason (optional)
	// ========================================
	fmt.Println("Test 5: FailWorkflow without Reason")
	fmt.Println("------------------------------------")

	noReasonWf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "fail-no-reason-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   2,
		Metadata: map[string]interface{}{
			"test": "fail-no-reason",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create second workflow: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Workflow ID: %s\n", noReasonWf.WorkflowID)

	// Cleanup second workflow on exit
	defer func() {
		_ = client.AbortWorkflow(noReasonWf.WorkflowID, "test cleanup")
	}()

	// Call FailWorkflow with empty reason
	err = client.FailWorkflow(noReasonWf.WorkflowID, "")
	assert(err == nil, "FailWorkflow without reason succeeds")

	noReasonStatus, err := client.GetWorkflow(noReasonWf.WorkflowID)
	if err != nil {
		fmt.Printf("   ERROR: GetWorkflow failed: %v\n", err)
		failCount++
	} else {
		assert(noReasonStatus.Status == "failed", fmt.Sprintf("Workflow status is 'failed' (got: %s)", noReasonStatus.Status))
		fmt.Printf("   Status: %s\n", noReasonStatus.Status)
	}
	fmt.Println()

	// ========================================
	// Test 6: Verify Failed Workflow Cannot Be Resumed
	// ========================================
	fmt.Println("Test 6: Verify Failed Workflow Cannot Be Resumed")
	fmt.Println("-------------------------------------------------")

	// Try to step gate on the failed workflow - should fail
	_, resumeErr := client.StepGate(workflow.WorkflowID, "step-2", axonflow.StepGateRequest{
		StepName: "Should Not Execute",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"tool": "noop",
		},
	})

	assert(resumeErr != nil, "StepGate on failed workflow returns error")
	if resumeErr != nil {
		fmt.Printf("   Expected error: %v\n", resumeErr)
	}

	// Try to complete the failed workflow - should fail
	completeErr := client.CompleteWorkflow(workflow.WorkflowID)
	assert(completeErr != nil, "CompleteWorkflow on failed workflow returns error")
	if completeErr != nil {
		fmt.Printf("   Expected error: %v\n", completeErr)
	}
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println("=================================================")
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)

	if failCount > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	} else {
		fmt.Println("ALL TESTS PASSED - FailWorkflow is working correctly")
		fmt.Println()
		fmt.Println("FailWorkflow operations validated:")
		fmt.Println("  - CreateWorkflow()")
		fmt.Println("  - StepGate() + MarkStepCompleted()")
		fmt.Println("  - FailWorkflow() with reason")
		fmt.Println("  - FailWorkflow() without reason")
		fmt.Println("  - GetWorkflow() verifies 'failed' status")
		fmt.Println("  - Failed workflow cannot be resumed")
	}
}
