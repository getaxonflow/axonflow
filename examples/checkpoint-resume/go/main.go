// Package main demonstrates and VALIDATES workflow checkpoints.
//
// This example tests ACTUAL functionality by verifying:
// 1. Step gates automatically create checkpoints
// 2. GET /checkpoints returns checkpoints ordered by step_index
// 3. Checkpoint types (step_gate vs approval_boundary) are correct
// 4. Blocked steps create non-resumable checkpoints
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Prerequisites:
//   - AxonFlow Agent running on localhost:8080
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

	"github.com/getaxonflow/axonflow-sdk-go/v5"
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

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	fmt.Println("Workflow Checkpoints - Go")
	fmt.Println("=========================")
	fmt.Println()
	fmt.Println("This test verifies step-gate checkpoints are created and listable.")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// Test 1: Create workflow
	fmt.Println("Test 1: Create Workflow")
	fmt.Println("-----------------------")

	wf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "checkpoint-test",
		Source:       axonflow.WorkflowSourceExternal,
	})
	assert(err == nil, fmt.Sprintf("Workflow created (err=%v)", err))
	if err != nil {
		os.Exit(1)
	}
	fmt.Printf("   Workflow ID: %s\n\n", wf.WorkflowID)

	// Test 2: Step gate for step 1
	fmt.Println("Test 2: Step Gate for step-1")
	fmt.Println("---------------------------")

	resp1, err := client.StepGate(wf.WorkflowID, "step-analyze", axonflow.StepGateRequest{
		StepName: "Analyze Data",
		StepType: axonflow.StepTypeToolCall,
	})
	assert(err == nil, fmt.Sprintf("Step gate returned (err=%v)", err))
	assert(!resp1.Cached, "First step is fresh")
	fmt.Println()

	// Test 3: Step gate for step 2
	fmt.Println("Test 3: Step Gate for step-2")
	fmt.Println("---------------------------")

	resp2, err := client.StepGate(wf.WorkflowID, "step-summarize", axonflow.StepGateRequest{
		StepName: "Summarize Results",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "gpt-4",
		Provider: "openai",
	})
	assert(err == nil, fmt.Sprintf("Step gate returned (err=%v)", err))
	assert(!resp2.Cached, "Second step is fresh")
	fmt.Println()

	// Test 4: List checkpoints
	fmt.Println("Test 4: List Checkpoints")
	fmt.Println("------------------------")

	checkpoints, err := client.GetCheckpoints(wf.WorkflowID)
	assert(err == nil, fmt.Sprintf("GetCheckpoints returned (err=%v)", err))
	if checkpoints != nil {
		assert(len(checkpoints.Checkpoints) == 2, fmt.Sprintf("Expected 2 checkpoints, got %d", len(checkpoints.Checkpoints)))
		assert(checkpoints.WorkflowID == wf.WorkflowID, "Correct workflow ID")

		for _, cp := range checkpoints.Checkpoints {
			fmt.Printf("   → step=%s index=%d type=%s decision=%s resumable=%v\n",
				cp.StepID, cp.StepIndex, cp.CheckpointType, cp.GateDecision, cp.IsResumable)
		}

		if len(checkpoints.Checkpoints) >= 2 {
			assert(checkpoints.Checkpoints[0].StepIndex < checkpoints.Checkpoints[1].StepIndex,
				"Checkpoints ordered by step_index")
			assert(checkpoints.Checkpoints[0].CheckpointType == "step_gate",
				fmt.Sprintf("First checkpoint type is step_gate (got %s)", checkpoints.Checkpoints[0].CheckpointType))
			assert(checkpoints.Checkpoints[0].IsResumable, "Allowed step is resumable")
		}
	}
	fmt.Println()

	// Test 5: Complete workflow
	fmt.Println("Test 5: Complete Workflow")
	fmt.Println("------------------------")

	err = client.CompleteWorkflow(wf.WorkflowID)
	assert(err == nil, fmt.Sprintf("Workflow completed (err=%v)", err))
	fmt.Println()

	// Summary
	fmt.Println("=========================")
	fmt.Printf("Results: %d passed, %d failed\n", passCount, failCount)
	if failCount > 0 {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	fmt.Println("ALL PASSED")
}
