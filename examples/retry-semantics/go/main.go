// Package main demonstrates and VALIDATES execution boundary semantics (#1414).
//
// This example tests ACTUAL functionality by verifying:
// 1. Default retry behavior is idempotent (same step returns cached decision)
// 2. Explicit retry_policy="reevaluate" forces fresh policy evaluation
// 3. Response includes cached (bool) and decision_source ("fresh"/"cached")
// 4. Different steps are evaluated independently
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

	"github.com/getaxonflow/axonflow-sdk-go/v6"
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
	fmt.Println("Execution Boundary Semantics - Go (#1414)")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("This test verifies idempotent retry behavior for WCP step gates.")
	fmt.Println()

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

	wf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "retry-semantics-test",
		Source:       axonflow.WorkflowSourceExternal,
	})
	assert(err == nil, fmt.Sprintf("Workflow created without error (err=%v)", err))
	assert(wf.WorkflowID != "", "Workflow ID is non-empty")
	fmt.Printf("   Workflow ID: %s\n\n", wf.WorkflowID)

	// ========================================
	// Test 2: First step gate call (fresh evaluation)
	// ========================================
	fmt.Println("Test 2: First Step Gate (fresh evaluation)")
	fmt.Println("------------------------------------------")

	resp1, err := client.StepGate(wf.WorkflowID, "step-analyze", axonflow.StepGateRequest{
		StepName: "Analyze Data",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"tool": "data_analyzer",
		},
	})
	assert(err == nil, fmt.Sprintf("Step gate returned without error (err=%v)", err))
	assert(resp1.Decision == axonflow.GateDecisionAllow, fmt.Sprintf("Decision is 'allow' (got %s)", resp1.Decision))
	assert(!resp1.Cached, fmt.Sprintf("First call is NOT cached (cached=%v)", resp1.Cached))
	assert(resp1.DecisionSource == "fresh", fmt.Sprintf("Decision source is 'fresh' (got %s)", resp1.DecisionSource))
	fmt.Println()

	// ========================================
	// Test 3: Same step gate call (idempotent - cached)
	// ========================================
	fmt.Println("Test 3: Same Step Gate Again (default idempotent)")
	fmt.Println("-------------------------------------------------")

	resp2, err := client.StepGate(wf.WorkflowID, "step-analyze", axonflow.StepGateRequest{
		StepName: "Analyze Data",
		StepType: axonflow.StepTypeToolCall,
	})
	assert(err == nil, fmt.Sprintf("Step gate returned without error (err=%v)", err))
	assert(resp2.Decision == axonflow.GateDecisionAllow, fmt.Sprintf("Same decision 'allow' (got %s)", resp2.Decision))
	assert(resp2.Cached, fmt.Sprintf("Second call IS cached (cached=%v)", resp2.Cached))
	assert(resp2.DecisionSource == "cached", fmt.Sprintf("Decision source is 'cached' (got %s)", resp2.DecisionSource))
	fmt.Println()

	// ========================================
	// Test 4: Same step with retry_policy=reevaluate (fresh)
	// ========================================
	fmt.Println("Test 4: Same Step with retry_policy=reevaluate")
	fmt.Println("----------------------------------------------")

	resp3, err := client.StepGate(wf.WorkflowID, "step-analyze", axonflow.StepGateRequest{
		StepName:    "Analyze Data",
		StepType:    axonflow.StepTypeToolCall,
		RetryPolicy: axonflow.RetryPolicyReevaluate,
	})
	assert(err == nil, fmt.Sprintf("Step gate returned without error (err=%v)", err))
	assert(resp3.Decision == axonflow.GateDecisionAllow, fmt.Sprintf("Decision is 'allow' (got %s)", resp3.Decision))
	assert(!resp3.Cached, fmt.Sprintf("Reevaluate is NOT cached (cached=%v)", resp3.Cached))
	assert(resp3.DecisionSource == "fresh", fmt.Sprintf("Decision source is 'fresh' (got %s)", resp3.DecisionSource))
	fmt.Println()

	// ========================================
	// Test 5: Different step is evaluated independently
	// ========================================
	fmt.Println("Test 5: Different Step (independent evaluation)")
	fmt.Println("-----------------------------------------------")

	resp4, err := client.StepGate(wf.WorkflowID, "step-summarize", axonflow.StepGateRequest{
		StepName: "Summarize Results",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "gpt-4",
		Provider: "openai",
	})
	assert(err == nil, fmt.Sprintf("Step gate returned without error (err=%v)", err))
	assert(!resp4.Cached, fmt.Sprintf("New step is NOT cached (cached=%v)", resp4.Cached))
	assert(resp4.DecisionSource == "fresh", fmt.Sprintf("Decision source is 'fresh' (got %s)", resp4.DecisionSource))
	fmt.Println()

	// ========================================
	// Complete workflow
	// ========================================
	fmt.Println("Test 6: Complete Workflow")
	fmt.Println("------------------------")

	err = client.CompleteWorkflow(wf.WorkflowID)
	assert(err == nil, fmt.Sprintf("Workflow completed without error (err=%v)", err))
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println("==========================================")
	fmt.Printf("Results: %d passed, %d failed\n", passCount, failCount)
	if failCount > 0 {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	fmt.Println("ALL PASSED")
}
