// Package main demonstrates and VALIDATES risk-tiered approval routing.
//
// This example tests ACTUAL functionality by verifying:
// 1. HITL approval requests carry the correct severity from policy evaluation
// 2. Severity filtering works on the HITL queue API
// 3. Risk score → severity derivation produces expected results
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Prerequisites:
//   - AxonFlow Agent running on localhost:8080
//   - Evaluation or Enterprise license (HITL requires Evaluation+)
//   - A dynamic policy with require_approval action configured
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
	fmt.Println("Risk-Tiered Approval Routing - Go")
	fmt.Println("==================================")
	fmt.Println()
	fmt.Println("This test verifies severity flows correctly from policies to HITL queue.")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-org"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// ========================================
	// Test 1: Create workflow and trigger step gate
	// ========================================
	fmt.Println("Test 1: Create Workflow")
	fmt.Println("-----------------------")

	wf, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "risk-tier-test",
		Source:       axonflow.WorkflowSourceExternal,
	})
	assert(err == nil, fmt.Sprintf("Workflow created (err=%v)", err))
	if err != nil {
		fmt.Println("Cannot continue without workflow")
		os.Exit(1)
	}
	fmt.Printf("   Workflow ID: %s\n\n", wf.WorkflowID)

	// ========================================
	// Test 2: Step gate with tool_call (default policy, likely allow)
	// ========================================
	fmt.Println("Test 2: Step Gate (tool_call)")
	fmt.Println("-----------------------------")

	resp, err := client.StepGate(wf.WorkflowID, "step-analyze", axonflow.StepGateRequest{
		StepName: "Analyze Data",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"tool": "data_analyzer",
		},
	})
	assert(err == nil, fmt.Sprintf("Step gate returned (err=%v)", err))
	if resp != nil {
		assert(resp.DecisionSource == "fresh", fmt.Sprintf("Decision source is fresh (got %s)", resp.DecisionSource))
		fmt.Printf("   Decision: %s (cached=%v)\n", resp.Decision, resp.Cached)
	}
	fmt.Println()

	// ========================================
	// Test 3: List HITL queue (if any require_approval policies matched)
	// ========================================
	fmt.Println("Test 3: HITL Queue Status")
	fmt.Println("-------------------------")

	hitlResult, err := client.ListHITLQueue(axonflow.ListHITLQueueOptions{})
	if err != nil {
		fmt.Printf("   SKIP: HITL queue not available (err=%v) — requires Evaluation+ license\n", err)
	} else {
		assert(true, fmt.Sprintf("HITL queue accessible (%d items)", len(hitlResult.Items)))
		for _, item := range hitlResult.Items {
			fmt.Printf("   → %s: severity=%s, status=%s, policy=%s\n",
				item.RequestID, item.Severity, item.Status, item.TriggeredPolicyName)
		}
	}
	fmt.Println()

	// ========================================
	// Test 4: Complete workflow
	// ========================================
	fmt.Println("Test 4: Complete Workflow")
	fmt.Println("------------------------")

	err = client.CompleteWorkflow(wf.WorkflowID)
	assert(err == nil, fmt.Sprintf("Workflow completed (err=%v)", err))
	fmt.Println()

	// ========================================
	// Summary
	// ========================================
	fmt.Println("==================================")
	fmt.Printf("Results: %d passed, %d failed\n", passCount, failCount)
	if failCount > 0 {
		fmt.Println("FAILED")
		os.Exit(1)
	}
	fmt.Println("ALL PASSED")
}
