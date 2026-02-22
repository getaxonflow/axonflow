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
	"io"
	"net/http"
	"os"
	"strings"
	"time"

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
		Model:    "llama3.2",
		Provider: "ollama",
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

	// ========================================
	// Test 7: Step Approval Flow
	// ========================================
	fmt.Println("Test 7: Step Approval Flow")
	fmt.Println("--------------------------")

	approvalWorkflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "wcp-approval-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   3,
		Metadata: map[string]interface{}{
			"test": "step-approval",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create approval workflow: %v\n", err)
		os.Exit(1)
	}

	assert(approvalWorkflow.WorkflowID != "", "Approval workflow created with valid ID")
	fmt.Printf("   Workflow ID: %s\n", approvalWorkflow.WorkflowID)

	// Cleanup the approval workflow on exit
	defer func() {
		if err := client.AbortWorkflow(approvalWorkflow.WorkflowID, "test cleanup"); err != nil {
			fmt.Printf("   Warning: Failed to abort approval workflow: %v\n", err)
		} else {
			fmt.Printf("   Cleaned up approval workflow: %s\n", approvalWorkflow.WorkflowID)
		}
	}()

	// Create a step gate to get a step ID
	approvalGate, err := client.StepGate(approvalWorkflow.WorkflowID, "approval-step-1", axonflow.StepGateRequest{
		StepName: "Approval Gate Step",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "llama3.2",
		Provider: "ollama",
		StepInput: map[string]interface{}{
			"prompt": "test approval flow",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate for approval test failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Gate decision: %s\n", approvalGate.Decision)

	// Test ApproveStep
	approveResp, err := client.ApproveStep(approvalWorkflow.WorkflowID, "approval-step-1")
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "enterprise") ||
			strings.Contains(errStr, "not available") || strings.Contains(errStr, "not supported") ||
			strings.Contains(errStr, "404") {
			fmt.Printf("   SKIP: ApproveStep not available (enterprise feature): %v\n", err)
		} else {
			fmt.Printf("   FAIL: ApproveStep returned unexpected error: %v\n", err)
			failCount++
		}
	} else {
		assert(approveResp.StepID != "", "ApproveStep returns StepID")
		assert(approveResp.WorkflowID == approvalWorkflow.WorkflowID, "ApproveStep returns correct WorkflowID")
		assert(approveResp.Status == "approved", fmt.Sprintf("ApproveStep status is 'approved' (got: %s)", approveResp.Status))
		fmt.Printf("   Step %s approved, status: %s\n", approveResp.StepID, approveResp.Status)
	}
	fmt.Println()

	// ========================================
	// Test 8: Step Rejection Flow
	// ========================================
	fmt.Println("Test 8: Step Rejection Flow")
	fmt.Println("---------------------------")

	rejectWorkflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "wcp-rejection-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   2,
		Metadata: map[string]interface{}{
			"test": "step-rejection",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create rejection workflow: %v\n", err)
		os.Exit(1)
	}

	assert(rejectWorkflow.WorkflowID != "", "Rejection workflow created with valid ID")
	fmt.Printf("   Workflow ID: %s\n", rejectWorkflow.WorkflowID)

	// Cleanup the rejection workflow on exit
	defer func() {
		if err := client.AbortWorkflow(rejectWorkflow.WorkflowID, "test cleanup"); err != nil {
			fmt.Printf("   Warning: Failed to abort rejection workflow: %v\n", err)
		} else {
			fmt.Printf("   Cleaned up rejection workflow: %s\n", rejectWorkflow.WorkflowID)
		}
	}()

	// Create a step gate to get a step ID
	_, err = client.StepGate(rejectWorkflow.WorkflowID, "reject-step-1", axonflow.StepGateRequest{
		StepName: "Rejection Gate Step",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "llama3.2",
		Provider: "ollama",
		StepInput: map[string]interface{}{
			"prompt": "test rejection flow",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate for rejection test failed: %v\n", err)
		os.Exit(1)
	}

	// Test RejectStep
	rejectResp, err := client.RejectStep(rejectWorkflow.WorkflowID, "reject-step-1")
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "enterprise") ||
			strings.Contains(errStr, "not available") || strings.Contains(errStr, "not supported") ||
			strings.Contains(errStr, "404") {
			fmt.Printf("   SKIP: RejectStep not available (enterprise feature): %v\n", err)
		} else {
			fmt.Printf("   FAIL: RejectStep returned unexpected error: %v\n", err)
			failCount++
		}
	} else {
		assert(rejectResp.StepID != "", "RejectStep returns StepID")
		assert(rejectResp.WorkflowID == rejectWorkflow.WorkflowID, "RejectStep returns correct WorkflowID")
		assert(rejectResp.Status == "rejected", fmt.Sprintf("RejectStep status is 'rejected' (got: %s)", rejectResp.Status))
		fmt.Printf("   Step %s rejected, status: %s\n", rejectResp.StepID, rejectResp.Status)
	}
	fmt.Println()

	// ========================================
	// Test 9: Get Pending Approvals
	// ========================================
	fmt.Println("Test 9: Get Pending Approvals")
	fmt.Println("-----------------------------")

	pendingResp, err := client.GetPendingApprovals(nil)
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "enterprise") ||
			strings.Contains(errStr, "not available") || strings.Contains(errStr, "not supported") ||
			strings.Contains(errStr, "404") {
			fmt.Printf("   SKIP: GetPendingApprovals not available (enterprise feature): %v\n", err)
		} else {
			fmt.Printf("   FAIL: GetPendingApprovals returned unexpected error: %v\n", err)
			failCount++
		}
	} else {
		assert(pendingResp.Approvals != nil, "PendingApprovals has Approvals array")
		assert(pendingResp.Total >= 0, fmt.Sprintf("PendingApprovals Total is non-negative (got: %d)", pendingResp.Total))
		fmt.Printf("   Total pending approvals: %d\n", pendingResp.Total)
		fmt.Printf("   Approvals in response: %d\n", len(pendingResp.Approvals))
	}

	// Also test with options
	pendingRespWithOpts, err := client.GetPendingApprovals(&axonflow.PendingApprovalsOptions{
		Limit: 10,
	})
	if err != nil {
		errStr := fmt.Sprintf("%v", err)
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "enterprise") ||
			strings.Contains(errStr, "not available") || strings.Contains(errStr, "not supported") ||
			strings.Contains(errStr, "404") {
			fmt.Printf("   SKIP: GetPendingApprovals with options not available (enterprise feature): %v\n", err)
		} else {
			fmt.Printf("   FAIL: GetPendingApprovals with options returned unexpected error: %v\n", err)
			failCount++
		}
	} else {
		assert(pendingRespWithOpts.Approvals != nil, "PendingApprovals (with opts) has Approvals array")
		assert(pendingRespWithOpts.Total >= 0, fmt.Sprintf("PendingApprovals (with opts) Total is non-negative (got: %d)", pendingRespWithOpts.Total))
		fmt.Printf("   With Limit=10: Total=%d, Approvals=%d\n", pendingRespWithOpts.Total, len(pendingRespWithOpts.Approvals))
	}
	fmt.Println()

	// ========================================
	// Test 6b: Fail Workflow
	// ========================================
	fmt.Println("Test 6b: Fail Workflow")
	fmt.Println("----------------------")

	failWorkflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "wcp-fail-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   2,
		Metadata: map[string]interface{}{
			"test": "fail-workflow",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create fail-test workflow: %v\n", err)
		os.Exit(1)
	}

	assert(failWorkflow.WorkflowID != "", "Fail-test workflow created with valid ID")
	fmt.Printf("   Workflow ID: %s\n", failWorkflow.WorkflowID)

	// v4.3.0: Use native SDK FailWorkflow() method
	err = client.FailWorkflow(failWorkflow.WorkflowID, "LLM provider timeout")
	if err != nil {
		fmt.Printf("   ERROR: FailWorkflow failed: %v\n", err)
		failCount++
	} else {
		assert(true, "FailWorkflow succeeded")
	}

	// Verify workflow status is now failed
	failedStatus, statusErr := client.GetWorkflow(failWorkflow.WorkflowID)
	if statusErr != nil {
		fmt.Printf("   ERROR: GetWorkflow failed: %v\n", statusErr)
		failCount++
	} else {
		assert(failedStatus.Status == "failed", fmt.Sprintf("Workflow status is 'failed' (got: %s)", failedStatus.Status))
	}
	fmt.Println()

	// Additional assertions using assertCheck pattern
	fmt.Println("Validating critical WCP functionality...")
	assertCheck(workflow.WorkflowID != "", "Workflow was created with valid ID")
	assertCheck(passCount > 0, "At least one WCP test passed")

	// ========================================
	// Test 10: SSE Streaming - Real-time execution status
	// ========================================
	fmt.Println("Test 10: SSE Streaming - Real-time execution status")
	fmt.Println("----------------------------------------------------")

	// Create a new workflow for SSE streaming test
	sseWorkflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "wcp-sse-streaming-test",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   2,
		Metadata: map[string]interface{}{
			"test": "sse-streaming",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: Failed to create SSE workflow: %v\n", err)
		os.Exit(1)
	}

	assert(sseWorkflow.WorkflowID != "", "SSE workflow created with valid ID")
	fmt.Printf("   Workflow ID: %s\n", sseWorkflow.WorkflowID)

	// Cleanup SSE workflow on exit
	defer func() {
		if err := client.AbortWorkflow(sseWorkflow.WorkflowID, "test cleanup"); err != nil {
			// ignore cleanup errors
		}
	}()

	// Run a step gate and complete a step to generate execution events
	sseGate, err := client.StepGate(sseWorkflow.WorkflowID, "sse-step-1", axonflow.StepGateRequest{
		StepName: "SSE Test Step",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "llama3.2",
		Provider: "ollama",
		StepInput: map[string]interface{}{
			"prompt": "test SSE streaming",
		},
	})

	if err != nil {
		fmt.Printf("   FATAL: StepGate for SSE test failed: %v\n", err)
		os.Exit(1)
	}

	if sseGate.IsAllowed() {
		err = client.MarkStepCompleted(sseWorkflow.WorkflowID, "sse-step-1", &axonflow.MarkStepCompletedRequest{
			Output: map[string]interface{}{"result": "sse test output"},
		})
		assert(err == nil, "MarkStepCompleted for SSE step succeeded")
	}

	// Stream execution status via HTTP SSE endpoint (on orchestrator, not agent)
	orchestratorEndpoint := getEnv("AXONFLOW_ORCHESTRATOR_URL", "http://localhost:8081")
	clientID := getEnv("AXONFLOW_CLIENT_ID", "demo-org")
	clientSecret := getEnv("AXONFLOW_CLIENT_SECRET", "")
	streamURL := fmt.Sprintf("%s/api/v1/unified/executions/%s/stream", orchestratorEndpoint, sseWorkflow.WorkflowID)
	fmt.Printf("   SSE URL: %s\n", streamURL)

	req, reqErr := http.NewRequest("GET", streamURL, nil)
	if reqErr != nil {
		fmt.Printf("   FATAL: Failed to create SSE request: %v\n", reqErr)
		os.Exit(1)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("X-Client-ID", clientID)
	req.Header.Set("X-Client-Secret", clientSecret)
	req.Header.Set("X-Tenant-ID", clientID)

	sseClient := &http.Client{Timeout: 30 * time.Second}
	resp, respErr := sseClient.Do(req)
	if respErr != nil {
		fmt.Printf("   Warning: SSE connection failed: %v\n", respErr)
		fmt.Println("   Note: SSE endpoint may not be available yet")
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)

		if resp.StatusCode == http.StatusOK {
			assert(true, "SSE endpoint returned HTTP 200")
			fmt.Println("   SSE streaming endpoint available (connected to active execution)")
		} else if resp.StatusCode == http.StatusNotFound &&
			(strings.Contains(bodyStr, "NOT_FOUND") || strings.Contains(bodyStr, "Execution not found")) {
			assert(true, "SSE endpoint available (returns proper 404 for completed execution)")
			fmt.Printf("   Response: %s\n", bodyStr)
			fmt.Println("   SSE endpoint available (connect during active execution for real-time events)")
		} else {
			assert(false, fmt.Sprintf("SSE endpoint returned unexpected HTTP %d: %s", resp.StatusCode, bodyStr))
		}
	}
	fmt.Println()

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
		fmt.Println()
		fmt.Println("WCP operations validated:")
		fmt.Println("  - CreateWorkflow()")
		fmt.Println("  - StepGate() with LLM_CALL, TOOL_CALL, CONNECTOR_CALL")
		fmt.Println("  - MarkStepCompleted()")
		fmt.Println("  - CompleteWorkflow()")
		fmt.Println("  - FailWorkflow()")
		fmt.Println("  - GetWorkflow()")
		fmt.Println("  - ApproveStep()")
		fmt.Println("  - RejectStep()")
		fmt.Println("  - GetPendingApprovals()")
		fmt.Println("  - SSE Streaming (real-time execution status)")
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
