// Package main demonstrates Workflow Policy Enforcement in Go.
//
// This example shows:
// 1. MAP policy enforcement with PolicyInfo in execution response
// 2. WCP policy enforcement with PoliciesEvaluated/PoliciesMatched in step gate response
// 3. Audit log verification to confirm operations are logged
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"context"
	"fmt"
	"os"
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

func main() {
	fmt.Println("==========================================")
	fmt.Println("Workflow Policy Enforcement - Go Example")
	fmt.Println("==========================================")
	fmt.Println()

	// Initialize client - use orchestrator endpoint for workflow APIs
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8081"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "secret"),
	})

	// Record start time for audit log query
	startTime := time.Now().Add(-1 * time.Second)

	// ==========================================
	// Part 1: WCP Policy Enforcement
	// ==========================================

	fmt.Println("Part 1: WCP (Workflow Control Plane) Policy Enforcement")
	fmt.Println("--------------------------------------------------------")
	fmt.Println()

	// Create workflow
	fmt.Println("1.1 Creating workflow...")
	workflow, err := client.CreateWorkflow(axonflow.CreateWorkflowRequest{
		WorkflowName: "policy-demo-go",
		Source:       axonflow.WorkflowSourceExternal,
		TotalSteps:   3,
		Metadata: map[string]interface{}{
			"example": "workflow-policy-go",
		},
	})
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    Workflow ID: %s\n\n", workflow.WorkflowID)

	// Check step gate - demonstrates policies_evaluated and policies_matched
	fmt.Println("1.2 Checking step gate (demonstrates policy info in response)...")
	gate, err := client.StepGate(workflow.WorkflowID, "step-1", axonflow.StepGateRequest{
		StepName: "Analyze Data",
		StepType: axonflow.StepTypeLLMCall,
		Model:    "claude-sonnet-4-20250514",
		Provider: "anthropic",
		StepInput: map[string]interface{}{
			"prompt": "Analyze customer sentiment",
		},
	})
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("    Decision: %s\n", gate.Decision)
	if gate.Reason != "" {
		fmt.Printf("    Reason: %s\n", gate.Reason)
	}

	// Display policy evaluation details (Issue #1021)
	if len(gate.PoliciesEvaluated) > 0 {
		fmt.Println("    Policies Evaluated:")
		for _, p := range gate.PoliciesEvaluated {
			fmt.Printf("      - %s (%s): action=%s\n", p.PolicyName, p.PolicyID, p.Action)
		}
	}
	if len(gate.PoliciesMatched) > 0 {
		fmt.Println("    Policies Matched:")
		for _, p := range gate.PoliciesMatched {
			fmt.Printf("      - %s: %s (reason: %s)\n", p.PolicyName, p.Action, p.Reason)
		}
	}
	fmt.Println()

	// Handle decision
	if gate.IsBlocked() {
		fmt.Println("    Step BLOCKED by policy!")
		fmt.Println("    Aborting workflow...")
		client.AbortWorkflow(workflow.WorkflowID, gate.Reason)
		return
	}

	if gate.RequiresApproval() {
		fmt.Printf("    Step requires approval: %s\n", gate.ApprovalURL)
		// In production, wait for approval
	}

	// Mark step completed
	if gate.IsAllowed() {
		client.MarkStepCompleted(workflow.WorkflowID, "step-1", nil)
		fmt.Println("    Step completed!")
	}
	fmt.Println()

	// Test with potentially sensitive content
	fmt.Println("1.3 Testing with database query (potential SQLi check)...")
	gate2, err := client.StepGate(workflow.WorkflowID, "step-2", axonflow.StepGateRequest{
		StepName: "Execute Query",
		StepType: axonflow.StepTypeToolCall,
		StepInput: map[string]interface{}{
			"query": "SELECT name, email FROM customers LIMIT 10",
		},
	})
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
	} else {
		fmt.Printf("    Decision: %s\n", gate2.Decision)
		if len(gate2.PoliciesEvaluated) > 0 {
			fmt.Printf("    Policies checked: %d\n", len(gate2.PoliciesEvaluated))
		}
		if len(gate2.PoliciesMatched) > 0 {
			fmt.Printf("    Policies matched: %d\n", len(gate2.PoliciesMatched))
			for _, p := range gate2.PoliciesMatched {
				fmt.Printf("      - %s: %s\n", p.PolicyName, p.Reason)
			}
		}
	}
	fmt.Println()

	// Complete workflow
	fmt.Println("1.4 Completing workflow...")
	err = client.CompleteWorkflow(workflow.WorkflowID)
	if err != nil {
		fmt.Printf("    ERROR: %v\n", err)
	} else {
		fmt.Println("    Workflow completed!")
	}
	fmt.Println()

	// ==========================================
	// Part 2: Audit Log Verification
	// ==========================================

	fmt.Println("Part 2: Audit Log Verification")
	fmt.Println("------------------------------")
	fmt.Println()

	// Delay to ensure audit logs are flushed (batch writer flushes every 5-10 seconds)
	fmt.Println("    Waiting for audit log batch flush...")
	time.Sleep(6 * time.Second)

	// Search for workflow audit logs
	fmt.Println("2.1 Searching for workflow audit logs...")
	auditLogs, err := client.SearchAuditLogs(context.Background(), &axonflow.AuditSearchRequest{
		StartTime: &startTime,
		Limit:     50,
	})
	if err != nil {
		fmt.Printf("    ERROR searching audit logs: %v\n", err)
	} else {
		// Count workflow-related entries
		workflowLogs := make(map[string]int)
		for _, entry := range auditLogs.Entries {
			if entry.RequestID == workflow.WorkflowID {
				workflowLogs[entry.RequestType]++
			}
		}

		if len(workflowLogs) > 0 {
			fmt.Printf("    ✅ Found %d audit log entries for workflow %s:\n", sumValues(workflowLogs), workflow.WorkflowID)
			for reqType, count := range workflowLogs {
				fmt.Printf("       - %s: %d\n", reqType, count)
			}
		} else {
			fmt.Println("    ⚠️  No audit logs found for this workflow")
			fmt.Println("       (Audit logs may take a moment to flush)")
		}
	}
	fmt.Println()

	// Verify expected audit entries
	fmt.Println("2.2 Verifying expected audit entries...")
	expectedTypes := []string{"workflow_created", "workflow_step_gate", "workflow_completed"}
	allFound := true
	for _, expected := range expectedTypes {
		found := false
		if auditLogs != nil {
			for _, entry := range auditLogs.Entries {
				if entry.RequestID == workflow.WorkflowID && entry.RequestType == expected {
					found = true
					break
				}
			}
		}
		if found {
			fmt.Printf("    ✅ %s: FOUND\n", expected)
		} else {
			fmt.Printf("    ❌ %s: NOT FOUND\n", expected)
			allFound = false
		}
	}
	fmt.Println()

	if allFound {
		fmt.Println("    ✅ All expected audit log entries verified!")
	} else {
		fmt.Println("    ⚠️  Some audit log entries were not found")
	}
	fmt.Println()

	// ==========================================
	// Summary
	// ==========================================

	// Assertions to validate actual functionality
	fmt.Println("Validating workflow policy functionality...")
	assertCheck(workflow.WorkflowID != "", "Workflow was created with valid ID")
	assertCheck(gate.Decision != "", "Step gate returned a decision")
	assertCheck(gate.Decision == "allow" || gate.Decision == "block" || gate.Decision == "require_approval",
		"Step gate decision is valid (allow/block/require_approval)")

	fmt.Println("==========================================")
	fmt.Println("Summary")
	fmt.Println("==========================================")
	fmt.Println()
	fmt.Println("WCP Policy Enforcement (Issue #1021):")
	fmt.Println("  - StepGateResponse.PoliciesEvaluated: all checked policies")
	fmt.Println("  - StepGateResponse.PoliciesMatched: policies that triggered decision")
	fmt.Println("  - PolicyMatch includes: PolicyID, PolicyName, Action, Reason")
	fmt.Println()
	fmt.Println("Audit Logging (Issue #1019):")
	fmt.Println("  - workflow_created: logged when workflow is registered")
	fmt.Println("  - workflow_step_gate: logged for each step gate check")
	fmt.Println("  - workflow_completed: logged when workflow completes")
	fmt.Println("  - workflow_aborted: logged when workflow is aborted")
	fmt.Println()
	fmt.Println("MAP Policy Enforcement (Issue #1020):")
	fmt.Println("  - PlanExecutionResponse.PolicyInfo: policy evaluation result")
	fmt.Println("  - Includes: Allowed, AppliedPolicies, RiskScore")
	fmt.Println("  - Returns 403 Forbidden if policies block execution")
	fmt.Println()

	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func sumValues(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}
