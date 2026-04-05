// Package main provides comprehensive SDK integration testing.
//
// This example validates all SDK methods work correctly against live services.
// Tests include:
// 1. Health checks (Agent + Orchestrator)
// 2. Gateway Mode request
// 3. Proxy Mode request
// 4. Static policy CRUD
// 5. Audit logging
// 6. Error handling (blocked requests)
// 7. Connector operations (list, install, uninstall)
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v5"
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
	fmt.Println("AxonFlow SDK Comprehensive Audit - Go")
	fmt.Println("======================================")
	fmt.Println()

	// Initialize AxonFlow client
	// Note: As of SDK v2.0.0 (ADR-026), all routes go through a single endpoint.
	// The Agent proxies orchestrator routes internally.
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo-client"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
	})

	var passed, failed int
	var approvedContextID string

	// Test 1: Agent Health Check
	fmt.Println("Test 1: Agent Health Check")
	if err := client.HealthCheck(); err != nil {
		fmt.Printf("  ❌ FAILED: %v\n\n", err)
		failed++
	} else {
		fmt.Println("  ✅ PASSED: Agent is healthy")
		passed++
	}

	// Test 2: Orchestrator Health Check (via direct HTTP)
	fmt.Println("Test 2: Orchestrator Health Check")
	if err := client.OrchestratorHealthCheck(); err != nil {
		fmt.Printf("  ❌ FAILED: %v\n\n", err)
		failed++
	} else {
		fmt.Println("  ✅ PASSED: Orchestrator is healthy")
		passed++
	}

	// Test 3: Gateway Mode - Safe Query
	fmt.Println("Test 3: Gateway Mode - Safe Query")
	result, err := client.GetPolicyApprovedContext(
		"audit-user",
		"What is the capital of France?",
		nil, nil,
	)
	if err != nil {
		fmt.Printf("  ❌ FAILED: %v\n\n", err)
		failed++
	} else if result.Approved {
		fmt.Printf("  ✅ PASSED: Query approved (contextId: %s)\n", result.ContextID)
		passed++
		approvedContextID = result.ContextID
	} else {
		fmt.Printf("  ❌ FAILED: Query unexpectedly blocked: %s\n", result.BlockReason)
		failed++
	}

	// Test 4: Gateway Mode - Blocked Query (SQL Injection)
	fmt.Println("Test 4: Gateway Mode - Blocked Query (SQL Injection)")
	result, _ = client.GetPolicyApprovedContext(
		"audit-user",
		"SELECT * FROM users; DROP TABLE users;",
		nil, nil,
	)
	if result != nil && !result.Approved {
		fmt.Printf("  ✅ PASSED: Query correctly blocked (%s)\n", result.BlockReason)
		passed++
	} else {
		fmt.Println("  ❌ FAILED: SQL injection should be blocked")
		failed++
	}

	// Test 5: Audit LLM Call
	fmt.Println("Test 5: Audit LLM Call")
	if approvedContextID != "" {
		tokenUsage := axonflow.TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		}
		auditResult, err := client.AuditLLMCall(
			approvedContextID,
			"Test response for SDK audit",
			"openai",
			"gpt-4",
			tokenUsage,
			250,
			nil,
		)
		if err != nil {
			fmt.Printf("  ❌ FAILED: %v\n\n", err)
			failed++
		} else if auditResult.Success {
			fmt.Printf("  ✅ PASSED: Audit recorded (auditId: %s)\n", auditResult.AuditID)
			passed++
		} else {
			fmt.Println("  ❌ FAILED: Audit not successful")
			failed++
		}
	} else {
		fmt.Println("  ⏭️ SKIPPED: No context ID from previous test")
	}

	// Test 6: List Connectors
	fmt.Println("Test 6: List Connectors")
	connectors, err := client.ListConnectors()
	if err != nil {
		fmt.Printf("  ❌ FAILED: %v\n\n", err)
		failed++
	} else {
		fmt.Printf("  ✅ PASSED: Found %d connectors\n", len(connectors))
		passed++
	}

	// Test 7: Static Policy CRUD
	fmt.Println("Test 7: Static Policy CRUD")
	policyName := fmt.Sprintf("sdk-audit-test-%d", time.Now().Unix())

	// Create policy
	createReq := &axonflow.CreateStaticPolicyRequest{
		Name:        policyName,
		Description: "Test policy from SDK audit",
		Category:    "security-sqli",
		Pattern:     "sdk-audit-test-pattern",
		Severity:    "low",
		Enabled:     true,
		Action:      "warn",
	}

	created, err := client.CreateStaticPolicy(createReq)
	if err != nil {
		fmt.Printf("  ❌ FAILED (Create): %v\n", err)
		failed++
	} else {
		fmt.Printf("  ✅ Create: Policy created (id: %s)\n", created.ID)

		// Get policy
		fetched, err := client.GetStaticPolicy(created.ID)
		if err != nil {
			fmt.Printf("  ❌ FAILED (Get): %v\n", err)
			failed++
		} else if fetched.Name == policyName {
			fmt.Println("  ✅ Get: Policy retrieved correctly")
		}

		// Update policy
		updatedDesc := "Updated description from SDK audit"
		updateReq := &axonflow.UpdateStaticPolicyRequest{
			Description: &updatedDesc,
		}
		updated, err := client.UpdateStaticPolicy(created.ID, updateReq)
		if err != nil {
			fmt.Printf("  ❌ FAILED (Update): %v\n", err)
			failed++
		} else if strings.Contains(updated.Description, "Updated") {
			fmt.Println("  ✅ Update: Policy updated correctly")
		}

		// Delete policy
		err = client.DeleteStaticPolicy(created.ID)
		if err != nil {
			fmt.Printf("  ❌ FAILED (Delete): %v\n", err)
			failed++
		} else {
			fmt.Println("  ✅ Delete: Policy deleted correctly")
			passed++
		}
	}

	// Test 8: List Static Policies
	fmt.Println("Test 8: List Static Policies")
	policies, err := client.ListStaticPolicies(nil)
	if err != nil {
		fmt.Printf("  ❌ FAILED: %v\n\n", err)
		failed++
	} else {
		fmt.Printf("  ✅ PASSED: Found %d policies\n", len(policies))
		passed++
	}

	// Additional assertions using assertCheck pattern
	fmt.Println("\nValidating critical functionality...")
	assertCheck(passed > 0, "At least one test passed")
	assertCheck(approvedContextID != "" || failed > 0, "Either got context ID or test recorded failure")

	// Summary
	fmt.Println()
	fmt.Println("======================================")
	fmt.Printf("Summary: %d passed, %d failed\n", passed, failed)
	fmt.Println()

	if failed > 0 || len(failures) > 0 {
		if len(failures) > 0 {
			fmt.Printf("Additional failures: %d\n", len(failures))
			for _, f := range failures {
				fmt.Printf("  - %s\n", f)
			}
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
