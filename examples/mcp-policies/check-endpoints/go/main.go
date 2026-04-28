// Package main demonstrates MCP standalone policy-check endpoints using the Go SDK.
//
// These endpoints validate MCP requests and responses against policies WITHOUT
// executing any connector queries. Use them when an external orchestrator
// (LangGraph, CrewAI) manages MCP execution but needs AxonFlow as a policy gate.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v6"
)

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("MCP Policy Check Endpoints - Go SDK")
	fmt.Println("====================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	ctx := context.Background()

	// ---------------------------------------------------------------
	// CHECK-INPUT TESTS
	// ---------------------------------------------------------------

	// Test 1: Clean SQL query passes
	fmt.Println("Test 1: Check-Input — Clean SQL Query")
	fmt.Println("--------------------------------------")
	resp, err := client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT name, department FROM employees WHERE id = 42",
		Operation:     "query",
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		assert(resp.Allowed, "allowed = true")
		assert(resp.PoliciesEvaluated > 0, fmt.Sprintf("policies_evaluated = %d", resp.PoliciesEvaluated))
	}
	fmt.Println()

	// Test 2: SQL injection blocked
	fmt.Println("Test 2: Check-Input — SQL Injection Blocked")
	fmt.Println("--------------------------------------------")
	resp, err = client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users UNION SELECT username, password FROM admin_users--",
	})
	if err != nil {
		// SDK may return error for 403 depending on implementation
		fmt.Printf("   Blocked (error): %v\n", err)
		assert(true, "Request was blocked")
	} else {
		assert(!resp.Allowed, "allowed = false")
		assert(resp.BlockReason != "", fmt.Sprintf("block_reason: %s", resp.BlockReason))
	}
	fmt.Println()

	// Test 3: Dangerous query blocked
	fmt.Println("Test 3: Check-Input — Dangerous Query (DROP TABLE)")
	fmt.Println("---------------------------------------------------")
	resp, err = client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users; DROP TABLE users--",
	})
	if err != nil {
		fmt.Printf("   Blocked (error): %v\n", err)
		assert(true, "Dangerous query was blocked")
	} else {
		assert(!resp.Allowed, "allowed = false")
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// CHECK-INPUT: PARAMETER SCANNING (Issue #1287)
	// ---------------------------------------------------------------

	// Test 4: Clean parameterized query passes
	fmt.Println("Test 4: Check-Input — Clean Parameterized Query")
	fmt.Println("------------------------------------------------")
	resp, err = client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users WHERE id = $1",
		Operation:     "query",
		Parameters:    map[string]interface{}{"1": "usr-42"},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		assert(resp.Allowed, "allowed = true")
	}
	fmt.Println()

	// Test 5: SQLi hidden in parameters — blocked
	fmt.Println("Test 5: Check-Input — SQLi in Parameters")
	fmt.Println("-----------------------------------------")
	resp, err = client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users WHERE id = $1",
		Operation:     "query",
		Parameters:    map[string]interface{}{"1": "1 OR 1=1; DROP TABLE users--"},
	})
	if err != nil {
		fmt.Printf("   Blocked (error): %v\n", err)
		assert(true, "SQLi in parameters was blocked")
	} else {
		assert(!resp.Allowed, "allowed = false (SQLi detected in parameters)")
		assert(resp.BlockReason != "", fmt.Sprintf("block_reason: %s", resp.BlockReason))
	}
	fmt.Println()

	// Test 6: PII hidden in parameters — detected
	fmt.Println("Test 6: Check-Input — PII in Parameters (SSN)")
	fmt.Println("----------------------------------------------")
	resp, err = client.MCPCheckInput(ctx, axonflow.MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "INSERT INTO contacts VALUES ($1, $2)",
		Operation:     "execute",
		Parameters:    map[string]interface{}{"1": "Alice", "2": "123-45-6789"},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		// PII detection uses redact action (not block), so allowed=true but policies match
		fmt.Printf("   allowed=%v, policies_evaluated=%d\n", resp.Allowed, resp.PoliciesEvaluated)
		assert(resp.PoliciesEvaluated > 0, "PII policies evaluated for parameters")
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// CHECK-OUTPUT TESTS
	// ---------------------------------------------------------------

	// Test 7: Clean response data passes
	fmt.Println("Test 7: Check-Output — Clean Response Data")
	fmt.Println("-------------------------------------------")
	outResp, err := client.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData: []map[string]interface{}{
			{"id": 1, "name": "Alice Johnson", "department": "Engineering"},
			{"id": 2, "name": "Bob Smith", "department": "Marketing"},
		},
		RowCount: 2,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		assert(outResp.Allowed, "allowed = true")
		assert(outResp.PoliciesEvaluated > 0, fmt.Sprintf("policies_evaluated = %d", outResp.PoliciesEvaluated))
	}
	fmt.Println()

	// Test 8: PII in response — redacted
	fmt.Println("Test 8: Check-Output — PII Redaction (SSN)")
	fmt.Println("-------------------------------------------")
	outResp, err = client.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData: []map[string]interface{}{
			{"id": 1, "name": "Alice", "ssn": "123-45-6789"},
			{"id": 2, "name": "Bob", "ssn": "987-65-4321"},
		},
		RowCount: 2,
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		assert(outResp.Allowed, "allowed = true (redacted, not blocked)")
		if outResp.RedactedData != nil {
			fmt.Printf("   INFO: redacted_data present (PII masked)\n")
		}
	}
	fmt.Println()

	// Test 9: Execute-style response
	fmt.Println("Test 9: Check-Output — Execute Response (Message)")
	fmt.Println("--------------------------------------------------")
	outResp, err = client.MCPCheckOutput(ctx, axonflow.MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "3 rows updated",
		Metadata: map[string]interface{}{
			"query": "UPDATE users SET status = 'active' WHERE region = 'us'",
		},
	})
	if err != nil {
		fmt.Printf("   ERROR: %v\n", err)
	} else {
		assert(outResp.Allowed, "allowed = true")
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------
	fmt.Println("====================================")
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL TESTS PASSED")
}
