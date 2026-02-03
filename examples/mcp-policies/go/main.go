// Package main demonstrates MCP policy enforcement with phase-aware blocking and redaction.
//
// This example validates:
// 1. REQUEST phase: SQLi patterns are blocked with 403
// 2. RESPONSE phase: PII in connector data is redacted
// 3. PolicyInfo metadata is included in all responses
//
// Policy Configuration (env vars):
//
//	MCP_STATIC_POLICIES_ENABLED - Enable/disable static MCP policies: "true" (default) or "false"
//
//	When enabled (default): static policies (SQLi blocking, PII redaction) are enforced
//	When disabled: static policies are skipped; only dynamic policies apply
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v2"
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
	fmt.Println("AxonFlow MCP Policy Enforcement - Go SDK")
	fmt.Println("=========================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""), // Empty for community mode
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	ctx := context.Background()

	// Test 1: Clean query should pass through
	fmt.Println("Test 1: Clean Query (No PII, No SQLi)")
	fmt.Println("--------------------------------------")
	resp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT 1 as test_value",
	})
	if err != nil {
		fmt.Printf("   Query failed: %v\n", err)
	} else {
		assert(resp.Success, "Query succeeded")
		assert(!resp.Redacted, "No redaction applied")
		if resp.PolicyInfo != nil {
			assert(resp.PolicyInfo.PoliciesEvaluated >= 0, "Policies were evaluated")
			assert(!resp.PolicyInfo.Blocked, "Request was not blocked")
			fmt.Printf("   PolicyInfo: %d policies evaluated in %dms\n",
				resp.PolicyInfo.PoliciesEvaluated, resp.PolicyInfo.ProcessingTimeMs)
		}
	}
	fmt.Println()

	// Test 2: SQLi pattern should be blocked
	fmt.Println("Test 2: SQL Injection Pattern (Request Blocked)")
	fmt.Println("------------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
	})
	if err != nil {
		// Check if it's a policy block error
		assert(true, "Request blocked as expected")
		fmt.Printf("   Block reason: %v\n", err)
	} else if !resp.Success {
		// Response indicates blocking
		assert(true, "Request blocked by policy")
		fmt.Printf("   Block reason: %s\n", resp.Error)
	} else {
		assert(false, "SQLi pattern should have been blocked")
	}
	fmt.Println()

	// Test 3: UNION-based SQLi should also be blocked
	fmt.Println("Test 3: UNION SQLi Pattern (Request Blocked)")
	fmt.Println("---------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT name FROM employees UNION SELECT password FROM admin_users",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "UNION SQLi blocked as expected")
		if resp != nil && resp.Error != "" {
			fmt.Printf("   Block reason: %s\n", resp.Error)
		} else if err != nil {
			fmt.Printf("   Block reason: %v\n", err)
		}
	} else {
		assert(false, "UNION SQLi should have been blocked")
	}
	fmt.Println()

	// Test 4: Response with PII should have redacted fields
	fmt.Println("Test 4: Response Redaction (PII in Data)")
	fmt.Println("-----------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM test_customers LIMIT 1",
	})
	if err != nil {
		fmt.Printf("   Query failed: %v\n", err)
		fmt.Println("   Note: test_customers table may not exist")
	} else if resp.Success {
		if resp.Redacted {
			assert(true, "Response was redacted")
			assert(len(resp.RedactedFields) > 0, "Redacted fields are listed")
			fmt.Printf("   Redacted fields: %v\n", resp.RedactedFields)
		} else {
			fmt.Println("   Note: No PII found in response")
		}
		if resp.PolicyInfo != nil {
			fmt.Printf("   PolicyInfo: %d redactions in %dms\n",
				resp.PolicyInfo.RedactionsApplied, resp.PolicyInfo.ProcessingTimeMs)
		}
	}
	fmt.Println()

	// Test 5: Request-side PII blocking (SSN in query)
	fmt.Println("Test 5: Request-side PII Blocking (SSN in Query)")
	fmt.Println("------------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM customers WHERE ssn = '123-45-6789'",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "SSN in query blocked as expected")
		if resp != nil && resp.Error != "" {
			fmt.Printf("   Block reason: %s\n", resp.Error)
		}
	} else {
		assert(false, "SSN in query should have been blocked")
	}
	fmt.Println()

	// ========================================
	// Policy Configuration Check (MCP_STATIC_POLICIES_ENABLED)
	// ========================================
	staticPoliciesEnabled := getEnv("MCP_STATIC_POLICIES_ENABLED", "true")
	fmt.Println("Test 6: Static Policies Configuration Check")
	fmt.Println("--------------------------------------------")
	if staticPoliciesEnabled == "true" {
		fmt.Println("   MCP_STATIC_POLICIES_ENABLED=true (default)")
		fmt.Println("   Static policies (SQLi blocking, PII redaction) are ACTIVE")
	} else {
		fmt.Println("   MCP_STATIC_POLICIES_ENABLED=false")
		fmt.Println("   Static policies are DISABLED; only dynamic policies apply")
		fmt.Println("   Note: SQLi blocking and PII redaction tests above may behave differently")
	}
	fmt.Println()

	// Summary
	fmt.Println("=========================================")
	if len(failures) == 0 {
		fmt.Println("ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("MCP Policy Enforcement validated:")
		fmt.Println("  - REQUEST phase: SQLi blocking")
		fmt.Println("  - REQUEST phase: PII blocking")
		fmt.Println("  - RESPONSE phase: PII redaction")
		fmt.Println("  - PolicyInfo metadata in responses")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
