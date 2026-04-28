// Package main demonstrates the simplest AxonFlow integration in Go.
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// This example tests policy evaluation without making LLM calls:
// 1. Safe query - should be approved
// 2. SQL injection - should be blocked
// 3. PII (SSN) - should be approved (redact mode, not block)
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v6"
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
	fmt.Println("AxonFlow Hello World - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize AxonFlow client
	// Uses AXONFLOW_ENDPOINT for self-hosted, or set AXONFLOW_TRY=1 for try.getaxonflow.com
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", ""),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	userToken := getEnv("AXONFLOW_USER_TOKEN", "hello-world-user")

	// Test 1: Safe Query - should be approved
	fmt.Println("Test 1: Safe Query")
	fmt.Println("------------------")
	result1, err1 := client.GetPolicyApprovedContext(userToken, "What is the weather today?", nil, nil)
	assertCheck(err1 == nil, "Safe query does not return error")
	if err1 == nil {
		assertCheck(result1.Approved, "Safe query is approved")
		assertCheck(result1.ContextID != "", "Safe query returns context ID")
	} else {
		fmt.Printf("   Error: %v\n", err1)
	}
	fmt.Println()

	// Test 2: SQL Injection - should be blocked
	fmt.Println("Test 2: SQL Injection")
	fmt.Println("---------------------")
	result2, err2 := client.GetPolicyApprovedContext(userToken, "SELECT * FROM users; DROP TABLE users;", nil, nil)
	assertCheck(err2 == nil, "SQLi query does not return error")
	if err2 == nil {
		assertCheck(!result2.Approved, "SQLi query is blocked")
		assertCheck(result2.BlockReason != "", "SQLi query has block reason")
		fmt.Printf("   Block reason: %s\n", result2.BlockReason)
	} else {
		fmt.Printf("   Error: %v\n", err2)
	}
	fmt.Println()

	// Test 3: PII (SSN) - should be approved (redact mode)
	fmt.Println("Test 3: PII (SSN)")
	fmt.Println("-----------------")
	result3, err3 := client.GetPolicyApprovedContext(userToken, "Process payment for SSN 123-45-6789", nil, nil)
	assertCheck(err3 == nil, "PII query does not return error")
	if err3 == nil {
		assertCheck(result3.Approved, "PII query is approved (redact mode)")
		assertCheck(len(result3.Policies) > 0, "PII query triggers policy detection")
		fmt.Printf("   Policies: %v\n", result3.Policies)
	} else {
		fmt.Printf("   Error: %v\n", err3)
	}
	fmt.Println()

	// Summary
	fmt.Println("========================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		os.Exit(0)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
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
