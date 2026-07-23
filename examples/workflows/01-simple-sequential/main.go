// Simple Sequential Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates a simple sequential LLM call through AxonFlow governance.
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
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
	fmt.Println("Simple Sequential Workflow - Go")
	fmt.Println("================================")
	fmt.Println()

	// Create AxonFlow client (no auth required for community mode)
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
	})

	// Test 1: Health check
	fmt.Println("Test 1: Health Check")
	fmt.Println("--------------------")
	err := client.HealthCheck()
	assertCheck(err == nil, "Agent is healthy")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Test 2: Send a simple query
	fmt.Println("Test 2: Simple Query")
	fmt.Println("--------------------")
	query := "What is the capital of France?"
	fmt.Printf("   Query: %s\n", query)

	response, err := client.ProxyLLMCall("", query, "chat", nil)
	assertCheck(err == nil, "LLM call does not return error")
	if err == nil {
		assertCheck(response.Success, "LLM response is successful")
		assertCheck(response.Data != nil, "Response has data")
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", response.Data), 80))
	} else {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Summary
	fmt.Println("================================")
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

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
