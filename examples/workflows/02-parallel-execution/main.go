// Parallel Execution Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates MAP (Multi-Agent Planning) for parallel task execution.
package main

import (
	"fmt"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
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
	fmt.Println("Parallel Execution Workflow - Go")
	fmt.Println("=================================")
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

	// Test 2: Complex query that benefits from parallelization
	fmt.Println("Test 2: Parallel Trip Planning Query")
	fmt.Println("-------------------------------------")
	query := "Plan a 3-day trip to Paris including: (1) round-trip flights from New York, " +
		"(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit"
	fmt.Printf("   Query: %s\n", truncate(query, 80))
	fmt.Println("   Note: MAP will detect independent tasks and execute them in parallel")

	startTime := time.Now()

	// Send query to AxonFlow (uses MAP for parallelization)
	response, err := client.ProxyLLMCall(
		getEnv("AXONFLOW_USER_TOKEN", "user-123"),
		query,
		"multi-agent-plan", // Use MAP for parallel execution
		map[string]interface{}{"provider": "openai"},
	)

	duration := time.Since(startTime)

	assertCheck(err == nil, "Parallel LLM call does not return error")
	if err == nil {
		assertCheck(response.Success, "Parallel response is successful")
		assertCheck(response.Data != nil, "Response has data")
		fmt.Printf("   Duration: %.1fs\n", duration.Seconds())
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", response.Data), 100))
	} else {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Summary
	fmt.Println("=================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println("Tip: MAP automatically parallelized the flight, hotel, and attractions search")
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
