// Conditional Logic Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates if/else branching based on API responses.
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v3"
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
	fmt.Println("Conditional Logic Workflow - Go")
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

	// Test 2: Search for flights
	fmt.Println("Test 2: Flight Search Query")
	fmt.Println("---------------------------")
	searchQuery := "Find round-trip flights from New York to Paris for next week"
	fmt.Printf("   Query: %s\n", searchQuery)

	searchResponse, err := client.ProxyLLMCall("user-123", searchQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Search query does not return error")
	if err == nil {
		assertCheck(searchResponse.Success, "Search response is successful")
		assertCheck(searchResponse.Data != nil, "Search response has data")
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", searchResponse.Data), 80))
	} else {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Test 3: Conditional logic based on search results
	fmt.Println("Test 3: Conditional Branching")
	fmt.Println("-----------------------------")
	var branchTaken string

	if searchResponse.Success {
		result := fmt.Sprintf("%v", searchResponse.Data)

		// Check if flights were found (simple string check for demo)
		if strings.Contains(strings.ToLower(result), "no flights") ||
			strings.Contains(strings.ToLower(result), "not available") {
			// Fallback path - no flights available
			branchTaken = "fallback"
			fmt.Println("   Branch: Fallback (no flights found)")
			fmt.Println("   Trying alternative dates...")

			altQuery := "Find flights from New York to Paris for the following week instead"
			altResponse, err := client.ProxyLLMCall("user-123", altQuery, "chat", map[string]interface{}{"provider": "openai"})
			assertCheck(err == nil, "Fallback query does not return error")
			if err == nil {
				assertCheck(altResponse.Success, "Fallback response is successful")
				fmt.Printf("   Alternative Response: %v\n", truncate(fmt.Sprintf("%v", altResponse.Data), 80))
			}
		} else {
			// Success path - flights found
			branchTaken = "success"
			fmt.Println("   Branch: Success (flights found)")

			bookQuery := "Based on the search results above, what would be the recommended booking?"
			bookResponse, err := client.ProxyLLMCall("user-123", bookQuery, "chat", map[string]interface{}{"provider": "openai"})
			assertCheck(err == nil, "Booking recommendation query does not return error")
			if err == nil {
				assertCheck(bookResponse.Success, "Booking recommendation response is successful")
				fmt.Printf("   Booking Recommendation: %v\n", truncate(fmt.Sprintf("%v", bookResponse.Data), 80))
			}
		}
	}

	assertCheck(branchTaken != "", "Workflow executed a conditional branch")
	fmt.Println()

	// Summary
	fmt.Println("================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println("Tip: This example demonstrates if/else branching based on API responses")
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
