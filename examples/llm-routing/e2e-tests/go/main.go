//go:build !loadtest

// Community LLM Provider E2E Tests using Go SDK
// Tests governed LLM access through AxonFlow Agent
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	// Create client - SDK talks to Agent which routes to Orchestrator
	agentURL := os.Getenv("AXONFLOW_ENDPOINT")
	if agentURL == "" {
		agentURL = os.Getenv("AGENT_URL")
	}
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	userToken := os.Getenv("AXONFLOW_USER_TOKEN")
	if userToken == "" {
		userToken = "test-user@example.com"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
	})

	fmt.Println("=== Community LLM Provider Tests (Go SDK) ===")
	fmt.Printf("Agent URL: %s\n\n", agentURL)

	// Test 1: Health check
	fmt.Println("Test 1: Agent health check")
	if err := client.HealthCheck(); err != nil {
		fmt.Printf("  Health check failed: %v\n", err)
		assertCheck(false, "Agent health check passed")
	} else {
		fmt.Println("  Agent is healthy")
		assertCheck(true, "Agent health check passed")
	}
	fmt.Println()

	// Test 2: Execute query with OpenAI preference
	fmt.Println("Test 2: Per-request selection - OpenAI")
	resp, err := client.ProxyLLMCall(
		userToken,
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "openai"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		assertCheck(false, "OpenAI provider query succeeded")
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
		assertCheck(resp.Success || resp.Data != nil, "OpenAI provider query succeeded")
	}
	fmt.Println()

	// Test 3: Execute query with Anthropic preference
	fmt.Println("Test 3: Per-request selection - Anthropic")
	resp, err = client.ProxyLLMCall(
		userToken,
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "anthropic"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		assertCheck(false, "Anthropic provider query succeeded")
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
		assertCheck(resp.Success || resp.Data != nil, "Anthropic provider query succeeded")
	}
	fmt.Println()

	// Test 4: Execute query with Gemini preference
	fmt.Println("Test 4: Per-request selection - Gemini")
	resp, err = client.ProxyLLMCall(
		userToken,
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "gemini"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
		assertCheck(false, "Gemini provider query succeeded")
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
		assertCheck(resp.Success || resp.Data != nil, "Gemini provider query succeeded")
	}
	fmt.Println()

	// Test 5: Weighted routing (no provider preference)
	fmt.Println("Test 5: Weighted routing distribution (5 queries)")
	successCount := 0
	for i := 0; i < 5; i++ {
		resp, err = client.ProxyLLMCall(
			userToken,
			"Hello",
			"chat",
			nil,
		)
		if err != nil {
			fmt.Printf("  Query %d: Error - %v\n", i+1, err)
		} else {
			fmt.Printf("  Query %d: Success\n", i+1)
			successCount++
		}
	}
	assertCheck(successCount > 0, "At least one weighted routing query succeeded")
	fmt.Println()

	fmt.Println("=== Tests Complete ===")

	if len(failures) > 0 {
		fmt.Printf("\nFAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL ASSERTIONS PASSED - LLM routing E2E tests verified!")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
