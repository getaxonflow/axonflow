// Community LLM Provider E2E Tests using Go SDK
// Tests governed LLM access through AxonFlow Agent
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Create client - SDK talks to Agent which routes to Orchestrator
	agentURL := os.Getenv("AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     agentURL,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		LicenseKey:   os.Getenv("AXONFLOW_LICENSE_KEY"),
	})

	fmt.Println("=== Community LLM Provider Tests (Go SDK) ===")
	fmt.Printf("Agent URL: %s\n\n", agentURL)

	// Test 1: Health check
	fmt.Println("Test 1: Agent health check")
	if err := client.HealthCheck(); err != nil {
		fmt.Printf("  Health check failed: %v\n", err)
	} else {
		fmt.Println("  Agent is healthy")
	}
	fmt.Println()

	// Test 2: Execute query with OpenAI preference
	fmt.Println("Test 2: Per-request selection - OpenAI")
	resp, err := client.ExecuteQuery(
		"test-user@example.com",
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "openai"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
	}
	fmt.Println()

	// Test 3: Execute query with Anthropic preference
	fmt.Println("Test 3: Per-request selection - Anthropic")
	resp, err = client.ExecuteQuery(
		"test-user@example.com",
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "anthropic"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
	}
	fmt.Println()

	// Test 4: Execute query with Gemini preference
	fmt.Println("Test 4: Per-request selection - Gemini")
	resp, err = client.ExecuteQuery(
		"test-user@example.com",
		"Say hello in 3 words",
		"chat",
		map[string]interface{}{"provider": "gemini"},
	)
	if err != nil {
		fmt.Printf("  Error: %v\n", err)
	} else {
		fmt.Printf("  Success: %v, Response: %s\n", resp.Success, truncate(fmt.Sprintf("%v", resp.Data), 50))
	}
	fmt.Println()

	// Test 5: Weighted routing (no provider preference)
	fmt.Println("Test 5: Weighted routing distribution (5 queries)")
	for i := 0; i < 5; i++ {
		resp, err = client.ExecuteQuery(
			"test-user@example.com",
			"Hello",
			"chat",
			nil,
		)
		if err != nil {
			fmt.Printf("  Query %d: Error - %v\n", i+1, err)
		} else {
			fmt.Printf("  Query %d: Success\n", i+1)
		}
	}
	fmt.Println()

	fmt.Println("=== Tests Complete ===")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
