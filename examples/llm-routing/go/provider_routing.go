// LLM Provider Routing Example
//
// This example demonstrates how AxonFlow routes requests to LLM providers.
// Provider selection is controlled SERVER-SIDE via environment variables,
// not per-request. This ensures consistent routing policies across your org.
//
// Server-side configuration (environment variables):
//
//	LLM_ROUTING_STRATEGY=weighted|round_robin|failover|cost_optimized*
//	PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20
//	DEFAULT_LLM_PROVIDER=openai
//
// * cost_optimized is Enterprise only
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize client
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   endpoint,
		LicenseKey: os.Getenv("AXONFLOW_LICENSE_KEY"),
		Mode:       "production",
		Debug:      os.Getenv("DEBUG") == "true",
		Timeout:    60 * time.Second,
	})

	fmt.Println("=== LLM Provider Routing Examples ===")
	fmt.Println()
	fmt.Println("Provider selection is server-side. Configure via environment variables:")
	fmt.Println("  LLM_ROUTING_STRATEGY=weighted")
	fmt.Println("  PROVIDER_WEIGHTS=openai:50,anthropic:30,ollama:20")
	fmt.Println()

	// Example 1: Send a request (server decides which provider to use)
	fmt.Println("1. Send request (server routes based on configured strategy):")
	resp1, err := client.ExecuteQuery(
		"demo-user",
		"What is 2 + 2?",
		"chat",
		nil,
	)
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else if resp1.Blocked {
		fmt.Printf("   Blocked: %s\n", resp1.BlockReason)
	} else {
		response := truncate(fmt.Sprintf("%v", resp1.Data), 100)
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Success: %v\n\n", resp1.Success)
	}

	// Example 2: Multiple requests show distribution based on weights
	fmt.Println("2. Multiple requests (observe provider distribution):")
	for i := 1; i <= 3; i++ {
		resp, err := client.ExecuteQuery(
			"demo-user",
			fmt.Sprintf("Question %d: What is the capital of France?", i),
			"chat",
			nil,
		)
		if err != nil {
			log.Printf("   Request %d Error: %v\n", i, err)
		} else if resp.Blocked {
			fmt.Printf("   Request %d Blocked: %s\n", i, resp.BlockReason)
		} else {
			fmt.Printf("   Request %d: Success (provider selected by server)\n", i)
		}
	}
	fmt.Println()

	// Example 3: Health check
	fmt.Println("3. Check agent health:")
	if err := client.HealthCheck(); err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		fmt.Println("   Status: healthy")
	}

	fmt.Println()
	fmt.Println("=== Examples Complete ===")
	fmt.Println()
	fmt.Println("To change provider routing, update server environment variables:")
	fmt.Println("  - LLM_ROUTING_STRATEGY: weighted, round_robin, failover")
	fmt.Println("  - PROVIDER_WEIGHTS: distribution percentages")
	fmt.Println("  - DEFAULT_LLM_PROVIDER: fallback for failover strategy")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
