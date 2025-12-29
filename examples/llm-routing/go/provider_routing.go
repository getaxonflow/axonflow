// LLM Provider Routing Example
//
// This example demonstrates how to:
// 1. Use default routing (server-side configuration)
// 2. Specify a preferred provider in requests
// 3. Query provider status
//
// Server-side configuration (environment variables):
//
//	LLM_ROUTING_STRATEGY=weighted|round_robin|failover
//	PROVIDER_WEIGHTS=openai:50,anthropic:30,bedrock:20
//	DEFAULT_LLM_PROVIDER=bedrock
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

	// Example 1: Default routing (uses server-side strategy)
	fmt.Println("1. Default routing (server decides provider):")
	defaultResp, err := client.ExecuteQuery(
		"demo-user", // userToken
		"What is 2 + 2?",
		"chat",
		nil, // context - let server decide provider
	)
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else if defaultResp.Blocked {
		fmt.Printf("   Blocked: %s\n", defaultResp.BlockReason)
	} else {
		response := truncate(fmt.Sprintf("%v", defaultResp.Data), 100)
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Success: %v\n\n", defaultResp.Success)
	}

	// Example 2: Request specific provider (Ollama - local)
	fmt.Println("2. Request specific provider (Ollama):")
	ollamaResp, err := client.ExecuteQuery(
		"demo-user",
		"What is the capital of France?",
		"chat",
		map[string]interface{}{
			"provider": "ollama", // Request specific provider
		},
	)
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else if ollamaResp.Blocked {
		fmt.Printf("   Blocked: %s\n", ollamaResp.BlockReason)
	} else {
		response := truncate(fmt.Sprintf("%v", ollamaResp.Data), 100)
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Success: %v\n\n", ollamaResp.Success)
	}

	// Example 3: Request with model override
	fmt.Println("3. Request with specific model:")
	modelResp, err := client.ExecuteQuery(
		"demo-user",
		"What is machine learning in one sentence?",
		"chat",
		map[string]interface{}{
			"provider": "ollama",
			"model":    "tinyllama", // Specify exact model
		},
	)
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else if modelResp.Blocked {
		fmt.Printf("   Blocked: %s\n", modelResp.BlockReason)
	} else {
		response := truncate(fmt.Sprintf("%v", modelResp.Data), 100)
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Success: %v\n\n", modelResp.Success)
	}

	// Example 4: Health check
	fmt.Println("4. Check agent health:")
	if err := client.HealthCheck(); err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		fmt.Println("   Status: healthy")
		fmt.Println("   Agent is responding correctly")
	}

	fmt.Println()
	fmt.Println("=== Examples Complete ===")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
