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
	"context"
	"fmt"
	"log"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize client
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	tenant := os.Getenv("AXONFLOW_TENANT")
	if tenant == "" {
		tenant = "demo"
	}

	client, err := axonflow.NewClient(
		axonflow.WithEndpoint(endpoint),
		axonflow.WithLicenseKey(os.Getenv("AXONFLOW_LICENSE_KEY")),
		axonflow.WithTenant(tenant),
	)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx := context.Background()
	fmt.Println("=== LLM Provider Routing Examples ===\n")

	// Example 1: Default routing (uses server-side strategy)
	fmt.Println("1. Default routing (server decides provider):")
	defaultResp, err := client.Proxy(ctx, &axonflow.ProxyRequest{
		Query:       "What is 2 + 2?",
		RequestType: "chat",
	})
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		response := truncate(defaultResp.Response, 50)
		provider := "unknown"
		if defaultResp.Metadata != nil {
			if p, ok := defaultResp.Metadata["provider"].(string); ok {
				provider = p
			}
		}
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Provider used: %s\n\n", provider)
	}

	// Example 2: Request a specific provider
	fmt.Println("2. Request specific provider (OpenAI):")
	openaiResp, err := client.Proxy(ctx, &axonflow.ProxyRequest{
		Query:       "What is the capital of France?",
		RequestType: "chat",
		Context: map[string]interface{}{
			"provider": "openai", // Request specific provider
		},
	})
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		response := truncate(openaiResp.Response, 50)
		provider := "unknown"
		if openaiResp.Metadata != nil {
			if p, ok := openaiResp.Metadata["provider"].(string); ok {
				provider = p
			}
		}
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Provider used: %s\n\n", provider)
	}

	// Example 3: Request Anthropic
	fmt.Println("3. Request specific provider (Anthropic):")
	anthropicResp, err := client.Proxy(ctx, &axonflow.ProxyRequest{
		Query:       "Explain quantum computing in one sentence.",
		RequestType: "chat",
		Context: map[string]interface{}{
			"provider": "anthropic",
		},
	})
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		response := truncate(anthropicResp.Response, 50)
		provider := "unknown"
		if anthropicResp.Metadata != nil {
			if p, ok := anthropicResp.Metadata["provider"].(string); ok {
				provider = p
			}
		}
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Provider used: %s\n\n", provider)
	}

	// Example 4: Request with model override
	fmt.Println("4. Request with specific model:")
	modelResp, err := client.Proxy(ctx, &axonflow.ProxyRequest{
		Query:       "What is machine learning?",
		RequestType: "chat",
		Context: map[string]interface{}{
			"provider": "openai",
			"model":    "gpt-4o-mini", // Specify exact model
		},
	})
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		response := truncate(modelResp.Response, 50)
		model := "unknown"
		if modelResp.Metadata != nil {
			if m, ok := modelResp.Metadata["model"].(string); ok {
				model = m
			}
		}
		fmt.Printf("   Response: %s...\n", response)
		fmt.Printf("   Model used: %s\n\n", model)
	}

	// Example 5: Health check to see available providers
	fmt.Println("5. Check provider health status:")
	health, err := client.Health(ctx)
	if err != nil {
		log.Printf("   Error: %v\n", err)
	} else {
		fmt.Printf("   Status: %s\n", health.Status)
		if health.Providers != nil {
			for name, status := range health.Providers {
				healthy := false
				if statusMap, ok := status.(map[string]interface{}); ok {
					if h, ok := statusMap["healthy"].(bool); ok {
						healthy = h
					}
				}
				symbol := "✗ unhealthy"
				if healthy {
					symbol = "✓ healthy"
				}
				fmt.Printf("   - %s: %s\n", name, symbol)
			}
		}
	}

	fmt.Println("\n=== Examples Complete ===")
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
