// Package main demonstrates AxonFlow Proxy Mode with Azure OpenAI.
//
// Proxy Mode is the simplest integration pattern:
//   - Send your query to AxonFlow
//   - AxonFlow routes to Azure OpenAI and handles policy enforcement
//   - Get the response back
//
// No need to manage Azure OpenAI credentials in your app - AxonFlow handles everything.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Proxy Mode with Azure OpenAI - Go")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Initialize AxonFlow client
	// In proxy mode, Azure OpenAI credentials are configured on the server
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "azure-openai-proxy-demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// Example 1: Basic query routed to Azure OpenAI
	fmt.Println("--- Example 1: Basic Azure OpenAI Query ---")
	runQuery(client, "What are the key benefits of Azure OpenAI for enterprises?", map[string]interface{}{
		"provider": "azure-openai", // Route to Azure OpenAI
	})

	// Example 2: Query with specific model
	fmt.Println("\n--- Example 2: Query with Model Selection ---")
	runQuery(client, "Explain Azure Private Link in 2 sentences.", map[string]interface{}{
		"provider": "azure-openai",
		"model":    "gpt-4o-mini",
	})

	// Example 3: SQL Injection - should be blocked by policy
	fmt.Println("\n--- Example 3: SQL Injection (should be blocked) ---")
	runQuery(client, "SELECT * FROM users; DROP TABLE secrets;", map[string]interface{}{
		"provider": "azure-openai",
	})

	// Example 4: PII - should be detected
	fmt.Println("\n--- Example 4: PII Detection ---")
	runQuery(client, "Send invoice to john.doe@company.com with SSN 123-45-6789", map[string]interface{}{
		"provider": "azure-openai",
	})

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Proxy Mode Demo Complete")
}

func runQuery(client *axonflow.AxonFlowClient, query string, context map[string]interface{}) {
	fmt.Printf("Query: %q\n", truncate(query, 50))

	startTime := time.Now()

	response, err := client.ExecuteQuery(
		"user-azure-proxy",
		query,
		"chat",
		context,
	)

	latency := time.Since(startTime)

	if err != nil {
		fmt.Printf("  Status: ERROR - %v\n", err)
		return
	}

	if response.Blocked {
		fmt.Printf("  Status: BLOCKED\n")
		fmt.Printf("  Reason: %s\n", response.BlockReason)
		if response.PolicyInfo != nil {
			fmt.Printf("  Policies: %v\n", response.PolicyInfo.PoliciesEvaluated)
		}
	} else {
		fmt.Printf("  Status: SUCCESS (latency: %v)\n", latency)
		resultStr := fmt.Sprintf("%v", response.Result)
		if resultStr == "" {
			resultStr = fmt.Sprintf("%v", response.Data)
		}
		fmt.Printf("  Response: %s\n", truncate(resultStr, 200))
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
