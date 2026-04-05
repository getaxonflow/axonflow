// Package main demonstrates AxonFlow Proxy Mode with Azure OpenAI.
//
// Proxy Mode is the simplest integration pattern:
//   - Send your query to AxonFlow
//   - AxonFlow routes to Azure OpenAI and handles policy enforcement
//   - Get the response back
//
// No need to manage Azure OpenAI credentials in your app - AxonFlow handles everything.
//
// Prerequisites:
//
//	PII_ACTION=block docker compose up -d
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v5"
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
	fmt.Println("AxonFlow Proxy Mode with Azure OpenAI - Go")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Initialize AxonFlow client
	// In proxy mode, Azure OpenAI credentials are configured on the server
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", ""),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""),
	})

	// Example 1: Basic query routed to Azure OpenAI
	fmt.Println("--- Example 1: Basic Azure OpenAI Query ---")
	runQuery(client, "What are the key benefits of Azure OpenAI for enterprises?", map[string]interface{}{
		"provider": "azure-openai", // Route to Azure OpenAI
	}, false, "Basic Azure query")

	// Example 2: Query with specific model
	fmt.Println("\n--- Example 2: Query with Model Selection ---")
	runQuery(client, "Explain Azure Private Link in 2 sentences.", map[string]interface{}{
		"provider": "azure-openai",
		"model":    "gpt-4o-mini",
	}, false, "Model selection query")

	// Example 3: SQL Injection - should be blocked by policy
	fmt.Println("\n--- Example 3: SQL Injection (should be blocked) ---")
	runQuery(client, "SELECT * FROM users; DROP TABLE secrets;", map[string]interface{}{
		"provider": "azure-openai",
	}, true, "SQL injection blocked")

	// Example 4: PII - should be blocked (requires PII_ACTION=block)
	fmt.Println("\n--- Example 4: PII Detection (should be blocked) ---")
	runQuery(client, "Send invoice to john.doe@company.com with SSN 123-45-6789", map[string]interface{}{
		"provider": "azure-openai",
	}, true, "PII detection")

	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL ASSERTIONS PASSED - Azure OpenAI Proxy Mode verified!")
}

func runQuery(client *axonflow.AxonFlowClient, query string, context map[string]interface{}, expectBlocked bool, testName string) {
	fmt.Printf("Query: %q\n", truncate(query, 50))

	startTime := time.Now()

	response, err := client.ProxyLLMCall(
		"user-azure-proxy",
		query,
		"chat",
		context,
	)

	latency := time.Since(startTime)

	if err != nil {
		fmt.Printf("  Status: ERROR - %v\n", err)
		// HTTP 403 errors may indicate blocking
		errStr := err.Error()
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "blocked") {
			assertCheck(expectBlocked, testName+": blocked via HTTP error as expected")
		} else {
			assertCheck(false, testName+": unexpected error")
		}
		return
	}

	if response.Blocked {
		fmt.Printf("  Status: BLOCKED\n")
		fmt.Printf("  Reason: %s\n", response.BlockReason)
		if response.PolicyInfo != nil {
			fmt.Printf("  Policies: %v\n", response.PolicyInfo.PoliciesEvaluated)
		}
		assertCheck(expectBlocked, testName+": blocked as expected")
		assertCheck(response.BlockReason != "", testName+": block reason provided")
	} else {
		fmt.Printf("  Status: SUCCESS (latency: %v)\n", latency)
		resultStr := fmt.Sprintf("%v", response.Result)
		if resultStr == "" {
			resultStr = fmt.Sprintf("%v", response.Data)
		}
		fmt.Printf("  Response: %s\n", truncate(resultStr, 200))
		assertCheck(!expectBlocked, testName+": not blocked as expected")
		assertCheck(response.Data != nil || response.Result != "", testName+": response has content")
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
