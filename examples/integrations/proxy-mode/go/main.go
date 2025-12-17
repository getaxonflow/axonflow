// Package main demonstrates AxonFlow Proxy Mode in Go.
//
// Proxy Mode is the simplest integration pattern:
//   - Send your query to AxonFlow
//   - AxonFlow handles policy enforcement AND LLM routing
//   - Get the response back
//
// No need to manage LLM API keys or audit calls - AxonFlow handles everything.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Proxy Mode - Go Example")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// Example queries
	queries := []struct {
		query       string
		userToken   string
		requestType string
		context     map[string]interface{}
	}{
		{
			query:       "What are the key benefits of AI governance?",
			userToken:   "user-proxy-go",
			requestType: "chat",
			context:     map[string]interface{}{"department": "engineering"},
		},
		{
			query:       "List 3 principles of responsible AI development.",
			userToken:   "user-proxy-go",
			requestType: "chat",
			context:     map[string]interface{}{"format": "list"},
		},
	}

	for i, q := range queries {
		fmt.Printf("\n%s\n", strings.Repeat("─", 60))
		fmt.Printf("Query %d: %q\n", i+1, truncate(q.query, 50))
		fmt.Printf("%s\n", strings.Repeat("─", 60))

		startTime := time.Now()

		// Single call to AxonFlow - it handles policy check AND LLM call
		response, err := client.ExecuteQuery(
			q.userToken,
			q.query,
			q.requestType,
			q.context,
		)

		latency := time.Since(startTime)

		if err != nil {
			fmt.Printf("\n  Status: ERROR\n")
			fmt.Printf("  Error: %v\n", err)
			continue
		}

		if response.Blocked {
			fmt.Printf("\n  Status: BLOCKED\n")
			fmt.Printf("  Reason: %s\n", response.BlockReason)
			if response.PolicyInfo != nil {
				fmt.Printf("  Policies: %v\n", response.PolicyInfo.PoliciesEvaluated)
			}
		} else {
			fmt.Printf("\n  Status: SUCCESS\n")
			fmt.Printf("  Latency: %v\n", latency)

			if response.PolicyInfo != nil {
				fmt.Printf("\n  Policy Info:\n")
				fmt.Printf("    Policies: %v\n", response.PolicyInfo.PoliciesEvaluated)
				fmt.Printf("    Processing: %s\n", response.PolicyInfo.ProcessingTime)
			}

			fmt.Printf("\n  Response:\n")
			resultStr := fmt.Sprintf("%v", response.Result)
			if resultStr == "" {
				resultStr = fmt.Sprintf("%v", response.Data)
			}
			fmt.Printf("    %s\n", truncate(resultStr, 300))
		}
	}

	// Demonstrate blocked query (SQL injection)
	fmt.Printf("\n%s\n", strings.Repeat("─", 60))
	fmt.Println("Query 3 (SQL Injection - should be blocked):")
	fmt.Printf("%s\n", strings.Repeat("─", 60))

	sqlResponse, err := client.ExecuteQuery(
		"user-proxy-go",
		"SELECT * FROM users; DROP TABLE secrets;",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		fmt.Printf("\n  Status: ERROR\n")
		fmt.Printf("  Error: %v\n", err)
	} else if sqlResponse.Blocked {
		fmt.Printf("\n  Status: BLOCKED (expected)\n")
		fmt.Printf("  Reason: %s\n", sqlResponse.BlockReason)
	} else {
		fmt.Printf("\n  Status: ALLOWED (unexpected)\n")
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("Proxy Mode Demo Complete")
	fmt.Printf("%s\n", strings.Repeat("=", 60))
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
