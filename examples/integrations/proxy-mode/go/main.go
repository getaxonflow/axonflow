// Package main demonstrates and VALIDATES AxonFlow Proxy Mode in Go.
//
// Proxy Mode is the simplest integration pattern:
//   - Send your query to AxonFlow
//   - AxonFlow handles policy enforcement AND LLM routing
//   - Get the response back
//
// No need to manage LLM API keys or audit calls - AxonFlow handles everything.
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Issue #1082: Examples should test actual behavior, not just API availability
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
)

var (
	passCount int
	failCount int
)

func assert(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
		passCount++
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failCount++
	}
}

func main() {
	fmt.Println("AxonFlow Proxy Mode - Go Example")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "proxy-mode-example"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""), // Optional for community mode
	})

	// User token: use JWT from env if available (required in enterprise/evaluation mode)
	userToken := getEnv("AXONFLOW_USER_TOKEN", "user-proxy-go")

	// Example queries
	queries := []struct {
		query       string
		userToken   string
		requestType string
		context     map[string]interface{}
	}{
		{
			query:       "What are the key benefits of AI governance?",
			userToken:   userToken,
			requestType: "chat",
			context:     map[string]interface{}{"department": "engineering"},
		},
		{
			query:       "List 3 principles of responsible AI development.",
			userToken:   userToken,
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
		response, err := client.ProxyLLMCall(
			q.userToken,
			q.query,
			q.requestType,
			q.context,
		)

		latency := time.Since(startTime)

		if err != nil {
			fmt.Printf("\n  Status: ERROR\n")
			fmt.Printf("  Error: %v\n", err)
			failCount++
			continue
		}

		if response.Blocked {
			fmt.Printf("\n  Status: BLOCKED\n")
			fmt.Printf("  Reason: %s\n", response.BlockReason)
			if response.PolicyInfo != nil {
				fmt.Printf("  Policies: %v\n", response.PolicyInfo.PoliciesEvaluated)
			}
		} else {
			// Response received (may be LLM success or provider error)
			assert(response.Data != nil, fmt.Sprintf("Query %d: Response data returned", i+1))
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

	sqlResponse, err := client.ProxyLLMCall(
		userToken,
		"SELECT * FROM users; DROP TABLE secrets;",
		"chat",
		map[string]interface{}{},
	)

	if err != nil {
		// SQLi blocking returns error with HTTP 403
		errStr := err.Error()
		if strings.Contains(errStr, "403") || strings.Contains(errStr, "blocked") {
			assert(true, "SQL injection query blocked with HTTP 403")
			fmt.Printf("\n  Status: BLOCKED (expected)\n")
			fmt.Printf("  Error: %v\n", err)
		} else {
			fmt.Printf("\n  Status: ERROR (unexpected)\n")
			fmt.Printf("  Error: %v\n", err)
			failCount++
		}
	} else if sqlResponse.Blocked {
		assert(true, "SQL injection query blocked")
		fmt.Printf("\n  Status: BLOCKED (expected)\n")
		fmt.Printf("  Reason: %s\n", sqlResponse.BlockReason)
	} else {
		assert(false, "SQL injection query should be blocked")
		fmt.Printf("\n  Status: ALLOWED (unexpected - security issue!)\n")
	}

	// Summary
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Printf("Results: %d PASS, %d FAIL\n", passCount, failCount)
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	if failCount > 0 {
		fmt.Println("SOME TESTS FAILED")
		os.Exit(1)
	} else {
		fmt.Println("ALL TESTS PASSED - Proxy Mode verified!")
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
