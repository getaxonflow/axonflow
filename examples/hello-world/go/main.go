// Package main demonstrates the simplest AxonFlow integration in Go.
//
// This example tests policy evaluation without making LLM calls:
// 1. Safe query - should be approved
// 2. SQL injection - should be blocked
// 3. PII (SSN) - should be blocked
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow Hello World - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// Test cases
	testCases := []struct {
		name     string
		query    string
		expected string
	}{
		{
			name:     "Safe Query",
			query:    "What is the weather today?",
			expected: "approved",
		},
		{
			name:     "SQL Injection",
			query:    "SELECT * FROM users; DROP TABLE users;",
			expected: "blocked",
		},
		{
			name:     "PII (SSN)",
			query:    "Process payment for SSN 123-45-6789",
			expected: "blocked",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("Test: %s\n", tc.name)
		queryPreview := tc.query
		if len(queryPreview) > 50 {
			queryPreview = queryPreview[:50] + "..."
		}
		fmt.Printf("  Query: %s\n\n", queryPreview)

		// Check policy approval
		result, err := client.GetPolicyApprovedContext(
			"hello-world-user", // userToken
			tc.query,           // query
			nil,                // dataSources (optional)
			nil,                // context (optional)
		)

		if err != nil {
			fmt.Printf("  Result: ERROR\n")
			fmt.Printf("  Error: %v\n", err)
		} else if result.Approved {
			fmt.Printf("  Result: APPROVED\n")
			fmt.Printf("  Context ID: %s\n", result.ContextID)
		} else {
			fmt.Printf("  Result: BLOCKED\n")
			fmt.Printf("  Reason: %s\n", result.BlockReason)
		}

		if result != nil && len(result.Policies) > 0 {
			fmt.Printf("  Policies: %v\n", result.Policies)
		}

		// Check if result matches expectation
		actual := "approved"
		if result != nil && !result.Approved {
			actual = "blocked"
		}
		status := "PASS"
		if actual != tc.expected {
			status = "FAIL"
		}
		fmt.Printf("  Test: %s (expected %s)\n\n", status, tc.expected)
	}

	fmt.Println("========================================")
	fmt.Println("Hello World Complete!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  - Gateway Mode: examples/integrations/gateway-mode/")
	fmt.Println("  - Proxy Mode: examples/integrations/proxy-mode/")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
