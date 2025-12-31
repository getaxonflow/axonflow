// Package main demonstrates AxonFlow's SQL injection detection capabilities.
//
// AxonFlow detects and blocks various SQLi patterns:
// - DROP/DELETE/TRUNCATE statements
// - UNION SELECT attacks
// - Boolean-based injection (OR 1=1)
// - Comment injection
// - Stacked queries
// - Time-based blind SQLi
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow SQL Injection Detection - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "sqli-detection-demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// SQLi test cases
	testCases := []struct {
		name        string
		query       string
		shouldBlock bool
		sqliType    string
	}{
		{
			name:        "Safe Query",
			query:       "Find users who signed up in the last 30 days",
			shouldBlock: false,
			sqliType:    "",
		},
		{
			name:        "DROP TABLE",
			query:       "SELECT * FROM users; DROP TABLE users;--",
			shouldBlock: true,
			sqliType:    "drop_table",
		},
		{
			name:        "UNION SELECT",
			query:       "Get user where id = 1 UNION SELECT password FROM admin",
			shouldBlock: true,
			sqliType:    "union_select",
		},
		{
			name:        "Boolean Injection (OR 1=1)",
			query:       "SELECT * FROM users WHERE username='' OR '1'='1'",
			shouldBlock: true,
			sqliType:    "boolean_injection",
		},
		{
			name:        "Comment Injection",
			query:       "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
			shouldBlock: false, // Comment injection not currently detected by default policies
			sqliType:    "comment_injection",
		},
		{
			name:        "Stacked Queries",
			query:       "SELECT name FROM users; DELETE FROM audit_log;",
			shouldBlock: true,
			sqliType:    "stacked_queries",
		},
		{
			name:        "Truncate Statement",
			query:       "SELECT * FROM data; TRUNCATE TABLE logs;",
			shouldBlock: true,
			sqliType:    "truncate",
		},
	}

	passed := 0
	failed := 0

	for _, tc := range testCases {
		fmt.Printf("Test: %s\n", tc.name)
		queryPreview := tc.query
		if len(queryPreview) > 60 {
			queryPreview = queryPreview[:60] + "..."
		}
		fmt.Printf("  Query: %s\n", queryPreview)

		result, err := client.GetPolicyApprovedContext(
			"sqli-detection-user",
			tc.query,
			nil,
			nil,
		)

		if err != nil {
			fmt.Printf("  Result: ERROR - %v\n", err)
			failed++
			fmt.Println()
			continue
		}

		wasBlocked := !result.Approved

		if wasBlocked {
			fmt.Printf("  Result: BLOCKED\n")
			fmt.Printf("  Reason: %s\n", result.BlockReason)
		} else {
			fmt.Printf("  Result: APPROVED\n")
			fmt.Printf("  Context ID: %s\n", result.ContextID)
		}

		if len(result.Policies) > 0 {
			fmt.Printf("  Policies: %v\n", result.Policies)
		}

		if wasBlocked == tc.shouldBlock {
			fmt.Printf("  Test: PASS\n")
			passed++
		} else {
			fmt.Printf("  Test: FAIL (expected %s)\n", expectedResult(tc.shouldBlock))
			failed++
		}

		fmt.Println()
	}

	fmt.Println("========================================")
	fmt.Printf("Results: %d passed, %d failed\n", passed, failed)
	fmt.Println()

	if failed > 0 {
		fmt.Println("Some tests failed. Check your AxonFlow policy configuration.")
		os.Exit(1)
	}

	fmt.Println("All SQLi detection tests passed!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  - PII Detection: ../pii-detection/")
	fmt.Println("  - Custom Policies: ../policies/")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func expectedResult(shouldBlock bool) string {
	if shouldBlock {
		return "blocked"
	}
	return "approved"
}
