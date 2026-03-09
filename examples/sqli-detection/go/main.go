// Package main demonstrates and VALIDATES AxonFlow's SQL injection detection.
//
// AxonFlow detects and blocks various SQLi patterns:
// - DROP/DELETE/TRUNCATE statements
// - UNION SELECT attacks
// - Boolean-based injection (OR 1=1)
// - Comment injection
// - Stacked queries
// - Time-based blind SQLi
//
// VALIDATION: This example exits with code 1 if any assertion fails.
// This ensures CI/CD pipelines catch regressions.
//
// Policy Configuration (env vars):
//
//	SQLI_ACTION - Controls SQLi detection behavior: "block" (default), "warn", or "log"
//
//	When SQLI_ACTION=block: (default) SQLi patterns are blocked
//	When SQLI_ACTION=warn:  SQLi is detected and flagged but NOT blocked
//	When SQLI_ACTION=log:   SQLi is detected and logged only
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v4"
)

var failures []string

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   ❌ FAIL: %s\n", message)
	} else {
		fmt.Printf("   ✓ PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("AxonFlow SQL Injection Detection - Go SDK")
	fmt.Println("==========================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
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

	for i, tc := range testCases {
		fmt.Printf("Test %d: %s\n", i+1, tc.name)
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
			fmt.Printf("   ❌ FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}

		wasBlocked := !result.Approved

		// Validate context ID for approved requests (UUID format)
		if result.Approved {
			assert(result.ContextID != "", "ContextID is not empty")
			fmt.Println("   Status: APPROVED")
		} else {
			fmt.Println("   Status: BLOCKED")
			fmt.Printf("   Reason: %s\n", result.BlockReason)
			assert(result.BlockReason != "", "BlockReason is provided for blocked requests")
		}

		// Verify expected behavior
		if tc.shouldBlock {
			assert(wasBlocked, fmt.Sprintf("SQLi type '%s' is blocked", tc.sqliType))
		} else {
			assert(!wasBlocked, "Safe query is approved")
		}

		fmt.Println()
	}

	// ========================================
	// Policy Configuration Test (SQLI_ACTION)
	// ========================================
	sqliAction := getEnv("SQLI_ACTION", "block")
	fmt.Printf("Policy Config: SQLI_ACTION=%s\n", sqliAction)
	fmt.Println()

	if sqliAction == "warn" {
		fmt.Println("Test (config): SQLI_ACTION=warn - SQLi detected but NOT blocked")
		result, err := client.GetPolicyApprovedContext(
			"sqli-config-test-user",
			"SELECT * FROM users; DROP TABLE users;--",
			nil,
			nil,
		)
		if err != nil {
			fmt.Printf("   FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}
		assert(result.Approved, "SQLI_ACTION=warn: SQLi query is approved (warn only, not blocked)")
		fmt.Println()
	}

	fmt.Println("==========================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("SQLi patterns validated:")
		fmt.Println("  - Safe query (approved)")
		fmt.Println("  - DROP TABLE (blocked)")
		fmt.Println("  - UNION SELECT (blocked)")
		fmt.Println("  - Boolean injection (blocked)")
		fmt.Println("  - Comment injection (not detected)")
		fmt.Println("  - Stacked queries (blocked)")
		fmt.Println("  - TRUNCATE (blocked)")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
