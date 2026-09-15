// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package main demonstrates and VALIDATES AxonFlow's SQL injection detection.
//
// AxonFlow detects various SQLi patterns:
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
// Expected outcome (v11): the stored policy action decides. Every shipped
// sys_sqli_* policy stores action "warn", so a detected SQLi pattern is
// APPROVED and the matched sys_sqli_* policy id is returned in Policies - the
// detection signal. It is not blocked. To block SQL injection, record an
// organization override of category "sqli" with action "block"
// (PUT /api/v1/detection-posture/sqli on the customer portal API, Enterprise)
// or change the policy's action. This example validates the shipped actions
// with no override recorded; against an org with sqli=block it fails loudly.
// The SQLI_ACTION environment variable no longer sets an action.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v9"
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

// sqliPolicies returns the sys_sqli_* ids among the matched policies.
func sqliPolicies(policies []string) []string {
	var ids []string
	for _, p := range policies {
		if strings.HasPrefix(p, "sys_sqli_") {
			ids = append(ids, p)
		}
	}
	return ids
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

	// SQLi test cases. expectDetected marks the patterns a shipped sys_sqli_*
	// policy matches; with its stored "warn" action they are approved, not blocked.
	testCases := []struct {
		name           string
		query          string
		expectDetected bool
		sqliType       string
	}{
		{
			name:           "Safe Query",
			query:          "Find users who signed up in the last 30 days",
			expectDetected: false,
			sqliType:       "",
		},
		{
			name:           "DROP TABLE",
			query:          "SELECT * FROM users; DROP TABLE users;--",
			expectDetected: true,
			sqliType:       "drop_table",
		},
		{
			name:           "UNION SELECT",
			query:          "Get user where id = 1 UNION SELECT password FROM admin",
			expectDetected: true,
			sqliType:       "union_select",
		},
		{
			name:           "Boolean Injection (OR 1=1)",
			query:          "SELECT * FROM users WHERE username='' OR '1'='1'",
			expectDetected: true,
			sqliType:       "boolean_injection",
		},
		{
			name:           "Comment Injection",
			query:          "SELECT * FROM users WHERE name='admin'-- AND password='secret'",
			expectDetected: false, // Comment injection not currently detected by default policies
			sqliType:       "comment_injection",
		},
		{
			name:           "Stacked Queries",
			query:          "SELECT name FROM users; DELETE FROM audit_log;",
			expectDetected: true,
			sqliType:       "stacked_queries",
		},
		{
			name:           "Truncate Statement",
			query:          "SELECT * FROM data; TRUNCATE TABLE logs;",
			expectDetected: true,
			sqliType:       "truncate",
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
			getEnv("AXONFLOW_USER_TOKEN", "sqli-detection-user"),
			tc.query,
			nil,
			nil,
		)

		if err != nil {
			fmt.Printf("   ❌ FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}

		detected := sqliPolicies(result.Policies)

		// Validate context ID for approved requests (UUID format)
		if result.Approved {
			assert(result.ContextID != "", "ContextID is not empty")
			if len(detected) > 0 {
				fmt.Printf("   Status: APPROVED - SQLi WARNED (%s)\n", strings.Join(detected, ", "))
			} else {
				fmt.Println("   Status: APPROVED")
			}
		} else {
			fmt.Println("   Status: BLOCKED")
			fmt.Printf("   Reason: %s\n", result.BlockReason)
			fmt.Println("   (the shipped sys_sqli_* action is warn; a block means an org sqli=block override or an edited policy action)")
		}

		// Verify expected behavior: the stored "warn" action approves the request
		if tc.expectDetected {
			assert(result.Approved, fmt.Sprintf("SQLi type '%s' is approved with a warning (stored action: warn)", tc.sqliType))
			assert(len(detected) > 0, fmt.Sprintf("SQLi type '%s' is detected (sys_sqli_* policy matched)", tc.sqliType))
		} else if tc.sqliType == "" {
			assert(result.Approved, "Safe query is approved")
			assert(len(detected) == 0, "Safe query matches no sys_sqli_* policy")
		} else {
			assert(result.Approved, fmt.Sprintf("SQLi type '%s' is approved", tc.sqliType))
		}

		fmt.Println()
	}

	fmt.Println("==========================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("SQLi patterns validated:")
		fmt.Println("  - Safe query (approved)")
		fmt.Println("  - DROP TABLE (detected, warned)")
		fmt.Println("  - UNION SELECT (detected, warned)")
		fmt.Println("  - Boolean injection (detected, warned)")
		fmt.Println("  - Comment injection (not detected)")
		fmt.Println("  - Stacked queries (detected, warned)")
		fmt.Println("  - TRUNCATE (detected, warned)")
		fmt.Println()
		fmt.Println("SQL injection warns by default. To block it, record an org override")
		fmt.Println("sqli=block or change the policy action.")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
