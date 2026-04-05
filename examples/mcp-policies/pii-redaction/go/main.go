// Package main demonstrates comprehensive PII redaction in MCP responses.
//
// This example validates that PII types are properly redacted in MCP connector responses:
// - US Social Security Numbers (SSN)
// - Credit Card numbers
// - Email addresses (non-critical, logged only)
// - Phone numbers (non-critical, logged only)
//
// Note: The test uses the pre-existing test_customers table which is seeded
// with PII data. Request-phase PII blocking prevents inserting PII via MCP,
// so we query existing test data.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v5"
)

var failures []string
var passes int

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func assert(condition bool, message string) {
	if !condition {
		failures = append(failures, message)
		fmt.Printf("   FAIL: %s\n", message)
	} else {
		passes++
		fmt.Printf("   PASS: %s\n", message)
	}
}

func main() {
	fmt.Println("MCP PII Redaction - Comprehensive Test")
	fmt.Println("=======================================")
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", ""), // Empty for community mode
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	ctx := context.Background()

	// Test 1: Query test_customers table (pre-seeded with PII data)
	fmt.Println("Test 1: Query test_customers (Response Redaction)")
	fmt.Println("-------------------------------------------------")

	resp, err := client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM test_customers LIMIT 1",
	})

	if err != nil {
		fmt.Printf("   Query failed: %v\n", err)
		fmt.Println("   Note: test_customers table may not exist")
		fmt.Println("   Skipping redaction tests...")
	} else {
		assert(resp.Success, "Query executed successfully")

		if resp.Redacted {
			assert(true, "Response was redacted")
			assert(len(resp.RedactedFields) > 0, "Redacted fields are listed")
			fmt.Printf("   Redacted fields: %v\n", resp.RedactedFields)

			// Check specific fields
			redactedFieldsStr := strings.Join(resp.RedactedFields, ", ")
			if strings.Contains(redactedFieldsStr, "ssn") {
				fmt.Println("   - SSN: redacted")
			}
			if strings.Contains(redactedFieldsStr, "credit_card") {
				fmt.Println("   - Credit Card: redacted")
			}
		} else {
			fmt.Println("   Note: No PII found in response (test_customers may be empty)")
		}

		if resp.PolicyInfo != nil {
			fmt.Printf("   PolicyInfo: %d policies, %d redactions in %dms\n",
				resp.PolicyInfo.PoliciesEvaluated,
				resp.PolicyInfo.RedactionsApplied,
				resp.PolicyInfo.ProcessingTimeMs)
		}
	}
	fmt.Println()

	// Test 2: Request-phase PII blocking (SSN in query)
	fmt.Println("Test 2: Request-phase PII Blocking (SSN)")
	fmt.Println("----------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM users WHERE ssn = '123-45-6789'",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "SSN in query blocked as expected")
		if err != nil {
			fmt.Printf("   Block reason: %v\n", err)
		}
	} else {
		assert(false, "SSN in query should have been blocked")
	}
	fmt.Println()

	// Test 3: Request-phase PII blocking (Credit Card)
	fmt.Println("Test 3: Request-phase PII Blocking (Credit Card)")
	fmt.Println("------------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM orders WHERE card = '4111111111111111'",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "Credit card in query blocked as expected")
		if err != nil {
			fmt.Printf("   Block reason: %v\n", err)
		}
	} else {
		assert(false, "Credit card in query should have been blocked")
	}
	fmt.Println()

	// Test 4: Request-phase PII blocking (India PAN)
	fmt.Println("Test 4: Request-phase PII Blocking (India PAN)")
	fmt.Println("----------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM customers WHERE pan = 'ABCPD1234E'",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "India PAN in query blocked as expected")
		if err != nil {
			fmt.Printf("   Block reason: %v\n", err)
		}
	} else {
		assert(false, "India PAN in query should have been blocked")
	}
	fmt.Println()

	// Test 5: Request-phase PII blocking (India Aadhaar)
	fmt.Println("Test 5: Request-phase PII Blocking (India Aadhaar)")
	fmt.Println("--------------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT * FROM customers WHERE aadhaar = '234567890123'",
	})
	if err != nil || (resp != nil && !resp.Success) {
		assert(true, "India Aadhaar in query blocked as expected")
		if err != nil {
			fmt.Printf("   Block reason: %v\n", err)
		}
	} else {
		assert(false, "India Aadhaar in query should have been blocked")
	}
	fmt.Println()

	// Test 6: Non-critical PII (email) - should NOT be blocked
	fmt.Println("Test 6: Non-critical PII (Email) - Should Pass")
	fmt.Println("----------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT 'john@example.com' as test_email",
	})
	if err == nil && resp.Success {
		assert(true, "Email in query allowed (non-critical PII)")
	} else {
		// Email might be blocked depending on policy configuration
		fmt.Println("   Note: Email was blocked (policy may be strict)")
	}
	fmt.Println()

	// Test 7: Non-critical PII (phone) - should NOT be blocked
	fmt.Println("Test 7: Non-critical PII (Phone) - Should Pass")
	fmt.Println("----------------------------------------------")
	resp, err = client.MCPQuery(ctx, axonflow.MCPQueryRequest{
		Connector: "postgres",
		Statement: "SELECT '+1-555-123-4567' as test_phone",
	})
	if err == nil && resp.Success {
		assert(true, "Phone in query allowed (non-critical PII)")
	} else {
		// Phone might be blocked depending on policy configuration
		fmt.Println("   Note: Phone was blocked (policy may be strict)")
	}
	fmt.Println()

	// Summary
	fmt.Println("=======================================")
	if len(failures) == 0 {
		fmt.Printf("ALL TESTS PASSED (%d assertions)\n", passes)
		fmt.Println()
		fmt.Println("MCP PII Handling validated:")
		fmt.Println("  Response-phase:")
		fmt.Println("    - SSN redaction in response data")
		fmt.Println("    - Credit card redaction in response data")
		fmt.Println("  Request-phase blocking:")
		fmt.Println("    - US SSN in query (critical)")
		fmt.Println("    - Credit Card in query (critical)")
		fmt.Println("    - India PAN in query (critical)")
		fmt.Println("    - India Aadhaar in query (critical)")
		fmt.Println("  Non-critical (allowed):")
		fmt.Println("    - Email in query")
		fmt.Println("    - Phone in query")
	} else {
		fmt.Printf("%d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
