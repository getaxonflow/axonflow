// Package main demonstrates AxonFlow's PII detection capabilities.
//
// AxonFlow detects and blocks requests containing sensitive PII:
// - US Social Security Numbers (SSN)
// - Credit Card numbers
// - India PAN (Permanent Account Number)
// - India Aadhaar numbers
// - Email addresses
// - Phone numbers
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow PII Detection - Go")
	fmt.Println("========================================")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "pii-detection-demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// PII test cases - each should be blocked
	testCases := []struct {
		name        string
		query       string
		shouldBlock bool
		piiType     string
	}{
		{
			name:        "Safe Query (No PII)",
			query:       "What is the capital of France?",
			shouldBlock: false,
			piiType:     "",
		},
		{
			name:        "US Social Security Number",
			query:       "Process refund for customer with SSN 123-45-6789",
			shouldBlock: true,
			piiType:     "ssn",
		},
		{
			name:        "Credit Card Number",
			query:       "Charge card 4111-1111-1111-1111 for $99.99",
			shouldBlock: true,
			piiType:     "credit_card",
		},
		{
			name:        "India PAN",
			query:       "Verify PAN number ABCDE1234F for tax filing",
			shouldBlock: true,
			piiType:     "pan",
		},
		{
			name:        "India Aadhaar",
			query:       "Link Aadhaar 2345 6789 0123 to account",
			shouldBlock: true,
			piiType:     "aadhaar",
		},
		{
			name:        "Email Address",
			query:       "Send invoice to john.doe@example.com",
			shouldBlock: true,
			piiType:     "email",
		},
		{
			name:        "Phone Number",
			query:       "Call customer at +1-555-123-4567",
			shouldBlock: true,
			piiType:     "phone",
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

		// Check policy approval
		result, err := client.GetPolicyApprovedContext(
			"pii-detection-user",
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

		// Verify expected behavior
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

	fmt.Println("All PII detection tests passed!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  - Custom Policies: ../policies/")
	fmt.Println("  - Code Governance: ../code-governance/")
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
