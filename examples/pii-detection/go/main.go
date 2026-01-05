// Package main demonstrates AxonFlow's PII detection capabilities.
//
// AxonFlow detects PII and flags it for redaction:
// - US Social Security Numbers (SSN)
// - Credit Card numbers
// - India PAN (Permanent Account Number)
// - India Aadhaar numbers
// - Email addresses
// - Phone numbers
//
// Default Behavior (Issue #891):
//
//	PII detection defaults to "redact" mode - requests are APPROVED but flagged
//	with RequiresRedaction=true for downstream redaction by the Orchestrator.
//	Set PII_ACTION=block to restore blocking behavior.
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
	fmt.Println("Default Mode: redact (PII flagged for redaction, not blocked)")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_AGENT_URL", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "pii-detection-demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo-secret"),
		LicenseKey:   getEnv("AXONFLOW_LICENSE_KEY", ""),
	})

	// PII test cases
	// expectRedact: true = critical PII (RequiresRedaction=true)
	// expectRedact: false = non-critical or no PII (logged but not flagged)
	testCases := []struct {
		name         string
		query        string
		expectRedact bool
	}{
		{
			name:         "Safe Query (No PII)",
			query:        "What is the capital of France?",
			expectRedact: false,
		},
		{
			name:         "US Social Security Number (Critical PII)",
			query:        "Process refund for customer with SSN 123-45-6789",
			expectRedact: true,
		},
		{
			name:         "Credit Card Number (Critical PII)",
			query:        "Charge card 4111-1111-1111-1111 for $99.99",
			expectRedact: true,
		},
		{
			name:         "India PAN (Critical PII)",
			query:        "Verify PAN number ABCDE1234F for tax filing",
			expectRedact: true,
		},
		{
			name:         "India Aadhaar (Critical PII)",
			query:        "Link Aadhaar 2345 6789 0123 to account",
			expectRedact: true,
		},
		{
			name:         "Email Address (Non-Critical PII)",
			query:        "Send invoice to john.doe@gmail.com",
			expectRedact: false, // Medium severity - logged but not flagged
		},
		{
			name:         "Phone Number (Non-Critical PII)",
			query:        "Call customer at +1-555-123-4567",
			expectRedact: false, // Medium severity - logged but not flagged
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

		// Check if request was approved
		if result.Approved {
			if result.RequiresRedaction {
				fmt.Println("  Result: APPROVED (requires redaction)")
			} else {
				fmt.Println("  Result: APPROVED")
			}
			fmt.Printf("  Context ID: %s\n", result.ContextID)
		} else {
			// Request was blocked (only if PII_ACTION=block)
			fmt.Println("  Result: BLOCKED")
			fmt.Printf("  Reason: %s\n", result.BlockReason)
		}

		if len(result.Policies) > 0 {
			fmt.Printf("  Policies: %v\n", result.Policies)
		}

		// Get actual redaction status (blocked also counts as "requires handling")
		actualRequiresRedaction := result.RequiresRedaction || !result.Approved

		// Verify expected behavior
		if tc.expectRedact && actualRequiresRedaction {
			fmt.Println("  Test: PASS (PII detected, flagged for redaction)")
			passed++
		} else if !tc.expectRedact && !actualRequiresRedaction && result.Approved {
			fmt.Println("  Test: PASS (no critical PII detected)")
			passed++
		} else {
			expected := "requires_redaction=true"
			if !tc.expectRedact {
				expected = "no critical PII"
			}
			fmt.Printf("  Test: FAIL (expected %s)\n", expected)
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
	fmt.Println("Configuration:")
	fmt.Println("  - Default: PII_ACTION=redact (PII flagged for redaction, not blocked)")
	fmt.Println("  - To block PII: PII_ACTION=block docker compose up -d")
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
