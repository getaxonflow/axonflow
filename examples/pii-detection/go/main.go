// Package main demonstrates and VALIDATES AxonFlow's PII detection capabilities.
//
// AxonFlow detects PII and flags it for redaction:
// - US Social Security Numbers (SSN)
// - Credit Card numbers
// - India PAN (Permanent Account Number)
// - India Aadhaar numbers
// - Email addresses
// - Phone numbers
//
// VALIDATION: This example exits with code 1 if any assertion fails.
// This ensures CI/CD pipelines catch regressions.
//
// Default Behavior (Issue #891):
//
//	PII detection defaults to "redact" mode - requests are APPROVED but flagged
//	with RequiresRedaction=true for downstream redaction by the Orchestrator.
//	Set PII_ACTION=block to restore blocking behavior.
//
// Policy Configuration (env vars):
//
//	PII_ACTION         - Controls PII detection behavior: "redact" (default), "block", or "log"
//	GATEWAY_PII_ACTION - Same as PII_ACTION but applies only in gateway mode
//
//	When PII_ACTION=block: requests with critical PII are blocked (Approved=false)
//	When PII_ACTION=log:   PII is detected and logged but passes through unmodified
//	When PII_ACTION=redact: (default) PII is flagged for downstream redaction
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go/v2"
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
	fmt.Println("AxonFlow PII Detection - Go SDK")
	fmt.Println("================================")
	fmt.Println()
	fmt.Println("Default Mode: redact (PII flagged for redaction, not blocked)")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
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
			query:        "Verify PAN number ABCPD1234E for tax filing",
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

	for i, tc := range testCases {
		fmt.Printf("Test %d: %s\n", i+1, tc.name)
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
			fmt.Printf("   ❌ FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}

		// Validate context ID (UUID format)
		assert(result.ContextID != "", "ContextID is not empty")

		// Check if request was approved
		if result.Approved {
			if result.RequiresRedaction {
				fmt.Println("   Status: APPROVED (requires redaction)")
			} else {
				fmt.Println("   Status: APPROVED")
			}
		} else {
			// Request was blocked (only if PII_ACTION=block)
			fmt.Println("   Status: BLOCKED")
			fmt.Printf("   Reason: %s\n", result.BlockReason)
		}

		// Get actual redaction status (blocked also counts as "requires handling")
		actualRequiresRedaction := result.RequiresRedaction || !result.Approved

		// Verify expected behavior
		if tc.expectRedact {
			assert(actualRequiresRedaction, "Critical PII detected and flagged for redaction")
		} else {
			assert(!actualRequiresRedaction && result.Approved, "No critical PII detected, request approved")
		}

		fmt.Println()
	}

	// ========================================
	// Policy Configuration Tests (PII_ACTION)
	// ========================================
	piiAction := getEnv("PII_ACTION", "redact")
	fmt.Printf("Policy Config: PII_ACTION=%s\n", piiAction)
	fmt.Println()

	if piiAction == "block" {
		fmt.Println("Test (config): PII_ACTION=block - SSN should be BLOCKED")
		result, err := client.GetPolicyApprovedContext(
			"pii-config-test-user",
			"Customer SSN is 999-88-7777",
			nil,
			nil,
		)
		if err != nil {
			fmt.Printf("   FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}
		assert(!result.Approved, "PII_ACTION=block: SSN query is blocked (not approved)")
		assert(result.BlockReason != "", "PII_ACTION=block: block reason is provided")
		fmt.Println()
	} else if piiAction == "log" {
		fmt.Println("Test (config): PII_ACTION=log - SSN should pass through unmodified")
		result, err := client.GetPolicyApprovedContext(
			"pii-config-test-user",
			"Customer SSN is 999-88-7777",
			nil,
			nil,
		)
		if err != nil {
			fmt.Printf("   FATAL: GetPolicyApprovedContext failed: %v\n", err)
			os.Exit(1)
		}
		assert(result.Approved, "PII_ACTION=log: SSN query is approved (pass-through)")
		assert(!result.RequiresRedaction, "PII_ACTION=log: no redaction required (log only)")
		fmt.Println()
	}

	fmt.Println("================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Println("PII types validated:")
		fmt.Println("  - Safe query (no PII)")
		fmt.Println("  - US SSN (critical)")
		fmt.Println("  - Credit card (critical)")
		fmt.Println("  - India PAN (critical)")
		fmt.Println("  - India Aadhaar (critical)")
		fmt.Println("  - Email (non-critical)")
		fmt.Println("  - Phone (non-critical)")
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
