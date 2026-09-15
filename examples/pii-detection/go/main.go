// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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
// Default Behavior (v11):
//
// The stored action of each matched PII policy decides. On the request side
// (this pre-check) the shipped SSN, credit card, PAN and Aadhaar policies store
// action_request=warn: the request is APPROVED and the matched policy ids are
// returned with it. Their stored response action is redact, so redaction
// happens on the response side. Environment variables no longer set detection
// actions. To change an outcome, record an organization override (Enterprise
// customer portal: PUT /api/v1/detection-posture/pii {"action":"block"}) or
// change the policy's action.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"

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

func main() {
	fmt.Println("AxonFlow PII Detection - Go SDK")
	fmt.Println("================================")
	fmt.Println()
	fmt.Println("Stored policy actions decide: request-side PII warns (approved, policy recorded)")
	fmt.Println()

	// Initialize AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     getEnv("AXONFLOW_CLIENT_ID", "demo"),
		ClientSecret: getEnv("AXONFLOW_CLIENT_SECRET", "demo"),
		Debug:        getEnv("AXONFLOW_DEBUG", "") == "true",
	})

	// PII test cases
	// expectDetect: true = critical PII (a policy matches; stored request action is warn)
	// expectDetect: false = non-critical or no PII (approved, no redaction flag)
	testCases := []struct {
		name         string
		query        string
		expectDetect bool
	}{
		{
			name:         "Safe Query (No PII)",
			query:        "What is the capital of France?",
			expectDetect: false,
		},
		{
			name:         "US Social Security Number (Critical PII)",
			query:        "Process refund for customer with SSN 123-45-6789",
			expectDetect: true,
		},
		{
			name:         "Credit Card Number (Critical PII)",
			query:        "Charge card 4111-1111-1111-1111 for $99.99",
			expectDetect: true,
		},
		{
			name:         "India PAN (Critical PII)",
			query:        "Verify PAN number ABCPD1234E for tax filing",
			expectDetect: true,
		},
		{
			name:         "India Aadhaar (Critical PII)",
			query:        "Link Aadhaar 2345 6789 0123 to account",
			expectDetect: true,
		},
		{
			name:         "Email Address (Non-Critical PII)",
			query:        "Send invoice to john.doe@gmail.com",
			expectDetect: false, // Medium severity - logged but not flagged
		},
		{
			name:         "Phone Number (Non-Critical PII)",
			query:        "Call customer at +1-555-123-4567",
			expectDetect: false, // Medium severity - logged but not flagged
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
			getEnv("AXONFLOW_USER_TOKEN", "pii-detection-user"),
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
			// Blocked only when an organization override or a policy edit sets block
			fmt.Println("   Status: BLOCKED")
			fmt.Printf("   Reason: %s\n", result.BlockReason)
		}
		if len(result.Policies) > 0 {
			fmt.Printf("   Policies: %v\n", result.Policies)
		}

		// Verify expected behavior against the shipped stored actions
		if tc.expectDetect {
			assert(result.Approved, "Request approved (stored request action is warn, not block)")
			assert(len(result.Policies) > 0, "Critical PII detected (policy matched)")
		} else {
			assert(!result.RequiresRedaction && result.Approved, "No critical PII detected, request approved")
		}

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
