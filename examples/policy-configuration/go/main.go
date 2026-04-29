// Package main demonstrates and VALIDATES policy configuration using the pre-check API.
//
// AxonFlow's static policies can be configured using environment variables.
// This example validates the CURRENT configuration by sending test queries through
// the pre-check API (GetPolicyApprovedContext) and checking that the Agent responds
// according to the configured policy actions.
//
// Environment variables (must match Agent-side config):
//
//	PII_ACTION   = block | redact | log  (default: redact)
//	SQLI_ACTION  = block | warn | log    (default: block)
//	GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)
//
// Mode-specific overrides (higher precedence):
//
//	GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION
//
// IMPORTANT: Changing policy behavior requires restarting the AxonFlow Agent with
// different env vars. This example validates behavior for the CURRENT configuration.
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Run with: go run main.go
// Prerequisites: docker compose up -d
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go/v7"
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
	fmt.Println("AxonFlow Per-Mode Policy Configuration - Go SDK")
	fmt.Println("================================================")
	fmt.Println()

	// Read expected policy actions (must match Agent-side config)
	// Pre-check API uses the Gateway engine, so read Gateway-specific overrides first
	piiAction := getEnv("GATEWAY_PII_ACTION", getEnv("PII_ACTION", "redact"))
	sqliAction := getEnv("GATEWAY_SQLI_ACTION", getEnv("SQLI_ACTION", "block"))
	policiesEnabled := getEnv("GATEWAY_STATIC_POLICIES_ENABLED", "true")

	fmt.Printf("Expected PII_ACTION:  %s\n", piiAction)
	fmt.Printf("Expected SQLI_ACTION: %s\n", sqliAction)
	fmt.Printf("Static policies enabled: %s\n", policiesEnabled)
	fmt.Println()

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
	})

	// ---------------------------------------------------------------
	// Test 1: Safe query — should always be approved
	// ---------------------------------------------------------------
	fmt.Println("Test 1: Safe Query (No PII, No SQLi)")
	fmt.Println("-------------------------------------")
	result, err := client.GetPolicyApprovedContext("", "What is the current date?", nil, nil)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Policy check failed: %v\n", err)
		os.Exit(1)
	}
	assert(result.Approved, "Safe query is approved")
	assert(result.ContextID != "", "Context ID is returned")
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 2: PII query (SSN) — behavior depends on PII_ACTION
	// ---------------------------------------------------------------
	fmt.Println("Test 2: PII Query (SSN '123-45-6789')")
	fmt.Println("--------------------------------------")
	fmt.Printf("  Expected action: %s\n", piiAction)
	result, err = client.GetPolicyApprovedContext("", "Process refund for SSN 123-45-6789", nil, nil)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Policy check failed: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(policiesEnabled) == "false" {
		// When static policies are disabled, everything passes through
		assert(result.Approved, "PII query approved (static policies disabled)")
		assert(len(result.Policies) == 0, "No policies matched (static policies disabled)")
	} else {
		switch strings.ToLower(piiAction) {
		case "block":
			assert(!result.Approved, "PII query blocked (PII_ACTION=block)")
			assert(result.BlockReason != "", "Block reason provided")
			fmt.Printf("   Block reason: %s\n", result.BlockReason)
		case "redact":
			// In redact mode, request phase approves but flags PII
			assert(result.Approved, "PII query approved in request phase (PII_ACTION=redact)")
			assert(len(result.Policies) > 0, "PII policies detected")
			fmt.Printf("   Policies: %v\n", result.Policies)
		case "warn":
			assert(result.Approved, "PII query approved (PII_ACTION=warn)")
			assert(len(result.Policies) > 0, "PII policies detected for warning")
		case "log":
			assert(result.Approved, "PII query approved (PII_ACTION=log)")
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 3: SQLi query — behavior depends on SQLI_ACTION
	// ---------------------------------------------------------------
	fmt.Println("Test 3: SQL Injection (UNION SELECT)")
	fmt.Println("-------------------------------------")
	fmt.Printf("  Expected action: %s\n", sqliAction)
	result, err = client.GetPolicyApprovedContext("", "SELECT name FROM employees UNION SELECT password FROM admin", nil, nil)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Policy check failed: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(policiesEnabled) == "false" {
		assert(result.Approved, "SQLi query approved (static policies disabled)")
	} else {
		switch strings.ToLower(sqliAction) {
		case "block":
			assert(!result.Approved, "SQLi query blocked (SQLI_ACTION=block)")
			assert(result.BlockReason != "", "Block reason provided")
			fmt.Printf("   Block reason: %s\n", result.BlockReason)
		case "warn":
			assert(result.Approved, "SQLi query approved with warning (SQLI_ACTION=warn)")
		case "log":
			assert(result.Approved, "SQLi query approved (SQLI_ACTION=log)")
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 4: Credit card PII — validates PII detection breadth
	// ---------------------------------------------------------------
	fmt.Println("Test 4: Credit Card PII")
	fmt.Println("-----------------------")
	result, err = client.GetPolicyApprovedContext("", "Charge card 4111-1111-1111-1111 for $50", nil, nil)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Policy check failed: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(policiesEnabled) == "false" {
		assert(result.Approved, "Credit card query approved (static policies disabled)")
	} else {
		switch strings.ToLower(piiAction) {
		case "block":
			assert(!result.Approved, "Credit card blocked (PII_ACTION=block)")
		case "redact":
			assert(result.Approved, "Credit card approved for redaction (PII_ACTION=redact)")
			assert(len(result.Policies) > 0, "Credit card PII detected")
		case "warn", "log":
			assert(result.Approved, "Credit card approved (PII_ACTION="+piiAction+")")
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------
	fmt.Println("================================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Printf("Policy configuration validated:\n")
		fmt.Printf("  PII_ACTION=%s, SQLI_ACTION=%s, enabled=%s\n", piiAction, sqliAction, policiesEnabled)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
