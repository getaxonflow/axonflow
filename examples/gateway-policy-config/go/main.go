// Package main demonstrates and VALIDATES per-mode Gateway policy configuration.
//
// AxonFlow's static policies can be configured per-mode using environment variables.
// This example validates the CURRENT configuration by sending test queries through
// the Gateway mode API and checking that the Agent responds according to the
// configured policy actions.
//
// Environment variables (must match Agent-side config):
//
//	GATEWAY_PII_ACTION   = block | redact | log  (default: redact)
//	GATEWAY_SQLI_ACTION  = block | warn | log    (default: block)
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
	fmt.Println("AxonFlow Gateway Policy Configuration - Go SDK")
	fmt.Println("===============================================")
	fmt.Println()

	// Read expected policy actions
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
	// Test 1: Safe query — always approved
	// ---------------------------------------------------------------
	fmt.Println("Test 1: Safe Query Pre-Check")
	fmt.Println("----------------------------")
	result, err := client.GetPolicyApprovedContext(
		"",
		"What are the best practices for deploying AI models?",
		nil, nil,
	)
	if err != nil {
		fmt.Printf("   ❌ FATAL: GetPolicyApprovedContext failed: %v\n", err)
		os.Exit(1)
	}
	assert(result.Approved, "Safe query is approved")
	assert(result.ContextID != "", "Context ID returned")
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 2: PII query (SSN) — depends on GATEWAY_PII_ACTION
	// ---------------------------------------------------------------
	fmt.Println("Test 2: PII Query (SSN '123-45-6789')")
	fmt.Println("--------------------------------------")
	fmt.Printf("  Expected action: %s\n", piiAction)
	result, err = client.GetPolicyApprovedContext(
		"",
		"Look up the customer with SSN 123-45-6789 and return their balance",
		nil, nil,
	)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Pre-check failed: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(policiesEnabled) == "false" {
		assert(result.Approved, "PII approved (static policies disabled)")
		assert(len(result.Policies) == 0, "No policies matched (disabled)")
	} else {
		switch strings.ToLower(piiAction) {
		case "block":
			assert(!result.Approved, "PII blocked (GATEWAY_PII_ACTION=block)")
			assert(result.BlockReason != "", "Block reason provided")
			fmt.Printf("   Block reason: %s\n", result.BlockReason)
		case "redact":
			assert(result.Approved, "PII approved for redaction (GATEWAY_PII_ACTION=redact)")
			assert(len(result.Policies) > 0, "PII policies detected")
			fmt.Printf("   Policies: %v\n", result.Policies)
		case "warn":
			assert(result.Approved, "PII approved with warning (GATEWAY_PII_ACTION=warn)")
			assert(len(result.Policies) > 0, "PII policies detected")
		case "log":
			assert(result.Approved, "PII approved (GATEWAY_PII_ACTION=log)")
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 3: SQLi query — depends on GATEWAY_SQLI_ACTION
	// ---------------------------------------------------------------
	fmt.Println("Test 3: SQLi Query (UNION SELECT)")
	fmt.Println("----------------------------------")
	fmt.Printf("  Expected action: %s\n", sqliAction)
	result, err = client.GetPolicyApprovedContext(
		"",
		"Run this: SELECT name FROM users UNION SELECT password FROM admin_users",
		nil, nil,
	)
	if err != nil {
		fmt.Printf("   ❌ FATAL: Pre-check failed: %v\n", err)
		os.Exit(1)
	}

	if strings.ToLower(policiesEnabled) == "false" {
		assert(result.Approved, "SQLi approved (static policies disabled)")
	} else {
		switch strings.ToLower(sqliAction) {
		case "block":
			assert(!result.Approved, "SQLi blocked (GATEWAY_SQLI_ACTION=block)")
			assert(result.BlockReason != "", "Block reason provided")
			fmt.Printf("   Block reason: %s\n", result.BlockReason)
		case "warn":
			assert(result.Approved, "SQLi approved with warning (GATEWAY_SQLI_ACTION=warn)")
		case "log":
			assert(result.Approved, "SQLi approved (GATEWAY_SQLI_ACTION=log)")
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 4: ProxyLLMCall — end-to-end governed LLM call
	// ---------------------------------------------------------------
	fmt.Println("Test 4: ProxyLLMCall (End-to-End)")
	fmt.Println("---------------------------------")
	llmResp, err := client.ProxyLLMCall(
		"",
		"Explain cloud computing in one sentence.",
		"chat",
		nil,
	)
	if err != nil {
		fmt.Printf("   ❌ FATAL: ProxyLLMCall failed: %v\n", err)
		os.Exit(1)
	}
	assert(llmResp.Success, "ProxyLLMCall succeeded")
	assert(!llmResp.Blocked, "Safe LLM call was not blocked")
	assert(llmResp.Result != "", "LLM response is not empty")
	fmt.Printf("   Response: %.80s...\n", llmResp.Result)
	fmt.Println()

	// ---------------------------------------------------------------
	// Summary
	// ---------------------------------------------------------------
	fmt.Println("===============================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println()
		fmt.Printf("Gateway policy config validated:\n")
		fmt.Printf("  PII_ACTION=%s, SQLI_ACTION=%s, enabled=%s\n", piiAction, sqliAction, policiesEnabled)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
