// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package main demonstrates and VALIDATES per-mode Gateway policy configuration.
//
// This example sends test queries through the Gateway mode API and checks that the
// Agent responds according to the shipped policy actions.
//
// v11: the stored policy action decides. GATEWAY_PII_ACTION, GATEWAY_SQLI_ACTION,
// PII_ACTION and SQLI_ACTION no longer set an action (ignored, with a boot WARN).
// The shipped request-phase actions exercised here:
//
//	sys_pii_ssn = warn (approved, policy id in Policies)
//	sys_sqli_*  = warn (approved, policy id in Policies)
//
// To change an outcome, record an organization override (customer portal API,
// Enterprise: PUT /api/v1/detection-posture/{pii|sqli} with {"action":"block"})
// or change the policy's action. This example validates the shipped actions with
// no override recorded.
//
// Still read from the environment (a non-action knob, must match Agent config):
//
//	GATEWAY_STATIC_POLICIES_ENABLED = true | false (default: true)
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

// hasPolicyPrefix reports whether any matched policy id starts with prefix.
func hasPolicyPrefix(policies []string, prefix string) bool {
	for _, p := range policies {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func main() {
	fmt.Println("AxonFlow Gateway Policy Configuration - Go SDK")
	fmt.Println("===============================================")
	fmt.Println()

	// Detection actions come from the stored policy rows (no org override
	// recorded), not from the environment.
	policiesEnabled := getEnv("GATEWAY_STATIC_POLICIES_ENABLED", "true")

	fmt.Println("Expected actions: shipped stored actions (PII warn at request phase, SQLi warn)")
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
	// Test 2: PII query (SSN) — sys_pii_ssn stores warn for the request phase
	// ---------------------------------------------------------------
	fmt.Println("Test 2: PII Query (SSN '123-45-6789')")
	fmt.Println("--------------------------------------")
	fmt.Println("  Expected action: warn (stored)")
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
		// warn approves the request and reports the matched policy
		assert(result.Approved, "PII approved with a warning (stored action: warn)")
		assert(hasPolicyPrefix(result.Policies, "sys_pii_"), "PII policy detected (sys_pii_* in Policies)")
		fmt.Printf("   Policies: %v\n", result.Policies)
		if !result.Approved {
			fmt.Printf("   Block reason: %s (an org pii=block override or an edited policy action is in force)\n", result.BlockReason)
		}
	}
	fmt.Println()

	// ---------------------------------------------------------------
	// Test 3: SQLi query — every sys_sqli_* policy stores warn
	// ---------------------------------------------------------------
	fmt.Println("Test 3: SQLi Query (UNION SELECT)")
	fmt.Println("----------------------------------")
	fmt.Println("  Expected action: warn (stored)")
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
		// SQL injection warns by default; it is not blocked
		assert(result.Approved, "SQLi approved with a warning (stored action: warn)")
		assert(hasPolicyPrefix(result.Policies, "sys_sqli_"), "SQLi policy detected (sys_sqli_* in Policies)")
		fmt.Printf("   Policies: %v\n", result.Policies)
		if !result.Approved {
			fmt.Printf("   Block reason: %s (an org sqli=block override or an edited policy action is in force)\n", result.BlockReason)
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
		fmt.Printf("  shipped stored actions (PII warn, SQLi warn), enabled=%s\n", policiesEnabled)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}
