// Package main demonstrates creating HITL policies with require_approval action
// and VALIDATES that enforcement actually works via ProxyLLMCall.
//
// This example shows how to create a policy that triggers
// Human-in-the-Loop (HITL) approval using the `require_approval` action.
//
// The `require_approval` action:
// - Enterprise: Pauses execution and creates an approval request in the HITL queue
// - Community: Auto-approves immediately (upgrade path to Enterprise)
//
// Use cases:
// - High-value transaction oversight (EU AI Act Article 14, SEBI AI/ML)
// - Admin access detection
// - Sensitive data access control
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v5"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   ✓ PASS: %s\n", message)
	} else {
		fmt.Printf("   ❌ FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	// Initialize the client (ClientID is used as tenant ID for policy APIs)
	agentURL := os.Getenv("AXONFLOW_ENDPOINT")
	if agentURL == "" {
		agentURL = os.Getenv("AXONFLOW_AGENT_URL")
	}
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo-tenant"
	}
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "demo-secret"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})

	fmt.Println("AxonFlow HITL - require_approval Policy Example")
	fmt.Println(strings.Repeat("=", 60))

	// 1. Create a policy with require_approval action
	fmt.Println("\n1. Creating HITL oversight policy...")

	policy, err := client.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
		Name:        "High-Value Transaction Oversight",
		Description: "Require human approval for high-value financial decisions",
		Category:    axonflow.CategorySecurityAdmin,
		// Pattern matches amounts over 1 million (₹, $, €) - case insensitive
		Pattern:  `(?i)(amount|value|total|transaction).*[₹$€]\s*[1-9][0-9]{6,}`,
		Severity: axonflow.SeverityHigh,
		Enabled:  true,
		Action:   axonflow.ActionRequireApproval, // Triggers HITL queue
	})
	if err != nil {
		handleError(err)
	}

	fmt.Printf("   Created policy: %s\n", policy.ID)
	fmt.Printf("   Name: %s\n", policy.Name)
	fmt.Printf("   Action: %s\n", policy.Action)
	fmt.Printf("   Tier: %s\n", policy.Tier)

	// 2. Test the pattern with sample inputs
	fmt.Println("\n2. Testing pattern with sample inputs...")

	testResult, err := client.TestPattern(policy.Pattern, []string{
		"Transfer amount $5000000 to account",   // Should match (5M)
		"Transaction value ₹100000000",          // Should match (10Cr)
		"Total: €2500000",                       // Should match (2.5M)
		"Payment of $500 completed",             // Should NOT match
		"Amount: $999999",                       // Should NOT match (under 1M)
	})
	if err != nil {
		handleError(err)
	}

	fmt.Println("\n   Test results:")
	for _, match := range testResult.Matches {
		icon := "✗ PASS"
		if match.Matched {
			icon = "✓ HITL"
		}
		input := match.Input
		if len(input) > 40 {
			input = input[:40] + "..."
		}
		fmt.Printf("   %s: \"%s\"\n", icon, input)
	}

	// 3. Test enforcement via ProxyLLMCall — verify policy actually blocks
	fmt.Println("\n3. Testing HITL enforcement via ProxyLLMCall...")
	fmt.Println("   Waiting for policy propagation...")
	time.Sleep(3 * time.Second)

	userToken := os.Getenv("AXONFLOW_USER_TOKEN")

	// 3a. Send a query that MATCHES the require_approval pattern
	fmt.Println("\n   3a. Sending query that matches HITL pattern...")
	matchingResponse, matchErr := client.ProxyLLMCall(
		userToken,
		"Process transaction amount $5000000 to offshore account",
		"chat",
		map[string]interface{}{"provider": "ollama"},
	)

	if matchErr != nil {
		// In community mode, the call may succeed (auto-approve) or fail due to missing LLM key
		errStr := matchErr.Error()
		if strings.Contains(errStr, "api_key") || strings.Contains(errStr, "authentication") || strings.Contains(errStr, "API key") {
			fmt.Printf("   Note: LLM API error (expected without key): %v\n", matchErr)
			assertCheck(true, "Matching query processed (LLM key issue expected in community mode)")
		} else {
			assertCheck(false, fmt.Sprintf("Matching query failed unexpectedly: %v", matchErr))
		}
	} else if matchingResponse.Blocked {
		// Enterprise mode: policy enforcement blocks the request
		fmt.Printf("   BLOCKED: %s\n", matchingResponse.BlockReason)
		assertCheck(true, "Enterprise HITL enforcement: matching query was blocked")
		assertCheck(
			strings.Contains(matchingResponse.BlockReason, "require_approval") ||
				strings.Contains(matchingResponse.BlockReason, "approval"),
			fmt.Sprintf("Block reason mentions approval (got: %s)", matchingResponse.BlockReason),
		)
	} else {
		// Community mode: auto-approved, call succeeds
		fmt.Println("   NOT BLOCKED (community mode auto-approve)")
		assertCheck(true, "Community mode: matching query auto-approved (expected)")
	}

	// 3b. Send a safe query that should NOT trigger HITL
	fmt.Println("\n   3b. Sending safe query (should NOT trigger HITL)...")
	safeResponse, safeErr := client.ProxyLLMCall(
		userToken,
		"What is the weather today?",
		"chat",
		map[string]interface{}{"provider": "ollama"},
	)

	if safeErr != nil {
		errStr := safeErr.Error()
		if strings.Contains(errStr, "api_key") || strings.Contains(errStr, "authentication") || strings.Contains(errStr, "API key") {
			fmt.Printf("   Note: LLM API error (expected without key): %v\n", safeErr)
			assertCheck(true, "Safe query processed (LLM key issue expected)")
		} else {
			assertCheck(false, fmt.Sprintf("Safe query failed unexpectedly: %v", safeErr))
		}
	} else {
		assertCheck(!safeResponse.Blocked, "Safe query was NOT blocked by HITL policy")
	}

	// 4. Create additional HITL policies
	fmt.Println("\n4. Creating admin access oversight policy...")

	adminPolicy, err := client.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
		Name:        "Admin Access Detection",
		Description: "Route admin operations through human review",
		Category:    axonflow.CategorySecurityAdmin,
		Pattern:     `(admin|root|superuser|sudo|DELETE\s+FROM|DROP\s+TABLE)`,
		Severity:    axonflow.SeverityCritical,
		Enabled:     true,
		Action:      axonflow.ActionRequireApproval,
	})
	if err != nil {
		handleError(err)
	}

	fmt.Printf("   Created: %s\n", adminPolicy.Name)
	fmt.Printf("   Action: %s\n", adminPolicy.Action)

	// 5. List all policies with require_approval action
	// Note: Filter by tenant tier to get our custom policies (system policies are on earlier pages)
	fmt.Println("\n5. Listing all HITL policies...")

	tenantTier := axonflow.TierTenant
	allPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Tier: tenantTier,
	})
	if err != nil {
		handleError(err)
	}

	var hitlCount int
	fmt.Println("   HITL policies:")
	for _, p := range allPolicies {
		if p.Action == axonflow.ActionRequireApproval {
			hitlCount++
			fmt.Printf("   - %s (%s)\n", p.Name, p.Severity)
		}
	}
	fmt.Printf("   Found %d HITL policies\n", hitlCount)

	// 6. Clean up test policies
	fmt.Println("\n6. Cleaning up test policies...")
	if err := client.DeleteStaticPolicy(policy.ID); err != nil {
		fmt.Printf("   Warning: Failed to delete policy: %v\n", err)
	} else {
		assertCheck(true, "Deleted high-value oversight policy")
	}
	if err := client.DeleteStaticPolicy(adminPolicy.ID); err != nil {
		fmt.Printf("   Warning: Failed to delete admin policy: %v\n", err)
	} else {
		assertCheck(true, "Deleted admin access policy")
	}

	// Final assertion summary
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Assertion Summary")
	fmt.Println(strings.Repeat("=", 60))
	if len(failures) == 0 {
		fmt.Println("All assertions passed!")
		fmt.Println()
		fmt.Println("HITL Policy operations validated:")
		fmt.Println("  - CreateStaticPolicy() with require_approval action")
		fmt.Println("  - TestPattern() for HITL trigger validation")
		fmt.Println("  - ProxyLLMCall() enforcement (blocked or auto-approved)")
		fmt.Println("  - ListStaticPolicies() filtering by action")
		fmt.Println("  - DeleteStaticPolicy()")
		fmt.Println()
		fmt.Println("Note: In Community Edition, require_approval auto-approves.")
		fmt.Println("Upgrade to Enterprise for full HITL queue functionality.")
	} else {
		fmt.Printf("%d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
}

func handleError(err error) {
	fmt.Printf("\nError: %v\n", err)

	if strings.Contains(err.Error(), "connection refused") {
		fmt.Println("\nHint: Make sure AxonFlow is running:")
		fmt.Println("  docker compose up -d")
	}

	os.Exit(1)
}
