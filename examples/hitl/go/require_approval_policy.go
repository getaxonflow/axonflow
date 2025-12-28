// Package main demonstrates creating HITL policies with require_approval action.
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
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize the client (ClientID is used as tenant ID for policy APIs)
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
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
		AgentURL:     agentURL,
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
		// Pattern matches amounts over 1 million (₹, $, €)
		Pattern:  `(amount|value|total|transaction).*[₹$€]\s*[1-9][0-9]{6,}`,
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
		"Transfer amount $5,000,000 to account", // Should match (5M)
		"Transaction value ₹10,00,00,000",       // Should match (10Cr)
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

	// 3. Create additional HITL policies
	fmt.Println("\n3. Creating admin access oversight policy...")

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

	// 4. List all policies with require_approval action
	// Note: Filter by tenant tier to get our custom policies (system policies are on earlier pages)
	fmt.Println("\n4. Listing all HITL policies...")

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

	// 5. Clean up test policies
	fmt.Println("\n5. Cleaning up test policies...")
	if err := client.DeleteStaticPolicy(policy.ID); err != nil {
		handleError(err)
	}
	if err := client.DeleteStaticPolicy(adminPolicy.ID); err != nil {
		handleError(err)
	}
	fmt.Println("   Deleted test policies")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Example completed successfully!")
	fmt.Println("\nNote: In Community Edition, require_approval auto-approves.")
	fmt.Println("Upgrade to Enterprise for full HITL queue functionality.")
}

func handleError(err error) {
	fmt.Printf("\nError: %v\n", err)

	if strings.Contains(err.Error(), "connection refused") {
		fmt.Println("\nHint: Make sure AxonFlow is running:")
		fmt.Println("  docker compose up -d")
	}

	os.Exit(1)
}
