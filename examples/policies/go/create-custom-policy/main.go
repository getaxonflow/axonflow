// Package main demonstrates how to create a custom static policy
// using the AxonFlow Go SDK.
//
// Static policies are pattern-based rules that detect:
// - PII (personally identifiable information)
// - SQL injection attempts
// - Sensitive data patterns
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize the client
	// For self-hosted Community, no auth needed when running locally
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL: endpoint,
		ClientID: "test-org-001", // Used as tenant ID
	})

	fmt.Println("AxonFlow Policy Management - Create Custom Policy")
	fmt.Println(string(make([]byte, 60)))

	// Create a custom PII detection policy
	// This policy detects email addresses from a specific domain
	fmt.Println("\n1. Creating custom email detection policy...")

	policy, err := client.CreateStaticPolicy(&axonflow.CreateStaticPolicyRequest{
		Name:        "Custom Email Pattern",
		Description: "Detects email addresses in specific company format",
		Category:    axonflow.CategoryPIIGlobal,
		Pattern:     `[a-zA-Z0-9._%+-]+@company\.com`,
		Severity:    axonflow.SeverityMedium,
		Action:      axonflow.ActionBlock,
		Enabled:     true,
	})
	if err != nil {
		fmt.Printf("Error creating policy: %v\n", err)
		if os.IsTimeout(err) || err.Error() == "connection refused" {
			fmt.Println("\nHint: Make sure AxonFlow is running:")
			fmt.Println("  docker compose up -d")
		}
		os.Exit(1)
	}

	fmt.Printf("   Created policy: %s\n", policy.ID)
	fmt.Printf("   Name: %s\n", policy.Name)
	fmt.Printf("   Tier: %s\n", policy.Tier) // Will be 'tenant' for custom policies
	fmt.Printf("   Category: %s\n", policy.Category)
	fmt.Printf("   Pattern: %s\n", policy.Pattern)

	// Test the pattern before using in production
	fmt.Println("\n2. Testing the pattern...")

	testResult, err := client.TestPattern(
		policy.Pattern,
		[]string{"john@company.com", "jane@gmail.com", "test@company.com", "invalid-email"},
	)
	if err != nil {
		fmt.Printf("Error testing pattern: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Pattern valid: %v\n", testResult.Valid)
	fmt.Println("\n   Test results:")

	for _, match := range testResult.Matches {
		icon := "\u2717"
		suffix := ""
		if match.Matched {
			icon = "\u2713"
			suffix = "-> MATCH"
		}
		fmt.Printf("   %s \"%s\" %s\n", icon, match.Input, suffix)
	}

	// Retrieve the created policy
	fmt.Println("\n3. Retrieving created policy...")

	retrieved, err := client.GetStaticPolicy(policy.ID)
	if err != nil {
		fmt.Printf("Error retrieving policy: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Retrieved: %s\n", retrieved.Name)
	fmt.Printf("   Version: %d\n", retrieved.Version)

	// Clean up - delete the test policy
	fmt.Println("\n4. Cleaning up (deleting test policy)...")

	err = client.DeleteStaticPolicy(policy.ID)
	if err != nil {
		fmt.Printf("Error deleting policy: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("   Deleted successfully")

	fmt.Println("\n" + string(make([]byte, 60)))
	fmt.Println("Example completed successfully!")
}
