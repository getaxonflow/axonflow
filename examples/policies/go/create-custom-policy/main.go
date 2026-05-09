// Package main demonstrates how to create a custom static policy
// using the AxonFlow Go SDK.
//
// Static policies are pattern-based rules that detect:
// - PII (personally identifiable information)
// - SQL injection attempts
// - Sensitive data patterns
//
// VALIDATION: This example exits with code 1 if any assertion fails.
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v8"
)

var failures []string

func assertCheck(condition bool, message string) {
	if condition {
		fmt.Printf("   PASS: %s\n", message)
	} else {
		fmt.Printf("   FAIL: %s\n", message)
		failures = append(failures, message)
	}
}

func main() {
	// Initialize the client
	// For self-hosted Community, no auth needed when running locally
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "test-org-001"
	}
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
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
		assertCheck(false, "Policy created successfully")
		exitWithResults()
	}

	assertCheck(policy.ID != "", "Policy created with ID")
	assertCheck(policy.Name == "Custom Email Pattern", "Policy name matches")
	assertCheck(policy.Category == axonflow.CategoryPIIGlobal, "Policy category matches")
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
		assertCheck(false, "Pattern test succeeded")
		exitWithResults()
	}

	assertCheck(testResult.Valid, "Pattern is valid")
	assertCheck(len(testResult.Matches) == 4, "All test inputs were checked")
	fmt.Printf("   Pattern valid: %v\n", testResult.Valid)
	fmt.Println("\n   Test results:")

	companyMatches := 0
	for _, match := range testResult.Matches {
		icon := "\u2717"
		suffix := ""
		if match.Matched {
			icon = "\u2713"
			suffix = "-> MATCH"
			companyMatches++
		}
		fmt.Printf("   %s \"%s\" %s\n", icon, match.Input, suffix)
	}
	assertCheck(companyMatches == 2, "Pattern correctly matched 2 company.com emails")

	// Retrieve the created policy
	fmt.Println("\n3. Retrieving created policy...")

	retrieved, err := client.GetStaticPolicy(policy.ID)
	if err != nil {
		fmt.Printf("Error retrieving policy: %v\n", err)
		assertCheck(false, "Policy retrieved successfully")
		exitWithResults()
	}

	assertCheck(retrieved.ID == policy.ID, "Retrieved policy ID matches")
	assertCheck(retrieved.Name == policy.Name, "Retrieved policy name matches")
	fmt.Printf("   Retrieved: %s\n", retrieved.Name)
	fmt.Printf("   Version: %d\n", retrieved.Version)

	// Clean up - delete the test policy
	fmt.Println("\n4. Cleaning up (deleting test policy)...")

	err = client.DeleteStaticPolicy(policy.ID)
	if err != nil {
		fmt.Printf("Error deleting policy: %v\n", err)
		assertCheck(false, "Policy deleted successfully")
		exitWithResults()
	}
	assertCheck(true, "Policy deleted successfully")
	fmt.Println("   Deleted successfully")

	fmt.Println("\n" + string(make([]byte, 60)))
	exitWithResults()
}

func exitWithResults() {
	if len(failures) > 0 {
		fmt.Printf("FAILED: %d assertions failed\n", len(failures))
		for _, f := range failures {
			fmt.Printf("  - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL ASSERTIONS PASSED - Policy management verified!")
}
