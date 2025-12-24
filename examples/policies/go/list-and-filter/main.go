// Package main demonstrates how to list and filter static policies
// using the AxonFlow Go SDK.
//
// This example shows:
// - List all static policies
// - Filter policies by category, tier, and status
// - Get effective policies with tier inheritance
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL: endpoint,
		ClientID: "test-org-001", // Used as tenant ID
	})

	fmt.Println("AxonFlow Policy Management - List and Filter")
	fmt.Println("============================================================")

	// 1. List all policies
	fmt.Println("\n1. Listing all policies...")

	allPolicies, err := client.ListStaticPolicies(nil)
	if err != nil {
		fmt.Printf("Error listing policies: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Total: %d policies\n", len(allPolicies))

	// Group by category for summary
	byCategory := make(map[string]int)
	for _, p := range allPolicies {
		byCategory[string(p.Category)]++
	}
	fmt.Println("\n   By category:")
	for cat, count := range byCategory {
		fmt.Printf("     %s: %d\n", cat, count)
	}

	// 2. Filter by category - SQL Injection policies
	fmt.Println("\n2. Filtering by category (security-sqli)...")

	sqliPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Category: axonflow.CategorySecuritySQLI,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Found: %d SQLi policies\n", len(sqliPolicies))

	// Show first 3
	for i, p := range sqliPolicies {
		if i >= 3 {
			fmt.Printf("     ... and %d more\n", len(sqliPolicies)-3)
			break
		}
		fmt.Printf("     - %s (severity: %s)\n", p.Name, p.Severity)
	}

	// 3. Filter by tier - System policies
	fmt.Println("\n3. Filtering by tier (system)...")

	systemPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Tier: axonflow.TierSystem,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Found: %d system policies\n", len(systemPolicies))

	// 4. Filter by enabled status
	fmt.Println("\n4. Filtering by enabled status...")

	enabled := true
	enabledPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Enabled: &enabled,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	disabled := false
	disabledPolicies, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Enabled: &disabled,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("   Enabled: %d\n", len(enabledPolicies))
	fmt.Printf("   Disabled: %d\n", len(disabledPolicies))

	// 5. Combine filters
	fmt.Println("\n5. Combining filters (enabled PII policies)...")

	piiEnabled, err := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Category: axonflow.CategoryPIIGlobal,
		Enabled:  &enabled,
	})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Found: %d enabled PII policies\n", len(piiEnabled))

	for i, p := range piiEnabled {
		if i >= 5 {
			break
		}
		pattern := p.Pattern
		if len(pattern) > 40 {
			pattern = pattern[:40] + "..."
		}
		fmt.Printf("     - %s: %s\n", p.Name, pattern)
	}

	// 6. Get effective policies (includes tier inheritance)
	fmt.Println("\n6. Getting effective policies...")

	effective, err := client.GetEffectiveStaticPolicies(nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("   Effective total: %d policies\n", len(effective))

	// Group by tier
	byTier := make(map[string]int)
	for _, p := range effective {
		byTier[string(p.Tier)]++
	}
	fmt.Println("\n   By tier (effective):")
	for tier, count := range byTier {
		fmt.Printf("     %s: %d\n", tier, count)
	}

	// 7. Pagination example
	fmt.Println("\n7. Pagination example...")

	page1, _ := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Limit:  5,
		Offset: 0,
	})

	page2, _ := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		Limit:  5,
		Offset: 5,
	})

	fmt.Printf("   Page 1: %d policies\n", len(page1))
	fmt.Printf("   Page 2: %d policies\n", len(page2))

	// 8. Sorting
	fmt.Println("\n8. Sorting by severity (descending)...")

	bySeverity, _ := client.ListStaticPolicies(&axonflow.ListStaticPoliciesOptions{
		SortBy:    "severity",
		SortOrder: "desc",
		Limit:     5,
	})

	fmt.Println("   Top 5 by severity:")
	for _, p := range bySeverity {
		fmt.Printf("     [%s] %s\n", p.Severity, p.Name)
	}

	fmt.Println("\n============================================================")
	fmt.Println("Example completed successfully!")
}
