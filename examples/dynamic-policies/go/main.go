// Dynamic Policy Management Example - Go
//
// Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
// Dynamic policies use an LLM to evaluate complex, context-aware rules that
// can't be expressed with simple regex patterns.
//
// SDK Methods demonstrated:
//   - ListDynamicPolicies()
//   - CreateDynamicPolicy()
//   - GetDynamicPolicy()
//   - UpdateDynamicPolicy()
//   - DeleteDynamicPolicy()
//   - ToggleDynamicPolicy()
//   - GetEffectiveDynamicPolicies()
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_ENDPOINT    - Agent URL (default: http://localhost:8080)
//   AXONFLOW_LICENSE_KEY - Required for dynamic policies

package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Initialize client
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	config := axonflow.Config{
		Endpoint:   endpoint,
		LicenseKey: os.Getenv("AXONFLOW_LICENSE_KEY"),
	}

	client, err := axonflow.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	fmt.Println("=== Dynamic Policy Management Example ===\n")

	// 1. List existing dynamic policies
	fmt.Println("1. Listing existing dynamic policies...")
	policies, err := client.ListDynamicPolicies(nil)
	if err != nil {
		log.Printf("   Failed to list policies: %v", err)
	} else {
		fmt.Printf("   Found %d dynamic policies\n", len(policies))
		for _, p := range policies {
			fmt.Printf("   - %s: %s (enabled: %v)\n", p.ID, p.Name, p.Enabled)
		}
	}

	// 2. Create a new dynamic policy
	fmt.Println("\n2. Creating a new dynamic policy...")
	newPolicy := axonflow.CreateDynamicPolicyRequest{
		Name:        "financial-advice-guard",
		Description: "Block requests that ask for specific financial advice",
		Prompt:      "Evaluate if this request is asking for specific financial advice like stock picks, investment amounts, or trading strategies. If so, block it.",
		Action:      axonflow.ActionBlock,
		Enabled:     true,
		TenantID:    "demo-tenant",
	}

	created, err := client.CreateDynamicPolicy(newPolicy)
	if err != nil {
		log.Printf("   Failed to create policy: %v", err)
	} else {
		fmt.Printf("   Created policy: %s (ID: %s)\n", created.Name, created.ID)
	}

	// 3. Get the policy by ID
	if created != nil {
		fmt.Println("\n3. Getting policy by ID...")
		policy, err := client.GetDynamicPolicy(created.ID)
		if err != nil {
			log.Printf("   Failed to get policy: %v", err)
		} else {
			fmt.Printf("   Policy: %s\n", policy.Name)
			fmt.Printf("   Description: %s\n", policy.Description)
			fmt.Printf("   Prompt: %s\n", policy.Prompt)
			fmt.Printf("   Action: %s\n", policy.Action)
		}
	}

	// 4. Update the policy
	if created != nil {
		fmt.Println("\n4. Updating policy description...")
		update := axonflow.UpdateDynamicPolicyRequest{
			Description: "Block requests asking for specific financial or investment advice",
		}
		updated, err := client.UpdateDynamicPolicy(created.ID, update)
		if err != nil {
			log.Printf("   Failed to update policy: %v", err)
		} else {
			fmt.Printf("   Updated description: %s\n", updated.Description)
		}
	}

	// 5. Toggle policy (disable it)
	if created != nil {
		fmt.Println("\n5. Toggling policy (disabling)...")
		toggled, err := client.ToggleDynamicPolicy(created.ID)
		if err != nil {
			log.Printf("   Failed to toggle policy: %v", err)
		} else {
			fmt.Printf("   Policy enabled: %v\n", toggled.Enabled)
		}
	}

	// 6. Get effective dynamic policies
	fmt.Println("\n6. Getting effective dynamic policies...")
	effective, err := client.GetEffectiveDynamicPolicies(nil)
	if err != nil {
		log.Printf("   Failed to get effective policies: %v", err)
	} else {
		fmt.Printf("   Found %d effective dynamic policies\n", len(effective))
	}

	// 7. Delete the test policy (cleanup)
	if created != nil {
		fmt.Println("\n7. Cleaning up - deleting test policy...")
		err := client.DeleteDynamicPolicy(created.ID)
		if err != nil {
			log.Printf("   Failed to delete policy: %v", err)
		} else {
			fmt.Println("   Policy deleted successfully")
		}
	}

	fmt.Println("\n=== Dynamic Policy Example Complete ===")
}
