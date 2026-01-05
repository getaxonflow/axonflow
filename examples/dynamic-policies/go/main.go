// Dynamic Policy Management Example - Go
//
// Demonstrates CRUD operations for dynamic policies (LLM-powered policies).
// Dynamic policies use conditions and actions to evaluate complex, context-aware
// rules that can't be expressed with simple regex patterns.
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
//   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
//   AXONFLOW_CLIENT_ID     - Client/Tenant ID for policy scoping
//   AXONFLOW_CLIENT_SECRET - Client secret (optional for community mode)

package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	// Initialize client
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo-tenant"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
	})

	fmt.Println("=== Dynamic Policy Management Example ===\n")

	// 1. List existing dynamic policies
	fmt.Println("1. Listing existing dynamic policies...")
	policies, err := client.ListDynamicPolicies(nil)
	if err != nil {
		log.Printf("   Failed to list policies: %v", err)
	} else {
		fmt.Printf("   Found %d dynamic policies\n", len(policies))
		for _, p := range policies {
			fmt.Printf("   - %s: %s (type: %s, enabled: %v)\n", p.ID, p.Name, p.Type, p.Enabled)
		}
	}

	// 2. Create a new dynamic policy
	fmt.Println("\n2. Creating a new dynamic policy...")
	newPolicy := &axonflow.CreateDynamicPolicyRequest{
		Name:        "high-risk-block",
		Description: "Block requests with high risk scores",
		Type:        "risk",
		Category:    "dynamic-risk",
		Conditions: []axonflow.DynamicPolicyCondition{
			{
				Field:    "risk_score",
				Operator: "greater_than",
				Value:    0.8,
			},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type:   "block",
				Config: map[string]interface{}{"reason": "High risk detected"},
			},
		},
		Priority: 100,
		Enabled:  true,
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
			fmt.Printf("   Type: %s\n", policy.Type)
			fmt.Printf("   Priority: %d\n", policy.Priority)
			fmt.Printf("   Conditions: %d\n", len(policy.Conditions))
			fmt.Printf("   Actions: %d\n", len(policy.Actions))
		}
	}

	// 4. Update the policy
	if created != nil {
		fmt.Println("\n4. Updating policy description...")
		newDesc := "Block requests with risk scores above threshold (0.8)"
		update := &axonflow.UpdateDynamicPolicyRequest{
			Description: &newDesc,
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
		toggled, err := client.ToggleDynamicPolicy(created.ID, false)
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
