// Dynamic Policy Management Example - Go
//
// Demonstrates and VALIDATES CRUD operations for dynamic policies.
// Dynamic policies use conditions and actions to evaluate complex, context-aware
// rules that can't be expressed with simple regex patterns.
//
// Issue #1082: Examples should test actual behavior, not just API availability
//
// SDK Methods tested:
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
//
// VALIDATION: This example exits with code 1 if any assertion fails.

package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
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
	// Initialize client
	// Note: Dynamic policies are managed by the orchestrator (port 8081)
	// In production, the agent proxies these requests, but for community mode
	// we connect to the orchestrator directly.
	endpoint := os.Getenv("AXONFLOW_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://localhost:8081" // Orchestrator port for dynamic policies
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo-tenant"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"), // Empty for community mode
	})

	fmt.Println("=== Dynamic Policy Management Example ===\n")

	// 1. List existing dynamic policies
	fmt.Println("1. Listing existing dynamic policies...")
	policies, err := client.ListDynamicPolicies(nil)
	if err != nil {
		fmt.Printf("   ERROR: Failed to list policies: %v\n", err)
		assertCheck(false, "ListDynamicPolicies succeeded")
	} else {
		assertCheck(true, "ListDynamicPolicies succeeded")
		fmt.Printf("   Found %d dynamic policies\n", len(policies))
		for i, p := range policies {
			if i >= 3 {
				fmt.Printf("   ... and %d more\n", len(policies)-3)
				break
			}
			fmt.Printf("   - %s: %s (type: %s)\n", p.ID, p.Name, p.Type)
		}
	}

	// 2. Create a new dynamic policy
	fmt.Println("\n2. Creating a new dynamic policy...")
	newPolicy := &axonflow.CreateDynamicPolicyRequest{
		Name:        fmt.Sprintf("test-high-risk-block-%d", os.Getpid()),
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
		fmt.Printf("   ERROR: Failed to create policy: %v\n", err)
		assertCheck(false, "CreateDynamicPolicy succeeded")
	} else {
		assertCheck(created.ID != "", "Created policy has ID")
		assertCheck(created.Name == newPolicy.Name, "Created policy name matches")
		assertCheck(created.Enabled, "Created policy is enabled")
		fmt.Printf("   Created policy: %s (ID: %s)\n", created.Name, created.ID)
	}

	// 3. Get the policy by ID
	if created != nil {
		fmt.Println("\n3. Getting policy by ID...")
		policy, err := client.GetDynamicPolicy(created.ID)
		if err != nil {
			fmt.Printf("   ERROR: Failed to get policy: %v\n", err)
			assertCheck(false, "GetDynamicPolicy succeeded")
		} else {
			assertCheck(policy.ID == created.ID, "Retrieved policy ID matches")
			assertCheck(policy.Name == created.Name, "Retrieved policy name matches")
			assertCheck(len(policy.Conditions) == 1, "Policy has 1 condition")
			assertCheck(len(policy.Actions) == 1, "Policy has 1 action")
			fmt.Printf("   Retrieved: %s (conditions: %d, actions: %d)\n", policy.Name, len(policy.Conditions), len(policy.Actions))
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
			fmt.Printf("   ERROR: Failed to update policy: %v\n", err)
			assertCheck(false, "UpdateDynamicPolicy succeeded")
		} else {
			assertCheck(updated.Description == newDesc, "Description was updated")
			fmt.Printf("   Updated: %s\n", updated.Description)
		}
	}

	// 5. Toggle policy (disable it)
	if created != nil {
		fmt.Println("\n5. Toggling policy (disabling)...")
		toggled, err := client.ToggleDynamicPolicy(created.ID, false)
		if err != nil {
			fmt.Printf("   ERROR: Failed to toggle policy: %v\n", err)
			assertCheck(false, "ToggleDynamicPolicy succeeded")
		} else {
			assertCheck(!toggled.Enabled, "Policy was disabled")
			fmt.Printf("   Policy enabled: %v\n", toggled.Enabled)
		}
	}

	// 6. Get effective dynamic policies
	fmt.Println("\n6. Getting effective dynamic policies...")
	effective, err := client.GetEffectiveDynamicPolicies(nil)
	if err != nil {
		fmt.Printf("   ERROR: Failed to get effective policies: %v\n", err)
		assertCheck(false, "GetEffectiveDynamicPolicies succeeded")
	} else {
		assertCheck(true, "GetEffectiveDynamicPolicies succeeded")
		fmt.Printf("   Found %d effective dynamic policies\n", len(effective))
	}

	// 7. Delete the test policy (cleanup)
	if created != nil {
		fmt.Println("\n7. Cleaning up - deleting test policy...")
		err := client.DeleteDynamicPolicy(created.ID)
		if err != nil {
			fmt.Printf("   ERROR: Failed to delete policy: %v\n", err)
			assertCheck(false, "DeleteDynamicPolicy succeeded")
		} else {
			assertCheck(true, "Policy deleted successfully")
			fmt.Println("   Policy deleted")
		}
	}

	// Summary
	fmt.Println("\n===========================================")
	if len(failures) > 0 {
		fmt.Printf("\n❌ %d assertion(s) failed:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
	fmt.Println("ALL TESTS PASSED - Dynamic Policy CRUD verified!")
}
