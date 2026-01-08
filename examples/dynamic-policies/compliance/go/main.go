// Compliance Policy Examples - Go
//
// Demonstrates using allowed_providers in dynamic policies for:
//   - GDPR: EU data sovereignty
//   - HIPAA: Healthcare data protection
//   - RBI: India financial data sovereignty
//
// SDK Methods demonstrated:
//   - CreateDynamicPolicy() with Actions containing allowed_providers config
//   - ListDynamicPolicies()
//   - DeleteDynamicPolicy()
//
// Usage:
//   go run main.go
//
// Environment:
//   AXONFLOW_ENDPOINT      - Agent URL (default: http://localhost:8080)
//   AXONFLOW_CLIENT_ID     - OAuth2 client ID (required for dynamic policies)
//   AXONFLOW_CLIENT_SECRET - OAuth2 client secret (required for dynamic policies)

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

	config := axonflow.AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     os.Getenv("AXONFLOW_CLIENT_ID"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
	}

	client := axonflow.NewClient(config)

	fmt.Println("=== Compliance Policy Examples ===\n")

	var createdPolicies []string

	// 1. GDPR - EU Data Sovereignty
	fmt.Println("1. Creating GDPR policy for EU data sovereignty...")
	gdprPolicy := axonflow.CreateDynamicPolicyRequest{
		Name:        "gdpr-eu-data-sovereignty",
		Description: "Route EU users to EU-hosted LLMs only (GDPR Article 44)",
		Type:        "content",
		Category:    "dynamic-compliance",
		Conditions: []axonflow.DynamicPolicyCondition{
			{Field: "user_region", Operator: "equals", Value: "EU"},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type: "route",
				Config: map[string]interface{}{
					"allowed_providers": []string{"ollama", "azure-eu"},
				},
			},
		},
		Enabled: true,
	}

	created, err := client.CreateDynamicPolicy(&gdprPolicy)
	if err != nil {
		log.Printf("   Failed to create GDPR policy: %v", err)
	} else {
		fmt.Printf("   Created: %s (ID: %s)\n", created.Name, created.ID)
		printAllowedProviders(created.Actions)
		createdPolicies = append(createdPolicies, created.ID)
	}

	// 2. HIPAA - Healthcare Data Protection
	fmt.Println("\n2. Creating HIPAA policy for PHI protection...")
	hipaaPolicy := axonflow.CreateDynamicPolicyRequest{
		Name:        "hipaa-phi-protection",
		Description: "Route PHI queries to local LLM only (HIPAA Safe Harbor)",
		Type:        "content",
		Category:    "dynamic-compliance",
		Conditions: []axonflow.DynamicPolicyCondition{
			{Field: "request_type", Operator: "equals", Value: "healthcare"},
			{Field: "contains_phi", Operator: "equals", Value: true},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type: "route",
				Config: map[string]interface{}{
					"allowed_providers": []string{"ollama"},
				},
			},
		},
		Enabled: true,
	}

	created, err = client.CreateDynamicPolicy(&hipaaPolicy)
	if err != nil {
		log.Printf("   Failed to create HIPAA policy: %v", err)
	} else {
		fmt.Printf("   Created: %s (ID: %s)\n", created.Name, created.ID)
		printAllowedProviders(created.Actions)
		createdPolicies = append(createdPolicies, created.ID)
	}

	// 3. RBI - India Financial Data Sovereignty
	fmt.Println("\n3. Creating RBI policy for financial data sovereignty...")
	rbiPolicy := axonflow.CreateDynamicPolicyRequest{
		Name:        "rbi-financial-data-sovereignty",
		Description: "Route banking queries to India-hosted providers (RBI Data Localization)",
		Type:        "content",
		Category:    "dynamic-compliance",
		Conditions: []axonflow.DynamicPolicyCondition{
			{Field: "request_type", Operator: "equals", Value: "banking"},
			{Field: "user_region", Operator: "equals", Value: "IN"},
		},
		Actions: []axonflow.DynamicPolicyAction{
			{
				Type: "route",
				Config: map[string]interface{}{
					"allowed_providers": []string{"azure-india", "ollama"},
				},
			},
		},
		Enabled: true,
	}

	created, err = client.CreateDynamicPolicy(&rbiPolicy)
	if err != nil {
		log.Printf("   Failed to create RBI policy: %v", err)
	} else {
		fmt.Printf("   Created: %s (ID: %s)\n", created.Name, created.ID)
		printAllowedProviders(created.Actions)
		createdPolicies = append(createdPolicies, created.ID)
	}

	// 4. List all compliance policies
	fmt.Println("\n4. Listing all compliance policies...")
	policies, err := client.ListDynamicPolicies(nil)
	if err != nil {
		log.Printf("   Failed to list policies: %v", err)
	} else {
		complianceCount := 0
		for _, p := range policies {
			if providers := getAllowedProviders(p.Actions); len(providers) > 0 {
				complianceCount++
				fmt.Printf("   - %s: providers=%v\n", p.Name, providers)
			}
		}
		fmt.Printf("   Found %d policies with provider restrictions\n", complianceCount)
	}

	// 5. Cleanup
	fmt.Println("\n5. Cleaning up test policies...")
	for _, id := range createdPolicies {
		if err := client.DeleteDynamicPolicy(id); err != nil {
			log.Printf("   Failed to delete %s: %v", id, err)
		}
	}
	fmt.Printf("   Deleted %d test policies\n", len(createdPolicies))

	fmt.Println("\n=== Compliance Policy Examples Complete ===")
}

// printAllowedProviders extracts and prints allowed_providers from action config
func printAllowedProviders(actions []axonflow.DynamicPolicyAction) {
	for _, action := range actions {
		if action.Config != nil {
			if providers, ok := action.Config["allowed_providers"]; ok {
				fmt.Printf("   Allowed providers: %v\n", providers)
				return
			}
		}
	}
}

// getAllowedProviders extracts allowed_providers from action config
func getAllowedProviders(actions []axonflow.DynamicPolicyAction) []interface{} {
	for _, action := range actions {
		if action.Config != nil {
			if providers, ok := action.Config["allowed_providers"]; ok {
				if providerList, ok := providers.([]interface{}); ok {
					return providerList
				}
			}
		}
	}
	return nil
}
