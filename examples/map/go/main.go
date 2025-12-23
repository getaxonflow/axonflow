// AxonFlow MAP (Multi-Agent Planning) Example - Go SDK
package main

import (
	"fmt"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	fmt.Println("AxonFlow MAP Example - Go")
	fmt.Println("==================================================")
	fmt.Println()

	// Initialize client - uses environment variables or defaults for self-hosted
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}
	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	if clientID == "" {
		clientID = "demo"
	}
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientSecret == "" {
		clientSecret = "demo"
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Debug:        true,
	})

	// Simple query for testing
	query := "Create a brief plan to greet a new user and ask how to help them"
	domain := "generic"

	fmt.Printf("Query: %s\n", query)
	fmt.Printf("Domain: %s\n", domain)
	fmt.Println("--------------------------------------------------")
	fmt.Println()

	// Generate a plan
	plan, err := client.GeneratePlan(query, domain)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		fmt.Println()
		fmt.Println("==================================================")
		fmt.Println("❌ Go MAP Test: FAIL")
		os.Exit(1)
	}

	fmt.Println("✅ Plan Generated Successfully")
	fmt.Printf("Plan ID: %s\n", plan.PlanID)
	fmt.Printf("Steps: %d\n", len(plan.Steps))

	for i, step := range plan.Steps {
		fmt.Printf("  %d. %s (%s)\n", i+1, step.Name, step.Type)
	}

	fmt.Println()
	fmt.Printf("Metadata: %v\n", plan.Metadata)
	fmt.Println()
	fmt.Println("==================================================")
	fmt.Println("✅ Go MAP Test: PASS")
}
