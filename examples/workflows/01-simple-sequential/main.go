package main

import (
	"fmt"
	"log"
	"os"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Get AxonFlow configuration from environment
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("❌ AXONFLOW_LICENSE_KEY must be set in .env file")
	}

	// Create AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")

	// Define a simple query
	query := "What is the capital of France?"
	fmt.Printf("📤 Sending query: %s\n", query)

	// Send query to AxonFlow
	response, err := client.ExecuteQuery(
		"user-123", // User token
		query,
		"chat", // Request type
		map[string]interface{}{
			"model": "gpt-4",
		},
	)
	if err != nil {
		log.Fatalf("❌ Query failed: %v", err)
	}

	if !response.Success {
		log.Fatalf("❌ Query failed: %s", response.Error)
	}

	// Print response
	fmt.Printf("📥 Response: %v\n", response.Data)
	fmt.Println("✅ Workflow completed successfully")
}
