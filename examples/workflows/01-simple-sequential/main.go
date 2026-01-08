package main

import (
	"fmt"
	"log"
	"os"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	// Get AxonFlow configuration from environment
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	clientID := os.Getenv("AXONFLOW_CLIENT_ID")
	clientSecret := os.Getenv("AXONFLOW_CLIENT_SECRET")
	if clientID == "" || clientSecret == "" {
		log.Fatal("AXONFLOW_CLIENT_ID and AXONFLOW_CLIENT_SECRET must be set")
	}

	// Create AxonFlow client
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint:     agentURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
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
		map[string]interface{}{"provider": "openai"},
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
