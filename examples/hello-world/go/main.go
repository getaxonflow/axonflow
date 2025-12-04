package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/axonflow/axonflow-go"
)

func main() {
	// Initialize AxonFlow client
	client, err := axonflow.NewClient(axonflow.Config{
		Endpoint:           getEnv("AXONFLOW_ENDPOINT", "https://YOUR_AGENT_ENDPOINT"),
		LicenseKey:         getEnv("AXONFLOW_LICENSE_KEY", "YOUR_LICENSE_KEY"),
		OrganizationID:     getEnv("AXONFLOW_ORG_ID", "my-org"),
		InsecureSkipVerify: true, // For self-signed certs in development
	})
	if err != nil {
		log.Fatal("Failed to create client:", err)
	}

	ctx := context.Background()

	fmt.Println("🔌 Connecting to AxonFlow...")

	// Send query with simple policy
	response, err := client.ExecuteQuery(ctx, &axonflow.QueryRequest{
		Query: "What is the capital of France?",
		Policy: `
			package axonflow.policy
			default allow = true
		`,
	})
	if err != nil {
		log.Fatal("❌ Error:", err)
	}

	// Display results
	fmt.Println("✅ Query successful!")
	fmt.Println("Response:", response.Result)
	fmt.Printf("Latency: %dms\n", response.Metadata.LatencyMS)
	fmt.Println("Policy Decision:", response.Metadata.PolicyDecision)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
