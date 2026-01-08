package main

import (
	"fmt"
	"log"
	"os"
	"time"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v2"
)

func main() {
	// Get AxonFlow agent URL from environment
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

	// Complex query that benefits from parallelization
	query := "Plan a 3-day trip to Paris including: (1) round-trip flights from New York, " +
		"(2) hotel recommendations in the city center, and (3) top 5 tourist attractions to visit"

	fmt.Println("📤 Planning trip to Paris...")
	fmt.Println("🔄 MAP will detect independent tasks and execute them in parallel")

	startTime := time.Now()

	// Send query to AxonFlow (uses MAP for parallelization)
	response, err := client.ExecuteQuery(
		"user-123",
		query,
		"multi-agent-plan", // Use MAP for parallel execution
		map[string]interface{}{"provider": "openai"},
	)
	if err != nil {
		log.Fatalf("❌ Query failed: %v", err)
	}

	if !response.Success {
		log.Fatalf("❌ Query failed: %s", response.Error)
	}

	duration := time.Since(startTime)

	// Print results
	fmt.Printf("⏱️  Parallel execution completed in %.1fs\n", duration.Seconds())
	fmt.Println("📥 Trip Plan:")
	fmt.Println(response.Result)
	fmt.Println()
	fmt.Println("✅ Workflow completed successfully")
	fmt.Printf("💡 Tip: MAP automatically parallelized the flight, hotel, and attractions search\n")
}
