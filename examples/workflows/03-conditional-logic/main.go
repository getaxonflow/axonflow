package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go"
)

func main() {
	// Get AxonFlow agent URL from environment
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
		Endpoint:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")

	// Step 1: Search for flights
	searchQuery := "Find round-trip flights from New York to Paris for next week"
	fmt.Println("📤 Searching for flights to Paris...")

	searchResponse, err := client.ExecuteQuery("user-123", searchQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Search failed: %v", err)
	}

	// Step 2: Conditional logic based on search results
	fmt.Println("✅ Received search results")

	if !searchResponse.Success {
		log.Fatalf("❌ Search failed: %s", searchResponse.Error)
	}

	result := fmt.Sprintf("%v", searchResponse.Data)

	// Check if flights were found (simple string check for demo)
	if strings.Contains(strings.ToLower(result), "no flights") ||
		strings.Contains(strings.ToLower(result), "not available") {
		// Fallback path - no flights available
		fmt.Println("⚠️  No flights found for selected dates")
		fmt.Println("💡 Trying alternative dates...")

		altQuery := "Find flights from New York to Paris for the following week instead"
		altResponse, err := client.ExecuteQuery("user-123", altQuery, "chat", map[string]interface{}{"model": "gpt-4"})
		if err != nil {
			log.Fatalf("❌ Alternative search failed: %v", err)
		}

		if !altResponse.Success {
			log.Fatalf("❌ Alternative search failed: %s", altResponse.Error)
		}

		fmt.Println("📥 Alternative Options:")
		fmt.Println(altResponse.Data)
		fmt.Println("✅ Workflow completed with fallback")
		return
	}

	// Success path - flights found
	fmt.Println("💡 Flights found! Analyzing best option...")
	fmt.Println(result)

	// Step 3: Proceed to booking (simplified for demo)
	bookQuery := "Based on the search results above, what would be the recommended booking?"
	fmt.Println("\n📤 Getting booking recommendation...")

	bookResponse, err := client.ExecuteQuery("user-123", bookQuery, "chat", map[string]interface{}{"model": "gpt-4"})
	if err != nil {
		log.Fatalf("❌ Booking recommendation failed: %v", err)
	}

	if !bookResponse.Success {
		log.Fatalf("❌ Booking recommendation failed: %s", bookResponse.Error)
	}

	fmt.Println("📥 Booking Recommendation:")
	fmt.Println(bookResponse.Data)
	fmt.Println("\n✅ Workflow completed successfully")
	fmt.Println("💡 Tip: This example demonstrates if/else branching based on API responses")
}
