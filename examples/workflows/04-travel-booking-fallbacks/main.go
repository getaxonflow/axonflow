package main

import (
	"fmt"
	"log"
	"os"
	"strings"

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
	fmt.Println("📤 Planning trip to Tokyo with intelligent fallbacks...")
	fmt.Println()

	// Track what was booked
	var flightOption, hotelOption string

	// STEP 1: Try direct flights first
	fmt.Println("🔍 Step 1: Searching for direct flights from San Francisco to Tokyo...")
	flightQuery1 := "Find direct flights from San Francisco to Tokyo next month"
	flightResp1, err := client.ExecuteQuery("user-123", flightQuery1, "chat", map[string]interface{}{"provider": "openai"})
	if err != nil {
		log.Fatalf("❌ Flight search failed: %v", err)
	}

	// Check if direct flights available
	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", flightResp1.Data)), "no direct flights") ||
		strings.Contains(strings.ToLower(fmt.Sprintf("%v", flightResp1.Data)), "not available") {
		fmt.Println("⚠️  No direct flights available")
		fmt.Println("📤 Step 2 (Fallback): Trying connecting flights...")

		// Fallback to connecting flights
		flightQuery2 := "Find connecting flights from San Francisco to Tokyo with 1 stop"
		flightResp2, err := client.ExecuteQuery("user-123", flightQuery2, "chat", map[string]interface{}{"provider": "openai"})
		if err != nil {
			log.Fatalf("❌ Fallback flight search failed: %v", err)
		}

		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", flightResp2.Data)), "no flights") {
			fmt.Println("⚠️  No connecting flights available either")
			fmt.Println("💡 Recommendation: Try different dates or airports")
			return
		}

		flightOption = "Connecting flight (1 stop)"
		fmt.Println("✅ Found connecting flight option")
	} else {
		flightOption = "Direct flight"
		fmt.Println("✅ Found direct flight")
	}

	fmt.Println()

	// STEP 2: Try 5-star hotels first
	fmt.Println("🔍 Step 3: Searching for 5-star hotels in Tokyo city center...")
	hotelQuery1 := "Find 5-star hotels in Tokyo Shibuya district"
	hotelResp1, err := client.ExecuteQuery("user-123", hotelQuery1, "chat", map[string]interface{}{"provider": "openai"})
	if err != nil {
		log.Fatalf("❌ Hotel search failed: %v", err)
	}

	// Check if 5-star hotels available
	if strings.Contains(strings.ToLower(fmt.Sprintf("%v", hotelResp1.Data)), "fully booked") ||
		strings.Contains(strings.ToLower(fmt.Sprintf("%v", hotelResp1.Data)), "no availability") {
		fmt.Println("⚠️  5-star hotels fully booked")
		fmt.Println("📤 Step 4 (Fallback): Trying 4-star hotels...")

		// Fallback to 4-star hotels
		hotelQuery2 := "Find 4-star hotels in Tokyo with good reviews"
		hotelResp2, err := client.ExecuteQuery("user-123", hotelQuery2, "chat", map[string]interface{}{"provider": "openai"})
		if err != nil {
			log.Fatalf("❌ Fallback hotel search failed: %v", err)
		}

		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", hotelResp2.Data)), "no availability") {
			fmt.Println("⚠️  4-star hotels also unavailable")
			fmt.Println("💡 Recommendation: Try Airbnb or alternative districts")
			return
		}

		hotelOption = "4-star hotel (fallback)"
		fmt.Println("✅ Found 4-star hotel alternative")
	} else {
		hotelOption = "5-star hotel"
		fmt.Println("✅ Found 5-star hotel")
	}

	fmt.Println()

	// STEP 3: Generate final itinerary
	fmt.Println("📋 Generating complete itinerary with selected options...")
	itineraryQuery := fmt.Sprintf("Create a 7-day Tokyo itinerary with %s and %s accommodation. "+
		"Include top attractions, restaurants, and transportation tips.",
		flightOption, hotelOption)

	itineraryResp, err := client.ExecuteQuery("user-123", itineraryQuery, "chat", map[string]interface{}{"provider": "openai"})
	if err != nil {
		log.Fatalf("❌ Itinerary generation failed: %v", err)
	}

	fmt.Println()
	fmt.Println("📥 Your Tokyo Itinerary:")
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println(itineraryResp.Data)
	fmt.Println("=" + strings.Repeat("=", 60))
	fmt.Println()
	fmt.Println("✅ Travel booking workflow completed successfully!")
	fmt.Printf("💡 Booked: %s + %s\n", flightOption, hotelOption)
}
