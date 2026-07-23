// Travel Booking with Fallbacks Workflow Example
//
// VALIDATION: This example exits with code 1 if any assertion fails.
//
// Demonstrates intelligent fallback logic for flight and hotel booking.
package main

import (
	"fmt"
	"os"
	"strings"

	axonflow "github.com/getaxonflow/axonflow-sdk-go/v9"
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
	fmt.Println("Travel Booking with Fallbacks - Go")
	fmt.Println("===================================")
	fmt.Println()

	// Create AxonFlow client (no auth required for community mode)
	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		Endpoint: getEnv("AXONFLOW_ENDPOINT", "http://localhost:8080"),
	})

	// Test 1: Health check
	fmt.Println("Test 1: Health Check")
	fmt.Println("--------------------")
	err := client.HealthCheck()
	assertCheck(err == nil, "Agent is healthy")
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	}
	fmt.Println()

	// Track what was booked and assertions
	var flightOption, hotelOption string

	// Test 2: Search for direct flights
	fmt.Println("Test 2: Direct Flight Search")
	fmt.Println("----------------------------")
	flightQuery1 := "Find direct flights from San Francisco to Tokyo next month"
	fmt.Printf("   Query: %s\n", truncate(flightQuery1, 60))

	flightResp1, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), flightQuery1, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Direct flight search does not return error")
	if err == nil {
		assertCheck(flightResp1.Success, "Direct flight search is successful")
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", flightResp1.Data), 80))

		// Check if direct flights available
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", flightResp1.Data)), "no direct flights") ||
			strings.Contains(strings.ToLower(fmt.Sprintf("%v", flightResp1.Data)), "not available") {
			fmt.Println("   Status: No direct flights, trying fallback...")

			// Fallback to connecting flights
			flightQuery2 := "Find connecting flights from San Francisco to Tokyo with 1 stop"
			flightResp2, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), flightQuery2, "chat", map[string]interface{}{"provider": "openai"})
			assertCheck(err == nil, "Fallback flight search does not return error")
			if err == nil && flightResp2.Success {
				flightOption = "Connecting flight (1 stop)"
				fmt.Println("   Fallback: Found connecting flight option")
			}
		} else {
			flightOption = "Direct flight"
			fmt.Println("   Status: Found direct flight")
		}
	}
	fmt.Println()

	// Test 3: Search for 5-star hotels
	fmt.Println("Test 3: Hotel Search with Fallback")
	fmt.Println("-----------------------------------")
	hotelQuery1 := "Find 5-star hotels in Tokyo Shibuya district"
	fmt.Printf("   Query: %s\n", hotelQuery1)

	hotelResp1, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), hotelQuery1, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "5-star hotel search does not return error")
	if err == nil {
		assertCheck(hotelResp1.Success, "5-star hotel search is successful")
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", hotelResp1.Data), 80))

		// Check if 5-star hotels available
		if strings.Contains(strings.ToLower(fmt.Sprintf("%v", hotelResp1.Data)), "fully booked") ||
			strings.Contains(strings.ToLower(fmt.Sprintf("%v", hotelResp1.Data)), "no availability") {
			fmt.Println("   Status: 5-star hotels full, trying fallback...")

			// Fallback to 4-star hotels
			hotelQuery2 := "Find 4-star hotels in Tokyo with good reviews"
			hotelResp2, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), hotelQuery2, "chat", map[string]interface{}{"provider": "openai"})
			assertCheck(err == nil, "Fallback hotel search does not return error")
			if err == nil && hotelResp2.Success {
				hotelOption = "4-star hotel (fallback)"
				fmt.Println("   Fallback: Found 4-star hotel alternative")
			}
		} else {
			hotelOption = "5-star hotel"
			fmt.Println("   Status: Found 5-star hotel")
		}
	}
	fmt.Println()

	// Test 4: Generate itinerary
	fmt.Println("Test 4: Itinerary Generation")
	fmt.Println("----------------------------")

	// Use defaults if options weren't set
	if flightOption == "" {
		flightOption = "Direct flight"
	}
	if hotelOption == "" {
		hotelOption = "5-star hotel"
	}

	itineraryQuery := fmt.Sprintf("Create a 7-day Tokyo itinerary with %s and %s accommodation. "+
		"Include top attractions, restaurants, and transportation tips.",
		flightOption, hotelOption)
	fmt.Printf("   Query: %s\n", truncate(itineraryQuery, 70))

	itineraryResp, err := client.ProxyLLMCall(getEnv("AXONFLOW_USER_TOKEN", "user-123"), itineraryQuery, "chat", map[string]interface{}{"provider": "openai"})
	assertCheck(err == nil, "Itinerary generation does not return error")
	if err == nil {
		assertCheck(itineraryResp.Success, "Itinerary generation is successful")
		assertCheck(itineraryResp.Data != nil, "Itinerary has data")
		fmt.Printf("   Booked: %s + %s\n", flightOption, hotelOption)
		fmt.Printf("   Response: %v\n", truncate(fmt.Sprintf("%v", itineraryResp.Data), 100))
	}
	fmt.Println()

	// Summary
	fmt.Println("===================================")
	if len(failures) == 0 {
		fmt.Println("✓ ALL TESTS PASSED")
		fmt.Println("Tip: This workflow demonstrates intelligent fallback logic for bookings")
		os.Exit(0)
	} else {
		fmt.Printf("❌ %d TEST(S) FAILED:\n", len(failures))
		for _, f := range failures {
			fmt.Printf("   - %s\n", f)
		}
		os.Exit(1)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}
