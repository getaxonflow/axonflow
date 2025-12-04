// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// APICallProcessor handles external API calls in workflows
type APICallProcessor struct {
	amadeusClient *AmadeusClient
}

// NewAPICallProcessor creates a new API call processor
func NewAPICallProcessor(amadeusClient *AmadeusClient) *APICallProcessor {
	return &APICallProcessor{
		amadeusClient: amadeusClient,
	}
}

// ExecuteStep executes an API call step
func (p *APICallProcessor) ExecuteStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	provider := step.Provider
	if provider == "" {
		return nil, fmt.Errorf("API call step must specify provider")
	}

	log.Printf("[APICallProcessor] Executing %s API call for step: %s", provider, step.Name)

	// Route to appropriate API provider
	switch provider {
	case "amadeus":
		return p.executeAmadeusCall(ctx, step, input, execution)
	default:
		return nil, fmt.Errorf("unsupported API provider: %s", provider)
	}
}

// Execute Amadeus API call
func (p *APICallProcessor) executeAmadeusCall(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	// Check if Amadeus is configured
	if p.amadeusClient == nil || !p.amadeusClient.IsConfigured() {
		log.Printf("[APICallProcessor] Amadeus not configured, using mock data")
		return p.mockAmadeusResponse(step), nil
	}

	// Extract function to determine API endpoint
	function := step.Function
	if function == "" {
		return nil, fmt.Errorf("amadeus API call must specify function")
	}

	// Route to appropriate Amadeus endpoint
	switch function {
	case "flight-search", "search-flights":
		return p.executeFlightSearch(ctx, step, input, execution)
	default:
		return nil, fmt.Errorf("unsupported Amadeus function: %s", function)
	}
}

// Execute flight search API call
func (p *APICallProcessor) executeFlightSearch(ctx context.Context, step WorkflowStep, input map[string]interface{}, execution *WorkflowExecution) (map[string]interface{}, error) {
	startTime := time.Now()

	// Extract parameters from input and workflow context
	params, err := p.extractFlightSearchParams(input, execution)
	if err != nil {
		return nil, fmt.Errorf("failed to extract flight search parameters: %w", err)
	}

	log.Printf("[APICallProcessor] Searching flights: %s → %s on %s (%d adults)",
		params.OriginLocationCode,
		params.DestinationLocationCode,
		params.DepartureDate,
		params.Adults)

	// Call Amadeus API
	response, err := p.amadeusClient.SearchFlights(ctx, *params)
	if err != nil {
		return nil, fmt.Errorf("amadeus flight search failed: %w", err)
	}

	duration := time.Since(startTime)
	log.Printf("[APICallProcessor] Flight search completed in %s: %d offers found", duration, len(response.Data))

	// Format response for workflow
	output := map[string]interface{}{
		"provider":       "amadeus",
		"function":       "flight-search",
		"offers_count":   len(response.Data),
		"offers":         response.Data,
		"meta":           response.Meta,
		"response_time":  duration.Milliseconds(),
		"status":         "success",
	}

	// Extract top offers for easy access
	if len(response.Data) > 0 {
		topOffers := make([]map[string]interface{}, 0)
		maxOffers := 3
		if len(response.Data) < maxOffers {
			maxOffers = len(response.Data)
		}

		for i := 0; i < maxOffers; i++ {
			offer := response.Data[i]
			topOffers = append(topOffers, map[string]interface{}{
				"id":    offer["id"],
				"price": offer["price"],
				"type":  offer["type"],
			})
		}
		output["top_offers"] = topOffers
	}

	return output, nil
}

// Extract flight search parameters from input
func (p *APICallProcessor) extractFlightSearchParams(input map[string]interface{}, execution *WorkflowExecution) (*FlightSearchParams, error) {
	params := &FlightSearchParams{
		Adults:       1, // Default
		Max:          10, // Default max results
		CurrencyCode: "EUR", // Default currency
	}

	// Try to get destination from workflow input
	destination, ok := execution.Input["destination"]
	if ok {
		if destStr, ok := destination.(string); ok {
			params.DestinationLocationCode = DestinationToIATA(destStr)
		}
	}

	// Try to get origin (default to common European hubs)
	origin, ok := execution.Input["origin"]
	if ok {
		if originStr, ok := origin.(string); ok {
			params.OriginLocationCode = DestinationToIATA(originStr)
		}
	} else {
		// Default origin for EU demo
		params.OriginLocationCode = "FRA" // Frankfurt
	}

	// Try to get departure date
	departureDate, ok := execution.Input["departure_date"]
	if ok {
		if dateStr, ok := departureDate.(string); ok {
			params.DepartureDate = dateStr
		}
	} else {
		// Default to 14 days from now (enough time for planning)
		params.DepartureDate = time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	}

	// Try to get adults count
	if adultsVal, ok := execution.Input["adults"]; ok {
		switch v := adultsVal.(type) {
		case int:
			params.Adults = v
		case float64:
			params.Adults = int(v)
		case string:
			// Try to parse string
			_, _ = fmt.Sscanf(v, "%d", &params.Adults)
		}
	}

	// Validate required fields
	if params.OriginLocationCode == "" {
		return nil, fmt.Errorf("origin location code is required")
	}
	if params.DestinationLocationCode == "" {
		return nil, fmt.Errorf("destination location code is required")
	}
	if params.DepartureDate == "" {
		return nil, fmt.Errorf("departure date is required")
	}

	return params, nil
}

// Mock Amadeus response for when API is not configured
func (p *APICallProcessor) mockAmadeusResponse(step WorkflowStep) map[string]interface{} {
	// Return a realistic mock response structure
	return map[string]interface{}{
		"provider":      "amadeus",
		"function":      step.Function,
		"status":        "mock",
		"offers_count":  3,
		"offers":        []interface{}{},
		"response_time": 150, // Mock 150ms response time
		"message":       "Mock response - Amadeus API not configured. Set AMADEUS_API_KEY and AMADEUS_API_SECRET to use real API.",
	}
}

// Utility: Replace template variables in strings
func (p *APICallProcessor) replaceTemplateVars(template string, input map[string]interface{}, execution *WorkflowExecution) string {
	result := template

	// Replace {{input.key}} variables
	for key, value := range input {
		placeholder := fmt.Sprintf("{{input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}

	// Replace {{workflow.input.key}} variables
	for key, value := range execution.Input {
		placeholder := fmt.Sprintf("{{workflow.input.%s}}", key)
		if str, ok := value.(string); ok {
			result = strings.ReplaceAll(result, placeholder, str)
		}
	}

	// Replace {{steps.stepname.output.key}} variables
	for _, stepExec := range execution.Steps {
		if stepExec.Status == "completed" {
			for key, value := range stepExec.Output {
				placeholder := fmt.Sprintf("{{steps.%s.output.%s}}", stepExec.Name, key)
				if str, ok := value.(string); ok {
					result = strings.ReplaceAll(result, placeholder, str)
				}
			}
		}
	}

	return result
}

// IsHealthy checks if API call processor is healthy
func (p *APICallProcessor) IsHealthy() bool {
	// Processor is always healthy (gracefully degrades to mock when APIs not configured)
	return true
}
