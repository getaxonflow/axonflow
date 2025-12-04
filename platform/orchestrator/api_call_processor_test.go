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
	"testing"
	"time"
)

func TestAPICallProcessor_IsHealthy(t *testing.T) {
	processor := NewAPICallProcessor(nil)

	if !processor.IsHealthy() {
		t.Error("Expected processor to be healthy")
	}
}

func TestAPICallProcessor_mockAmadeusResponse(t *testing.T) {
	processor := &APICallProcessor{}

	tests := []struct {
		name     string
		step     WorkflowStep
		checkKey string
	}{
		{
			name:     "flight search function",
			step:     WorkflowStep{Function: "searchFlights"},
			checkKey: "function",
		},
		{
			name:     "hotel search function",
			step:     WorkflowStep{Function: "searchHotels"},
			checkKey: "function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.mockAmadeusResponse(tt.step)

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			// Check required fields
			if provider, ok := result["provider"].(string); !ok || provider != "amadeus" {
				t.Error("Expected provider to be 'amadeus'")
			}

			if function, ok := result["function"].(string); !ok || function != tt.step.Function {
				t.Errorf("Expected function to be %q", tt.step.Function)
			}

			if status, ok := result["status"].(string); !ok || status != "mock" {
				t.Error("Expected status to be 'mock'")
			}

			if _, ok := result["message"].(string); !ok {
				t.Error("Expected message field")
			}
		})
	}
}

func TestAPICallProcessor_replaceTemplateVars(t *testing.T) {
	processor := &APICallProcessor{}

	tests := []struct {
		name      string
		template  string
		input     map[string]interface{}
		execution *WorkflowExecution
		expected  string
	}{
		{
			name:     "replace input variables",
			template: "Search for {{input.destination}} flights",
			input: map[string]interface{}{
				"destination": "Paris",
			},
			execution: &WorkflowExecution{},
			expected:  "Search for Paris flights",
		},
		{
			name:     "replace workflow input variables",
			template: "From {{workflow.input.origin}} to {{workflow.input.destination}}",
			input:    map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"origin":      "London",
					"destination": "Tokyo",
				},
			},
			expected: "From London to Tokyo",
		},
		{
			name:     "replace step output variables",
			template: "Based on {{steps.search.output.result}}",
			input:    map[string]interface{}{},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "search",
						Status: "completed",
						Output: map[string]interface{}{
							"result": "flight found",
						},
					},
				},
			},
			expected: "Based on flight found",
		},
		{
			name:     "skip incomplete step outputs",
			template: "Result: {{steps.search.output.result}}",
			input:    map[string]interface{}{},
			execution: &WorkflowExecution{
				Steps: []StepExecution{
					{
						Name:   "search",
						Status: "running",
						Output: map[string]interface{}{
							"result": "partial",
						},
					},
				},
			},
			expected: "Result: {{steps.search.output.result}}", // Unchanged
		},
		{
			name:     "no variables to replace",
			template: "Simple text without variables",
			input:    map[string]interface{}{},
			execution: &WorkflowExecution{},
			expected:  "Simple text without variables",
		},
		{
			name:     "multiple replacements",
			template: "{{input.greeting}} {{input.name}}!",
			input: map[string]interface{}{
				"greeting": "Hello",
				"name":     "World",
			},
			execution: &WorkflowExecution{},
			expected:  "Hello World!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.replaceTemplateVars(tt.template, tt.input, tt.execution)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAPICallProcessor_extractFlightSearchParams(t *testing.T) {
	processor := &APICallProcessor{}

	tests := []struct {
		name        string
		input       map[string]interface{}
		execution   *WorkflowExecution
		expectError bool
		checkField  func(params *FlightSearchParams) bool
	}{
		{
			name:  "basic flight search with destination",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination": "Paris",
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.DestinationLocationCode == "PAR" // Paris maps to PAR
			},
		},
		{
			name:  "with origin and destination",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"origin":      "London",
					"destination": "Tokyo",
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.OriginLocationCode == "LON" &&
					params.DestinationLocationCode == "TYO"
			},
		},
		{
			name:  "with adults as int",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination": "Rome",
					"adults":      2,
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.Adults == 2
			},
		},
		{
			name:  "with adults as float64",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination": "Berlin",
					"adults":      3.0,
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.Adults == 3
			},
		},
		{
			name:  "with adults as string",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination": "Madrid",
					"adults":      "4",
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.Adults == 4
			},
		},
		{
			name:  "with departure date",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination":    "Amsterdam",
					"departure_date": "2025-06-15",
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.DepartureDate == "2025-06-15"
			},
		},
		{
			name:  "missing destination returns error",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"origin": "London",
				},
			},
			expectError: true,
		},
		{
			name:  "default values when not provided",
			input: map[string]interface{}{},
			execution: &WorkflowExecution{
				Input: map[string]interface{}{
					"destination": "New York",
				},
			},
			expectError: false,
			checkField: func(params *FlightSearchParams) bool {
				return params.CurrencyCode == "EUR" &&
					params.Max == 10 &&
					params.Adults == 1 &&
					params.OriginLocationCode == "FRA" // Default origin
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := processor.extractFlightSearchParams(tt.input, tt.execution)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if params == nil {
				t.Fatal("Expected non-nil params")
			}

			if tt.checkField != nil && !tt.checkField(params) {
				t.Error("Field check failed")
			}
		})
	}
}

func TestAPICallProcessor_extractFlightSearchParams_DefaultDate(t *testing.T) {
	processor := &APICallProcessor{}

	execution := &WorkflowExecution{
		Input: map[string]interface{}{
			"destination": "Vienna",
		},
	}

	params, err := processor.extractFlightSearchParams(map[string]interface{}{}, execution)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Default date should be 14 days from now
	expectedDate := time.Now().AddDate(0, 0, 14).Format("2006-01-02")
	if params.DepartureDate != expectedDate {
		t.Errorf("Expected departure date %s, got %s", expectedDate, params.DepartureDate)
	}
}

func TestNewAPICallProcessor(t *testing.T) {
	tests := []struct {
		name   string
		client *AmadeusClient
	}{
		{
			name:   "with nil client",
			client: nil,
		},
		{
			name:   "with client",
			client: &AmadeusClient{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewAPICallProcessor(tt.client)
			if processor == nil {
				t.Fatal("Expected non-nil processor")
			}
		})
	}
}
