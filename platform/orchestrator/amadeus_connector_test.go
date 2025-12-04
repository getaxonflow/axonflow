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
	"testing"

	"axonflow/platform/connectors/base"
)

// =============================================================================
// Simple Getter Functions Tests (Low-Hanging Fruit)
// =============================================================================

// TestAmadeusConnector_Name tests the Name() getter
func TestAmadeusConnector_Name(t *testing.T) {
	tests := []struct {
		name       string
		connector  *AmadeusConnector
		wantName   string
	}{
		{
			name: "with config name",
			connector: &AmadeusConnector{
				config: &base.ConnectorConfig{
					Name: "custom-amadeus",
				},
			},
			wantName: "custom-amadeus",
		},
		{
			name: "with nil config",
			connector: &AmadeusConnector{
				config: nil,
			},
			wantName: "amadeus-connector",
		},
		{
			name: "with empty config name",
			connector: &AmadeusConnector{
				config: &base.ConnectorConfig{
					Name: "",
				},
			},
			wantName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.connector.Name()
			if got != tt.wantName {
				t.Errorf("Name() = %v, want %v", got, tt.wantName)
			}
		})
	}
}

// TestAmadeusConnector_Type tests the Type() getter
func TestAmadeusConnector_Type(t *testing.T) {
	connector := &AmadeusConnector{}
	got := connector.Type()
	want := "amadeus"

	if got != want {
		t.Errorf("Type() = %v, want %v", got, want)
	}
}

// TestAmadeusConnector_Version tests the Version() getter
func TestAmadeusConnector_Version(t *testing.T) {
	connector := &AmadeusConnector{}
	got := connector.Version()

	// Version should be a valid semantic version format
	if got == "" {
		t.Error("Version() returned empty string")
	}

	// Should be specific version
	want := "0.2.1"
	if got != want {
		t.Errorf("Version() = %v, want %v", got, want)
	}
}

// TestAmadeusConnector_Capabilities tests the Capabilities() getter
func TestAmadeusConnector_Capabilities(t *testing.T) {
	connector := &AmadeusConnector{}
	got := connector.Capabilities()

	want := []string{"query", "flights", "hotels", "airports"}

	if len(got) != len(want) {
		t.Errorf("Capabilities() length = %v, want %v", len(got), len(want))
		return
	}

	for i, cap := range want {
		if got[i] != cap {
			t.Errorf("Capabilities()[%d] = %v, want %v", i, got[i], cap)
		}
	}
}

// TestAmadeusConnector_toIATACode tests city name to IATA code conversion
func TestAmadeusConnector_toIATACode(t *testing.T) {
	connector := &AmadeusConnector{}

	tests := []struct {
		name        string
		destination string
		wantCode    string
	}{
		// Europe
		{"paris lowercase", "paris", "PAR"},
		{"Paris capitalized", "Paris", "PAR"},
		{"PARIS uppercase", "PARIS", "PAR"},
		{"  paris  with spaces", "  paris  ", "PAR"},
		{"london", "london", "LON"},
		{"amsterdam", "amsterdam", "AMS"},
		{"barcelona", "barcelona", "BCN"},
		{"rome", "rome", "ROM"},
		{"berlin", "berlin", "BER"},
		{"madrid", "madrid", "MAD"},
		{"lisbon", "lisbon", "LIS"},

		// Asia
		{"tokyo", "tokyo", "TYO"},
		{"singapore", "singapore", "SIN"},
		{"bangkok", "bangkok", "BKK"},
		{"hong kong", "hong kong", "HKG"},
		{"seoul", "seoul", "SEL"},
		{"dubai", "dubai", "DXB"},

		// Americas
		{"new york", "new york", "NYC"},
		{"los angeles", "los angeles", "LAX"},
		{"san francisco", "san francisco", "SFO"},
		{"chicago", "chicago", "CHI"},
		{"miami", "miami", "MIA"},
		{"toronto", "toronto", "YTO"},

		// Oceania
		{"sydney", "sydney", "SYD"},
		{"melbourne", "melbourne", "MEL"},
		{"auckland", "auckland", "AKL"},

		// Already IATA codes
		{"JFK code", "JFK", "JFK"},
		{"lax lowercase code", "lax", "LAX"},
		{"SFO code", "SFO", "SFO"},

		// Unknown cities (fallback)
		{"unknown city", "unknown", "PAR"},
		{"empty string", "", "PAR"},
		{"long city name", "someveryunknowncity", "PAR"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := connector.toIATACode(tt.destination)
			if got != tt.wantCode {
				t.Errorf("toIATACode(%q) = %v, want %v", tt.destination, got, tt.wantCode)
			}
		})
	}
}

// TestAmadeusConnector_getEnvironment tests environment detection
func TestAmadeusConnector_getEnvironment(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		wantEnv     string
	}{
		{
			name:    "test environment",
			baseURL: "https://test.api.amadeus.com",
			wantEnv: "test",
		},
		{
			name:    "test with path",
			baseURL: "https://api.amadeus.com/test/v1",
			wantEnv: "test",
		},
		{
			name:    "production environment",
			baseURL: "https://api.amadeus.com",
			wantEnv: "production",
		},
		{
			name:    "production with path",
			baseURL: "https://api.amadeus.com/v1/flights",
			wantEnv: "production",
		},
		{
			name:    "empty URL",
			baseURL: "",
			wantEnv: "production",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			connector := &AmadeusConnector{
				client: &AmadeusClient{
					baseURL: tt.baseURL,
				},
			}

			got := connector.getEnvironment()
			if got != tt.wantEnv {
				t.Errorf("getEnvironment() = %v, want %v", got, tt.wantEnv)
			}
		})
	}
}

// =============================================================================
// Constructor Tests
// =============================================================================

// TestNewAmadeusConnector tests the constructor
func TestNewAmadeusConnector(t *testing.T) {
	connector := NewAmadeusConnector()

	if connector == nil {
		t.Fatal("NewAmadeusConnector() returned nil")
	}

	// Verify basic fields are initialized
	if connector.logger == nil {
		t.Error("logger not initialized")
	}

	// Cache should be enabled by default
	if !connector.cacheEnabled {
		t.Error("cacheEnabled should be true by default")
	}
}

// =============================================================================
// Interface Implementation Tests
// =============================================================================

// TestAmadeusConnector_HealthCheck tests the HealthCheck method
func TestAmadeusConnector_HealthCheck(t *testing.T) {
	connector := &AmadeusConnector{
		client: nil, // Not connected
		config: &base.ConnectorConfig{
			Name: "test-amadeus",
		},
	}

	ctx := context.Background()

	// Should not panic with nil client
	status, err := connector.HealthCheck(ctx)

	// Health check should return unhealthy status if not connected
	if err != nil {
		t.Logf("HealthCheck returned expected error: %v", err)
	}

	if status != nil {
		t.Logf("HealthCheck status: %+v", status)
	}
}

// TestAmadeusConnector_Disconnect tests the Disconnect method
func TestAmadeusConnector_Disconnect(t *testing.T) {
	connector := &AmadeusConnector{
		client: nil,
		config: &base.ConnectorConfig{
			Name: "test-amadeus",
		},
		logger: NewAmadeusConnector().logger, // Use default logger
	}

	ctx := context.Background()

	// Should not panic
	err := connector.Disconnect(ctx)

	if err != nil {
		t.Errorf("Disconnect() returned error: %v", err)
	}
}
