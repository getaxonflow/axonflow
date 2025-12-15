// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"strings"
	"testing"
)

// TestDestinationToIATA verifies city to IATA code conversion
func TestDestinationToIATA(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		expected    string
	}{
		// Europe
		{
			name:        "Paris lowercase",
			destination: "paris",
			expected:    "PAR",
		},
		{
			name:        "Paris uppercase",
			destination: "PARIS",
			expected:    "PAR",
		},
		{
			name:        "Paris mixed case",
			destination: "Paris",
			expected:    "PAR",
		},
		{
			name:        "London",
			destination: "london",
			expected:    "LON",
		},
		{
			name:        "Barcelona",
			destination: "barcelona",
			expected:    "BCN",
		},
		{
			name:        "Amsterdam",
			destination: "amsterdam",
			expected:    "AMS",
		},

		// Asia
		{
			name:        "Tokyo",
			destination: "tokyo",
			expected:    "TYO",
		},
		{
			name:        "Bangkok",
			destination: "bangkok",
			expected:    "BKK",
		},
		{
			name:        "Singapore",
			destination: "singapore",
			expected:    "SIN",
		},
		{
			name:        "Hong Kong",
			destination: "hong kong",
			expected:    "HKG",
		},
		{
			name:        "Hong Kong uppercase",
			destination: "HONG KONG",
			expected:    "HKG",
		},
		{
			name:        "Dubai",
			destination: "dubai",
			expected:    "DXB",
		},

		// Americas
		{
			name:        "New York",
			destination: "new york",
			expected:    "NYC",
		},
		{
			name:        "Los Angeles",
			destination: "los angeles",
			expected:    "LAX",
		},
		{
			name:        "San Francisco",
			destination: "san francisco",
			expected:    "SFO",
		},
		{
			name:        "Chicago",
			destination: "chicago",
			expected:    "CHI",
		},
		{
			name:        "Miami",
			destination: "miami",
			expected:    "MIA",
		},

		// Oceania
		{
			name:        "Sydney",
			destination: "sydney",
			expected:    "SYD",
		},
		{
			name:        "Melbourne",
			destination: "melbourne",
			expected:    "MEL",
		},
		{
			name:        "Auckland",
			destination: "auckland",
			expected:    "AKL",
		},

		// Unknown cities - should use first 3 letters
		{
			name:        "Unknown city - uses first 3 letters",
			destination: "boston",
			expected:    "BOS",
		},
		{
			name:        "Unknown city uppercase",
			destination: "Seattle",
			expected:    "SEA",
		},

		// Edge cases
		{
			name:        "City with special characters",
			destination: "new-york",
			expected:    "NEW", // Hyphen stripped, becomes "newyork" → first 3 letters
		},
		{
			name:        "City with numbers (ignored)",
			destination: "paris123",
			expected:    "PAR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DestinationToIATA(tt.destination)

			if result != tt.expected {
				t.Errorf("DestinationToIATA(%q) = %q, expected %q", tt.destination, result, tt.expected)
			}

			// Verify result is always 3 characters uppercase
			if len(result) != 3 {
				t.Errorf("IATA code should be 3 characters, got %d: %q", len(result), result)
			}

			// Verify all uppercase
			if result != strings.ToUpper(result) {
				t.Errorf("IATA code should be uppercase, got %q", result)
			}
		})
	}
}

// TestDestinationToIATA_EdgeCases verifies edge case handling
func TestDestinationToIATA_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		minLength   int // minimum expected length
	}{
		{
			name:        "Empty string",
			destination: "",
			minLength:   0, // May return empty or default
		},
		{
			name:        "Single character",
			destination: "a",
			minLength:   0, // Too short to generate 3-letter code
		},
		{
			name:        "Two characters",
			destination: "ab",
			minLength:   0, // Too short to generate 3-letter code
		},
		{
			name:        "Three characters",
			destination: "abc",
			minLength:   3,
		},
		{
			name:        "Very long city name",
			destination: "llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch",
			minLength:   3, // Should take first 3 letters
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DestinationToIATA(tt.destination)

			// Just verify it doesn't crash and returns reasonable length
			if tt.minLength > 0 && len(result) < tt.minLength {
				t.Errorf("Expected result length >= %d, got %d: %q", tt.minLength, len(result), result)
			}
		})
	}
}

// TestNewAmadeusClient verifies client creation
func TestNewAmadeusClient(t *testing.T) {
	client := NewAmadeusClient()

	if client == nil {
		t.Fatal("NewAmadeusClient should return non-nil client")
	}

	// Verify client has expected structure
	if client.baseURL == "" {
		t.Error("Client should have a base URL set")
	}

	if client.httpClient == nil {
		t.Error("Client should have an HTTP client initialized")
	}
}

// TestIsConfigured verifies configuration check
func TestIsConfigured(t *testing.T) {
	tests := []struct {
		name     string
		client   *AmadeusClient
		expected bool
	}{
		{
			name: "Configured client",
			client: &AmadeusClient{
				apiKey:    "test-key",
				apiSecret: "test-secret",
			},
			expected: true,
		},
		{
			name: "Missing API key",
			client: &AmadeusClient{
				apiKey:    "",
				apiSecret: "test-secret",
			},
			expected: false,
		},
		{
			name: "Missing API secret",
			client: &AmadeusClient{
				apiKey:    "test-key",
				apiSecret: "",
			},
			expected: false,
		},
		{
			name: "Both missing",
			client: &AmadeusClient{
				apiKey:    "",
				apiSecret: "",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.client.IsConfigured()

			if result != tt.expected {
				t.Errorf("IsConfigured() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
