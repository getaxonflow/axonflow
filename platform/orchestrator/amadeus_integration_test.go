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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestAmadeusClientSearchFlights tests flight search with mock HTTP server
func TestAmadeusClientSearchFlights(t *testing.T) {
	// Create unified mock Amadeus server (handles both auth and API calls)
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token request
		if r.URL.Path == "/v1/security/oauth2/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock_token",
				"expires_in":   1800,
			})
			return
		}

		// Handle flight search request
		if r.URL.Path == "/v2/shopping/flight-offers" {
			// Verify authentication header
			auth := r.Header.Get("Authorization")
			if auth != "Bearer mock_token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Return mock flight data
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"id":    "1",
						"price": map[string]interface{}{"total": "299.99"},
					},
					{
						"id":    "2",
						"price": map[string]interface{}{"total": "349.99"},
					},
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer apiServer.Close()

	// Create client with mock servers (override baseURL to point to mock)
	client := &AmadeusClient{
		apiKey:     "test_key",
		apiSecret:  "test_secret",
		baseURL:    apiServer.URL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	// Test successful flight search
	params := FlightSearchParams{
		OriginLocationCode:      "NYC",
		DestinationLocationCode: "LAX",
		DepartureDate:           "2025-12-01",
		Adults:                  1,
		Max:                     5,
	}

	ctx := context.Background()
	result, err := client.SearchFlights(ctx, params)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Verify result contains flight data
	if len(result.Data) != 2 {
		t.Errorf("Expected 2 flights, got %d", len(result.Data))
	}
}

// TestAmadeusClientSearchFlightsAuthFailure tests auth failure handling
func TestAmadeusClientSearchFlightsAuthFailure(t *testing.T) {
	// Create mock server that returns 401
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_client",
		})
	}))
	defer server.Close()

	client := &AmadeusClient{
		apiKey:     "invalid_key",
		apiSecret:  "invalid_secret",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	params := FlightSearchParams{
		OriginLocationCode:      "NYC",
		DestinationLocationCode: "LAX",
		DepartureDate:           "2025-12-01",
	}

	ctx := context.Background()
	_, err := client.SearchFlights(ctx, params)

	if err == nil {
		t.Error("Expected error for auth failure, got nil")
	}
}

// TestAmadeusClientNotConfigured tests behavior when credentials are missing
func TestAmadeusClientNotConfigured(t *testing.T) {
	client := &AmadeusClient{
		apiKey:     "",
		apiSecret:  "",
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	if client.IsConfigured() {
		t.Error("Expected IsConfigured() to return false when credentials missing")
	}

	params := FlightSearchParams{
		OriginLocationCode:      "NYC",
		DestinationLocationCode: "LAX",
		DepartureDate:           "2025-12-01",
	}

	ctx := context.Background()
	_, err := client.SearchFlights(ctx, params)

	if err == nil {
		t.Error("Expected error when API not configured, got nil")
	}
}

// TestAmadeusClientGetAccessToken tests OAuth token retrieval
func TestAmadeusClientGetAccessToken(t *testing.T) {
	// Create mock OAuth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/security/oauth2/token" {
			// Verify request method and content type
			if r.Method != http.MethodPost {
				t.Errorf("Expected POST, got %s", r.Method)
			}

			if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("Expected application/x-www-form-urlencoded content type")
			}

			// Return mock token
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test_access_token_12345",
				"expires_in":   1800,
				"token_type":   "Bearer",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := &AmadeusClient{
		apiKey:     "test_api_key",
		apiSecret:  "test_api_secret",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	ctx := context.Background()
	token, err := client.getAccessToken(ctx)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if token != "test_access_token_12345" {
		t.Errorf("Expected token 'test_access_token_12345', got %q", token)
	}
}

// TestAmadeusClientGetAccessTokenNetworkError tests network error handling
func TestAmadeusClientGetAccessTokenNetworkError(t *testing.T) {
	client := &AmadeusClient{
		apiKey:     "test_key",
		apiSecret:  "test_secret",
		baseURL:    "http://invalid-url-that-does-not-exist.local:9999",
		httpClient: &http.Client{Timeout: 1 * time.Second},
	}

	ctx := context.Background()
	_, err := client.getAccessToken(ctx)

	if err == nil {
		t.Error("Expected network error, got nil")
	}
}

// TestAmadeusClientGetAccessTokenInvalidJSON tests invalid JSON response handling
func TestAmadeusClientGetAccessTokenInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("invalid json response"))
	}))
	defer server.Close()

	client := &AmadeusClient{
		apiKey:     "test_key",
		apiSecret:  "test_secret",
		baseURL:    server.URL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}

	ctx := context.Background()
	_, err := client.getAccessToken(ctx)

	if err == nil {
		t.Error("Expected JSON parsing error, got nil")
	}
}
