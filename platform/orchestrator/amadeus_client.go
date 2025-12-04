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

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// AmadeusClient handles authentication and API calls to Amadeus
type AmadeusClient struct {
	apiKey      string
	apiSecret   string
	baseURL     string
	accessToken string
	tokenExpiry time.Time
	httpClient  *http.Client
	mu          sync.RWMutex
}

// AmadeusTokenResponse represents OAuth token response
type AmadeusTokenResponse struct {
	Type        string `json:"type"`
	Username    string `json:"username"`
	AppName     string `json:"application_name"`
	ClientID    string `json:"client_id"`
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
}

// FlightSearchParams represents flight search parameters
type FlightSearchParams struct {
	OriginLocationCode      string `json:"originLocationCode"`
	DestinationLocationCode string `json:"destinationLocationCode"`
	DepartureDate           string `json:"departureDate"`
	Adults                  int    `json:"adults"`
	Max                     int    `json:"max,omitempty"`
	CurrencyCode            string `json:"currencyCode,omitempty"`
}

// FlightOffer represents a flight offer from Amadeus
type FlightOffer struct {
	ID    string                 `json:"id"`
	Type  string                 `json:"type"`
	Price map[string]interface{} `json:"price"`
	Data  map[string]interface{} `json:"itineraries"`
}

// FlightSearchResponse represents Amadeus flight search response
type FlightSearchResponse struct {
	Data []map[string]interface{} `json:"data"`
	Meta map[string]interface{}   `json:"meta,omitempty"`
}

// NewAmadeusClient creates a new Amadeus API client
func NewAmadeusClient() *AmadeusClient {
	apiKey := os.Getenv("AMADEUS_API_KEY")
	apiSecret := os.Getenv("AMADEUS_API_SECRET")
	env := os.Getenv("AMADEUS_ENV") // "test" or "production"

	if env == "" {
		env = "test"
	}

	baseURL := "https://test.api.amadeus.com"
	if env == "production" {
		baseURL = "https://api.amadeus.com"
	}

	return &AmadeusClient{
		apiKey:     apiKey,
		apiSecret:  apiSecret,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// IsConfigured checks if API credentials are available
func (c *AmadeusClient) IsConfigured() bool {
	return c.apiKey != "" && c.apiSecret != ""
}

// getAccessToken obtains or refreshes the OAuth access token
func (c *AmadeusClient) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid
	if c.accessToken != "" && time.Now().Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	// Request new access token
	tokenURL := c.baseURL + "/v1/security/oauth2/token"

	// Use url.Values for proper form encoding
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", c.apiKey)
	formData.Set("client_secret", c.apiSecret)
	encodedData := formData.Encode()

	log.Printf("[Amadeus] Requesting token from %s", tokenURL)
	log.Printf("[Amadeus] Form data: %s", encodedData)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(encodedData))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp AmadeusTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Cache token with expiry
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second) // 5 min buffer

	log.Printf("[Amadeus] Access token obtained, expires in %d seconds", tokenResp.ExpiresIn)

	return c.accessToken, nil
}

// SearchFlights searches for flight offers
func (c *AmadeusClient) SearchFlights(ctx context.Context, params FlightSearchParams) (*FlightSearchResponse, error) {
	if !c.IsConfigured() {
		return nil, fmt.Errorf("amadeus API credentials not configured")
	}

	// Get access token
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Build query string
	url := fmt.Sprintf("%s/v2/shopping/flight-offers?originLocationCode=%s&destinationLocationCode=%s&departureDate=%s&adults=%d",
		c.baseURL,
		params.OriginLocationCode,
		params.DestinationLocationCode,
		params.DepartureDate,
		params.Adults,
	)

	if params.Max > 0 {
		url += fmt.Sprintf("&max=%d", params.Max)
	}

	if params.CurrencyCode != "" {
		url += fmt.Sprintf("&currencyCode=%s", params.CurrencyCode)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var flightResp FlightSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&flightResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	log.Printf("[Amadeus] Flight search successful: %d offers found", len(flightResp.Data))

	return &flightResp, nil
}

// DestinationToIATA converts common destination names to IATA codes
// This is a simple lookup - in production, use Amadeus Airport & City Search API
func DestinationToIATA(destination string) string {
	iataMap := map[string]string{
		// Europe
		"paris":      "PAR",
		"london":     "LON",
		"amsterdam":  "AMS",
		"barcelona":  "BCN",
		"rome":       "ROM",
		"berlin":     "BER",
		"madrid":     "MAD",
		"lisbon":     "LIS",

		// Asia
		"tokyo":      "TYO",
		"singapore":  "SIN",
		"bangkok":    "BKK",
		"hong kong":  "HKG",
		"seoul":      "SEL",
		"dubai":      "DXB",

		// Americas
		"new york":   "NYC",
		"los angeles": "LAX",
		"san francisco": "SFO",
		"chicago":    "CHI",
		"miami":      "MIA",
		"toronto":    "YTO",

		// Oceania
		"sydney":     "SYD",
		"melbourne":  "MEL",
		"auckland":   "AKL",
	}

	// Normalize input
	normalized := ""
	for _, c := range destination {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == ' ' {
			if c >= 'A' && c <= 'Z' {
				normalized += string(c + 32) // Convert to lowercase
			} else {
				normalized += string(c)
			}
		}
	}

	if code, exists := iataMap[normalized]; exists {
		return code
	}

	// Default to first 3 letters uppercase (best effort)
	if len(normalized) >= 3 {
		result := ""
		for i := 0; i < 3 && i < len(normalized); i++ {
			c := normalized[i]
			if c >= 'a' && c <= 'z' {
				result += string(c - 32) // Convert to uppercase
			} else if c >= 'A' && c <= 'Z' {
				result += string(c)
			}
		}
		if len(result) == 3 {
			return result
		}
	}

	return "PAR" // Default fallback
}
