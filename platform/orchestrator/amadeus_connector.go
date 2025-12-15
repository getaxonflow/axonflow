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
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"axonflow/platform/connectors/base"
)

// AmadeusConnector implements the MCP Connector interface for Amadeus Travel API
// This version uses the existing AmadeusClient with real OAuth authentication
type AmadeusConnector struct {
	config       *base.ConnectorConfig
	client       *AmadeusClient // Use existing orchestrator client
	logger       *log.Logger
	cacheEnabled bool
	cacheTTL     time.Duration
}

// NewAmadeusConnector creates a new Amadeus connector instance
func NewAmadeusConnector() *AmadeusConnector {
	return &AmadeusConnector{
		logger:       log.New(os.Stdout, "[MCP_AMADEUS] ", log.LstdFlags),
		cacheEnabled: true,
		cacheTTL:     15 * time.Minute,
	}
}

// Connect establishes a connection to Amadeus API
func (c *AmadeusConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	c.config = config

	// Security best practice: Always prefer environment variables (from Secrets Manager) over database credentials
	// Environment variables are more secure and easier to rotate
	apiKey := os.Getenv("AMADEUS_API_KEY")
	apiSecret := os.Getenv("AMADEUS_API_SECRET")

	// Fallback to config credentials only if environment variables not set
	if apiKey == "" {
		apiKey = config.Credentials["api_key"]
	}
	if apiSecret == "" {
		apiSecret = config.Credentials["api_secret"]
	}

	if apiKey == "" || apiSecret == "" {
		return base.NewConnectorError(config.Name, "Connect", "Amadeus API credentials not provided", nil)
	}

	// Create AmadeusClient using existing implementation
	env := "test"
	if envVal, ok := config.Options["environment"].(string); ok {
		env = envVal
	}

	// Set environment variables for AmadeusClient
	if err := os.Setenv("AMADEUS_API_KEY", apiKey); err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to set AMADEUS_API_KEY", err)
	}
	if err := os.Setenv("AMADEUS_API_SECRET", apiSecret); err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to set AMADEUS_API_SECRET", err)
	}
	if err := os.Setenv("AMADEUS_ENV", env); err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to set AMADEUS_ENV", err)
	}

	c.client = NewAmadeusClient()

	if !c.client.IsConfigured() {
		return base.NewConnectorError(config.Name, "Connect", "failed to configure Amadeus client", nil)
	}

	// Test authentication by getting a token
	_, err := c.client.getAccessToken(ctx)
	if err != nil {
		return base.NewConnectorError(config.Name, "Connect", "failed to authenticate with Amadeus", err)
	}

	c.logger.Printf("Connected to Amadeus API: %s (environment=%s) with OAuth authentication ✅", config.Name, env)

	return nil
}

// Disconnect closes the connection (no-op for HTTP API)
func (c *AmadeusConnector) Disconnect(ctx context.Context) error {
	c.logger.Printf("Disconnected from Amadeus API: %s", c.config.Name)
	return nil
}

// HealthCheck verifies the API is accessible
func (c *AmadeusConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	if c.client == nil {
		return &base.HealthStatus{
			Healthy: false,
			Error:   "client not connected",
		}, nil
	}

	start := time.Now()
	_, err := c.client.getAccessToken(ctx)
	latency := time.Since(start)

	if err != nil {
		return &base.HealthStatus{
			Healthy:   false,
			Latency:   latency,
			Timestamp: time.Now(),
			Error:     err.Error(),
		}, nil
	}

	details := map[string]string{
		"base_url":    c.client.baseURL,
		"environment": c.getEnvironment(),
		"auth":        "OAuth 2.0",
	}

	return &base.HealthStatus{
		Healthy:   true,
		Latency:   latency,
		Details:   details,
		Timestamp: time.Now(),
	}, nil
}

// Query executes a read operation (MCP Resource pattern)
func (c *AmadeusConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if c.client == nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "client not connected", nil)
	}

	// Parse query statement to determine operation type
	operation := strings.ToLower(strings.TrimSpace(query.Statement))

	start := time.Now()
	var rows []map[string]interface{}
	var err error

	switch {
	case strings.HasPrefix(operation, "search_flights"):
		rows, err = c.searchFlights(ctx, query.Parameters)
	case strings.HasPrefix(operation, "search_hotels"):
		rows, err = c.searchHotels(ctx, query.Parameters)
	case strings.HasPrefix(operation, "lookup_airport"):
		rows, err = c.lookupAirport(ctx, query.Parameters)
	default:
		return nil, base.NewConnectorError(c.config.Name, "Query",
			fmt.Sprintf("unsupported operation: %s", operation), nil)
	}

	duration := time.Since(start)

	if err != nil {
		return nil, base.NewConnectorError(c.config.Name, "Query", "query execution failed", err)
	}

	c.logger.Printf("Query executed successfully: %s (%d results in %v)", operation, len(rows), duration)

	return &base.QueryResult{
		Rows:      rows,
		RowCount:  len(rows),
		Duration:  duration,
		Cached:    false,
		Connector: c.config.Name,
	}, nil
}

// Execute executes a write operation (not supported for Amadeus)
func (c *AmadeusConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return nil, base.NewConnectorError(c.config.Name, "Execute",
		"write operations not supported for Amadeus API", nil)
}

// Name returns the connector instance name
func (c *AmadeusConnector) Name() string {
	if c.config != nil {
		return c.config.Name
	}
	return "amadeus-connector"
}

// Type returns the connector type
func (c *AmadeusConnector) Type() string {
	return "amadeus"
}

// Version returns the connector version
func (c *AmadeusConnector) Version() string {
	return "0.2.1"
}

// Capabilities returns the list of connector capabilities
func (c *AmadeusConnector) Capabilities() []string {
	return []string{"query", "flights", "hotels", "airports"}
}

// searchFlights searches for flight offers using real Amadeus API
func (c *AmadeusConnector) searchFlights(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	// Extract parameters
	origin, _ := params["origin"].(string)
	destination, _ := params["destination"].(string)
	departureDate, _ := params["departure_date"].(string)

	adults := 1
	if a, ok := params["adults"].(float64); ok {
		adults = int(a)
	} else if a, ok := params["adults"].(int); ok {
		adults = a
	}

	max := 5
	if m, ok := params["max"].(float64); ok {
		max = int(m)
	} else if m, ok := params["max"].(int); ok {
		max = m
	}

	// Convert city names to IATA codes if needed
	originCode := c.toIATACode(origin)
	destCode := c.toIATACode(destination)

	// Call real Amadeus API
	searchParams := FlightSearchParams{
		OriginLocationCode:      originCode,
		DestinationLocationCode: destCode,
		DepartureDate:           departureDate,
		Adults:                  adults,
		Max:                     max,
		CurrencyCode:            "USD",
	}

	response, err := c.client.SearchFlights(ctx, searchParams)
	if err != nil {
		return nil, err
	}

	c.logger.Printf("Flight search: %s->%s on %s, found %d offers", originCode, destCode, departureDate, len(response.Data))

	return response.Data, nil
}

// searchHotels searches for hotel offers
func (c *AmadeusConnector) searchHotels(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	cityCode, _ := params["city_code"].(string)
	checkIn, _ := params["check_in"].(string)
	checkOut, _ := params["check_out"].(string)

	// Hotel search would use Amadeus Hotel Search API
	// For now, return empty results with note
	c.logger.Printf("Hotel search: city=%s (hotel API integration pending)", cityCode)

	return []map[string]interface{}{
		{
			"note":      "Hotel search API integration pending",
			"city_code": cityCode,
			"check_in":  checkIn,
			"check_out": checkOut,
		},
	}, nil
}

// lookupAirport looks up airport information
func (c *AmadeusConnector) lookupAirport(ctx context.Context, params map[string]interface{}) ([]map[string]interface{}, error) {
	query, _ := params["query"].(string)

	code := c.toIATACode(query)

	// Return basic airport info
	rows := []map[string]interface{}{
		{
			"code":  code,
			"query": query,
			"type":  "airport",
		},
	}

	return rows, nil
}

// toIATACode converts destination name to IATA code
func (c *AmadeusConnector) toIATACode(destination string) string {
	iataMap := map[string]string{
		// Europe
		"paris":     "PAR",
		"london":    "LON",
		"amsterdam": "AMS",
		"barcelona": "BCN",
		"rome":      "ROM",
		"berlin":    "BER",
		"madrid":    "MAD",
		"lisbon":    "LIS",

		// Asia
		"tokyo":     "TYO",
		"singapore": "SIN",
		"bangkok":   "BKK",
		"hong kong": "HKG",
		"seoul":     "SEL",
		"dubai":     "DXB",

		// Americas
		"new york":      "NYC",
		"los angeles":   "LAX",
		"san francisco": "SFO",
		"chicago":       "CHI",
		"miami":         "MIA",
		"toronto":       "YTO",

		// Oceania
		"sydney":    "SYD",
		"melbourne": "MEL",
		"auckland":  "AKL",
	}

	normalized := strings.ToLower(strings.TrimSpace(destination))
	if code, exists := iataMap[normalized]; exists {
		return code
	}

	// If already a 3-letter code, return as-is
	if len(destination) == 3 {
		return strings.ToUpper(destination)
	}

	return "PAR" // Default fallback
}

func (c *AmadeusConnector) getEnvironment() string {
	if strings.Contains(c.client.baseURL, "test") {
		return "test"
	}
	return "production"
}
