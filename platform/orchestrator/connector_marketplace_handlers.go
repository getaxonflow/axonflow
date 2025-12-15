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
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/connectors/base"
	httpconnector "axonflow/platform/connectors/http"
	"axonflow/platform/connectors/mongodb"
	"axonflow/platform/connectors/mysql"
	"axonflow/platform/connectors/postgres"
	"axonflow/platform/connectors/redis"
	"axonflow/platform/connectors/registry"
)

// Global connector registry
var connectorRegistry *registry.Registry

// ConnectorMetadata represents connector information for the marketplace
type ConnectorMetadata struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	Version      string   `json:"version"`
	Description  string   `json:"description"`
	Category     string   `json:"category"`
	Icon         string   `json:"icon"`
	Tags         []string `json:"tags"`
	Capabilities []string `json:"capabilities"`
	ConfigSchema interface{} `json:"config_schema"`
	Installed    bool     `json:"installed"`
	Healthy      bool     `json:"healthy,omitempty"`
	LastCheck    string   `json:"last_check,omitempty"`
}

// ConnectorInstallRequest represents a request to install a connector
type ConnectorInstallRequest struct {
	ConnectorID string                 `json:"connector_id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Options     map[string]interface{} `json:"options"`
	Credentials map[string]string      `json:"credentials"`
}

// buildConnectionURL constructs a connection URL from options and credentials for database connectors.
// Credentials are properly URL-encoded to handle special characters like @, :, /, etc.
func buildConnectionURL(connectorType string, options map[string]interface{}, credentials map[string]string) string {
	// If connection_url is explicitly provided, use it
	if connURL, ok := options["connection_url"].(string); ok && connURL != "" {
		return connURL
	}

	// Extract common fields with nil safety
	host := getStringOption(options, "host", "localhost")
	database := getStringOption(options, "database", "")

	// Safely extract credentials (nil map safe)
	var username, password string
	if credentials != nil {
		username = credentials["username"]
		password = credentials["password"]
	}

	switch connectorType {
	case "postgres":
		port := getIntOption(options, "port", 5432)
		// Support both ssl_mode and sslmode for flexibility
		sslMode := getStringOption(options, "ssl_mode", "")
		if sslMode == "" {
			sslMode = getStringOption(options, "sslmode", "disable")
		}
		return buildPostgresURL(host, port, database, username, password, sslMode)

	case "mysql":
		port := getIntOption(options, "port", 3306)
		return buildMySQLURL(host, port, database, username, password)

	case "mongodb":
		port := getIntOption(options, "port", 27017)
		authSource := getStringOption(options, "auth_source", "")
		return buildMongoDBURL(host, port, database, username, password, authSource)

	case "redis":
		port := getIntOption(options, "port", 6379)
		db := getIntOption(options, "db", 0)
		return buildRedisURL(host, port, db, password)

	case "cassandra":
		port := getIntOption(options, "port", 9042)
		keyspace := getStringOption(options, "keyspace", database)
		return buildCassandraURL(host, port, keyspace, username, password)

	default:
		// For HTTP and other connectors, use base_url if provided
		if baseURL, ok := options["base_url"].(string); ok {
			return baseURL
		}
		return ""
	}
}

// buildPostgresURL constructs a PostgreSQL connection URL with proper encoding
func buildPostgresURL(host string, port int, database, username, password, sslMode string) string {
	u := &url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + database,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	q := u.Query()
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// buildMySQLURL constructs a MySQL DSN with proper encoding
// MySQL DSN format: [username[:password]@][protocol[(address)]]/dbname[?param1=value1&...]
func buildMySQLURL(host string, port int, database, username, password string) string {
	// MySQL driver uses a different format than standard URLs
	// We need to escape special characters in username/password
	if username != "" && password != "" {
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			url.QueryEscape(username),
			url.QueryEscape(password),
			host, port, database)
	}
	if username != "" {
		return fmt.Sprintf("%s@tcp(%s:%d)/%s", url.QueryEscape(username), host, port, database)
	}
	return fmt.Sprintf("tcp(%s:%d)/%s", host, port, database)
}

// buildMongoDBURL constructs a MongoDB connection URL with proper encoding
func buildMongoDBURL(host string, port int, database, username, password, authSource string) string {
	u := &url.URL{
		Scheme: "mongodb",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + database,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	if authSource != "" {
		q := u.Query()
		q.Set("authSource", authSource)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// buildRedisURL constructs a Redis connection URL with proper encoding
func buildRedisURL(host string, port, db int, password string) string {
	u := &url.URL{
		Scheme: "redis",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   fmt.Sprintf("/%d", db),
	}
	if password != "" {
		// Redis uses empty username with password
		u.User = url.UserPassword("", password)
	}
	return u.String()
}

// buildCassandraURL constructs a Cassandra connection URL
// Cassandra typically uses host:port/keyspace format
func buildCassandraURL(host string, port int, keyspace, username, password string) string {
	u := &url.URL{
		Scheme: "cassandra",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + keyspace,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	return u.String()
}

// getStringOption safely extracts a string from options map (nil-safe)
func getStringOption(options map[string]interface{}, key, defaultVal string) string {
	if options == nil {
		return defaultVal
	}
	if val, ok := options[key].(string); ok {
		return val
	}
	return defaultVal
}

// getIntOption safely extracts an int from options map (handles float64 from JSON, nil-safe)
func getIntOption(options map[string]interface{}, key string, defaultVal int) int {
	if options == nil {
		return defaultVal
	}
	if val, ok := options[key].(float64); ok {
		return int(val)
	}
	if val, ok := options[key].(int); ok {
		return val
	}
	return defaultVal
}

// createConnectorInstance is a factory function that creates connector instances by type
func createConnectorInstance(connectorType string) (base.Connector, error) {
	switch connectorType {
	case "amadeus":
		return NewAmadeusConnector(), nil
	case "redis":
		return redis.NewRedisConnector(), nil
	case "http":
		return httpconnector.NewHTTPConnector(), nil
	case "postgres":
		return postgres.NewPostgresConnector(), nil
	case "mysql":
		return mysql.NewMySQLConnector(), nil
	case "mongodb":
		return mongodb.NewMongoDBConnector(), nil
	default:
		return nil, fmt.Errorf("unsupported connector type: %s", connectorType)
	}
}

// initializeConnectorRegistry initializes the global connector registry
func initializeConnectorRegistry() {
	// Check if DATABASE_URL is available for persistent storage
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL != "" {
		var err error
		connectorRegistry, err = registry.NewRegistryWithStorage(dbURL)
		if err != nil {
			log.Printf("Failed to initialize registry with storage: %v. Falling back to in-memory.", err)
			connectorRegistry = registry.NewRegistry()
		} else {
			log.Println("Connector registry initialized with PostgreSQL persistence")

			// Set factory for lazy-loading connectors
			connectorRegistry.SetFactory(createConnectorInstance)

			// Start periodic reload every 30 seconds to sync with other orchestrator instances
			ctx := context.Background()
			connectorRegistry.StartPeriodicReload(ctx, 30*time.Second)
			log.Println("Started periodic connector reload (every 30 seconds)")
		}
	} else {
		connectorRegistry = registry.NewRegistry()
		log.Println("Connector registry initialized with in-memory storage")
	}
}

// getConnectorMetadata returns metadata for all available connectors
func getConnectorMetadata() []ConnectorMetadata {
	return []ConnectorMetadata{
		{
			ID:          "amadeus-travel",
			Name:        "Amadeus Travel API",
			Type:        "amadeus",
			Version:     "0.2.0",
			Description: "Access flight search, hotel search, and airport information from Amadeus Travel API",
			Category:    "Travel",
			Icon:        "✈️",
			Tags:        []string{"travel", "flights", "hotels", "api"},
			Capabilities: []string{"query", "flights", "hotels", "airports"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"api_key", "api_secret"},
				"properties": map[string]interface{}{
					"environment": map[string]interface{}{
						"type": "string",
						"enum": []string{"test", "production"},
						"default": "test",
						"description": "API environment (test or production)",
					},
				},
				"credentials": map[string]interface{}{
					"api_key": map[string]interface{}{
						"type": "string",
						"description": "Amadeus API Key",
					},
					"api_secret": map[string]interface{}{
						"type": "string",
						"description": "Amadeus API Secret",
					},
				},
			},
		},
		{
			ID:          "redis-cache",
			Name:        "Redis Cache",
			Type:        "redis",
			Version:     "0.2.0",
			Description: "High-performance key-value caching with sub-10ms latency",
			Category:    "Cache",
			Icon:        "⚡",
			Tags:        []string{"cache", "redis", "kv-store", "performance"},
			Capabilities: []string{"query", "execute", "cache", "kv-store"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"host"},
				"properties": map[string]interface{}{
					"host": map[string]interface{}{
						"type": "string",
						"description": "Redis host",
					},
					"port": map[string]interface{}{
						"type": "number",
						"default": 6379,
						"description": "Redis port",
					},
					"db": map[string]interface{}{
						"type": "number",
						"default": 0,
						"description": "Redis database number",
					},
				},
				"credentials": map[string]interface{}{
					"password": map[string]interface{}{
						"type": "string",
						"description": "Redis password (optional)",
					},
				},
			},
		},
		{
			ID:          "http-rest",
			Name:        "HTTP REST API",
			Type:        "http",
			Version:     "0.2.0",
			Description: "Generic REST API connector with multiple authentication methods",
			Category:    "API",
			Icon:        "🔌",
			Tags:        []string{"http", "rest", "api", "generic"},
			Capabilities: []string{"query", "execute", "rest-api"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"base_url"},
				"properties": map[string]interface{}{
					"base_url": map[string]interface{}{
						"type": "string",
						"description": "Base URL of the API",
					},
					"auth_type": map[string]interface{}{
						"type": "string",
						"enum": []string{"none", "bearer", "basic", "api-key"},
						"default": "none",
						"description": "Authentication type",
					},
					"timeout": map[string]interface{}{
						"type": "number",
						"default": 30,
						"description": "Request timeout in seconds",
					},
					"headers": map[string]interface{}{
						"type": "object",
						"description": "Custom headers to include in requests",
					},
				},
				"credentials": map[string]interface{}{
					"token": map[string]interface{}{
						"type": "string",
						"description": "Bearer token (for bearer auth)",
					},
					"username": map[string]interface{}{
						"type": "string",
						"description": "Username (for basic auth)",
					},
					"password": map[string]interface{}{
						"type": "string",
						"description": "Password (for basic auth)",
					},
					"api_key": map[string]interface{}{
						"type": "string",
						"description": "API key (for api-key auth)",
					},
					"header_name": map[string]interface{}{
						"type": "string",
						"default": "X-API-Key",
						"description": "Header name for API key (for api-key auth)",
					},
				},
			},
		},
		{
			ID:          "postgresql",
			Name:        "PostgreSQL Database",
			Type:        "postgres",
			Version:     "0.1.0",
			Description: "Connect to PostgreSQL databases with connection pooling",
			Category:    "Database",
			Icon:        "🐘",
			Tags:        []string{"database", "sql", "postgres"},
			Capabilities: []string{"query", "execute", "transactions"},
			ConfigSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"host", "database"},
				"properties": map[string]interface{}{
					"host": map[string]interface{}{
						"type": "string",
						"description": "PostgreSQL host",
					},
					"port": map[string]interface{}{
						"type": "number",
						"default": 5432,
						"description": "PostgreSQL port",
					},
					"database": map[string]interface{}{
						"type": "string",
						"description": "Database name",
					},
				},
				"credentials": map[string]interface{}{
					"username": map[string]interface{}{
						"type": "string",
						"description": "Database username",
					},
					"password": map[string]interface{}{
						"type": "string",
						"description": "Database password",
					},
				},
			},
		},
	}
}

// listConnectorsHandler returns all available connectors with their metadata
func listConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	metadata := getConnectorMetadata()

	// Add installation status for each connector
	installedConnectors := connectorRegistry.ListWithTypes()

	for i := range metadata {
		_, installed := installedConnectors[metadata[i].ID]
		metadata[i].Installed = installed

		if installed {
			// Get health status
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			status, err := connectorRegistry.HealthCheckSingle(ctx, metadata[i].ID)
			if err == nil && status != nil {
				metadata[i].Healthy = status.Healthy
				metadata[i].LastCheck = status.Timestamp.Format(time.RFC3339)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"connectors": metadata,
		"total": len(metadata),
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// getConnectorDetailsHandler returns details for a specific connector
func getConnectorDetailsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	metadata := getConnectorMetadata()

	var found *ConnectorMetadata
	for i := range metadata {
		if metadata[i].ID == connectorID {
			found = &metadata[i]
			break
		}
	}

	if found == nil {
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	// Add installation status
	installedConnectors := connectorRegistry.ListWithTypes()
	_, installed := installedConnectors[connectorID]
	found.Installed = installed

	if installed {
		// Get health status
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		status, err := connectorRegistry.HealthCheckSingle(ctx, connectorID)
		if err == nil && status != nil {
			found.Healthy = status.Healthy
			found.LastCheck = status.Timestamp.Format(time.RFC3339)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(found); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// installConnectorHandler installs a connector for a tenant
func installConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	var req ConnectorInstallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate connector ID
	metadata := getConnectorMetadata()
	var connectorType string
	for i := range metadata {
		if metadata[i].ID == connectorID {
			connectorType = metadata[i].Type
			break
		}
	}

	if connectorType == "" {
		http.Error(w, "Connector not found", http.StatusNotFound)
		return
	}

	// Create connector instance
	var connector base.Connector
	switch connectorType {
	case "amadeus":
		connector = NewAmadeusConnector() // Use orchestrator's version with real OAuth
	case "redis":
		connector = redis.NewRedisConnector()
	case "http":
		connector = httpconnector.NewHTTPConnector()
	case "postgres":
		connector = postgres.NewPostgresConnector()
	default:
		http.Error(w, "Unsupported connector type", http.StatusBadRequest)
		return
	}

	// Create config with properly constructed ConnectionURL
	config := &base.ConnectorConfig{
		Name:          req.Name,
		Type:          connectorType,
		ConnectionURL: buildConnectionURL(connectorType, req.Options, req.Credentials),
		TenantID:      req.TenantID,
		Options:       req.Options,
		Credentials:   req.Credentials,
		Timeout:       30 * time.Second,
	}

	// Register connector
	if err := connectorRegistry.Register(connectorID, connector, config); err != nil {
		http.Error(w, "Failed to install connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connector installed successfully",
		"connector_id": connectorID,
		"name": req.Name,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// uninstallConnectorHandler uninstalls a connector
func uninstallConnectorHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	if err := connectorRegistry.Unregister(connectorID); err != nil {
		http.Error(w, "Failed to uninstall connector: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Connector uninstalled successfully",
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// connectorHealthCheckHandler performs health check on a specific connector
func connectorHealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	connectorID := vars["id"]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	status, err := connectorRegistry.HealthCheckSingle(ctx, connectorID)
	if err != nil {
		http.Error(w, "Health check failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}
