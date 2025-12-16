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

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/policy"
	"axonflow/platform/agent/sqli"
	"axonflow/platform/connectors/amadeus"
	"axonflow/platform/connectors/azureblob"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/cassandra"
	"axonflow/platform/connectors/config"
	"axonflow/platform/connectors/gcs"
	httpconnector "axonflow/platform/connectors/http"
	"axonflow/platform/connectors/hubspot"
	"axonflow/platform/connectors/jira"
	"axonflow/platform/connectors/mongodb"
	"axonflow/platform/connectors/mysql"
	"axonflow/platform/connectors/postgres"
	"axonflow/platform/connectors/redis"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/connectors/s3"
	"axonflow/platform/connectors/salesforce"
	"axonflow/platform/connectors/servicenow"
	"axonflow/platform/connectors/slack"
	"axonflow/platform/connectors/snowflake"
)

// Global MCP connector registry
var mcpRegistry *registry.Registry

// Global RuntimeConfigService for three-tier configuration
var runtimeConfigService *config.RuntimeConfigService

// Internal service authentication constants for orchestrator-to-agent routing.
const (
	// internalServiceClientID is the client ID used for internal orchestrator calls
	internalServiceClientID = "orchestrator-internal"

	// internalServiceTokenFallback is used when AXONFLOW_INTERNAL_SERVICE_SECRET is not configured
	internalServiceTokenFallback = "orchestrator-internal-token"

	// internalServiceSecretEnvVar is the environment variable for the shared secret
	internalServiceSecretEnvVar = "AXONFLOW_INTERNAL_SERVICE_SECRET"

	// internalServiceSecretMinLength is the recommended minimum length for the shared secret.
	internalServiceSecretMinLength = 32
)

// internalServiceAuthWarningLogged tracks if we've already logged the fallback warning.
var internalServiceAuthWarningLogged bool

// logInternalServiceAuthWarning logs a warning if fallback mode is being used.
// This should be called during initialization to alert operators about security configuration.
func logInternalServiceAuthWarning() {
	if internalServiceAuthWarningLogged {
		return
	}
	secret := os.Getenv(internalServiceSecretEnvVar)
	if secret == "" {
		log.Printf("[SECURITY WARNING] %s not configured - using fallback token for internal service auth. This is acceptable for development but NOT recommended for production. Set %s to a secure random string (minimum %d characters).",
			internalServiceSecretEnvVar, internalServiceSecretEnvVar, internalServiceSecretMinLength)
	} else if len(secret) < internalServiceSecretMinLength {
		log.Printf("[SECURITY WARNING] %s is only %d characters - recommend at least %d characters for production security.",
			internalServiceSecretEnvVar, len(secret), internalServiceSecretMinLength)
	}
	internalServiceAuthWarningLogged = true
}

// isValidInternalServiceRequest checks if the request is from a trusted internal service.
// If AXONFLOW_INTERNAL_SERVICE_SECRET is configured, validates the token against it.
// Otherwise falls back to checking the hardcoded token (for OSS/dev environments).
func isValidInternalServiceRequest(clientID, userToken string) bool {
	if clientID != internalServiceClientID {
		return false
	}

	// If shared secret is configured, validate against it
	if secret := os.Getenv(internalServiceSecretEnvVar); secret != "" {
		return userToken == secret
	}

	// Fallback for OSS/dev: accept hardcoded token
	return userToken == internalServiceTokenFallback
}

// InitializeMCPRegistry sets up the MCP connector registry and registers default connectors
// Configuration priority: Database > Config File (AXONFLOW_CONFIG_FILE) > Environment Variables
func InitializeMCPRegistry() error {
	return InitializeMCPRegistryWithDB(nil)
}

// InitializeMCPRegistryWithDB sets up the MCP connector registry with optional database support
// This enables three-tier configuration: Database > Config File > Env Vars
func InitializeMCPRegistryWithDB(db *sql.DB) error {
	// Log security warning if internal service auth is using fallback token
	logInternalServiceAuthWarning()

	mcpRegistry = registry.NewRegistry()
	log.Println("[MCP] Initializing connector registry...")

	// Check for config file (OSS mode)
	configFilePath := os.Getenv("AXONFLOW_CONFIG_FILE")
	if configFilePath == "" {
		// Check default locations
		defaultPaths := []string{
			"./axonflow.yaml",
			"./config/axonflow.yaml",
			"/etc/axonflow/axonflow.yaml",
		}
		for _, path := range defaultPaths {
			if _, err := os.Stat(path); err == nil {
				configFilePath = path
				break
			}
		}
	}

	// Initialize RuntimeConfigService for three-tier configuration
	selfHosted := os.Getenv("AXONFLOW_SELF_HOSTED") == "true"

	runtimeConfigService = config.NewRuntimeConfigService(config.RuntimeConfigServiceOptions{
		DB:         db,
		ConfigFile: configFilePath,
		SelfHosted: selfHosted,
		CacheTTL:   30 * time.Second,
	})

	// If config file exists, try loading connectors from it
	if configFilePath != "" {
		err := initializeFromConfigFile(configFilePath)
		if err != nil {
			// Check if this is a "no connectors" error vs a real parsing error
			if err.Error() == "no enabled connectors found in config file" {
				// Config file loaded successfully but no connectors were configured
				// This is likely user error (empty file or no connectors section)
				// Fall back to env vars to prevent silent failure
				log.Printf("[MCP] WARNING: Config file %s loaded but contains no connectors, falling back to env vars", configFilePath)
			} else {
				log.Printf("[MCP] Config file loading failed, falling back to env vars: %v", err)
			}
		} else if mcpRegistry.Count() > 0 {
			log.Printf("[MCP] Registry initialized from config file: %s (%d connectors)", configFilePath, mcpRegistry.Count())
			return nil
		}
		// If we get here, fall through to env var configuration
	}

	// Fallback to environment variable based configuration
	log.Println("[MCP] Using environment variable configuration (legacy mode)")

	// Register PostgreSQL connector (uses DATABASE_URL)
	if err := registerPostgresConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register PostgreSQL connector: %v", err)
	}

	// Register Cassandra connector (if configured)
	if err := registerCassandraConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register Cassandra connector: %v", err)
	}

	// Register Slack connector (if configured)
	if err := registerSlackConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register Slack connector: %v", err)
	}

	// Register Salesforce connector (if configured)
	if err := registerSalesforceConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register Salesforce connector: %v", err)
	}

	// Register Snowflake connector (if configured)
	if err := registerSnowflakeConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register Snowflake connector: %v", err)
	}

	// Register Amadeus connector (if configured)
	if err := registerAmadeusConnector(); err != nil {
		log.Printf("[MCP] Warning: Failed to register Amadeus connector: %v", err)
	}

	log.Printf("[MCP] Registry initialized with %d connectors", mcpRegistry.Count())
	return nil
}

// initializeFromConfigFile loads connectors from a YAML config file
func initializeFromConfigFile(configFilePath string) error {
	log.Printf("[MCP] Loading connectors from config file: %s", configFilePath)

	loader, err := config.NewYAMLConfigFileLoader(configFilePath)
	if err != nil {
		return fmt.Errorf("failed to create config file loader: %w", err)
	}

	// Set the file loader on the runtime config service
	runtimeConfigService.SetConfigFileLoader(loader)

	// Load connectors for wildcard tenant (all connectors in file)
	connectorConfigs, err := loader.LoadConnectors("*")
	if err != nil {
		return fmt.Errorf("failed to load connectors from config file: %w", err)
	}

	if len(connectorConfigs) == 0 {
		return fmt.Errorf("no enabled connectors found in config file")
	}

	// Register each connector
	for _, cfg := range connectorConfigs {
		if err := registerConnectorFromConfig(cfg); err != nil {
			log.Printf("[MCP] Warning: Failed to register connector '%s': %v", cfg.Name, err)
			continue
		}
		log.Printf("[MCP] Registered %s connector from config file: %s", cfg.Type, cfg.Name)
	}

	return nil
}

// registerConnectorFromConfig creates and registers a connector from a base.ConnectorConfig
func registerConnectorFromConfig(cfg *base.ConnectorConfig) error {
	var connector base.Connector

	switch cfg.Type {
	case "postgres":
		connector = postgres.NewPostgresConnector()
	case "cassandra":
		connector = cassandra.NewCassandraConnector()
	case "slack":
		connector = slack.NewSlackConnector()
	case "salesforce":
		connector = salesforce.NewSalesforceConnector()
	case "snowflake":
		connector = snowflake.NewSnowflakeConnector()
	case "amadeus":
		connector = amadeus.NewAmadeusConnector()
	case "mysql":
		connector = mysql.NewMySQLConnector()
	case "mongodb":
		connector = mongodb.NewMongoDBConnector()
	case "http":
		connector = httpconnector.NewHTTPConnector()
	case "redis":
		connector = redis.NewRedisConnector()
	case "s3":
		connector = s3.NewS3Connector()
	case "azureblob":
		connector = azureblob.NewAzureBlobConnector()
	case "gcs":
		connector = gcs.NewGCSConnector()
	case "hubspot":
		connector = hubspot.NewHubSpotConnector()
	case "jira":
		connector = jira.NewJiraConnector()
	case "servicenow":
		connector = servicenow.NewServiceNowConnector()
	default:
		return fmt.Errorf("unsupported connector type: %s", cfg.Type)
	}

	return mcpRegistry.Register(cfg.Name, connector, cfg)
}

// GetRuntimeConfigService returns the global RuntimeConfigService instance
// This is useful for other parts of the agent that need config access
func GetRuntimeConfigService() *config.RuntimeConfigService {
	return runtimeConfigService
}

// GetConnectorForTenant retrieves a connector for a specific tenant.
// It uses the TenantConnectorRegistry for dynamic loading (ADR-007 compliant).
// Falls back to the static registry if TenantConnectorRegistry is not initialized.
//
// Parameters:
//   - ctx: Context for timeout/cancellation
//   - tenantID: The tenant ID for multi-tenant isolation
//   - connectorName: The name of the connector to retrieve
//
// Returns:
//   - The connector if found
//   - An error if connector not found or loading fails
func GetConnectorForTenant(ctx context.Context, tenantID, connectorName string) (base.Connector, error) {
	// Try TenantConnectorRegistry first (dynamic, per-tenant)
	tenantReg := GetTenantConnectorRegistry()
	if tenantReg != nil {
		connector, err := tenantReg.GetConnector(ctx, tenantID, connectorName)
		if err == nil {
			log.Printf("[MCP] Retrieved connector '%s' for tenant '%s' from TenantConnectorRegistry", connectorName, tenantID)
			return connector, nil
		}
		// Log the error but fall back to static registry
		log.Printf("[MCP] TenantConnectorRegistry lookup failed for '%s' (tenant: %s): %v, falling back to static registry",
			connectorName, tenantID, err)
	}

	// Fall back to static registry (backward compatibility)
	if mcpRegistry == nil {
		return nil, fmt.Errorf("MCP registry not initialized")
	}

	connector, err := mcpRegistry.Get(connectorName)
	if err != nil {
		return nil, fmt.Errorf("connector '%s' not found: %w", connectorName, err)
	}

	log.Printf("[MCP] Retrieved connector '%s' from static registry (fallback)", connectorName)
	return connector, nil
}

// IsTenantConnectorRegistryEnabled returns true if dynamic per-tenant connector loading is available.
func IsTenantConnectorRegistryEnabled() bool {
	return GetTenantConnectorRegistry() != nil
}

// registerPostgresConnector registers a PostgreSQL connector
func registerPostgresConnector() error {
	cfg, err := config.LoadPostgresConfig("axonflow_rds")
	if err != nil {
		return err
	}

	connector := postgres.NewPostgresConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered PostgreSQL connector: %s", cfg.Name)
	return nil
}

// registerCassandraConnector registers a Cassandra connector
func registerCassandraConnector() error {
	cfg, err := config.LoadCassandraConfig("mmt_bookings")
	if err != nil {
		// Cassandra is optional - only register if configured
		return nil
	}

	connector := cassandra.NewCassandraConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered Cassandra connector: %s", cfg.Name)
	return nil
}

// registerSlackConnector registers a Slack connector
func registerSlackConnector() error {
	cfg, err := config.LoadSlackConfig("slack_workspace")
	if err != nil {
		// Slack is optional - only register if configured
		return nil
	}

	connector := slack.NewSlackConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered Slack connector: %s", cfg.Name)
	return nil
}

// registerSalesforceConnector registers a Salesforce connector
func registerSalesforceConnector() error {
	cfg, err := config.LoadSalesforceConfig("salesforce_crm")
	if err != nil {
		// Salesforce is optional - only register if configured
		return nil
	}

	connector := salesforce.NewSalesforceConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered Salesforce connector: %s", cfg.Name)
	return nil
}

// registerSnowflakeConnector registers a Snowflake connector
func registerSnowflakeConnector() error {
	cfg, err := config.LoadSnowflakeConfig("snowflake_warehouse")
	if err != nil {
		// Snowflake is optional - only register if configured
		return nil
	}

	connector := snowflake.NewSnowflakeConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered Snowflake connector: %s", cfg.Name)
	return nil
}

// registerAmadeusConnector registers an Amadeus connector
// The connector name "amadeus-travel" matches the orchestrator's planning engine expectations
func registerAmadeusConnector() error {
	cfg, err := config.LoadAmadeusConfig("amadeus-travel")
	if err != nil {
		// Amadeus is optional - only register if configured
		return nil
	}

	connector := amadeus.NewAmadeusConnector()
	if err := mcpRegistry.Register(cfg.Name, connector, cfg); err != nil {
		return err
	}

	log.Printf("[MCP] Registered Amadeus connector: %s", cfg.Name)
	return nil
}

// RegisterMCPHandlers adds MCP endpoints to the router
func RegisterMCPHandlers(r *mux.Router) {
	// List all connectors
	r.HandleFunc("/mcp/connectors", mcpListConnectorsHandler).Methods("GET")

	// Health check for specific connector
	r.HandleFunc("/mcp/connectors/{name}/health", mcpConnectorHealthHandler).Methods("GET")

	// Execute query (MCP Resource pattern - read-only)
	r.HandleFunc("/mcp/resources/query", mcpQueryHandler).Methods("POST")

	// Execute command (MCP Tool pattern - write operations)
	r.HandleFunc("/mcp/tools/execute", mcpExecuteHandler).Methods("POST")

	// Overall MCP health check
	r.HandleFunc("/mcp/health", mcpHealthHandler).Methods("GET")

	log.Println("[MCP] Registered MCP endpoint handlers")
}

// mcpListConnectorsHandler lists all registered connectors with health status
// GET /mcp/connectors
func mcpListConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get health status for all connectors
	healthStatuses := mcpRegistry.HealthCheck(ctx)

	// Build response
	connectors := make([]map[string]interface{}, 0)
	for name, status := range healthStatuses {
		connector := map[string]interface{}{
			"name":       name,
			"healthy":    status.Healthy,
			"latency_ms": status.Latency.Milliseconds(),
		}

		// Get connector type from registry
		if conn, err := mcpRegistry.Get(name); err == nil {
			connector["type"] = conn.Type()
			connector["version"] = conn.Version()
			connector["capabilities"] = conn.Capabilities()
		}

		if !status.Healthy {
			connector["error"] = status.Error
		}

		connectors = append(connectors, connector)
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"connectors": connectors,
		"count":      len(connectors),
	}); err != nil {
		log.Printf("Error encoding connectors list response: %v", err)
	}
}

// mcpConnectorHealthHandler checks health of a specific connector
// GET /mcp/connectors/{name}/health
func mcpConnectorHealthHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	vars := mux.Vars(r)
	connectorName := vars["name"]

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status, err := mcpRegistry.HealthCheckSingle(ctx, connectorName)
	if err != nil {
		sendErrorResponse(w, "Connector not found", http.StatusNotFound, nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding connector health response: %v", err)
	}
}

// MCPQueryRequest represents a request to query a connector
type MCPQueryRequest struct {
	ClientID   string                 `json:"client_id"`   // Required for authentication
	LicenseKey string                 `json:"license_key"` // Service license key for permission validation
	UserToken  string                 `json:"user_token"`  // Required for authentication
	Connector  string                 `json:"connector"`   // Connector name
	Operation  string                 `json:"operation"`   // Operation name (e.g., "search_flights", "query")
	Statement  string                 `json:"statement"`   // SQL/CQL statement
	Parameters map[string]interface{} `json:"parameters"`  // Query parameters
	Limit      int                    `json:"limit"`       // Result limit (optional)
	Timeout    string                 `json:"timeout"`     // Timeout (optional, e.g., "5s")
}

// mcpQueryHandler executes a query via a connector (MCP Resource pattern)
// POST /mcp/resources/query
func mcpQueryHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	var req MCPQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Extract license key from headers if not in request body (SDK sends in X-License-Key header)
	if req.LicenseKey == "" {
		req.LicenseKey = r.Header.Get("X-License-Key")
	}

	ctx := r.Context()

	// 1. Validate client authentication
	client, err := validateClient(req.ClientID)
	if err != nil {
		sendErrorResponse(w, "Invalid client", http.StatusUnauthorized, nil)
		return
	}

	if !client.Enabled {
		sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
		return
	}

	// 2. Validate user token
	// For internal orchestrator-to-agent routing, bypass token validation
	// This allows the orchestrator to call MCP connectors without requiring user tokens
	// Uses AXONFLOW_INTERNAL_SERVICE_SECRET if configured, otherwise falls back to hardcoded token
	var user *User
	if isValidInternalServiceRequest(req.ClientID, req.UserToken) {
		log.Printf("[MCP] Internal orchestrator request - bypassing user token validation")
		user = &User{
			ID:          0,
			Email:       "orchestrator@axonflow.internal",
			Name:        "Orchestrator Internal",
			TenantID:    client.TenantID,
			Role:        "service",
			Permissions: []string{"query", "execute", "mcp"},
		}
	} else {
		var err error
		user, err = validateUserToken(req.UserToken, client.TenantID)
		if err != nil {
			sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
			return
		}
	}

	// 3. Verify tenant isolation
	if user.TenantID != client.TenantID {
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	// 4. Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	servicePermissionGranted := false
	if req.LicenseKey != "" {
		// Validate license key
		validationResult, err := license.ValidateLicense(ctx, req.LicenseKey)
		if err != nil {
			log.Printf("[MCP] License validation failed: %v", err)
			sendErrorResponse(w, "Invalid license key", http.StatusUnauthorized, nil)
			return
		}

		if !validationResult.Valid {
			log.Printf("[MCP] License invalid or expired: %s", validationResult.Error)
			sendErrorResponse(w, "License invalid or expired", http.StatusUnauthorized, nil)
			return
		}

		// Check service permissions (if this is a service license)
		if validationResult.ServiceName != "" {
			pe := policy.NewPermissionEvaluator()

			// Determine operation name (use provided operation or default to "query")
			operation := req.Operation
			if operation == "" {
				operation = "query"
			}

			allowed, err := pe.EvaluateMCPPermission(validationResult, req.Connector, operation)
			if !allowed {
				log.Printf("[MCP] Permission denied: %v", err)
				sendErrorResponse(w, fmt.Sprintf("Permission denied: %v", err), http.StatusForbidden, nil)
				return
			}

			log.Printf("[MCP] Service '%s' granted permission for %s:%s",
				validationResult.ServiceName, req.Connector, operation)
			servicePermissionGranted = true
		}
	}

	// 5. Validate tenant has access to connector (only for non-service licenses)
	// V2 service licenses already validated permissions via EvaluateMCPPermission above
	if !servicePermissionGranted {
		if err := mcpRegistry.ValidateTenantAccess(req.Connector, user.TenantID); err != nil {
			sendErrorResponse(w, "Unauthorized connector access", http.StatusForbidden, nil)
			return
		}
	}

	// 6. Get connector (uses TenantConnectorRegistry with fallback to static registry)
	connector, err := GetConnectorForTenant(ctx, user.TenantID, req.Connector)
	if err != nil {
		log.Printf("[MCP] Connector not found: %v", err)
		sendErrorResponse(w, "Connector not found", http.StatusNotFound, nil)
		return
	}

	// 7. Parse timeout
	var timeout time.Duration
	if req.Timeout != "" {
		timeout, err = time.ParseDuration(req.Timeout)
		if err != nil {
			sendErrorResponse(w, "Invalid timeout format", http.StatusBadRequest, nil)
			return
		}
	}

	// 8. Execute query
	// Use operation as statement for API connectors (e.g., "search_flights" for Amadeus)
	// For SQL connectors, statement would contain the actual SQL query
	statement := req.Statement
	if statement == "" && req.Operation != "" {
		statement = req.Operation
	}

	query := &base.Query{
		Statement:  statement,
		Parameters: req.Parameters,
		Timeout:    timeout,
		Limit:      req.Limit,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := connector.Query(ctx, query)
	if err != nil {
		log.Printf("[MCP] Query failed: %v", err)
		sendErrorResponse(w, "Query execution failed", http.StatusInternalServerError, nil)
		return
	}

	// 9. Scan response for SQL injection (if enabled)
	scanResult, scanErr := sqli.GetGlobalMiddleware().ScanQueryResponse(ctx, req.Connector, result.Rows)
	if scanErr != nil {
		log.Printf("[MCP] SQLi scan error: %v", scanErr)
		// Continue - don't block on scan errors
	} else if scanResult.Blocked {
		log.Printf("[MCP] SQLi detected in response from connector '%s': pattern=%s category=%s",
			req.Connector, scanResult.Pattern, scanResult.Category)
		sendErrorResponse(w, fmt.Sprintf("Response blocked: potential SQL injection detected (pattern: %s)", scanResult.Pattern), http.StatusForbidden, nil)
		return
	}

	// 10. Return results
	// SDK expects "data" field (ConnectorResponse.Data), not "rows"
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"connector":   req.Connector,
		"data":        result.Rows, // SDK looks for "data" field in sdk/golang/axonflow.go:595
		"row_count":   result.RowCount,
		"duration_ms": result.Duration.Milliseconds(),
	}); err != nil {
		log.Printf("Error encoding MCP query response: %v", err)
	}

	log.Printf("[MCP] Query executed: connector=%s, rows=%d, duration=%v",
		req.Connector, result.RowCount, result.Duration)
}

// MCPExecuteRequest represents a request to execute a command via a connector
type MCPExecuteRequest struct {
	ClientID   string                 `json:"client_id"`   // Required for authentication
	LicenseKey string                 `json:"license_key"` // Service license key for permission validation
	UserToken  string                 `json:"user_token"`  // Required for authentication
	Connector  string                 `json:"connector"`   // Connector name
	Operation  string                 `json:"operation"`   // Operation name (e.g., "insert", "update", "delete")
	Action     string                 `json:"action"`      // Action type (INSERT, UPDATE, DELETE)
	Statement  string                 `json:"statement"`   // SQL/CQL statement
	Parameters map[string]interface{} `json:"parameters"`  // Command parameters
	Timeout    string                 `json:"timeout"`     // Timeout (optional)
}

// mcpExecuteHandler executes a command via a connector (MCP Tool pattern)
// POST /mcp/tools/execute
func mcpExecuteHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	var req MCPExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Extract license key from headers if not in request body (SDK sends in X-License-Key header)
	if req.LicenseKey == "" {
		req.LicenseKey = r.Header.Get("X-License-Key")
	}

	// Authentication and authorization (same as query handler)
	client, err := validateClient(req.ClientID)
	if err != nil || !client.Enabled {
		sendErrorResponse(w, "Invalid or disabled client", http.StatusUnauthorized, nil)
		return
	}

	user, err := validateUserToken(req.UserToken, client.TenantID)
	if err != nil {
		sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
		return
	}

	if user.TenantID != client.TenantID {
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	ctx := r.Context()

	// Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	servicePermissionGranted := false
	if req.LicenseKey != "" {
		// Validate license key
		validationResult, err := license.ValidateLicense(ctx, req.LicenseKey)
		if err != nil {
			log.Printf("[MCP] License validation failed: %v", err)
			sendErrorResponse(w, "Invalid license key", http.StatusUnauthorized, nil)
			return
		}

		if !validationResult.Valid {
			log.Printf("[MCP] License invalid or expired: %s", validationResult.Error)
			sendErrorResponse(w, "License invalid or expired", http.StatusUnauthorized, nil)
			return
		}

		// Check service permissions (if this is a service license)
		if validationResult.ServiceName != "" {
			pe := policy.NewPermissionEvaluator()

			// Determine operation name (use provided operation or derive from action)
			operation := req.Operation
			if operation == "" {
				operation = strings.ToLower(req.Action) // "INSERT" -> "insert"
			}

			allowed, err := pe.EvaluateMCPPermission(validationResult, req.Connector, operation)
			if !allowed {
				log.Printf("[MCP] Permission denied: %v", err)
				sendErrorResponse(w, fmt.Sprintf("Permission denied: %v", err), http.StatusForbidden, nil)
				return
			}

			log.Printf("[MCP] Service '%s' granted permission for %s:%s",
				validationResult.ServiceName, req.Connector, operation)
			servicePermissionGranted = true
		}
	}

	// Validate tenant has access to connector (only for non-service licenses)
	// V2 service licenses already validated permissions via EvaluateMCPPermission above
	if !servicePermissionGranted {
		if err := mcpRegistry.ValidateTenantAccess(req.Connector, user.TenantID); err != nil {
			sendErrorResponse(w, "Unauthorized connector access", http.StatusForbidden, nil)
			return
		}
	}

	// Get connector (uses TenantConnectorRegistry with fallback to static registry)
	connector, err := GetConnectorForTenant(ctx, user.TenantID, req.Connector)
	if err != nil {
		log.Printf("[MCP] Connector not found: %v", err)
		sendErrorResponse(w, "Connector not found", http.StatusNotFound, nil)
		return
	}

	// Parse timeout
	var timeout time.Duration
	if req.Timeout != "" {
		timeout, err = time.ParseDuration(req.Timeout)
		if err != nil {
			sendErrorResponse(w, "Invalid timeout format", http.StatusBadRequest, nil)
			return
		}
	}

	// Execute command
	cmd := &base.Command{
		Action:     req.Action,
		Statement:  req.Statement,
		Parameters: req.Parameters,
		Timeout:    timeout,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	result, err := connector.Execute(ctx, cmd)
	if err != nil {
		log.Printf("[MCP] Execute failed: %v", err)
		sendErrorResponse(w, "Command execution failed", http.StatusInternalServerError, nil)
		return
	}

	// Scan response for SQL injection (if enabled)
	scanResult, scanErr := sqli.GetGlobalMiddleware().ScanCommandResponse(ctx, req.Connector, result.Message, result.Metadata)
	if scanErr != nil {
		log.Printf("[MCP] SQLi scan error: %v", scanErr)
		// Continue - don't block on scan errors
	} else if scanResult.Blocked {
		log.Printf("[MCP] SQLi detected in command response from connector '%s': pattern=%s category=%s",
			req.Connector, scanResult.Pattern, scanResult.Category)
		sendErrorResponse(w, fmt.Sprintf("Response blocked: potential SQL injection detected (pattern: %s)", scanResult.Pattern), http.StatusForbidden, nil)
		return
	}

	// Return results
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"connector":     req.Connector,
		"rows_affected": result.RowsAffected,
		"duration_ms":   result.Duration.Milliseconds(),
		"message":       result.Message,
	}); err != nil {
		log.Printf("Error encoding MCP execute response: %v", err)
	}

	log.Printf("[MCP] Command executed: connector=%s, action=%s, rows_affected=%d, duration=%v",
		req.Connector, req.Action, result.RowsAffected, result.Duration)
}

// mcpHealthHandler returns overall MCP system health
// GET /mcp/health
func mcpHealthHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	healthStatuses := mcpRegistry.HealthCheck(ctx)

	healthyCount := 0
	unhealthyCount := 0
	for _, status := range healthStatuses {
		if status.Healthy {
			healthyCount++
		} else {
			unhealthyCount++
		}
	}

	overallHealthy := unhealthyCount == 0

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"healthy":          overallHealthy,
		"total_connectors": mcpRegistry.Count(),
		"healthy_count":    healthyCount,
		"unhealthy_count":  unhealthyCount,
		"timestamp":        time.Now().UTC(),
	}); err != nil {
		log.Printf("Error encoding MCP health check response: %v", err)
	}
}
