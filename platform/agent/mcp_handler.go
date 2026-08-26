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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"axonflow/platform/agent/fincrime"
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
	sharedaudit "axonflow/platform/shared/audit"
	"axonflow/platform/shared/idempotency"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/secretenv"
	"axonflow/platform/shared/serviceauth"
)

// Global MCP connector registry
var mcpRegistry *registry.Registry

// Global RuntimeConfigService for three-tier configuration
var runtimeConfigService *config.RuntimeConfigService

// internalTokenValidator is initialized at startup if AXONFLOW_INTERNAL_SERVICE_SECRET is configured.
// It validates HMAC-signed tokens from the orchestrator, with backward compatibility for legacy tokens.
var internalTokenValidator *serviceauth.TokenValidator

func init() {
	// secretenv.Get trims AWS-SM-quirky trailing whitespace; an HMAC seed
	// with a stray newline produces a different digest from the orchestrator
	// side and silently fails the 401 verification path.
	if secret := secretenv.Get(serviceauth.SecretEnvVar); secret != "" {
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
	}
	serviceauth.LogAuthWarning()
}

// validateServiceLicense validates a service license key and checks MCP
// permissions. In community mode, license validation is skipped entirely since
// MCP features are community features. Returns (servicePermissionGranted, error);
// on error the HTTP response has already been sent.
//
// For service licenses it gates the requested connector:operation through
// EvaluateMCPPermission — making it a Policy Enforcement Point.
// auditTenantID/auditOrgID/auditClientID carry the AUTHENTICATED request identity
// (resolved by the caller) used to key the canonical audit_logs row on a
// permission-denied deny (#2684); they are NOT the service-license identity
// (ValidationResult.OrgID is the licensee/deployment, which must never land in a
// customer-data row).
// latencyMs (#3424) is the CALLING handler's elapsed time. This gate runs
// before the connector is touched, so it is a pure enforcement duration on
// both call sites.
func validateServiceLicense(ctx context.Context, w http.ResponseWriter, licenseKey, connector, operation, fallbackOperation, auditTenantID, auditOrgID, auditClientID string, latencyMs int64) (bool, error) {
	if licenseKey == "" || isCommunityMode() || isCommunitySaasMode() {
		return false, nil
	}

	validationResult, err := license.ValidateLicense(ctx, licenseKey)
	if err != nil {
		log.Printf("[MCP] License validation failed: %v", err)
		sendErrorResponse(w, "Invalid license key", http.StatusUnauthorized, nil)
		return false, err
	}

	if !validationResult.Valid {
		log.Printf("[MCP] License invalid or expired: %s", validationResult.Error)
		sendErrorResponse(w, "License invalid or expired", http.StatusUnauthorized, nil)
		return false, fmt.Errorf("license invalid or expired: %s", validationResult.Error)
	}

	// Check service permissions (if this is a service license)
	if validationResult.ServiceName != "" {
		op := operation
		if op == "" {
			op = fallbackOperation
		}

		pe := policy.NewPermissionEvaluator()
		allowed, err := pe.EvaluateMCPPermission(validationResult, connector, op)
		if !allowed {
			log.Printf("[MCP] Permission denied: %v", err)
			// #2684: the EvaluateMCPPermission gate is a PEP; its authz-failure deny
			// previously wrote NO canonical row (sibling of #2683 HOLE D). Record a
			// canonical plane=mcp "blocked" row keyed on the AUTHENTICATED request
			// identity passed by the caller — never the service-license deployment id
			// (the licensee, not a customer tenant). The reason is connector:op only
			// (the license key never appears). 403 stays authoritative; audit is
			// best-effort.
			writeMCPDecisionAudit(ctx, usageDB,
				uuid.New().String(), "",
				auditTenantID, auditOrgID, auditClientID, "",
				"", "service",
				"mcp_permission_check", fmt.Sprintf("mcp permission: %s:%s", connector, op), "",
				mcpVerdictBlocked,
				[]string{"mcp_permission_denied"},
				[]string{fmt.Sprintf("service permission denied for %s:%s", connector, op)},
				nil,
				"",
				nil,
				latencyMs)
			sendErrorResponse(w, fmt.Sprintf("Permission denied: %v", err), http.StatusForbidden, nil)
			return false, fmt.Errorf("permission denied: %v", err)
		}

		log.Printf("[MCP] Service '%s' granted permission for %s:%s",
			validationResult.ServiceName, connector, op)
		return true, nil
	}

	return false, nil
}

// getMCPAuditQueue returns the audit queue for MCP handlers.
func getMCPAuditQueue() *AuditQueue {
	if auditManager != nil {
		return auditManager.GetQueue()
	}
	return nil
}

// computeStatementHash computes a SHA256 hash of the statement for audit logging.
// This provides linkage without storing the raw query for privacy.
func computeStatementHash(statement string) string {
	if statement == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(statement))
	return hex.EncodeToString(hash[:])
}

// computeParametersHash computes a SHA256 hash of the parameters map for audit logging.
// JSON-serializes with sorted keys (Go's json.Marshal sorts map keys), then SHA-256 + hex.
// Returns "" for nil or empty maps.
func computeParametersHash(params map[string]interface{}) string {
	if len(params) == 0 {
		return ""
	}
	data, err := json.Marshal(params)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// logMCPQueryAudit logs an MCP query operation to the audit queue.
// This is called at the end of mcpQueryHandler to persist the audit entry.
func logMCPQueryAudit(entry MCPQueryAuditEntry) {
	auditQueue := getMCPAuditQueue()
	if auditQueue == nil {
		log.Printf("[MCP Audit] Skipping audit - queue not initialized")
		return
	}

	if err := auditQueue.LogMCPQueryAudit(entry); err != nil {
		log.Printf("[MCP Audit] Failed to log audit entry: %v", err)
	} else {
		log.Printf("[MCP Audit] Logged: connector=%s, blocked=%v, redacted=%v, exfil=%v",
			entry.ConnectorName, entry.RequestBlocked, entry.ResponseRedacted, entry.ExfilExceeded)
	}
}

// extractMatchedPolicyIDs extracts policy IDs from PolicyMatch structs for audit logging.
func extractMatchedPolicyIDs(matches []sharedpolicy.PolicyMatch) []string {
	if len(matches) == 0 {
		return nil
	}
	ids := make([]string, len(matches))
	for i, m := range matches {
		ids[i] = m.PolicyID
	}
	return ids
}

// InitializeMCPRegistry sets up the MCP connector registry and registers default connectors
// Configuration priority: Database > Config File (AXONFLOW_CONFIG_FILE) > Environment Variables
func InitializeMCPRegistry() error {
	return InitializeMCPRegistryWithDB(nil)
}

// InitializeMCPRegistryWithDB sets up the MCP connector registry with optional database support
// This enables three-tier configuration: Database > Config File > Env Vars
func InitializeMCPRegistryWithDB(db *sql.DB) error {
	mcpRegistry = registry.NewRegistry()
	log.Println("[MCP] Initializing connector registry...")

	// Check for config file (Community mode)
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

// validateTenantConnectorAccess checks tenant access using runtime configuration when available.
// Falls back to static registry for backward compatibility.
func validateTenantConnectorAccess(ctx context.Context, connectorName, tenantID string) error {
	if runtimeConfigService != nil {
		if _, _, err := runtimeConfigService.GetConnectorConfig(ctx, tenantID, connectorName); err != nil {
			log.Printf("[MCP] Runtime connector access check failed for %q (tenant: %s): %v; falling back to static registry validation",
				logutil.Sanitize(connectorName), logutil.Sanitize(tenantID), err)
		} else {
			return nil
		}
	}
	if mcpRegistry == nil {
		return fmt.Errorf("MCP registry not initialized")
	}
	return mcpRegistry.ValidateTenantAccess(connectorName, tenantID)
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
			log.Printf("[MCP] Retrieved connector '%s' for tenant '%s' from TenantConnectorRegistry", logutil.Sanitize(connectorName), logutil.Sanitize(tenantID))
			return connector, nil
		}
		// Log the error but fall back to static registry
		log.Printf("[MCP] TenantConnectorRegistry lookup failed for '%s' (tenant: %s): %v, falling back to static registry",
			logutil.Sanitize(connectorName), logutil.Sanitize(tenantID), err)
	}

	// Fall back to static registry (backward compatibility)
	if mcpRegistry == nil {
		return nil, fmt.Errorf("MCP registry not initialized")
	}

	// #3067 (S-1): the static-registry fallback is tenant-scoped too. Before,
	// a lookup that missed the per-tenant cache fell through to a flat
	// deployment-wide map and could return another tenant's connector.
	connector, err := mcpRegistry.Get(tenantID, connectorName)
	if err != nil {
		return nil, fmt.Errorf("connector '%s' not found: %w", connectorName, err)
	}

	log.Printf("[MCP] Retrieved connector '%s' from static registry (fallback, tenant: %s)", logutil.Sanitize(connectorName), logutil.Sanitize(tenantID))
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
	// Connector inventory + per-connector health.
	//
	// #3067 (S-5): these two were registered with NO auth middleware and
	// served every tenant's connector name, type, version, capabilities,
	// health and raw driver error strings (which routinely embed host/db/user)
	// to any anonymous caller; the /health variant additionally opened a live
	// connection using the victim's decrypted credentials. They are now behind
	// apiAuthMiddleware and scoped to the authenticated tenant, which is the
	// same gate /api/clients and /api/policies/test already use. Registering
	// them here (rather than leaving them bare on globalRouter) also keeps
	// them from shadowing the authenticated proxy prefix — the route-ordering
	// class tracked separately as #2883.
	//
	// NOTE (R3 BLOCKER): these are registered for GET ONLY, deliberately.
	// apiAuthMiddleware forwards CORS preflights (`OPTIONS`) to the next
	// handler WITHOUT authenticating — so registering "OPTIONS" here would
	// hand an anonymous caller the handler with no identity in context, which
	// resolves to the deployment-shared scope and serves exactly the
	// inventory + live health check this change is closing. These endpoints
	// are server-to-server (SDK/plugin), not browser-XHR, so they need no
	// preflight.
	r.Handle("/mcp/connectors", apiAuthMiddleware(http.HandlerFunc(mcpListConnectorsHandler))).Methods("GET")

	// Health check for specific connector
	r.Handle("/mcp/connectors/{name}/health", apiAuthMiddleware(http.HandlerFunc(mcpConnectorHealthHandler))).Methods("GET")

	// Execute query (MCP Resource pattern - read-only)
	r.HandleFunc("/mcp/resources/query", mcpQueryHandler).Methods("POST")

	// Execute command (MCP Tool pattern - write operations)
	r.HandleFunc("/mcp/tools/execute", mcpExecuteHandler).Methods("POST")

	// Overall MCP health check
	r.HandleFunc("/mcp/health", mcpHealthHandler).Methods("GET")

	// Standalone policy-check endpoints (Issue #1258)
	// These allow external orchestrators to use AxonFlow as a policy gate
	// without routing MCP execution through AxonFlow.
	r.HandleFunc("/api/v1/mcp/check-input", mcpCheckInputHandler).Methods("POST")
	r.HandleFunc("/api/v1/mcp/check-output", mcpCheckOutputHandler).Methods("POST")

	log.Println("[MCP] Registered MCP endpoint handlers")
}

// mcpListConnectorsHandler lists all registered connectors with health status
// GET /mcp/connectors
func mcpListConnectorsHandler(w http.ResponseWriter, r *http.Request) {
	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	// Tenant comes from the authenticated credential (apiAuthMiddleware), never
	// from a caller-supplied header or path segment (#3067 S-5).
	tenantID := TenantIDFromContext(r.Context())

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Get health status for the connectors this tenant may reach
	healthStatuses := mcpRegistry.HealthCheck(ctx, tenantID)

	// Build response
	connectors := make([]map[string]interface{}, 0)
	for name, status := range healthStatuses {
		connector := map[string]interface{}{
			"name":       name,
			"healthy":    status.Healthy,
			"latency_ms": status.Latency.Milliseconds(),
		}

		// Get connector type from registry
		if conn, err := mcpRegistry.Get(tenantID, name); err == nil {
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

	// #3067 (S-5): scope to the authenticated tenant. Naming another tenant's
	// connector now yields the same 404 as a nonexistent one — no existence
	// oracle, and no live connection opened with the victim's credentials.
	tenantID := TenantIDFromContext(r.Context())

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	status, err := mcpRegistry.HealthCheckSingle(ctx, tenantID, connectorName)
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
	TenantID   string                 `json:"tenant_id"`   // Tenant for internal service requests
	Connector  string                 `json:"connector"`   // Connector name
	Operation  string                 `json:"operation"`   // Operation name (e.g., "search_flights", "query")
	Statement  string                 `json:"statement"`   // SQL/CQL statement
	Parameters map[string]interface{} `json:"parameters"`  // Query parameters
	Limit      int                    `json:"limit"`       // Result limit (optional)
	Timeout    string                 `json:"timeout"`     // Timeout (optional, e.g., "5s")
}

// --- Policy evaluation helpers (Issue #1258) ---
// These helpers allow the same policy logic to be reused by mcpQueryHandler,
// mcpExecuteHandler, and the new standalone check-input / check-output handlers.

// InputPolicyOutcome carries the results of dynamic + request-phase static policy evaluation.
// It avoids mixing audit concerns with policy logic so callers retain full control.
type InputPolicyOutcome struct {
	// EvalUnavailable is true when the dynamic evaluator returned a transient error.
	// Callers should respond with 503 Service Unavailable.
	EvalUnavailable bool

	// DynamicBlocked is true when the dynamic policy engine was the deciding factor.
	// Callers should include DynamicInfo in the 403 response body.
	DynamicBlocked bool

	// DynamicBlockReason is the human-readable block reason from the dynamic policy engine.
	DynamicBlockReason string

	// DynamicInfo is the structured info returned by the dynamic evaluator.
	// Populated whenever the dynamic evaluator ran (allowed or blocked).
	DynamicInfo *sharedpolicy.DynamicPolicyInfo

	// StaticResult is the result of request-phase static policy evaluation.
	// Nil when the static policy engine is disabled or the connector is excluded.
	StaticResult *sharedpolicy.RequestResult

	// FinCrime is the Fraud & Risk Add-on seam result (ADR-061 / #3329).
	// Nil on community builds, when the fincrime engine is not wired, when
	// the request carries no fincrime context and produced no score, or
	// when an earlier engine already blocked. Advisory-shaped: it can only
	// request needs_approval, never deny.
	FinCrime *fincrime.Result
}

// evaluateInputPolicies runs dynamic + request-phase static policy checks without
// calling any connector. Shared by mcpQueryHandler, mcpExecuteHandler,
// mcpCheckInputHandler, and handleDecide (Issues #1258, #2801).
//
// detectionCfg is caller-resolved (ResolveMCPDetectionConfig for the managed/
// advisory MCP planes, ResolveGatewayDetectionConfig for /decide) so each
// caller's org-override posture and connector-scoping rules stay exactly what
// they are today; this function no longer resolves a config itself.
//
// runDynamicPolicy gates the dynamic policy engine (rate limits, budgets,
// time/role access). /decide passes false: dynamic policy support there is
// M2 scope per epic #2426 (see decision_handler.go doc comment) — the
// orchestrator round-trip it requires doesn't fit /decide's inline
// single-digit-millisecond RPC budget.
//
// v9 Phase 8 #2384 PR-C1: orgID is plumbed through to EvalOptions.OrgID so
// metrics.RecordViolation can stamp shared AuditEntry.OrgID, which the
// audit_queue persistence path uses to pin app.current_org_id under
// axonflow_app_role for the policy_metrics / policy_violations INSERTs.
//
// toolIdentity (#2801) feeds capability-scoped evaluation and is DISTINCT
// from connectorName: ADVISORY planes (check-input, mcp-server check_policy,
// /decide) pass the caller-sent tool identity — the enforcing client is the
// trust anchor for what tool it is about to run. MANAGED-CONNECTOR planes
// (resources/query, tools/execute) MUST pass "" — there the AGENT executes
// the statement against the real connector, and the connector NAME is
// tenant-chosen free-form text: a postgres connector registered as
// "jira_get_issue" would otherwise classify text-document and silently lose
// SQLi enforcement on statements that genuinely execute. Empty = full
// evaluation (fail-closed).
// segments is the caller's fail-closed-resolved governance-segment set
// (ADR-060) to apply to this evaluation, or nil when the calling plane has
// not resolved one - see the Segments field doc (shared/policy/types.go)
// for exactly which callers pass a real set as of #3430/#3447 and which
// still pass nil, and why. This is a plain slice, never a status: a caller
// that resolves fail-closed and gets ok==false MUST deny before ever
// reaching this function, not translate the failure into an empty/nil
// segments argument here - nil/empty here always means "resolved to no
// segments / not resolved on this plane", never "resolution failed".
//
// #3447: the set is applied to BOTH planes this function touches, not just
// the local static pass. It is relayed to the orchestrator's dynamic
// evaluator as DynamicPolicyRequest.SegmentIDs (see the dynamicReq literal
// below) so a verified member does not get segment-scoped DYNAMIC policies
// silently skipped while the static half enforces them. Threading it into
// the static EvalOptions alone would close only half the bypass.
func evaluateInputPolicies(
	ctx context.Context,
	tenantID, orgID, userID, userRole, connectorName, toolIdentity, operation, statement string,
	parameters map[string]interface{},
	detectionCfg ModeDetectionConfig,
	runDynamicPolicy bool,
	segments []string,
) InputPolicyOutcome {
	var out InputPolicyOutcome

	// Dynamic policy evaluation (rate limits, budgets, time/role access)
	if runDynamicPolicy {
		dynamicEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
		if dynamicEvaluator != nil && dynamicEvaluator.IsEnabled(connectorName) {
			dynamicReq := sharedpolicy.DynamicPolicyRequest{
				TenantID: tenantID,
				// Decision 5 (#3490): the orchestrator's dynamic gate keys
				// on org_id now, and this hop carries NO tenancy headers
				// (dynamic_evaluator.go sets only Content-Type,
				// X-Request-Source and the internal-service token), so
				// carriesStampedTenancy is false there and the org can only
				// come from this field. Leaving it unset would have made
				// every tenant-authored dynamic policy silently inapplicable
				// on the MCP planes - a total, quiet loss of enforcement,
				// not a refusal. orgID here is the validated caller org the
				// static half one screen below already scopes by.
				OrganizationID: orgID,
				UserID:         userID,
				UserRole:       userRole,
				ConnectorName:  connectorName,
				Operation:      operation,
				Statement:      statement,
				Parameters:     parameters,
				// #3447: RELAY the set the agent already resolved; the
				// orchestrator deliberately does NOT resolve independently.
				// The two processes hold SEPARATE segment caches with
				// separate TTL clocks (segmentCache, default 60s,
				// instantiated once per process at
				// identity_attribute_resolver.go), so independent resolution
				// would let them observe different sets on the SAME request
				// - the static half enforcing a segment-scoped policy while
				// the dynamic half does not. Relaying one resolution makes
				// that split verdict impossible by construction, and costs
				// one resolution per request instead of two. The trust
				// argument is a wash either way: the orchestrator already
				// trusts what the agent asserts across the HMAC-authenticated
				// internal plane (requireInternalProxyAuth, #3068).
				SegmentIDs: segments,
			}
			dynamicResp, info, err := dynamicEvaluator.EvaluateWithGracefulDegradation(ctx, dynamicReq)
			out.DynamicInfo = info
			if err != nil {
				log.Printf("[MCP] Dynamic policy evaluation failed: %v", err)
				out.EvalUnavailable = true
				return out
			}
			if !dynamicResp.Allowed {
				log.Printf("[MCP] Request blocked by dynamic policy: %s", logutil.Sanitize(dynamicResp.BlockReason))
				out.DynamicBlocked = true
				out.DynamicBlockReason = dynamicResp.BlockReason
				return out
			}
		}
	}

	// Request-phase static policy evaluation (SQLi, PII, sensitive-data, compliance)
	policyEngine := sharedpolicy.GetGlobalEngine()
	if policyEngine != nil && detectionCfg.Enabled && detectionCfg.IsConnectorEnabled(connectorName) {
		// Security + sensitive-data + compliance categories stay explicit; the
		// PII categories are policy-derived (every enabled PII-category system
		// policy) so a new pii-* category (e.g. pii-indonesia) is auto-covered —
		// no hardcoded PII list to forget. The non-PII categories keep the slice
		// non-empty, so the empty-Categories-means-all whitelist footgun can't
		// apply here.
		inputCats := []sharedpolicy.PolicyCategory{
			sharedpolicy.CategorySecuritySQLi,
			sharedpolicy.CategorySecurityDangerous,
			sharedpolicy.CategorySensitiveData,
			sharedpolicy.CategoryComplianceRBI,
			sharedpolicy.CategoryComplianceSEBI,
			sharedpolicy.CategoryComplianceEUAIAct,
			sharedpolicy.CategoryComplianceMASFEAT,
			// ADR-061 / #3329: the FinCrime Policy Pack rows. Dedicated
			// category so the pack is governed by neither the PII/SQLi
			// posture levers nor capability scoping; rows exist only where
			// the enterprise pack was seeded, so this is a no-op otherwise.
			sharedpolicy.CategoryFinCrime,
		}
		inputCats = append(inputCats, policyEngine.EnabledPIICategories(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseRequest)...)
		out.StaticResult = policyEngine.EvaluateRequest(ctx, statement, sharedpolicy.EvalOptions{
			TenantID: tenantID,
			OrgID:    orgID,
			// #3048 R3 HIGH-3: scope the loader's tenant pass by the
			// validated caller org (org_id may differ from tenant_id).
			OrgScope:      sharedpolicy.OrgScopePtr(orgID),
			ConnectorName: connectorName,
			UserID:        userID,
			Parameters:    parameters,
			Categories:    inputCats,
			// #2801: capability-scoped evaluation. Advisory planes pass the
			// caller-sent tool identity (e.g.
			// claude_code.mcp__atlassian__editJiraIssue); managed-connector
			// planes pass "" (see the function doc). Unclassified/empty
			// identities get full evaluation.
			ToolIdentity:    toolIdentity,
			SkipCategories:  detectionCfg.SkipCategories,
			ActionOverrides: detectionCfg.BuildActionOverrides(),
			// #3430/#3447: the caller-supplied, already
			// fail-closed-resolved segment set (nil for planes that don't
			// resolve one - see this function's own doc and the Segments
			// field doc in shared/policy/types.go). A segment-scoped
			// static_policies row is excluded whenever the caller is not a
			// member (fail-closed, #3266 leak closed). This is the STATIC
			// half only; the dynamic half is the SegmentIDs relay above.
			Segments: segments,
		})
		if out.StaticResult.Blocked {
			policyID := "unknown"
			if out.StaticResult.BlockedBy != nil {
				policyID = out.StaticResult.BlockedBy.PolicyID
			}
			log.Printf("[MCP] Request blocked by static policy '%s': %s",
				policyID, out.StaticResult.BlockReason)
		}
	}

	// FinCrime seam (ADR-061 Decision 2 / #3329): Engine A evaluators +
	// Engine B scorer, consulted AFTER the static engine so the pack
	// policies (which the static engine evaluates like any other rows) have
	// already spoken. Skipped when the request is already blocked: a deny is
	// terminal and the seam is advisory-shaped (needs_approval at most), so
	// consulting it could not change the outcome. fincrimeEngine is nil on
	// community builds and when boot wiring did not construct it; the nil
	// path and the no-fincrime-context path both return nil, keeping this a
	// strict no-op for non-fincrime traffic.
	//
	// Gated on installed decision metadata: only the callers that WIRED the
	// seam (decide + MCP query/execute/check-input, each installing
	// fincrime.WithDecisionMeta with the id their audit rows carry) consult
	// it. A caller without metadata (today: the JSON-RPC mcp-server
	// check_policy plane, mcp_server_handler.go, which mints its decision id
	// only after evaluation and consumes no seam result) gets NO half
	// coverage: no scorer call the frozen contract could not attribute, no
	// validation verdict its response would silently drop. The pack's
	// static rows still enforce there like on every plane; wiring the seam
	// itself for that plane is P2 alongside gateway/WCP (ADR-061 rollout
	// checklist).
	if fincrime.DecisionMetaFromContext(ctx) != nil &&
		(out.StaticResult == nil || !out.StaticResult.Blocked) {
		out.FinCrime = fincrimeEngine.Evaluate(ctx, fincrime.Input{
			TenantID:      tenantID,
			OrgID:         orgID,
			UserID:        userID,
			UserRole:      userRole,
			ConnectorName: connectorName,
			ToolIdentity:  toolIdentity,
			Operation:     operation,
			AgentID:       ClientIDFromContext(ctx),
			SessionID:     clientSessionIDFromContext(ctx),
			Parameters:    parameters,
		})
		// #3306 attribution for pack-row matches on planes whose
		// terminal-allow audit rows do not carry request-phase match ids
		// (mcp query/execute): stamp the fincrime-category matches onto the
		// ctx audit holder so MergeAuditDetails appends them. Attribution
		// only, deduplicated everywhere it merges; planes that already
		// record the ids (decide, check-input) are unchanged.
		if out.StaticResult != nil {
			var packIDs, packNames []string
			for _, m := range out.StaticResult.MatchedPolicies {
				if m.Category == sharedpolicy.CategoryFinCrime {
					packIDs = append(packIDs, m.PolicyID)
					packNames = append(packNames, m.PolicyName)
				}
			}
			fincrime.StampPackMatches(ctx, packIDs, packNames)
		}
	}

	return out
}

// redactInputStatement runs the engine's redactor over a request statement so
// an allowed-but-PII-bearing statement can be forwarded in masked form. This is
// the request-phase half of the redaction contract (ADR-056 / #2563): /decide
// emits a self-describing redact_pii obligation naming check-input, and
// check-input returns the engine-masked statement so the PEP never hand-rolls
// its own patterns. The same engine primitive (EvaluateResponse) that masks
// connector responses masks the request — masking is direction-agnostic.
//
// Categories are policy-derived via the engine's canonical
// EnabledPIICategories (Session A's helper, #2565) — every enabled PII-category
// policy by the pii-* convention, so a new jurisdiction (e.g. pii-indonesia) is
// auto-covered with no hardcoded list. Returns the masked statement and whether
// any masking occurred; on no-PII / engine-disabled it returns ("", false, …)
// and the caller forwards the original statement verbatim.
//
// CONNECTOR-AGNOSTIC (ADR-056 Decision 3): unlike the managed-connector
// block/deny evaluators (evaluateInputPolicies / evaluateOutputPolicies), this
// path deliberately does NOT gate on mcpDetectionCfg.IsConnectorEnabled. A PEP
// in gateway/PDP mode has no managed connector — it passes a synthetic origin
// tag — so honouring the connector allowlist here would let an operator's
// allowlist (which excludes that synthetic tag) silently disable redaction
// while /decide still emits the obligation: the PEP would forward unredacted
// PII believing it had discharged the obligation. That fail-open is exactly
// what the ADR forbids. Redaction is content governance; the connector axis is
// meaningless for it. (The block/deny gate is unchanged; only this additive
// masking step is connector-agnostic.)
//
// CROSS-CONFIG fail-OPEN fix (#2563 B1): `/decide` emits the redact_pii
// obligation under the GATEWAY detection config, but check-input historically
// gated this fulfillment on the MCP config. With MCP redaction OFF + Gateway ON
// the PEP got the obligation, called check-input, and the redactor silently did
// not run — returning "nothing redacted", which the PEP could not distinguish
// from "engine looked, found nothing" → unredacted PII forwarded. Two fixes:
//  1. UNIFY the enable decision — redaction runs when EITHER the MCP or the
//     Gateway static-policy detection is enabled, so whenever /decide (gateway)
//     could emit the obligation, the fulfillment endpoint will actually redact.
//  2. Report `evaluated` — whether the detector ran at all — so check-input can
//     tell the PEP "redactor did not run" and the PEP fails CLOSED rather than
//     forwarding (covers a stale/cached obligation reaching a now-disabled
//     redactor). evaluated=false only when no detection config is enabled (a
//     state in which /decide also emits no obligation).
//
// Returns (masked, redacted, evaluated). redacted implies evaluated.
func redactInputStatement(ctx context.Context, tenantID, userID, connectorName, statement string) (masked string, redacted, evaluated bool) {
	policyEngine := sharedpolicy.GetGlobalEngine()
	// #2581: per-org posture. The auth-stamped request context carries the org
	// (check-input stamps it before this path); empty → deployment-global.
	orgID := OrgIDFromContext(ctx)
	mcpCfg := ResolveMCPDetectionConfig(ctx, orgID)
	gwCfg := ResolveGatewayDetectionConfig(ctx, orgID)
	// Effective config = whichever surface is enabled (prefer MCP for managed
	// connectors). The two derive their PII action from the same PII_ACTION env.
	effective := mcpCfg
	if !mcpCfg.Enabled && gwCfg.Enabled {
		effective = gwCfg
	}
	if policyEngine == nil || (!mcpCfg.Enabled && !gwCfg.Enabled) {
		return "", false, false
	}
	if statement == "" {
		return "", false, true // detector available; nothing to scan
	}
	// #2820: fail closed on a policy-LOAD error. EnabledPIICategories below
	// returns nil on BOTH "no PII category" and a load error; without this gate
	// a transient load failure would report evaluated=true, redacted=false —
	// "redactor ran, nothing to mask" — and the PEP would forward the statement
	// with PII unredacted (fulfilling a /decide redact_pii obligation it did not
	// actually discharge). Reporting evaluated=false makes the PEP fail CLOSED
	// (the #2563 B1 contract: redaction_evaluated=false → do not forward).
	if err := policyEngine.PoliciesLoadable(ctx, tenantID, sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)), sharedpolicy.PhaseRequest); err != nil {
		log.Printf("[MCP] redactInputStatement: could not load request-phase policies (fail-closed, #2820): %v", err)
		return "", false, false
	}
	// working accumulates redactions across the static engine and the
	// enterprise Indonesia checksum detector (the two diverged request-phase
	// detectors). evaluated stays true throughout — detection IS configured.
	working := statement
	anyRedacted := false

	// Static-engine redaction (regex categories: e.g. US SSN, Singapore NRIC).
	// Policy-derived category scoping (Session A's canonical helper, #2565):
	// the PII categories with an ENABLED request-phase policy for this tenant.
	// PhaseRequest keeps the redaction coverage phase-consistent with /decide's
	// obligation emission (also request-phase). EnabledPIICategories returns nil
	// when no PII policy is enabled — we MUST skip the EvaluateResponse call in
	// that case, because passing an empty Categories evaluates ALL policies (the
	// whitelist short-circuits).
	piiCats := policyEngine.EnabledPIICategories(ctx, tenantID, sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)), sharedpolicy.PhaseRequest)
	if len(piiCats) > 0 {
		result := policyEngine.EvaluateResponse(ctx, []map[string]interface{}{{"statement": working}}, sharedpolicy.EvalOptions{
			TenantID: tenantID,
			OrgScope: sharedpolicy.OrgScopePtr(OrgIDFromContext(ctx)), // #3048 R3 HIGH-3

			ConnectorName:   connectorName,
			UserID:          userID,
			Categories:      piiCats,
			SkipCategories:  effective.SkipCategories,
			ActionOverrides: effective.BuildActionOverrides(),
			MaxRedactions:   100,
		})
		if result != nil && result.Redacted {
			if rows, ok := result.Content.([]map[string]interface{}); ok && len(rows) > 0 {
				if out, ok := rows[0]["statement"].(string); ok && out != working {
					working = out
					anyRedacted = true
				}
			}
		}
	}

	// Enterprise Indonesia checksum redaction (NIK / NPWP). The static engine
	// above carries regex categories but NOT the checksum-validated NIK
	// detector, so without this step check-input masks Singapore NRIC yet
	// leaves NIK intact. /decide emits a redact_pii obligation naming
	// check-input for critical Indonesia PII (gateway_handlers / decision_handler),
	// so check-input MUST actually mask it here — otherwise the obligation is
	// unfulfillable and the PEP forwards NIK unredacted (#2571).
	if idMasked, changed := maskJSONSafe(working, redactIndonesiaPIIInString); changed {
		working = idMasked
		anyRedacted = true
	}

	if !anyRedacted {
		return "", false, true // redactor ran; nothing in scope to mask
	}
	return working, true, true
}

// OutputPolicyOutcome carries the results of SQLi scanning, response-phase static
// policy evaluation, and optionally exfiltration detection.
// It avoids mixing audit concerns with policy logic so callers retain full control.
type OutputPolicyOutcome struct {
	// SQLiBlocked is true when a SQL injection pattern was detected in the response.
	SQLiBlocked bool

	// SQLiPattern is the pattern that triggered the SQLi block.
	SQLiPattern string

	// StaticResult is the result of response-phase static policy evaluation (PII redaction etc).
	// Nil when the static policy engine is disabled or the connector is excluded.
	StaticResult *sharedpolicy.ResponseResult

	// RedactedRows is non-nil when PII redaction was applied to query rows.
	RedactedRows []map[string]interface{}

	// RedactedMessage is non-empty when PII redaction was applied to a command response message.
	RedactedMessage string

	// IndonesiaRedactedTypes lists the Indonesia (OJK/UU PDP) PII types masked on
	// the response in redact mode (e.g. nik, npwp_legacy, phone_indonesia). These
	// redactions come from the Enterprise Indonesia detector, NOT the shared static
	// engine, so they are tracked here separately and OR'd into the audit
	// redaction signal — otherwise a response whose ONLY redaction is Indonesian
	// PII would be masked for the caller but recorded as un-redacted in the audit
	// trail (the whole point of response-side governance is audit visibility).
	IndonesiaRedactedTypes []string

	// ExfilResult is the raw exfiltration check result. Nil when checkExfiltration is false
	// or when the exfiltration checker is disabled.
	ExfilResult *sharedpolicy.ExfiltrationResult

	// ExfilInfo is the structured exfiltration info for inclusion in PolicyInfo.
	ExfilInfo *sharedpolicy.ExfiltrationCheckInfo

	// RedactionEvaluated reports whether the response-phase redaction pipeline
	// actually RAN for this response (detection enabled for the connector and
	// not withheld by a fail-closed load error), regardless of whether it masked
	// anything. It is the response-plane mirror of the input plane's
	// redaction.Evaluated (#2865): a PEP fulfilling a response-phase redact_pii
	// obligation MUST fail closed when this is false, because "no redacted_data"
	// is then indistinguishable from "looked, found nothing." Surfaced to callers
	// as MCPCheckOutputResponse.redaction_evaluated on the allow path.
	RedactionEvaluated bool
}

// evaluateOutputPolicies runs SQLi response scanning, response-phase static policy
// evaluation (PII redaction), and optionally exfiltration detection on pre-executed
// connector output. No connector is called.
//
// Pass rows for query results and an empty message; pass nil rows and a non-empty message
// for execute results. Pass messageMetadata from CommandResult.Metadata (may be nil).
// Set checkExfiltration true for query-style responses, false for execute responses.
//
// Shared by mcpQueryHandler, mcpExecuteHandler, and mcpCheckOutputHandler (Issue #1258).
// maskJSONSafe applies masker to s while guaranteeing the result stays valid JSON
// when s was valid JSON. The EE Indonesia detector (redactIndonesiaPIIInString) and
// the static redactor mask matched spans IN the serialized string; when a PII value
// sits in a NON-string JSON position — a bare number, e.g. a NIK stored as an integer
// `{"nik":3174012509900001}` — flat masking yields invalid JSON and a downstream JSON
// consumer (the Claude Desktop proxy re-validates redacted_data) fail-closes the whole
// benign response. When s is valid JSON, maskJSONSafe applies masker per leaf (string
// leaves in place; a matched NUMBER leaf coerces to its masked STRING form) and
// re-serializes; otherwise it applies masker to the whole string unchanged.
func maskJSONSafe(s string, masker func(string) (string, bool)) (string, bool) {
	if !json.Valid([]byte(s)) {
		return masker(s)
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var root interface{}
	if err := dec.Decode(&root); err != nil || dec.More() {
		return masker(s) // not a single clean JSON document
	}
	changed := false
	var walk func(n interface{}) interface{}
	walk = func(n interface{}) interface{} {
		switch v := n.(type) {
		case map[string]interface{}:
			for k, val := range v {
				v[k] = walk(val)
			}
			return v
		case []interface{}:
			for i, val := range v {
				v[i] = walk(val)
			}
			return v
		case string:
			if m, c := masker(v); c {
				changed = true
				return m
			}
			return v
		case json.Number:
			if m, c := masker(v.String()); c {
				changed = true
				return m // coerce masked number -> string (keeps JSON valid)
			}
			return v
		default:
			return n // bool, nil
		}
	}
	root = walk(root)
	if !changed {
		// The per-leaf walk masked nothing. If the whole-string masker WOULD mask
		// (a match only across a JSON leaf boundary), fall back to it — a
		// redacted-but-possibly-invalid result, never the original unmasked
		// (fail-closed, never fail-open on a PII path).
		if flat, fc := masker(s); fc {
			return flat, true
		}
		return s, false
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // don't gratuitously escape <>& on the repair path
	if err := enc.Encode(root); err != nil {
		return masker(s) // fall back rather than emit nothing
	}
	out := strings.TrimRight(buf.String(), "\n")
	// A span matching across a JSON leaf boundary is invisible to the per-leaf walk
	// and would survive in `out` even though we masked OTHER leaves. If the masker
	// still finds something in `out`, fall back to the flat whole-string result
	// (fail-closed) rather than forward a partially-redacted document.
	if _, residual := masker(out); residual {
		flat, _ := masker(s)
		return flat, true
	}
	return out, true
}

// indonesiaPIIRemainsAfterMask reports whether Indonesia PII is STILL present in
// the content that is about to be forwarded, after the redaction pass ran.
//
// It reconstructs the same concatenated text the detection pass used, so the
// two are directly comparable: if the detector found something before and still
// finds something after, at least one value was not masked. That is the case a
// batch-level "did we mask anything" flag cannot see, because the detector reads
// leaves joined together and the masker reads them one at a time -- a match
// spanning a leaf boundary is visible to the first and invisible to the second.
//
// Returning TRUE downgrades the recorded action from "redacted" to "detected".
// Fail-safe direction: an inconclusive answer must never inflate the claim.
func indonesiaPIIRemainsAfterMask(rows []map[string]interface{}, message string) bool {
	var text string
	if rows != nil {
		for _, row := range rows {
			for _, v := range row {
				if s, ok := v.(string); ok {
					text += s + " "
				}
			}
		}
	} else {
		text = message
	}
	if text == "" {
		return false
	}
	res := checkIndonesiaResponsePII(text, false)
	return res != nil && res.HasPII
}

// toolIdentity (#2801): same contract as evaluateInputPolicies — advisory
// planes (check-output, mcp-server check_output) pass the caller-sent
// connector_type; managed-connector planes (query/execute responses) pass ""
// because the connector NAME is tenant-chosen free-form text, not a
// capability statement. Empty = full evaluation.
// orgID is the caller's authenticated org scope (#3447). It was previously
// read back out of ctx at nine separate points inside this function
// (OrgIDFromContext), which made the response phase the only evaluator on
// either plane whose org scope was implicit — evaluateInputPolicies has taken
// an explicit orgID since #2384. Every call site passes the same value its
// ctx already carried, so this is a plumbing change, not a scope change; it
// exists so a caller whose authoritative org is NOT the ctx-stamped one
// (any future plane) cannot silently evaluate the response phase under a
// different org than the request phase.
//
// segments carries the same fail-closed-resolved governance-segment set
// (ADR-060) as evaluateInputPolicies' identically-named parameter - see its
// doc comment. Response-phase evaluation is restriction-only (redact/
// withhold, never grant), so applying the same fail-closed set here only
// ever makes the response MORE restrictive, never less; see the #3430
// call-site comments in mcpToolCheckOutput for why the response phase is in
// scope for this issue, not deferred alongside it. As of #3447 the four
// legacy MCP REST handlers in this file pass a real set here too
// (resolveHumanActorSegmentsForPolicy, human_actor_segment_gate.go).
func evaluateOutputPolicies(
	ctx context.Context,
	tenantID, orgID, userID, connectorName, toolIdentity string,
	rows []map[string]interface{},
	message string,
	messageMetadata map[string]interface{},
	rowCount int,
	checkExfiltration bool,
	isGateway bool, // true for PEP/gateway callers (check-output) → bypass the connector allowlist for PII detection
	segments []string,
) OutputPolicyOutcome {
	// #3447 R3: orgID became an explicit parameter here (the response-phase
	// census needs it). Before that, every org-derived read in this function
	// took OrgIDFromContext(ctx). Fall back to that when the parameter is
	// empty, so threading the value stays a PLUMBING change rather than a
	// behaviour change for a caller that has ctx but passes "" — otherwise a
	// per-org detection posture silently stops applying and a response that
	// should BLOCK merely redacts.
	if orgID == "" {
		orgID = OrgIDFromContext(ctx)
	}
	var out OutputPolicyOutcome

	// #2801: capability scoping must be plane-consistent. The SQLi response
	// middleware below is the same execution-class detector family as the
	// static security-sqli category — SQL keywords in a text-document tool's
	// OUTPUT are documentation, not a statement any executor runs — so it is
	// gated by the identical engine-side classification (built-in registry +
	// Enterprise extension + kill switch). Nil engine => scan runs
	// (fail-closed).
	textDocumentTool := false
	if eng := sharedpolicy.GetGlobalEngine(); eng != nil {
		textDocumentTool = eng.IsTextDocumentTool(toolIdentity)
	}

	// 1. SQLi response scan
	if textDocumentTool {
		// skip: execution-class scan on a text-document tool's output
	} else if rows != nil {
		scanResult, scanErr := sqli.GetGlobalMiddleware().ScanQueryResponse(ctx, connectorName, rows)
		if scanErr != nil {
			log.Printf("[MCP] SQLi scan error: %v", scanErr)
			// Continue - don't block on scan errors
		} else if scanResult.Blocked {
			log.Printf("[MCP] SQLi detected in response from connector '%s': pattern=%s category=%s",
				logutil.Sanitize(connectorName), logutil.Sanitize(scanResult.Pattern), logutil.Sanitize(string(scanResult.Category)))
			out.SQLiBlocked = true
			out.SQLiPattern = scanResult.Pattern
			return out
		}
	} else if message != "" {
		scanResult, scanErr := sqli.GetGlobalMiddleware().ScanCommandResponse(ctx, connectorName, message, messageMetadata)
		if scanErr != nil {
			log.Printf("[MCP] SQLi scan error: %v", scanErr)
			// Continue - don't block on scan errors
		} else if scanResult.Blocked {
			log.Printf("[MCP] SQLi detected in command response from connector '%s': pattern=%s category=%s",
				logutil.Sanitize(connectorName), logutil.Sanitize(scanResult.Pattern), logutil.Sanitize(string(scanResult.Category)))
			out.SQLiBlocked = true
			out.SQLiPattern = scanResult.Pattern
			return out
		}
	}

	// #2581: per-org posture. #3447: orgID is now the explicit parameter
	// rather than a ctx read-back; an empty value still resolves to the
	// deployment-global config (fail-safe, identical to pre-#2581).
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, orgID)
	// Connector-agnostic gateway path: a PEP/gateway caller (isGateway, e.g.
	// check-output submitting pre-executed output) has no managed connector, so
	// the MCP connector allowlist (IsConnectorEnabled, permissive-when-empty)
	// must NOT gate it — otherwise a configured allowlist silently disables
	// response PII redaction for the gateway. Managed-connector responses
	// (query/execute) keep the allowlist.
	detectionGate := mcpDetectionCfg.Enabled && (isGateway || mcpDetectionCfg.IsConnectorEnabled(connectorName))

	// #2820: fail closed on a policy-LOAD error before the static PII pass. The
	// static pass (step 3) enumerates categories via Enabled*Categories, which
	// return nil on BOTH "no enabled category" and a load error — so a transient
	// load failure would leave outCats empty, SKIP EvaluateResponse, and forward
	// the response with generic PII (email / SSN / phone) unredacted. Withhold
	// the whole response instead: a redactor must never forward content it could
	// not scan. Gated on detectionGate (only when detection would run for this
	// connector) so a detection-off deployment is unaffected. The engine-independent
	// Indonesia checksum masker (step 2) is NOT sufficient on its own — it cannot
	// clear generic PII — so a load error must block, not fall through to it.
	if policyEngine := sharedpolicy.GetGlobalEngine(); policyEngine != nil && detectionGate {
		if err := policyEngine.PoliciesLoadable(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseResponse); err != nil {
			log.Printf("[MCP] Response withheld: policy engine could not load response-phase policies (fail-closed, #2820): %v", err)
			out.StaticResult = &sharedpolicy.ResponseResult{
				Blocked:         true,
				EvaluationError: true,
				BlockReason:     "response withheld: policy engine could not evaluate (fail-closed)",
			}
			return out
		}
	}

	// #2865: record that the response redaction pipeline ran, so a response-phase
	// PEP can tell "scanned, nothing to mask" from "not scanned" and fail closed
	// on the latter. Set AFTER the #2820 load-error withhold (a withheld response
	// returns Blocked above, never as an allow that could claim it was scanned)
	// and guarded on a non-nil engine — with a nil engine the static PII pass
	// below is skipped and only the Indonesia checksum masker runs, which cannot
	// clear generic PII, so claiming "evaluated" would be a fail-open. This
	// mirrors the input plane's redaction.Evaluated exactly (engine nil OR
	// detection off ⇒ not evaluated). In a serving agent the engine is always
	// wired before the MCP routes mount (run.go), so the normal path is unaffected.
	out.RedactionEvaluated = detectionGate && sharedpolicy.GetGlobalEngine() != nil

	// 2. Indonesia (OJK/UU PDP) checksum-validated PII governance on the response.
	// The static policy engine CANNOT cover NIK on responses: sys_pii_indonesia_ktp
	// is a request-phase "menu/spec parity" row, and the real checksum-validated
	// NIK/NPWP detector is the Enterprise Indonesia detector — which, like the
	// orchestrator's response-side detector, must run on the response too. Without
	// this, NIK is governed on input (decision_handler/gateway_handlers) but leaks
	// on output. Runs before the static pass so a critical-PII hard-deny wins.
	if detectionGate {
		var idText string
		if rows != nil {
			for _, row := range rows {
				for _, v := range row {
					if s, ok := v.(string); ok {
						idText += s + " "
					}
				}
			}
		} else {
			idText = message
		}
		blockOnCritical := mcpDetectionCfg.PIIAction == DetectionActionBlock
		if idResult := checkIndonesiaResponsePII(idText, blockOnCritical); idResult != nil {
			if idResult.BlockRecommended {
				out.StaticResult = &sharedpolicy.ResponseResult{
					Blocked:     true,
					BlockReason: idResult.Reason,
					BlockedBy: &sharedpolicy.CompiledPolicy{
						PolicyID: "sys_pii_indonesia_ktp",
						Name:     "Indonesian KTP/NIK Detection",
						Category: sharedpolicy.CategoryPIIIndonesia,
					},
				}
				log.Printf("[MCP] Response blocked by Indonesia PII detection: %s", logutil.Sanitize(idResult.Reason))
				// #3242: persist the UU PDP / OJK detection events (MASKED values
				// only) so the OJK pii_redactions export evidences this RESPONSE-side
				// refusal. This plane is the one an auditor is most likely to be
				// missing: input-side NIK governance was already visible via the
				// decision row, output-side governance was invisible everywhere.
				// Best-effort; the block above is already held. No-op in community.
				recordIndonesiaPIIEvents(ctx, orgID, tenantID, "", "",
					PlaneMCP, indonesiaPIIActionBlocked, idResult)
				return out
			}
			// anyMasked records whether the redact pass below ACTUALLY modified
			// content. The persisted detection event's action is derived from it, so
			// "redacted" is never claimed on the strength of the posture alone:
			// idText is the concatenation of every string leaf, so a match spanning a
			// leaf boundary is detectable there and yet absent from every individual
			// leaf, leaving the content unmodified.
			anyMasked := false
			if idResult.HasPII && mcpDetectionCfg.PIIAction == DetectionActionRedact {
				// Mask NIK/NPWP/etc ONLY under PII_ACTION=redact, then feed the masked
				// content forward into the static pass below. Under warn/log the action
				// is detect-don't-modify (parity with the static engine + orchestrator,
				// which never mutate content for warn/log); block is handled above.
				if rows != nil {
					anyRedacted := false
					for _, row := range rows {
						for k, v := range row {
							if s, ok := v.(string); ok {
								if masked, changed := maskJSONSafe(s, redactIndonesiaPIIInString); changed {
									row[k] = masked
									anyRedacted = true
								}
							}
						}
					}
					if anyRedacted {
						out.RedactedRows = rows
						out.IndonesiaRedactedTypes = indonesiaDetectedTypeNames(idResult)
						anyMasked = true
					}
				} else if message != "" {
					if masked, changed := maskJSONSafe(message, redactIndonesiaPIIInString); changed {
						message = masked
						out.RedactedMessage = masked
						out.IndonesiaRedactedTypes = indonesiaDetectedTypeNames(idResult)
						anyMasked = true
					}
				}
			}
			// #3242: record the non-blocking outcome. Under a warn/log posture the
			// content is forwarded UNMODIFIED and this event is the only record that
			// Indonesia PII left the deployment in a tool response, so the action
			// must distinguish "we masked it" from "we saw it and did not".
			//
			// anyMasked alone is NOT sufficient to claim "redacted". It is a
			// BATCH-level flag over N detections, and the two passes see different
			// text: the detector runs over every string leaf CONCATENATED, the
			// masker runs per leaf. A match that spans a leaf boundary is detected
			// and NOT masked, so a batch where anything was masked would record
			// "redacted" for a bank account that was forwarded in the clear.
			//
			// The content is therefore RE-SCANNED after masking. If the detector
			// still finds Indonesia PII in what is about to be forwarded, at least
			// one value survived and the honest action is "detected" -- the record
			// that PII left the deployment unmasked, which is the one an auditor
			// most needs.
			if idResult.HasPII {
				cleanAfterMask := anyMasked && !indonesiaPIIRemainsAfterMask(rows, message)
				recordIndonesiaPIIEvents(ctx, orgID, tenantID, "", "",
					PlaneMCP, indonesiaPIIActionForEnforcedPlane(false, cleanAfterMask), idResult)
			}
		}
	}

	// 3. Response-phase static policy evaluation (PII redaction)
	policyEngine := sharedpolicy.GetGlobalEngine()
	if policyEngine != nil && detectionGate {
		var responseContent []map[string]interface{}
		if rows != nil {
			responseContent = rows
		} else if message != "" {
			responseContent = []map[string]interface{}{{"message": message}}
		}
		// Policy-derived PII categories: evaluate every enabled PII-category
		// system policy for the tenant rather than a hardcoded literal (which
		// had silently omitted pii-indonesia). nil => no enabled PII policies =>
		// skip the static PII pass; must NOT pass empty Categories, which would
		// evaluate ALL policies (the whitelist short-circuits on empty).
		piiCats := policyEngine.EnabledPIICategories(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseResponse)
		// #2705: also evaluate the sensitive-data (secrets) category so a credential-
		// shaped connector RESPONSE is warn/block-enforced per the profile lever (the
		// block is already honored below via out.StaticResult.Blocked). nil+nil => skip
		// (must NOT pass empty Categories — the whitelist footgun evaluates ALL).
		sensCats := policyEngine.EnabledSensitiveDataCategories(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseResponse)
		// #2727: also evaluate the security-dangerous category (dangerous commands +
		// indirect prompt-injection patterns, migrations 059/116) against the tool
		// OUTPUT. These policies seeded phase='request', so a malicious instruction
		// returned in a connector free-text field (a design-partner R&C policy pack,
		// section 5.1, OWASP LLM01) re-entered the model's context ungoverned. Once
		// migration core/128 flips them to phase='both' they load on the response
		// plane; folding the category in here is what actually evaluates them
		// (filterByCategories excludes any category not in the include set). On a
		// match the response action is resolved just below (REDACT by default -
		// sanitize the full injection statement, #2738 - configurable per-org to
		// warn/block), and the outcome is audited through the existing
		// out.StaticResult redacted/blocked path. nil => no enabled security-dangerous
		// policy for this phase => skip (must NOT pass empty Categories, the footgun).
		dangerCats := policyEngine.EnabledSecurityDangerousCategories(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseResponse)
		outCats := append(append(append([]sharedpolicy.PolicyCategory{}, piiCats...), sensCats...), dangerCats...)
		if responseContent != nil && len(outCats) > 0 {
			// #2727: the security-dangerous (injection) category is REDACTED on the
			// response plane by default (strip the injected span; surrounding data
			// survives), overridable per-(org, dangerous_command) to warn/block via
			// the detection-posture override. This is plane-specific: BuildActionOverrides
			// carries the request-plane DangerousCommandAction (block) for this category,
			// so we replace that entry for the response pass only. ResolveResponseInjectionAction
			// returns the org override when set, else the REDACT default.
			actionOverrides := mcpDetectionCfg.BuildActionOverrides()
			actionOverrides[sharedpolicy.CategorySecurityDangerous] = ResolveResponseInjectionAction(ctx, orgID).ToPolicyAction()
			out.StaticResult = policyEngine.EvaluateResponse(ctx, responseContent, sharedpolicy.EvalOptions{
				TenantID:      tenantID,
				OrgScope:      sharedpolicy.OrgScopePtr(orgID), // #3048 R3 HIGH-3
				ConnectorName: connectorName,
				UserID:        userID,
				Categories:    outCats,
				// #2801: capability scoping on the response plane. For the
				// categories evaluated here it only affects a text-document
				// tool's security-dangerous EXECUTION-class policies (the
				// content-borne injection guards and all PII/sensitive-data
				// stay in); unknown/empty identities are unaffected.
				ToolIdentity:    toolIdentity,
				SkipCategories:  mcpDetectionCfg.SkipCategories,
				ActionOverrides: actionOverrides,
				MaxRedactions:   100,
				// #3430/#3447: caller-supplied, already fail-closed-resolved
				// segment set (nil for planes that don't resolve one - see
				// this function's doc). Excludes segment-scoped
				// static_policies rows the caller is not a member of
				// (fail-closed, #3266 leak closed).
				Segments: segments,
			})
			// #2820: second line of defense — a load race between the
			// PoliciesLoadable gate above and here (cache expiry mid-request)
			// leaves EvaluationError set; withhold rather than forward unscanned
			// content.
			if out.StaticResult.EvaluationError {
				log.Printf("[MCP] Response withheld: response-phase scan could not complete (fail-closed, #2820)")
				out.StaticResult.Blocked = true
				if out.StaticResult.BlockReason == "" {
					out.StaticResult.BlockReason = "response withheld: policy engine could not evaluate (fail-closed)"
				}
				return out
			}
			if out.StaticResult.Blocked {
				policyID := "unknown"
				if out.StaticResult.BlockedBy != nil {
					policyID = out.StaticResult.BlockedBy.PolicyID
				}
				log.Printf("[MCP] Response blocked by policy '%s': %s",
					policyID, out.StaticResult.BlockReason)
				return out
			}
			if out.StaticResult.Redacted {
				if rows != nil {
					if redactedRows, ok := out.StaticResult.Content.([]map[string]interface{}); ok {
						out.RedactedRows = redactedRows
					}
				} else if message != "" {
					if redactedRows, ok := out.StaticResult.Content.([]map[string]interface{}); ok && len(redactedRows) > 0 {
						if msg, ok := redactedRows[0]["message"].(string); ok {
							out.RedactedMessage = msg
						}
					}
				}
			}
		}
	}

	// 4. Exfiltration detection (enabled for query responses, disabled for execute)
	if checkExfiltration {
		exfiltrationChecker := sharedpolicy.GetGlobalExfiltrationChecker()
		if exfiltrationChecker != nil && exfiltrationChecker.IsEnabled() {
			// Use redacted data for accurate byte-count measurement
			var dataForExfil interface{}
			if rows != nil {
				if out.RedactedRows != nil {
					dataForExfil = out.RedactedRows
				} else {
					dataForExfil = rows
				}
			}
			exfilResult, exfilInfo := exfiltrationChecker.CheckWithInfo(ctx, rowCount, dataForExfil)
			out.ExfilResult = exfilResult
			out.ExfilInfo = exfilInfo
			if exfilResult.Exceeded {
				log.Printf("[MCP] Exfiltration limit exceeded for connector '%s': %s (actual=%d, limit=%d)",
					logutil.Sanitize(connectorName), logutil.Sanitize(exfilResult.LimitType), exfilResult.ActualValue, exfilResult.LimitValue)
			}
		}
	}

	return out
}

// WasRedacted reports whether ANY response redaction occurred — from the shared
// static engine OR the Enterprise Indonesia detector. Every redaction surface
// (client response body, MCP-tool response, audit trail) MUST gate on this, not
// on StaticResult alone: an Indonesia-ONLY redaction leaves StaticResult nil, so
// gating on StaticResult would forward the (already-masked) content with NO
// redaction signal — and on paths that gate the masked DATA on StaticResult,
// would forward the UNMASKED original (#2563 round-2 leak).
func (o OutputPolicyOutcome) WasRedacted() bool {
	return o.RedactedRows != nil || o.RedactedMessage != "" ||
		(o.StaticResult != nil && o.StaticResult.Redacted)
}

// RedactedFieldNames returns the union of static-engine redacted field paths and
// Indonesia-detector redacted type names, for client + audit redaction metadata.
func (o OutputPolicyOutcome) RedactedFieldNames() []string {
	var fields []string
	if o.StaticResult != nil && o.StaticResult.Redacted {
		fields = sharedpolicy.GetRedactedFieldPaths(o.StaticResult)
	}
	return append(fields, o.IndonesiaRedactedTypes...)
}

// mcpOutputDecisionVerdict maps a response-phase OutputPolicyOutcome to the
// canonical Decision Mode (verdict, policy_ids, reasons) triple recorded into
// audit_logs via recordDecideDecision. The branch order mirrors
// mcpCheckOutputHandler exactly (SQLi → static block → exfil → allow), so the
// recorded verdict always matches the HTTP branch that fires.
//
// Redaction is an allow-with-obligation, NOT a deny: a masked response still
// reaches the caller, so it records verdict=allow and surfaces the redacted
// field names in reasons (#2563 AUDIT-A1 HARD RULE 1 — redact must be
// portal-visible too, and distinguishable from a clean allow on the explain
// endpoint).
// blockedPolicyIDs returns the policy ids to attribute a response-phase block
// to. Most blocks populate MatchedPolicies, but a few single-policy blocks (the
// Indonesia NIK/KTP hard-deny) set only BlockedBy. Fall back to BlockedBy so the
// portal feed's policy_id column is populated for those cases too, instead of an
// empty attribution.
func blockedPolicyIDs(r *sharedpolicy.ResponseResult) []string {
	if ids := extractMatchedPolicyIDs(r.MatchedPolicies); len(ids) > 0 {
		return ids
	}
	if r.BlockedBy != nil && r.BlockedBy.PolicyID != "" {
		return []string{r.BlockedBy.PolicyID}
	}
	return nil
}

// #2641 (AUDIT-C / vocab contract #2638): returns the canonical PAST-TENSE
// policy_decision — blocked | redacted | allowed — NOT the legacy agent /decide
// vocab (allow/deny). A response redaction is its own "redacted" verdict (distinct
// from a clean allow) so the portal feed shows Redacted, not Allowed, for a
// NIK/NPWP response mask; the caller routes a "redacted" verdict to
// writeMCPDecisionAudit so redacted_fields lands on the canonical row.
func mcpOutputDecisionVerdict(outcome OutputPolicyOutcome) (verdict string, policyIDs, reasons []string, policyNames map[string]string) {
	// #3365: derive the display-name map beside the ids, in the same function
	// that picks them, so the two can never disagree about which policies a
	// row attributes. Synthetic ids (sqli_response_scan, exfiltration_limit)
	// resolve through the builtin table at stamp time.
	if outcome.StaticResult != nil {
		policyNames = policyNamesFromMatches(outcome.StaticResult.MatchedPolicies)
		if b := outcome.StaticResult.BlockedBy; b != nil && b.PolicyID != "" && b.Name != "" {
			policyNames = mergePolicyNames(policyNames, map[string]string{b.PolicyID: b.Name})
		}
	}
	switch {
	case outcome.SQLiBlocked:
		return mcpVerdictBlocked, []string{"sqli_response_scan"},
			[]string{fmt.Sprintf("SQL injection detected in response: %s", outcome.SQLiPattern)}, nil
	case outcome.StaticResult != nil && outcome.StaticResult.Blocked:
		return mcpVerdictBlocked, blockedPolicyIDs(outcome.StaticResult),
			[]string{outcome.StaticResult.BlockReason}, policyNames
	case outcome.ExfilResult != nil && outcome.ExfilResult.Exceeded:
		return mcpVerdictBlocked, []string{"exfiltration_limit"},
			[]string{outcome.ExfilResult.BlockReason}, nil
	}
	// Non-blocking terminal. Static redactions carry their matched policy ids; surface
	// the redacted field names so a redact is distinguishable from a clean allow.
	if outcome.StaticResult != nil {
		policyIDs = extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
	}
	if outcome.WasRedacted() {
		// Label the redaction by class so the audit feed is accurate: an
		// indirect-prompt-injection sanitization (#2727, security-dangerous) is NOT
		// a PII redaction. PII/Indonesia redactions keep the existing wording.
		label := "response PII redacted"
		if outcome.StaticResult != nil && redactionInvolvesInjection(outcome.StaticResult.MatchedPolicies) {
			label = "response prompt-injection sanitized"
		}
		if fields := outcome.RedactedFieldNames(); len(fields) > 0 {
			reasons = []string{label + ": " + strings.Join(fields, ", ")}
		} else {
			reasons = []string{label}
		}
		return mcpVerdictRedacted, policyIDs, reasons, policyNames
	}
	return mcpVerdictAllowed, policyIDs, reasons, policyNames
}

// redactionInvolvesInjection reports whether any matched response-phase policy is
// the security-dangerous (indirect prompt-injection) category, so the audit
// reason can describe an injection sanitization correctly rather than mislabeling
// it as a PII redaction (#2727).
func redactionInvolvesInjection(matches []sharedpolicy.PolicyMatch) bool {
	for i := range matches {
		if matches[i].Category == sharedpolicy.CategorySecurityDangerous {
			return true
		}
	}
	return false
}

// extractDynamicPolicyIDs returns the policy ids of the dynamic matches that
// drove a check-input decision, for canonical audit_logs attribution. Falls back
// to a generic "dynamic_policy" sentinel when the evaluator returned no per-policy
// match (e.g. a degraded/aggregate block), so the portal feed's policy_id column
// is never empty for a dynamic deny — mirroring blockedPolicyIDs' fallback on the
// response plane.
func extractDynamicPolicyIDs(info *sharedpolicy.DynamicPolicyInfo) []string {
	if info == nil {
		return []string{"dynamic_policy"}
	}
	ids := make([]string, 0, len(info.MatchedPolicies))
	for _, m := range info.MatchedPolicies {
		if m.PolicyID != "" {
			ids = append(ids, m.PolicyID)
		}
	}
	if len(ids) == 0 {
		return []string{"dynamic_policy"}
	}
	return ids
}

// mcpInputDecisionVerdict maps a terminal request-phase InputPolicyOutcome to the
// canonical Decision Mode (verdict, policy_ids, reasons) triple recorded into
// audit_logs via recordDecideDecision — the request-plane mirror of
// mcpOutputDecisionVerdict (#2627, mirroring #2586). The branch order matches the
// uncovered terminal branches of mcpCheckInputHandler: dynamic-block deny → allow.
//
// The static-block deny is deliberately NOT routed here: that path already
// dual-writes a richer canonical audit_logs row via writeExplainableAuditLog
// (policy_matches + risk_level), and the override-flip allow already writes one via
// writeOverrideUsedEvent. Routing those through this triple would double-write a
// second audit_logs row under the same decision_id. This helper covers exactly the
// two branches that previously wrote only the mcp_query_audits satellite.
//
// #2641 (AUDIT-C / vocab contract #2638): the verdict is the canonical PAST-TENSE
// policy_decision the portal decisions feed keys on — blocked | redacted | allowed
// — NOT the legacy agent /decide vocab (allow/deny). A redaction is its OWN verdict
// ("redacted"), distinct from a clean allow: a masked statement still forwards to
// the caller, but recording it as "allowed" hid the redaction from the portal
// (#2641 MCPIN — "redaction landing as allowed"). The redact reason is still
// surfaced so /explain stays self-describing.
func mcpInputDecisionVerdict(outcome InputPolicyOutcome, didRedact bool) (verdict string, policyIDs, reasons []string, policyNames map[string]string) {
	if outcome.DynamicBlocked {
		// #3365: dynamic matches carry their display names; the aggregate
		// "dynamic_policy" sentinel resolves through the builtin table.
		return mcpVerdictBlocked, extractDynamicPolicyIDs(outcome.DynamicInfo),
			[]string{outcome.DynamicBlockReason}, policyNamesFromDynamic(outcome.DynamicInfo)
	}
	// A non-blocking static (redact) policy carries its matched ids; surface them so
	// the portal feed attributes the decision correctly.
	if outcome.StaticResult != nil {
		policyIDs = extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
		policyNames = policyNamesFromMatches(outcome.StaticResult.MatchedPolicies)
	}
	if didRedact {
		return mcpVerdictRedacted, policyIDs, []string{"request PII redacted"}, policyNames
	}
	return mcpVerdictAllowed, policyIDs, reasons, policyNames
}

// applyResponseRedactionAudit records response-side redactions into the audit
// entry from BOTH sources (static engine + Indonesia detector). Either source
// alone counts — without the Indonesia arm, a response whose only masking is
// Indonesian PII would be returned redacted but logged un-redacted, defeating
// the OJK/UU-PDP response-audit purpose. Shared by all three output handlers.
func applyResponseRedactionAudit(auditEntry *MCPQueryAuditEntry, outcome OutputPolicyOutcome) {
	if !outcome.WasRedacted() {
		return
	}
	fields := outcome.RedactedFieldNames()
	auditEntry.ResponseRedacted = true
	auditEntry.ResponseRedactionsCount = len(fields)
	auditEntry.ResponseRedactedFields = fields
}

// mcpQueryHandler executes a query via a connector (MCP Resource pattern)
// POST /mcp/resources/query
func mcpQueryHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	var req MCPQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Extract client secret from OAuth2 Basic auth header if not in request body
	if req.LicenseKey == "" {
		req.LicenseKey = extractClientSecret(r)
	}

	// Initialize audit entry (will be populated throughout the handler).
	// #2679 (FIX-HOLE1 / AUDIT-C #2641): mint a decision_id up front so the
	// canonical audit_logs row this handler now emits on every terminal verdict
	// shares the same id as the legacy mcp_query_audits satellite (correlation).
	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.Connector,
		Operation:     "query",
		DecisionID:    uuid.New().String(),
		Success:       false, // Will be set to true only on successful completion
	}

	ctx := r.Context()

	// 1. Authenticate via unified authenticator
	hints := &AuthHints{ClientID: req.ClientID, UserToken: req.UserToken, TenantID: req.TenantID}
	auth, authErr := Authenticate(r, hints)
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}
	client := auth.Client

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via `ctx` agree
	// with the four-key shape apiAuthMiddleware writes (auth.go:658-661).
	// This handler is NOT behind apiAuthMiddleware. Sibling of #2319.
	ctx = stampAuthContext(ctx, client, auth.Kind)
	r = r.WithContext(ctx)

	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(ctx, auth.TenantID)

	// 1b. Resolve user identity
	user, userErr := ResolveUser(auth, req.UserToken)
	if userErr != nil {
		// Enterprise mode: if user token fails but Basic auth succeeded,
		// create a service user from client identity (backwards compat).
		// Email uses client.ID (the org boundary, not the credential identity)
		// because the synthetic user is org-scoped — ID:0 + Role:"service"
		// already weaken the audit value, and the email is human-readable
		// rather than load-bearing for any per-credential audit query.
		// Do NOT change to client.ClientID without an audit-query review.
		if auth.Kind == AuthKindEnterprise && req.UserToken == "" && !ResolveRequireUserToken(ctx, auth.OrgID) {
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		} else {
			// #3472: a PRESENTED token that fails validation (malformed, expired,
			// wrong alg, bad signature, jti-revoked) is a rejected access attempt,
			// not a compatibility case. Audit it, then 401. Parity with
			// decision_handler.go's /decide arm.
			//
			// #3476: with the org's posture requiring a token, a token-ABSENT
			// caller now also reaches this branch. The req.UserToken != "" guard
			// below is what keeps the two causes distinct: a presented-and-invalid
			// token still audits as user_token_rejected (#3472, unchanged); an
			// absent-and-required token audits under its own marker,
			// user_token_required, so the two causes never collapse.
			if req.UserToken != "" {
				writeMCPDecisionAudit(ctx, usageDB,
					auditEntry.DecisionID, auditEntry.AuditID,
					client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_resources_query", fmt.Sprintf("mcp resources/query: %s", req.Connector), "",
					mcpVerdictBlocked,
					[]string{"user_token_rejected"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					// #3472: reached before any connector.Query hop, so this IS an
					// honest enforcement duration (unlike the shared emitDecisionAudit
					// closure below, whose LatencyUnmeasured rationale doesn't apply here).
					time.Since(startTime).Milliseconds())
			} else {
				writeMCPDecisionAudit(ctx, usageDB,
					auditEntry.DecisionID, auditEntry.AuditID,
					client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_resources_query", fmt.Sprintf("mcp resources/query: %s", req.Connector), "",
					mcpVerdictBlocked,
					[]string{"user_token_required"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					time.Since(startTime).Milliseconds())
			}
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}

	// Verify tenant isolation
	if user.TenantID != client.TenantID {
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	// Update audit entry with authenticated user/client info.
	// ADR-052 §5: audit_logs.client_id is the credential identity (e.g.
	// api_key_id for API-keyed callers post-Fix 4), not the org boundary;
	// client.OrgID is the RLS boundary.
	auditEntry.TenantID = user.TenantID
	auditEntry.OrgID = client.OrgID
	auditEntry.ClientID = client.ClientID
	auditEntry.UserID = fmt.Sprintf("%d", user.ID)

	// 2. Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	// In community mode, skip license validation entirely - these are community features
	servicePermissionGranted, err := validateServiceLicense(ctx, w, req.LicenseKey, req.Connector, req.Operation, "query", user.TenantID, client.OrgID, client.ClientID, time.Since(startTime).Milliseconds())
	if err != nil {
		return // response already sent by validateServiceLicense
	}

	// 3. Validate tenant has access to connector (only for non-service licenses)
	// V2 service licenses already validated permissions via EvaluateMCPPermission above
	if !servicePermissionGranted {
		if err := validateTenantConnectorAccess(ctx, req.Connector, user.TenantID); err != nil {
			sendErrorResponse(w, "Unauthorized connector access", http.StatusForbidden, nil)
			return
		}
	}

	// 4. Get connector (uses TenantConnectorRegistry with fallback to static registry)
	connector, err := GetConnectorForTenant(ctx, user.TenantID, req.Connector)
	if err != nil {
		log.Printf("[MCP] Connector not found: %v", err)
		sendErrorResponse(w, "Connector not found", http.StatusNotFound, nil)
		return
	}

	// 5. Parse timeout
	var timeout time.Duration
	if req.Timeout != "" {
		timeout, err = time.ParseDuration(req.Timeout)
		if err != nil {
			sendErrorResponse(w, "Invalid timeout format", http.StatusBadRequest, nil)
			return
		}
	}

	// 6. Execute query
	// Use operation as statement for API connectors (e.g., "search_flights" for Amadeus)
	// For SQL connectors, statement would contain the actual SQL query
	statement := req.Statement
	if statement == "" && req.Operation != "" {
		statement = req.Operation
	}

	// Update audit entry with statement hash
	auditEntry.StatementHash = computeStatementHash(statement)

	query := &base.Query{
		Statement:  statement,
		Parameters: req.Parameters,
		Timeout:    timeout,
		Limit:      req.Limit,
		// Read-only posture (#2720, epic #2716): under MCP_READ_ONLY, run the
		// query inside the connector's read-only transaction (FU-4 #2735,
		// Postgres BEGIN READ ONLY) as a database-enforced backstop. The
		// statement-verb gate above already rejects classified writes; this
		// ensures anything the parser misses (a write smuggled past via a form
		// it never anticipated) is rejected by the DB at SQLSTATE 25006.
		ReadOnly: readOnlyPostureEnabled(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// #2679 (FIX-HOLE1): this connector-exec route is a full PEP, but every
	// terminal verdict previously wrote ONLY the mcp_query_audits satellite (no
	// reader) — so blocks/redactions were invisible in the portal /decisions feed
	// and the SEBI/EU-AI-Act exports. emitDecisionAudit additively persists the
	// canonical audit_logs row (plane=mcp, canonical past-tense policy_decision,
	// redacted_fields) via the AUDIT-C writer, keyed by the SAME decision_id as the
	// satellite. The satellite logMCPQueryAudit call at each branch is preserved.
	// query is a NON-PII descriptor (connector name) — the raw statement (which may
	// bear NIK/NPWP/SSN) MUST NOT land in audit_logs.query; it stays correlatable
	// via the preserved StatementHash.
	queryDescriptor := fmt.Sprintf("mcp resources/query: %s", req.Connector)
	correlationID := traceIDFromHeader(r.Header.Get("traceparent"))
	emitDecisionAudit := func(verdict string, policyIDs, reasons, redactedFields []string, policyNames map[string]string) {
		writeMCPDecisionAudit(ctx, usageDB,
			auditEntry.DecisionID, auditEntry.AuditID,
			user.TenantID, auditEntry.OrgID, auth.Client.ID, user.Email,
			auditEntry.UserID, user.Role,
			"mcp_resources_query", queryDescriptor, auditEntry.StatementHash,
			verdict, policyIDs, reasons, redactedFields,
			correlationID,
			policyNames,
			// #3424: NULL, deliberately. This ONE closure is invoked for
			// verdicts reached BEFORE connector.Query (policy blocks) and for
			// verdicts reached AFTER it (response SQLi / static / exfiltration
			// blocks and the redaction row), so a single time.Since(startTime)
			// would be an enforcement duration on some of its rows and an
			// enforcement duration plus a third-party connector round trip on
			// others. Averaging those together is the mixed-semantics defect
			// LatencyEnforcementPredicate exists to keep out of the tile.
			// Splitting the closure per verdict is filed as #3432.
			sharedaudit.LatencyUnmeasured)
	}

	// Read-only enforcement posture (#2720, epic #2716). resources/query hands the
	// caller-supplied statement straight to connector.Query, and SQL connectors
	// execute it verbatim, so a write DML (DELETE/UPDATE/DROP/...) would mutate
	// even though the plane's operation is the fixed "query". Classify the
	// STATEMENT verb and block writes here, before connector.Query, fail-closed on
	// an unclassifiable statement. Non-overridable; canonical "blocked" audit row.
	if readOnlyPostureEnabled() && statementIsWritePath(statement) {
		reason := fmt.Sprintf("read-only posture active: write-path statement on connector %q is blocked; only read-path operations are permitted", req.Connector)
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = reason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(mcpVerdictBlocked, []string{readOnlyPosturePolicyID}, []string{reason}, nil, nil)
		sendErrorResponse(w, "Request blocked: "+reason, http.StatusForbidden, nil)
		return
	}

	// #3447 (ADR-060 Slice 3): resolve this caller's governance-segment set
	// ONCE, fail-closed, and reuse it for BOTH the request phase below and
	// the response phase further down. Two resolutions in one request could
	// observe two different cache states and enforce two different sets on
	// one logical call. Keyed on the VALIDATED token email (user.Email),
	// never the trust-gated X-User-Email header. See
	// human_actor_segment_gate.go for the full contract.
	segmentIDs, segOK := resolveHumanActorSegmentsForPolicy(ctx, user.OrgID, auth.OrgID, user.Email,
		callerIsVerifiedHuman(auth, userErr, req.UserToken))
	if !segOK {
		// A resolver error for a caller who HAS a principal denies, on its
		// OWN channel: guard id segment_resolution_failed + 403. Deliberately
		// NOT InputPolicyOutcome.EvalUnavailable, which surfaces as 503
		// "Dynamic policy evaluation unavailable" — folding the two together
		// would make a deliberate policy-side deny indistinguishable from a
		// real orchestrator outage in both the audit row and the dashboard.
		writeMCPDecisionAudit(ctx, usageDB,
			auditEntry.DecisionID, auditEntry.AuditID,
			user.TenantID, auditEntry.OrgID, auth.ClientID, user.Email,
			auditEntry.UserID, "",
			"mcp_resources_query", queryDescriptor, "",
			mcpVerdictBlocked,
			[]string{mcpSegmentResolutionFailedPolicyID},
			[]string{segmentResolutionFailedReason},
			nil,
			correlationID,
			nil, // #3365: guard id resolves via the builtin table
			// Reached before connector.Query, so this IS an honest
			// enforcement duration (unlike the shared emitDecisionAudit
			// closure, whose LatencyUnmeasured rationale does not apply here).
			time.Since(startTime).Milliseconds())
		sendErrorResponse(w, "Request blocked: "+segmentResolutionFailedReason, http.StatusForbidden, nil)
		return
	}

	// Dynamic + request-phase static policy evaluation (Issues #968, #1081, #1258)
	// v9 Phase 8 #2384 PR-C1: orgID is on the legacy *User struct as OrgID.
	// #2581: per-org posture. orgID is the auth-derived org for this request; an
	// org with no override row resolves to the deployment-global config.
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, user.OrgID)
	// ADR-061 / #3329: decision metadata for the fincrime seam (frozen
	// scorer contract plane vocabulary "mcp"). The same ctx flows into the
	// audit writers below, which merge any fincrime attribution.
	ctx = fincrime.WithDecisionMeta(ctx, "mcp", auditEntry.DecisionID)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID), user.Role,
		req.Connector, "" /* toolIdentity: agent-executed plane, never capability-scoped (#2801) */, "query", statement, req.Parameters,
		mcpDetectionCfg, true, /* runDynamicPolicy */
		segmentIDs /* #3447: fail-closed-resolved above; nil means "org-only", never "resolution failed" */)

	if inputOutcome.EvalUnavailable {
		// Fail-closed: governance could not be rendered (503). Record a canonical
		// "error" row so the unevaluated attempt is portal-visible (#2679).
		emitDecisionAudit(mcpVerdictError,
			[]string{"dynamic_policy_unavailable"},
			[]string{"dynamic policy evaluation unavailable"}, nil, nil)
		sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
		return
	}

	if inputOutcome.DynamicBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = inputOutcome.DynamicBlockReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2679: a dynamic-policy block previously wrote ONLY the satellite, so the
		// portal feed showed it as "Logged", not "Blocked". Emit the canonical deny.
		v, pids, reasons, pnames := mcpInputDecisionVerdict(inputOutcome, false)
		emitDecisionAudit(v, pids, reasons, nil, pnames)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":             false,
			"error":               inputOutcome.DynamicBlockReason,
			"dynamic_policy_info": inputOutcome.DynamicInfo,
		})
		return
	}

	if inputOutcome.StaticResult != nil {
		auditEntry.RequestPoliciesEvaluated = inputOutcome.StaticResult.PoliciesEvaluated
		auditEntry.RequestMatchedPolicies = extractMatchedPolicyIDs(inputOutcome.StaticResult.MatchedPolicies)
		if inputOutcome.StaticResult.Blocked {
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = inputOutcome.StaticResult.BlockReason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			// #2679: request-phase static block — canonical deny row. The static-block
			// path here has no richer writeExplainableAuditLog (unlike check-input), so
			// this is the only canonical row; no double-write.
			emitDecisionAudit(mcpVerdictBlocked,
				extractMatchedPolicyIDs(inputOutcome.StaticResult.MatchedPolicies),
				[]string{inputOutcome.StaticResult.BlockReason}, nil,
				policyNamesFromMatches(inputOutcome.StaticResult.MatchedPolicies))
			sendErrorResponse(w, fmt.Sprintf("Request blocked: %s", inputOutcome.StaticResult.BlockReason),
				http.StatusForbidden, nil)
			return
		}
	}

	result, err := connector.Query(ctx, query)
	if err != nil {
		log.Printf("[MCP] Query failed: %v", err)

		// Log audit entry for query error
		auditEntry.ErrorMessage = err.Error()
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2679: tool-error fail-closed — the governed request could not be
		// fulfilled. Record a canonical "error" row (never the raw err string,
		// which may echo statement/PII).
		emitDecisionAudit(mcpVerdictError,
			[]string{"connector_error"}, []string{"query execution failed"}, nil, nil)

		sendErrorResponse(w, "Query execution failed", http.StatusInternalServerError, nil)
		return
	}

	// Response-phase policy evaluation: SQLi scan, PII redaction, exfiltration (Issue #1258)
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, auditEntry.OrgID, fmt.Sprintf("%d", user.ID), req.Connector,
		// toolIdentity: agent-executed plane, never capability-scoped (#2801)
		"",
		result.Rows, "", nil, result.RowCount, true,
		// isGateway: managed connector
		false,
		// #3447: the SAME set resolved once above for the request phase -- not
		// a second resolution, so the two phases of one call can never
		// disagree about membership.
		segmentIDs)

	// #2679: the response-phase verdict (SQLi/static-block/exfil-block → blocked;
	// redact → redacted; else allowed). Computed once; mcpOutputDecisionVerdict's
	// branch order mirrors the early-return order below, so the recorded verdict
	// always matches the HTTP branch that fires.
	outVerdict, outPolicyIDs, outReasons, outPolicyNames := mcpOutputDecisionVerdict(outputOutcome)

	// Use redacted row data if PII was redacted
	responseData := result.Rows
	if outputOutcome.RedactedRows != nil {
		responseData = outputOutcome.RedactedRows
	}

	// Update audit entry with output policy results
	auditEntry.ExfilRowsReturned = result.RowCount
	applyResponseRedactionAudit(&auditEntry, outputOutcome)

	if outputOutcome.SQLiBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("SQL injection detected: %s", outputOutcome.SQLiPattern)
		auditEntry.RowCount = result.RowCount
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response SQLi block
		sendErrorResponse(w,
			fmt.Sprintf("Response blocked: potential SQL injection detected (pattern: %s)", outputOutcome.SQLiPattern),
			http.StatusForbidden, nil)
		return
	}

	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason)
		auditEntry.RowCount = result.RowCount
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response static block
		sendErrorResponse(w, fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason),
			http.StatusForbidden, nil)
		return
	}

	if outputOutcome.ExfilResult != nil && outputOutcome.ExfilResult.Exceeded {
		auditEntry.ExfilExceeded = true
		auditEntry.ExfilLimitType = outputOutcome.ExfilResult.LimitType
		auditEntry.RowCount = result.RowCount
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: exfiltration-limit block
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":      false,
			"error":        outputOutcome.ExfilResult.BlockReason,
			"limit_type":   outputOutcome.ExfilResult.LimitType,
			"actual_value": outputOutcome.ExfilResult.ActualValue,
			"limit_value":  outputOutcome.ExfilResult.LimitValue,
		})
		return
	}

	// Build policy info for response
	policyInfo := sharedpolicy.BuildPolicyInfo(inputOutcome.StaticResult, outputOutcome.StaticResult)
	if policyInfo != nil && outputOutcome.ExfilInfo != nil {
		policyInfo.ExfiltrationCheck = outputOutcome.ExfilInfo
	} else if policyInfo == nil && outputOutcome.ExfilInfo != nil {
		policyInfo = &sharedpolicy.PolicyInfo{
			ExfiltrationCheck: outputOutcome.ExfilInfo,
		}
	}
	if policyInfo != nil && inputOutcome.DynamicInfo != nil {
		policyInfo.DynamicPolicyInfo = inputOutcome.DynamicInfo
	} else if policyInfo == nil && inputOutcome.DynamicInfo != nil {
		policyInfo = &sharedpolicy.PolicyInfo{
			DynamicPolicyInfo: inputOutcome.DynamicInfo,
		}
	}

	// 8. Return results
	// SDK expects "data" field (ConnectorResponse.Data), not "rows"
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success":     true,
		"connector":   req.Connector,
		"data":        responseData, // SDK looks for "data" field in sdk/golang/axonflow.go:595
		"row_count":   result.RowCount,
		"duration_ms": result.Duration.Milliseconds(),
	}

	// Add policy info fields (additive, backward compatible). Gate on WasRedacted
	// (static OR Indonesia) so an Indonesia-only redaction still surfaces the flag.
	if outputOutcome.WasRedacted() {
		response["redacted"] = true
		response["redacted_fields"] = outputOutcome.RedactedFieldNames()
	}
	if policyInfo != nil {
		response["policy_info"] = policyInfo
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding MCP query response: %v", err)
	}

	// Log successful audit entry
	auditEntry.Success = true
	auditEntry.RowCount = result.RowCount
	auditEntry.DurationMs = time.Since(startTime).Milliseconds()
	logMCPQueryAudit(auditEntry)
	// #2679: terminal allow (clean or redacted) previously wrote ONLY the
	// satellite, so an allowed/redacted governance decision never reached the
	// portal feed. A response redaction is its OWN verdict ("redacted") carrying
	// redacted_fields — recording it as "allowed" would hide the mask.
	emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, outputOutcome.RedactedFieldNames(), outPolicyNames)

	log.Printf("[MCP] Query executed: connector=%s, rows=%d, duration=%v",
		req.Connector, result.RowCount, result.Duration)
}

// MCPExecuteRequest represents a request to execute a command via a connector
type MCPExecuteRequest struct {
	ClientID   string                 `json:"client_id"`   // Required for authentication
	LicenseKey string                 `json:"license_key"` // Service license key for permission validation
	UserToken  string                 `json:"user_token"`  // Required for authentication
	TenantID   string                 `json:"tenant_id"`   // Tenant for internal service requests
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
	startTime := time.Now()

	if mcpRegistry == nil {
		sendErrorResponse(w, "MCP registry not initialized", http.StatusServiceUnavailable, nil)
		return
	}

	var req MCPExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Extract client secret from OAuth2 Basic auth header if not in request body
	if req.LicenseKey == "" {
		req.LicenseKey = extractClientSecret(r)
	}

	// Determine operation name for audit
	operation := req.Operation
	if operation == "" {
		operation = strings.ToLower(req.Action) // "INSERT" -> "insert"
		if operation == "" {
			operation = "execute"
		}
	}

	// Initialize audit entry (will be populated throughout the handler).
	// #2679 (FIX-HOLE1): mint a decision_id up front so the canonical audit_logs
	// row this handler now emits shares the same id as the mcp_query_audits
	// satellite (correlation).
	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.Connector,
		Operation:     operation,
		DecisionID:    uuid.New().String(),
		Success:       false, // Will be set to true only on successful completion
	}

	ctx := r.Context()

	// 1. Authenticate via unified authenticator
	hints := &AuthHints{ClientID: req.ClientID, UserToken: req.UserToken, TenantID: req.TenantID}
	auth, authErr := Authenticate(r, hints)
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}
	client := auth.Client

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via `ctx` agree
	// with the four-key shape apiAuthMiddleware writes (auth.go:658-661).
	// This handler is NOT behind apiAuthMiddleware. Sibling of #2319.
	ctx = stampAuthContext(ctx, client, auth.Kind)
	r = r.WithContext(ctx)

	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(ctx, auth.TenantID)

	// 1b. Resolve user identity
	user, userErr := ResolveUser(auth, req.UserToken)
	if userErr != nil {
		// Synthetic service-user email is org-scoped by design. See sibling
		// fallback in handleMCPQueryAccess for the full rationale.
		if auth.Kind == AuthKindEnterprise && req.UserToken == "" && !ResolveRequireUserToken(ctx, auth.OrgID) {
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		} else {
			// #3472: a PRESENTED token that fails validation (malformed, expired,
			// wrong alg, bad signature, jti-revoked) is a rejected access attempt,
			// not a compatibility case. Audit it, then 401. Parity with
			// decision_handler.go's /decide arm.
			//
			// #3476: with the org's posture requiring a token, a token-ABSENT
			// caller now also reaches this branch. The req.UserToken != "" guard
			// below keeps the two causes distinct: a presented-and-invalid token
			// still audits as user_token_rejected (#3472, unchanged); an
			// absent-and-required token audits under its own marker,
			// user_token_required, so the two causes never collapse.
			if req.UserToken != "" {
				writeMCPDecisionAudit(ctx, usageDB,
					auditEntry.DecisionID, auditEntry.AuditID,
					client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_tools_execute", fmt.Sprintf("mcp tools/execute: %s", req.Connector), "",
					mcpVerdictBlocked,
					[]string{"user_token_rejected"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					// #3472: reached before any connector.Execute hop, so this IS an
					// honest enforcement duration (unlike the shared emitDecisionAudit
					// closure below, whose LatencyUnmeasured rationale doesn't apply here).
					time.Since(startTime).Milliseconds())
			} else {
				writeMCPDecisionAudit(ctx, usageDB,
					auditEntry.DecisionID, auditEntry.AuditID,
					client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_tools_execute", fmt.Sprintf("mcp tools/execute: %s", req.Connector), "",
					mcpVerdictBlocked,
					[]string{"user_token_required"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					time.Since(startTime).Milliseconds())
			}
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}

	// Verify tenant isolation
	if user.TenantID != client.TenantID {
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	// Update audit entry with authenticated user/client info.
	// ADR-052 §5: see sibling audit-entry assignment in handleMCPQueryAccess
	// for rationale (audit_logs.client_id = credential identity, not org).
	auditEntry.TenantID = user.TenantID
	auditEntry.OrgID = auth.OrgID
	auditEntry.ClientID = client.ClientID
	auditEntry.UserID = fmt.Sprintf("%d", user.ID)

	// Read-only enforcement posture (#2720, epic #2716). This is the connector
	// EXECUTE plane, whose real side effect is connector.Execute below, so the
	// posture gates it here as an early hard boundary, before connector
	// resolution, policy evaluation, the override flow, and the Execute call.
	// A write-path call is blocked (canonical "blocked" audit row,
	// non-overridable); read-path calls fall through to normal governance.
	// Mirrors the mcp_server_handler check_policy gate; reuses classifyMCPCall.
	if readOnlyPostureEnabled() && classifyMCPCall(req.Connector, "", operation) == mcpAccessWrite {
		reason := fmt.Sprintf("read-only posture active: write-path tool call %q is blocked; only read-path operations are permitted", req.Connector)
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = reason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		writeMCPDecisionAudit(ctx, usageDB,
			auditEntry.DecisionID, auditEntry.AuditID,
			user.TenantID, auditEntry.OrgID, client.ClientID, user.Email,
			auditEntry.UserID, user.Role,
			"mcp_tools_execute", fmt.Sprintf("mcp tools/execute: %s", req.Connector), auditEntry.StatementHash,
			mcpVerdictBlocked,
			[]string{readOnlyPosturePolicyID},
			[]string{reason},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,
			// #3424: measured. Unlike the emitDecisionAudit closure below, this
			// gate is a direct call that always fires BEFORE connector
			// resolution, so the elapsed time is enforcement only.
			time.Since(startTime).Milliseconds())
		sendErrorResponse(w, "Request blocked: "+reason, http.StatusForbidden, nil)
		return
	}

	// Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	// In community mode, skip license validation entirely - these are community features
	servicePermissionGranted, err := validateServiceLicense(ctx, w, req.LicenseKey, req.Connector, req.Operation, strings.ToLower(req.Action), user.TenantID, auth.OrgID, client.ClientID, time.Since(startTime).Milliseconds())
	if err != nil {
		return // response already sent by validateServiceLicense
	}

	// Validate tenant has access to connector (only for non-service licenses)
	// V2 service licenses already validated permissions via EvaluateMCPPermission above
	if !servicePermissionGranted {
		if err := validateTenantConnectorAccess(ctx, req.Connector, user.TenantID); err != nil {
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

	// Update audit entry with statement hash
	auditEntry.StatementHash = computeStatementHash(req.Statement)

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// #2679 (FIX-HOLE1): canonical audit_logs writer for this connector-exec PEP.
	// See the sibling rationale in mcpQueryHandler — every terminal verdict
	// previously wrote ONLY the reader-less mcp_query_audits satellite, hiding
	// blocks/redactions from the portal feed + compliance exports. emitDecisionAudit
	// additively persists the canonical row (plane=mcp, canonical past-tense
	// policy_decision, redacted_fields) keyed by the SAME decision_id; query is a
	// NON-PII descriptor (the raw statement MUST NOT land in audit_logs.query).
	execDescriptor := fmt.Sprintf("mcp tools/execute: %s", req.Connector)
	correlationID := traceIDFromHeader(r.Header.Get("traceparent"))
	emitDecisionAudit := func(verdict string, policyIDs, reasons, redactedFields []string, policyNames map[string]string) {
		writeMCPDecisionAudit(ctx, usageDB,
			auditEntry.DecisionID, auditEntry.AuditID,
			user.TenantID, auditEntry.OrgID, auth.Client.ID, user.Email,
			auditEntry.UserID, user.Role,
			"mcp_tools_execute", execDescriptor, auditEntry.StatementHash,
			verdict, policyIDs, reasons, redactedFields,
			correlationID,
			policyNames,
			// #3424: NULL, deliberately -- same shared-closure reason as
			// mcpQueryHandler above (verdicts on both sides of
			// connector.Execute share this one call site). Filed as #3432.
			sharedaudit.LatencyUnmeasured)
	}

	// #3447 (ADR-060 Slice 3): one fail-closed segment resolution per request,
	// reused by the request phase below and the response phase further down.
	// See mcpQueryHandler's sibling block and human_actor_segment_gate.go.
	segmentIDs, segOK := resolveHumanActorSegmentsForPolicy(ctx, user.OrgID, auth.OrgID, user.Email,
		callerIsVerifiedHuman(auth, userErr, req.UserToken))
	if !segOK {
		// Own channel (segment_resolution_failed + 403), never EvalUnavailable
		// /503 -- see mcpQueryHandler's sibling block.
		writeMCPDecisionAudit(ctx, usageDB,
			auditEntry.DecisionID, auditEntry.AuditID,
			user.TenantID, auditEntry.OrgID, client.ClientID, user.Email,
			auditEntry.UserID, "",
			"mcp_tools_execute", execDescriptor, "",
			mcpVerdictBlocked,
			[]string{mcpSegmentResolutionFailedPolicyID},
			[]string{segmentResolutionFailedReason},
			nil,
			correlationID,
			nil,                                  // #3365: guard id resolves via the builtin table
			time.Since(startTime).Milliseconds()) // reached before connector.Execute -- enforcement only
		sendErrorResponse(w, "Request blocked: "+segmentResolutionFailedReason, http.StatusForbidden, nil)
		return
	}

	// Dynamic + request-phase static policy evaluation (Issues #968, #1081, #1258)
	// v9 Phase 8 #2384 PR-C1: orgID plumbed through for RLS-aware audit writes.
	// #2581: per-org posture. orgID is the auth-derived org for this request; an
	// org with no override row resolves to the deployment-global config.
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, user.OrgID)
	// ADR-061 / #3329: decision metadata for the fincrime seam ("mcp" plane);
	// the audit writers merge any fincrime attribution off this ctx.
	ctx = fincrime.WithDecisionMeta(ctx, "mcp", auditEntry.DecisionID)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID), user.Role,
		req.Connector, "" /* toolIdentity: agent-executed plane, never capability-scoped (#2801) */, "execute", req.Statement, req.Parameters,
		mcpDetectionCfg, true, /* runDynamicPolicy */
		segmentIDs /* #3447: fail-closed-resolved above; nil means "org-only", never "resolution failed" */)

	if inputOutcome.EvalUnavailable {
		// Fail-closed: governance could not be rendered (503) → canonical error row.
		emitDecisionAudit(mcpVerdictError,
			[]string{"dynamic_policy_unavailable"},
			[]string{"dynamic policy evaluation unavailable"}, nil, nil)
		sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
		return
	}

	if inputOutcome.DynamicBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = inputOutcome.DynamicBlockReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		v, pids, reasons, pnames := mcpInputDecisionVerdict(inputOutcome, false) // #2679: dynamic block
		emitDecisionAudit(v, pids, reasons, nil, pnames)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":             false,
			"error":               inputOutcome.DynamicBlockReason,
			"dynamic_policy_info": inputOutcome.DynamicInfo,
		})
		return
	}

	if inputOutcome.StaticResult != nil {
		auditEntry.RequestPoliciesEvaluated = inputOutcome.StaticResult.PoliciesEvaluated
		auditEntry.RequestMatchedPolicies = extractMatchedPolicyIDs(inputOutcome.StaticResult.MatchedPolicies)
		if inputOutcome.StaticResult.Blocked {
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = inputOutcome.StaticResult.BlockReason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			emitDecisionAudit(mcpVerdictBlocked, // #2679: request static block
				extractMatchedPolicyIDs(inputOutcome.StaticResult.MatchedPolicies),
				[]string{inputOutcome.StaticResult.BlockReason}, nil,
				policyNamesFromMatches(inputOutcome.StaticResult.MatchedPolicies))
			sendErrorResponse(w, fmt.Sprintf("Request blocked: %s", inputOutcome.StaticResult.BlockReason),
				http.StatusForbidden, nil)
			return
		}
	}

	result, err := connector.Execute(ctx, cmd)
	if err != nil {
		log.Printf("[MCP] Execute failed: %v", err)

		// Log audit entry for execution error
		auditEntry.ErrorMessage = err.Error()
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2679: tool-error fail-closed → canonical error row (never the raw err).
		emitDecisionAudit(mcpVerdictError,
			[]string{"connector_error"}, []string{"command execution failed"}, nil, nil)

		sendErrorResponse(w, "Command execution failed", http.StatusInternalServerError, nil)
		return
	}

	// Response-phase policy evaluation: SQLi scan, PII redaction (Issue #1258)
	// Exfiltration checking is not applied to execute results (execute returns rows_affected, not data rows).
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, auditEntry.OrgID, fmt.Sprintf("%d", user.ID), req.Connector,
		// toolIdentity: agent-executed plane, never capability-scoped (#2801)
		"",
		nil, result.Message, result.Metadata, int(result.RowsAffected), false,
		// isGateway: managed connector
		false,
		// #3447: the SAME set resolved once above for the request phase.
		segmentIDs)

	// #2679: response-phase verdict, computed once; branch order mirrors the
	// early-return order below so the recorded verdict matches the HTTP branch.
	outVerdict, outPolicyIDs, outReasons, outPolicyNames := mcpOutputDecisionVerdict(outputOutcome)

	// Use redacted message if PII was redacted
	responseMessage := result.Message
	if outputOutcome.RedactedMessage != "" {
		responseMessage = outputOutcome.RedactedMessage
	}

	// Update audit entry with output policy results
	applyResponseRedactionAudit(&auditEntry, outputOutcome)

	if outputOutcome.SQLiBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("SQL injection detected: %s", outputOutcome.SQLiPattern)
		auditEntry.RowCount = int(result.RowsAffected)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response SQLi block
		sendErrorResponse(w,
			fmt.Sprintf("Response blocked: potential SQL injection detected (pattern: %s)", outputOutcome.SQLiPattern),
			http.StatusForbidden, nil)
		return
	}

	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason)
		auditEntry.RowCount = int(result.RowsAffected)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response static block
		sendErrorResponse(w, fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason),
			http.StatusForbidden, nil)
		return
	}

	// Build policy info for response
	policyInfo := sharedpolicy.BuildPolicyInfo(inputOutcome.StaticResult, outputOutcome.StaticResult)
	if policyInfo != nil && inputOutcome.DynamicInfo != nil {
		policyInfo.DynamicPolicyInfo = inputOutcome.DynamicInfo
	} else if policyInfo == nil && inputOutcome.DynamicInfo != nil {
		policyInfo = &sharedpolicy.PolicyInfo{
			DynamicPolicyInfo: inputOutcome.DynamicInfo,
		}
	}

	// Return results
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"success":       true,
		"connector":     req.Connector,
		"rows_affected": result.RowsAffected,
		"duration_ms":   result.Duration.Milliseconds(),
		"message":       responseMessage,
	}
	if outputOutcome.WasRedacted() {
		response["redacted"] = true
		response["redacted_fields"] = outputOutcome.RedactedFieldNames()
	}
	if policyInfo != nil {
		response["policy_info"] = policyInfo
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding MCP execute response: %v", err)
	}

	// Log successful audit entry
	auditEntry.Success = true
	auditEntry.RowCount = int(result.RowsAffected)
	auditEntry.DurationMs = time.Since(startTime).Milliseconds()
	logMCPQueryAudit(auditEntry)
	// #2679: terminal allow (clean or redacted) → canonical row keyed by the same
	// decision_id. A response redaction is its OWN verdict ("redacted") carrying
	// redacted_fields, distinct from a clean allow.
	emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, outputOutcome.RedactedFieldNames(), outPolicyNames)

	log.Printf("[MCP] Command executed: connector=%s, action=%s, rows_affected=%d, duration=%v",
		logutil.Sanitize(req.Connector), logutil.Sanitize(req.Action), result.RowsAffected, result.Duration)
}

// --- Standalone policy-check endpoints (Issue #1258) ---

// MCPCheckInputRequest is the request body for POST /api/v1/mcp/check-input.
// External orchestrators submit the proposed statement before executing it themselves.
type MCPCheckInputRequest struct {
	ClientID      string `json:"client_id"`
	UserToken     string `json:"user_token"`
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id,omitempty"`
	UserRole      string `json:"user_role,omitempty"`
	ConnectorType string `json:"connector_type"`
	// Tool is the caller-sent tool identity (#2904), distinct from
	// ConnectorType/server. Passed through as evaluateInputPolicies'
	// toolIdentity param instead of duplicating ConnectorType into both.
	Tool       string                 `json:"tool,omitempty"`
	Statement  string                 `json:"statement"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
	Operation  string                 `json:"operation,omitempty"` // "query" or "execute"; defaults to "execute"
	// ContentType selects the request-redaction detector (ADR-056 / #2563
	// addendum). Empty defaults to "text/plain". A content_type with no
	// registered detector is rejected (415) so the caller fails closed rather
	// than forward content the engine cannot govern. Media (image/*) becomes a
	// registered detector, not a contract change.
	ContentType string `json:"content_type,omitempty"`
}

// MCPCheckInputResponse is the response body for POST /api/v1/mcp/check-input.
//
// Plugin Batch 1 (ADR-043/044): block responses carry a stable decision_id,
// risk_level + policy_matches, and override availability so the caller can
// (1) surface a useful reason to the end user and (2) call explainDecision
// or createOverride without another round-trip. Fields are omitempty so
// pre-batch callers see the old shape byte-for-byte.
type MCPCheckInputResponse struct {
	Allowed            bool                     `json:"allowed"`
	BlockReason        string                   `json:"block_reason,omitempty"`
	PoliciesEvaluated  int                      `json:"policies_evaluated"`
	PolicyInfo         *sharedpolicy.PolicyInfo `json:"policy_info,omitempty"`
	DecisionID         string                   `json:"decision_id,omitempty"`
	RiskLevel          string                   `json:"risk_level,omitempty"`
	PolicyMatches      []RicherPolicyMatch      `json:"policy_matches,omitempty"`
	OverrideAvailable  *bool                    `json:"override_available,omitempty"`
	OverrideExistingID string                   `json:"override_existing_id,omitempty"`

	// Request-phase redaction (ADR-056 / #2563). When an allowed statement
	// carries PII under a redact (not block) policy, the engine returns the
	// masked statement here so a PEP can forward redacted content WITHOUT
	// hand-rolling its own patterns. This is what makes a /decide redact_pii
	// obligation engine-fulfillable: the obligation names this endpoint, the
	// PEP POSTs the statement, and forwards RedactedStatement. omitempty keeps
	// the response byte-for-byte identical for existing callers (and for any
	// allowed statement with no PII), so the field is purely additive.
	Redacted          bool   `json:"redacted,omitempty"`
	RedactedStatement string `json:"redacted_statement,omitempty"`
	// RedactionEvaluated reports whether the redaction detector actually RAN
	// (regardless of whether it masked anything). A PEP fulfilling a redact_pii
	// obligation MUST fail closed when this is false — it means the redactor did
	// not run (no detection config enabled), so "redacted:false" would otherwise
	// be indistinguishable from "looked, found nothing" (#2563 B1). omitempty:
	// true is sent on every evaluated allow path; absent ⇒ not evaluated ⇒ the
	// PEP fails closed.
	RedactionEvaluated bool `json:"redaction_evaluated,omitempty"`
}

// RicherPolicyMatch is the plugin-facing shape of a matched policy. Kept
// local to the agent so we don't entangle shared/policy with platform/agent
// concerns — the plugin only needs policy_id, policy_name, risk_level, and
// allow_override to surface a useful block reason and decide whether to
// offer an override CTA.
//
// Version is the live static_policies.version at decision time (#1983 / α1).
// omitempty so dynamic-only matches (where version is unknown / 0) and pre-α1
// audit records keep byte-for-byte shape; ADR-043 §"Versioning" makes
// additive omitempty fields non-breaking.
type RicherPolicyMatch struct {
	PolicyID      string `json:"policy_id"`
	PolicyName    string `json:"policy_name,omitempty"`
	RiskLevel     string `json:"risk_level,omitempty"`
	AllowOverride bool   `json:"allow_override"`
	Version       int    `json:"policy_version,omitempty"`
}

// MCPCheckOutputRequest is the request body for POST /api/v1/mcp/check-output.
// External orchestrators submit the raw connector response for policy scanning.
type MCPCheckOutputRequest struct {
	ClientID      string `json:"client_id"`
	UserToken     string `json:"user_token"`
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id,omitempty"`
	ConnectorType string `json:"connector_type"`
	// Tool is the caller-sent tool identity (#2904/#2955), distinct from
	// ConnectorType/server. Passed through as evaluateOutputPolicies'
	// toolIdentity param instead of duplicating ConnectorType into both, so
	// response-plane capability scoping keys off server.tool rather than the
	// bare server (the langgraph de-concat SDKs already send it here). Omitted →
	// empty toolIdentity → full (fail-closed) evaluation; no fallback from
	// ConnectorType, mirroring the check-input plane.
	Tool         string                   `json:"tool,omitempty"`
	ResponseData []map[string]interface{} `json:"response_data,omitempty"` // query-style row results
	Message      string                   `json:"message,omitempty"`       // execute-style response message
	Metadata     map[string]interface{}   `json:"metadata,omitempty"`      // connector metadata (used by SQLi scanning)
	RowCount     int                      `json:"row_count,omitempty"`
}

// MCPCheckOutputResponse is the response body for POST /api/v1/mcp/check-output.
//
// DecisionID is minted on every governance decision (allow + deny + redact)
// per Plugin Batch 1 / ADR-042 / ADR-043, so callers can correlate the
// decision back to the audit log via /explain/{id} and create overrides
// without an extra round-trip. omitempty preserves byte-for-byte
// pre-batch shape when a caller doesn't surface it.
type MCPCheckOutputResponse struct {
	Allowed           bool                                `json:"allowed"`
	BlockReason       string                              `json:"block_reason,omitempty"`
	RedactedData      interface{}                         `json:"redacted_data,omitempty"`
	PoliciesEvaluated int                                 `json:"policies_evaluated"`
	ExfiltrationInfo  *sharedpolicy.ExfiltrationCheckInfo `json:"exfiltration_info,omitempty"`
	PolicyInfo        *sharedpolicy.PolicyInfo            `json:"policy_info,omitempty"`
	DecisionID        string                              `json:"decision_id,omitempty"`

	// RedactionEvaluated mirrors MCPCheckInputResponse.RedactionEvaluated for the
	// response phase (#2865). True when the response redaction pipeline ran; a
	// response-phase PEP MUST fail closed when it is false/absent (the redactor
	// did not run, so absence of redacted_data cannot be trusted as
	// "nothing to mask"). omitempty keeps the pre-#2865 byte shape and leaves a
	// strict PEP fail-closed when detection is disabled for the connector.
	RedactionEvaluated bool `json:"redaction_evaluated,omitempty"`
}

// mcpCheckInputHandler evaluates dynamic + request-phase static policies for a proposed
// MCP statement without executing any connector.
// POST /api/v1/mcp/check-input
func mcpCheckInputHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Bound the request body (#2803): the statement is parsed more than once
	// (decode here, plus the governance-metadata duplicate-key scan + re-serialize
	// for create_override), so cap the input the same way the MCP-server endpoint
	// does to avoid a large-body parse-amplification.
	r.Body = http.MaxBytesReader(w, r.Body, mcpMaxRequestBody)

	var req MCPCheckInputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Validate required fields
	if req.ConnectorType == "" {
		sendErrorResponse(w, "connector_type is required", http.StatusBadRequest, nil)
		return
	}
	if req.Statement == "" {
		sendErrorResponse(w, "statement is required", http.StatusBadRequest, nil)
		return
	}

	// Authenticate via unified authenticator
	hints := &AuthHints{ClientID: req.ClientID, UserToken: req.UserToken, TenantID: req.TenantID}
	auth, authErr := Authenticate(r, hints)
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, auth arm): an unauthenticated
		// check-input attempt previously vanished with no audit trail. Record a
		// canonical "blocked" row under the fixed `mcpUnauthenticatedTenant` sentinel
		// (NOT the caller-claimed req.TenantID — an unauthenticated caller must never
		// be able to inject a row into another tenant's decisions feed) with empty
		// org_id so it stays out of every real tenant's portal scope while still
		// recording the denied attempt for security audit. Best-effort.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			mcpUnauthenticatedTenant, "", strings.TrimSpace(req.ClientID), "",
			"", "service",
			"mcp_check_input", "mcp check-input: unauthenticated", "",
			mcpVerdictBlocked,
			[]string{"unauthenticated"},
			[]string{"authentication failed: " + authErr.Message},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}

	// Governance-plane metadata exemption (#2803): strip the create_override
	// justification from the statement before evaluation so a justification
	// explaining a `.env` block is not itself blocked by the policy it
	// overrides. The override TARGET scope stays in the statement and is still
	// evaluated. Applied AFTER Authenticate (so an unauthenticated caller can
	// neither trigger the code path nor forge a log line via a crafted
	// connector_type) but BEFORE every downstream use of req.Statement
	// (evaluation, redaction, statement hash). See governance_metadata.go.
	if sanitized, exempt := stripGovernanceMetadata(req.ConnectorType, req.Statement); len(exempt) > 0 {
		log.Printf("[MCP] check-input: exempted governance metadata fields %v for %s", exempt, stripLogCRLF(req.ConnectorType))
		req.Statement = sanitized
	}

	// Content-type-agnostic redaction (ADR-056 / #2563 addendum): reject a
	// content_type with no registered detector. Runs AFTER auth so the detector
	// registry isn't probeable by unauthenticated callers (#2563 L1). Empty/text
	// defaults to the built-in text detector, so existing callers are
	// unaffected; a caller asking us to govern (e.g.) an image with no media
	// detector registered fails closed here rather than forwarding ungoverned.
	if _, ok := requestRedactionDetectorFor(req.ContentType); !ok {
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS): this is a fail-closed governance
		// refusal (we will not forward ungoverned content for an unsupported
		// content_type), but it previously returned with no audit trail. Record a
		// canonical "blocked" row against the authenticated tenant so the refusal is
		// portal-visible. Best-effort; the 415 response is already authoritative.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			auth.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_input", "mcp check-input: unsupported content_type", "",
			mcpVerdictBlocked,
			[]string{"content_type_unsupported"},
			[]string{"no redaction detector registered for content_type: " + req.ContentType},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		sendErrorResponse(w, "no redaction detector registered for content_type: "+req.ContentType, http.StatusUnsupportedMediaType, nil)
		return
	}

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via r.Context()
	// agree with the four-key shape apiAuthMiddleware writes
	// (auth.go:658-661). This handler is NOT behind apiAuthMiddleware.
	// Sibling of #2319.
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))

	// #2896: client-asserted AI-tool session id (X-Session-Id) → request
	// context → audit_logs.session_id, ONLY under the identity trust gate
	// (attributedSessionID resolves to "" otherwise → no-op stamp). Same
	// mechanism requireMCPAuth uses on the MCP-server plane (#2753).
	if sid := attributedSessionID(r); sid != "" {
		r = r.WithContext(withClientSessionID(r.Context(), sid))
	}

	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(r.Context(), auth.TenantID)

	// V1 Plugin Pro daily-cap enforcement (umbrella #1958 + #1976):
	// /api/v1/mcp/check-input is registered directly on globalRouter
	// without proxyAuthMiddleware/apiAuthMiddleware so we run the cap
	// check here. Plugins' pre-tool hooks call this on every governed
	// tool invocation; without enforcement here a Free tenant gets
	// unlimited governance evaluation.
	if enforceCommunitySaasDailyCap(w, auth) {
		return
	}

	// Resolve user and extract identity fields
	user, userErr := ResolveUser(auth, req.UserToken)
	if userErr != nil {
		if auth.Kind == AuthKindEnterprise && req.UserToken == "" && !ResolveRequireUserToken(r.Context(), auth.OrgID) {
			user = &User{
				ID:       0,
				Email:    auth.Client.ID + "@axonflow.local",
				Name:     auth.Client.Name,
				TenantID: auth.Client.TenantID,
				Role:     "service",
			}
		} else {
			// #3472: a PRESENTED token that fails validation (malformed, expired,
			// wrong alg, bad signature, jti-revoked) is a rejected access attempt,
			// not a compatibility case. Audit it, then 401. Parity with
			// decision_handler.go's /decide arm.
			//
			// #3476: with the org's posture requiring a token, a token-ABSENT
			// caller now also reaches this branch. The req.UserToken != "" guard
			// below keeps the two causes distinct: a presented-and-invalid token
			// still audits as user_token_rejected (#3472, unchanged); an
			// absent-and-required token audits under its own marker,
			// user_token_required, so the two causes never collapse.
			if req.UserToken != "" {
				writeMCPDecisionAudit(r.Context(), usageDB,
					uuid.New().String(), "",
					auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_check_input", "mcp check-input: user token rejected", "",
					mcpVerdictBlocked,
					[]string{"user_token_rejected"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,                                  // #3365: guard ids resolve via the builtin table
					time.Since(startTime).Milliseconds(), // #3472: agent-local check-input evaluation, no downstream hop
					req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			} else {
				writeMCPDecisionAudit(r.Context(), usageDB,
					uuid.New().String(), "",
					auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_check_input", "mcp check-input: user token required", "",
					mcpVerdictBlocked,
					[]string{"user_token_required"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					time.Since(startTime).Milliseconds(),
					req.ConnectorType, req.Tool)
			}
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}
	if user.TenantID != auth.Client.TenantID {
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, tenant arm): a cross-tenant identity
		// mismatch is a fail-closed authz refusal. Record it against the credential's
		// authenticated tenant (auth.Client.TenantID — the trusted boundary, not the
		// user-asserted one) so the refused attempt is portal-visible. Best-effort.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_input", "mcp check-input: tenant mismatch", "",
			mcpVerdictBlocked,
			[]string{"tenant_mismatch"},
			[]string{"resolved user tenant does not match authenticated client tenant"},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	tenantID := auth.TenantID
	userID := fmt.Sprintf("%d", user.ID)
	userRole := user.Role
	orgID := auth.OrgID
	// For internal service requests, use body-supplied user fields if present
	if auth.Kind == AuthKindInternalService {
		if req.UserID != "" {
			userID = req.UserID
		}
		if req.UserRole != "" {
			userRole = req.UserRole
		}
	}

	// Per-caller identity for audit attribution AND Plugin Batch 1 (ADR-044)
	// override scoping. #2896: the client-asserted X-User-Email is honored
	// ONLY under the AXONFLOW_TRUST_IDENTITY_HEADERS opt-in — it was
	// previously read unconditionally here, which let any governed caller (a)
	// forge another principal's audit identity and (b) hijack another user's
	// active session override via applyOverrideToCheckInputBlock below (a
	// deny→allow flip keyed on this variable). With the gate off (default)
	// both attribution and override scope fall back to the validated
	// identity. Resolved before the missing-tenant early deny so that row
	// attributes consistently with the decide plane's early denies.
	userEmail := attributedUserEmail(r, user.Email, callerIsVerifiedHuman(auth, userErr, req.UserToken))

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, tenant arm): authenticated but no
		// resolvable tenant scope — a fail-closed refusal. org_id is still known, so
		// record the deny (tenant_id falls back to the writer's "unknown" sentinel).
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			"", orgID, auth.ClientID, userEmail,
			userID, userRole,
			"mcp_check_input", "mcp check-input: missing tenant scope", "",
			mcpVerdictBlocked,
			[]string{"tenant_id_missing"},
			[]string{"tenant_id is required"},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		sendErrorResponse(w, "tenant_id is required", http.StatusBadRequest, nil)
		return
	}

	// Wrap the remainder of the handler in the idempotency dedup helper.
	// Pass-through when no Idempotency-Key header is set or no store is
	// wired (tests, community boot). The closure captures parsed body +
	// resolved identity so we don't reshape signatures across the file.
	//
	// Idempotency scope key. For internal-service auth (HMAC-signed
	// orchestrator-→-agent callbacks) auth.OrgID is whatever the proxy
	// header carries — sometimes empty. Mirror the orchestrator audit-
	// tool-call shape: fall back to tenantID so dedup actually fires
	// instead of "lookup error: orgID empty" per retry.
	idempOrgID := orgID
	if idempOrgID == "" {
		idempOrgID = tenantID
	}
	// #3447 SECURITY: the idempotency cache key is (org, tenant, Idempotency-Key,
	// endpoint) and carries NO principal, while Wrap replays a hit WITHOUT
	// invoking the handler — so the segment gate below never runs on a replay.
	//
	// That was authorization-neutral before this issue: Segments was passed
	// unconditionally nil here, so every caller in the org received the same
	// verdict and a replay could only return a verdict the replaying caller
	// would have got anyway. Making the verdict a function of segment
	// membership is what turns a shared cache row into a bypass: a member of a
	// targeted segment replaying a NON-member's cached allow would be served an
	// allow on a statement their segment's policy blocks, on a key the caller
	// chooses. The same applies in reverse to the segment_resolution_failed 403
	// (4xx is cached), which would replay one caller's transient resolution
	// failure to everyone sharing that key for the TTL.
	//
	// So the principal is folded into the endpoint discriminator: a different
	// enforcement subject is a different cache row, and a genuine retry by the
	// same caller still dedups. It is the caller's VALIDATED identity, the same
	// value the gate resolves segments from — keying on anything the caller can
	// assert would reintroduce the bypass through the other door. Hashed, so the
	// idempotency_keys.endpoint column carries no identity material.
	idempotency.Wrap(w, r, mcpIdempStore, idempOrgID, tenantID, mcpCheckInputIdempEndpoint(user.Email), func(w http.ResponseWriter, r *http.Request) {
		// Generate a stable decision_id up front so it can be attached to both
		// the audit entry and the response body. The explain endpoint
		// (GET /api/v1/decisions/:id/explain) resolves by this id.
		decisionID := uuid.New().String()

		auditEntry := MCPQueryAuditEntry{
			AuditID:        uuid.New().String(),
			ConnectorName:  req.ConnectorType,
			Operation:      "check-input",
			TenantID:       tenantID,
			OrgID:          orgID,
			UserID:         userID,
			StatementHash:  computeStatementHash(req.Statement),
			ParametersHash: computeParametersHash(req.Parameters),
			ParameterCount: len(req.Parameters),
			DecisionID:     decisionID,
		}

		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		operation := req.Operation
		if operation == "" {
			operation = "execute"
		}

		// emitInputDecision converges this check-input verdict onto the canonical
		// audit_logs decision feed the customer portal reads (GET /api/v1/decisions
		// filters audit_logs WHERE policy_details->>'decision_id' IS NOT NULL), keyed
		// by the SAME decisionID as the mcp_query_audits satellite — the request-plane
		// mirror of #2586 (#2627). Reuses the writer /decide uses (recordDecideDecision
		// → writeDecisionAuditLog); plane=mcp. Called from the dynamic-block and the
		// terminal allow/redact branches — the ONLY two that previously wrote only the
		// satellite. The static-block deny + override-flip allow branches write their
		// own richer canonical rows (writeExplainableAuditLog / writeOverrideUsedEvent)
		// and must NOT be routed here, or they'd double-write a second audit_logs row
		// under the same decision_id. audit_logs is deliberately not FORCE-RLS (mig
		// 101), so this plain insert succeeds under AXONFLOW_DB_USE_APP_ROLE on AND off
		// — identical to the production /decide path. query is a non-PII descriptor
		// (connector type) — the raw statement MUST NOT land in audit_logs.query.
		emitInputDecision := func(verdict string, policyIDs, reasons []string, policyNames map[string]string) {
			recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageTool,
				verdict, policyIDs, time.Since(startTime).Milliseconds(), reasons,
				"", nil, false, &decisionAuditInput{
					clientID:  auth.Client.ID,
					requestID: auditEntry.AuditID,
					userEmail: userEmail,
					userRole:  userRole,
					userID:    user.ID,
					query:     fmt.Sprintf("mcp check-input: %s", req.ConnectorType),
					plane:     PlaneMCP, // #2627: MCP request plane → audit_logs.plane=mcp
					// #2598: correlate with the response-plane check-output (and any
					// /decide stage) of the SAME logical tool call when the gateway
					// propagates a W3C traceparent. Absent header → "" → singleton.
					correlationID: traceIDFromHeader(r.Header.Get("traceparent")),
					toolServer:    req.ConnectorType, // #2904
					toolName:      req.Tool,          // #2904
					policyNames:   policyNames,       // #3365
				})
		}

		// Read-only enforcement posture (#2720, epic #2716). This is the
		// SDK / Decision-Mode PEP request gate: a PEP forwards the call only if
		// check-input returns allowed. Under MCP_READ_ONLY a write-path call must
		// be refused here, before policy evaluation and the override flow, so the
		// PEP never forwards it. Non-overridable; canonical "blocked" audit row.
		// Mirrors the mcp_server_handler check_policy gate; reuses classifyMCPCall.
		if readOnlyPostureEnabled() && classifyMCPCall(req.ConnectorType, req.Tool, operation) == mcpAccessWrite {
			reason := fmt.Sprintf("read-only posture active: write-path tool call %q is blocked; only read-path operations are permitted", req.ConnectorType)
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = reason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", fmt.Sprintf("mcp check-input: %s", req.ConnectorType), auditEntry.StatementHash,
				mcpVerdictBlocked,
				[]string{readOnlyPosturePolicyID},
				[]string{reason},
				nil,
				traceIDFromHeader(r.Header.Get("traceparent")),
				nil,                                  // #3365: guard ids resolve via the builtin table
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: reason,
				DecisionID:  decisionID,
			})
			return
		}

		// #3447 (ADR-060 Slice 3): one fail-closed segment resolution for this
		// request. Keyed on user.Email -- the VALIDATED token claim -- and
		// deliberately NOT on userEmail above, which folds in the trust-gated
		// X-User-Email header: keying resolution on a caller-supplied header
		// would let the same human shed their segments by naming a non-member
		// colleague. See human_actor_segment_gate.go.
		// user.OrgID, not the credential's auth.OrgID: the segment set is a
		// property of the USER's org, and this is the key every already-merged
		// human-actor plane resolves on (/api/v1/process run.go:2184, gateway
		// pre-check gateway_handlers.go:696). Keeping one key across the planes
		// is what stops the same human resolving to different sets on different
		// routes. (The MCP-server plane uses auth.OrgID only because it has no
		// resolved User at all there -- identity arrives as a ValidatedIdentity.)
		segmentIDs, segOK := resolveHumanActorSegmentsForPolicy(ctx, user.OrgID, auth.OrgID, user.Email,
			callerIsVerifiedHuman(auth, userErr, req.UserToken))
		if !segOK {
			// Own channel (segment_resolution_failed + 403), never
			// outcome.EvalUnavailable / 503 "Dynamic policy evaluation
			// unavailable": a policy-side deny is not an availability failure.
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = segmentResolutionFailedReason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, user.Email,
				userID, "",
				"mcp_check_input", fmt.Sprintf("mcp check-input: %s", req.ConnectorType), auditEntry.StatementHash,
				mcpVerdictBlocked,
				[]string{mcpSegmentResolutionFailedPolicyID},
				[]string{segmentResolutionFailedReason},
				nil,
				traceIDFromHeader(r.Header.Get("traceparent")),
				nil,                                  // #3365: guard id resolves via the builtin table
				time.Since(startTime).Milliseconds(), // agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: segmentResolutionFailedReason,
				DecisionID:  decisionID,
			})
			return
		}

		// v9 Phase 8 #2384 PR-C1: orgID plumbed through.
		// #2581: per-org posture. orgID is the auth-derived org for this request; an
		// org with no override row resolves to the deployment-global config.
		mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, orgID)
		// ADR-061 / #3329: decision metadata for the fincrime seam ("mcp"
		// plane); the audit writers merge any fincrime attribution off this ctx.
		ctx = fincrime.WithDecisionMeta(ctx, "mcp", decisionID)
		outcome := evaluateInputPolicies(ctx,
			tenantID, orgID, userID, userRole,
			req.ConnectorType, req.Tool /* toolIdentity: advisory plane, caller-sent tool identity (#2801, #2904) */, operation, req.Statement, req.Parameters,
			mcpDetectionCfg, true, /* runDynamicPolicy */
			segmentIDs /* #3447: fail-closed-resolved above; nil means "org-only", never "resolution failed" */)

		if outcome.EvalUnavailable {
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			// #2641 (MCPIN-PREPOLICY-EARLYRETURNS / fail-closed): the dynamic evaluator
			// was unreachable, so the request is refused (503). This previously wrote
			// ONLY the mcp_query_audits satellite. Record a canonical "error" row
			// (governance could not be rendered → fail-closed) so the unevaluated
			// attempt is portal-visible, keyed by the same decision_id.
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", fmt.Sprintf("mcp check-input: %s", req.ConnectorType), "",
				mcpVerdictError,
				[]string{"dynamic_policy_unavailable"},
				[]string{"dynamic policy evaluation unavailable"},
				nil,
				traceIDFromHeader(r.Header.Get("traceparent")),
				nil,                                  // #3365: guard ids resolve via the builtin table
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
			return
		}

		if outcome.DynamicBlocked {
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = outcome.DynamicBlockReason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			// #2627: a dynamic-policy block previously wrote ONLY the
			// mcp_query_audits satellite, so the portal feed showed it as
			// "Logged", not "Blocked". Emit the canonical audit_logs deny row.
			v, pids, reasons, pnames := mcpInputDecisionVerdict(outcome, false)
			emitInputDecision(v, pids, reasons, pnames)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:     false,
				BlockReason: outcome.DynamicBlockReason,
				DecisionID:  decisionID,
			})
			return
		}

		policiesEvaluated := 0
		if outcome.StaticResult != nil {
			auditEntry.RequestPoliciesEvaluated = outcome.StaticResult.PoliciesEvaluated
			auditEntry.RequestMatchedPolicies = extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
			policiesEvaluated = outcome.StaticResult.PoliciesEvaluated
			if outcome.StaticResult.Blocked {
				auditEntry.RequestBlocked = true
				auditEntry.RequestBlockReason = outcome.StaticResult.BlockReason
				auditEntry.DurationMs = time.Since(startTime).Milliseconds()

				// Plugin Batch 1: enrich the block response with decision_id,
				// risk_level, policy_matches, override_available.
				matches, topRisk, overrideAvail, overrideExistingID :=
					buildRicherCheckInputBlock(ctx, usageDB, tenantID, userEmail,
						outcome.StaticResult.MatchedPolicies)

				// #1983 / α1: stamp { policy_id -> version } on the audit entry
				// before logMCPQueryAudit so the version surfaces in the
				// MCPQueryAuditEntry → audit_queue Details map. Built from the
				// richer matches (one DB lookup per policy already happened in
				// buildRicherCheckInputBlock). Empty when all matches are
				// dynamic-only / unknown.
				auditEntry.PolicyVersions = collectPolicyVersions(matches)
				logMCPQueryAudit(auditEntry)

				// ADR-044: if the caller has an active session override on any
				// of the matched policies, flip deny -> allow and emit an
				// override_used audit event. Must run before the block audit
				// write so we don't record a denied decision that didn't
				// actually fire.
				if usedOverrideID, overriddenMatch, applied := applyOverrideToCheckInputBlock(
					ctx, usageDB, tenantID, userEmail, matches,
				); applied {
					// #1983 / α1: stamp policy_id + policy_version of the
					// match the override unblocked into policy_details so
					// explain can answer "which version of which policy was
					// overridden."
					var overriddenPolicyID string
					var overriddenPolicyName string
					var overriddenPolicyVersion int
					if overriddenMatch != nil {
						overriddenPolicyID = overriddenMatch.PolicyID
						overriddenPolicyName = overriddenMatch.PolicyName
						overriddenPolicyVersion = overriddenMatch.Version
					}
					writeOverrideUsedEvent(ctx, usageDB, usedOverrideID,
						decisionID, tenantID, orgID, auth.Client.ID, userEmail,
						overriddenPolicyID, overriddenPolicyName, overriddenPolicyVersion,
						traceIDFromHeader(r.Header.Get("traceparent"))) // #2598 correlation
					log.Printf("[MCP] Override %s applied — flipping deny to allow for decision %s",
						usedOverrideID, decisionID)
					// Fall through to the non-block success path below by
					// clearing the StaticResult.Blocked condition. We can't
					// mutate outcome in place cleanly; instead encode the
					// allowed response directly here and return.
					auditEntry.RequestBlocked = false
					auditEntry.RequestBlockReason = ""
					auditEntry.PolicyVersions = collectPolicyVersions(matches)
					auditEntry.Success = true
					auditEntry.DurationMs = time.Since(startTime).Milliseconds()
					logMCPQueryAudit(auditEntry)
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
						Allowed:            true,
						PoliciesEvaluated:  policiesEvaluated,
						DecisionID:         decisionID,
						OverrideExistingID: usedOverrideID,
					})
					return
				}

				// Dual-write to audit_logs so explainDecision(id) can resolve
				// this decision. mcp_query_audits is the legacy per-connector
				// audit table; audit_logs is what the explain/override/audit-
				// search endpoints read.
				// #2641 (R3 Finding 12 / PII safety): the canonical decision row's
				// `query` column carries a NON-PII descriptor — never the raw statement
				// (which may bear NIK/NPWP/SSN). The /explain + /decisions endpoints read
				// policy_details (decision_id/matches/reason), NOT this column, so the
				// descriptor loses nothing; the real statement stays correlatable via the
				// preserved StatementHash. Consistent with the descriptor every other MCP
				// audit write in this PR uses.
				writeExplainableAuditLog(ctx, usageDB,
					decisionID, auditEntry.AuditID,
					tenantID, orgID, auth.Client.ID, userEmail,
					userID, userRole,
					"mcp_check_input", fmt.Sprintf("mcp check-input: %s", req.ConnectorType), auditEntry.StatementHash,
					outcome.StaticResult.BlockReason, topRisk, matches,
					traceIDFromHeader(r.Header.Get("traceparent")), // #2598 correlation
					time.Since(startTime).Milliseconds(),           // #3424: agent-local check-input evaluation, no downstream hop
					req.ConnectorType, req.Tool)                    // #2904: tool_server, tool_name

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
					Allowed:            false,
					BlockReason:        outcome.StaticResult.BlockReason,
					PoliciesEvaluated:  policiesEvaluated,
					DecisionID:         decisionID,
					RiskLevel:          topRisk,
					PolicyMatches:      matches,
					OverrideAvailable:  overrideAvail,
					OverrideExistingID: overrideExistingID,
				})
				return
			}
		}

		policyInfo := sharedpolicy.BuildPolicyInfo(outcome.StaticResult, nil)
		if policyInfo != nil && outcome.DynamicInfo != nil {
			policyInfo.DynamicPolicyInfo = outcome.DynamicInfo
		} else if policyInfo == nil && outcome.DynamicInfo != nil {
			policyInfo = &sharedpolicy.PolicyInfo{DynamicPolicyInfo: outcome.DynamicInfo}
		}

		// Request-phase redaction (ADR-056 / #2563): when the allowed statement
		// carries PII under a redact (not block) policy, hand the PEP the
		// engine-masked statement so it can forward redacted content. This is the
		// engine-backed fulfillment of a /decide redact_pii obligation — the PEP
		// never runs its own patterns. Dispatched through the content-type detector
		// seam (text/plain today; media routes to the orchestrator media subsystem).
		// No-PII / engine-disabled returns the statement unchanged (didRedact=false),
		// so the omitempty fields stay absent and existing callers see the old shape.
		detector, _ := requestRedactionDetectorFor(req.ContentType) // presence verified at handler entry
		redaction := detector.Redact(ctx, RedactionInput{
			TenantID:      tenantID,
			UserID:        userID,
			ConnectorName: req.ConnectorType,
			ContentType:   req.ContentType,
			Text:          req.Statement,
		})
		redactedStmt, didRedact := redaction.Text, redaction.Redacted
		if didRedact {
			// #2641 sibling finding #3 (LOW): the satellite previously recorded only
			// the ResponseRedacted bool, leaving ResponseRedactionsCount/Fields zero —
			// asymmetric with the response plane (applyResponseRedactionAudit). The
			// request-redaction detector contract (RedactionOutput) exposes no
			// per-field names, and the masked unit on this surface IS the single
			// statement, so record count=1 + the coarse "statement" descriptor. Honest
			// at the grain available; never fabricates field names we don't have.
			auditEntry.ResponseRedacted = true
			auditEntry.ResponseRedactionsCount = 1
			auditEntry.ResponseRedactedFields = []string{"statement"}
		}

		auditEntry.Success = true
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2627/#2641: the terminal allow (clean or redacted) previously wrote ONLY
		// the mcp_query_audits satellite, so an allowed governance decision never
		// reached the portal feed. Emit the canonical audit_logs row keyed by the same
		// decision_id. A redaction is its OWN verdict ("redacted") — recording it as
		// "allowed" hid the mask from the portal (#2641 MCPIN). query is a non-PII
		// descriptor (connector type) — the raw statement MUST NOT land in
		// audit_logs.query.
		v, pids, reasons, pnames := mcpInputDecisionVerdict(outcome, didRedact)
		if v == mcpVerdictRedacted {
			// A redaction MUST carry redacted_fields on the canonical row (AUDIT-C
			// DoD). recordDecideDecision → writeDecisionAuditLog omits that column, so
			// route redactions through the MCP canonical writer; clean allows keep the
			// /decide writer (preserves the OTel decision span + obligations slot).
			inputDescriptor := fmt.Sprintf("mcp check-input: %s", req.ConnectorType)
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", inputDescriptor, computeStatementHash(inputDescriptor),
				mcpVerdictRedacted, pids, reasons, auditEntry.ResponseRedactedFields,
				traceIDFromHeader(r.Header.Get("traceparent")),
				pnames,                               // #3365
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		} else {
			emitInputDecision(v, pids, reasons, pnames)
		}

		resp := MCPCheckInputResponse{
			Allowed:           true,
			PoliciesEvaluated: policiesEvaluated,
			PolicyInfo:        policyInfo,
			// Plugin Batch 1: every governance decision surfaces decision_id —
			// allow paths included, so callers can fetch the audit record via
			// /explain/{id} or compare requests across allow/deny without an
			// extra round-trip. The deny paths above already emit it.
			DecisionID: decisionID,
			// RedactionEvaluated lets a PEP fulfilling a redact_pii obligation fail
			// closed when the redactor did not run (#2563 B1) — true on every
			// evaluated allow path, absent only when no detection config is enabled.
			RedactionEvaluated: redaction.Evaluated,
		}
		if didRedact {
			resp.Redacted = true
			resp.RedactedStatement = redactedStmt
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}) // end idempotency.Wrap closure
}

// mcpCheckOutputHandler evaluates response-phase policies (SQLi scan, PII redaction,
// exfiltration limits) on pre-executed connector output without calling any connector.
// POST /api/v1/mcp/check-output
func mcpCheckOutputHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var req MCPCheckOutputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Validate required fields
	if req.ConnectorType == "" {
		sendErrorResponse(w, "connector_type is required", http.StatusBadRequest, nil)
		return
	}
	if len(req.ResponseData) == 0 && req.Message == "" {
		sendErrorResponse(w, "response_data or message is required", http.StatusBadRequest, nil)
		return
	}

	// Authenticate via unified authenticator
	hints := &AuthHints{ClientID: req.ClientID, UserToken: req.UserToken, TenantID: req.TenantID}
	auth, authErr := Authenticate(r, hints)
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, response plane): mirror the check-input
		// auth arm — record an unauthenticated check-output deny under the
		// `mcpUnauthenticatedTenant` sentinel (never the caller-claimed tenant) so the
		// attempt is auditable without spoofing a real tenant's feed.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			mcpUnauthenticatedTenant, "", strings.TrimSpace(req.ClientID), "",
			"", "service",
			"mcp_check_output", "mcp check-output: unauthenticated", "",
			mcpVerdictBlocked,
			[]string{"unauthenticated"},
			[]string{"authentication failed: " + authErr.Message},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-output evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via r.Context()
	// agree with the four-key shape apiAuthMiddleware writes
	// (auth.go:658-661). This handler is NOT behind apiAuthMiddleware.
	// Sibling of #2319.
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))

	// #2896: client-asserted AI-tool session id (X-Session-Id) → request
	// context → audit_logs.session_id, ONLY under the identity trust gate
	// (attributedSessionID resolves to "" otherwise → no-op stamp). The
	// desktop proxy sends it on every check-output call; it was previously
	// dropped on this plane. Same mechanism requireMCPAuth uses (#2753).
	if sid := attributedSessionID(r); sid != "" {
		r = r.WithContext(withClientSessionID(r.Context(), sid))
	}

	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(r.Context(), auth.TenantID)

	// #2860: Enterprise per-client version-distribution telemetry for the MCP
	// response plane — the Desktop proxy (mcp-proxy/<v>) and the claude-code
	// plugin both stamp X-Axonflow-Client on this call. Reached only after
	// Authenticate() above succeeds (this route is POST-only and not behind
	// apiAuthMiddleware), so unauthenticated junk can't mint label series.
	// Telemetry-only + fail-open by contract (community no-op), so a
	// missing/garbage header never affects the response verdict. Unlike the
	// decide plane, this records post-decode+auth — the two planes' series are
	// "attempts" (decide) vs "authenticated requests" (mcp) and don't reconcile
	// 1:1 across Grafana.
	recordClientVersionTelemetry(PlaneMCP, r.Header.Get("X-Axonflow-Client"))

	// V1 Plugin Pro daily-cap enforcement (umbrella #1958 + #1976):
	// /api/v1/mcp/check-output is registered directly on globalRouter
	// without daily-cap middleware. Plugins call this on every governed
	// post-tool result; without enforcement here a Free tenant gets
	// unlimited output policy evaluation.
	if enforceCommunitySaasDailyCap(w, auth) {
		return
	}

	user, userErr := ResolveUser(auth, req.UserToken)
	if userErr != nil {
		if auth.Kind == AuthKindEnterprise && req.UserToken == "" && !ResolveRequireUserToken(r.Context(), auth.OrgID) {
			user = &User{
				ID:       0,
				Email:    auth.Client.ID + "@axonflow.local",
				Name:     auth.Client.Name,
				TenantID: auth.Client.TenantID,
				Role:     "service",
			}
		} else {
			// #3472: a PRESENTED token that fails validation (malformed, expired,
			// wrong alg, bad signature, jti-revoked) is a rejected access attempt,
			// not a compatibility case. Audit it, then 401. Parity with
			// decision_handler.go's /decide arm.
			//
			// #3476: with the org's posture requiring a token, a token-ABSENT
			// caller now also reaches this branch. The req.UserToken != "" guard
			// below keeps the two causes distinct: a presented-and-invalid token
			// still audits as user_token_rejected (#3472, unchanged); an
			// absent-and-required token audits under its own marker,
			// user_token_required, so the two causes never collapse.
			if req.UserToken != "" {
				writeMCPDecisionAudit(r.Context(), usageDB,
					uuid.New().String(), "",
					auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_check_output", "mcp check-output: user token rejected", "",
					mcpVerdictBlocked,
					[]string{"user_token_rejected"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,                                  // #3365: guard ids resolve via the builtin table
					time.Since(startTime).Milliseconds(), // #3472: agent-local check-output evaluation, no downstream hop
					req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
			} else {
				writeMCPDecisionAudit(r.Context(), usageDB,
					uuid.New().String(), "",
					auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
					"", "",
					"mcp_check_output", "mcp check-output: user token required", "",
					mcpVerdictBlocked,
					[]string{"user_token_required"},
					[]string{userErr.Message},
					nil,
					traceIDFromHeader(r.Header.Get("traceparent")),
					nil,
					time.Since(startTime).Milliseconds(),
					req.ConnectorType, req.Tool)
			}
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}
	if user.TenantID != auth.Client.TenantID {
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, response plane): mirror check-input.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			auth.Client.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_output", "mcp check-output: tenant mismatch", "",
			mcpVerdictBlocked,
			[]string{"tenant_mismatch"},
			[]string{"resolved user tenant does not match authenticated client tenant"},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-output evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}

	tenantID := auth.TenantID
	userID := fmt.Sprintf("%d", user.ID)
	orgID := auth.OrgID
	if auth.Kind == AuthKindInternalService {
		if req.UserID != "" {
			userID = req.UserID
		}
	}

	// #2896: audit-attribution identity for the response plane. check-output
	// previously ignored X-User-Email entirely, so the desktop proxy's
	// per-leader identity attributed to the fleet service user. Honored ONLY
	// under AXONFLOW_TRUST_IDENTITY_HEADERS; falls back to the validated
	// user.Email. Attribution only — the policy evaluation below never sees it.
	userEmail := attributedUserEmail(r, user.Email, callerIsVerifiedHuman(auth, userErr, req.UserToken))

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
		// #2641 (MCPIN-PREPOLICY-EARLYRETURNS, response plane): mirror check-input.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			"", orgID, auth.ClientID, userEmail,
			userID, user.Role,
			"mcp_check_output", "mcp check-output: missing tenant scope", "",
			mcpVerdictBlocked,
			[]string{"tenant_id_missing"},
			[]string{"tenant_id is required"},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard ids resolve via the builtin table
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-output evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
		sendErrorResponse(w, "tenant_id is required", http.StatusBadRequest, nil)
		return
	}

	// Mint a decision_id up front so every response branch (deny + allow +
	// redact) can surface it. Same pattern as mcpCheckInputHandler — Plugin
	// Batch 1 / ADR-042 / ADR-043 require decision_id on every governance
	// decision. The audit_logs row is the lookup target for /explain/{id}.
	decisionID := uuid.New().String()

	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.ConnectorType,
		Operation:     "check-output",
		TenantID:      tenantID,
		OrgID:         orgID,
		UserID:        userID,
		DecisionID:    decisionID,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Enable exfiltration checks for query-style responses (rows) but not for
	// execute-style responses (message only) — consistent with mcpExecuteHandler.
	checkExfiltration := len(req.ResponseData) > 0

	// #3447 (ADR-060 Slice 3): one fail-closed segment resolution for this
	// request. Keyed on user.Email -- the VALIDATED token claim -- never on
	// userEmail above, which folds in the trust-gated X-User-Email header (a
	// caller-supplied value must never decide which segment-scoped policies
	// apply). This handler has only the response phase, so the single
	// resolution has a single consumer. See human_actor_segment_gate.go.
	// user.OrgID, not the credential's auth.OrgID -- see the sibling comment in
	// mcpCheckInputHandler: one resolution key across every merged human-actor
	// plane, so the same human cannot resolve to different sets per route.
	segmentIDs, segOK := resolveHumanActorSegmentsForPolicy(ctx, user.OrgID, auth.OrgID, user.Email,
		callerIsVerifiedHuman(auth, userErr, req.UserToken))
	if !segOK {
		// Own channel (segment_resolution_failed + 403). The response plane
		// has no EvalUnavailable/503 channel at all, and must not grow one
		// here: a resolver-error deny is a policy decision, not an outage.
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = segmentResolutionFailedReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, auditEntry.AuditID,
			tenantID, orgID, auth.ClientID, user.Email,
			userID, "",
			"mcp_check_output", fmt.Sprintf("mcp check-output: %s", req.ConnectorType), "",
			mcpVerdictBlocked,
			[]string{mcpSegmentResolutionFailedPolicyID},
			[]string{segmentResolutionFailedReason},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,                                  // #3365: guard id resolves via the builtin table
			time.Since(startTime).Milliseconds(), // agent-local check-output evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:     false,
			BlockReason: segmentResolutionFailedReason,
			DecisionID:  decisionID,
		})
		return
	}

	outcome := evaluateOutputPolicies(ctx,
		tenantID, orgID, userID, req.ConnectorType,
		// toolIdentity: advisory plane, caller-sent tool identity (#2801, #2904,
		// #2955) - distinct from ConnectorType/server; empty means full
		// (fail-closed) evaluation, no fallback
		req.Tool,
		req.ResponseData, req.Message, req.Metadata, req.RowCount, checkExfiltration,
		// isGateway: check-output is a PEP/gateway caller
		true,
		// #3447: the caller's fail-closed-resolved governance-segment set.
		segmentIDs)

	auditEntry.ExfilRowsReturned = req.RowCount
	applyResponseRedactionAudit(&auditEntry, outcome)

	// #1983 / α1: stamp policy_version for any matched static policies
	// (block + redact branches). Single batch lookup per request — output
	// path doesn't run buildRicherCheckInputBlock so no DB calls have
	// happened yet for these IDs. Empty result map is safe (no static
	// match → no version stamp; mirrors check-input semantics).
	if outcome.StaticResult != nil && len(outcome.StaticResult.MatchedPolicies) > 0 {
		ids := extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
		auditEntry.PolicyVersions = lookupPolicyVersionsByID(ctx, usageDB, ids)
	}

	// #2563 (AUDIT-A1): converge the MCP response plane onto the canonical
	// audit_logs decision feed the customer portal reads (GET /api/v1/decisions
	// filters audit_logs WHERE policy_details->>'decision_id' IS NOT NULL). The
	// mcp_query_audits satellite written by logMCPQueryAudit in each branch below
	// is never read there, so a NIK/NPWP response block otherwise surfaces as
	// "Logged", not "Blocked" — undermining the audit story. Reuse the SAME
	// writer /decide uses (recordDecideDecision → writeDecisionAuditLog), keyed by
	// the SAME decisionID as the satellite, so the decision lands in the portal
	// feed with no portal-side change. audit_logs is deliberately not FORCE-RLS
	// (migration 101 deferred it for the cross-org cleanup worker), so this plain
	// insert succeeds under AXONFLOW_DB_USE_APP_ROLE on AND off — identical to the
	// production /decide path. Emitted once here, before the branch dispatch:
	// mcpOutputDecisionVerdict mirrors the branch order so the recorded verdict
	// matches the branch that fires. query is a non-PII descriptor (connector +
	// operation) — raw response_data MUST NOT land in audit_logs.query.
	outVerdict, outPolicyIDs, outReasons, outPolicyNames := mcpOutputDecisionVerdict(outcome)
	if outVerdict == mcpVerdictRedacted {
		// #2641 (AUDIT-C): a response redaction (e.g. an OJK NIK/NPWP mask) is its
		// OWN verdict and MUST carry redacted_fields on the canonical row. The
		// recordDecideDecision → writeDecisionAuditLog writer omits that column, so
		// route the redacted verdict through the MCP canonical writer (which carries
		// redacted_fields), keyed by the same decision_id. Block/allow keep the
		// /decide writer below (OTel decision span + obligations slot). query is a
		// non-PII descriptor — raw response_data MUST NOT land in audit_logs.query.
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, auditEntry.AuditID,
			tenantID, orgID, auth.Client.ID, userEmail,
			fmt.Sprintf("%d", user.ID), user.Role,
			"mcp_check_output", fmt.Sprintf("mcp check-output: %s", req.ConnectorType), "",
			mcpVerdictRedacted, outPolicyIDs, outReasons, outcome.RedactedFieldNames(),
			traceIDFromHeader(r.Header.Get("traceparent")),
			outPolicyNames,                       // #3365
			time.Since(startTime).Milliseconds(), // #3424: agent-local check-output evaluation, no downstream hop
			req.ConnectorType, req.Tool)          // #2955: tool_server, tool_name
	} else {
		recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageTool,
			outVerdict, outPolicyIDs, time.Since(startTime).Milliseconds(), outReasons,
			"", nil, false, &decisionAuditInput{
				clientID:  auth.Client.ID,
				requestID: auditEntry.AuditID,
				userEmail: userEmail, // #2896: trust-gated attribution (validated fallback)
				userRole:  user.Role,
				userID:    user.ID,
				query:     fmt.Sprintf("mcp check-output: %s", req.ConnectorType),
				plane:     PlaneMCP, // #2592: MCP response plane → audit_logs.plane=mcp
				// #2598: correlate this response-plane decision with the request-plane
				// check-input (and any /decide stage) of the SAME logical tool call when
				// the proxy/gateway propagates a W3C traceparent across the hops. Absent
				// header → "" → singleton, preserving the chronological-only behavior.
				correlationID: traceIDFromHeader(r.Header.Get("traceparent")),
				toolServer:    req.ConnectorType, // #2955: tool_server (server axis)
				toolName:      req.Tool,          // #2955: tool_name (sub-tool axis)
			})
	}

	if outcome.SQLiBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("SQL injection detected: %s", outcome.SQLiPattern)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:     false,
			BlockReason: fmt.Sprintf("Response blocked: potential SQL injection detected (pattern: %s)", outcome.SQLiPattern),
			DecisionID:  decisionID,
		})
		return
	}

	if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outcome.StaticResult.BlockReason)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:     false,
			BlockReason: fmt.Sprintf("Response blocked: %s", outcome.StaticResult.BlockReason),
			DecisionID:  decisionID,
		})
		return
	}

	if outcome.ExfilResult != nil && outcome.ExfilResult.Exceeded {
		auditEntry.ExfilExceeded = true
		auditEntry.ExfilLimitType = outcome.ExfilResult.LimitType
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:          false,
			BlockReason:      outcome.ExfilResult.BlockReason,
			ExfiltrationInfo: outcome.ExfilInfo,
			DecisionID:       decisionID,
		})
		return
	}

	// Build redacted_data for the response
	var redactedData interface{}
	if outcome.RedactedRows != nil {
		redactedData = outcome.RedactedRows
	} else if outcome.RedactedMessage != "" {
		redactedData = outcome.RedactedMessage
	}

	policiesEvaluated := 0
	if outcome.StaticResult != nil {
		policiesEvaluated = outcome.StaticResult.PoliciesEvaluated
	}

	policyInfo := sharedpolicy.BuildPolicyInfo(nil, outcome.StaticResult)
	if policyInfo != nil && outcome.ExfilInfo != nil {
		policyInfo.ExfiltrationCheck = outcome.ExfilInfo
	} else if policyInfo == nil && outcome.ExfilInfo != nil {
		policyInfo = &sharedpolicy.PolicyInfo{ExfiltrationCheck: outcome.ExfilInfo}
	}

	auditEntry.Success = true
	auditEntry.DurationMs = time.Since(startTime).Milliseconds()
	logMCPQueryAudit(auditEntry)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
		Allowed:           true,
		RedactedData:      redactedData,
		PoliciesEvaluated: policiesEvaluated,
		ExfiltrationInfo:  outcome.ExfilInfo,
		PolicyInfo:        policyInfo,
		// Plugin Batch 1: every governance decision surfaces decision_id —
		// allow paths included, mirroring mcpCheckInputHandler.
		DecisionID: decisionID,
		// #2865: response-plane mirror of check-input's redaction_evaluated —
		// lets a PEP fail closed when the redactor did not run.
		RedactionEvaluated: outcome.RedactionEvaluated,
	})
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

	// #3067: /mcp/health is an unauthenticated liveness probe, so the live
	// health checks it runs are limited to the deployment-shared (operator-
	// configured) connectors. Previously it opened a connection to EVERY
	// tenant's backend on every anonymous GET — cross-tenant credential use
	// plus a free amplification lever. Per-tenant connector health is served
	// by the authenticated /mcp/connectors endpoints. total_connectors keeps
	// its deployment-wide meaning (an aggregate integer that was already
	// public here) so operator dashboards do not silently change scale.
	healthStatuses := mcpRegistry.HealthCheck(ctx, registry.SharedTenant)

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
