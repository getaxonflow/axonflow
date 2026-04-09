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
	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/connectors/s3"
	"axonflow/platform/connectors/salesforce"
	"axonflow/platform/connectors/servicenow"
	"axonflow/platform/connectors/slack"
	"axonflow/platform/connectors/snowflake"
	sharedpolicy "axonflow/platform/shared/policy"
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
	if secret := os.Getenv(serviceauth.SecretEnvVar); secret != "" {
		internalTokenValidator = serviceauth.NewTokenValidator(secret, serviceauth.RealClock{}, serviceauth.DefaultClockSkew)
	}
	serviceauth.LogAuthWarning()
}

// validateServiceLicense validates a service license key and checks MCP permissions.
// In community mode, license validation is skipped entirely since MCP features are community features.
// Returns (servicePermissionGranted, error). On error, the HTTP response has already been sent.
func validateServiceLicense(ctx context.Context, w http.ResponseWriter, licenseKey, connector, operation, fallbackOperation string) (bool, error) {
	if licenseKey == "" || isCommunityMode() {
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

	connector, err := mcpRegistry.Get(connectorName)
	if err != nil {
		return nil, fmt.Errorf("connector '%s' not found: %w", connectorName, err)
	}

	log.Printf("[MCP] Retrieved connector '%s' from static registry (fallback)", logutil.Sanitize(connectorName))
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
}

// evaluateInputPolicies runs dynamic + request-phase static policy checks without
// calling any connector. Shared by mcpQueryHandler, mcpExecuteHandler, and
// mcpCheckInputHandler (Issue #1258).
func evaluateInputPolicies(
	ctx context.Context,
	tenantID, userID, userRole, connectorName, operation, statement string,
	parameters map[string]interface{},
) InputPolicyOutcome {
	var out InputPolicyOutcome

	// Dynamic policy evaluation (rate limits, budgets, time/role access)
	dynamicEvaluator := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	if dynamicEvaluator != nil && dynamicEvaluator.IsEnabled(connectorName) {
		dynamicReq := sharedpolicy.DynamicPolicyRequest{
			TenantID:      tenantID,
			UserID:        userID,
			UserRole:      userRole,
			ConnectorName: connectorName,
			Operation:     operation,
			Statement:     statement,
			Parameters:    parameters,
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

	// Request-phase static policy evaluation (SQLi, PII, compliance)
	policyEngine := sharedpolicy.GetGlobalEngine()
	mcpDetectionCfg := GetMCPDetectionConfig()
	if policyEngine != nil && mcpDetectionCfg.Enabled && mcpDetectionCfg.IsConnectorEnabled(connectorName) {
		out.StaticResult = policyEngine.EvaluateRequest(ctx, statement, sharedpolicy.EvalOptions{
			TenantID:      tenantID,
			ConnectorName: connectorName,
			UserID:        userID,
			Parameters:    parameters,
			Categories: []sharedpolicy.PolicyCategory{
				sharedpolicy.CategorySecuritySQLi,
				sharedpolicy.CategorySecurityDangerous,
				sharedpolicy.CategoryPIIGlobal,
				sharedpolicy.CategoryPIIUS,
				sharedpolicy.CategoryPIIIndia,
				sharedpolicy.CategoryPIIEU,
				sharedpolicy.CategoryPIISingapore,
				sharedpolicy.CategoryComplianceRBI,
				sharedpolicy.CategoryComplianceSEBI,
				sharedpolicy.CategoryComplianceEUAIAct,
				sharedpolicy.CategoryComplianceMASFEAT,
			},
			SkipCategories:  mcpDetectionCfg.SkipCategories,
			ActionOverrides: mcpDetectionCfg.BuildActionOverrides(),
		})
		if out.StaticResult.Blocked {
			log.Printf("[MCP] Request blocked by static policy '%s': %s",
				out.StaticResult.BlockedBy.PolicyID, out.StaticResult.BlockReason)
		}
	}

	return out
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

	// ExfilResult is the raw exfiltration check result. Nil when checkExfiltration is false
	// or when the exfiltration checker is disabled.
	ExfilResult *sharedpolicy.ExfiltrationResult

	// ExfilInfo is the structured exfiltration info for inclusion in PolicyInfo.
	ExfilInfo *sharedpolicy.ExfiltrationCheckInfo
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
func evaluateOutputPolicies(
	ctx context.Context,
	tenantID, userID, connectorName string,
	rows []map[string]interface{},
	message string,
	messageMetadata map[string]interface{},
	rowCount int,
	checkExfiltration bool,
) OutputPolicyOutcome {
	var out OutputPolicyOutcome

	// 1. SQLi response scan
	if rows != nil {
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

	// 2. Response-phase static policy evaluation (PII redaction)
	policyEngine := sharedpolicy.GetGlobalEngine()
	mcpDetectionCfg := GetMCPDetectionConfig()
	if policyEngine != nil && mcpDetectionCfg.Enabled && mcpDetectionCfg.IsConnectorEnabled(connectorName) {
		var responseContent []map[string]interface{}
		if rows != nil {
			responseContent = rows
		} else if message != "" {
			responseContent = []map[string]interface{}{{"message": message}}
		}
		if responseContent != nil {
			out.StaticResult = policyEngine.EvaluateResponse(ctx, responseContent, sharedpolicy.EvalOptions{
				TenantID:      tenantID,
				ConnectorName: connectorName,
				UserID:        userID,
				Categories: []sharedpolicy.PolicyCategory{
					sharedpolicy.CategoryPIIGlobal,
					sharedpolicy.CategoryPIIUS,
					sharedpolicy.CategoryPIIIndia,
					sharedpolicy.CategoryPIIEU,
					sharedpolicy.CategoryPIISingapore,
				},
				SkipCategories:  mcpDetectionCfg.SkipCategories,
				ActionOverrides: mcpDetectionCfg.BuildActionOverrides(),
				MaxRedactions:   100,
			})
			if out.StaticResult.Blocked {
				log.Printf("[MCP] Response blocked by policy '%s': %s",
					out.StaticResult.BlockedBy.PolicyID, out.StaticResult.BlockReason)
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

	// 3. Exfiltration detection (enabled for query responses, disabled for execute)
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

	// Initialize audit entry (will be populated throughout the handler)
	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.Connector,
		Operation:     "query",
		Success:       false, // Will be set to true only on successful completion
	}

	ctx := r.Context()

	// 1. Check authentication - with multiple bypass modes
	// Priority: Community mode > Internal service request > Enterprise validation
	// Pattern follows PR #97: DEPLOYMENT_MODE == "community" || mode == ""
	var client *Client
	var user *User

	if isCommunityMode() {
		// Community mode: Skip client/user authentication
		// This allows Community deployments to work without client/user registration.
		// When user upgrades to Enterprise (sets DEPLOYMENT_MODE=enterprise), full validation kicks in.
		log.Printf("[MCP] Community mode - bypassing client and user token validation")
		client = &Client{
			ID:          "community",
			Name:        "Community Client",
			TenantID:    "community",
			Permissions: []string{"query", "execute", "mcp"},
			RateLimit:   0,
			Enabled:     true,
		}
		user = &User{
			ID:          0,
			Email:       "user@community.local",
			Name:        "Community User",
			TenantID:    "community",
			Role:        "admin",
			Permissions: []string{"query", "execute", "mcp"},
		}
	} else if serviceauth.IsValidInternalServiceRequest(req.ClientID, req.UserToken, internalTokenValidator) {
		// Internal orchestrator-to-agent routing (used in Enterprise/SaaS deployments)
		// Uses HMAC-signed tokens if AXONFLOW_INTERNAL_SERVICE_SECRET is configured,
		// with backward compatibility for legacy plain-secret tokens.
		log.Printf("[MCP] Internal orchestrator request - bypassing client and user token validation")
		tenantID := req.TenantID
		if tenantID == "" {
			tenantID = req.ClientID
		}
		client = &Client{
			ID:          serviceauth.ClientID,
			Name:        "Orchestrator Internal",
			TenantID:    tenantID,
			Permissions: []string{"query", "execute", "mcp"},
			RateLimit:   0, // No rate limit for internal service
			Enabled:     true,
		}
		user = &User{
			ID:          0,
			Email:       "orchestrator@axonflow.internal",
			Name:        "Orchestrator Internal",
			TenantID:    tenantID,
			Role:        "service",
			Permissions: []string{"query", "execute", "mcp"},
		}
	} else {
		// Enterprise/SaaS mode: try Basic auth first (service license), then whitelist
		var err error
		clientID := extractClientID(r)
		clientSecret := extractClientSecret(r)

		if clientID != "" && clientSecret != "" {
			// Basic auth present — use the same validation as proxy (DB or whitelist)
			authCtx, authCancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer authCancel()
			if authDB != nil {
				client, err = validateClientCredentialsDB(authCtx, authDB, clientID, clientSecret)
			} else {
				client, err = validateClientCredentials(authCtx, clientID, clientSecret)
			}
			if err != nil {
				sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
				return
			}
		} else {
			// No Basic auth credentials provided. In enterprise/SaaS mode we
			// require proper OAuth2 Client Credentials (clientId + clientSecret
			// as a signed license key). The previous fallback to a mock
			// validateClient() was a no-auth security hole — it accepted any
			// client_id from the request body and attributed everything to the
			// deployment's own org, breaking multi-tenant isolation.
			sendErrorResponse(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized, nil)
			return
		}

		if !client.Enabled {
			sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
			return
		}

		// Validate user token (optional for Basic auth — derive from client)
		user, err = validateUserToken(req.UserToken, client.TenantID)
		if err != nil && clientID == "" {
			// Only fail on user token if no Basic auth was provided
			sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
			return
		} else if err != nil {
			// Basic auth present — create a service user from client identity
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		}

		// Verify tenant isolation
		if user.TenantID != client.TenantID {
			sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
			return
		}
	}

	// Update audit entry with authenticated user/client info
	auditEntry.TenantID = user.TenantID
	auditEntry.OrgID = client.OrgID
	auditEntry.ClientID = client.ID
	auditEntry.UserID = fmt.Sprintf("%d", user.ID)

	// 2. Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	// In community mode, skip license validation entirely - these are community features
	servicePermissionGranted, err := validateServiceLicense(ctx, w, req.LicenseKey, req.Connector, req.Operation, "query")
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
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Dynamic + request-phase static policy evaluation (Issues #968, #1081, #1258)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, fmt.Sprintf("%d", user.ID), user.Role,
		req.Connector, "query", statement, req.Parameters)

	if inputOutcome.EvalUnavailable {
		sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
		return
	}

	if inputOutcome.DynamicBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = inputOutcome.DynamicBlockReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
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

		sendErrorResponse(w, "Query execution failed", http.StatusInternalServerError, nil)
		return
	}

	// Response-phase policy evaluation: SQLi scan, PII redaction, exfiltration (Issue #1258)
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, fmt.Sprintf("%d", user.ID), req.Connector,
		result.Rows, "", nil, result.RowCount, true)

	// Use redacted row data if PII was redacted
	responseData := result.Rows
	if outputOutcome.RedactedRows != nil {
		responseData = outputOutcome.RedactedRows
	}

	// Update audit entry with output policy results
	auditEntry.ExfilRowsReturned = result.RowCount
	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Redacted {
		auditEntry.ResponseRedacted = true
		auditEntry.ResponseRedactionsCount = len(outputOutcome.StaticResult.RedactedFields)
		auditEntry.ResponseRedactedFields = sharedpolicy.GetRedactedFieldPaths(outputOutcome.StaticResult)
	}

	if outputOutcome.SQLiBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("SQL injection detected: %s", outputOutcome.SQLiPattern)
		auditEntry.RowCount = result.RowCount
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
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
	redactedFields := sharedpolicy.GetRedactedFieldPaths(outputOutcome.StaticResult)

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

	// Add policy info fields (additive, backward compatible)
	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Redacted {
		response["redacted"] = true
		response["redacted_fields"] = redactedFields
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

	// Initialize audit entry (will be populated throughout the handler)
	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.Connector,
		Operation:     operation,
		Success:       false, // Will be set to true only on successful completion
	}

	ctx := r.Context()

	// Authentication - same pattern as mcpQueryHandler
	// Priority: Community mode > Internal service request > Enterprise validation
	var client *Client
	var user *User

	if isCommunityMode() {
		// Community mode: Skip client/user authentication
		log.Printf("[MCP Execute] Community mode - bypassing client and user token validation")
		client = &Client{
			ID:          "community",
			Name:        "Community Client",
			TenantID:    "community",
			Permissions: []string{"query", "execute", "mcp"},
			RateLimit:   0,
			Enabled:     true,
		}
		user = &User{
			ID:          0,
			Email:       "user@community.local",
			Name:        "Community User",
			TenantID:    "community",
			Role:        "admin",
			Permissions: []string{"query", "execute", "mcp"},
		}
	} else if serviceauth.IsValidInternalServiceRequest(req.ClientID, req.UserToken, internalTokenValidator) {
		// Internal orchestrator-to-agent routing (used in Enterprise/SaaS deployments)
		log.Printf("[MCP Execute] Internal orchestrator request - bypassing client and user token validation")
		tenantID := req.TenantID
		if tenantID == "" {
			tenantID = req.ClientID
		}
		client = &Client{
			ID:          serviceauth.ClientID,
			Name:        "Orchestrator Internal",
			TenantID:    tenantID,
			Permissions: []string{"query", "execute", "mcp"},
			RateLimit:   0,
			Enabled:     true,
		}
		user = &User{
			ID:          0,
			Email:       "orchestrator@axonflow.internal",
			Name:        "Orchestrator Internal",
			TenantID:    tenantID,
			Role:        "service",
			Permissions: []string{"query", "execute", "mcp"},
		}
	} else {
		// Enterprise/SaaS mode: try Basic auth first (service license), then whitelist
		var err error
		clientID := extractClientID(r)
		clientSecret := extractClientSecret(r)

		if clientID != "" && clientSecret != "" {
			// Basic auth present — use the same validation as proxy (DB or whitelist)
			authCtx, authCancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer authCancel()
			if authDB != nil {
				client, err = validateClientCredentialsDB(authCtx, authDB, clientID, clientSecret)
			} else {
				client, err = validateClientCredentials(authCtx, clientID, clientSecret)
			}
			if err != nil {
				sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
				return
			}
		} else {
			// No Basic auth credentials. Enterprise mode requires proper OAuth2
			// Client Credentials. Removed the legacy validateClient() fallback
			// which accepted any client_id from request body without
			// authentication — a multi-tenant security hole.
			sendErrorResponse(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized, nil)
			return
		}

		if !client.Enabled {
			sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
			return
		}

		// Validate user token (optional for Basic auth — derive from client)
		user, err = validateUserToken(req.UserToken, client.TenantID)
		if err != nil && clientID == "" {
			// Only fail on user token if no Basic auth was provided
			sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
			return
		} else if err != nil {
			// Basic auth present — create a service user from client identity
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		}

		// Verify tenant isolation
		if user.TenantID != client.TenantID {
			sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
			return
		}
	}

	// Update audit entry with authenticated user/client info
	auditEntry.TenantID = user.TenantID
	auditEntry.OrgID = client.OrgID
	auditEntry.ClientID = client.ID
	auditEntry.UserID = fmt.Sprintf("%d", user.ID)

	// Validate service license and check permissions (SERVICE IDENTITY SYSTEM)
	// In community mode, skip license validation entirely - these are community features
	servicePermissionGranted, err := validateServiceLicense(ctx, w, req.LicenseKey, req.Connector, req.Operation, strings.ToLower(req.Action))
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

	// Dynamic + request-phase static policy evaluation (Issues #968, #1081, #1258)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, fmt.Sprintf("%d", user.ID), user.Role,
		req.Connector, "execute", req.Statement, req.Parameters)

	if inputOutcome.EvalUnavailable {
		sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
		return
	}

	if inputOutcome.DynamicBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = inputOutcome.DynamicBlockReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
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

		sendErrorResponse(w, "Command execution failed", http.StatusInternalServerError, nil)
		return
	}

	// Response-phase policy evaluation: SQLi scan, PII redaction (Issue #1258)
	// Exfiltration checking is not applied to execute results (execute returns rows_affected, not data rows).
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, fmt.Sprintf("%d", user.ID), req.Connector,
		nil, result.Message, result.Metadata, int(result.RowsAffected), false)

	// Use redacted message if PII was redacted
	responseMessage := result.Message
	if outputOutcome.RedactedMessage != "" {
		responseMessage = outputOutcome.RedactedMessage
	}

	// Update audit entry with output policy results
	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Redacted {
		auditEntry.ResponseRedacted = true
		auditEntry.ResponseRedactionsCount = len(outputOutcome.StaticResult.RedactedFields)
		auditEntry.ResponseRedactedFields = sharedpolicy.GetRedactedFieldPaths(outputOutcome.StaticResult)
	}

	if outputOutcome.SQLiBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("SQL injection detected: %s", outputOutcome.SQLiPattern)
		auditEntry.RowCount = int(result.RowsAffected)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
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
	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Redacted {
		response["redacted"] = true
		response["redacted_fields"] = sharedpolicy.GetRedactedFieldPaths(outputOutcome.StaticResult)
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

	log.Printf("[MCP] Command executed: connector=%s, action=%s, rows_affected=%d, duration=%v",
		logutil.Sanitize(req.Connector), logutil.Sanitize(req.Action), result.RowsAffected, result.Duration)
}

// --- Standalone policy-check endpoints (Issue #1258) ---

// MCPCheckInputRequest is the request body for POST /api/v1/mcp/check-input.
// External orchestrators submit the proposed statement before executing it themselves.
type MCPCheckInputRequest struct {
	ClientID      string                 `json:"client_id"`
	UserToken     string                 `json:"user_token"`
	TenantID      string                 `json:"tenant_id"`
	UserID        string                 `json:"user_id,omitempty"`
	UserRole      string                 `json:"user_role,omitempty"`
	ConnectorType string                 `json:"connector_type"`
	Statement     string                 `json:"statement"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`
	Operation     string                 `json:"operation,omitempty"` // "query" or "execute"; defaults to "execute"
}

// MCPCheckInputResponse is the response body for POST /api/v1/mcp/check-input.
type MCPCheckInputResponse struct {
	Allowed           bool                     `json:"allowed"`
	BlockReason       string                   `json:"block_reason,omitempty"`
	PoliciesEvaluated int                      `json:"policies_evaluated"`
	PolicyInfo        *sharedpolicy.PolicyInfo `json:"policy_info,omitempty"`
}

// MCPCheckOutputRequest is the request body for POST /api/v1/mcp/check-output.
// External orchestrators submit the raw connector response for policy scanning.
type MCPCheckOutputRequest struct {
	ClientID      string                   `json:"client_id"`
	UserToken     string                   `json:"user_token"`
	TenantID      string                   `json:"tenant_id"`
	UserID        string                   `json:"user_id,omitempty"`
	ConnectorType string                   `json:"connector_type"`
	ResponseData  []map[string]interface{} `json:"response_data,omitempty"` // query-style row results
	Message       string                   `json:"message,omitempty"`       // execute-style response message
	Metadata      map[string]interface{}   `json:"metadata,omitempty"`      // connector metadata (used by SQLi scanning)
	RowCount      int                      `json:"row_count,omitempty"`
}

// MCPCheckOutputResponse is the response body for POST /api/v1/mcp/check-output.
type MCPCheckOutputResponse struct {
	Allowed           bool                                `json:"allowed"`
	BlockReason       string                              `json:"block_reason,omitempty"`
	RedactedData      interface{}                         `json:"redacted_data,omitempty"`
	PoliciesEvaluated int                                 `json:"policies_evaluated"`
	ExfiltrationInfo  *sharedpolicy.ExfiltrationCheckInfo `json:"exfiltration_info,omitempty"`
	PolicyInfo        *sharedpolicy.PolicyInfo            `json:"policy_info,omitempty"`
}

// mcpCheckInputHandler evaluates dynamic + request-phase static policies for a proposed
// MCP statement without executing any connector.
// POST /api/v1/mcp/check-input
func mcpCheckInputHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

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

	// Authentication — same three-way pattern as mcpQueryHandler
	// Note: tenant_id validation moved to after auth since Basic auth derives it from client
	// orgID is also derived per-request from the authenticated client's license
	// (client.OrgID), so multi-tenant deployments correctly scope audit records
	// by the calling org rather than the deployment's own label.
	var tenantID, userID, userRole, orgID string

	if isCommunityMode() {
		tenantID = "community"
		userID = "0"
		userRole = "admin"
		orgID = getDeploymentOrgID() // community mode has no license, use deployment label
	} else if serviceauth.IsValidInternalServiceRequest(req.ClientID, req.UserToken, internalTokenValidator) {
		tenantID = req.TenantID
		if tenantID == "" {
			tenantID = req.ClientID
		}
		userID = req.UserID
		userRole = req.UserRole
		orgID = r.Header.Get("X-Org-ID") // trusted internal service request
	} else {
		// Enterprise/SaaS mode: try Basic auth first, then legacy whitelist
		var client *Client
		var user *User
		var err error
		clientID := extractClientID(r)
		clientSecret := extractClientSecret(r)

		if clientID != "" && clientSecret != "" {
			authCtx, authCancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer authCancel()
			if authDB != nil {
				client, err = validateClientCredentialsDB(authCtx, authDB, clientID, clientSecret)
			} else {
				client, err = validateClientCredentials(authCtx, clientID, clientSecret)
			}
			if err != nil {
				sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
				return
			}
		} else {
			// No Basic auth credentials. Enterprise mode requires proper OAuth2
			// Client Credentials. Removed the legacy validateClient() fallback
			// which accepted any client_id from request body without
			// authentication — a multi-tenant security hole.
			sendErrorResponse(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized, nil)
			return
		}
		if !client.Enabled {
			sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
			return
		}
		user, err = validateUserToken(req.UserToken, client.TenantID)
		if err != nil && clientID == "" {
			sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
			return
		} else if err != nil {
			user = &User{
				ID:       0,
				Email:    client.ID + "@axonflow.local",
				Name:     client.Name,
				TenantID: client.TenantID,
				Role:     "service",
			}
		}
		if user.TenantID != client.TenantID {
			sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
			return
		}
		tenantID = user.TenantID
		userID = fmt.Sprintf("%d", user.ID)
		userRole = user.Role
		orgID = client.OrgID // from the validated client license (Ed25519-signed)
	}

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
		sendErrorResponse(w, "tenant_id is required", http.StatusBadRequest, nil)
		return
	}

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
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	operation := req.Operation
	if operation == "" {
		operation = "execute"
	}

	outcome := evaluateInputPolicies(ctx,
		tenantID, userID, userRole,
		req.ConnectorType, operation, req.Statement, req.Parameters)

	if outcome.EvalUnavailable {
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		sendErrorResponse(w, "Dynamic policy evaluation unavailable", http.StatusServiceUnavailable, nil)
		return
	}

	if outcome.DynamicBlocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = outcome.DynamicBlockReason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
			Allowed:     false,
			BlockReason: outcome.DynamicBlockReason,
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
			logMCPQueryAudit(auditEntry)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:           false,
				BlockReason:       outcome.StaticResult.BlockReason,
				PoliciesEvaluated: policiesEvaluated,
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

	auditEntry.Success = true
	auditEntry.DurationMs = time.Since(startTime).Milliseconds()
	logMCPQueryAudit(auditEntry)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
		Allowed:           true,
		PoliciesEvaluated: policiesEvaluated,
		PolicyInfo:        policyInfo,
	})
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

	// Authentication — same three-way pattern as mcpQueryHandler
	// Note: tenant_id validation moved to after auth since Basic auth derives it from client.
	// orgID is derived per-request from the authenticated client's license (client.OrgID),
	// so multi-tenant deployments correctly scope audit records by the calling org.
	var tenantID, userID, orgID string

	if isCommunityMode() {
		tenantID = "community"
		userID = "0"
		orgID = getDeploymentOrgID() // community mode has no license, use deployment label
	} else if serviceauth.IsValidInternalServiceRequest(req.ClientID, req.UserToken, internalTokenValidator) {
		tenantID = req.TenantID
		if tenantID == "" {
			tenantID = req.ClientID
		}
		userID = req.UserID
		orgID = r.Header.Get("X-Org-ID") // trusted internal service request
	} else {
		// Enterprise/SaaS mode: try Basic auth first, then legacy whitelist
		var client *Client
		var user *User
		var err error
		clientID := extractClientID(r)
		clientSecret := extractClientSecret(r)

		if clientID != "" && clientSecret != "" {
			authCtx, authCancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer authCancel()
			if authDB != nil {
				client, err = validateClientCredentialsDB(authCtx, authDB, clientID, clientSecret)
			} else {
				client, err = validateClientCredentials(authCtx, clientID, clientSecret)
			}
			if err != nil {
				sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
				return
			}
		} else {
			// No Basic auth credentials. Enterprise mode requires proper OAuth2
			// Client Credentials. Removed the legacy validateClient() fallback
			// which accepted any client_id from request body without
			// authentication — a multi-tenant security hole.
			sendErrorResponse(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized, nil)
			return
		}
		if !client.Enabled {
			sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
			return
		}
		user, err = validateUserToken(req.UserToken, client.TenantID)
		if err != nil && clientID == "" {
			sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
			return
		} else if err != nil {
			user = &User{
				ID:       0,
				Email:    client.ID + "@axonflow.local",
				Name:     client.Name,
				TenantID: client.TenantID,
				Role:     "service",
			}
		}
		if user.TenantID != client.TenantID {
			sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
			return
		}
		tenantID = user.TenantID
		userID = fmt.Sprintf("%d", user.ID)
		orgID = client.OrgID // from the validated client license (Ed25519-signed)
	}

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
		sendErrorResponse(w, "tenant_id is required", http.StatusBadRequest, nil)
		return
	}

	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.ConnectorType,
		Operation:     "check-output",
		TenantID:      tenantID,
		OrgID:         orgID,
		UserID:        userID,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Enable exfiltration checks for query-style responses (rows) but not for
	// execute-style responses (message only) — consistent with mcpExecuteHandler.
	checkExfiltration := len(req.ResponseData) > 0

	outcome := evaluateOutputPolicies(ctx,
		tenantID, userID, req.ConnectorType,
		req.ResponseData, req.Message, req.Metadata, req.RowCount, checkExfiltration)

	auditEntry.ExfilRowsReturned = req.RowCount
	if outcome.StaticResult != nil && outcome.StaticResult.Redacted {
		auditEntry.ResponseRedacted = true
		auditEntry.ResponseRedactionsCount = len(outcome.StaticResult.RedactedFields)
		auditEntry.ResponseRedactedFields = sharedpolicy.GetRedactedFieldPaths(outcome.StaticResult)
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
