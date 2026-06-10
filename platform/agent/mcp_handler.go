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
	"axonflow/platform/connectors/s3"
	"axonflow/platform/connectors/salesforce"
	"axonflow/platform/connectors/servicenow"
	"axonflow/platform/connectors/slack"
	"axonflow/platform/connectors/snowflake"
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

// validateServiceLicense validates a service license key and checks MCP permissions.
// In community mode, license validation is skipped entirely since MCP features are community features.
// Returns (servicePermissionGranted, error). On error, the HTTP response has already been sent.
func validateServiceLicense(ctx context.Context, w http.ResponseWriter, licenseKey, connector, operation, fallbackOperation string) (bool, error) {
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
//
// v9 Phase 8 #2384 PR-C1: orgID is plumbed through to EvalOptions.OrgID so
// metrics.RecordViolation can stamp shared AuditEntry.OrgID, which the
// audit_queue persistence path uses to pin app.current_org_id under
// axonflow_app_role for the policy_metrics / policy_violations INSERTs.
func evaluateInputPolicies(
	ctx context.Context,
	tenantID, orgID, userID, userRole, connectorName, operation, statement string,
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
	// #2581: per-org posture. orgID is the auth-derived org for this request; an
	// org with no override row resolves to the deployment-global config.
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, orgID)
	if policyEngine != nil && mcpDetectionCfg.Enabled && mcpDetectionCfg.IsConnectorEnabled(connectorName) {
		// Security + compliance categories stay explicit; the PII categories are
		// policy-derived (every enabled PII-category system policy) so a new
		// pii-* category (e.g. pii-indonesia) is auto-covered — no hardcoded PII
		// list to forget. The non-PII categories keep the slice non-empty, so
		// the empty-Categories-means-all whitelist footgun can't apply here.
		inputCats := []sharedpolicy.PolicyCategory{
			sharedpolicy.CategorySecuritySQLi,
			sharedpolicy.CategorySecurityDangerous,
			sharedpolicy.CategoryComplianceRBI,
			sharedpolicy.CategoryComplianceSEBI,
			sharedpolicy.CategoryComplianceEUAIAct,
			sharedpolicy.CategoryComplianceMASFEAT,
		}
		inputCats = append(inputCats, policyEngine.EnabledPIICategories(ctx, tenantID, nil, sharedpolicy.PhaseRequest)...)
		out.StaticResult = policyEngine.EvaluateRequest(ctx, statement, sharedpolicy.EvalOptions{
			TenantID:        tenantID,
			OrgID:           orgID,
			ConnectorName:   connectorName,
			UserID:          userID,
			Parameters:      parameters,
			Categories:      inputCats,
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
	piiCats := policyEngine.EnabledPIICategories(ctx, tenantID, nil, sharedpolicy.PhaseRequest)
	if len(piiCats) > 0 {
		result := policyEngine.EvaluateResponse(ctx, []map[string]interface{}{{"statement": working}}, sharedpolicy.EvalOptions{
			TenantID:        tenantID,
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

func evaluateOutputPolicies(
	ctx context.Context,
	tenantID, userID, connectorName string,
	rows []map[string]interface{},
	message string,
	messageMetadata map[string]interface{},
	rowCount int,
	checkExfiltration bool,
	isGateway bool, // true for PEP/gateway callers (check-output) → bypass the connector allowlist for PII detection
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

	// #2581: per-org posture. check-output stamps orgID into ctx; the managed-
	// connector query/execute paths may not, in which case orgID is empty →
	// deployment-global (fail-safe, identical to pre-#2581).
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, OrgIDFromContext(ctx))
	// Connector-agnostic gateway path: a PEP/gateway caller (isGateway, e.g.
	// check-output submitting pre-executed output) has no managed connector, so
	// the MCP connector allowlist (IsConnectorEnabled, permissive-when-empty)
	// must NOT gate it — otherwise a configured allowlist silently disables
	// response PII redaction for the gateway. Managed-connector responses
	// (query/execute) keep the allowlist.
	detectionGate := mcpDetectionCfg.Enabled && (isGateway || mcpDetectionCfg.IsConnectorEnabled(connectorName))

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
				return out
			}
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
					}
				} else if message != "" {
					if masked, changed := maskJSONSafe(message, redactIndonesiaPIIInString); changed {
						message = masked
						out.RedactedMessage = masked
						out.IndonesiaRedactedTypes = indonesiaDetectedTypeNames(idResult)
					}
				}
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
		piiCats := policyEngine.EnabledPIICategories(ctx, tenantID, nil, sharedpolicy.PhaseResponse)
		if responseContent != nil && len(piiCats) > 0 {
			out.StaticResult = policyEngine.EvaluateResponse(ctx, responseContent, sharedpolicy.EvalOptions{
				TenantID:        tenantID,
				ConnectorName:   connectorName,
				UserID:          userID,
				Categories:      piiCats,
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

func mcpOutputDecisionVerdict(outcome OutputPolicyOutcome) (verdict string, policyIDs, reasons []string) {
	switch {
	case outcome.SQLiBlocked:
		return VerdictDeny, []string{"sqli_response_scan"},
			[]string{fmt.Sprintf("SQL injection detected in response: %s", outcome.SQLiPattern)}
	case outcome.StaticResult != nil && outcome.StaticResult.Blocked:
		return VerdictDeny, blockedPolicyIDs(outcome.StaticResult),
			[]string{outcome.StaticResult.BlockReason}
	case outcome.ExfilResult != nil && outcome.ExfilResult.Exceeded:
		return VerdictDeny, []string{"exfiltration_limit"},
			[]string{outcome.ExfilResult.BlockReason}
	}
	// Terminal allow. Static redactions carry their matched policy ids; surface
	// the redacted field names so a redact is distinguishable from a clean allow.
	if outcome.StaticResult != nil {
		policyIDs = extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
	}
	if outcome.WasRedacted() {
		if fields := outcome.RedactedFieldNames(); len(fields) > 0 {
			reasons = []string{"response PII redacted: " + strings.Join(fields, ", ")}
		} else {
			reasons = []string{"response PII redacted"}
		}
	}
	return VerdictAllow, policyIDs, reasons
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
// Redaction is an allow-with-obligation, NOT a deny (same as the response plane):
// a masked statement still forwards to the caller, so it records verdict=allow and
// surfaces the redaction in reasons so a redact is distinguishable from a clean
// allow on the explain endpoint (#2563 AUDIT-A1 HARD RULE 1).
func mcpInputDecisionVerdict(outcome InputPolicyOutcome, didRedact bool) (verdict string, policyIDs, reasons []string) {
	if outcome.DynamicBlocked {
		return VerdictDeny, extractDynamicPolicyIDs(outcome.DynamicInfo),
			[]string{outcome.DynamicBlockReason}
	}
	// Terminal allow. A non-blocking static (redact) policy carries its matched
	// ids; surface them so the portal feed attributes the allow correctly.
	if outcome.StaticResult != nil {
		policyIDs = extractMatchedPolicyIDs(outcome.StaticResult.MatchedPolicies)
	}
	if didRedact {
		reasons = []string{"request PII redacted"}
	}
	return VerdictAllow, policyIDs, reasons
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

	// Initialize audit entry (will be populated throughout the handler)
	auditEntry := MCPQueryAuditEntry{
		AuditID:       uuid.New().String(),
		ConnectorName: req.Connector,
		Operation:     "query",
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
		if auth.Kind == AuthKindEnterprise {
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		} else {
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
	// v9 Phase 8 #2384 PR-C1: orgID is on the legacy *User struct as OrgID.
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID), user.Role,
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
		result.Rows, "", nil, result.RowCount, true, false /* isGateway: managed connector */)

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
		if auth.Kind == AuthKindEnterprise {
			user = &User{
				ID:          0,
				Email:       client.ID + "@axonflow.local",
				Name:        client.Name,
				TenantID:    client.TenantID,
				Role:        "service",
				Permissions: client.Permissions,
			}
		} else {
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
	// v9 Phase 8 #2384 PR-C1: orgID plumbed through for RLS-aware audit writes.
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID), user.Role,
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
		nil, result.Message, result.Metadata, int(result.RowsAffected), false, false /* isGateway: managed connector */)

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

	// Authenticate via unified authenticator
	hints := &AuthHints{ClientID: req.ClientID, UserToken: req.UserToken, TenantID: req.TenantID}
	auth, authErr := Authenticate(r, hints)
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}

	// Content-type-agnostic redaction (ADR-056 / #2563 addendum): reject a
	// content_type with no registered detector. Runs AFTER auth so the detector
	// registry isn't probeable by unauthenticated callers (#2563 L1). Empty/text
	// defaults to the built-in text detector, so existing callers are
	// unaffected; a caller asking us to govern (e.g.) an image with no media
	// detector registered fails closed here rather than forwarding ungoverned.
	if _, ok := requestRedactionDetectorFor(req.ContentType); !ok {
		sendErrorResponse(w, "no redaction detector registered for content_type: "+req.ContentType, http.StatusUnsupportedMediaType, nil)
		return
	}

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via r.Context()
	// agree with the four-key shape apiAuthMiddleware writes
	// (auth.go:658-661). This handler is NOT behind apiAuthMiddleware.
	// Sibling of #2319.
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))

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
		if auth.Kind == AuthKindEnterprise {
			user = &User{
				ID:       0,
				Email:    auth.Client.ID + "@axonflow.local",
				Name:     auth.Client.Name,
				TenantID: auth.Client.TenantID,
				Role:     "service",
			}
		} else {
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}
	if user.TenantID != auth.Client.TenantID {
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

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
		sendErrorResponse(w, "tenant_id is required", http.StatusBadRequest, nil)
		return
	}

	// Per-caller identity for Plugin Batch 1 override scoping. Falls back
	// to the authenticated user's email when the client hasn't supplied
	// X-User-Email (e.g. a legacy SDK caller).
	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
		userEmail = user.Email
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
	idempotency.Wrap(w, r, mcpIdempStore, idempOrgID, tenantID, "mcp.check-input", func(w http.ResponseWriter, r *http.Request) {
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
		emitInputDecision := func(verdict string, policyIDs, reasons []string) {
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
				})
		}

		// v9 Phase 8 #2384 PR-C1: orgID plumbed through.
		outcome := evaluateInputPolicies(ctx,
			tenantID, orgID, userID, userRole,
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
			// #2627: a dynamic-policy block previously wrote ONLY the
			// mcp_query_audits satellite, so the portal feed showed it as
			// "Logged", not "Blocked". Emit the canonical audit_logs deny row.
			v, pids, reasons := mcpInputDecisionVerdict(outcome, false)
			emitInputDecision(v, pids, reasons)
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
					var overriddenPolicyVersion int
					if overriddenMatch != nil {
						overriddenPolicyID = overriddenMatch.PolicyID
						overriddenPolicyVersion = overriddenMatch.Version
					}
					writeOverrideUsedEvent(ctx, usageDB, usedOverrideID,
						decisionID, tenantID, orgID, auth.Client.ID, userEmail,
						overriddenPolicyID, overriddenPolicyVersion,
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
				writeExplainableAuditLog(ctx, usageDB,
					decisionID, auditEntry.AuditID,
					tenantID, orgID, auth.Client.ID, userEmail,
					userID, userRole,
					"mcp_check_input", req.Statement, auditEntry.StatementHash,
					outcome.StaticResult.BlockReason, topRisk, matches,
					traceIDFromHeader(r.Header.Get("traceparent"))) // #2598 correlation

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
			auditEntry.ResponseRedacted = true
		}

		auditEntry.Success = true
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2627: the terminal allow (clean or redacted) previously wrote ONLY the
		// mcp_query_audits satellite, so an allowed governance decision never reached
		// the portal feed. Emit the canonical audit_logs allow row. A redact is an
		// allow-with-obligation, recorded verdict=allow + surfaced in reasons so it
		// stays distinguishable from a clean allow on /explain.
		v, pids, reasons := mcpInputDecisionVerdict(outcome, didRedact)
		emitInputDecision(v, pids, reasons)

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
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}

	// Stamp auth identity (TenantID/OrgID/ClientID/AuthKind) into the
	// request context so downstream functions reached via r.Context()
	// agree with the four-key shape apiAuthMiddleware writes
	// (auth.go:658-661). This handler is NOT behind apiAuthMiddleware.
	// Sibling of #2319.
	r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))

	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(r.Context(), auth.TenantID)

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
		if auth.Kind == AuthKindEnterprise {
			user = &User{
				ID:       0,
				Email:    auth.Client.ID + "@axonflow.local",
				Name:     auth.Client.Name,
				TenantID: auth.Client.TenantID,
				Role:     "service",
			}
		} else {
			sendErrorResponse(w, userErr.Message, userErr.HTTPStatus, nil)
			return
		}
	}
	if user.TenantID != auth.Client.TenantID {
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

	// Validate tenant_id after auth (Basic auth derives it from client)
	if tenantID == "" {
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

	outcome := evaluateOutputPolicies(ctx,
		tenantID, userID, req.ConnectorType,
		req.ResponseData, req.Message, req.Metadata, req.RowCount, checkExfiltration, true /* isGateway: check-output is a PEP/gateway caller */)

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
	outVerdict, outPolicyIDs, outReasons := mcpOutputDecisionVerdict(outcome)
	recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageTool,
		outVerdict, outPolicyIDs, time.Since(startTime).Milliseconds(), outReasons,
		"", nil, false, &decisionAuditInput{
			clientID:  auth.Client.ID,
			requestID: auditEntry.AuditID,
			userEmail: user.Email,
			userRole:  user.Role,
			userID:    user.ID,
			query:     fmt.Sprintf("mcp check-output: %s", req.ConnectorType),
			plane:     PlaneMCP, // #2592: MCP response plane → audit_logs.plane=mcp
			// #2598: correlate this response-plane decision with the request-plane
			// check-input (and any /decide stage) of the SAME logical tool call when
			// the proxy/gateway propagates a W3C traceparent across the hops. Absent
			// header → "" → singleton, preserving the chronological-only behavior.
			correlationID: traceIDFromHeader(r.Header.Get("traceparent")),
		})

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
