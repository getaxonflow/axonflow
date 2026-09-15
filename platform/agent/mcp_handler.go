// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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

// mcpInputPolicyCategories is the STATIC portion of the category whitelist
// evaluated on the managed MCP planes by evaluateInputPolicies. The PII portion
// is NOT here: it is policy-derived per request (every enabled PII-category
// system policy), so a new pii-* category is covered without a hand list to
// forget, which was the #2965 defect that left pii-indonesia ungoverned
// elsewhere. These non-PII categories also keep the slice non-empty, so the
// empty-Categories-means-evaluate-everything footgun cannot apply here.
//
// #3529: hoisted from an inline literal to a package var so the sibling planes'
// guard test can see it. The three other planes were already package vars and
// this one was invisible to any test. Its compliance portion is sourced from
// sharedpolicy.AllComplianceCategories() rather than hand-listed.
//
// CategoryFinCrime is listed EXPLICITLY and must stay that way. It is
// deliberately outside the compliance vocabulary (ADR-061 / #3329: the pack is
// governed by neither the PII/SQLi detection overrides nor capability scoping), so
// AllComplianceCategories does not return it and must not start to. Rows exist
// only where the enterprise pack was seeded, so it is a no-op otherwise.
var mcpInputPolicyCategories = append([]sharedpolicy.PolicyCategory{
	sharedpolicy.CategorySecuritySQLi,
	sharedpolicy.CategorySecurityDangerous,
	sharedpolicy.CategorySensitiveData,
	sharedpolicy.CategoryFinCrime,
}, sharedpolicy.AllComplianceCategories()...)

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
// It uses the TenantConnectorRegistry for dynamic loading (ADR-006 compliant).
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

// InputPolicyOutcome is the MCP request pass's detector evaluation: the shared
// engine's request-phase result, whose detector facts are what the anchored
// engine decides from (enforceMCPRequest, and handleDecide), and the options it
// ran under, which a redaction the decision requires reuses so both scan the
// same policies (maskMCPStatement).
type InputPolicyOutcome struct {
	// StaticResult is the request-phase evaluation. Nil when the static policy
	// engine is disabled or the connector is excluded, and then every detector
	// is ABSENT to the anchored engine.
	StaticResult *sharedpolicy.RequestResult
	// Options are the options StaticResult was evaluated under.
	Options sharedpolicy.EvalOptions
}

// evaluateInputPolicies runs the request-phase detector pass without calling any
// connector. Shared by mcpQueryHandler, mcpExecuteHandler, mcpCheckInputHandler,
// the MCP server's check_policy and handleDecide (Issues #1258, #2801). It
// decides nothing: its result's detector facts are the anchored engine's input,
// and no field of it is read as a verdict (PRD v11 §1.1, §1.2).
//
// detectionCfg is caller-resolved (ResolveMCPDetectionConfig for the MCP
// planes, ResolveGatewayDetectionConfig for /decide) so each caller's
// org-override posture and connector-scoping rules stay what they are.
//
// orgID reaches EvalOptions.OrgID so metrics.RecordViolation can stamp the
// shared AuditEntry.OrgID, which the audit_queue persistence path uses to pin
// app.current_org_id under axonflow_app_role (v9 Phase 8 #2384 PR-C1).
//
// capabilityScopeIdentity is an ENFORCEMENT INPUT (#2801, #3717). When it
// positively classifies as a text-document tool the engine skips
// execution-class detectors, so a name that reaches it can only turn a deny
// into an allow; empty means full evaluation, the fail-closed direction. An
// enforcement point that runs the tool itself (check-input, check_policy,
// /decide) passes the tool it reports; the connector routes pass "", because
// there the agent executes the statement and the connector name is
// tenant-chosen free text.
//
// A REQUIRED parameter rather than a wrapper with a default, and the detector
// call stays in this function by name: TestLegacyCallSiteCensusIsComplete
// records it here, and a delegating wrapper would move it somewhere the census
// does not record.
func evaluateInputPolicies(
	ctx context.Context,
	tenantID, orgID, userID, connectorName, capabilityScopeIdentity, statement string,
	parameters map[string]interface{},
	detectionCfg ModeDetectionConfig,
) InputPolicyOutcome {
	var out InputPolicyOutcome
	policyEngine := sharedpolicy.GetGlobalEngine()
	if policyEngine == nil || !detectionCfg.Enabled || !detectionCfg.IsConnectorEnabled(connectorName) {
		return out
	}
	// The static portion is the package-level mcpInputPolicyCategories; the PII
	// portion stays policy-derived per request. Copied into a fresh slice rather
	// than appended onto the package var: appending to a shared slice that has
	// spare capacity writes into its backing array, which would let one request
	// mutate the whitelist every other request reads.
	inputCats := make([]sharedpolicy.PolicyCategory, 0, len(mcpInputPolicyCategories)+len(sharedpolicy.AllTextPIICategories()))
	inputCats = append(inputCats, mcpInputPolicyCategories...)
	inputCats = append(inputCats, policyEngine.EnabledPIICategories(ctx, tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseRequest)...)
	opts := sharedpolicy.EvalOptions{
		TenantID: tenantID,
		OrgID:    orgID,
		// #3048 R3 HIGH-3: scope the loader's tenant pass by the validated
		// caller org (org_id may differ from tenant_id).
		OrgScope:        sharedpolicy.OrgScopePtr(orgID),
		ConnectorName:   connectorName,
		UserID:          userID,
		Parameters:      parameters,
		Categories:      inputCats,
		ToolIdentity:    capabilityScopeIdentity,
		SkipCategories:  detectionCfg.SkipCategories,
		ActionOverrides: detectionCfg.BuildActionOverrides(),
	}
	out.StaticResult = policyEngine.EvaluateRequest(ctx, statement, opts)
	out.Options = opts
	return out
}

// OutputPolicyOutcome carries the results of SQLi scanning, response-phase static
// policy evaluation, and optionally exfiltration detection.
// It avoids mixing audit concerns with policy logic so callers retain full control.
type OutputPolicyOutcome struct {

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
func evaluateOutputPolicies(
	ctx context.Context,
	tenantID, orgID, userID, connectorName, toolIdentity string,
	rows []map[string]interface{},
	message string,
	messageMetadata map[string]interface{},
	rowCount int,
	checkExfiltration bool,
	isGateway bool, // true for PEP/gateway callers (check-output) → bypass the connector allowlist for PII detection
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

	// 1. SQLi response scan. It DETECTS - the middleware logs and audits what it
	// finds - and decides nothing: the response pass's verdict is the anchored
	// engine's (enforceMCPResponse below). The block it once returned here was
	// unreachable in production, because the global middleware is DefaultConfig
	// with BlockOnDetection false and nothing constructs another.
	if !textDocumentTool {
		var scanErr error
		if rows != nil {
			_, scanErr = sqli.GetGlobalMiddleware().ScanQueryResponse(ctx, connectorName, rows)
		} else if message != "" {
			_, scanErr = sqli.GetGlobalMiddleware().ScanCommandResponse(ctx, connectorName, message, messageMetadata)
		}
		if scanErr != nil {
			log.Printf("[MCP] SQLi scan error: %v", scanErr)
		}
	}

	// #2581: per-org posture. #3447: orgID is now the explicit parameter
	// rather than a ctx read-back; an empty value resolves no override, so the
	// stored policy actions decide (fail-safe).
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
				mcpResponseSeamFrom(ctx).noteLegacyValidator(legacyValidatorIndonesia, legacyActionBlocked)
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
				// Mask NIK/NPWP/etc ONLY under an org pii=redact override, then feed the masked
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
			if anyMasked {
				mcpResponseSeamFrom(ctx).noteLegacyValidator(legacyValidatorIndonesia, legacyActionMasked)
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
	var responseContent []map[string]interface{}
	if rows != nil {
		responseContent = rows
	} else if message != "" {
		responseContent = []map[string]interface{}{{"message": message}}
	}
	// #3564: the options the evaluation below runs under, hoisted so the
	// enforcing seam's redaction scans exactly the policies it loaded.
	var evalOpts sharedpolicy.EvalOptions
	policyEngine := sharedpolicy.GetGlobalEngine()
	if policyEngine != nil && detectionGate {
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
			// response plane (strip the injected span; surrounding data survives)
			// because that is the injection rows' STORED response action (core/128
			// sets action_response='redact'; the dangerous-command rows are
			// request-phase only). An organization's recorded dangerous_command
			// override replaces it here exactly as it does on the request plane.
			// Before #3961 this site forced redact over whatever the row stored
			// unless the org had an override - a displacement with no record - and
			// with stored actions deciding there is nothing left to force.
			actionOverrides := mcpDetectionCfg.BuildActionOverrides()
			evalOpts = sharedpolicy.EvalOptions{
				TenantID: tenantID,
				OrgScope: sharedpolicy.OrgScopePtr(orgID), // #3048 R3 HIGH-3
				// OrgID is the organization a recorded violation's audit row
				// is written under (EvalOptions). OrgScope alone is not
				// enough: it scopes the policy load, not the row.
				OrgID:         orgID,
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
			}
			out.StaticResult = policyEngine.EvaluateResponse(ctx, responseContent, evalOpts)
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
		}
	}

	// #3564: THE ANCHORED ENGINE AUTHORS THIS PASS'S VERDICT (PRD v11 §1.1).
	// enforceMCPResponse replaces the shared engine's result with the anchored
	// engine's, which the one mapping below then applies.
	enforceMCPResponse(ctx, orgID, &out, responseContent, evalOpts)
	if out.StaticResult != nil && applyResponseStaticResult(&out, rows, message) {
		return out
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

// applyResponseStaticResult maps a response pass's static-policy result onto
// the outcome every caller reads, and reports whether the response is withheld.
//
// It is the ONE mapping both engines' results take (#3564): the legacy engine's
// EvaluateResponse result, and the anchored engine's (enforceMCPResponse), which
// produces the same shape. Its body is the block that was inline in
// evaluateOutputPolicies until #3564, MOVED UNCHANGED apart from reporting the
// withhold instead of returning the outcome itself.
func applyResponseStaticResult(out *OutputPolicyOutcome, rows []map[string]interface{}, message string) bool {
	if out.StaticResult.Blocked {
		policyID := "unknown"
		if out.StaticResult.BlockedBy != nil {
			policyID = out.StaticResult.BlockedBy.PolicyID
		}
		log.Printf("[MCP] Response blocked by policy '%s': %s",
			policyID, out.StaticResult.BlockReason)
		return true
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
	return false
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

// mcpInputDecisionVerdict maps the MCP request pass's anchored permit onto the
// canonical audit_logs vocabulary for check-input's and check_policy's terminal
// allow rows (#2627/#2641): the PAST-TENSE policy_decision the portal decisions
// feed keys on - redacted | allowed - not the /decide vocabulary. A redaction is
// its OWN verdict: a masked statement still forwards, but recording it as
// "allowed" hid the mask from the portal (#2641 MCPIN). The ids are the
// controls that determined the verdict, by corpus id, with the names they carry
// (#3365). A refusal writes its own richer row (writeExplainableAuditLog).
func mcpInputDecisionVerdict(enforced requestPassEnforcement, didRedact bool) (verdict string, policyIDs, reasons []string, policyNames map[string]string) {
	policyIDs, policyNames = enforced.evaluatedPolicies, policyIdentityNames(enforced.policyIdentities)
	if didRedact {
		return mcpVerdictRedacted, policyIDs, []string{"request PII redacted"}, policyNames
	}
	return mcpVerdictAllowed, policyIDs, nil, policyNames
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
		sendMCPPassRefusal(w, nil, http.StatusForbidden, "Request blocked: "+reason)
		return
	}

	// THE ANCHORED ENGINE AUTHORS THE REQUEST PASS'S VERDICT (PRD v11 §1.1,
	// mcp_request_enforcing_seam.go). The shared engine's evaluation is its
	// detector input and nothing else. No segment gate stands here any more:
	// the anchored engine reads no segments, as on decide.
	//
	// #2581: per-org posture. orgID is the auth-derived org for this request; an
	// org with no override row keeps the stored policy actions.
	ctx = withMCPRequestSeam(ctx)
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, user.OrgID)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID),
		req.Connector,
		"", // capabilityScopeIdentity: the agent runs the statement, so no tool identity scopes it (#2801)
		statement, req.Parameters,
		mcpDetectionCfg)
	requestEnforced := enforceMCPRequest(ctx, requestPassInput{
		orgID:        client.OrgID,
		decisionID:   auditEntry.DecisionID,
		query:        statement,
		auth:         auth,
		user:         user,
		userIdentity: callerUserIdentity(auth.Kind, userErr, req.UserToken),
		observation:  observationOf(inputOutcome.StaticResult),
	}, pepHandshakeResolution{}) // this route resolves no capability handshake
	if inputOutcome.StaticResult != nil {
		auditEntry.RequestPoliciesEvaluated = inputOutcome.StaticResult.PoliciesEvaluated
	}
	auditEntry.RequestMatchedPolicies = requestEnforced.evaluatedPolicies
	if refuseMCPConnectorRequest(ctx, w, requestEnforced, &auditEntry, startTime, emitDecisionAudit) {
		return
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
	// #3564: the MCP response pass's enforcing seam reads the request's subject
	// off the context and records which engine decided for the response and
	// the audit rows below. This route resolves no capability handshake.
	ctx = withMCPResponseSeam(ctx, auditEntry.DecisionID,
		requestSubject(client.OrgID, auth, user, callerUserIdentity(auth.Kind, userErr, req.UserToken)), pepHandshakeResolution{})
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, auditEntry.OrgID, fmt.Sprintf("%d", user.ID), req.Connector,
		// toolIdentity: agent-executed plane, never capability-scoped (#2801)
		"",
		result.Rows, "", nil, result.RowCount, true,
		// isGateway: managed connector
		false)

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

	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason)
		auditEntry.RowCount = result.RowCount
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response static block
		sendMCPResponseRefusal(ctx, w, fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason))
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
		body := map[string]interface{}{
			"success":      false,
			"blocked":      true,
			"error":        outputOutcome.ExfilResult.BlockReason,
			"limit_type":   outputOutcome.ExfilResult.LimitType,
			"actual_value": outputOutcome.ExfilResult.ActualValue,
			"limit_value":  outputOutcome.ExfilResult.LimitValue,
		}
		mcpResponseSeamFrom(ctx).stamp(body)
		_ = json.NewEncoder(w).Encode(body)
		return
	}

	// Build policy info for response
	policyInfo := sharedpolicy.BuildPolicyInfo(anchoredRequestResult(requestEnforced, inputOutcome.StaticResult), outputOutcome.StaticResult)
	if policyInfo != nil && outputOutcome.ExfilInfo != nil {
		policyInfo.ExfiltrationCheck = outputOutcome.ExfilInfo
	} else if policyInfo == nil && outputOutcome.ExfilInfo != nil {
		policyInfo = &sharedpolicy.PolicyInfo{
			ExfiltrationCheck: outputOutcome.ExfilInfo,
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
	// #3564: which engine authored the response pass's verdict, and for which
	// type of principal.
	mcpResponseSeamFrom(ctx).stamp(response)

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
		sendMCPPassRefusal(w, nil, http.StatusForbidden, "Request blocked: "+reason)
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

	// THE ANCHORED ENGINE AUTHORS THE REQUEST PASS'S VERDICT (PRD v11 §1.1,
	// mcp_request_enforcing_seam.go). The shared engine's evaluation is its
	// detector input and nothing else. No segment gate stands here any more:
	// the anchored engine reads no segments, as on decide.
	//
	// #2581: per-org posture. orgID is the auth-derived org for this request; an
	// org with no override row keeps the stored policy actions.
	ctx = withMCPRequestSeam(ctx)
	mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, user.OrgID)
	inputOutcome := evaluateInputPolicies(ctx,
		user.TenantID, user.OrgID, fmt.Sprintf("%d", user.ID),
		req.Connector,
		"", // capabilityScopeIdentity: the agent runs the statement, so no tool identity scopes it (#2801)
		req.Statement, req.Parameters,
		mcpDetectionCfg)
	requestEnforced := enforceMCPRequest(ctx, requestPassInput{
		orgID:        client.OrgID,
		decisionID:   auditEntry.DecisionID,
		query:        req.Statement,
		auth:         auth,
		user:         user,
		userIdentity: callerUserIdentity(auth.Kind, userErr, req.UserToken),
		observation:  observationOf(inputOutcome.StaticResult),
	}, pepHandshakeResolution{}) // this route resolves no capability handshake
	if inputOutcome.StaticResult != nil {
		auditEntry.RequestPoliciesEvaluated = inputOutcome.StaticResult.PoliciesEvaluated
	}
	auditEntry.RequestMatchedPolicies = requestEnforced.evaluatedPolicies
	if refuseMCPConnectorRequest(ctx, w, requestEnforced, &auditEntry, startTime, emitDecisionAudit) {
		return
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
	// #3564: the MCP response pass's enforcing seam reads the request's subject
	// off the context and records which engine decided for the response and
	// the audit rows below. This route resolves no capability handshake.
	ctx = withMCPResponseSeam(ctx, auditEntry.DecisionID,
		requestSubject(client.OrgID, auth, user, callerUserIdentity(auth.Kind, userErr, req.UserToken)), pepHandshakeResolution{})
	outputOutcome := evaluateOutputPolicies(ctx,
		user.TenantID, auditEntry.OrgID, fmt.Sprintf("%d", user.ID), req.Connector,
		// toolIdentity: agent-executed plane, never capability-scoped (#2801)
		"",
		nil, result.Message, result.Metadata, int(result.RowsAffected), false,
		// isGateway: managed connector
		false)

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

	if outputOutcome.StaticResult != nil && outputOutcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason)
		auditEntry.RowCount = int(result.RowsAffected)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		emitDecisionAudit(outVerdict, outPolicyIDs, outReasons, nil, outPolicyNames) // #2679: response static block
		sendMCPResponseRefusal(ctx, w, fmt.Sprintf("Response blocked: %s", outputOutcome.StaticResult.BlockReason))
		return
	}

	// Build policy info for response
	policyInfo := sharedpolicy.BuildPolicyInfo(anchoredRequestResult(requestEnforced, inputOutcome.StaticResult), outputOutcome.StaticResult)

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
	// #3564: which engine authored the response pass's verdict, and for which
	// type of principal.
	mcpResponseSeamFrom(ctx).stamp(response)
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
	// Engine, SubjectType and PolicyBundle say which policy engine authored the
	// verdict, the type of the principal it was evaluated for and the digest of
	// the policy set that decided it (PRD v11 §1.4, §1.6).
	Engine       string `json:"engine,omitempty"`
	SubjectType  string `json:"subject_type,omitempty"`
	PolicyBundle string `json:"policy_bundle,omitempty"`
	// PolicyPacks names the add-on policy packs whose controls composed into
	// PolicyBundle on this pass, each as <pack id>@<pack document digest> (PRD
	// v11 §1.9, #4196); omitted when none binds.
	PolicyPacks []string `json:"policy_packs,omitempty"`
	// LegacyValidators names a checksum validator that acted on the statement
	// before the anchored engine decided it (#4122).
	LegacyValidators []LegacyValidatorAction `json:"legacy_validators,omitempty"`
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

	// Engine, SubjectType and PolicyBundle say which policy engine authored the
	// response pass's verdict, the type of the principal it was evaluated for
	// and the digest of the policy set that decided it (#3564, PRD v11 §1.4,
	// §1.6). All three are omitted on a body written before the pass ran.
	Engine       string `json:"engine,omitempty"`
	SubjectType  string `json:"subject_type,omitempty"`
	PolicyBundle string `json:"policy_bundle,omitempty"`
	// PolicyPacks names the add-on policy packs whose controls composed into
	// PolicyBundle on the response pass, as `<pack id>@<digest>`, sorted
	// (#4196, PRD v11 §1.9); omitted when none binds.
	PolicyPacks []string `json:"policy_packs,omitempty"`
	// LegacyValidators names a checksum validator that acted before the
	// anchored engine decided (#4122); omitted when none did.
	LegacyValidators []LegacyValidatorAction `json:"legacy_validators,omitempty"`
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

	// #3766: the ADR-065 capability handshake on the MCP plane.
	//
	// Resolved immediately after the authenticated identity is captured, which
	// is #3704 §4.5's primary rule. It is NOT resolved before the body decode
	// the way the decide plane does it, and that divergence is forced rather
	// than chosen: this plane authenticates from hints carried IN THE BODY, so
	// the client identity the declaration binds to does not exist until the
	// decode has run. See resolveMCPPEPHandshake for the denominator skew that
	// costs and why it is in the safe direction.
	//
	// A caller that presents NO handshake resolves to `absent`, refuses
	// nothing, and takes byte-for-byte the path it took before this existed.
	//
	// Bound to auth.ClientID, the CANONICAL client identity Authenticate
	// derived from the credentials - never req.ClientID, which is a
	// caller-supplied hint. Composing the enforcement point's identifier from a
	// value the caller chooses would put the namespace back under the caller's
	// control, which is the whole point of §4.2's server-owned prefix.
	ctx, pepHandshake := resolveMCPPEPHandshake(r.Context(), r, auth.ClientID)
	r = r.WithContext(ctx)
	if pepHandshake.refused {
		// The request was never evaluated, so this is an HTTP error rather than
		// a policy deny. Reporting an unevaluated request as a policy denial
		// would put a client-side defect into the compliance record as a policy
		// outcome - the same reasoning, and the same split, as the decide
		// plane's malformed-handshake path.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			auth.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_input", "mcp check-input: "+req.ConnectorType, "",
			mcpVerdictBlocked,
			[]string{pepHandshake.reason},
			[]string{pepHandshake.reason + ": " + pepHandshake.detail},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,
			time.Since(startTime).Milliseconds(),
			req.ConnectorType, req.Tool)
		sendErrorResponse(w, pepHandshake.reason+": "+pepHandshake.detail, pepHandshake.status, nil)
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
	if !canRedactRequestContentType(req.ContentType) {
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

	// Per-caller identity for audit attribution. #2896: the client-asserted
	// X-User-Email is honored ONLY under the AXONFLOW_TRUST_IDENTITY_HEADERS
	// opt-in — it was previously read unconditionally here, which let any
	// governed caller forge another principal's audit identity. With the gate
	// off (default) attribution falls back to the validated identity. Resolved
	// before the missing-tenant early deny so that row attributes consistently
	// with the decide plane's early denies.
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
	// The idempotency cache key is (org, tenant, Idempotency-Key, endpoint), and
	// Wrap replays a hit WITHOUT invoking the handler. The anchored engine
	// decides for the admitted principal (a published document can constrain
	// one user and not another), so a key with no principal in it would replay
	// one caller's cached allow to another, on a key the caller chooses; a
	// cached 403 would replay the same way.
	//
	// So the principal is folded into the endpoint discriminator: a different
	// subject is a different cache row, and a genuine retry by the same caller
	// still dedups. It is the caller's VALIDATED identity, the principal the
	// engine decides for; keying on anything the caller can assert would
	// reintroduce the replay through the other door. Hashed, so the
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
		// → writeDecisionAuditLog); plane=mcp. Called from the terminal clean-allow
		// branch only: a refusal writes its own richer canonical row
		// (writeExplainableAuditLog) and a redaction its own verdict
		// (writeMCPDecisionAudit), and routing either here would double-write a
		// second audit_logs row under the same decision_id. audit_logs is deliberately not FORCE-RLS (mig
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

		// THE ANCHORED ENGINE AUTHORS THE REQUEST PASS'S VERDICT (PRD v11 §1.1,
		// mcp_request_enforcing_seam.go). No segment gate stands here any more:
		// the anchored engine reads no segments, as on decide.
		//
		// v9 Phase 8 #2384 PR-C1: orgID plumbed through. #2581: per-org posture;
		// an org with no override row keeps the stored policy actions.
		ctx = withMCPRequestSeam(ctx)
		seam := mcpRequestSeamFrom(ctx)
		mcpDetectionCfg := ResolveMCPDetectionConfig(ctx, orgID)
		// The Indonesia checksum validator acts BEFORE the pass, named (#4122).
		evaluated := maskIndonesiaBeforeTheRequestPass(ctx, orgID, tenantID, decisionID, req.Statement, mcpDetectionCfg)
		outcome := evaluateInputPolicies(ctx,
			tenantID, orgID, userID,
			req.ConnectorType,
			// The caller runs the tool and reports its own name, which is the
			// premise capability scoping rests on (#2801, #2904, #3717).
			req.Tool,
			evaluated, req.Parameters,
			mcpDetectionCfg)
		observation := observationOf(outcome.StaticResult)
		enforced := enforceMCPRequest(ctx, requestPassInput{
			orgID:        orgID,
			decisionID:   decisionID,
			query:        evaluated,
			auth:         auth,
			user:         user,
			userIdentity: callerUserIdentity(auth.Kind, userErr, req.UserToken),
			observation:  observation,
		}, pepHandshake)
		projected := projectMCPStatement(ctx, orgID, enforced, pepHandshake, req.Statement, evaluated, outcome.Options, observation)
		policiesEvaluated := 0
		if outcome.StaticResult != nil {
			auditEntry.RequestPoliciesEvaluated = outcome.StaticResult.PoliciesEvaluated
			policiesEvaluated = outcome.StaticResult.PoliciesEvaluated
		}
		auditEntry.RequestMatchedPolicies = enforced.evaluatedPolicies
		descriptor := fmt.Sprintf("mcp check-input: %s", req.ConnectorType)
		traceID := traceIDFromHeader(r.Header.Get("traceparent"))

		if projected.unavailable != "" {
			// FAIL CLOSED (PRD v11 §1.7): nothing decides a request the engine
			// could not decide. The canonical "error" row keeps the unevaluated
			// attempt portal-visible under the same decision_id (#2641).
			recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, "unavailable", projected.unavailable)
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", descriptor, "",
				mcpVerdictError,
				[]string{"decision_enforcement_unavailable"},
				[]string{projected.unavailable},
				nil,
				traceID,
				nil,                                  // #3365: guard ids resolve via the builtin table
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			sendMCPPassRefusal(w, seam, http.StatusServiceUnavailable, enforceCauseMessages[projected.unavailable])
			return
		}

		engine, subjectType, policyBundle := seam.wireFields()
		legacyValidators := seam.legacyValidatorsActed()
		if !projected.allowed {
			recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, VerdictDeny, projected.reasonCode)
			matches := anchoredPolicyMatches(enforced)
			auditEntry.RequestBlocked = true
			auditEntry.RequestBlockReason = projected.blockReason
			auditEntry.DurationMs = time.Since(startTime).Milliseconds()
			logMCPQueryAudit(auditEntry)
			// Dual-write to audit_logs so explainDecision(id) resolves this
			// decision. The query column carries a NON-PII descriptor, never the
			// raw statement; the statement hash keeps it correlatable (#2641).
			writeExplainableAuditLog(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", descriptor, auditEntry.StatementHash,
				projected.blockReason, "", matches,
				traceID,                              // #2598 correlation
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(MCPCheckInputResponse{
				Allowed:           false,
				BlockReason:       projected.blockReason,
				PoliciesEvaluated: policiesEvaluated,
				DecisionID:        decisionID,
				PolicyMatches:     matches,
				Engine:            engine,
				SubjectType:       subjectType,
				PolicyBundle:      policyBundle,
				PolicyPacks:       seam.packsRecorded(),
				LegacyValidators:  legacyValidators,
			})
			return
		}

		recordAnchoredEnforcement(mcpRequestSeamScope, enforced.engine, VerdictAllow, projected.reasonCode)
		if projected.redacted {
			// The masked unit on this surface IS the single statement, so the
			// satellite records count=1 and the coarse "statement" descriptor
			// (#2641 sibling finding #3).
			auditEntry.ResponseRedacted = true
			auditEntry.ResponseRedactionsCount = 1
			auditEntry.ResponseRedactedFields = []string{"statement"}
		}
		auditEntry.Success = true
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		// #2627/#2641: the terminal allow (clean or redacted) writes the canonical
		// audit_logs row keyed by the same decision_id. A redaction is its OWN
		// verdict ("redacted") and must carry redacted_fields, so it goes through
		// the MCP canonical writer; a clean allow keeps the /decide writer.
		v, pids, reasons, pnames := mcpInputDecisionVerdict(enforced, projected.redacted)
		if v == mcpVerdictRedacted {
			writeMCPDecisionAudit(ctx, usageDB,
				decisionID, auditEntry.AuditID,
				tenantID, orgID, auth.Client.ID, userEmail,
				userID, userRole,
				"mcp_check_input", descriptor, computeStatementHash(descriptor),
				mcpVerdictRedacted, pids, reasons, auditEntry.ResponseRedactedFields,
				traceID,
				pnames,                               // #3365
				time.Since(startTime).Milliseconds(), // #3424: agent-local check-input evaluation, no downstream hop
				req.ConnectorType, req.Tool)          // #2904: tool_server, tool_name
		} else {
			emitInputDecision(v, pids, reasons, pnames)
		}

		resp := MCPCheckInputResponse{
			Allowed:           true,
			PoliciesEvaluated: policiesEvaluated,
			PolicyInfo:        sharedpolicy.BuildPolicyInfo(anchoredRequestResult(enforced, outcome.StaticResult), nil),
			// Plugin Batch 1: every governance decision surfaces decision_id.
			DecisionID: decisionID,
			// The anchored decision ran and its redaction, if any, was discharged
			// above, so a PEP fulfilling a redact_pii obligation may forward what
			// it is handed (#2563 B1).
			RedactionEvaluated: true,
			Engine:             engine,
			SubjectType:        subjectType,
			PolicyBundle:       policyBundle,
			PolicyPacks:        seam.packsRecorded(),
			LegacyValidators:   legacyValidators,
		}
		if projected.redacted {
			resp.Redacted = true
			resp.RedactedStatement = projected.statement
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

	// #3766: the ADR-065 capability handshake on the MCP response plane.
	// Resolved immediately after the authenticated identity is captured and
	// bound to the CANONICAL auth.ClientID, never the caller-supplied
	// req.ClientID. See resolveMCPPEPHandshake.
	pepCtx, pepHandshake := resolveMCPPEPHandshake(r.Context(), r, auth.ClientID)
	r = r.WithContext(pepCtx)
	if pepHandshake.refused {
		// Never evaluated, so an HTTP error rather than a policy deny - the
		// same split the decide plane makes, so a client-side defect does not
		// enter the compliance record as a policy outcome.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			auth.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_output", "mcp check-output: "+req.ConnectorType, "",
			mcpVerdictBlocked,
			[]string{pepHandshake.reason},
			[]string{pepHandshake.reason + ": " + pepHandshake.detail},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,
			time.Since(startTime).Milliseconds(),
			req.ConnectorType, req.Tool)
		sendErrorResponse(w, pepHandshake.reason+": "+pepHandshake.detail, pepHandshake.status, nil)
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

	// REST check-output: no segment gate stands here any more. It resolved the caller's
	// governance segments and refused the request when that failed, on behalf
	// of an organization's segment-scoped static rows, and those rows no longer
	// decide: the anchored engine authors this verdict and reads no segments
	// (PRD v11 §1.1, §1.2). So the shared engine's detector pass runs with no
	// segment set, and a segment resolution that would fail changes nothing.

	// #3564: the MCP response pass's enforcing seam reads the request's subject
	// and the admitted handshake off the context, and records which engine
	// decided for the response body and the audit rows below.
	ctx = withMCPResponseSeam(ctx, decisionID,
		requestSubject(orgID, auth, user, callerUserIdentity(auth.Kind, userErr, req.UserToken)),
		pepHandshake)
	outcome := evaluateOutputPolicies(ctx,
		tenantID, orgID, userID, req.ConnectorType,
		// toolIdentity: advisory plane, caller-sent tool identity (#2801, #2904,
		// #2955) - distinct from ConnectorType/server; empty means full
		// (fail-closed) evaluation, no fallback
		req.Tool,
		req.ResponseData, req.Message, req.Metadata, req.RowCount, checkExfiltration,
		// isGateway: check-output is a PEP/gateway caller
		true)

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
				// #3365, PRD v11 §1.14: the display names of the ids this row
				// records, as the redacted branch above already stamps them.
				policyNames: outPolicyNames,
				// #2598: correlate this response-plane decision with the request-plane
				// check-input (and any /decide stage) of the SAME logical tool call when
				// the proxy/gateway propagates a W3C traceparent across the hops. Absent
				// header → "" → singleton, preserving the chronological-only behavior.
				correlationID: traceIDFromHeader(r.Header.Get("traceparent")),
				toolServer:    req.ConnectorType, // #2955: tool_server (server axis)
				toolName:      req.Tool,          // #2955: tool_name (sub-tool axis)
			})
	}

	// #3564: engine and subject type ride every body written after the
	// response pass.
	engine, subjectType, policyBundle := mcpResponseSeamFrom(ctx).wireFields()
	legacyValidators := mcpResponseSeamFrom(ctx).legacyValidatorsActed()
	policyPacks := mcpResponseSeamFrom(ctx).packsRecorded()

	if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = fmt.Sprintf("Response blocked: %s", outcome.StaticResult.BlockReason)
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:          false,
			BlockReason:      fmt.Sprintf("Response blocked: %s", outcome.StaticResult.BlockReason),
			DecisionID:       decisionID,
			Engine:           engine,
			SubjectType:      subjectType,
			PolicyBundle:     policyBundle,
			PolicyPacks:      policyPacks,
			LegacyValidators: legacyValidators,
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
			Engine:           engine,
			SubjectType:      subjectType,
			PolicyBundle:     policyBundle,
			PolicyPacks:      policyPacks,
			LegacyValidators: legacyValidators,
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

	// #3766 / ADR-065 invariant 8: an enforcement point that DECLARED it cannot
	// discharge field_redact must not be handed redacted_data and trusted to
	// forward it in place of the original response.
	//
	// The gate is `redactedData != nil` - the response plane's exact analogue
	// of check-input's didRedact - so a caller that declares no redaction
	// capability keeps using this plane freely for output that needed none.
	// Placed BEFORE the encode, because handing over the content and then
	// reporting a refusal would leak what the refusal exists to withhold.
	if reason, denied := applyMCPRedactionRefusal(pepHandshake, redactedData != nil); denied {
		log.Printf("[pep-handshake] check-output denied on plane %s: the advertising enforcement point cannot discharge the inline redaction (decision_id=%s)",
			PlaneMCP, decisionID)
		auditEntry.RequestBlocked = true
		auditEntry.RequestBlockReason = reason
		auditEntry.DurationMs = time.Since(startTime).Milliseconds()
		logMCPQueryAudit(auditEntry)
		descriptor := fmt.Sprintf("mcp check-output: %s", req.ConnectorType)
		// ctx, not r.Context(): it carries the response pass's enforcement
		// record, which this row writes like every other row after the pass.
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, auditEntry.AuditID,
			auth.TenantID, auth.OrgID, auth.ClientID, "",
			"", "service",
			"mcp_check_output", descriptor, computeStatementHash(descriptor),
			mcpVerdictBlocked,
			[]string{pepCapabilityUnsupportedCode},
			[]string{reason},
			nil,
			traceIDFromHeader(r.Header.Get("traceparent")),
			nil,
			time.Since(startTime).Milliseconds(),
			req.ConnectorType, req.Tool)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(MCPCheckOutputResponse{
			Allowed:          false,
			BlockReason:      reason,
			DecisionID:       decisionID,
			Engine:           engine,
			SubjectType:      subjectType,
			PolicyBundle:     policyBundle,
			PolicyPacks:      policyPacks,
			LegacyValidators: legacyValidators,
			// RedactedData is deliberately ABSENT.
		})
		return
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
		Engine:             engine,
		SubjectType:        subjectType,
		PolicyBundle:       policyBundle,
		PolicyPacks:        policyPacks,
		LegacyValidators:   legacyValidators,
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
