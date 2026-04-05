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

// Build trigger: Test AWS OIDC authentication for GitHub Actions

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/marketplace"
	"axonflow/platform/agent/node_enforcement"
	"axonflow/platform/common/usage"
	"axonflow/platform/orchestrator/cost"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
)

// AxonFlow Agent - Authentication, Authorization & Static Policy Enforcement Gateway
// This service sits between clients and the AxonFlow Orchestrator

// isCommunityMode returns true if running in Community mode.
// Community mode bypasses license validation and authentication for local development.
// Pattern: DEPLOYMENT_MODE == "community" || DEPLOYMENT_MODE == "" (unset)
// This is the canonical way to check for Community mode across the codebase.
func isCommunityMode() bool {
	mode := os.Getenv("DEPLOYMENT_MODE")
	return mode == "community" || mode == ""
}

// getDeploymentOrgID returns the canonical deployment org_id from the ORG_ID env var.
// This is the single source of truth for org identity — set at deployment time in
// docker-compose or platform config. License org_id must match this value.
// Defaults to "local-dev-org" if not set — matches docker-compose.yml default.
// This default MUST NOT change across versions — existing installs rely on the
// implicit value for data continuity via the RLS org_id column.
func getDeploymentOrgID() string {
	orgID := os.Getenv("ORG_ID")
	if orgID == "" {
		return "local-dev-org"
	}
	return orgID
}

// Internal service URLs - auto-discovered based on environment (ADR-026: Single Entry Point)
// Docker Compose services communicate via service names on the axonflow-network.
// No configuration required - the Agent detects Docker and uses appropriate URLs.
const (
	// DefaultOrchestratorURL is the internal URL for the Orchestrator service in Docker
	DefaultOrchestratorURL = "http://axonflow-orchestrator:8081"

	// DefaultPortalURL is the internal URL for the Customer Portal service in Docker
	// Service name: axonflow-customer-portal, internal port: 8080 (mapped to 8082 externally)
	DefaultPortalURL = "http://axonflow-customer-portal:8080"

	// LocalOrchestratorURL is used for local development without Docker
	LocalOrchestratorURL = "http://localhost:8081"

	// LocalPortalURL is used for local development without Docker
	LocalPortalURL = "http://localhost:8082"
)

// Configuration
var (
	jwtSecret              = []byte(os.Getenv("JWT_SECRET"))
	orchestratorURL        = getOrchestratorURL() // Auto-discovered based on environment
	authDB                 *sql.DB                // Database for Option 3 authentication
	usageDB                *sql.DB // Database for usage metering
	tierAwarePolicyEngine  *TierAwarePolicyEngine // Tier-aware policy engine for tenant-specific policies
	meteringService           *marketplace.MeteringService // AWS Marketplace metering
	costService               *cost.Service // Cost tracking and budget enforcement (Issue #1082)
	circuitBreakerInstance    *circuitbreaker.CircuitBreaker // Circuit breaker for auto-trip on error/violation thresholds (#1176)
)

// proxyPolicyCategories is the set of policy categories evaluated for proxy requests.
// Used by both clientRequestHandler and policyTestHandler to avoid divergence.
var proxyPolicyCategories = []sharedpolicy.PolicyCategory{
	sharedpolicy.CategorySecuritySQLi,
	sharedpolicy.CategorySecurityDangerous,
	sharedpolicy.CategoryAdminAccess,
	sharedpolicy.CategoryPIIGlobal,
	sharedpolicy.CategoryPIIUS,
	sharedpolicy.CategoryPIIIndia,
	sharedpolicy.CategoryPIIEU,
	sharedpolicy.CategoryPIISingapore,
	sharedpolicy.CategorySensitiveData,
	sharedpolicy.CategoryComplianceRBI,
	sharedpolicy.CategoryComplianceSEBI,
	sharedpolicy.CategoryComplianceEUAIAct,
	sharedpolicy.CategoryComplianceMASFEAT,
}

// Prometheus metrics
var (
	promRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_agent_requests_total",
			Help: "Total number of requests processed by the agent",
		},
		[]string{"status"},
	)
	promRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_agent_request_duration_milliseconds",
			Help:    "Request duration in milliseconds",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
		[]string{"type"},
	)
	promPolicyEvaluations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_agent_policy_evaluations_total",
			Help: "Total number of policy evaluations",
		},
	)
	promBlockedRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_agent_blocked_requests_total",
			Help: "Total number of blocked requests",
		},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(promRequestsTotal)
	prometheus.MustRegister(promRequestDuration)
	prometheus.MustRegister(promPolicyEvaluations)
	prometheus.MustRegister(promBlockedRequests)
}

// AgentMetrics tracks real performance metrics
type AgentMetrics struct {
	mu sync.RWMutex

	// Request counters
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	blockedRequests int64

	// Latency tracking (in nanoseconds)
	latencies     []int64
	lastLatencies []int64 // Keep last 1000 for P99 calculation

	// Throughput
	startTime     time.Time
	lastResetTime time.Time

	// Policy evaluation metrics (end-to-end by policy type)
	staticPolicyLatencies  []int64
	dynamicPolicyLatencies []int64

	// Per-stage timing metrics (in milliseconds)
	authTimings         []int64 // Client + user validation + tenant check
	staticPolicyTimings []int64 // Static policy evaluation only
	networkTimings      []int64 // Agent → Orchestrator network time

	// Request type breakdown (for detailed analysis)
	requestTypeCounters map[string]*RequestTypeMetrics

	// Connector-specific metrics
	connectorMetrics map[string]*ConnectorMetrics

	// Error tracking for error rate calculation
	errorTimestamps []time.Time // Track recent error timestamps for rate calculation

	// Health status tracking
	healthCheckPassed bool
	consecutiveErrors int64
}

// RequestTypeMetrics tracks metrics per request type (sql, llm_chat, rag_search, mcp-query)
type RequestTypeMetrics struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	BlockedRequests int64
	Latencies       []int64 // Last 1000 latencies in ms
}

// ConnectorMetrics tracks metrics per MCP connector
type ConnectorMetrics struct {
	ConnectorName   string
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	Latencies       []int64 // Last 1000 latencies in ms
	LastError       string
	LastErrorTime   time.Time
}

// Global metrics instance
var agentMetrics *AgentMetrics

// Client request structures
type ClientRequest struct {
	Query       string                 `json:"query"`
	UserToken   string                 `json:"user_token"`
	ClientID    string                 `json:"client_id"`
	RequestType string                 `json:"request_type"`       // "sql", "llm_chat", "rag_search"
	SkipLLM     bool                   `json:"skip_llm,omitempty"` // Skip LLM calls for hourly tests
	Context     map[string]interface{} `json:"context"`
	PlanID      string                 `json:"plan_id,omitempty"`  // For execute-plan requests
	Media       []MediaContentRequest  `json:"media,omitempty"`    // Optional media (images) for multimodal governance
}

// MediaContentRequest represents a media item in the client API request.
type MediaContentRequest struct {
	Source     string `json:"source"`               // "base64" or "url"
	Base64Data string `json:"base64_data,omitempty"` // Base64-encoded image data
	URL        string `json:"url,omitempty"`         // Image URL
	MIMEType   string `json:"mime_type"`             // e.g., "image/jpeg"
}

type ClientResponse struct {
	Success        bool                   `json:"success"`
	Data           interface{}            `json:"data,omitempty"`
	Result         string                 `json:"result,omitempty"`          // For multi-agent planning - MUST match SDK type
	PlanID         string                 `json:"plan_id,omitempty"`         // For multi-agent planning
	Steps          []interface{}          `json:"steps,omitempty"`           // For multi-agent planning - workflow steps
	Metadata       map[string]interface{} `json:"metadata,omitempty"`        // For multi-agent planning - MUST match SDK type
	Error          string                 `json:"error,omitempty"`
	Blocked        bool                   `json:"blocked"`
	BlockReason    string                 `json:"block_reason,omitempty"`
	PolicyInfo     *PolicyEvaluationInfo  `json:"policy_info,omitempty"`
	BudgetInfo     *BudgetInfo            `json:"budget_info,omitempty"`     // Issue #1082: Budget enforcement status
	MediaAnalysis  interface{}            `json:"media_analysis,omitempty"`  // Media governance analysis results
}

type PolicyEvaluationInfo struct {
	PoliciesEvaluated []string `json:"policies_evaluated"`
	StaticChecks      []string `json:"static_checks"`
	ProcessingTime    string   `json:"processing_time"`
	TenantID          string   `json:"tenant_id"`
	// CodeArtifact contains metadata about detected code in LLM responses
	// Part of Issue #761: Governed Code Generation
	CodeArtifact *CodeArtifactMetadata `json:"code_artifact,omitempty"`
}

// User represents authenticated user information
type User struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Department  string   `json:"department"`
	Role        string   `json:"role"`
	Region      string   `json:"region"`
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"tenant_id"`
}

// recordLatency adds a latency measurement to the appropriate buckets
func (m *AgentMetrics) recordLatency(latencyMs int64, policyType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to general latencies (for overall P99 calculation)
	m.latencies = append(m.latencies, latencyMs)

	// Keep only last 1000 entries for P99 calculation
	if len(m.lastLatencies) >= 1000 {
		m.lastLatencies = m.lastLatencies[1:]
	}
	m.lastLatencies = append(m.lastLatencies, latencyMs)

	// Add to policy-type specific latencies
	switch policyType {
	case "static":
		if len(m.staticPolicyLatencies) >= 1000 {
			m.staticPolicyLatencies = m.staticPolicyLatencies[1:]
		}
		m.staticPolicyLatencies = append(m.staticPolicyLatencies, latencyMs)
	case "dynamic":
		if len(m.dynamicPolicyLatencies) >= 1000 {
			m.dynamicPolicyLatencies = m.dynamicPolicyLatencies[1:]
		}
		m.dynamicPolicyLatencies = append(m.dynamicPolicyLatencies, latencyMs)
	}
}

// Client represents an authenticated client.
// ID and TenantID come from the Basic auth clientId (tenant identity for data isolation).
// OrgID comes from the license validation (org entitlement scope).
type Client struct {
	ID            string    `json:"id"`        // Client identifier (from Basic auth username)
	Name          string    `json:"name"`
	OrgID         string    `json:"org_id"`    // Organization ID from license (entitlement scope)
	TenantID      string    `json:"tenant_id"` // Tenant ID for data isolation (from Basic auth clientId)
	Permissions   []string  `json:"permissions"`
	RateLimit     int       `json:"rate_limit"`
	Enabled       bool      `json:"enabled"`
	LicenseTier   string    `json:"license_tier,omitempty"`
	LicenseExpiry time.Time `json:"license_expiry,omitempty"`
	APIKeyID      string    `json:"api_key_id,omitempty"`   // For Option 3 usage tracking
	ServiceName   string    `json:"service_name,omitempty"` // For V2 service licenses
}

// substituteGrafanaPassword substitutes {{GRAFANA_PASSWORD}} in SQL.
// Returns empty string if migration should be skipped (Grafana not deployed).
func substituteGrafanaPassword(sqlContent string) (string, error) {
	if !strings.Contains(sqlContent, "{{GRAFANA_PASSWORD}}") {
		return sqlContent, nil
	}
	password := os.Getenv("GRAFANA_PASSWORD")
	if password == "" || password == "not-deployed" {
		return "", nil // skip migration
	}
	if len(password) < 16 {
		return "", fmt.Errorf("GRAFANA_PASSWORD too short (%d chars, need 16+)", len(password))
	}
	return strings.ReplaceAll(sqlContent, "{{GRAFANA_PASSWORD}}", password), nil
}

// Application readiness state for health checks
// This allows the health endpoint to respond immediately while initialization happens
var appReady atomic.Bool

// Global router and server - allows health checks to pass immediately while initialization happens
var (
	globalRouter *mux.Router
	globalCORS   *cors.Cors
)

// initServerImmediately starts the HTTP server immediately with just /health endpoint.
// This allows ECS/ALB health checks to pass during the potentially slow initialization
// phase (database connections, migrations, Redis, etc.). Other routes are added
// after initialization completes. The server NEVER shuts down - eliminating any
// transition gaps that could cause health check failures.
func initServerImmediately(port string) {
	globalRouter = mux.NewRouter()

	// CORS middleware - configured once, used for all requests
	globalCORS = cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Configure for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Register health check immediately - responds even during initialization
	globalRouter.HandleFunc("/health", readinessAwareHealthHandler).Methods("GET")

	// Start server immediately in goroutine - health checks will pass right away
	go func() {
		handler := globalCORS.Handler(globalRouter)
		log.Printf("🚀 AxonFlow Agent starting on port %s (status: starting)", port)
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Small delay to ensure server is ready to accept connections
	time.Sleep(50 * time.Millisecond)
	log.Println("✅ Health endpoint ready - initialization can proceed safely")
}

// readinessAwareHealthHandler returns health status based on initialization state
func readinessAwareHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := "starting"
	if appReady.Load() {
		status = "healthy"
	}
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             status,
		"service":            "axonflow-agent",
		"timestamp":          time.Now().UTC(),
		"version":            GetPlatformVersion(),
		"capabilities":       getCapabilities(),
		"sdk_compatibility":  getSDKCompatibility(),
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// Run is the exported entry point for the agent service.
//
// Testing Note: This function is currently at 0% test coverage because it:
// 1. Calls log.Fatal() which exits the process (untestable)
// 2. Calls http.ListenAndServe() which blocks forever (untestable)
// 3. Has hard-coded dependencies (env vars, file paths, network calls)
// 4. Performs 10+ different operations (license, migrations, DB, Redis, HTTP server)
//
// To make this testable, it should be refactored to:
// - Extract initialization logic into NewApp(config) (*App, error)
// - Extract server logic into app.Run() error
// - Use dependency injection for all external dependencies
// - Return errors instead of calling log.Fatal()
//
// Refactoring planned for Phase 5 (Open Source Preparation).
// Current architecture is functional but not ideal for testing.
func Run() {
	// Start server IMMEDIATELY with /health endpoint so ECS/ALB health checks pass
	// during initialization. Other routes are added after initialization completes.
	// The server NEVER shuts down - eliminating transition gaps.
	port := getEnv("PORT", "8080")
	initServerImmediately(port)

	// License validation (optional for central agent deployments and community mode)
	// Central agents validate CLIENT license keys during request processing
	// Community mode skips license validation entirely (for local development)
	// This validation is only needed for customer-deployed agents
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")

	if isCommunityMode() {
		log.Println("🏠 Community mode - skipping license validation")
		log.Println("   Perfect for Community contributors and local development")
	} else if licenseKey == "" {
		log.Println("⚠️  AXONFLOW_LICENSE_KEY not set - running in central agent mode")
		log.Println("   Central agents validate client license keys during request processing")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := license.ValidateWithRetry(ctx, licenseKey, 3)
		if err != nil {
			log.Fatalf("License validation failed: %v", err)
		}

		if !result.Valid {
			log.Fatalf("Invalid license: %s (error: %s)", result.Message, result.Error)
		}

		// Validate license org_id matches deployment ORG_ID.
		// ORG_ID is the canonical deployment identity (set in docker-compose/env).
		// License org_id must match — mismatch means data will split across orgs.
		deploymentOrgID := getDeploymentOrgID()
		if result.OrgID != "" && result.OrgID != deploymentOrgID {
			log.Fatalf("❌ License org_id mismatch: license has org_id=%q but deployment ORG_ID=%q. "+
				"These must match or data will be split across organizations. "+
				"Either update ORG_ID in your docker-compose/env to match the license, "+
				"or request a new license with org_id=%q.",
				result.OrgID, deploymentOrgID, deploymentOrgID)
		}

		log.Printf("✅ License validated successfully")
		log.Printf("   Tier: %s", result.Tier)
		log.Printf("   Org: %s", deploymentOrgID)
		log.Printf("   Max Nodes: %d", result.MaxNodes)
		log.Printf("   Expires: %s", result.ExpiresAt.Format("2006-01-02"))

		if result.DaysUntilExpiry <= 3 && result.DaysUntilExpiry > 0 {
			log.Printf("   ⚠️  LICENSE EXPIRING IN %d DAYS — renew at https://getaxonflow.com/evaluation-license", result.DaysUntilExpiry)
		} else if result.DaysUntilExpiry <= 30 {
			log.Printf("   ⚠️  License expires in %d days - contact sales for renewal", result.DaysUntilExpiry)
		}
	}

	// Initialize metrics with all tracking structures
	agentMetrics = &AgentMetrics{
		lastLatencies:          make([]int64, 0, 1000),
		staticPolicyLatencies:  make([]int64, 0, 1000),
		dynamicPolicyLatencies: make([]int64, 0, 1000),
		authTimings:            make([]int64, 0, 1000),
		staticPolicyTimings:    make([]int64, 0, 1000),
		networkTimings:         make([]int64, 0, 1000),
		requestTypeCounters:    make(map[string]*RequestTypeMetrics),
		connectorMetrics:       make(map[string]*ConnectorMetrics),
		errorTimestamps:        make([]time.Time, 0, 1000),
		startTime:              time.Now(),
		lastResetTime:          time.Now(),
		healthCheckPassed:      true,
	}
	// Note: mu (sync.RWMutex) is automatically initialized to zero value (unlocked state)

	// Run database migrations first (Principle 11: Proper setup before operations)
	// Build connection string from separate env vars (12-Factor App methodology)
	// URI format requires URL encoding for password with special characters
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort := os.Getenv("DATABASE_PORT")
	dbName := os.Getenv("DATABASE_NAME")
	dbUser := os.Getenv("DATABASE_USER")
	dbPassword := os.Getenv("DATABASE_PASSWORD")
	dbSSLMode := os.Getenv("DATABASE_SSLMODE")

	// Fallback: Support legacy DATABASE_URL for backward compatibility
	dbURL := os.Getenv("DATABASE_URL")
	if dbHost != "" && dbPassword != "" {
		// Build connection string with URL-encoded password for URI format
		if dbPort == "" {
			dbPort = "5432"
		}
		if dbName == "" {
			dbName = "axonflow"
		}
		if dbUser == "" {
			dbUser = "axonflow_app"
		}
		if dbSSLMode == "" {
			dbSSLMode = "require"
		}
		// URL-encode password to handle special characters in URI format
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			url.QueryEscape(dbUser), url.QueryEscape(dbPassword), dbHost, dbPort, dbName, dbSSLMode)
		log.Println("✅ Built database connection string from separate env vars (12-Factor App)")
	}

	if dbURL != "" {

		log.Println("Running database migrations...")
		migrationsPath := "/app/migrations/"

		// Multi-path migration collection (ADR-012)
		// Collects migrations from core/, enterprise/, industry/* based on DEPLOYMENT_MODE
		migrations, err := collectMigrations(migrationsPath)
		if err != nil {
			log.Printf("⚠️  Failed to collect migration files: %v (continuing anyway)", err)
		} else if len(migrations) == 0 {
			log.Println("ℹ️  No migration files found")
		} else {
			// Validate migration dependencies before running
			if err := validateMigrationDependencies(migrations); err != nil {
				log.Fatalf("❌ Migration dependency validation failed: %v", err)
			}

			// Connect to database for migrations with retry logic
			// Retry is needed because Docker DNS (127.0.0.11:53) takes a few seconds to initialize
			// after container startup. Without retry, RDS hostname resolution fails immediately.
			maxRetries := 5
			var migrationDB *sql.DB
			var err error

			for attempt := 1; attempt <= maxRetries; attempt++ {
				migrationDB, err = sql.Open("postgres", dbURL)
				if err == nil {
					// Test connection with ping
					err = migrationDB.Ping()
					if err == nil {
						log.Printf("✅ Connected to database for migrations (attempt %d/%d)", attempt, maxRetries)
						break
					}
				}

				// Connection or ping failed
				if attempt < maxRetries {
					backoff := time.Duration(attempt*2) * time.Second
					log.Printf("⚠️  Database connection failed (attempt %d/%d): %v", attempt, maxRetries, err)
					log.Printf("   Retrying in %v... (Docker DNS may still be initializing)", backoff)
					time.Sleep(backoff)
				}
			}

			if err != nil {
				log.Printf("❌ Failed to connect to database after %d attempts: %v", maxRetries, err)
				log.Fatalf("Database migrations failed. Exiting to prevent incomplete setup.")
			}

			defer func() { _ = migrationDB.Close() }()

			// Ensure schema_migrations table exists (run migration 020 first if needed)
			ensureSchemaMigrationsTable(migrationDB)

			// Set session variable for dblink usage in migrations (required for migration 017)
			// Migration 017 uses dblink_exec to create Grafana database outside transaction context
			// dblink requires password authentication even for localhost connections
			// Use set_config() function which supports parameterized queries (unlike SET SESSION)
			_, err = migrationDB.Exec("SELECT set_config('app.db_password', $1, false)", dbPassword)
			if err != nil {
				log.Printf("⚠️  Failed to set session variable app.db_password: %v", err)
			} else {
				log.Println("✅ Set app.db_password session variable for dblink migrations")
			}

			// Get list of applied migrations
			appliedMigrations := getAppliedMigrations(migrationDB)

			successCount := 0
			skippedCount := 0
			for _, migration := range migrations {
				filename := filepath.Base(migration.Path)

				// Skip if already applied
				if appliedMigrations[migration.Version] {
					log.Printf("⏭️  Migration %s [%s] already applied (skipping)", filename, migration.Category)
					skippedCount++
					continue
				}

				// Read migration file
				sqlBytes, err := os.ReadFile(migration.Path)
				if err != nil {
					log.Printf("⚠️  Failed to read migration %s: %v", filename, err)
					continue
				}

				// Substitute GRAFANA_PASSWORD for migration 107 (grafana_database)
				sqlContent, err := substituteGrafanaPassword(string(sqlBytes))
				if err != nil {
					log.Fatalf("Migration %s failed: %v", filename, err)
				}
				if sqlContent == "" {
					log.Printf("⚠️  Skipping %s (Grafana not deployed)", filename)
					skippedCount++
					continue
				}

				// Execute migration (not in transaction to allow migrations to manage their own transactions)
				startTime := time.Now()
				_, err = migrationDB.Exec(sqlContent)
				executionTimeMs := int(time.Since(startTime).Milliseconds())

				if err != nil {
					// Record failure
					recordMigrationFailure(migrationDB, migration.Version, filename, err, executionTimeMs)

					// Fail immediately on migration error (Principle 3: No Silent Failures)
					log.Printf("❌ Migration %s [%s] FAILED: %v", filename, migration.Category, err)
					log.Fatalf("Database migrations failed. Exiting to prevent incomplete setup.")
				}

				// Record success
				recordMigrationSuccess(migrationDB, migration.Version, filename, executionTimeMs)
				log.Printf("✅ Migration %s [%s] applied successfully (%dms)", filename, migration.Category, executionTimeMs)
				successCount++
			}

			log.Printf("✅ Database migrations completed: %d applied, %d skipped, %d total", successCount, skippedCount, len(migrations))
		}
	}

	// Initialize database, audit manager, and policy engine.
	// DB mode: full enforcement with DB-loaded policies + DB audit.
	// No-DB mode: engine with nil DB (community fallback) + JSONL audit.
	if dbURL != "" {
		var err error
		authDB, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to authentication database: %v", err)
		}
		defer func() { _ = authDB.Close() }()

		if err := authDB.Ping(); err != nil {
			log.Fatalf("Failed to ping authentication database: %v", err)
		}
		log.Println("✅ Authentication database connected (Option 3)")

		usageDB = authDB
		log.Println("✅ Usage metering database connected")

		// Audit manager with DB — writes to Postgres
		initAuditManager(usageDB)
		if auditManager != nil {
			defer func() {
				if err := auditManager.Shutdown(context.Background()); err != nil {
					log.Printf("⚠️ Audit manager shutdown error: %v", err)
				}
			}()
			if recovered, err := auditManager.RecoverEntries(); err != nil {
				log.Printf("⚠️ Failed to recover audit entries: %v", err)
			} else if recovered > 0 {
				log.Printf("✅ Recovered %d audit entries from fallback file", recovered)
			}
		}

		// Tier-aware policy engine (tenant-specific policies from DB)
		tierAwarePolicyEngine = NewTierAwarePolicyEngine(authDB, nil)
		log.Println("✅ Tier-aware policy engine initialized")

		// Activate integration-specific policies before policy engine init
		// so the shared engine sees enabled rows on first load.
		ActivateIntegrationsFromEnv(usageDB)

		// Shared policy engine with DB — loads policies from database
		var sharedAuditQueue sharedpolicy.AuditQueue
		if auditManager != nil {
			sharedAuditQueue = &SharedPolicyAuditAdapter{queue: auditManager.GetQueue()}
		}
		sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(authDB, sharedpolicy.DefaultEngineConfig(), sharedAuditQueue))
		log.Println("✅ Policy enforcement: DB-backed shared engine (with audit)")

		// Cost service for budget enforcement (requires DB)
		costRepo := cost.NewPostgresRepository(authDB)
		costService = cost.NewService(costRepo, nil)
		log.Println("✅ Cost service initialized (budget enforcement enabled)")

		// AWS Marketplace metering (requires DB)
		if os.Getenv("ENABLE_MARKETPLACE_METERING") == "true" {
			productCode := os.Getenv("MARKETPLACE_PRODUCT_CODE")
			if productCode == "" {
				log.Fatal("❌ MARKETPLACE_PRODUCT_CODE required when ENABLE_MARKETPLACE_METERING=true")
			}

			var mErr error
			meteringService, mErr = marketplace.NewMeteringService(authDB, productCode)
			if mErr != nil {
				log.Fatalf("❌ Failed to create AWS Marketplace metering service: %v", mErr)
			}

			ctx := context.Background()
			if mErr := meteringService.Start(ctx); mErr != nil {
				log.Printf("⚠️  Failed to start AWS Marketplace metering: %v", mErr)
			} else {
				log.Println("✅ AWS Marketplace metering service started")
			}
		}
	} else {
		// AxonFlow requires PostgreSQL for policy enforcement, audit logging,
		// and execution tracking. Without a database, the platform cannot
		// provide governance guarantees. Refuse to start.
		log.Fatal("❌ DATABASE_URL is required. AxonFlow requires PostgreSQL for policy enforcement, " +
			"audit logging, and execution tracking. Set DATABASE_URL or use 'docker compose up -d' " +
			"which includes PostgreSQL. See: https://docs.getaxonflow.com/docs/deployment/quickstart")
	}

	// DB-independent initializations (work in both DB and no-DB mode)
	sharedpolicy.InitGlobalExfiltrationChecker()
	exfilLimits := sharedpolicy.GetGlobalExfiltrationChecker().GetLimits()
	log.Printf("✅ Exfiltration checker initialized (enabled=%v, maxRows=%d, maxBytes=%d)",
		exfilLimits.Enabled, exfilLimits.MaxRowsPerQuery, exfilLimits.MaxBytesPerQuery)

	sharedpolicy.InitGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalOrchestratorEndpoint(getOrchestratorURL())
	dynamicEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	if dynamicEval != nil {
		config := dynamicEval.GetConfig()
		log.Printf("✅ Dynamic policy evaluator initialized (enabled=%v, endpoint=%s, graceful=%v)",
			config.Enabled, config.OrchestratorEndpoint, config.GracefulDegradation)
	}

	InitDetectionConfigs()
	log.Println("✅ Detection configs cached (MCP + Gateway static policy settings)")

	// Redis rate limiting (works without DB)
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		if err := initRedis(redisURL); err != nil {
			log.Printf("Warning: Failed to initialize Redis: %v", err)
			log.Println("Falling back to in-memory rate limiting")
		} else {
			log.Println("✅ Redis rate limiting enabled")
			defer func() {
				if err := closeRedis(); err != nil {
					log.Printf("Error closing Redis: %v", err)
				}
			}()
		}
	} else {
		log.Println("ℹ️  REDIS_URL not set - using in-memory rate limiting")
	}

	// Initialize node enforcement (heartbeat + monitoring)
	var heartbeatService *node_enforcement.HeartbeatService
	var nodeMonitor *node_enforcement.NodeMonitor
	if usageDB != nil {
		// Determine instance type
		instanceType := "agent"

		// Extract orgID from environment (for customer-deployed agents)
		// In central mode, this will be empty and heartbeats won't be recorded
		// In customer mode, ORG_ID must be set to enable node enforcement
		orgID := os.Getenv("ORG_ID")
		if orgID == "" {
			// Central agent mode - skip heartbeat (agents don't have their own orgID)
			log.Println("ℹ️  ORG_ID not set - skipping node enforcement (central agent mode)")
		} else {
			// Customer-deployed agent mode - enable heartbeat
			// Note: licenseKey may be empty for testing, but should be set in production
			heartbeatService = node_enforcement.NewHeartbeatService(
				usageDB,
				instanceType,
				licenseKey,
				orgID,
			)

			// Start heartbeat service
			ctx := context.Background()
			if err := heartbeatService.Start(ctx); err != nil {
				log.Printf("⚠️  Failed to start heartbeat service: %v", err)
			} else {
				log.Println("✅ Heartbeat service started")
			}

			// Initialize node monitor (only if explicitly enabled)
			if os.Getenv("ENABLE_NODE_MONITOR") == "true" {
				alerter := node_enforcement.NewMultiChannelAlerter()
				nodeMonitor = node_enforcement.NewNodeMonitor(usageDB, alerter)
				nodeMonitor.Start(ctx)
				log.Println("✅ Node monitoring started")
			}
		}
	}

	// Cleanup services on shutdown
	if heartbeatService != nil {
		defer heartbeatService.Stop()
	}
	if nodeMonitor != nil {
		defer nodeMonitor.Stop()
	}
	if meteringService != nil {
		defer meteringService.Stop()
	}

	// Initialize MCP connector registry (ADR-007: three-tier configuration)
	// Configuration priority: Database > Config File (AXONFLOW_CONFIG_FILE) > Environment Variables
	if configFile := os.Getenv("AXONFLOW_CONFIG_FILE"); configFile != "" {
		log.Printf("[MCP] Using config file from AXONFLOW_CONFIG_FILE: %s", configFile)
	}
	if err := InitializeMCPRegistryWithDB(authDB); err != nil {
		log.Printf("Warning: Failed to initialize MCP registry: %v", err)
		log.Println("Agent will run without MCP connector support")
	} else {
		log.Println("AxonFlow Agent initialized with MCP connector support")
		// Ensure connectors are properly disconnected on shutdown
		defer func() {
			if mcpRegistry != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				mcpRegistry.DisconnectAll(ctx)
			}
		}()
	}

	// Initialize TenantConnectorRegistry for per-tenant connector management (ADR-007)
	// This provides dynamic connector loading with three-tier configuration:
	// Database > Config File > Environment Variables
	tenantConnectorEnabled := os.Getenv("TENANT_CONNECTOR_REGISTRY_ENABLED") != "false"
	if tenantConnectorEnabled {
		runtimeConfigSvc := GetRuntimeConfigService()
		if runtimeConfigSvc == nil {
			log.Println("Warning: RuntimeConfigService not available, per-tenant connector registry disabled")
			tenantConnectorEnabled = false
		} else {
			connectorFactory := DefaultConnectorFactory()
			tenantRegistry := InitTenantConnectorRegistry(runtimeConfigSvc, connectorFactory)
			if tenantRegistry != nil {
				log.Println("AxonFlow Agent initialized with per-tenant connector registry (ADR-007)")
				// Start periodic cleanup of expired connectors (StartPeriodicCleanup spawns its own goroutine)
				tenantRegistry.StartPeriodicCleanup(context.Background(), 5*time.Minute)
				// Ensure tenant connectors are properly disconnected on shutdown
				defer func() {
					if reg := GetTenantConnectorRegistry(); reg != nil {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						reg.DisconnectAll(ctx)
					}
				}()
			}
		}
	} else {
		log.Println("Per-tenant connector registry disabled via TENANT_CONNECTOR_REGISTRY_ENABLED=false")
	}

	// Register all routes on the global router (server is already running with /health)
	// /health was registered in initServerImmediately() - now add all other routes

	// Metrics endpoint for real performance data (JSON format)
	globalRouter.HandleFunc("/metrics", metricsHandler).Methods("GET")

	// Prometheus metrics endpoint (Prometheus exposition format)
	globalRouter.Handle("/prometheus", promhttp.Handler()).Methods("GET")

	// Main client request endpoint - all requests flow through here
	globalRouter.HandleFunc("/api/request", clientRequestHandler).Methods("POST")

	// Client management endpoints
	globalRouter.HandleFunc("/api/clients", listClientsHandler).Methods("GET")
	globalRouter.HandleFunc("/api/clients", createClientHandler).Methods("POST")

	// Policy testing endpoint — protected by auth middleware (tenant from credentials)
	globalRouter.Handle("/api/policies/test", apiAuthMiddleware(http.HandlerFunc(policyTestHandler))).Methods("POST")

	// Register MCP connector endpoints
	RegisterMCPHandlers(globalRouter)

	// Register MCP server protocol endpoint (Claude Code plugin — #1484)
	RegisterMCPServerHandler(globalRouter)

	// Register connector refresh API endpoints (ADR-007)
	// These endpoints allow manual cache invalidation for connector configurations
	if tenantConnectorEnabled {
		RegisterConnectorRefreshHandlers(globalRouter)
	}

	// Register Gateway Mode endpoints (pre-check and audit)
	RegisterGatewayHandlers(globalRouter)

	// Register Static Policy API endpoints (ADR-018: Unified Policy Management)
	// This enables the Customer Portal to list static policies from the Agent
	RegisterStaticPolicyHandlers(globalRouter, usageDB)

	// Register HITL (Human-in-the-Loop) API endpoints (EU AI Act Article 14)
	// Enterprise feature: Human oversight queue for high-risk AI decisions
	hitlRepo := hitl.NewRepository(usageDB)
	// Read pending approval limit from license tier
	hitlLimits := license.GetCurrentLimits(context.Background())
	hitlService := hitl.NewService(hitlRepo, hitl.ServiceConfig{
		MaxPendingApprovals: hitlLimits.MaxPendingApprovals,
	})
	hitlHandler := hitl.NewHandler(hitlService)
	hitlHandler.RegisterRoutes(globalRouter)
	// Note: In community edition, RegisterRoutes registers a single /status endpoint
	// Auth for HITL is handled by the handler reading X-Org-ID/X-Tenant-ID headers,
	// which are set by proxyAuthMiddleware for proxied requests or directly by clients.

	// Start HITL expiration background job (1-hour ticker)
	// Enterprise: expires stale pending approval requests. Community: no-op.
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			count, err := hitlService.ExpireStaleRequests(context.Background())
			if err != nil {
				log.Printf("[HITL] Expiration error: %v", err)
			} else if count > 0 {
				log.Printf("[HITL] Expired %d stale approval requests", count)
			}
		}
	}()

	// Register Circuit Breaker API endpoints (EU AI Act Article 14)
	// Enterprise feature: Emergency stop/interrupt capability for AI operations
	// Issue #1176: Wire circuit breaker into request pipeline with meaningful thresholds
	cbRepo := circuitbreaker.NewRepository(usageDB)
	circuitBreakerInstance = circuitbreaker.New(cbRepo, circuitbreaker.Config{
		DefaultTimeout:           5 * time.Minute,
		MaxTimeout:               1 * time.Hour,
		ErrorThreshold:           10,
		PolicyViolationThreshold: 20,
		PolicyViolationWindow:    5 * time.Minute,
		EnableAutoRecovery:       true,
	})
	notifService := circuitbreaker.NewNotificationService(cbRepo)
	circuitBreakerInstance.SetTripCallback(notifService.HandleTripEvent)
	cbHandler := circuitbreaker.NewHandler(circuitBreakerInstance)
	cbHandler.SetNotificationService(notifService)
	cbHandler.RegisterRoutes(globalRouter, mux.MiddlewareFunc(apiAuthMiddleware))
	// Note: In community edition, RegisterRoutes is a no-op (Circuit Breaker is an enterprise feature)

	// Load active circuits from DB so they survive agent restarts
	if err := circuitBreakerInstance.LoadCircuits(context.Background(), ""); err != nil {
		log.Printf("⚠️  Failed to load active circuits: %v", err)
	}

	// Background goroutine to expire open circuits after their timeout
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := circuitBreakerInstance.ExpireCircuits(context.Background()); err != nil {
				log.Printf("[CircuitBreaker] Expiration error: %v", err)
			}
		}
	}()

	// Register Reverse Proxy routes (ADR-026: Single Entry Point Architecture)
	// Proxies requests to Orchestrator and Portal based on path
	proxyConfig := GetProxyConfig()
	proxyHandler, err := NewReverseProxyHandler(proxyConfig)
	if err != nil {
		log.Printf("⚠️  Failed to initialize reverse proxy: %v", err)
		log.Println("   SDK clients will need to connect directly to backend services")
	} else {
		proxyHandler.RegisterProxyRoutes(globalRouter)
		log.Println("✅ Reverse proxy initialized (ADR-026: Single Entry Point)")
	}

	// Mark application as ready - /health will now return "healthy"
	appReady.Store(true)
	log.Println("✅ All initialization complete - application ready")
	log.Printf("🚀 AxonFlow Agent fully operational on port %s", port)

	// Block forever - server is running in goroutine, nothing else to do
	select {}
}

//nolint:unused // Used in tests
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":             "healthy",
		"service":            "axonflow-agent",
		"timestamp":          time.Now().UTC(),
		"version":            GetPlatformVersion(),
		"capabilities":       getCapabilities(),
		"sdk_compatibility":  getSDKCompatibility(),
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

func clientRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	atomic.AddInt64(&agentMetrics.totalRequests, 1)

	// Log incoming request with headers
	log.Printf("📨 Incoming request from %s - Method: %s, Path: %s", r.RemoteAddr, r.Method, logutil.Sanitize(r.URL.Path))
	log.Printf("   Headers: X-License-Key: %s, X-Client-Secret: %s, Content-Type: %s",
		maskString(r.Header.Get("X-License-Key")),
		maskString(r.Header.Get("X-Client-Secret")),
		r.Header.Get("Content-Type"))

	var req ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		atomic.AddInt64(&agentMetrics.failedRequests, 1)
		log.Printf("❌ Request body parse failed: %v", err)
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	parseTime := time.Since(startTime)
	log.Printf("[TIMING] Request parse: %v", parseTime)
	log.Printf("   Request body: ClientID='%s', RequestType='%s', Query='%s'",
		logutil.Sanitize(req.ClientID), logutil.Sanitize(req.RequestType), logutil.Sanitize(truncateString(req.Query, 50)))

	// 1. Validate client authentication
	validateClientStart := time.Now()

	var client *Client
	var err error

	if isCommunityMode() {
		log.Printf("🏠 Community mode: Skipping authentication for client '%s'", logutil.Sanitize(req.ClientID))
		// Create a default client for community deployments
		client = &Client{
			ID:          req.ClientID,
			Name:        "Community",
			OrgID:       getDeploymentOrgID(),
			TenantID:    req.ClientID,
			Enabled:     true,
			LicenseTier: "Community",
			RateLimit:   0,
			Permissions: []string{},
		}
	} else {
		// Production mode: Validate credentials via OAuth2 Basic auth
		clientSecret := extractClientSecret(r)
		if clientSecret == "" {
			log.Printf("❌ Missing authentication - no Authorization header")
			sendErrorResponse(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized, nil)
			return
		}
		log.Printf("🔐 Validating credentials for client '%s' with secret '%s...'", logutil.Sanitize(req.ClientID), maskString(clientSecret))

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Use Option 3 (database-backed) if available, otherwise Option 2 (whitelist)
		if authDB != nil {
			client, err = validateClientCredentialsDB(ctx, authDB, req.ClientID, clientSecret)
		} else {
			client, err = validateClientCredentials(ctx, req.ClientID, clientSecret)
		}
		if err != nil {
			log.Printf("❌ Credentials validation failed for client '%s': %v", logutil.Sanitize(req.ClientID), err)
			sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
			return
		}
		log.Printf("✅ Credentials validated successfully for client '%s' (Tier: %s)", logutil.Sanitize(client.ID), logutil.Sanitize(client.LicenseTier))
	}

	if !client.Enabled {
		sendErrorResponse(w, "Client disabled", http.StatusForbidden, nil)
		return
	}
	validateClientTime := time.Since(validateClientStart)
	log.Printf("[TIMING] Client validation: %v", validateClientTime)

	// 2. Validate and extract user from token
	validateUserStart := time.Now()
	user, err := validateUserToken(req.UserToken, client.TenantID)
	if err != nil {
		sendErrorResponse(w, fmt.Sprintf("Invalid user token: %v", err), http.StatusUnauthorized, nil)
		return
	}

	validateUserTime := time.Since(validateUserStart)
	log.Printf("[TIMING] User token validation: %v", validateUserTime)

	// 3. Verify tenant isolation
	tenantCheckStart := time.Now()
	log.Printf("🔍 Checking tenant isolation: User TenantID='%s', Client TenantID='%s'", logutil.Sanitize(user.TenantID), logutil.Sanitize(client.TenantID))
	if user.TenantID != client.TenantID {
		log.Printf("❌ TENANT MISMATCH: User TenantID='%s' does not match Client TenantID='%s'", logutil.Sanitize(user.TenantID), logutil.Sanitize(client.TenantID))
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}
	tenantCheckTime := time.Since(tenantCheckStart)
	log.Printf("✅ Tenant isolation check passed")
	log.Printf("[TIMING] Tenant isolation check: %v", tenantCheckTime)

	// 3.5 Circuit breaker check — block if circuit is open for this client/tenant/org (#1176)
	if circuitBreakerInstance != nil {
		cbResult, cbErr := circuitBreakerInstance.Check(r.Context(), circuitbreaker.CheckInput{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ID,
		})
		if cbErr != nil {
			log.Printf("⚠️ Circuit breaker check error: %v", cbErr)
		} else if !cbResult.Allowed {
			log.Printf("🔴 Request blocked by circuit breaker: scope=%s reason=%s", logutil.Sanitize(string(cbResult.Scope)), logutil.Sanitize(string(cbResult.Reason)))
			if retryAfter := circuitBreakerRetryAfter(cbResult.ExpiresAt); retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			sendErrorResponse(w, fmt.Sprintf("Service temporarily unavailable: circuit breaker active (reason: %s)", cbResult.Reason), http.StatusServiceUnavailable, nil)
			return
		}
	}

	// 4. Apply static policy enforcement
	// Uses UnifiedPolicyEngine (shared engine) as primary path, with fallbacks.
	// Phase 2: Tenant-specific policies via tierAwarePolicyEngine (below).
	policyEvalStart := time.Now()
	log.Printf("📋 Evaluating static policies for request type: %s", req.RequestType)
	var policyResult *StaticPolicyResult

	// Check if gateway static policies are enabled (proxy uses gateway config)
	gatewayDetectionCfg := GetGatewayDetectionConfig()
	sharedEngine := sharedpolicy.GetGlobalEngine()
	if !gatewayDetectionCfg.Enabled {
		// Static policies disabled — create empty result
		policyResult = &StaticPolicyResult{}
	} else if sharedEngine != nil {
		// Primary path: UnifiedPolicyEngine (same as Gateway handler)
		skipCats := append([]sharedpolicy.PolicyCategory(nil), gatewayDetectionCfg.SkipCategories...)
		if user.Role == "admin" {
			skipCats = append(skipCats, sharedpolicy.CategoryAdminAccess)
		}
		requestResult := sharedEngine.EvaluateRequest(r.Context(), req.Query, sharedpolicy.EvalOptions{
			TenantID:        user.TenantID,
			ConnectorName:   "proxy",
			UserID:          fmt.Sprintf("%d", user.ID),
			Categories:      proxyPolicyCategories,
			SkipCategories:  skipCats,
			ActionOverrides: gatewayDetectionCfg.BuildActionOverrides(),
		})
		policyResult = convertSharedResultToStatic(requestResult)
		log.Printf("[Proxy] Shared policy engine evaluated %d policies in %dms",
			requestResult.PoliciesEvaluated, requestResult.ProcessingTimeMs)
	} else {
		log.Println("[Proxy] WARNING: No policy engine available (shared engine not initialized)")
		policyResult = &StaticPolicyResult{}
	}

	// Phase 2: Tenant-specific policies (if not already blocked and tier engine available)
	if !policyResult.Blocked && tierAwarePolicyEngine != nil {
		ctx := r.Context()
		tierResult, err := tierAwarePolicyEngine.EvaluatePolicy(ctx, user.TenantID, nil, req.Query)
		if err != nil {
			log.Printf("⚠️ Tier-aware policy evaluation error: %v", err)
		} else if tierResult.Matched && tierResult.Action == "block" {
			// Tenant policy triggered a block
			policyResult.Blocked = true
			policyResult.Reason = fmt.Sprintf("Blocked by %s policy: %s", tierResult.Tier, tierResult.PolicyName)
			policyResult.TriggeredPolicies = append(policyResult.TriggeredPolicies, tierResult.PolicyID)
			policyResult.Severity = tierResult.Severity
			log.Printf("🛡️ Tenant policy blocked request: %s (tier: %s)", tierResult.PolicyName, tierResult.Tier)
		} else if tierResult.Matched {
			// Policy matched but action is not block (allow, warn, log, redact, require_approval)
			policyResult.TriggeredPolicies = append(policyResult.TriggeredPolicies, tierResult.PolicyID)
			log.Printf("📝 Tenant policy matched (action=%s): %s", tierResult.Action, tierResult.PolicyName)

			// Issue #1081: Set RequiresApproval for HITL enforcement (Enterprise only)
			if tierResult.Action == "require_approval" {
				policyResult.RequiresApproval = true
				log.Printf("⏸️ HITL required by tenant policy: %s", tierResult.PolicyName)
			}
		}
	}

	policyEvalTime := time.Since(policyEvalStart)
	log.Printf("✅ Policy evaluation complete: Blocked=%v, TriggeredPolicies=%d", policyResult.Blocked, len(policyResult.TriggeredPolicies))
	log.Printf("[TIMING] Policy evaluation: %v", policyEvalTime)

	if policyResult.Blocked {
		log.Printf("Request blocked by static policy for user %s: %s", logutil.Sanitize(user.Email), logutil.Sanitize(policyResult.Reason))

		// Record policy violation for auto-trip threshold tracking (#1176)
		if circuitBreakerInstance != nil {
			for _, policyID := range policyResult.TriggeredPolicies {
				if err := circuitBreakerInstance.RecordPolicyViolation(r.Context(), client.OrgID, client.TenantID, client.ID, policyID); err != nil {
					log.Printf("⚠️ Circuit breaker RecordPolicyViolation error: %v", err)
				}
			}
		}

		// Track blocked request metrics
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.blockedRequests, 1)
			latencyMs := int64(time.Since(startTime).Milliseconds())
			agentMetrics.recordLatency(latencyMs, "static")
		}

		// Record Prometheus metrics
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		promPolicyEvaluations.Inc()
		promRequestDuration.WithLabelValues("static").Observe(float64(time.Since(startTime).Milliseconds()))

		response := ClientResponse{
			Success:     false,
			Blocked:     true,
			BlockReason: policyResult.Reason,
			PolicyInfo: &PolicyEvaluationInfo{
				PoliciesEvaluated: policyResult.TriggeredPolicies,
				StaticChecks:      policyResult.ChecksPerformed,
				ProcessingTime:    time.Since(startTime).String(),
				TenantID:          user.TenantID,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding service permission denied response: %v", err)
		}
		return
	}

	// Issue #1081: HITL (Human-in-the-Loop) enforcement for compliance frameworks
	// HITL is an ENTERPRISE-ONLY feature. It is ONLY triggered by policy evaluation
	// returning require_approval action. We do NOT trust client-provided context metadata.
	requiresHITL := policyResult.RequiresApproval && !isCommunityMode()
	if requiresHITL {
		log.Printf("⏸️ [Proxy Mode] HITL required - blocking request for human approval")

		// Track HITL blocked request metrics
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.blockedRequests, 1)
			latencyMs := int64(time.Since(startTime).Milliseconds())
			agentMetrics.recordLatency(latencyMs, "hitl")
		}

		// Record Prometheus metrics
		promRequestsTotal.WithLabelValues("hitl_blocked").Inc()
		promBlockedRequests.Inc()
		promPolicyEvaluations.Inc()
		promRequestDuration.WithLabelValues("hitl").Observe(float64(time.Since(startTime).Milliseconds()))

		response := ClientResponse{
			Success:     false,
			Blocked:     true,
			BlockReason: "require_approval",
			PolicyInfo: &PolicyEvaluationInfo{
				PoliciesEvaluated: append(policyResult.TriggeredPolicies, "hitl_compliance"),
				StaticChecks:      policyResult.ChecksPerformed,
				ProcessingTime:    time.Since(startTime).String(),
				TenantID:          user.TenantID,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden) // 403 for HITL block
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding HITL blocked response: %v", err)
		}
		return
	}

	// Rate limiting is now handled inside validateClientCredentials() during authentication
	rateLimitTime := time.Duration(0)

	// Issue #1082: Budget enforcement - check before allowing request
	budgetCheckStart := time.Now()
	var budgetInfo *BudgetInfo
	if costService != nil {
		ctx := r.Context()
		log.Printf("💰 [clientRequestHandler] Checking budget: OrgID=%s, TenantID=%s, UserID=%d", client.OrgID, client.TenantID, user.ID)
		budgetDecision, err := costService.CheckBudget(ctx, client.OrgID, "", "", fmt.Sprintf("%d", user.ID), client.TenantID)
		if err != nil {
			log.Printf("⚠️ [clientRequestHandler] Budget check failed: %v (allowing request)", err)
		} else {
			log.Printf("💰 [clientRequestHandler] Budget decision: Allowed=%v, BudgetID=%s, UsedUSD=%.4f, LimitUSD=%.4f, Percentage=%.2f",
				budgetDecision.Allowed, budgetDecision.BudgetID, budgetDecision.UsedUSD, budgetDecision.LimitUSD, budgetDecision.Percentage)
		}
		if budgetDecision != nil {
			budgetInfo = &BudgetInfo{
				BudgetID:   budgetDecision.BudgetID,
				BudgetName: budgetDecision.BudgetName,
				UsedUSD:    budgetDecision.UsedUSD,
				LimitUSD:   budgetDecision.LimitUSD,
				Percentage: budgetDecision.Percentage,
				Exceeded:   !budgetDecision.Allowed || budgetDecision.Percentage >= 100,
				Action:     string(budgetDecision.Action),
			}

			// Block if budget exceeded and action is block
			if !budgetDecision.Allowed {
				log.Printf("💰 [clientRequestHandler] Request blocked by budget: %s", budgetDecision.Message)
				response := ClientResponse{
					Success:     false,
					Blocked:     true,
					BlockReason: budgetDecision.Message,
					BudgetInfo:  budgetInfo,
					PolicyInfo: &PolicyEvaluationInfo{
						PoliciesEvaluated: []string{"budget_exceeded"},
						StaticChecks:      policyResult.ChecksPerformed,
						ProcessingTime:    time.Since(startTime).String(),
						TenantID:          user.TenantID,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired) // 402 Payment Required
				_ = json.NewEncoder(w).Encode(response)
				return
			}

			// Warn if exceeded but action is warn
			if budgetDecision.Percentage >= 100 && budgetDecision.Action == cost.OnExceedWarn {
				log.Printf("⚠️ [clientRequestHandler] Budget exceeded with warn action: %s", budgetDecision.Message)
				w.Header().Set("X-Budget-Warning", budgetDecision.Message)
			}
		}
	}
	budgetCheckTime := time.Since(budgetCheckStart)
	log.Printf("[TIMING] Budget check: %v", budgetCheckTime)

	// Calculate auth time (client + user + tenant validation)
	authTime := validateClientTime + validateUserTime + tenantCheckTime

	// Record per-stage metrics (convert to milliseconds)
	if agentMetrics != nil {
		agentMetrics.mu.Lock()
		// Auth timing
		authMs := authTime.Milliseconds()
		if len(agentMetrics.authTimings) >= 1000 {
			agentMetrics.authTimings = agentMetrics.authTimings[1:]
		}
		agentMetrics.authTimings = append(agentMetrics.authTimings, authMs)

		// Static policy timing
		policyMs := policyEvalTime.Milliseconds()
		if len(agentMetrics.staticPolicyTimings) >= 1000 {
			agentMetrics.staticPolicyTimings = agentMetrics.staticPolicyTimings[1:]
		}
		agentMetrics.staticPolicyTimings = append(agentMetrics.staticPolicyTimings, policyMs)
		agentMetrics.mu.Unlock()
	}

	// Send response
	totalProcessingTime := time.Since(startTime)
	log.Printf("[TIMING] Total processing time: %v (parse: %v, client: %v, user: %v, tenant: %v, policy: %v, ratelimit: %v)",
		totalProcessingTime, parseTime, validateClientTime, validateUserTime, tenantCheckTime, policyEvalTime, rateLimitTime)

	// 6. Forward to AxonFlow Orchestrator (include skip_llm flag for hourly tests)
	orchestratorStart := time.Now()
	log.Printf("🚀 Forwarding request to orchestrator: ClientID=%s, RequestType=%s", req.ClientID, req.RequestType)
	orchestratorResp, err := forwardToOrchestrator(req, user, client)
	orchestratorTime := time.Since(orchestratorStart)
	if err != nil {
		log.Printf("❌ Orchestrator forward failed: %v (time: %v)", err, orchestratorTime)
	} else {
		log.Printf("✅ Orchestrator responded successfully (time: %v)", orchestratorTime)
	}

	// Record network timing (Agent → Orchestrator)
	if agentMetrics != nil && err == nil {
		agentMetrics.mu.Lock()
		networkMs := orchestratorTime.Milliseconds()
		if len(agentMetrics.networkTimings) >= 1000 {
			agentMetrics.networkTimings = agentMetrics.networkTimings[1:]
		}
		agentMetrics.networkTimings = append(agentMetrics.networkTimings, networkMs)
		agentMetrics.mu.Unlock()
	}

	if err != nil {
		// Track failed request
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.failedRequests, 1)
		}
		// Record error for circuit breaker auto-trip (#1176 Phase 2B)
		if circuitBreakerInstance != nil {
			if cbErr := circuitBreakerInstance.RecordError(r.Context(), client.OrgID, client.TenantID, client.ID); cbErr != nil {
				log.Printf("[CircuitBreaker] RecordError failed: %v", cbErr)
			}
		}
		sendErrorResponse(w, "Orchestrator error: "+err.Error(), http.StatusInternalServerError, nil)
		return
	}

	// Detect orchestrator-level errors (e.g., 409 cancelled, 410 expired, 403 blocked).
	// forwardToOrchestrator returns nil error for any HTTP response with valid JSON,
	// even non-2xx status codes. We must inspect the response body to determine
	// if the orchestrator reported a business-level failure.
	orchSuccess := true
	orchError := ""
	orchHTTPStatus := 200
	orchMap, _ := orchestratorResp.(map[string]interface{})
	if orchMap != nil {
		if s, exists := orchMap["success"]; exists {
			if sb, ok := s.(bool); ok {
				orchSuccess = sb
				if !sb {
					orchHTTPStatus = 500
				}
			}
		}
		if e, exists := orchMap["error"]; exists {
			if es, ok := e.(string); ok && es != "" {
				orchError = es
			}
		}
	}

	// Track request outcome based on orchestrator response
	latencyMs := int64(time.Since(startTime).Milliseconds())
	if orchSuccess {
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.successRequests, 1)
			agentMetrics.recordLatency(latencyMs, "dynamic")
		}
		promRequestsTotal.WithLabelValues("success").Inc()
	} else {
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.failedRequests, 1)
			agentMetrics.recordLatency(latencyMs, "dynamic")
		}
		promRequestsTotal.WithLabelValues("orchestrator_error").Inc()
		log.Printf("[clientRequestHandler] Orchestrator returned error: %s", orchError)
		// Record orchestrator-level error for circuit breaker auto-trip (#1176 Phase 2B)
		if circuitBreakerInstance != nil {
			if cbErr := circuitBreakerInstance.RecordError(r.Context(), client.OrgID, client.TenantID, client.ID); cbErr != nil {
				log.Printf("[CircuitBreaker] RecordError failed: %v", cbErr)
			}
		}
	}
	promPolicyEvaluations.Inc()
	promRequestDuration.WithLabelValues("dynamic").Observe(float64(latencyMs))

	// Issue #1082: Record cost tracking after successful LLM call
	// This updates budget usage so enforcement works on subsequent requests
	// Skip cost recording for orchestrator errors (no LLM call was made)
	if costService != nil && orchSuccess && orchMap != nil {
		if providerInfoRaw, exists := orchMap["provider_info"]; exists {
			if providerInfoMap, ok := providerInfoRaw.(map[string]interface{}); ok {
				// Extract provider info
				provider := ""
				model := ""
				tokensUsed := 0
				costUSD := 0.0

				if p, ok := providerInfoMap["provider"].(string); ok {
					provider = p
				}
				if m, ok := providerInfoMap["model"].(string); ok {
					model = m
				}
				if t, ok := providerInfoMap["tokens_used"].(float64); ok {
					tokensUsed = int(t)
				}
				if c, ok := providerInfoMap["cost"].(float64); ok {
					costUSD = c
				}

				// Record usage if we have token info
				if tokensUsed > 0 || costUSD > 0 {
					// Generate request ID (ClientRequest doesn't have one, generate based on timestamp)
					requestID := fmt.Sprintf("req_%d", time.Now().UnixNano())
					usageRecord := &cost.UsageRecord{
						RequestID: requestID,
						Timestamp: time.Now().UTC(),
						OrgID:     client.OrgID,
						TenantID:  user.TenantID,
						UserID:    fmt.Sprintf("%d", user.ID),
						Provider:  provider,
						Model:     model,
						TokensIn:  tokensUsed / 2, // Approximate split (tokens_used is total)
						TokensOut: tokensUsed / 2,
						CostUSD:   costUSD,
					}

					// Issue #1082: Record synchronously so budget enforcement works on subsequent requests
					// This ensures budget check sees updated usage before allowing next request
					ctx := context.Background()
					if err := costService.RecordUsage(ctx, usageRecord); err != nil {
						log.Printf("💰 [clientRequestHandler] Failed to record usage: %v", err)
					} else {
						log.Printf("💰 [clientRequestHandler] Recorded cost: provider=%s model=%s tokens=%d cost=$%.6f",
							usageRecord.Provider, usageRecord.Model, usageRecord.TokensIn+usageRecord.TokensOut, usageRecord.CostUSD)
					}
				}
			}
		}
	}

	// 7. Detect code artifacts in response (Issue #761: Governed Code Generation)
	var codeArtifact *CodeArtifactMetadata
	if responseContent := extractResponseContent(orchestratorResp); responseContent != "" {
		codeArtifact = DetectCodeInResponse(responseContent)
		if codeArtifact != nil {
			// Evaluate code-specific policies
			policiesChecked, _ := EvaluateCodePolicies(responseContent)
			codeArtifact.PoliciesChecked = policiesChecked
			log.Printf("[AUDIT] Code artifact detected: language=%s, type=%s, size=%d bytes, secrets=%d, unsafe=%d",
				codeArtifact.Language, codeArtifact.CodeType, codeArtifact.SizeBytes,
				codeArtifact.SecretsDetected, codeArtifact.UnsafePatterns)
		}
	}

	// 8. Return response with policy information
	// Issue #1082: Extract "data" field from orchestratorResp (which now contains full response)
	responseData := orchestratorResp
	if orchMap != nil {
		if data, exists := orchMap["data"]; exists {
			responseData = data
		}
	}

	// orchSuccess and orchError were extracted above (after forwardToOrchestrator)
	// and used for metrics, cost tracking, and now the client response.
	response := ClientResponse{
		Success: orchSuccess,
		Data:    responseData,
		Error:   orchError,
		PolicyInfo: &PolicyEvaluationInfo{
			PoliciesEvaluated: policyResult.TriggeredPolicies,
			StaticChecks:      policyResult.ChecksPerformed,
			ProcessingTime:    time.Since(startTime).String(),
			TenantID:          user.TenantID,
			CodeArtifact:      codeArtifact,
		},
		BudgetInfo: budgetInfo, // Issue #1082: Include budget status in response
	}

	// Extract media_analysis from orchestrator response (media governance results)
	if orchMap != nil {
		if mediaAnalysis, exists := orchMap["media_analysis"]; exists && mediaAnalysis != nil {
			response.MediaAnalysis = mediaAnalysis
		}
	}

	// For multi-agent planning requests (GeneratePlan and ExecutePlan), flatten orchestrator response fields to top level
	// This allows client SDKs to access plan_id, result, metadata directly
	if req.RequestType == "multi-agent-plan" || req.RequestType == "execute-plan" {
		if orchMap, ok := orchestratorResp.(map[string]interface{}); ok {
			if planID, exists := orchMap["plan_id"]; exists {
				if planIDStr, ok := planID.(string); ok {
					response.PlanID = planIDStr
				}
			}
			if result, exists := orchMap["result"]; exists {
				// Convert to string to match SDK ClientResponse type
				if resultStr, ok := result.(string); ok {
					response.Result = resultStr
					log.Printf("[DEBUG] Extracted result from orchestrator: type=string, length=%d", len(resultStr))
				} else {
					// Fallback: convert to string representation
					response.Result = fmt.Sprintf("%v", result)
					log.Printf("[WARN] result field is not a string, type=%T, converted to string", result)
				}
			} else {
				log.Printf("[WARN] No 'result' field found in orchestrator response, keys: %v", getKeys(orchMap))
			}
			if metadata, exists := orchMap["metadata"]; exists {
				// Convert to map[string]interface{} to match SDK ClientResponse type
				if metadataMap, ok := metadata.(map[string]interface{}); ok {
					response.Metadata = metadataMap
				} else {
					log.Printf("[WARN] metadata field is not a map, type=%T", metadata)
				}
			}
			if steps, exists := orchMap["steps"]; exists {
				// Convert steps to []interface{} for SDK
				if stepsSlice, ok := steps.([]interface{}); ok {
					response.Steps = stepsSlice
					log.Printf("[DEBUG] Extracted steps from orchestrator: count=%d", len(stepsSlice))
				} else {
					log.Printf("[WARN] steps field is not a slice, type=%T", steps)
				}
			} else {
				log.Printf("[DEBUG] No 'steps' field in orchestrator response (may be expected for failed plans)")
			}
		} else {
			log.Printf("[WARN] orchestratorResp is not a map, type=%T", orchestratorResp)
		}
	}

	log.Printf("[DEBUG] Sending response: Success=%v, ResultType=%T, ResultLength=%d, PlanID=%s",
		response.Success, response.Result, getStringLength(response.Result), response.PlanID)

	// Marshal to bytes to log actual JSON being sent
	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response: %v", err)
		sendErrorResponse(w, "Internal marshaling error", http.StatusInternalServerError, nil)
		return
	}

	// Log JSON structure (truncate result field for readability)
	var logStruct map[string]interface{}
	if err := json.Unmarshal(responseBytes, &logStruct); err == nil {
		if resultVal, ok := logStruct["result"]; ok {
			if resultStr, ok := resultVal.(string); ok && len(resultStr) > 100 {
				logStruct["result"] = resultStr[:100] + "...[truncated]"
			}
		}
		if logJSON, err := json.Marshal(logStruct); err == nil {
			log.Printf("[DEBUG] Actual JSON being sent: %s", string(logJSON))
		}
	}
	log.Printf("[DEBUG] Full response length: %d bytes", len(responseBytes))

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseBytes); err != nil {
		log.Printf("Error writing response: %v", err)
	}

	// Record usage asynchronously (don't block response)
	if usageDB != nil && client != nil && client.OrgID != "" {
		go func() {
			recorder := usage.NewUsageRecorder(usageDB)
			instanceID := os.Getenv("HOSTNAME") // Docker container ID
			if instanceID == "" {
				instanceID = "agent-unknown"
			}

			err := recorder.RecordAPICall(usage.APICallEvent{
				OrgID:          client.OrgID,
				ClientID:       client.ID,
				InstanceID:     instanceID,
				InstanceType:   "agent",
				HTTPMethod:     r.Method,
				HTTPPath:       r.URL.Path,
				HTTPStatusCode: orchHTTPStatus,
				LatencyMs:      time.Since(startTime).Milliseconds(),
			})

			if err != nil {
				log.Printf("[USAGE] Failed to record API call: %v", err)
			}
		}()
	}
}

func validateClient(clientID string) (*Client, error) {
	// In production, this would query a database
	// For now, return a mock client
	if clientID == "" {
		return nil, fmt.Errorf("client ID required")
	}

	return &Client{
		ID:          clientID,
		Name:        "Demo Client",
		OrgID:       getDeploymentOrgID(),
		TenantID:    clientID,
		Permissions: []string{"query", "llm"},
		RateLimit:   100,
		Enabled:     true,
	}, nil
}

func validateUserToken(tokenString string, expectedTenantID string) (*User, error) {
	// Community mode: Don't require a token for local development
	// Uses DEPLOYMENT_MODE check - simple and clean pattern
	if isCommunityMode() {
		log.Printf("[Community] Authentication bypassed for tenant %s", expectedTenantID)
		return &User{
			ID:          1,
			Email:       "local-dev@axonflow.local",
			Name:        "Local Development User",
			Role:        "admin",
			Region:      "local",
			Permissions: []string{"query", "llm", "mcp_query", "admin"},
			TenantID:    expectedTenantID,
		}, nil
	} else if tokenString == "" {
		return nil, fmt.Errorf("token required")
	}

	// Validate JWT token using the configured secret
	// Generate tokens using: scripts/generate-jwt.sh
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract user information from token
	// In production, you might need to fetch additional details from database
	tenantID := getClaimString(claims, "tenant_id")
	if tenantID == "" {
		tenantID = "tenant_1" // Fallback for backward compatibility
	}

	// Extract user_id - handle both string and numeric types
	var userID int
	switch v := claims["user_id"].(type) {
	case float64:
		userID = int(v)
	case string:
		userID = 1 // Default for string-based user IDs
	default:
		userID = 1
	}

	return &User{
		ID:          userID,
		Email:       getClaimString(claims, "email"),
		Name:        getClaimString(claims, "name"),
		Department:  getClaimString(claims, "department"),
		Role:        getClaimString(claims, "role"),
		Region:      getClaimString(claims, "region"),
		Permissions: getClaimStringArray(claims, "permissions"),
		TenantID:    tenantID, // Extract from JWT claims for multi-tenant isolation
	}, nil
}

// checkRateLimit moved to auth.go as part of license-based authentication

func forwardToOrchestrator(req ClientRequest, user *User, client *Client) (interface{}, error) {
	// Prepare orchestrator request
	// Copy context and add plan_id if present (for execute-plan requests)
	context := req.Context
	if req.PlanID != "" {
		if context == nil {
			context = make(map[string]interface{})
		}
		context["plan_id"] = req.PlanID
	}
	orchestratorReq := map[string]interface{}{
		"query":        req.Query,
		"user":         user,
		"client":       client,
		"request_type": req.RequestType,
		"skip_llm":     req.SkipLLM,
		"context":      context,
		"request_id":   fmt.Sprintf("req_%d", time.Now().UnixNano()),
	}

	// Forward media items (images) to orchestrator for media governance analysis
	if len(req.Media) > 0 {
		orchestratorReq["media"] = req.Media
	}

	jsonData, err := json.Marshal(orchestratorReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Determine orchestrator endpoint based on request type
	var orchEndpoint string
	switch req.RequestType {
	case "multi-agent-plan", "generate-plan":
		// Route GeneratePlan requests to /api/v1/plan (stores plan without executing)
		orchEndpoint = "/api/v1/plan"
		log.Printf("[ROUTING] GeneratePlan request detected, routing to %s", orchEndpoint)
	case "execute-plan":
		// Route ExecutePlan requests to /api/v1/plan/execute (executes stored plan)
		orchEndpoint = "/api/v1/plan/execute"
		log.Printf("[ROUTING] ExecutePlan request detected, routing to %s", orchEndpoint)
	default:
		// Route all other requests (sql, chat, completion, embedding) to /api/v1/process
		orchEndpoint = "/api/v1/process"
	}

	// Make HTTP call to orchestrator
	orchURL := orchestratorURL + orchEndpoint
	log.Printf("🚀 Forwarding to orchestrator: %s (ClientID: %s, Type: %s)", orchURL, req.ClientID, req.RequestType)
	orchReq, err := http.NewRequest("POST", orchURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator request: %v", err)
	}
	orchReq.Header.Set("Content-Type", "application/json")
	// Forward tenant/org/client context so orchestrator handlers can access them
	if user != nil && user.TenantID != "" {
		orchReq.Header.Set("X-Tenant-ID", user.TenantID)
	}
	if client != nil {
		if client.OrgID != "" {
			orchReq.Header.Set("X-Org-ID", getDeploymentOrgID())
		}
		if (user == nil || user.TenantID == "") && client.TenantID != "" {
			orchReq.Header.Set("X-Tenant-ID", client.TenantID)
		}
	}
	resp, err := http.DefaultClient.Do(orchReq)
	if err != nil {
		log.Printf("❌ ERROR: Failed to call orchestrator at %s: %v", orchURL, err)
		return nil, fmt.Errorf("orchestrator connection failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	log.Printf("✅ Orchestrator responded with status: %d", resp.StatusCode)

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode orchestrator response: %v", err)
	}

	// Issue #1082: Return full response to preserve provider_info for cost tracking
	// The caller will extract "data" as needed, but provider_info is accessible
	return result, nil
}

func listClientsHandler(w http.ResponseWriter, r *http.Request) {
	// Mock client list
	clients := []Client{
		{
			ID:          "client_1",
			Name:        "Customer Support App",
			TenantID:    "tenant_1",
			Permissions: []string{"query", "llm"},
			RateLimit:   100,
			Enabled:     true,
		},
		{
			ID:          "client_2",
			Name:        "Healthcare Analytics",
			TenantID:    "tenant_2",
			Permissions: []string{"query", "llm", "rag"},
			RateLimit:   50,
			Enabled:     true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(clients); err != nil {
		log.Printf("Error encoding clients response: %v", err)
	}
}

func createClientHandler(w http.ResponseWriter, r *http.Request) {
	var client Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// In production, save to database
	client.Enabled = true

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(client); err != nil {
		log.Printf("Error encoding client response: %v", err)
	}
}

func policyTestHandler(w http.ResponseWriter, r *http.Request) {
	var testReq struct {
		Query       string `json:"query"`
		UserEmail   string `json:"user_email"`
		RequestType string `json:"request_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&testReq); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Derive tenant from auth context (set by apiAuthMiddleware or community default)
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "community" // default for community mode
	}
	testUser := &User{
		Email:       testReq.UserEmail,
		Role:        "agent",
		Permissions: []string{"query"},
		TenantID:    tenantID,
	}

	// Two-phase evaluation (same as proxy handler — uses shared engine as primary)
	var result *StaticPolicyResult
	gatewayDetectionCfg := GetGatewayDetectionConfig()
	sharedEngine := sharedpolicy.GetGlobalEngine()
	if !gatewayDetectionCfg.Enabled {
		result = &StaticPolicyResult{}
	} else if sharedEngine != nil {
		skipCats := append([]sharedpolicy.PolicyCategory(nil), gatewayDetectionCfg.SkipCategories...)
		if testUser.Role == "admin" {
			skipCats = append(skipCats, sharedpolicy.CategoryAdminAccess)
		}
		requestResult := sharedEngine.EvaluateRequest(r.Context(), testReq.Query, sharedpolicy.EvalOptions{
			TenantID:        testUser.TenantID,
			ConnectorName:   "proxy",
			UserID:          fmt.Sprintf("%d", testUser.ID),
			Categories:      proxyPolicyCategories,
			SkipCategories:  skipCats,
			ActionOverrides: gatewayDetectionCfg.BuildActionOverrides(),
		})
		result = convertSharedResultToStatic(requestResult)
	} else {
		log.Println("[PolicyTest] WARNING: No policy engine available")
		result = &StaticPolicyResult{}
	}

	// Phase 2: Tier-aware policies (if not blocked and engine available)
	if !result.Blocked && tierAwarePolicyEngine != nil {
		ctx := r.Context()
		tierResult, err := tierAwarePolicyEngine.EvaluatePolicy(ctx, testUser.TenantID, nil, testReq.Query)
		if err != nil {
			log.Printf("⚠️ Tier-aware policy test error: %v", err)
		} else if tierResult.Matched && tierResult.Action == "block" {
			result.Blocked = true
			result.Reason = fmt.Sprintf("Blocked by %s policy: %s", tierResult.Tier, tierResult.PolicyName)
			result.TriggeredPolicies = append(result.TriggeredPolicies, tierResult.PolicyID)
			result.Severity = tierResult.Severity
		} else if tierResult.Matched {
			result.TriggeredPolicies = append(result.TriggeredPolicies, tierResult.PolicyID)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked":            result.Blocked,
		"reason":             result.Reason,
		"triggered_policies": result.TriggeredPolicies,
		"checks_performed":   result.ChecksPerformed,
		"processing_time_ms": result.ProcessingTimeMs,
	}); err != nil {
		log.Printf("Error encoding policy test response: %v", err)
	}
}

// Utility functions
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int, policyInfo *PolicyEvaluationInfo) {
	response := ClientResponse{
		Success:    false,
		Error:      message,
		PolicyInfo: policyInfo,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}

// circuitBreakerRetryAfter computes a Retry-After value in seconds from the circuit's ExpiresAt.
// Returns empty string for indefinite/manual trips (no ExpiresAt) so the header is omitted.
func circuitBreakerRetryAfter(expiresAt *time.Time) string {
	if expiresAt == nil {
		return ""
	}
	seconds := int(time.Until(*expiresAt).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d", seconds)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getOrchestratorURL returns the Orchestrator URL based on environment.
// Priority:
// 1. ORCHESTRATOR_URL env var (explicit override, required for ECS/K8s)
// 2. Docker detection (/.dockerenv or hex hostname) → axonflow-orchestrator:8081
// 3. Fallback to localhost:8081 for local development
func getOrchestratorURL() string {
	// Check for explicit override first (required for ECS, Kubernetes, etc.)
	if envURL := os.Getenv("ORCHESTRATOR_URL"); envURL != "" {
		log.Printf("[Agent] Using ORCHESTRATOR_URL from env: %s", envURL)
		return envURL
	}
	// Auto-detect Docker Compose environments
	if isRunningInDocker() {
		log.Printf("[Agent] Docker detected, using orchestrator URL: %s", DefaultOrchestratorURL)
		return DefaultOrchestratorURL
	}
	log.Printf("[Agent] Local mode, using orchestrator URL: %s", LocalOrchestratorURL)
	return LocalOrchestratorURL
}

// isRunningInDocker detects if the process is running inside a Docker container
func isRunningInDocker() bool {
	// Method 1: Check for /.dockerenv file (most reliable)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Method 2: Check if HOSTNAME looks like a container ID (12+ hex chars)
	hostname := os.Getenv("HOSTNAME")
	if len(hostname) >= 12 {
		isHex := true
		for _, c := range hostname[:12] {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				isHex = false
				break
			}
		}
		if isHex {
			return true
		}
	}

	return false
}

func getClaimString(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getClaimStringArray(claims jwt.MapClaims, key string) []string {
	// Handle JSON array (from standard JWT)
	if arr, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	// Handle comma-separated string (legacy format)
	if val, ok := claims[key].(string); ok {
		if val == "" {
			return []string{}
		}
		return strings.Split(val, ",")
	}
	return []string{}
}

// metricsHandler returns real-time performance metrics
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Safety check for nil metrics
	if agentMetrics == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Metrics not initialized",
			"timestamp": time.Now().UTC(),
		}); err != nil {
			log.Printf("Error encoding metrics error response: %v", err)
		}
		return
	}

	agentMetrics.mu.RLock()

	// Calculate metrics
	uptime := time.Since(agentMetrics.startTime).Seconds()
	totalReqs := atomic.LoadInt64(&agentMetrics.totalRequests)
	successReqs := atomic.LoadInt64(&agentMetrics.successRequests)
	failedReqs := atomic.LoadInt64(&agentMetrics.failedRequests)
	blockedReqs := atomic.LoadInt64(&agentMetrics.blockedRequests)

	// Calculate RPS
	rps := float64(0)
	if uptime > 0 {
		rps = float64(totalReqs) / uptime
	}

	// Calculate comprehensive latency percentiles (P50, P95, P99)
	staticP50 := calculateP50(agentMetrics.staticPolicyLatencies)
	staticP95 := calculateP95(agentMetrics.staticPolicyLatencies)
	staticP99 := calculateP99(agentMetrics.staticPolicyLatencies)
	avgLatency := calculateAverage(agentMetrics.lastLatencies)

	// Overall latency percentiles
	overallP50 := calculateP50(agentMetrics.lastLatencies)
	overallP95 := calculateP95(agentMetrics.lastLatencies)
	overallP99 := calculateP99(agentMetrics.lastLatencies)

	// Calculate per-stage metrics
	authP50 := calculateP50(agentMetrics.authTimings)
	authP95 := calculateP95(agentMetrics.authTimings)
	authP99 := calculateP99(agentMetrics.authTimings)
	authAvg := calculateAverage(agentMetrics.authTimings)

	staticPolicyP50 := calculateP50(agentMetrics.staticPolicyTimings)
	staticPolicyP95 := calculateP95(agentMetrics.staticPolicyTimings)
	staticPolicyP99 := calculateP99(agentMetrics.staticPolicyTimings)
	staticPolicyAvg := calculateAverage(agentMetrics.staticPolicyTimings)

	networkP50 := calculateP50(agentMetrics.networkTimings)
	networkP95 := calculateP95(agentMetrics.networkTimings)
	networkP99 := calculateP99(agentMetrics.networkTimings)
	networkAvg := calculateAverage(agentMetrics.networkTimings)

	// Calculate error rate (errors per second over last 60 seconds)
	errorRate := calculateErrorRate(agentMetrics.errorTimestamps)

	// Success rate
	successRate := float64(100.0)
	if totalReqs > 0 {
		successRate = float64(successReqs) * 100.0 / float64(totalReqs)
	}

	// Health status determination
	isHealthy := true
	healthStatus := "healthy"
	if agentMetrics.consecutiveErrors > 5 {
		isHealthy = false
		healthStatus = "degraded"
	}
	if agentMetrics.consecutiveErrors > 10 {
		healthStatus = "unhealthy"
	}

	// Release read lock before calling methods that acquire their own locks
	errorTimestampsCopy := make([]time.Time, len(agentMetrics.errorTimestamps))
	copy(errorTimestampsCopy, agentMetrics.errorTimestamps)
	agentMetrics.mu.RUnlock()

	// Get request type and connector metrics (these methods acquire their own locks)
	requestTypeMetrics := agentMetrics.getRequestTypeMetrics()
	connectorMetrics := agentMetrics.getConnectorMetrics()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_metrics": map[string]interface{}{
			// Core counters
			"uptime_seconds":   uptime,
			"total_requests":   totalReqs,
			"success_requests": successReqs,
			"failed_requests":  failedReqs,
			"blocked_requests": blockedReqs,
			"success_rate":     successRate,
			"rps":              rps,

			// Error rate (NEW - for Grafana error rate panel)
			"error_rate_per_sec": errorRate,

			// Overall latency percentiles (NEW - complete distribution)
			"p50_ms":         overallP50,
			"p95_ms":         overallP95,
			"p99_ms":         overallP99,
			"avg_latency_ms": avgLatency,

			// Legacy static policy metrics (backward compatibility)
			"static_policy_p50_ms": staticP50,
			"static_policy_p95_ms": staticP95,
			"static_policy_p99_ms": staticP99,

			// Per-stage authentication metrics
			"auth_p50_ms": authP50,
			"auth_p95_ms": authP95,
			"auth_p99_ms": authP99,
			"auth_avg_ms": authAvg,

			// Per-stage static policy evaluation metrics
			"static_policy_eval_p50_ms": staticPolicyP50,
			"static_policy_eval_p95_ms": staticPolicyP95,
			"static_policy_eval_p99_ms": staticPolicyP99,
			"static_policy_eval_avg_ms": staticPolicyAvg,

			// Per-stage network metrics
			"network_p50_ms": networkP50,
			"network_p95_ms": networkP95,
			"network_p99_ms": networkP99,
			"network_avg_ms": networkAvg,
		},

		// Health status (NEW - for Grafana health status panel)
		"health": map[string]interface{}{
			"status":             healthStatus,
			"healthy":            isHealthy,
			"consecutive_errors": agentMetrics.consecutiveErrors,
			"up":                 1, // Always 1 if responding (for Prometheus up metric)
		},

		// Request type breakdown (NEW - for detailed analysis)
		"request_types": requestTypeMetrics,

		// Connector metrics (NEW - for per-connector dashboards)
		"connectors": connectorMetrics,

		"timestamp": time.Now().UTC(),
	}); err != nil {
		log.Printf("Error encoding metrics response: %v", err)
	}
}

// Helper function to calculate P99
func calculateP99(latencies []int64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)

	// Simple bubble sort for small arrays
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Get 99th percentile
	idx := int(float64(len(sorted)) * 0.99)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	// Return P99 in milliseconds
	return float64(sorted[idx])
}

// Helper function to calculate average
func calculateAverage(latencies []int64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	var sum int64
	for _, lat := range latencies {
		sum += lat
	}

	// Return average in milliseconds
	return float64(sum) / float64(len(latencies))
}

// calculatePercentile calculates any percentile from latencies
func calculatePercentile(latencies []int64, percentile float64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)

	// Simple sort (use sort package for larger arrays in future)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Calculate index for given percentile
	idx := int(float64(len(sorted)) * percentile)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	return float64(sorted[idx])
}

// calculateP50 calculates the 50th percentile (median)
func calculateP50(latencies []int64) float64 {
	return calculatePercentile(latencies, 0.50)
}

// calculateP95 calculates the 95th percentile
func calculateP95(latencies []int64) float64 {
	return calculatePercentile(latencies, 0.95)
}

// calculateErrorRate calculates errors per second over the last minute
func calculateErrorRate(errorTimestamps []time.Time) float64 {
	if len(errorTimestamps) == 0 {
		return 0
	}

	// Count errors in last 60 seconds
	cutoff := time.Now().Add(-60 * time.Second)
	count := 0
	for _, ts := range errorTimestamps {
		if ts.After(cutoff) {
			count++
		}
	}

	// Return errors per second
	return float64(count) / 60.0
}

// recordError records an error timestamp for error rate calculation
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordError() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errorTimestamps = append(m.errorTimestamps, time.Now())

	// Keep only last 1000 error timestamps
	if len(m.errorTimestamps) > 1000 {
		m.errorTimestamps = m.errorTimestamps[len(m.errorTimestamps)-1000:]
	}

	// Update consecutive error tracking
	m.consecutiveErrors++
}

// recordSuccess resets consecutive error counter
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveErrors = 0
}

// recordRequestTypeMetrics records metrics for a specific request type
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordRequestTypeMetrics(requestType string, latencyMs int64, success bool, blocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.requestTypeCounters == nil {
		m.requestTypeCounters = make(map[string]*RequestTypeMetrics)
	}

	if _, exists := m.requestTypeCounters[requestType]; !exists {
		m.requestTypeCounters[requestType] = &RequestTypeMetrics{
			Latencies: make([]int64, 0, 1000),
		}
	}

	rtm := m.requestTypeCounters[requestType]
	rtm.TotalRequests++

	if blocked {
		rtm.BlockedRequests++
	} else if success {
		rtm.SuccessRequests++
	} else {
		rtm.FailedRequests++
	}

	// Record latency
	rtm.Latencies = append(rtm.Latencies, latencyMs)
	if len(rtm.Latencies) > 1000 {
		rtm.Latencies = rtm.Latencies[1:]
	}
}

// recordConnectorMetrics records metrics for a specific MCP connector
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordConnectorMetrics(connector string, latencyMs int64, success bool, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connectorMetrics == nil {
		m.connectorMetrics = make(map[string]*ConnectorMetrics)
	}

	if _, exists := m.connectorMetrics[connector]; !exists {
		m.connectorMetrics[connector] = &ConnectorMetrics{
			ConnectorName: connector,
			Latencies:     make([]int64, 0, 1000),
		}
	}

	cm := m.connectorMetrics[connector]
	cm.TotalRequests++

	if success {
		cm.SuccessRequests++
	} else {
		cm.FailedRequests++
		cm.LastError = errMsg
		cm.LastErrorTime = time.Now()
	}

	// Record latency
	cm.Latencies = append(cm.Latencies, latencyMs)
	if len(cm.Latencies) > 1000 {
		cm.Latencies = cm.Latencies[1:]
	}
}

// getRequestTypeMetrics returns a map of request type metrics for export
func (m *AgentMetrics) getRequestTypeMetrics() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]map[string]interface{})

	for name, rtm := range m.requestTypeCounters {
		successRate := float64(100.0)
		if rtm.TotalRequests > 0 {
			successRate = float64(rtm.SuccessRequests) * 100.0 / float64(rtm.TotalRequests)
		}

		result[name] = map[string]interface{}{
			"total_requests":   rtm.TotalRequests,
			"success_requests": rtm.SuccessRequests,
			"failed_requests":  rtm.FailedRequests,
			"blocked_requests": rtm.BlockedRequests,
			"success_rate":     successRate,
			"p50_ms":           calculateP50(rtm.Latencies),
			"p95_ms":           calculateP95(rtm.Latencies),
			"p99_ms":           calculateP99(rtm.Latencies),
			"avg_ms":           calculateAverage(rtm.Latencies),
		}
	}

	return result
}

// getConnectorMetrics returns a map of connector metrics for export
func (m *AgentMetrics) getConnectorMetrics() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]map[string]interface{})

	for name, cm := range m.connectorMetrics {
		successRate := float64(100.0)
		if cm.TotalRequests > 0 {
			successRate = float64(cm.SuccessRequests) * 100.0 / float64(cm.TotalRequests)
		}

		result[name] = map[string]interface{}{
			"total_requests":   cm.TotalRequests,
			"success_requests": cm.SuccessRequests,
			"failed_requests":  cm.FailedRequests,
			"success_rate":     successRate,
			"p50_ms":           calculateP50(cm.Latencies),
			"p95_ms":           calculateP95(cm.Latencies),
			"p99_ms":           calculateP99(cm.Latencies),
			"avg_ms":           calculateAverage(cm.Latencies),
			"last_error":       cm.LastError,
			"last_error_time":  cm.LastErrorTime,
		}
	}

	return result
}

// maskString masks a string for logging (shows first 8 chars and last 4)
func maskString(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= 12 {
		return s[:4] + "***"
	}
	return s[:8] + "..." + s[len(s)-4:]
}

// truncateString truncates a string for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getStringLength(v interface{}) int {
	if v == nil {
		return 0
	}
	if str, ok := v.(string); ok {
		return len(str)
	}
	return -1
}

func getKeys(m map[string]interface{}) []string {
	if m == nil {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// encodePostgreSQLPassword manually parses a PostgreSQL URL and encodes the password
// This is necessary because CloudFormation resolves Secrets Manager passwords without URL encoding,
// and special characters in passwords (like ;, <, >, &, etc.) cause url.Parse() to fail.
//
// PostgreSQL URL format: postgresql://username:password@host:port/database?params
//
// We cannot use url.Parse() directly because it fails when the password contains unencoded special chars.
// Instead, we manually extract the password, encode it, and reconstruct the URL.
//
//nolint:unused // Used in tests
func encodePostgreSQLPassword(dbURL string) string {
	// Find the scheme end (://)
	schemeEnd := strings.Index(dbURL, "://")
	if schemeEnd == -1 {
		log.Printf("⚠️  Database URL missing scheme (://), using as-is")
		return dbURL
	}

	// Extract scheme (postgresql)
	scheme := dbURL[:schemeEnd+3] // Include ://

	// Find the @ that separates userinfo from host
	atIndex := strings.Index(dbURL[schemeEnd+3:], "@")
	if atIndex == -1 {
		log.Printf("⚠️  Database URL missing @ separator, using as-is")
		return dbURL
	}
	atIndex += schemeEnd + 3 // Adjust for offset

	// Extract userinfo (username:password)
	userInfo := dbURL[schemeEnd+3 : atIndex]

	// Find the : that separates username from password
	colonIndex := strings.Index(userInfo, ":")
	if colonIndex == -1 {
		// No password, just username
		log.Println("✓ Database URL has no password, no encoding needed")
		return dbURL
	}

	// Extract username and password
	username := userInfo[:colonIndex]
	password := userInfo[colonIndex+1:]

	// Extract everything after @
	hostAndRest := dbURL[atIndex+1:]

	// Use url.UserPassword() for proper userinfo encoding
	// This is the CORRECT way to encode passwords for username:password@host URLs
	// url.QueryEscape() is WRONG - it's for query parameters, not userinfo
	userPassword := url.UserPassword(username, password)
	encodedUserInfo := userPassword.String()

	// Reconstruct the URL
	reconstructed := scheme + encodedUserInfo + "@" + hostAndRest

	log.Printf("✓ Database URL password encoded using url.UserPassword() (%d chars → %d chars)",
		len(password), len(encodedUserInfo))

	return reconstructed
}
