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

	"axonflow/platform/agent/license"
	"axonflow/platform/agent/marketplace"
	"axonflow/platform/agent/node_enforcement"
	"axonflow/platform/common/usage"
)

// AxonFlow Agent - Authentication, Authorization & Static Policy Enforcement Gateway
// This service sits between clients and the AxonFlow Orchestrator

// Configuration
var (
	jwtSecret          = []byte(os.Getenv("JWT_SECRET"))
	orchestratorURL    = getEnv("ORCHESTRATOR_URL", "http://localhost:8081")
	authDB             *sql.DB // Database for Option 3 authentication
	usageDB            *sql.DB // Database for usage metering
	staticPolicyEngine *StaticPolicyEngine
	dbPolicyEngine     *DatabasePolicyEngine
	meteringService    *marketplace.MeteringService // AWS Marketplace metering
)

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
}

type ClientResponse struct {
	Success     bool                   `json:"success"`
	Data        interface{}            `json:"data,omitempty"`
	Result      string                 `json:"result,omitempty"`   // For multi-agent planning - MUST match SDK type
	PlanID      string                 `json:"plan_id,omitempty"`  // For multi-agent planning
	Metadata    map[string]interface{} `json:"metadata,omitempty"` // For multi-agent planning - MUST match SDK type
	Error       string                 `json:"error,omitempty"`
	Blocked     bool                   `json:"blocked"`
	BlockReason string                 `json:"block_reason,omitempty"`
	PolicyInfo  *PolicyEvaluationInfo  `json:"policy_info,omitempty"`
}

type PolicyEvaluationInfo struct {
	PoliciesEvaluated []string `json:"policies_evaluated"`
	StaticChecks      []string `json:"static_checks"`
	ProcessingTime    string   `json:"processing_time"`
	TenantID          string   `json:"tenant_id"`
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

// Client represents registered client application
type Client struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	OrgID         string    `json:"org_id"` // Organization ID for usage tracking
	TenantID      string    `json:"tenant_id"`
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
		"status":    status,
		"service":   "axonflow-agent",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
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

	// License validation (optional for central agent deployments and self-hosted mode)
	// Central agents validate CLIENT license keys during request processing
	// Self-hosted mode skips license validation entirely (for OSS/local development)
	// This validation is only needed for customer-deployed agents
	selfHostedMode := os.Getenv("SELF_HOSTED_MODE") == "true"
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")

	if selfHostedMode {
		log.Println("🏠 SELF_HOSTED_MODE enabled - skipping license validation")
		log.Println("   Perfect for OSS contributors and local development")
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

		log.Printf("✅ License validated successfully")
		log.Printf("   Tier: %s", result.Tier)
		log.Printf("   Max Nodes: %d", result.MaxNodes)
		log.Printf("   Expires: %s", result.ExpiresAt.Format("2006-01-02"))

		if result.DaysUntilExpiry <= 30 {
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

	// Try to initialize database policy engine first
	dbEngine, err := NewDatabasePolicyEngine()
	if err != nil {
		log.Printf("Failed to initialize database policy engine: %v", err)
		log.Println("Falling back to static policy engine")
		staticPolicyEngine = NewStaticPolicyEngine()
	} else {
		dbPolicyEngine = dbEngine
		log.Println("AxonFlow Agent initialized with database-backed policy enforcement")
		defer func() { _ = dbPolicyEngine.Close() }()

		// Recover any failed audit entries from fallback file
		// This ensures compliance audit trails are not lost even after crashes
		if recovered, err := dbPolicyEngine.RecoverAuditEntries(); err != nil {
			log.Printf("⚠️ Failed to recover audit entries: %v", err)
		} else if recovered > 0 {
			log.Printf("✅ Recovered %d audit entries from fallback file", recovered)
		}
	}

	// Initialize Option 3 authentication database
	if dbURL != "" {
		authDB, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Fatalf("Failed to connect to authentication database: %v", err)
		}
		defer func() { _ = authDB.Close() }()

		// Test connection
		if err := authDB.Ping(); err != nil {
			log.Fatalf("Failed to ping authentication database: %v", err)
		}
		log.Println("✅ Authentication database connected (Option 3)")

		// Use same database for usage metering
		usageDB = authDB
		log.Println("✅ Usage metering database connected")

		// Initialize AWS Marketplace metering (if enabled)
		if os.Getenv("ENABLE_MARKETPLACE_METERING") == "true" {
			productCode := os.Getenv("MARKETPLACE_PRODUCT_CODE")
			if productCode == "" {
				log.Fatal("❌ MARKETPLACE_PRODUCT_CODE required when ENABLE_MARKETPLACE_METERING=true")
			}

			var err error
			meteringService, err = marketplace.NewMeteringService(authDB, productCode)
			if err != nil {
				log.Fatalf("❌ Failed to create AWS Marketplace metering service: %v", err)
			}

			ctx := context.Background()
			if err := meteringService.Start(ctx); err != nil {
				log.Printf("⚠️  Failed to start AWS Marketplace metering: %v", err)
			} else {
				log.Println("✅ AWS Marketplace metering service started")
			}
		}

		// Initialize Redis for distributed rate limiting
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
	} else {
		log.Println("ℹ️  DATABASE_URL not set - Option 3 disabled, using Option 2 whitelist")
		log.Println("⚠️  Usage metering disabled - DATABASE_URL required")
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

	// Initialize MCP connector registry
	if err := InitializeMCPRegistry(); err != nil {
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

	// Policy testing endpoint for debugging
	globalRouter.HandleFunc("/api/policies/test", policyTestHandler).Methods("POST")

	// Register MCP connector endpoints
	RegisterMCPHandlers(globalRouter)

	// Register Gateway Mode endpoints (pre-check and audit)
	RegisterGatewayHandlers(globalRouter)

	// Mark application as ready - /health will now return "healthy"
	appReady.Store(true)
	log.Println("✅ All initialization complete - application ready")
	log.Printf("🚀 AxonFlow Agent fully operational on port %s", port)

	// Block forever - server is running in goroutine, nothing else to do
	select {}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"service":   "axonflow-agent",
		"timestamp": time.Now().UTC(),
		"version":   "1.0.0",
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

func clientRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	atomic.AddInt64(&agentMetrics.totalRequests, 1)

	// Log incoming request with headers
	log.Printf("📨 Incoming request from %s - Method: %s, Path: %s", r.RemoteAddr, r.Method, r.URL.Path)
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
		req.ClientID, req.RequestType, truncateString(req.Query, 50))

	// 1. Validate client authentication
	validateClientStart := time.Now()

	// Check if running in self-hosted mode (no license validation)
	selfHostedMode := os.Getenv("SELF_HOSTED_MODE") == "true"

	var client *Client
	var err error

	if selfHostedMode {
		log.Printf("🏠 Self-hosted mode: Skipping authentication for client '%s'", req.ClientID)
		// Create a dummy client for self-hosted deployments
		client = &Client{
			ID:          req.ClientID,
			Name:        "Self-Hosted",
			OrgID:       "self-hosted",
			TenantID:    req.ClientID,
			Enabled:     true,
			LicenseTier: "OSS",
			RateLimit:   0,
			Permissions: []string{},
		}
	} else {
		// Production mode: Validate license key
		licenseKey := r.Header.Get("X-License-Key")
		if licenseKey == "" {
			log.Printf("❌ Missing X-License-Key header")
			sendErrorResponse(w, "X-License-Key header required", http.StatusUnauthorized, nil)
			return
		}
		log.Printf("🔐 Validating license for client '%s' with key '%s...'", req.ClientID, maskString(licenseKey))

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Use Option 3 (database-backed) if available, otherwise Option 2 (whitelist)
		if authDB != nil {
			client, err = validateClientLicenseDB(ctx, authDB, req.ClientID, licenseKey)
		} else {
			client, err = validateClientLicense(ctx, req.ClientID, licenseKey)
		}
		if err != nil {
			log.Printf("❌ License validation failed for client '%s': %v", req.ClientID, err)
			sendErrorResponse(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized, nil)
			return
		}
		log.Printf("✅ License validated successfully for client '%s' (Tier: %s)", client.ID, client.LicenseTier)
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
		sendErrorResponse(w, "Invalid user token", http.StatusUnauthorized, nil)
		return
	}

	validateUserTime := time.Since(validateUserStart)
	log.Printf("[TIMING] User token validation: %v", validateUserTime)

	// 3. Verify tenant isolation
	tenantCheckStart := time.Now()
	log.Printf("🔍 Checking tenant isolation: User TenantID='%s', Client TenantID='%s'", user.TenantID, client.TenantID)
	if user.TenantID != client.TenantID {
		log.Printf("❌ TENANT MISMATCH: User TenantID='%s' does not match Client TenantID='%s'", user.TenantID, client.TenantID)
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}
	tenantCheckTime := time.Since(tenantCheckStart)
	log.Printf("✅ Tenant isolation check passed")
	log.Printf("[TIMING] Tenant isolation check: %v", tenantCheckTime)

	// 4. Apply static policy enforcement (use DB engine if available)
	policyEvalStart := time.Now()
	log.Printf("📋 Evaluating static policies for request type: %s", req.RequestType)
	var policyResult *StaticPolicyResult
	if dbPolicyEngine != nil {
		policyResult = dbPolicyEngine.EvaluateStaticPolicies(user, req.Query, req.RequestType)
	} else {
		policyResult = staticPolicyEngine.EvaluateStaticPolicies(user, req.Query, req.RequestType)
	}
	policyEvalTime := time.Since(policyEvalStart)
	log.Printf("✅ Policy evaluation complete: Blocked=%v, TriggeredPolicies=%d", policyResult.Blocked, len(policyResult.TriggeredPolicies))
	log.Printf("[TIMING] Policy evaluation: %v", policyEvalTime)

	if policyResult.Blocked {
		log.Printf("Request blocked by static policy for user %s: %s", user.Email, policyResult.Reason)

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

	// Rate limiting is now handled inside validateClientLicense() during authentication
	rateLimitTime := time.Duration(0)

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
		sendErrorResponse(w, "Orchestrator error: "+err.Error(), http.StatusInternalServerError, nil)
		return
	}

	// Track successful request
	if agentMetrics != nil {
		atomic.AddInt64(&agentMetrics.successRequests, 1)
		latencyMs := int64(time.Since(startTime).Milliseconds())
		agentMetrics.recordLatency(latencyMs, "dynamic")
	}

	// Record Prometheus metrics
	promRequestsTotal.WithLabelValues("success").Inc()
	promPolicyEvaluations.Inc()
	promRequestDuration.WithLabelValues("dynamic").Observe(float64(time.Since(startTime).Milliseconds()))

	// 7. Return response with policy information
	response := ClientResponse{
		Success: true,
		Data:    orchestratorResp,
		PolicyInfo: &PolicyEvaluationInfo{
			PoliciesEvaluated: policyResult.TriggeredPolicies,
			StaticChecks:      policyResult.ChecksPerformed,
			ProcessingTime:    time.Since(startTime).String(),
			TenantID:          user.TenantID,
		},
	}

	// For multi-agent planning requests, flatten orchestrator response fields to top level
	// This allows client SDKs to access plan_id, result, metadata directly
	if req.RequestType == "multi-agent-plan" {
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
				HTTPStatusCode: 200, // Success if we got here
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
		TenantID:    "tenant_1",
		Permissions: []string{"query", "llm"},
		RateLimit:   100,
		Enabled:     true,
	}, nil
}

func validateUserToken(tokenString string, expectedTenantID string) (*User, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("token required")
	}

	// Test mode: Tenant mismatch test token - user from trip_planner_tenant
	if strings.HasPrefix(tokenString, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoy") {
		testTenantID := "trip_planner_tenant" // Fixed user tenant for mismatch testing
		log.Printf("Using test mode (mismatch) token validation with tenant_id: %s", testTenantID)
		return &User{
			ID:          2, // Different user ID for mismatch scenarios
			Email:       "tenant_test@example.com",
			Name:        "Tenant Test User",
			Role:        "agent",
			Region:      "us_west",
			Permissions: []string{"query", "basic_pii"},
			TenantID:    testTenantID, // Fixed for mismatch testing
		}, nil
	}

	// Test mode: Normal test token - user from same tenant as client
	if strings.HasPrefix(tokenString, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox") {
		log.Printf("Using test mode token validation with tenant_id: %s", expectedTenantID)
		return &User{
			ID:          1,
			Email:       "test@example.com",
			Name:        "Test User",
			Role:        "agent",
			Region:      "us_west",
			Permissions: []string{"query", "basic_pii"},
			TenantID:    expectedTenantID, // Uses client's tenant for same-tenant tests
		}, nil
	}

	// Test mode: Demo user token with MCP permissions - for demo clients (trip planner, healthcare, etc.)
	if strings.HasPrefix(tokenString, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZGVtby10cmF2ZWxlci0xIi") {
		log.Printf("Using demo user token validation with tenant_id: %s", expectedTenantID)
		return &User{
			ID:          999, // Demo user ID
			Email:       "demo@example.com",
			Name:        "Demo Traveler",
			Role:        "user",
			Region:      "eu",
			Permissions: []string{"query", "llm", "mcp_query", "amadeus"}, // Full MCP permissions
			TenantID:    expectedTenantID,                                 // Uses client's tenant (travel-eu, healthcare-eu, etc.)
		}, nil
	}

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

	return &User{
		ID:          int(claims["user_id"].(float64)),
		Email:       claims["email"].(string),
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
	orchestratorReq := map[string]interface{}{
		"query":        req.Query,
		"user":         user,
		"client":       client,
		"request_type": req.RequestType,
		"skip_llm":     req.SkipLLM,
		"context":      req.Context,
		"request_id":   fmt.Sprintf("req_%d", time.Now().UnixNano()),
	}

	jsonData, err := json.Marshal(orchestratorReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Determine orchestrator endpoint based on request type
	var orchEndpoint string
	switch req.RequestType {
	case "multi-agent-plan":
		// Route multi-agent planning requests to /api/v1/plan
		orchEndpoint = "/api/v1/plan"
		log.Printf("[ROUTING] Multi-agent planning request detected, routing to %s", orchEndpoint)
	default:
		// Route all other requests (sql, chat, completion, embedding) to /api/v1/process
		orchEndpoint = "/api/v1/process"
	}

	// Make HTTP call to orchestrator
	orchURL := orchestratorURL + orchEndpoint
	log.Printf("🚀 Forwarding to orchestrator: %s (ClientID: %s, Type: %s)", orchURL, req.ClientID, req.RequestType)
	resp, err := http.Post(orchURL, "application/json", bytes.NewBuffer(jsonData))
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

	// Extract the data field from orchestrator response
	if data, ok := result["data"]; ok {
		return data, nil
	}

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

	// Mock user for testing
	testUser := &User{
		Email:       testReq.UserEmail,
		Role:        "agent",
		Permissions: []string{"query"},
		TenantID:    "tenant_1",
	}

	// Use DB engine if available for testing
	var result *StaticPolicyResult
	if dbPolicyEngine != nil {
		result = dbPolicyEngine.EvaluateStaticPolicies(testUser, testReq.Query, testReq.RequestType)
	} else {
		result = staticPolicyEngine.EvaluateStaticPolicies(testUser, testReq.Query, testReq.RequestType)
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

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getClaimString(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getClaimStringArray(claims jwt.MapClaims, key string) []string {
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
func (m *AgentMetrics) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveErrors = 0
}

// recordRequestTypeMetrics records metrics for a specific request type
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
