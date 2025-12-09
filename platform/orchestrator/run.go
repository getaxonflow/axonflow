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
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq" // PostgreSQL driver
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"axonflow/platform/agent/node_enforcement"
)

// AxonFlow Orchestrator - Dynamic Policy Enforcement & LLM Routing Engine
// This service handles intelligent request routing and response processing

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const (
	ctxKeyRequestID contextKey = "request_id"
	ctxKeyUser      contextKey = "user"
	ctxKeyClient    contextKey = "client"
)

// Configuration
var (
	dynamicPolicyEngine interface {
		EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
		ListActivePolicies() []DynamicPolicy
		IsHealthy() bool
	}
	llmRouter          *LLMRouter
	responseProcessor  *ResponseProcessor
	auditLogger        *AuditLogger
	metricsCollector   *MetricsCollector
	workflowEngine     *WorkflowEngine
	planningEngine     *PlanningEngine                    // Multi-Agent Planning v0.1
	resultAggregator   *ResultAggregator                  // Multi-Agent Planning v0.1
	mcpQueryRouter     *MCPQueryRouter                    // MCP query routing to agent
	agentMCPEndpoint   string                             // Agent MCP handler endpoint
	usageDB            *sql.DB                            // Database for usage metering
	heartbeatService   *node_enforcement.HeartbeatService // Node enforcement
	nodeMonitor        *node_enforcement.NodeMonitor      // Node enforcement
	policyAPIHandler   *PolicyAPIHandler                  // Policy CRUD API handler
	templateAPIHandler *TemplateAPIHandler                // Policy Templates API handler
)

// Per-stage metrics (similar to Agent)
type OrchestratorMetrics struct {
	mu                   sync.RWMutex
	dynamicPolicyTimings []int64 // Dynamic policy evaluation time
	llmTimings           []int64 // LLM routing + inference time
	startTime            time.Time

	// Request counters
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	blockedRequests int64

	// Error tracking for error rate calculation
	errorTimestamps []time.Time

	// Health status tracking
	healthCheckPassed bool
	consecutiveErrors int64

	// Per-request-type metrics
	requestTypeMetrics map[string]*RequestTypeOrchestratorMetrics

	// Per-LLM-provider metrics
	providerMetrics map[string]*LLMProviderMetrics
}

// RequestTypeOrchestratorMetrics tracks metrics per request type
type RequestTypeOrchestratorMetrics struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	BlockedRequests int64
	Latencies       []int64
}

// LLMProviderMetrics tracks metrics per LLM provider
type LLMProviderMetrics struct {
	ProviderName string
	TotalCalls   int64
	SuccessCalls int64
	FailedCalls  int64
	TotalTokens  int64
	TotalCost    float64
	Latencies    []int64
}

var orchestratorMetrics *OrchestratorMetrics

// Prometheus metrics
var (
	promRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_orchestrator_requests_total",
			Help: "Total number of requests processed by the orchestrator",
		},
		[]string{"status"},
	)
	promRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_orchestrator_request_duration_milliseconds",
			Help:    "Request duration in milliseconds",
			Buckets: []float64{10, 50, 100, 200, 500, 1000, 2000, 5000, 10000},
		},
		[]string{"type"},
	)
	promPolicyEvaluations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_orchestrator_policy_evaluations_total",
			Help: "Total number of dynamic policy evaluations",
		},
	)
	promBlockedRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_orchestrator_blocked_requests_total",
			Help: "Total number of blocked requests by dynamic policies",
		},
	)
	promLLMCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_orchestrator_llm_calls_total",
			Help: "Total number of LLM API calls",
		},
		[]string{"provider", "status"},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(promRequestsTotal)
	prometheus.MustRegister(promRequestDuration)
	prometheus.MustRegister(promPolicyEvaluations)
	prometheus.MustRegister(promBlockedRequests)
	prometheus.MustRegister(promLLMCalls)
}

// Request structures
type OrchestratorRequest struct {
	RequestID   string                 `json:"request_id"`
	Query       string                 `json:"query"`
	RequestType string                 `json:"request_type"`
	SkipLLM     bool                   `json:"skip_llm,omitempty"` // Skip LLM calls for hourly tests
	User        UserContext            `json:"user"`
	Client      ClientContext          `json:"client"`
	Context     map[string]interface{} `json:"context"`
	Timestamp   time.Time              `json:"timestamp"`
}

type UserContext struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"tenant_id"`
}

type ClientContext struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	OrgID    string `json:"org_id"` // Organization ID for usage tracking
	TenantID string `json:"tenant_id"`
}

type OrchestratorResponse struct {
	RequestID      string                  `json:"request_id"`
	Success        bool                    `json:"success"`
	Data           interface{}             `json:"data,omitempty"`
	Error          string                  `json:"error,omitempty"`
	Redacted       bool                    `json:"redacted"`
	RedactedFields []string                `json:"redacted_fields,omitempty"`
	PolicyInfo     *PolicyEvaluationResult `json:"policy_info"`
	ProviderInfo   *ProviderInfo           `json:"provider_info"`
	ProcessingTime string                  `json:"processing_time"`
}

type PolicyEvaluationResult struct {
	Allowed          bool     `json:"allowed"`
	AppliedPolicies  []string `json:"applied_policies"`
	RiskScore        float64  `json:"risk_score"`
	RequiredActions  []string `json:"required_actions"`
	ProcessingTimeMs int64    `json:"processing_time_ms"`
	DatabaseAccessed bool     `json:"database_accessed,omitempty"`
}

type ProviderInfo struct {
	Provider       string  `json:"provider"`
	Model          string  `json:"model"`
	ResponseTimeMs int64   `json:"response_time_ms"`
	TokensUsed     int     `json:"tokens_used,omitempty"`
	Cost           float64 `json:"cost,omitempty"`
}

// LoadLLMConfig loads LLM configuration from environment with hierarchy
// Hierarchy: environment-specific env vars > generic env vars > CloudFormation defaults
func LoadLLMConfig() LLMRouterConfig {
	config := LLMRouterConfig{}

	// OpenAI configuration
	config.OpenAIKey = os.Getenv("OPENAI_API_KEY")

	// Anthropic configuration
	config.AnthropicKey = os.Getenv("ANTHROPIC_API_KEY")

	// Bedrock configuration
	// Allow environment-specific overrides (e.g., BEDROCK_REGION_PROD)
	config.BedrockRegion = os.Getenv("BEDROCK_REGION")
	config.BedrockModel = os.Getenv("BEDROCK_MODEL")

	// Ollama configuration
	config.OllamaEndpoint = os.Getenv("OLLAMA_ENDPOINT")
	config.OllamaModel = os.Getenv("OLLAMA_MODEL")

	// Backward compatibility: LocalEndpoint
	if config.OllamaEndpoint == "" {
		config.LocalEndpoint = os.Getenv("LOCAL_LLM_ENDPOINT")
	}

	log.Printf("[LLM Config] Loaded provider configuration:")
	if config.OpenAIKey != "" {
		log.Printf("  - OpenAI: enabled (key: %s...)", config.OpenAIKey[:min(10, len(config.OpenAIKey))])
	}
	if config.AnthropicKey != "" {
		log.Printf("  - Anthropic: enabled (key: %s...)", config.AnthropicKey[:min(10, len(config.AnthropicKey))])
	}
	if config.BedrockRegion != "" {
		log.Printf("  - Bedrock: enabled (region: %s, model: %s)", config.BedrockRegion, config.BedrockModel)
	}
	if config.OllamaEndpoint != "" {
		log.Printf("  - Ollama: enabled (endpoint: %s, model: %s)", config.OllamaEndpoint, config.OllamaModel)
	}
	if config.LocalEndpoint != "" && config.OllamaEndpoint == "" {
		log.Printf("  - Local LLM: enabled (endpoint: %s) [deprecated: use OLLAMA_ENDPOINT]", config.LocalEndpoint)
	}

	return config
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Run is the exported entry point for the orchestrator service.
//
// It initializes all components (database, LLM providers, policy engine),
// sets up HTTP routes, and starts the server. The function blocks until
// the server is shut down.
//
// Environment variables used:
//   - PORT: HTTP server port (default: 8081)
//   - DATABASE_URL: PostgreSQL connection string
//   - OPENAI_API_KEY: OpenAI API key (optional)
//   - BEDROCK_REGION: AWS Bedrock region (optional)
//   - OLLAMA_ENDPOINT: Ollama endpoint URL (optional)
func Run() {
	log.Println("Starting AxonFlow Orchestrator...")

	// Initialize components
	initializeComponents()

	// Cleanup node enforcement on shutdown
	if heartbeatService != nil {
		defer heartbeatService.Stop()
	}
	if nodeMonitor != nil {
		defer nodeMonitor.Stop()
	}

	// Setup router
	r := mux.NewRouter()

	// CORS middleware
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Configure for production
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	// Health check
	r.HandleFunc("/health", healthHandler).Methods("GET")

	// Metrics endpoints
	r.HandleFunc("/metrics", simpleMetricsHandler).Methods("GET") // JSON metrics (legacy)
	r.Handle("/prometheus", promhttp.Handler()).Methods("GET")    // Prometheus native format

	// Main processing endpoint
	r.HandleFunc("/api/v1/process", processRequestHandler).Methods("POST")

	// Provider management
	r.HandleFunc("/api/v1/providers/status", providerStatusHandler).Methods("GET")
	r.HandleFunc("/api/v1/providers/weights", updateProviderWeightsHandler).Methods("PUT")

	// Dynamic policy endpoints
	r.HandleFunc("/api/v1/policies/dynamic", listDynamicPoliciesHandler).Methods("GET")
	r.HandleFunc("/api/v1/policies/test", testPolicyHandler).Methods("POST")

	// Metrics and monitoring
	r.HandleFunc("/api/v1/metrics", metricsHandler).Methods("GET")
	r.HandleFunc("/api/v1/audit/search", auditSearchHandler).Methods("POST")
	r.HandleFunc("/api/v1/audit/tenant/{tenant_id}", tenantAuditLogsHandler).Methods("GET")

	// Workflow endpoints
	r.HandleFunc("/api/v1/workflows/executions/tenant/{tenant_id}", tenantWorkflowExecutionsHandler).Methods("GET")
	r.HandleFunc("/api/v1/workflows/execute", executeWorkflowHandler).Methods("POST")
	r.HandleFunc("/api/v1/workflows/executions/{id}", getWorkflowExecutionHandler).Methods("GET")
	r.HandleFunc("/api/v1/workflows/executions", listWorkflowExecutionsHandler).Methods("GET")

	// Multi-Agent Planning endpoint (v0.1)
	r.HandleFunc("/api/v1/plan", planRequestHandler).Methods("POST")

	// MCP Connector Marketplace endpoints (v0.2)
	r.HandleFunc("/api/v1/connectors", listConnectorsHandler).Methods("GET")
	r.HandleFunc("/api/v1/connectors/{id}", getConnectorDetailsHandler).Methods("GET")
	r.HandleFunc("/api/v1/connectors/{id}/install", installConnectorHandler).Methods("POST")
	r.HandleFunc("/api/v1/connectors/{id}/uninstall", uninstallConnectorHandler).Methods("DELETE")
	r.HandleFunc("/api/v1/connectors/{id}/health", connectorHealthCheckHandler).Methods("GET")

	// Policy Management CRUD API (Track A - Policy Enforcement)
	// These endpoints use http.ServeMux pattern - adapt for gorilla/mux
	r.HandleFunc("/api/v1/policies", policyAPIListCreateHandler).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/api/v1/policies/import", policyAPIImportHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/policies/export", policyAPIExportHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/policies/{id}", policyAPIGetUpdateDeleteHandler).Methods("GET", "PUT", "DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/policies/{id}/test", policyAPITestHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/policies/{id}/versions", policyAPIVersionsHandler).Methods("GET", "OPTIONS")

	// Policy Templates API (Track D - Policy Templates)
	r.HandleFunc("/api/v1/templates", templateAPIListHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/templates/categories", templateAPICategoriesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/templates/stats", templateAPIStatsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/templates/{id}", templateAPIGetHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/templates/{id}/apply", templateAPIApplyHandler).Methods("POST", "OPTIONS")

	// Start server
	port := getEnv("PORT", "8081")
	handler := c.Handler(r)
	log.Printf("AxonFlow Orchestrator listening on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func initializeComponents() {
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

		// NOTE: Database migrations are handled by Agent only
		// Orchestrator should NOT run migrations because:
		// 1. Agent has proper migration tracking (schema_migrations table)
		// 2. Agent sets required session variable (app.db_password for migration 017 dblink)
		// 3. Running migrations from both Agent and Orchestrator causes race conditions
		// 4. Some migrations (e.g., 017_grafana_database.sql) require session variables that Orchestrator doesn't provide
		//
		// Migration execution disabled: 2025-11-19
		// Previously caused: Migration 017 failed with "pq: password is required" because Orchestrator
		// doesn't set app.db_password session variable for dblink authentication
		log.Println("ℹ️  Database migrations handled by Agent (Orchestrator skips migrations)")

		/* DISABLED - migrations run by Agent only
		log.Println("Running database migrations...")
		migrationsPath := "/app/migrations/"

		// Simple SQL file execution (no golang-migrate dependency)
		// Read all .sql files in order
		files, err := filepath.Glob(filepath.Join(migrationsPath, "*.sql"))
		if err != nil {
			log.Printf("⚠️  Failed to list migration files: %v (continuing anyway)", err)
		} else if len(files) == 0 {
			log.Println("ℹ️  No migration files found")
		} else {
			// Sort files alphabetically (001_, 002_, etc.)
			sort.Strings(files)

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
				log.Printf("⚠️  Database migrations skipped. Orchestrator will continue but may have incomplete schema.")
			}

			if err == nil {
				defer func() { _ = migrationDB.Close() }()

				successCount := 0
				for _, file := range files {
					sqlBytes, err := os.ReadFile(file)
					if err != nil {
						log.Printf("⚠️  Failed to read migration %s: %v", filepath.Base(file), err)
						continue
					}

					_, err = migrationDB.Exec(string(sqlBytes))
					if err != nil {
						// Log error but continue (migrations may be idempotent)
						log.Printf("⚠️  Migration %s execution warning: %v", filepath.Base(file), err)
					} else {
						successCount++
					}
				}

				log.Printf("✅ Database migrations completed (%d/%d files processed)", successCount, len(files))
			}
		}
		*/ // End of disabled migration block

		// SECURITY: Don't log DATABASE_URL contents as it may contain credentials
		log.Printf("DATABASE_URL is set (length: %d chars)", len(dbURL))

		// Initialize usage metering database connection
		var err error
		usageDB, err = sql.Open("postgres", dbURL)
		if err != nil {
			log.Printf("Warning: Failed to connect to usage database: %v", err)
			log.Println("Usage metering will be disabled")
		} else if err := usageDB.Ping(); err != nil {
			log.Printf("Warning: Failed to ping usage database: %v", err)
			log.Println("Usage metering will be disabled")
			usageDB = nil
		} else {
			log.Println("✅ Usage metering database connected")
		}
	} else {
		log.Println("WARNING: DATABASE_URL environment variable is NOT set!")
		log.Println("⚠️  Usage metering disabled - DATABASE_URL required")
	}

	// Initialize node enforcement (heartbeat + monitoring)
	if usageDB != nil {
		// Determine instance ID and type
		instanceID := os.Getenv("HOSTNAME") // Docker container ID
		if instanceID == "" {
			log.Println("HOSTNAME not set, using default instance ID")
		}
		instanceType := "orchestrator"

		// Get license key and orgID from environment
		licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
		orgID := os.Getenv("ORG_ID")

		if orgID != "" {
			// Customer-deployed orchestrator mode - enable heartbeat
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
		} else {
			// Central orchestrator mode - skip heartbeat
			log.Println("ℹ️  ORG_ID not set - skipping node enforcement (central mode)")
		}
	}

	// Initialize RuntimeConfigService for ADR-007 three-tier config
	// Priority: Database > Config File > Env Vars
	selfHosted := os.Getenv("AXONFLOW_SELF_HOSTED") == "true"
	InitRuntimeConfigService(usageDB, selfHosted)
	log.Println("RuntimeConfigService initialized (ADR-007 compliant)")

	// Wire config file loader for Priority 2 (OSS config file support)
	// Checks AXONFLOW_CONFIG_FILE or AXONFLOW_LLM_CONFIG_FILE env vars
	SetConfigFileLoaderFromEnv() // Logs its own success/failure messages

	// Initialize Dynamic Policy Engine (try database-backed first)
	dbEngine, err := NewDatabaseDynamicPolicyEngine()
	if err != nil {
		log.Printf("Failed to initialize database-backed dynamic policy engine: %v", err)
		log.Println("Falling back to in-memory dynamic policy engine")
		dynamicPolicyEngine = NewDynamicPolicyEngine()
		log.Println("Dynamic Policy Engine initialized (in-memory)")
	} else {
		dynamicPolicyEngine = dbEngine
		log.Println("Dynamic Policy Engine initialized with DATABASE backing ✅")
	}

	// Initialize LLM Router using RuntimeConfigService (ADR-007)
	// Falls back to env vars if database not available
	ctx := context.Background()
	tenantID := os.Getenv("ORG_ID") // Use org ID as tenant ID
	if tenantID == "" {
		tenantID = "default" // Fallback for single-tenant deployments
	}
	SetLLMRouter(NewLLMRouter(LoadLLMConfigFromService(ctx, tenantID)))
	log.Println("LLM Router initialized with multi-provider support (ADR-007 compliant)")

	// Initialize Amadeus API Client
	amadeusClient := NewAmadeusClient()
	if amadeusClient.IsConfigured() {
		log.Println("Amadeus API Client initialized and configured ✅")
	} else {
		log.Println("Amadeus API Client initialized (not configured - will use mock data)")
	}

	// Initialize Response Processor
	responseProcessor = NewResponseProcessor()
	log.Println("Response Processor initialized with PII detection")

	// Initialize Audit Logger
	auditLogger = NewAuditLogger(os.Getenv("DATABASE_URL"))
	log.Println("Audit Logger initialized")

	// Initialize Metrics Collector
	metricsCollector = NewMetricsCollector()
	log.Println("Metrics Collector initialized")

	// Initialize per-stage metrics
	orchestratorMetrics = &OrchestratorMetrics{
		dynamicPolicyTimings: make([]int64, 0, 1000),
		llmTimings:           make([]int64, 0, 1000),
		startTime:            time.Now(),
		errorTimestamps:      make([]time.Time, 0, 1000),
		healthCheckPassed:    true,
		requestTypeMetrics:   make(map[string]*RequestTypeOrchestratorMetrics),
		providerMetrics:      make(map[string]*LLMProviderMetrics),
	}
	log.Println("Per-stage metrics initialized (comprehensive)")

	// Initialize Workflow Engine
	log.Println("Initializing Workflow Engine...")
	workflowEngine = NewWorkflowEngine()
	if workflowEngine == nil {
		log.Println("WARNING: Workflow Engine failed to initialize - workflow endpoints will not be available")
	} else {
		workflowEngine.InitializeWithDependencies(GetLLMRouter(), amadeusClient)
		log.Println("Workflow Engine initialized successfully with API call support")
	}

	// Initialize Planning Engine (Multi-Agent Planning v0.1)
	log.Println("Initializing Planning Engine...")
	if router := GetLLMRouter(); router != nil {
		planningEngine = NewPlanningEngine(router)
		log.Println("Planning Engine initialized with LLM-based decomposition")
	} else {
		log.Println("WARNING: Planning Engine not initialized - LLM Router unavailable")
	}

	// Initialize Result Aggregator (Multi-Agent Planning v0.1)
	log.Println("Initializing Result Aggregator...")
	if router := GetLLMRouter(); router != nil {
		resultAggregator = NewResultAggregator(router)
		log.Println("Result Aggregator initialized with LLM synthesis")
	} else {
		log.Println("WARNING: Result Aggregator not initialized - LLM Router unavailable")
	}

	// Initialize Connector Registry (MCP v0.2)
	log.Println("Initializing MCP Connector Registry...")
	initializeConnectorRegistry()
	log.Println("MCP Connector Registry initialized ✅")

	// Initialize MCP Query Router (MCP query forwarding to agent)
	log.Println("Initializing MCP Query Router...")
	agentMCPEndpoint = os.Getenv("AGENT_MCP_ENDPOINT")
	if agentMCPEndpoint == "" {
		agentMCPEndpoint = "http://localhost:8080" // Default for local development
		log.Printf("⚠️  AGENT_MCP_ENDPOINT not set, using default: %s (for local dev only)", agentMCPEndpoint)
	} else {
		log.Printf("Agent MCP endpoint configured: %s", agentMCPEndpoint)
	}
	mcpQueryRouter = NewMCPQueryRouter(agentMCPEndpoint)
	log.Println("MCP Query Router initialized ✅")

	// Initialize Policy CRUD API (Track A - Policy Enforcement)
	log.Println("Initializing Policy CRUD API...")
	if usageDB != nil {
		policyRepo := NewPolicyRepository(usageDB)
		// Cast dynamicPolicyEngine to *DynamicPolicyEngine if it's the database-backed version
		var engine *DynamicPolicyEngine
		if dbEngine, ok := dynamicPolicyEngine.(*DatabaseDynamicPolicyEngine); ok {
			// Use a wrapper or create a new in-memory engine for the API
			// For now, pass nil since the service doesn't heavily depend on it for CRUD
			_ = dbEngine // Acknowledge the variable
			engine = nil
		}
		policyService := NewPolicyService(policyRepo, engine)
		policyAPIHandler = NewPolicyAPIHandler(policyService)
		log.Println("Policy CRUD API initialized ✅")

		// Initialize Policy Templates API (Track D - Policy Templates)
		log.Println("Initializing Policy Templates API...")
		templateRepo := NewTemplateRepository(usageDB)
		templateService := NewTemplateService(templateRepo, policyRepo)
		templateAPIHandler = NewTemplateAPIHandler(templateService)
		log.Println("Policy Templates API initialized ✅")
	} else {
		log.Println("⚠️  Policy CRUD API not initialized - database connection required")
		log.Println("⚠️  Policy Templates API not initialized - database connection required")
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	router := GetLLMRouter()
	components := map[string]bool{
		"policy_engine":      dynamicPolicyEngine.IsHealthy(),
		"llm_router":         router != nil && router.IsHealthy(),
		"response_processor": responseProcessor.IsHealthy(),
		"audit_logger":       auditLogger.IsHealthy(),
		"workflow_engine":    workflowEngine.IsHealthy(),
	}

	// Add Multi-Agent Planning components (v0.1)
	if planningEngine != nil {
		components["planning_engine"] = planningEngine.IsHealthy()
	}
	if resultAggregator != nil {
		components["result_aggregator"] = resultAggregator.IsHealthy()
	}

	health := map[string]interface{}{
		"status":     "healthy",
		"service":    "axonflow-orchestrator",
		"version":    "1.0.0",
		"timestamp":  time.Now().UTC(),
		"components": components,
		"features": map[string]bool{
			"multi_agent_planning": planningEngine != nil && resultAggregator != nil,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func processRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var req OrchestratorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Add request ID if not provided
	if req.RequestID == "" {
		req.RequestID = generateRequestID()
	}

	// Create processing context
	ctx := context.WithValue(r.Context(), ctxKeyRequestID, req.RequestID)
	ctx = context.WithValue(ctx, ctxKeyUser, req.User)
	ctx = context.WithValue(ctx, ctxKeyClient, req.Client)

	// 1. Evaluate dynamic policies
	policyStartTime := time.Now()
	policyResult := dynamicPolicyEngine.EvaluateDynamicPolicies(ctx, req)
	policyEvalTime := time.Since(policyStartTime)

	// Record policy evaluation metric
	promPolicyEvaluations.Inc()
	promRequestDuration.WithLabelValues("dynamic_policy").Observe(float64(policyEvalTime.Milliseconds()))

	// Record per-stage dynamic policy timing
	if orchestratorMetrics != nil {
		orchestratorMetrics.mu.Lock()
		policyMs := policyEvalTime.Milliseconds()
		if len(orchestratorMetrics.dynamicPolicyTimings) >= 1000 {
			orchestratorMetrics.dynamicPolicyTimings = orchestratorMetrics.dynamicPolicyTimings[1:]
		}
		orchestratorMetrics.dynamicPolicyTimings = append(orchestratorMetrics.dynamicPolicyTimings, policyMs)
		orchestratorMetrics.mu.Unlock()
	}

	if !policyResult.Allowed {
		// Log blocked request
		auditLogger.LogBlockedRequest(ctx, req, policyResult)

		// Record blocked request metrics
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		latencyMs := time.Since(startTime).Milliseconds()
		promRequestDuration.WithLabelValues("blocked").Observe(float64(latencyMs))

		// Record comprehensive metrics
		if orchestratorMetrics != nil {
			orchestratorMetrics.recordRequest(req.RequestType, "", latencyMs, false, true, 0, 0)
		}

		response := OrchestratorResponse{
			RequestID:      req.RequestID,
			Success:        false,
			Error:          "Request blocked by dynamic policy",
			PolicyInfo:     policyResult,
			ProcessingTime: time.Since(startTime).String(),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
		return
	}

	// 2. Route based on request type
	// MCP queries should go to agent MCP handler, not LLM
	if req.RequestType == "mcp-query" {
		log.Printf("[Orchestrator] Routing MCP query to agent - connector: %v, query: %s",
			req.Context["connector"], req.Query)

		response, err := mcpQueryRouter.RouteToAgent(ctx, req)
		latencyMs := time.Since(startTime).Milliseconds()
		if err != nil {
			log.Printf("[Orchestrator] MCP query routing failed: %v", err)
			auditLogger.LogFailedRequest(ctx, req, err)
			promRequestsTotal.WithLabelValues("error").Inc()
			promRequestDuration.WithLabelValues("mcp_error").Observe(float64(latencyMs))
			// Record comprehensive metrics
			if orchestratorMetrics != nil {
				orchestratorMetrics.recordRequest(req.RequestType, "mcp", latencyMs, false, false, 0, 0)
			}
			sendErrorResponse(w, fmt.Sprintf("MCP query failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Record successful MCP query
		promRequestsTotal.WithLabelValues("success").Inc()
		promRequestDuration.WithLabelValues("mcp").Observe(float64(latencyMs))
		// Record comprehensive metrics
		if orchestratorMetrics != nil {
			orchestratorMetrics.recordRequest(req.RequestType, "mcp", latencyMs, true, false, 0, 0)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
		}
		return
	}

	// 3. Route to appropriate LLM provider (skip if requested for hourly tests)
	var llmResponse *LLMResponse
	var providerInfo *ProviderInfo
	var err error

	// Diagnostic logging for skip_llm troubleshooting
	queryPreview := req.Query
	if len(queryPreview) > 50 {
		queryPreview = queryPreview[:50] + "..."
	}
	log.Printf("[LLM] Request received: skip_llm=%v, query=%q", req.SkipLLM, queryPreview)

	if req.SkipLLM {
		log.Printf("[LLM] SKIPPING: Using mock response (skip_llm=true)")
		// Mock response for hourly tests (no LLM cost)
		llmResponse = &LLMResponse{
			Content: "test_response_hourly_validation",
			Metadata: map[string]interface{}{
				"skipped_llm": true,
			},
		}
		providerInfo = &ProviderInfo{
			Provider: "mock",
			Model:    "test",
		}
	} else {
		log.Printf("[LLM] CALLING: Routing to LLM provider (skip_llm=false)")
		llmStartTime := time.Now()
		llmResponse, providerInfo, err = GetLLMRouter().RouteRequest(ctx, req)
		providerName := "unknown"
		if providerInfo != nil {
			providerName = providerInfo.Provider
		}
		log.Printf("[LLM] COMPLETED: provider=%s, latency=%v, err=%v", providerName, time.Since(llmStartTime), err)
		llmTime := time.Since(llmStartTime)

		// Record per-stage LLM timing
		if orchestratorMetrics != nil && err == nil {
			orchestratorMetrics.mu.Lock()
			llmMs := llmTime.Milliseconds()
			if len(orchestratorMetrics.llmTimings) >= 1000 {
				orchestratorMetrics.llmTimings = orchestratorMetrics.llmTimings[1:]
			}
			orchestratorMetrics.llmTimings = append(orchestratorMetrics.llmTimings, llmMs)
			orchestratorMetrics.mu.Unlock()
		}

		if err != nil {
			auditLogger.LogFailedRequest(ctx, req, err)
			latencyMsErr := time.Since(startTime).Milliseconds()

			// Record failed LLM call
			promLLMCalls.WithLabelValues("unknown", "error").Inc()
			promRequestsTotal.WithLabelValues("error").Inc()
			promRequestDuration.WithLabelValues("error").Observe(float64(latencyMsErr))

			// Record comprehensive metrics
			if orchestratorMetrics != nil {
				orchestratorMetrics.recordRequest(req.RequestType, "unknown", latencyMsErr, false, false, 0, 0)
			}

			sendErrorResponse(w, "LLM routing failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Record successful LLM call
	promLLMCalls.WithLabelValues(providerInfo.Provider, "success").Inc()

	// 3. Process response (PII detection, redaction, etc.)
	processedResponse, redactionInfo := responseProcessor.ProcessResponse(ctx, req.User, llmResponse)

	// 4. Log successful request
	_ = auditLogger.LogSuccessfulRequest(ctx, req, processedResponse, policyResult, providerInfo)

	// 5. Collect metrics
	finalLatencyMs := time.Since(startTime).Milliseconds()
	metricsCollector.RecordRequest(req.RequestType, providerInfo.Provider, time.Since(startTime))

	// Record Prometheus metrics
	promRequestsTotal.WithLabelValues("success").Inc()
	promRequestDuration.WithLabelValues("llm").Observe(float64(finalLatencyMs))

	// Record comprehensive metrics with provider info
	if orchestratorMetrics != nil {
		orchestratorMetrics.recordRequest(
			req.RequestType,
			providerInfo.Provider,
			finalLatencyMs,
			true,
			false,
			providerInfo.TokensUsed,
			providerInfo.Cost,
		)
	}

	// 6. Return response
	response := OrchestratorResponse{
		RequestID:      req.RequestID,
		Success:        true,
		Data:           processedResponse,
		Redacted:       redactionInfo.HasRedactions,
		RedactedFields: redactionInfo.RedactedFields,
		PolicyInfo:     policyResult,
		ProviderInfo:   providerInfo,
		ProcessingTime: time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func providerStatusHandler(w http.ResponseWriter, r *http.Request) {
	status := GetLLMRouter().GetProviderStatus()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func updateProviderWeightsHandler(w http.ResponseWriter, r *http.Request) {
	var weights map[string]float64
	if err := json.NewDecoder(r.Body).Decode(&weights); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := GetLLMRouter().UpdateProviderWeights(weights); err != nil {
		sendErrorResponse(w, "Failed to update weights: "+err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Provider weights updated",
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func listDynamicPoliciesHandler(w http.ResponseWriter, r *http.Request) {
	policies := dynamicPolicyEngine.ListActivePolicies()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(policies); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func testPolicyHandler(w http.ResponseWriter, r *http.Request) {
	var testReq struct {
		Query       string      `json:"query"`
		User        UserContext `json:"user"`
		RequestType string      `json:"request_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&testReq); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Create test request
	req := OrchestratorRequest{
		RequestID:   "test-" + generateRequestID(),
		Query:       testReq.Query,
		RequestType: testReq.RequestType,
		User:        testReq.User,
		Timestamp:   time.Now(),
	}

	// Evaluate policies
	result := dynamicPolicyEngine.EvaluateDynamicPolicies(r.Context(), req)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := metricsCollector.GetMetrics()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// Helper functions for per-stage metrics calculation
func calculatePercentileOrchestrator(timings []int64, percentile float64) float64 {
	if len(timings) == 0 {
		return 0
	}

	sorted := make([]int64, len(timings))
	copy(sorted, timings)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	index := int(float64(len(sorted)) * percentile)
	if index >= len(sorted) {
		index = len(sorted) - 1
	}

	return float64(sorted[index])
}

func calculateP50Orchestrator(timings []int64) float64 {
	return calculatePercentileOrchestrator(timings, 0.50)
}

func calculateP95Orchestrator(timings []int64) float64 {
	return calculatePercentileOrchestrator(timings, 0.95)
}

func calculateP99Orchestrator(timings []int64) float64 {
	return calculatePercentileOrchestrator(timings, 0.99)
}

func calculateAverageOrchestrator(timings []int64) float64 {
	if len(timings) == 0 {
		return 0
	}

	sum := int64(0)
	for _, t := range timings {
		sum += t
	}

	return float64(sum) / float64(len(timings))
}

// calculateErrorRateOrchestrator calculates errors per second over the last 60 seconds
func calculateErrorRateOrchestrator(errorTimestamps []time.Time) float64 {
	cutoff := time.Now().Add(-60 * time.Second)
	count := 0
	for _, ts := range errorTimestamps {
		if ts.After(cutoff) {
			count++
		}
	}
	return float64(count) / 60.0
}

// recordOrchestratorRequest records a request with all its metrics
func (m *OrchestratorMetrics) recordRequest(requestType string, provider string, latencyMs int64, success bool, blocked bool, tokens int, cost float64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.totalRequests++
	if blocked {
		m.blockedRequests++
	} else if success {
		m.successRequests++
		m.consecutiveErrors = 0
		m.healthCheckPassed = true
	} else {
		m.failedRequests++
		m.consecutiveErrors++
		m.errorTimestamps = append(m.errorTimestamps, time.Now())
		// Trim old error timestamps (keep last 1000)
		if len(m.errorTimestamps) > 1000 {
			m.errorTimestamps = m.errorTimestamps[1:]
		}
		// Mark unhealthy after 5 consecutive errors
		if m.consecutiveErrors >= 5 {
			m.healthCheckPassed = false
		}
	}

	// Record per-request-type metrics
	if requestType != "" {
		rtm, exists := m.requestTypeMetrics[requestType]
		if !exists {
			rtm = &RequestTypeOrchestratorMetrics{
				Latencies: make([]int64, 0, 1000),
			}
			m.requestTypeMetrics[requestType] = rtm
		}
		rtm.TotalRequests++
		if blocked {
			rtm.BlockedRequests++
		} else if success {
			rtm.SuccessRequests++
		} else {
			rtm.FailedRequests++
		}
		rtm.Latencies = append(rtm.Latencies, latencyMs)
		if len(rtm.Latencies) > 1000 {
			rtm.Latencies = rtm.Latencies[1:]
		}
	}

	// Record per-provider metrics
	if provider != "" && !blocked {
		pm, exists := m.providerMetrics[provider]
		if !exists {
			pm = &LLMProviderMetrics{
				ProviderName: provider,
				Latencies:    make([]int64, 0, 1000),
			}
			m.providerMetrics[provider] = pm
		}
		pm.TotalCalls++
		if success {
			pm.SuccessCalls++
		} else {
			pm.FailedCalls++
		}
		pm.TotalTokens += int64(tokens)
		pm.TotalCost += cost
		pm.Latencies = append(pm.Latencies, latencyMs)
		if len(pm.Latencies) > 1000 {
			pm.Latencies = pm.Latencies[1:]
		}
	}
}

// simpleMetricsHandler returns simplified metrics for easy consumption
func simpleMetricsHandler(w http.ResponseWriter, r *http.Request) {
	metrics := metricsCollector.GetMetrics()

	// Calculate totals from MetricsCollector
	collectorTotalRequests := int64(0)
	collectorSuccessRequests := int64(0)
	collectorBlockedRequests := int64(0)
	var dynamicP99 time.Duration

	for _, rtMetrics := range metrics.RequestMetrics {
		collectorTotalRequests += rtMetrics.TotalRequests
		collectorSuccessRequests += rtMetrics.SuccessCount
		collectorBlockedRequests += rtMetrics.BlockedCount
		if rtMetrics.P99ResponseTime > dynamicP99 {
			dynamicP99 = rtMetrics.P99ResponseTime
		}
	}

	// Use comprehensive metrics from orchestratorMetrics if available
	var totalRequests, successRequests, failedRequests, blockedRequests int64
	var errorRate float64
	var healthUp int
	var consecutiveErrors int64
	var dynamicPolicyP50, dynamicPolicyP95, dynamicPolicyP99, dynamicPolicyAvg float64
	var llmP50, llmP95, llmP99, llmAvg float64
	requestTypes := make(map[string]interface{})
	providers := make(map[string]interface{})

	if orchestratorMetrics != nil {
		orchestratorMetrics.mu.RLock()
		totalRequests = orchestratorMetrics.totalRequests
		successRequests = orchestratorMetrics.successRequests
		failedRequests = orchestratorMetrics.failedRequests
		blockedRequests = orchestratorMetrics.blockedRequests
		errorRate = calculateErrorRateOrchestrator(orchestratorMetrics.errorTimestamps)
		if orchestratorMetrics.healthCheckPassed {
			healthUp = 1
		}
		consecutiveErrors = orchestratorMetrics.consecutiveErrors

		// Percentiles for dynamic policy
		dynamicPolicyP50 = calculateP50Orchestrator(orchestratorMetrics.dynamicPolicyTimings)
		dynamicPolicyP95 = calculateP95Orchestrator(orchestratorMetrics.dynamicPolicyTimings)
		dynamicPolicyP99 = calculateP99Orchestrator(orchestratorMetrics.dynamicPolicyTimings)
		dynamicPolicyAvg = calculateAverageOrchestrator(orchestratorMetrics.dynamicPolicyTimings)

		// Percentiles for LLM
		llmP50 = calculateP50Orchestrator(orchestratorMetrics.llmTimings)
		llmP95 = calculateP95Orchestrator(orchestratorMetrics.llmTimings)
		llmP99 = calculateP99Orchestrator(orchestratorMetrics.llmTimings)
		llmAvg = calculateAverageOrchestrator(orchestratorMetrics.llmTimings)

		// Per-request-type metrics
		for reqType, rtm := range orchestratorMetrics.requestTypeMetrics {
			requestTypes[reqType] = map[string]interface{}{
				"total_requests":   rtm.TotalRequests,
				"success_requests": rtm.SuccessRequests,
				"failed_requests":  rtm.FailedRequests,
				"blocked_requests": rtm.BlockedRequests,
				"p50_ms":           calculateP50Orchestrator(rtm.Latencies),
				"p95_ms":           calculateP95Orchestrator(rtm.Latencies),
				"p99_ms":           calculateP99Orchestrator(rtm.Latencies),
			}
		}

		// Per-provider metrics
		for provider, pm := range orchestratorMetrics.providerMetrics {
			providers[provider] = map[string]interface{}{
				"total_calls":   pm.TotalCalls,
				"success_calls": pm.SuccessCalls,
				"failed_calls":  pm.FailedCalls,
				"total_tokens":  pm.TotalTokens,
				"total_cost":    pm.TotalCost,
				"p50_ms":        calculateP50Orchestrator(pm.Latencies),
				"p95_ms":        calculateP95Orchestrator(pm.Latencies),
				"p99_ms":        calculateP99Orchestrator(pm.Latencies),
			}
		}
		orchestratorMetrics.mu.RUnlock()
	} else {
		// Fallback to MetricsCollector data
		totalRequests = collectorTotalRequests
		successRequests = collectorSuccessRequests
		blockedRequests = collectorBlockedRequests
		healthUp = 1
	}

	// Calculate RPS
	uptime := time.Since(metrics.CollectionStarted).Seconds()
	rps := float64(totalRequests) / uptime

	// Success rate
	successRate := float64(100.0)
	if totalRequests > 0 {
		successRate = float64(successRequests) * 100.0 / float64(totalRequests)
	}

	// Comprehensive metrics output
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"orchestrator_metrics": map[string]interface{}{
			"uptime_seconds":   uptime,
			"total_requests":   totalRequests,
			"success_requests": successRequests,
			"failed_requests":  failedRequests,
			"blocked_requests": blockedRequests,
			"success_rate":     successRate,
			"rps":              rps,

			// Error rate (NEW)
			"error_rate_per_sec": errorRate,

			// Legacy metric name for compatibility
			"dynamic_policy_p99_ms":  float64(dynamicP99.Milliseconds()),
			"policy_evaluations":     metrics.PolicyMetrics.TotalEvaluations,
			"avg_evaluation_time_ms": float64(metrics.PolicyMetrics.AvgEvaluationTime.Milliseconds()),

			// Per-stage dynamic policy metrics (enhanced with P50/P95)
			"dynamic_policy_eval_p50_ms": dynamicPolicyP50,
			"dynamic_policy_eval_p95_ms": dynamicPolicyP95,
			"dynamic_policy_eval_p99_ms": dynamicPolicyP99,
			"dynamic_policy_eval_avg_ms": dynamicPolicyAvg,

			// Per-stage LLM routing metrics (enhanced with P50/P95)
			"llm_routing_p50_ms": llmP50,
			"llm_routing_p95_ms": llmP95,
			"llm_routing_p99_ms": llmP99,
			"llm_routing_avg_ms": llmAvg,
		},
		"health": map[string]interface{}{
			"up":                 healthUp,
			"consecutive_errors": consecutiveErrors,
		},
		"request_types": requestTypes,
		"providers":     providers,
		"timestamp":     time.Now().UTC(),
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func auditSearchHandler(w http.ResponseWriter, r *http.Request) {
	var searchReq struct {
		UserEmail   string    `json:"user_email,omitempty"`
		ClientID    string    `json:"client_id,omitempty"`
		StartTime   time.Time `json:"start_time"`
		EndTime     time.Time `json:"end_time"`
		RequestType string    `json:"request_type,omitempty"`
		Limit       int       `json:"limit,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&searchReq); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if searchReq.Limit == 0 {
		searchReq.Limit = 100
	}

	results, err := auditLogger.SearchAuditLogs(searchReq)
	if err != nil {
		sendErrorResponse(w, "Audit search failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func tenantAuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]

	if tenantID == "" {
		sendErrorResponse(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Search audit logs for specific tenant
	searchReq := struct {
		TenantID string `json:"tenant_id"`
		Limit    int    `json:"limit"`
	}{
		TenantID: tenantID,
		Limit:    50,
	}

	results, err := auditLogger.SearchAuditLogs(searchReq)
	if err != nil {
		sendErrorResponse(w, "Failed to fetch tenant audit logs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(results); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func tenantWorkflowExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]

	if tenantID == "" {
		sendErrorResponse(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Get workflow executions for specific tenant
	executions, err := workflowEngine.GetExecutionsByTenant(tenantID)
	if err != nil {
		sendErrorResponse(w, "Failed to fetch tenant workflow executions: "+err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"tenant_id":  tenantID,
		"count":      len(executions),
		"executions": executions,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// Utility functions
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	response := OrchestratorResponse{
		Success: false,
		Error:   message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func generateRequestID() string {
	return fmt.Sprintf("req_%d_%s", time.Now().Unix(), generateRandomString(8))
}

func generateRandomString(length int) string {
	// Cryptographically secure random string generation
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)

	// Use crypto/rand for true randomness
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to math/rand if crypto/rand fails (shouldn't happen)
		for i := range b {
			b[i] = charset[mathRand.Intn(len(charset))]
		}
		return string(b)
	}

	for i := range b {
		b[i] = charset[int(randomBytes[i])%len(charset)]
	}
	return string(b)
}

// encodePostgreSQLPassword manually parses a PostgreSQL URL and encodes the password
// This is needed because CloudFormation passes passwords unencoded in connection strings
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

// Workflow API Handlers

func executeWorkflowHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Workflow Workflow               `json:"workflow"`
		Input    map[string]interface{} `json:"input"`
		User     UserContext            `json:"user"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate workflow definition
	if req.Workflow.Metadata.Name == "" {
		sendErrorResponse(w, "Workflow name is required", http.StatusBadRequest)
		return
	}

	if len(req.Workflow.Spec.Steps) == 0 {
		sendErrorResponse(w, "Workflow must have at least one step", http.StatusBadRequest)
		return
	}

	// Execute workflow
	execution, err := workflowEngine.ExecuteWorkflow(r.Context(), req.Workflow, req.Input, req.User)
	if err != nil {
		sendErrorResponse(w, "Workflow execution failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(execution); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func getWorkflowExecutionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	executionID := vars["id"]

	if executionID == "" {
		sendErrorResponse(w, "Execution ID is required", http.StatusBadRequest)
		return
	}

	execution, err := workflowEngine.GetExecution(executionID)
	if err != nil {
		sendErrorResponse(w, "Execution not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(execution); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func listWorkflowExecutionsHandler(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	limit := 10 // default

	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	executions, err := workflowEngine.ListRecentExecutions(limit)
	if err != nil {
		sendErrorResponse(w, "Failed to list executions: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"executions": executions,
		"count":      len(executions),
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// === Multi-Agent Planning Handler (v0.1) ===

// PlanRequest represents a multi-agent planning request
type PlanRequest struct {
	Query         string                 `json:"query"`
	Domain        string                 `json:"domain"`         // Optional: travel, healthcare, finance, generic
	ExecutionMode string                 `json:"execution_mode"` // auto, parallel, sequential
	User          UserContext            `json:"user"`
	Client        map[string]interface{} `json:"client,omitempty"` // Client info from Agent (for audit)
	Context       map[string]interface{} `json:"context"`
}

// PlanResponse represents the response from a planning request
type PlanResponse struct {
	Success             bool         `json:"success"`
	PlanID              string       `json:"plan_id"`
	WorkflowExecutionID string       `json:"workflow_execution_id"`
	Result              interface{}  `json:"result"`
	Metadata            PlanMetadata `json:"metadata"`
	Error               string       `json:"error,omitempty"`
}

// PlanMetadata holds metadata about plan execution
type PlanMetadata struct {
	TasksExecuted   int            `json:"tasks_executed"`
	ExecutionMode   string         `json:"execution_mode"`
	ExecutionTimeMs int64          `json:"execution_time_ms"`
	Tasks           []TaskMetadata `json:"tasks"`
}

// TaskMetadata holds metadata about individual task
type TaskMetadata struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	TimeMs int64  `json:"time_ms"`
}

// planRequestHandler handles multi-agent planning requests
func planRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	log.Println("[PlanRequest] Received multi-agent planning request")

	// Check if planning engine is available
	if planningEngine == nil {
		sendErrorResponse(w, "Multi-Agent Planning not available - Planning Engine not initialized", http.StatusServiceUnavailable)
		return
	}

	if workflowEngine == nil {
		sendErrorResponse(w, "Multi-Agent Planning not available - Workflow Engine not initialized", http.StatusServiceUnavailable)
		return
	}

	// Parse request
	var req PlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// === GOVERNANCE: Validate Authentication (from Agent) ===
	// All planning requests MUST come through AxonFlow Agent
	// Direct access to /api/v1/plan is not supported for governance compliance

	if req.User.ID == 0 {
		log.Printf("[PlanRequest] BLOCKED: Missing user authentication (request must come through Agent)")
		sendErrorResponse(w, "Authentication required: requests must be routed through AxonFlow Agent", http.StatusUnauthorized)
		return
	}

	// Extract client info for audit logging and multi-tenant logging
	clientName := "unknown"
	clientID := "unknown"
	if req.Client != nil {
		if name, ok := req.Client["name"].(string); ok {
			clientName = name
		}
		if id, ok := req.Client["id"].(string); ok {
			clientID = id
			if clientName == "unknown" {
				clientName = id
			}
		}
	}

	// Generate request ID for tracing
	requestID := fmt.Sprintf("plan-%d-%s", time.Now().UnixNano(), clientID)

	log.Printf("[PlanRequest] Authenticated request - User: %s (ID: %d), Client: %s",
		req.User.Email, req.User.ID, clientName)

	// Validate request
	if req.Query == "" {
		sendErrorResponse(w, "Query is required", http.StatusBadRequest)
		return
	}

	// Set defaults
	if req.Domain == "" {
		// Try to extract domain from context (for clients that send it there)
		if domain, ok := req.Context["domain"].(string); ok && domain != "" {
			req.Domain = domain
			log.Printf("[PlanRequest] Domain extracted from context: %s", domain)
		} else {
			req.Domain = "generic"
		}
	}
	if req.ExecutionMode == "" {
		req.ExecutionMode = "auto"
	}

	log.Printf("[PlanRequest] Query: %s, Domain: %s, Mode: %s, RequestID: %s", req.Query, req.Domain, req.ExecutionMode, requestID)

	// Step 1: Generate execution plan
	planGenReq := PlanGenerationRequest{
		Query:         req.Query,
		Domain:        req.Domain,
		ExecutionMode: req.ExecutionMode,
		ClientID:      clientID,
		RequestID:     requestID,
		Context:       req.Context,
	}

	workflow, err := planningEngine.GeneratePlan(r.Context(), planGenReq)
	if err != nil {
		log.Printf("[PlanRequest] Plan generation failed: %v", err)
		sendErrorResponse(w, "Planning failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[PlanRequest] Plan generated: %d steps", len(workflow.Spec.Steps))

	// Step 2: Execute workflow (with parallel support)
	// Add 25-second timeout for trip planning to ensure quick failover to mock data
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	enableParallel := req.ExecutionMode == "auto" || req.ExecutionMode == "parallel"
	execution, err := workflowEngine.ExecuteWorkflowWithParallelSupport(ctx, *workflow, req.Context, req.User, enableParallel)
	if err != nil {
		log.Printf("[PlanRequest] Execution failed: %v", err)
		sendErrorResponse(w, "Execution failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[PlanRequest] Execution completed: %s", execution.ID)

	// Step 3: Build response
	executionTimeMs := time.Since(startTime).Milliseconds()

	// Build task metadata
	tasks := make([]TaskMetadata, len(execution.Steps))
	for i, step := range execution.Steps {
		// Parse process time (format: "123.45ms")
		timeMs := int64(0)
		if duration, err := time.ParseDuration(step.ProcessTime); err == nil {
			timeMs = duration.Milliseconds()
		}

		tasks[i] = TaskMetadata{
			Name:   step.Name,
			Status: step.Status,
			TimeMs: timeMs,
		}
	}

	// Extract final result
	log.Printf("[PlanResponse] execution.Output: %+v", execution.Output)
	log.Printf("[PlanResponse] execution.Output keys: %v", getOutputKeys(execution.Output))

	var finalResult interface{}
	if execution.Output != nil {
		if result, ok := execution.Output["final_result"]; ok {
			log.Printf("[PlanResponse] Found final_result, type: %T, length: %d", result, getResultLength(result))
			finalResult = result
		} else {
			log.Printf("[PlanResponse] WARNING: final_result key not found in execution.Output, using entire output map")
			// Fallback: return entire output
			finalResult = execution.Output
		}
	} else {
		log.Printf("[PlanResponse] WARNING: execution.Output is nil")
		finalResult = "Plan executed successfully (no output generated)"
	}

	response := PlanResponse{
		Success:             true,
		PlanID:              fmt.Sprintf("plan_%d_%s", time.Now().Unix(), generateRandomString(8)),
		WorkflowExecutionID: execution.ID,
		Result:              finalResult,
		Metadata: PlanMetadata{
			TasksExecuted:   len(execution.Steps),
			ExecutionMode:   req.ExecutionMode,
			ExecutionTimeMs: executionTimeMs,
			Tasks:           tasks,
		},
	}

	log.Printf("[PlanRequest] Success in %dms: %d tasks executed", executionTimeMs, len(execution.Steps))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func getOutputKeys(output map[string]interface{}) []string {
	if output == nil {
		return []string{}
	}
	keys := make([]string, 0, len(output))
	for k := range output {
		keys = append(keys, k)
	}
	return keys
}

func getResultLength(result interface{}) int {
	if result == nil {
		return 0
	}
	if str, ok := result.(string); ok {
		return len(str)
	}
	return -1 // Not a string
}

// === Policy CRUD API Handlers (gorilla/mux wrappers) ===
// These wrap PolicyAPIHandler methods for gorilla/mux routing

// policyAPIListCreateHandler handles GET (list) and POST (create) for /api/v1/policies
func policyAPIListCreateHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	// Delegate to the handler which handles method dispatch
	policyAPIHandler.handlePolicies(w, r)
}

// policyAPIGetUpdateDeleteHandler handles GET/PUT/DELETE for /api/v1/policies/{id}
func policyAPIGetUpdateDeleteHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	// gorilla/mux extracts {id} into vars, but our handler expects URL path parsing
	// Rewrite the URL path to match the expected format
	vars := mux.Vars(r)
	policyID := vars["id"]
	r.URL.Path = "/api/v1/policies/" + policyID
	policyAPIHandler.handlePolicyByID(w, r)
}

// policyAPITestHandler handles POST /api/v1/policies/{id}/test
func policyAPITestHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	vars := mux.Vars(r)
	policyID := vars["id"]
	r.URL.Path = "/api/v1/policies/" + policyID + "/test"
	policyAPIHandler.handlePolicyByID(w, r)
}

// policyAPIVersionsHandler handles GET /api/v1/policies/{id}/versions
func policyAPIVersionsHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	vars := mux.Vars(r)
	policyID := vars["id"]
	r.URL.Path = "/api/v1/policies/" + policyID + "/versions"
	policyAPIHandler.handlePolicyByID(w, r)
}

// policyAPIImportHandler handles POST /api/v1/policies/import
func policyAPIImportHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	policyAPIHandler.handleImport(w, r)
}

// policyAPIExportHandler handles GET /api/v1/policies/export
func policyAPIExportHandler(w http.ResponseWriter, r *http.Request) {
	if policyAPIHandler == nil {
		sendErrorResponse(w, "Policy API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	policyAPIHandler.handleExport(w, r)
}

// === Policy Templates API Handlers (gorilla/mux wrappers) ===
// These wrap TemplateAPIHandler methods for gorilla/mux routing

// templateAPIListHandler handles GET /api/v1/templates
func templateAPIListHandler(w http.ResponseWriter, r *http.Request) {
	if templateAPIHandler == nil {
		sendErrorResponse(w, "Templates API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	templateAPIHandler.HandleListTemplates(w, r)
}

// templateAPIGetHandler handles GET /api/v1/templates/{id}
func templateAPIGetHandler(w http.ResponseWriter, r *http.Request) {
	if templateAPIHandler == nil {
		sendErrorResponse(w, "Templates API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	vars := mux.Vars(r)
	templateID := vars["id"]
	templateAPIHandler.HandleGetTemplate(w, r, templateID)
}

// templateAPIApplyHandler handles POST /api/v1/templates/{id}/apply
func templateAPIApplyHandler(w http.ResponseWriter, r *http.Request) {
	if templateAPIHandler == nil {
		sendErrorResponse(w, "Templates API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	vars := mux.Vars(r)
	templateID := vars["id"]
	templateAPIHandler.HandleApplyTemplate(w, r, templateID)
}

// templateAPICategoriesHandler handles GET /api/v1/templates/categories
func templateAPICategoriesHandler(w http.ResponseWriter, r *http.Request) {
	if templateAPIHandler == nil {
		sendErrorResponse(w, "Templates API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	templateAPIHandler.HandleGetCategories(w, r)
}

// templateAPIStatsHandler handles GET /api/v1/templates/stats
func templateAPIStatsHandler(w http.ResponseWriter, r *http.Request) {
	if templateAPIHandler == nil {
		sendErrorResponse(w, "Templates API not initialized - database connection required", http.StatusServiceUnavailable)
		return
	}
	templateAPIHandler.HandleGetUsageStats(w, r)
}
