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
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	mathRand "math/rand"
	"net"
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

	"axonflow/platform/agent"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/node_enforcement"
	"axonflow/platform/orchestrator/cloudstorage" // Cloud storage backends for audit exports (#589)
	"axonflow/platform/orchestrator/cost"         // Cost controls & budget management (#764)
	"axonflow/platform/orchestrator/euaiact"      // EU AI Act compliance - Community stub or EE impl
	"axonflow/platform/orchestrator/llm"
	"axonflow/platform/orchestrator/masfeat"  // MAS FEAT module - Community stub or EE impl
	"axonflow/platform/orchestrator/ojk"      // OJK module - Community stub or EE impl
	"axonflow/platform/orchestrator/media"    // Media governance analysis pipeline
	"axonflow/platform/orchestrator/planning" // MAP two-step execution (#927)
	"axonflow/platform/orchestrator/rbi"      // RBI FREE-AI module - Community stub or EE impl
	"axonflow/platform/orchestrator/replay"   // Execution replay/debug mode (#763)
	"axonflow/platform/orchestrator/sebi"     // SEBI AI/ML module - Community stub or EE impl
	"axonflow/platform/orchestrator/ui"       // Embedded execution viewer UI
	"axonflow/platform/orchestrator/webhooks"
	"axonflow/platform/orchestrator/workflow_control" // Workflow Control Plane V1 (#834)
	"axonflow/platform/shared/execution"              // Unified execution tracking (#1075)
	"axonflow/platform/shared/idempotency"            // HTTP Idempotency-Key dedup (#2420)
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/secretenv"
	"axonflow/platform/shared/serviceauth"
)

// AxonFlow Orchestrator - Dynamic Policy Enforcement & LLM Routing Engine
// This service handles intelligent request routing and response processing

// contextKey is a private type for context keys to avoid collisions
type contextKey string

const (
	ctxKeyRequestID contextKey = "request_id"
	ctxKeyUser      contextKey = "user"
	ctxKeyClient    contextKey = "client"
	// ctxKeyRedactionInfo carries the response-plane *RedactionInfo (verdict +
	// redacted fields) from the handler to LogSuccessfulRequest (#2626). A typed
	// key avoids the string-key collision/lint smell the old "redaction_info"
	// literal carried.
	ctxKeyRedactionInfo contextKey = "redaction_info"
	// ctxKeyCorrelationID carries the request's W3C correlation_id (#2611) so the
	// response-plane audit row can be stitched to the request-plane decision.
	ctxKeyCorrelationID contextKey = "correlation_id"
)

// Configuration
var (
	dynamicPolicyEngine interface {
		EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
		ListActivePolicies() []DynamicPolicy
		IsHealthy() bool
	}
	// Note: Legacy llmRouter *LLMRouter removed in v2.3.0.
	// All LLM routing now uses llmRouterWrapper LLMRouterInterface.
	responseProcessor       *ResponseProcessor
	auditLogger             *AuditLogger
	metricsCollector        *MetricsCollector
	workflowEngine          *WorkflowEngine
	hitlWorkflowEngine      *HITLWorkflowEngine                // HITL-aware workflow engine (Issue #1082)
	hitlEnabled             bool                               // HITL mode flag (Issue #1082)
	planningEngine          *PlanningEngine                    // Multi-Agent Planning v0.1
	resultAggregator        *ResultAggregator                  // Multi-Agent Planning v0.1
	mcpQueryRouter          *MCPQueryRouter                    // MCP query routing to agent
	agentMCPEndpoint        string                             // Agent MCP handler endpoint
	usageDB                 *sql.DB                            // Database for usage metering
	heartbeatService        *node_enforcement.HeartbeatService // Node enforcement
	nodeMonitor             *node_enforcement.NodeMonitor      // Node enforcement
	policyAPIHandler        *PolicyAPIHandler                  // Policy CRUD API handler
	dynamicPolicyAPIHandler *DynamicPolicyAPIHandler           // Dynamic Policy API handler (ADR-026)
	templateAPIHandler      *TemplateAPIHandler                // Policy Templates API handler
	llmProviderRouter       *llm.UnifiedRouter                 // Unified LLM provider router (ADR-007, ADR-022)
	llmRouterWrapper        LLMRouterInterface                 // Interface for router compatibility (ADR-022 Phase 6)
	llmProviderAPIHandler   *LLMProviderAPIHandler             // LLM Provider REST API handler

	// Enterprise Compliance Modules
	sebiModule    *sebi.SEBIModule // SEBI AI/ML Guidelines compliance (India)
	rbiModule     *rbi.RBIModule   // RBI FREE-AI Framework compliance (India Banking)
	euaiactModule *euaiact.Module  // EU AI Act compliance (Europe)
	masfeatModule *masfeat.Module  // MAS FEAT compliance (Singapore)
	ojkModule     *ojk.OJKModule  // OJK AI Governance compliance (Indonesia)

	// Execution Replay/Debug Mode (#763)
	replayService *replay.Service // Execution replay service
	replayHandler *replay.Handler // Execution replay HTTP handlers

	// Cost Controls & Budget Management (#764)
	costService *cost.Service // Cost tracking and budget management
	costHandler *cost.Handler // Cost control HTTP handlers

	// HTTP Idempotency-Key dedup (#2420)
	orchIdempStore *idempotency.Store

	// MAP Two-Step Execution (#925)
	planService         *planning.Service             // Plan storage and retrieval for GeneratePlan/ExecutePlan
	mapExecutionTracker *MAPExecutionTracker          // Unified execution tracking for MAP (#1075)
	executionRepo       execution.ExecutionRepository // Execution history repository
	mapWCPExecutor      *MAPWCPExecutor               // WCP-backed executor for confirm/step modes

	// Workflow Control Plane V1 (#834)
	workflowControlService *workflow_control.Service // Workflow governance service
	workflowControlHandler *workflow_control.Handler // Workflow Control HTTP handlers
	webhookHandler         *webhooks.Handler         // Webhook notification HTTP handlers

	// Unified Execution Tracking (#1075)
	unifiedExecutionHandler *UnifiedExecutionHandler // Unified execution status API

	// Media Governance Pipeline
	mediaPipeline       *media.Pipeline              // Media analysis pipeline (image governance)
	mediaGovConfigStore *MediaGovernanceConfigStore  // Per-tenant media governance config
	mediaGovHandler     *MediaGovernanceHandler      // Media governance API handler
	mediaAuditHandler   *MediaGovernanceAuditHandler // Media audit export handler (Enterprise)

	// Tier enforcement
	tierChecker         LicenseChecker       // Global tier-aware license checker
	auditCleanupService *AuditCleanupService // Tier-aware audit log cleanup

	// Evaluation tier features
	policySimulationHandler *PolicySimulationHandler // Policy simulation + impact report
	evidenceExportHandler   *EvidenceExportHandler   // Evidence export + summary

	// Proxy auth validation — verifies requests came through the Agent gateway
	proxyTokenValidator *serviceauth.TokenValidator
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
	promPlanCleanups = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_orchestrator_plan_cleanups_total",
			Help: "Total number of expired plans cleaned up",
		},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(promRequestsTotal)
	prometheus.MustRegister(promRequestDuration)
	prometheus.MustRegister(promPolicyEvaluations)
	prometheus.MustRegister(promBlockedRequests)
	prometheus.MustRegister(promLLMCalls)
	prometheus.MustRegister(promPlanCleanups)
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
	Media       []MediaContentRequest  `json:"media,omitempty"` // Optional media (images) for multimodal requests
	Timestamp   time.Time              `json:"timestamp"`
}

// MediaContentRequest represents a media item in the API request.
type MediaContentRequest struct {
	Source     string `json:"source"`                // "base64" or "url"
	Base64Data string `json:"base64_data,omitempty"` // Base64-encoded image data
	URL        string `json:"url,omitempty"`         // Image URL
	MIMEType   string `json:"mime_type"`             // e.g., "image/jpeg"
}

type UserContext struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Region      string   `json:"region"` // User's region for geo-based routing policies
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"tenant_id"`
	OrgID       string   `json:"org_id"` // Org for multi-tenant isolation; populated from X-Org-ID header set by the agent
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
	MediaAnalysis  *MediaAnalysisResponse  `json:"media_analysis,omitempty"` // Results of media governance analysis
	ProcessingTime string                  `json:"processing_time"`
}

// MediaAnalysisResponse contains aggregated media analysis results in the API response.
type MediaAnalysisResponse struct {
	Results        []MediaAnalysisItemResponse `json:"results"`
	TotalCostUSD   float64                     `json:"total_cost_usd"`
	AnalysisTimeMs int64                       `json:"analysis_time_ms"`
}

// MediaAnalysisItemResponse contains analysis results for a single media item.
type MediaAnalysisItemResponse struct {
	MediaIndex          int                  `json:"media_index"`
	SHA256Hash          string               `json:"sha256_hash"`
	HasFaces            bool                 `json:"has_faces"`
	FaceCount           int                  `json:"face_count"`
	HasBiometricData    bool                 `json:"has_biometric_data"`
	NSFWScore           float64              `json:"nsfw_score"`
	ViolenceScore       float64              `json:"violence_score"`
	ContentSafe         bool                 `json:"content_safe"`
	DocumentType        string               `json:"document_type,omitempty"`
	IsSensitiveDocument bool                 `json:"is_sensitive_document"`
	HasPII              bool                 `json:"has_pii"`
	PIITypes            []string             `json:"pii_types,omitempty"`
	HasExtractedText    bool                 `json:"has_extracted_text"`
	ExtractedTextLength int                  `json:"extracted_text_length"`
	EstimatedCostUSD    float64              `json:"estimated_cost_usd"`
	Warnings            []string             `json:"warnings,omitempty"`
	StructuredWarnings  []media.MediaWarning `json:"structured_warnings,omitempty"`
}

type PolicyEvaluationResult struct {
	Allowed          bool     `json:"allowed"`
	AppliedPolicies  []string `json:"applied_policies"`
	RiskScore        float64  `json:"risk_score"`
	Severity         string   `json:"severity,omitempty"`           // Highest severity of matched policies: critical, high, medium, low
	SeverityPolicyID string   `json:"severity_policy_id,omitempty"` // Policy that contributed the highest severity
	RequiredActions  []string `json:"required_actions"`
	ProcessingTimeMs int64    `json:"processing_time_ms"`
	DatabaseAccessed bool     `json:"database_accessed,omitempty"`

	// Structured per-policy detail (ADR-044 / ADR-043). Mirror of AppliedPolicies
	// with risk and override semantics so downstream code (WCP adapter, explain
	// handler) can decide overridability without re-querying policies.
	AppliedPoliciesDetail []AppliedPolicyDetail `json:"applied_policies_detail,omitempty"`

	// Override enforcement (ADR-044): when a session override flipped a deny
	// into an allow, these fields record which override was applied.
	OverrideApplied bool   `json:"override_applied,omitempty"`
	OverrideID      string `json:"override_id,omitempty"`
	OverrideReason  string `json:"override_reason,omitempty"`

	// LLM Routing overrides from dynamic policies
	PreferredProvider string   `json:"preferred_provider,omitempty"` // Preferred LLM provider
	AllowedProviders  []string `json:"allowed_providers,omitempty"`  // Strict list for compliance (failover only within this list)
	RoutingReason     string   `json:"routing_reason,omitempty"`     // Why routing was changed
}

// AppliedPolicyDetail is the structured per-policy match carried inside
// PolicyEvaluationResult for use by the WCP adapter and explain handler.
// Introduced for ADR-044/ADR-043 — lets consumers decide override eligibility
// without a second database round-trip.
type AppliedPolicyDetail struct {
	PolicyID      string `json:"policy_id"`
	PolicyName    string `json:"policy_name"`
	Description   string `json:"description,omitempty"`
	Action        string `json:"action"`
	RiskLevel     string `json:"risk_level"`     // low|medium|high|critical
	AllowOverride bool   `json:"allow_override"` // false iff policy forbids session override
	MatchedRule   string `json:"matched_rule,omitempty"`
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
//
// Provider Configuration:
//   - OPENAI_API_KEY: OpenAI API key
//   - ANTHROPIC_API_KEY: Anthropic API key
//   - BEDROCK_REGION, BEDROCK_MODEL: AWS Bedrock configuration
//   - OLLAMA_ENDPOINT, OLLAMA_MODEL: Ollama configuration
//   - GOOGLE_API_KEY, GOOGLE_MODEL: Google Gemini configuration
//   - AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_API_KEY, AZURE_OPENAI_DEPLOYMENT_NAME: Azure OpenAI configuration
//
// Routing Configuration (Phase 1: Community):
//   - LLM_ROUTING_STRATEGY: "weighted" (default), "round_robin", "failover"
//   - PROVIDER_WEIGHTS: "openai:50,anthropic:30,bedrock:20" or "bedrock:100"
//   - DEFAULT_LLM_PROVIDER: fallback provider for failover strategy
func LoadLLMConfig() LLMRouterConfig {
	config := LLMRouterConfig{}

	// LLM API keys are read via secretenv.Get because every provider's
	// official SDK passes the key into an HTTP Authorization header
	// (Bearer / x-api-key) — Go's net/http rejects header values
	// containing control characters with `invalid header field value`.
	// AWS Secrets Manager secret values commonly carry trailing newlines,
	// which causes every LLM call to fail closed with a confusing
	// transport-layer error. Trimming defensively at boot avoids that.
	// Endpoints / model names / deployment names are kept on os.Getenv
	// because they're URLs / identifiers, not secrets.

	// OpenAI configuration
	config.OpenAIKey = secretenv.Get("OPENAI_API_KEY")

	// Anthropic configuration
	config.AnthropicKey = secretenv.Get("ANTHROPIC_API_KEY")

	// Bedrock configuration
	// Allow environment-specific overrides (e.g., BEDROCK_REGION_PROD)
	config.BedrockRegion = os.Getenv("BEDROCK_REGION")
	config.BedrockModel = os.Getenv("BEDROCK_MODEL")

	// Ollama configuration
	config.OllamaEndpoint = os.Getenv("OLLAMA_ENDPOINT")
	config.OllamaModel = os.Getenv("OLLAMA_MODEL")

	// Gemini configuration
	config.GeminiKey = secretenv.Get("GOOGLE_API_KEY")
	config.GeminiModel = os.Getenv("GOOGLE_MODEL")

	// Mistral configuration
	config.MistralKey = secretenv.Get("MISTRAL_API_KEY")
	config.MistralModel = os.Getenv("MISTRAL_MODEL")
	config.MistralEndpoint = os.Getenv("MISTRAL_ENDPOINT")

	// Azure OpenAI configuration
	config.AzureOpenAIEndpoint = os.Getenv("AZURE_OPENAI_ENDPOINT")
	config.AzureOpenAIAPIKey = secretenv.Get("AZURE_OPENAI_API_KEY")
	config.AzureOpenAIDeploymentName = os.Getenv("AZURE_OPENAI_DEPLOYMENT_NAME")
	config.AzureOpenAIAPIVersion = os.Getenv("AZURE_OPENAI_API_VERSION")

	// Backward compatibility: LocalEndpoint
	if config.OllamaEndpoint == "" {
		config.LocalEndpoint = os.Getenv("LOCAL_LLM_ENDPOINT")
	}

	// Load routing configuration
	routingConfig := LoadRoutingConfig()
	config.RoutingStrategy = routingConfig.Strategy
	config.ProviderWeights = routingConfig.ProviderWeights
	config.DefaultProvider = routingConfig.DefaultProvider

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
	if config.GeminiKey != "" {
		log.Printf("  - Gemini: enabled (key: %s..., model: %s)", config.GeminiKey[:min(10, len(config.GeminiKey))], config.GeminiModel)
	}
	if config.MistralKey != "" {
		log.Printf("  - Mistral: enabled (key: %s..., model: %s)", config.MistralKey[:min(10, len(config.MistralKey))], config.MistralModel)
	}
	if config.AzureOpenAIEndpoint != "" {
		log.Printf("  - Azure OpenAI: enabled (endpoint: %s, deployment: %s)", config.AzureOpenAIEndpoint, config.AzureOpenAIDeploymentName)
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

	// Resolve and log the active governance profile at orchestrator startup.
	// This mirrors the agent startup banner so operators can see what posture
	// BOTH components are running under. The orchestrator consults the same
	// detection engine for response-side PII/SQLi scoring, so the profile
	// must be visible here too. (Review finding M2.)
	profile := agent.ResolveProfile()
	agent.LogProfileBanner("orchestrator", profile, agent.DetectionConfigFromEnv())

	// Initialize components
	initializeComponents()

	// Cleanup node enforcement on shutdown
	if heartbeatService != nil {
		defer heartbeatService.Stop()
	}
	if nodeMonitor != nil {
		defer nodeMonitor.Stop()
	}
	// Cleanup Redis for policy enforcement on shutdown
	defer func() {
		if err := ClosePolicyRedis(); err != nil {
			log.Printf("Error closing Redis: %v", err)
		}
	}()

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
	r.HandleFunc("/api/v1/audit/tool-call", auditToolCallHandler).Methods("POST")
	r.HandleFunc("/api/v1/audit/tenant/{tenant_id}", tenantAuditLogsHandler).Methods("GET")

	// Policy overrides (ADR-044) + explainability (ADR-043) — Plugin Batch 1
	r.HandleFunc("/api/v1/overrides", createOverrideHandler).Methods("POST")
	r.HandleFunc("/api/v1/overrides", listOverridesHandler).Methods("GET")
	r.HandleFunc("/api/v1/overrides/{id}", getOverrideHandler).Methods("GET")
	r.HandleFunc("/api/v1/overrides/{id}", revokeOverrideHandler).Methods("DELETE")
	r.HandleFunc("/api/v1/decisions/{id}/explain", explainDecisionHandler).Methods("GET")
	// V1.1 decision-list companion (issue #1982). Lookback window + page
	// size are tier-gated (see decisions_list_handler.go); cap-hit returns
	// the V1 upgrade envelope at 429.
	r.HandleFunc("/api/v1/decisions", listDecisionsHandler).Methods("GET")
	r.HandleFunc("/api/v1/audit/summary", auditSummaryRequestHandler).Methods("POST", "OPTIONS")

	// Workflow endpoints
	r.HandleFunc("/api/v1/workflows/executions/tenant/{tenant_id}", tenantWorkflowExecutionsHandler).Methods("GET")
	r.HandleFunc("/api/v1/workflows/execute", executeWorkflowHandler).Methods("POST")
	r.HandleFunc("/api/v1/workflows/executions/{id}", getWorkflowExecutionHandler).Methods("GET")
	r.HandleFunc("/api/v1/workflows/executions", listWorkflowExecutionsHandler).Methods("GET")
	// HITL endpoints (Issue #1082)
	r.HandleFunc("/api/v1/workflows/executions/{id}/hitl-status", getHITLExecutionStatusHandler).Methods("GET")

	// Multi-Agent Planning endpoints (v0.1 + v1.0)
	r.HandleFunc("/api/v1/plan", planRequestHandler).Methods("POST")                                 // GeneratePlan (stores plan)
	r.HandleFunc("/api/v1/plan/execute", executePlanHandler).Methods("POST")                         // ExecutePlan (executes stored plan)
	r.HandleFunc("/api/v1/plan/{id}", getPlanStatusHandler).Methods("GET")                           // GetPlanStatus (retrieve plan)
	r.HandleFunc("/api/v1/plan/{id}/cancel", cancelPlanHandler).Methods("POST")                      // CancelPlan (MAP v1.0)
	r.HandleFunc("/api/v1/plan/{id}/versions", getPlanVersionsHandler).Methods("GET")                // GetPlanVersions (MAP v1.0)
	r.HandleFunc("/api/v1/plan/{id}", updatePlanHandler).Methods("PUT")                              // UpdatePlan (MAP v1.0)
	r.HandleFunc("/api/v1/plan/{id}/resume", resumePlanHandler).Methods("POST")                      // ResumePlan (MAP v1.0, Enterprise)
	r.HandleFunc("/api/v1/plan/{id}/rollback/{version:[0-9]+}", rollbackPlanHandler).Methods("POST") // RollbackPlan (MAP v1.0, Enterprise)

	// MAP step approval endpoints (v4.3.0, Enterprise — #1076; tier lowered
	// to Evaluation+ in v7.4.0 — #1677).
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/approve", mapStepApproveHandler).Methods("POST")
	r.HandleFunc("/api/v1/plans/{id}/steps/{step_id}/reject", mapStepRejectHandler).Methods("POST")
	// MAP plane-scoped pending approvals listing — the MAP counterpart of the
	// WCP /api/v1/workflows/approvals/pending endpoint (Issue #1680). Tier
	// gate is enforced inside the handler (IsHITLApprovalEnabled) to match
	// approve/reject semantics.
	r.HandleFunc("/api/v1/plans/approvals/pending", mapPendingApprovalsHandler).Methods("GET", "OPTIONS")

	// Cost Estimation endpoints (v4.3.0)
	r.HandleFunc("/api/v1/plans/estimate", estimatePlanCostHandler).Methods("POST") // EstimatePlanCost
	r.HandleFunc("/api/v1/plans/{id}/cost", getPlanCostHandler).Methods("GET")      // GetPlanCost

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

	// Dynamic Policy API (ADR-026: Single Entry Point Architecture)
	// New consistent path: /api/v1/dynamic-policies (matches /api/v1/static-policies pattern)
	if dynamicPolicyAPIHandler != nil {
		dynamicPolicyAPIHandler.RegisterRoutes(r)
		log.Println("Dynamic Policy API routes registered (/api/v1/dynamic-policies)")
	}

	// MCP Dynamic Policy Evaluation Endpoint (Issue #968)
	// Called by Agent for dynamic policy evaluation before MCP queries
	// Works with both in-memory and database-backed policy engines
	if engine, ok := dynamicPolicyEngine.(MCPPolicyEngine); ok {
		mcpDynamicPolicyHandler := NewMCPDynamicPolicyHandler(engine)
		mcpDynamicPolicyHandler.RegisterRoutes(r)
		log.Println("MCP Dynamic Policy API routes registered (/api/v1/mcp/evaluate-policies)")
	}

	// LLM Provider Management API (ADR-007 - Pluggable LLM Providers)
	// Register routes only if bootstrap was successful
	if llmProviderAPIHandler != nil {
		llmProviderAPIHandler.RegisterRoutesWithMux(r)
		log.Println("LLM Provider API routes registered (/api/v1/llm-providers)")
	}

	// SEBI Compliance Module (Enterprise - India Regulatory)
	if sebiModule != nil {
		sebiModule.RegisterRoutesWithMux(r)
		if sebiModule.IsHealthy() {
			log.Println("SEBI Compliance API routes registered (/api/v1/sebi/...)")
		} else {
			log.Println("SEBI Compliance Module loaded (routes inactive — Enterprise build required)")
		}
	}

	// RBI FREE-AI Compliance Module (Enterprise - India Banking)
	if rbiModule != nil {
		rbiModule.RegisterRoutesWithMux(r)
		if rbiModule.IsHealthy() {
			log.Println("RBI FREE-AI Compliance API routes registered (/api/v1/rbi/...)")
		} else {
			log.Println("RBI FREE-AI Compliance Module loaded (routes inactive — Enterprise build required)")
		}
	}

	// EU AI Act Compliance Module (Enterprise - EU Regulatory)
	if euaiactModule != nil {
		euaiactModule.RegisterRoutesWithMux(r)
		if euaiactModule.IsHealthy() {
			log.Println("EU AI Act Compliance API routes registered (/api/v1/euaiact/...)")
		} else {
			log.Println("EU AI Act Compliance Module loaded (routes inactive — Enterprise build required)")
		}
	}

	// MAS FEAT Compliance Module (Enterprise - Singapore MAS)
	if masfeatModule != nil {
		masfeatModule.RegisterRoutesWithMux(r)
		if masfeatModule.IsHealthy() {
			log.Println("MAS FEAT Compliance API routes registered (/api/v1/masfeat/...)")
		} else {
			log.Println("MAS FEAT Compliance Module loaded (routes inactive — Enterprise build required)")
		}
	}

	// OJK Compliance Module (Enterprise - Indonesia OJK/BI/UU PDP)
	if ojkModule != nil {
		ojkModule.RegisterRoutesWithMux(r)
		if ojkModule.IsHealthy() {
			log.Println("OJK Compliance API routes registered (/api/v1/ojk/...)")
		} else {
			log.Println("OJK Compliance Module loaded (routes inactive — Enterprise build required)")
		}
	}

	// Media Governance Config API (#1222)
	if mediaGovHandler != nil {
		mediaGovHandler.RegisterRoutes(r)
		log.Println("Media Governance Config API routes registered (/api/v1/media-governance/...)")
	}
	if mediaAuditHandler != nil {
		mediaAuditHandler.RegisterRoutes(r)
		log.Println("Media Governance Audit Export API registered (/api/v1/media-governance/audit/...)")
	}

	// Execution Replay/Debug Mode (#763)
	if replayHandler != nil {
		replayHandler.RegisterRoutes(r)
		log.Println("Execution Replay API routes registered (/api/v1/executions/...)")
	}

	// Embedded Execution Viewer UI
	uiHandler := ui.NewHandler()
	uiHandler.RegisterRoutes(r)
	log.Println("Execution Viewer UI registered (/ui/executions/)")

	// Cost Controls & Budget Management (#764)
	if costHandler != nil {
		costHandler.RegisterCommunityRoutes(r)
		log.Println("Cost pricing & usage summary API routes registered (community)")
		if !isCommunityMode() {
			costHandler.RegisterEnterpriseRoutes(r)
			log.Println("Budget management & analytics API routes registered (enterprise)")
		}
	}

	// Workflow Control Plane V1 (#834)
	// Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
	if workflowControlHandler != nil {
		workflowControlHandler.RegisterRoutes(r)
		log.Println("Workflow Control Plane API routes registered (/api/v1/workflows/...)")
		if !isCommunityMode() {
			workflowControlHandler.RegisterEnterpriseRoutes(r)
			log.Println("WCP Enterprise routes registered (approval/rejection)")
		} else if tierChecker != nil && tierChecker.IsHITLApprovalEnabled() {
			workflowControlHandler.RegisterEvaluationRoutes(r)
			log.Println("WCP Evaluation routes registered (approval/rejection via eval license)")
		}
	}

	// Webhook management routes (available in all modes — webhooks are a core MAP v1.0 feature)
	if webhookHandler != nil {
		webhookHandler.RegisterRoutes(r)
		log.Println("Webhook API routes registered (/api/v1/webhooks/...)")
	}

	// Unified Execution Tracking (#1075)
	// Common API for tracking both MAP plans and WCP workflows
	if unifiedExecutionHandler != nil {
		unifiedExecutionHandler.RegisterRoutes(r)
		log.Println("Unified Execution API routes registered (/api/v1/unified/executions/...)")
	}

	// Policy Simulation (Evaluation tier+)
	if policySimulationHandler != nil {
		policySimulationHandler.RegisterRoutes(r)
		log.Println("Policy Simulation API routes registered (/api/v1/policies/simulate, /api/v1/policies/impact-report)")
	}

	// Evidence Export (Evaluation tier+)
	if evidenceExportHandler != nil {
		evidenceExportHandler.RegisterRoutes(r)
		log.Println("Evidence Export API routes registered (/api/v1/evidence/export, /api/v1/evidence/summary)")
	}

	// Agent Config CRUD API (MAP v1.0 — Enterprise)
	// Full CRUD for database-backed agent configs (EE binary overrides the 501 stub)
	if usageDB != nil && !isCommunityMode() {
		if factory := GetAgentCRUDHandlerFactory(); factory != nil {
			var registry *AgentRegistry
			if planningEngine != nil {
				registry = planningEngine.GetAgentRegistry()
			}
			agentCRUDHandler := factory(usageDB, registry)
			r.PathPrefix("/api/v1/agents").Handler(agentCRUDHandler)
			log.Println("Agent Config CRUD API routes registered (/api/v1/agents/...)")
		}
	}

	// Start server. Refactored from http.ListenAndServe → net.Listen +
	// http.Serve so the readiness signal (port-bound) precedes the
	// startup-telemetry goroutine. Pre-#2087 the goroutine fired BEFORE
	// the listener bound, so a process that failed to bind (port in use,
	// privilege denied, etc.) could still emit a "deployment started"
	// signal — false positive contradicting the locked rule "emit only
	// once /health would 200." Now the bind happens first; only on
	// success does the telemetry goroutine spawn.
	port := getEnv("PORT", "8081")
	handler := c.Handler(r)

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("AxonFlow Orchestrator listen on port %s: %v", port, err)
	}
	log.Printf("AxonFlow Orchestrator listening on port %s", port)

	// Anonymous platform startup telemetry (#2004 PR3). Fire-and-forget
	// in a goroutine — runs concurrently with http.Serve below. The
	// 5s HTTP timeout inside MaybeSendStartupTelemetry caps blocking;
	// AXONFLOW_TELEMETRY=off short-circuits, and community_saas mode
	// (DEPLOYMENT_MODE=community-saas) also short-circuits per the
	// user-locked design.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		sent, err := MaybeSendStartupTelemetry(ctx)
		if err != nil {
			log.Printf("[startup-telemetry] error: %v", err)
		} else if sent {
			log.Println("[startup-telemetry] ping delivered")
		}
	}()

	log.Fatal(http.Serve(listener, handler))
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
		// Set DATABASE_URL for components that read it from environment
		// This ensures NewDatabaseDynamicPolicyEngine() and other components can access the constructed URL
		if err := os.Setenv("DATABASE_URL", dbURL); err != nil {
			log.Printf("Warning: failed to set DATABASE_URL: %v", err)
		}
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

		// Initialize usage metering database connection.
		// v9 Brief 11.5 / Session 20: route through agent.OpenAppRoleConnection so
		// AXONFLOW_DB_USE_APP_ROLE=true (default in v9.0.0) actually flips the
		// connection role to axonflow_app_role instead of silently using the
		// table-owner role and bypassing FORCE RLS.
		var err error
		bootCtx := context.Background()
		usageDB, err = agent.OpenAppRoleConnection(bootCtx, dbURL, 5)
		if err != nil {
			log.Printf("Warning: Failed to connect to usage database: %v", err)
			log.Println("Usage metering will be disabled")
			usageDB = nil
		} else {
			var connectedRole string
			if err := usageDB.QueryRowContext(bootCtx, "SELECT current_user").Scan(&connectedRole); err != nil {
				log.Printf("Warning: Failed to query current_user on usageDB: %v (continuing)", err)
			}
			log.Printf("✅ usageDB connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
				connectedRole, agent.UseAppRoleEnabled(), agent.EnvAppRoleURL, os.Getenv(agent.EnvAppRoleURL) != "")
		}
	} else {
		log.Println("WARNING: DATABASE_URL environment variable is NOT set!")
		log.Println("⚠️  Usage metering disabled - DATABASE_URL required")
	}

	// Initialize Redis for distributed policy enforcement (rate limiting, budget tracking)
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		if err := InitPolicyRedis(redisURL); err != nil {
			log.Printf("⚠️  Failed to initialize Redis for policy enforcement: %v", err)
			log.Println("Falling back to in-memory policy storage")
		}
	}

	// Wire idempotency dedup for /api/v1/audit/tool-call (#2420). Opens an
	// admin pool for the cross-tenant background sweep; appDB is the same
	// pool the audit handler already uses. nil-tolerant if admin open
	// fails — sweep is a soft cap, the table is small and the TTL is
	// 24h-bounded.
	if usageDB != nil {
		idempAdminDB, idempAdminErr := agent.OpenPlatformAdminConnection(context.Background(), 3)
		if idempAdminErr != nil {
			log.Printf("[Idempotency] admin pool unavailable, sweep disabled: %v", idempAdminErr)
			idempAdminDB = nil
		}
		orchIdempStore = idempotency.NewStore(usageDB, idempAdminDB)
		if idempAdminDB != nil {
			go func() {
				ticker := time.NewTicker(1 * time.Hour)
				defer ticker.Stop()
				for range ticker.C {
					n, err := orchIdempStore.Sweep(context.Background())
					if err != nil {
						log.Printf("[Idempotency] sweep error: %v", err)
					} else if n > 0 {
						log.Printf("[Idempotency] swept %d expired key(s)", n)
					}
				}
			}()
		}
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

			// Initialize node monitor (only if explicitly enabled).
			//
			// Mirrors the agent's parallel site (platform/agent/run.go): the
			// EE GetActiveNodesByOrg runs `SELECT org_id, COUNT(*) FROM
			// agent_heartbeats ... GROUP BY org_id` — a cross-org sweep.
			// Under FORCE RLS on agent_heartbeats (mig 107) as
			// axonflow_app_role, that query silently returns 0 rows per org
			// and license-limit violations never fire. Open admin
			// (BYPASSRLS) connection if configured; fall back to usageDB
			// with a WARNING for legacy deployments + dev compose.
			if os.Getenv("ENABLE_NODE_MONITOR") == "true" {
				agent.RequirePlatformAdminOrFatal("NodeMonitor")
				alerter := node_enforcement.NewMultiChannelAlerter()
				monitorDB := usageDB
				if adminDB, adminErr := agent.OpenPlatformAdminConnection(ctx, 3); adminErr != nil {
					log.Printf("[NodeMonitor] failed to open admin connection (%v); falling back to usageDB", adminErr)
				} else if adminDB != nil {
					log.Println("[NodeMonitor] using axonflow_platform_admin (BYPASSRLS) connection for cross-org node counts")
					monitorDB = adminDB
				} else {
					log.Println("[NodeMonitor] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to usageDB. Under FORCE RLS as app_role, NodeMonitor will not observe cross-org rows.")
				}
				nodeMonitor = node_enforcement.NewNodeMonitor(monitorDB, alerter)
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

	// Wire config file loader for Priority 2 (Community config file support)
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

	// Initialize LLM Router context (ADR-007)
	ctx := context.Background()
	tenantID := os.Getenv("ORG_ID") // Use org ID as tenant ID
	if tenantID == "" {
		tenantID = "local-dev-org" // Default — matches docker-compose.yml
		log.Println("⚠️  ORG_ID not set — defaulting to 'local-dev-org'. Set ORG_ID explicitly for production deployments.")
	}
	// Load runtime config and convert directly to provider configs, bypassing
	// goroutine-unsafe os.Setenv (see ApplyLLMConfigToEnv deprecation).
	runtimeLLMConfig := LoadLLMConfigFromService(ctx, tenantID)
	providerConfigs := LLMConfigToProviderConfigs(runtimeLLMConfig)

	// Initialize tier-aware license checker early (needed for LLM registry provider count limit)
	tierChecker = NewEnvLicenseChecker()
	log.Printf("License tier: %s", tierChecker.Tier())

	// Initialize pluggable LLM provider system (ADR-007 Phase 2, ADR-022)
	// This uses the factory pattern from llm/factories.go and bootstrap from llm/bootstrap.go
	log.Println("Initializing pluggable LLM provider system (ADR-007 Phase 2)...")
	// Create registry with tier-aware provider count limit
	llmRegistry := llm.NewRegistry(llm.WithMaxProviders(tierChecker.MaxLLMProviders()))
	bootstrapResult, err := llm.BootstrapFromEnv(&llm.BootstrapConfig{
		SkipHealthCheck: false, // Perform health checks on startup
		ProviderConfigs: providerConfigs,
		Registry:        llmRegistry,
	})
	if err != nil {
		log.Printf("⚠️  LLM bootstrap error: %v (LLM features may be unavailable)", err)
	} else if len(bootstrapResult.ProvidersBootstrapped) == 0 {
		log.Println("ℹ️  No LLM providers bootstrapped (check ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_ENDPOINT)")
	} else {
		log.Printf("✅ Bootstrapped %d LLM provider(s): %v", len(bootstrapResult.ProvidersBootstrapped), bootstrapResult.ProvidersBootstrapped)
		if len(bootstrapResult.Warnings) > 0 {
			for _, w := range bootstrapResult.Warnings {
				log.Printf("⚠️  LLM bootstrap warning: %s", w)
			}
		}

		// Create the new router from the already-bootstrapped registry
		// Note: We use the registry from bootstrapResult directly instead of calling
		// QuickBootstrap() which would bootstrap providers again.
		//
		// Use routing config from environment variables (ADR-021: LLM Provider Routing Control)
		routingConfig := LoadRoutingConfig()
		weights := make(map[string]float64)
		if len(routingConfig.ProviderWeights) > 0 {
			// Use custom weights from PROVIDER_WEIGHTS env var
			for _, name := range bootstrapResult.ProvidersBootstrapped {
				if w, ok := routingConfig.ProviderWeights[name]; ok {
					weights[name] = w
				}
			}
			log.Printf("[LLM Router] Using custom weights from PROVIDER_WEIGHTS: %v", weights)
		} else {
			// Fall back to equal weights if no custom weights configured
			equalWeight := 1.0 / float64(len(bootstrapResult.ProvidersBootstrapped))
			for _, name := range bootstrapResult.ProvidersBootstrapped {
				weights[name] = equalWeight
			}
		}

		// Create unified router that bridges legacy and new APIs (ADR-022: Router Consolidation)
		// Convert orchestrator.RoutingStrategy to llm.RoutingStrategy
		llmProviderRouter = llm.NewUnifiedRouter(llm.UnifiedRouterConfig{
			Registry: bootstrapResult.Registry,
			RoutingConfig: llm.RoutingConfig{
				Strategy:        llm.RoutingStrategy(routingConfig.Strategy),
				ProviderWeights: weights,
				DefaultProvider: routingConfig.DefaultProvider,
			},
		})
		log.Printf("[LLM Router] Unified router initialized with strategy: %s", routingConfig.Strategy)

		// Create wrapper for LLMRouterInterface compatibility (ADR-022 Phase 6)
		llmRouterWrapper = NewUnifiedRouterWrapper(llmProviderRouter)
		log.Println("[LLM Router] Interface wrapper created for legacy compatibility")

		// Create API handler using the underlying Router
		llmProviderAPIHandler = NewLLMProviderAPIHandlerWithRouter(llmProviderRouter.Router(), log.Default())
		if llmProviderAPIHandler != nil {
			log.Println("✅ LLM Provider API handler initialized (ADR-007 Phase 2)")
		} else {
			log.Println("⚠️  Failed to create LLM Provider API handler (router registry issue)")
		}
	}

	// Initialize Amadeus API Client
	amadeusClient := NewAmadeusClient()
	if amadeusClient.IsConfigured() {
		log.Println("Amadeus API Client initialized and configured ✅")
	} else {
		log.Println("Amadeus API Client initialized (not configured - will use mock data)")
	}

	// Initialize shared policy engine in orchestrator process (required for response PII detection).
	// The agent has its own engine — the orchestrator needs its own since they're separate processes.
	if usageDB != nil {
		sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(
			usageDB, sharedpolicy.DefaultEngineConfig(), nil))
		log.Println("Shared policy engine initialized for orchestrator response processing")

		// Wire the orchestrator's OWN per-org detection-action override cache
		// (#2612). Separate binary → separate cache instance + DB handle from the
		// agent's. Makes the response plane honor a per-org redact/block/warn/log
		// posture instead of only the deployment-global config. Fail-safe to global.
		InitDetectionOverrides(usageDB)
	}

	// Initialize Response Processor (uses shared engine if available, else legacy regexes)
	responseProcessor = NewResponseProcessor()
	if responseProcessor.IsUsingSharedEngine() {
		log.Println("Response Processor initialized with shared policy engine (database-driven PII detection)")
	} else {
		log.Println("Response Processor initialized with legacy PII detection (shared engine not available)")
	}

	// Initialize Audit Logger
	auditLogger = NewAuditLogger(dbURL)
	log.Println("Audit Logger initialized")

	// Initialize Media Governance Pipeline
	log.Println("Initializing Media Governance Pipeline...")
	mediaResult, mediaErr := media.BootstrapFromEnv(nil)
	if mediaErr != nil {
		log.Printf("⚠️  Media bootstrap error: %v (media governance will be unavailable)", mediaErr)
	} else {
		mediaPipeline = media.NewPipeline(
			media.WithPipelineRegistry(mediaResult.Registry),
			media.WithPipelineAuditLogger(media.NewAuditLogger()),
		)
		if len(mediaResult.AnalyzersBootstrapped) > 0 {
			log.Printf("✅ Media Governance Pipeline initialized with %d analyzer(s): %v",
				len(mediaResult.AnalyzersBootstrapped), mediaResult.AnalyzersBootstrapped)
		} else {
			log.Println("ℹ️  Media Governance Pipeline initialized (no analyzers configured — governance signals will be empty)")
		}
	}

	// Initialize Media Governance Config Store (per-tenant config)
	if usageDB != nil {
		var configErr error
		mediaGovConfigStore, configErr = NewMediaGovernanceConfigStore(usageDB)
		if configErr != nil {
			log.Printf("⚠️  Failed to initialize media governance config store: %v", configErr)
		} else {
			mediaGovHandler = NewMediaGovernanceHandler(mediaGovConfigStore, tierChecker)
			mediaAuditHandler = NewMediaGovernanceAuditHandler(usageDB, tierChecker)
			log.Println("Media Governance Config Store initialized ✅")
		}
	}

	// Log media governance status for Community deployments
	if tierChecker != nil && !tierChecker.MediaGovernanceEnabled() {
		envVal := os.Getenv("MEDIA_GOVERNANCE_ENABLED")
		if envVal != "true" && envVal != "1" {
			log.Println("Media governance disabled. Set MEDIA_GOVERNANCE_ENABLED=true to activate.")
		}
	}

	// Initialize Audit Cleanup Service (tier-aware retention enforcement)
	// tierChecker already initialized above (before LLM registry creation)
	if usageDB != nil {
		auditCleanupService = NewAuditCleanupService(usageDB, tierChecker)

		// #2590: config-governed retention executor for the six audit tables
		// that had a retention config row but no executing prune branch
		// (UU PDP / DPA deletion obligations). Dry-run unless the operator
		// opts in via AXONFLOW_AUDIT_RETENTION_ENFORCE=true. Cross-org deletes
		// and the FORCE-RLS reads (audit_retention_config, decision_chain)
		// route through the axonflow_platform_admin (BYPASSRLS) pool when
		// configured; mirror the NodeMonitor fallback + warning otherwise.
		retentionEnforce := auditRetentionEnforceEnabled()
		auditCleanupService.SetRetentionEnforce(retentionEnforce)
		if adminDB, adminErr := agent.OpenPlatformAdminConnection(context.Background(), 3); adminErr != nil {
			log.Printf("[AuditRetention] failed to open admin connection (%v); falling back to usageDB", adminErr)
		} else if adminDB != nil {
			auditCleanupService.SetRetentionAdminDB(adminDB)
			log.Println("[AuditRetention] using axonflow_platform_admin (BYPASSRLS) connection for cross-org retention")
		} else if agent.UseAppRoleEnabled() {
			log.Println("[AuditRetention] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; under FORCE RLS as app_role, per-org overrides + decision_chain retention will not see cross-org rows")
		}

		auditCleanupService.StartCleanupWorker(context.Background(), 1*time.Hour)
		log.Printf("Audit Cleanup Service initialized (tier retention: %d days; config-governed retention executor enforce=%v)",
			tierChecker.AuditRetentionDays(), retentionEnforce)
	}

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
		workflowEngine.InitializeWithDependencies(llmRouterWrapper, amadeusClient)
		log.Println("Workflow Engine initialized successfully with API call support")

		// Initialize HITL Workflow Engine (Issue #1082)
		// Check if HITL is enabled via environment variable
		hitlEnabled = os.Getenv("AXONFLOW_HITL_ENABLED") == "true"
		if hitlEnabled {
			log.Println("Initializing HITL Workflow Engine (require_approval support)...")
			var policyChecker HITLPolicyChecker
			var approvalService HITLApprovalService
			if !isCommunityMode() {
				// Enterprise mode: wire real policy checker and approval adapter
				policyChecker = &MAPHITLPolicyChecker{}
				approvalService = &MAPHITLApprovalAdapter{}
				log.Println("HITL Enterprise adapters initialized (policy checker + approval service)")
			}
			hitlWorkflowEngine = NewHITLWorkflowEngine(workflowEngine, policyChecker, approvalService)
			log.Println("HITL Workflow Engine initialized ✅")
		} else {
			log.Println("HITL mode disabled (set AXONFLOW_HITL_ENABLED=true to enable)")
		}
	}

	// Initialize Planning Engine (Multi-Agent Planning v0.1)
	log.Println("Initializing Planning Engine...")
	if llmRouterWrapper != nil {
		planningEngine = NewPlanningEngine(llmRouterWrapper)
		log.Println("Planning Engine initialized with LLM-based decomposition")

		// Wire database agent source for enterprise mode (MAP v1.0)
		// This enables hybrid mode: file-based configs + database-backed configs (DB takes priority)
		if usageDB != nil && !isCommunityMode() {
			if factory := GetDatabaseAgentSourceFactory(); factory != nil {
				dbSource := factory(usageDB)
				orgID := os.Getenv("DEFAULT_ORG_ID")
				if orgID == "" {
					orgID = "default"
				}
				registry := planningEngine.GetAgentRegistry()
				registry.SetDatabaseSource(dbSource, orgID)
				if err := registry.LoadFromDatabase(context.Background()); err != nil {
					log.Printf("⚠️  Failed to load database agent configs: %v", err)
				} else {
					stats := registry.HybridStats()
					log.Printf("Database agent configs loaded (mode=%s, db_domains=%d, file_domains=%d)",
						stats.Mode, stats.DBSourcedDomains, stats.FileSourcedDomains)
				}
			}
		}
	} else {
		log.Println("WARNING: Planning Engine not initialized - LLM Router unavailable")
	}

	// Initialize generic connector router and wire to planning engine
	connectorRouter := InitDefaultConnectorRouter()
	if planningEngine != nil {
		planningEngine.SetConnectorRouter(connectorRouter)
		caps := connectorRouter.ListCapabilities()
		if len(caps) > 0 {
			log.Printf("Generic connector router wired to Planning Engine (%d capabilities)", len(caps))
		} else {
			log.Println("Generic connector router initialized (no capabilities configured)")
		}
	}

	// Initialize Result Aggregator (Multi-Agent Planning v0.1)
	log.Println("Initializing Result Aggregator...")
	if llmRouterWrapper != nil {
		resultAggregator = NewResultAggregator(llmRouterWrapper)
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
		// Issue #1082: Pass the policy engine as a PolicyEngineRefresher so the
		// PolicyService can trigger immediate cache refresh after policy changes.
		// Both DynamicPolicyEngine and DatabaseDynamicPolicyEngine implement RefreshPolicies().
		var policyRefresher PolicyEngineRefresher
		if dbEngine, ok := dynamicPolicyEngine.(*DatabaseDynamicPolicyEngine); ok {
			policyRefresher = dbEngine
		} else if memEngine, ok := dynamicPolicyEngine.(*DynamicPolicyEngine); ok {
			policyRefresher = memEngine
		}
		policyService := NewPolicyServiceWithRefresher(policyRepo, policyRefresher)
		policyAPIHandler = NewPolicyAPIHandler(policyService)
		log.Println("Policy CRUD API initialized ✅")

		// Initialize Dynamic Policy API (ADR-026: Single Entry Point)
		dynamicPolicyAPIHandler = NewDynamicPolicyAPIHandler(policyService)
		log.Println("Dynamic Policy API initialized ✅ (ADR-026)")

		// Initialize Policy Simulation + Conflict Detection (Evaluation tier+)
		conflictService := NewPolicyConflictService(policyService)
		if tierChecker != nil && tierChecker.IsPolicySimulationEnabled() {
			policySimulationHandler = NewPolicySimulationHandler(dynamicPolicyEngine, policyService, conflictService, tierChecker)
			log.Println("Policy Simulation API initialized ✅ (Evaluation tier)")
		}

		// Initialize Evidence Export (Evaluation tier+)
		if tierChecker != nil && tierChecker.IsEvidenceExportEnabled() {
			evidenceExportHandler = NewEvidenceExportHandler(usageDB, tierChecker)
			log.Println("Evidence Export API initialized ✅ (Evaluation tier)")
		}

		// Initialize Policy Templates API (Track D - Policy Templates)
		log.Println("Initializing Policy Templates API...")
		templateRepo := NewTemplateRepository(usageDB)
		templateService := NewTemplateService(templateRepo, policyRepo)
		templateAPIHandler = NewTemplateAPIHandler(templateService)
		log.Println("Policy Templates API initialized ✅")

		// Initialize Execution Replay/Debug Mode (#763)
		log.Println("Initializing Execution Replay Service...")
		replayRepo := replay.NewPostgresRepository(usageDB)
		replayService = replay.NewService(replayRepo)
		replayHandler = replay.NewHandler(replayService)

		// Wire replay recorder to workflow engine
		if workflowEngine != nil {
			replayAdapter := NewReplayServiceAdapter(replayService)
			workflowEngine.SetReplayRecorder(replayAdapter)
			log.Println("Execution Replay Service wired to Workflow Engine ✅")
		}
		log.Println("Execution Replay Service initialized ✅")

		// Initialize Cost Controls & Budget Management (#764)
		log.Println("Initializing Cost Controls Service...")
		costRepo := cost.NewPostgresRepository(usageDB)
		pricing := cost.LoadPricingFromEnv()
		costService = cost.NewService(costRepo, pricing)
		costHandler = cost.NewHandler(costService)
		log.Println("Cost Controls Service initialized ✅")

		// Wire cost estimation into planning engine for plan cost estimates
		if planningEngine != nil && pricing != nil {
			planningEngine.SetPricingConfig(pricing)
			log.Println("Cost estimation wired to Planning Engine ✅")
		}

		// Wire cost estimation into workflow engine for per-step cost tracking
		if workflowEngine != nil && pricing != nil {
			workflowEngine.SetPricingConfig(pricing)
			log.Println("Cost estimation wired to Workflow Engine ✅")
		}

		// Initialize MAP Two-Step Execution (#925)
		log.Println("Initializing Planning Service for MAP two-step execution...")
		planRepo := planning.NewPostgresRepository(usageDB)
		// Use tier-appropriate plan limits
		planConfig := planning.ServiceConfig{
			MaxPlansWithVersioning: tierChecker.MaxPlans(),
			MaxVersionsPerPlan:     tierChecker.MaxVersionsPerPlan(),
		}
		planService = planning.NewServiceWithConfig(planRepo, planConfig)
		// Wire audit logging for MAP (Issue #1019, #1020)
		if auditLogger != nil {
			planService.SetAuditLogger(NewMAPAuditAdapter(auditLogger))
		}
		// Start background cleanup worker for expired plans (configurable interval)
		cleanupInterval := 15 * time.Minute
		if envInterval := os.Getenv("PLAN_CLEANUP_INTERVAL"); envInterval != "" {
			if parsed, err := time.ParseDuration(envInterval); err == nil && parsed > 0 {
				cleanupInterval = parsed
				log.Printf("Using custom plan cleanup interval: %v", cleanupInterval)
			} else {
				log.Printf("Invalid PLAN_CLEANUP_INTERVAL %q, using default 15m", envInterval)
			}
		}
		planService.StartCleanupWorkerWithMetrics(context.Background(), cleanupInterval, func(cleaned int, err error, duration time.Duration) {
			if err == nil && cleaned > 0 {
				promPlanCleanups.Add(float64(cleaned))
			}
		})
		log.Println("Planning Service initialized ✅")

		// Initialize unified execution tracking (#1075)
		log.Println("Initializing Unified Execution Tracker for MAP...")
		executionRepo = execution.NewPostgresRepository(usageDB)
		mapExecutionTracker = NewMAPExecutionTracker(executionRepo, planService)
		mapExecutionTracker.MaxConcurrentExecutions = tierChecker.MaxConcurrentExecutions()
		// Wire execution repo to audit cleanup for history purging
		if auditCleanupService != nil {
			auditCleanupService.SetExecutionRepo(executionRepo)
		}
		log.Println("Unified Execution Tracker initialized ✅")

		// Initialize Workflow Control Plane V1 (#834)
		// Governance gates for external orchestrators (LangChain, LangGraph, CrewAI)
		log.Println("Initializing Workflow Control Plane Service...")
		workflowControlRepo := workflow_control.NewPostgresRepository(usageDB)
		workflowControlConfig := &workflow_control.ServiceConfig{
			BaseURL: os.Getenv("PORTAL_BASE_URL"), // For generating approval URLs
		}
		// Create policy adapter to connect WCP to dynamic policy engine (Issue #1021)
		wcpPolicyAdapter := NewWCPPolicyAdapter(dynamicPolicyEngine)

		// Issue #1082: Wire WCP require_approval action to HITL queue (Enterprise only)
		if err := InitializeWCPHITL(usageDB, wcpPolicyAdapter); err != nil {
			log.Printf("⚠️  WCP HITL wiring failed: %v", err)
		}

		workflowControlService = workflow_control.NewService(workflowControlRepo, wcpPolicyAdapter, workflowControlConfig)

		// Wire audit logging for WCP (Issue #1019)
		if auditLogger != nil {
			workflowControlService.SetAuditLogger(NewWCPAuditAdapter(auditLogger))
		}

		// Wire unified execution tracking for WCP (#1075)
		wcpExecutionTracker := NewWCPExecutionTracker(executionRepo, workflowControlService)
		wcpExecutionTracker.MaxConcurrentExecutions = tierChecker.MaxConcurrentExecutions()
		if pricing != nil {
			wcpExecutionTracker.SetCostEstimator(pricing)
		}
		workflowControlService.SetExecutionTracker(wcpExecutionTracker)

		// Create EventHub for SSE streaming (#1074)
		executionEventHub := execution.NewEventHub()
		mapExecutionTracker.SetEventHub(executionEventHub)
		wcpExecutionTracker.SetEventHub(executionEventHub)

		// Create unified execution handler for both MAP and WCP (#1075)
		unifiedExecutionHandler = NewUnifiedExecutionHandler(executionRepo, mapExecutionTracker, wcpExecutionTracker, executionEventHub, planService)
		unifiedExecutionHandler.SetLicenseChecker(tierChecker)
		log.Println("Unified Execution Handler initialized ✅")

		workflowControlHandler = workflow_control.NewHandler(workflowControlService)
		log.Println("Workflow Control Plane Service initialized ✅")

		// Initialize Webhook Notifications (MAP v1.0 Phase B)
		webhookRepo := webhooks.NewPostgresRepository(usageDB)
		webhookService := webhooks.NewService(webhookRepo, credentialEncryptor)
		webhookHandler = webhooks.NewHandler(webhookService)
		workflowControlService.SetWebhookNotifier(webhookService)
		log.Println("Webhook Notifications Service initialized ✅")

		// Initialize MAP WCP Executor for confirm/step modes (MAP v1.0 Phase 3a)
		if planService != nil {
			mapWCPExecutor = NewMAPWCPExecutor(workflowControlService, planService)
			log.Println("MAP WCP Executor initialized (confirm/step modes) ✅")
		}

		// Initialize cloud storage backend for audit exports (#589)
		var auditStorageBackend cloudstorage.StorageBackend
		storageCfg := cloudstorage.NewStorageConfigFromEnv()
		if storageCfg.Type != "" && storageCfg.Type != cloudstorage.StorageTypeLocal {
			backend, storageErr := cloudstorage.NewStorageBackend(context.Background(), storageCfg)
			if storageErr != nil {
				log.Printf("⚠️  Audit export cloud storage (%s) init failed: %v — falling back to local", storageCfg.Type, storageErr)
			} else {
				auditStorageBackend = backend
				log.Printf("Audit export cloud storage initialized: %s ✅", storageCfg.Type)
			}
		}

		// Initialize SEBI Compliance Module (Enterprise - India Regulatory)
		log.Println("Initializing SEBI Compliance Module...")
		sebiConfig := sebi.SEBIModuleConfig{
			DB:             usageDB,
			StorageBackend: auditStorageBackend,
		}
		var sebiErr error
		sebiModule, sebiErr = sebi.NewSEBIModule(sebiConfig)
		if sebiErr != nil {
			log.Printf("⚠️  SEBI Module initialization error: %v", sebiErr)
		} else if sebiModule.IsHealthy() {
			log.Println("SEBI Compliance Module initialized ✅")
		} else {
			log.Println("⚠️  SEBI Module initialized but not healthy - database may be required")
		}

		// Initialize RBI FREE-AI Compliance Module (Enterprise - India Banking)
		log.Println("Initializing RBI FREE-AI Compliance Module...")
		rbiConfig := rbi.DefaultConfig()
		rbiConfig.DB = usageDB
		rbiConfig.StorageBackend = auditStorageBackend
		var rbiErr error
		rbiModule, rbiErr = rbi.NewRBIModule(rbiConfig)
		if rbiErr != nil {
			log.Printf("⚠️  RBI Module initialization error: %v", rbiErr)
		} else if rbiModule.IsHealthy() {
			log.Println("RBI FREE-AI Compliance Module initialized ✅")
		} else {
			log.Println("⚠️  RBI Module initialized but not healthy - database may be required")
		}

		// Initialize EU AI Act Compliance Module (Enterprise - EU Regulatory)
		log.Println("Initializing EU AI Act Compliance Module...")
		euaiactConfig := euaiact.ModuleConfig{
			DB:                   usageDB,
			StorageBackend:       auditStorageBackend,
			DefaultAccuracyMin:   0.80, // 80% minimum accuracy threshold
			DefaultBiasMax:       0.10, // 10% maximum bias score
			AlertCooldownMinutes: 15,   // 15 minutes between alerts
		}
		var euaiactErr error
		euaiactModule, euaiactErr = euaiact.NewModule(euaiactConfig)
		if euaiactErr != nil {
			log.Printf("⚠️  EU AI Act Module initialization error: %v", euaiactErr)
		} else if euaiactModule.IsHealthy() {
			log.Println("EU AI Act Compliance Module initialized ✅")
		} else {
			log.Println("⚠️  EU AI Act Module initialized but not healthy - database may be required")
		}

		// Initialize MAS FEAT Compliance Module (Enterprise - Singapore MAS)
		log.Println("Initializing MAS FEAT Compliance Module...")
		masfeatConfig := masfeat.ModuleConfig{
			DB:                              usageDB,
			DefaultBiasThreshold:            0.10, // 10% maximum bias score
			DefaultAssessmentValidityMonths: 12,   // 12 months validity
		}
		var masfeatErr error
		masfeatModule, masfeatErr = masfeat.NewModule(masfeatConfig)
		if masfeatErr != nil {
			log.Printf("⚠️  MAS FEAT Module initialization error: %v", masfeatErr)
		} else if masfeatModule.IsHealthy() {
			log.Println("MAS FEAT Compliance Module initialized ✅")
		} else {
			log.Println("⚠️  MAS FEAT Module initialized but not healthy - database may be required")
		}

		// Initialize OJK Compliance Module (Enterprise - Indonesia)
		log.Println("Initializing OJK Compliance Module...")
		ojkConfig := ojk.OJKModuleConfig{
			DB:             usageDB,
			StorageBackend: auditStorageBackend,
		}
		var ojkErr error
		ojkModule, ojkErr = ojk.NewOJKModule(ojkConfig)
		if ojkErr != nil {
			log.Printf("⚠️  OJK Module initialization error: %v", ojkErr)
		} else if ojkModule.IsHealthy() {
			log.Println("OJK Compliance Module initialized ✅")
		} else {
			log.Println("⚠️  OJK Module initialized but not healthy - database may be required")
		}
	} else {
		log.Println("⚠️  Policy CRUD API not initialized - database connection required")
		log.Println("⚠️  Policy Templates API not initialized - database connection required")
		log.Println("⚠️  SEBI Compliance Module not initialized - database connection required")
		log.Println("⚠️  RBI FREE-AI Compliance Module not initialized - database connection required")
		log.Println("⚠️  EU AI Act Compliance Module not initialized - database connection required")
		log.Println("⚠️  MAS FEAT Compliance Module not initialized - database connection required")
		log.Println("⚠️  OJK Compliance Module not initialized - database connection required")
	}

	// Initialize proxy auth validator — verifies requests came through the Agent gateway.
	// secretenv.Get trims SM-derived whitespace so the agent's HMAC signature
	// matches; otherwise the orchestrator's verifier would compute a different
	// digest from the same logical secret and fail-closed silently.
	if secret := secretenv.Get(serviceauth.SecretEnvVar); secret != "" {
		proxyTokenValidator = serviceauth.NewTokenValidator(secret, nil, serviceauth.DefaultClockSkew)
		log.Println("Proxy auth validation enabled for audit write endpoints")
	} else {
		log.Println("[SECURITY] Proxy auth validation disabled — AXONFLOW_INTERNAL_SERVICE_SECRET not set")
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	components := map[string]bool{
		"policy_engine":      dynamicPolicyEngine.IsHealthy(),
		"llm_router":         llmRouterWrapper != nil && llmRouterWrapper.IsHealthy(),
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

	// Add compliance modules
	if sebiModule != nil {
		components["sebi_compliance"] = sebiModule.IsHealthy()
	}
	if rbiModule != nil {
		components["rbi_compliance"] = rbiModule.IsHealthy()
	}
	if euaiactModule != nil {
		components["euaiact_compliance"] = euaiactModule.IsHealthy()
	}
	if masfeatModule != nil {
		components["masfeat_compliance"] = masfeatModule.IsHealthy()
	}

	health := map[string]interface{}{
		"status":            "healthy",
		"service":           "axonflow-orchestrator",
		"version":           getPlatformVersion(),
		"timestamp":         time.Now().UTC(),
		"components":        components,
		"capabilities":         getCapabilities(),
		"sdk_compatibility":    getSDKCompatibility(),
		"plugin_compatibility": getPluginCompatibility(),
		"features": map[string]bool{
			"multi_agent_planning": planningEngine != nil && resultAggregator != nil,
			"sebi_compliance":      sebiModule != nil && sebiModule.IsHealthy(),
			"rbi_compliance":       rbiModule != nil && rbiModule.IsHealthy(),
			"euaiact_compliance":   euaiactModule != nil && euaiactModule.IsHealthy(),
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

	// Identity from headers (set by the agent) takes precedence over JSON body.
	// This ensures tenant_id and org_id are server-derived from auth, not client-supplied.
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		req.User.TenantID = tenantID
		req.Client.TenantID = tenantID
	}
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		req.Client.OrgID = orgID
		req.User.OrgID = orgID
		// Defense-in-depth: warn if incoming org_id doesn't match deployment ORG_ID.
		// The agent should always send the deployment ORG_ID (validated at startup).
		// A mismatch here means either a misconfigured agent or direct orchestrator access.
		expectedOrgID := os.Getenv("ORG_ID")
		if expectedOrgID == "" {
			expectedOrgID = "local-dev-org"
		}
		if orgID != expectedOrgID {
			log.Printf("[SECURITY] X-Org-ID mismatch: received %q but deployment ORG_ID is %q. "+
				"This may indicate misconfigured agent or direct orchestrator access bypassing the agent.",
				logutil.Sanitize(orgID), logutil.Sanitize(expectedOrgID))
		}
	}
	if clientID := r.Header.Get("X-Tenant-ID"); clientID != "" {
		req.Client.ID = clientID
	}

	// Create processing context
	ctx := context.WithValue(r.Context(), ctxKeyRequestID, req.RequestID)
	ctx = context.WithValue(ctx, ctxKeyUser, req.User)
	ctx = context.WithValue(ctx, ctxKeyClient, req.Client)

	// 0. Run media governance analysis (before policy evaluation so media.* fields are available)
	var mediaAnalysisResp *MediaAnalysisResponse
	if len(req.Media) > 0 && mediaPipeline != nil && isMediaGovernanceEnabled(&req) {
		// Check per-tenant analyzer restrictions (enforcement pending pipeline support)
		if allowed := getAllowedAnalyzers(&req); allowed != nil {
			log.Printf("[MEDIA] Tenant analyzer restriction in effect: %v (pipeline filtering pending)", logutil.Sanitize(fmt.Sprintf("%v", allowed)))
		}
		mediaItems := convertMediaRequestsToMediaContent(req.Media)
		mediaStart := time.Now()
		results, mediaErr := mediaPipeline.AnalyzeMedia(ctx, req.RequestID, mediaItems)
		if mediaErr != nil {
			log.Printf("[MEDIA] Analysis failed for request %s: %v", logutil.Sanitize(req.RequestID), mediaErr)
			if mediaPipeline.GetEnforcementStrategy(ctx) == media.EnforcementFailClosed {
				// #2680: this fail-closed media deny is a terminal block; record a
				// canonical audit_logs row (plane=media, verdict=blocked) before the
				// 403 so the auditor sees it like every other plane's deny.
				if auditLogger != nil {
					_ = auditLogger.LogBlockedMedia(ctx, req, mediaErr)
				}
				sendErrorResponse(w, fmt.Sprintf("media analysis failed: %v", mediaErr), http.StatusForbidden)
				return
			}
		} else if len(results) > 0 {
			mediaAnalysisResp = buildMediaAnalysisResponse(results)
			if mediaAnalysisResp != nil {
				mediaAnalysisResp.AnalysisTimeMs = time.Since(mediaStart).Milliseconds()
			}

			// Inject media analysis into request context for dynamic policy engine
			// This enables media.* policy conditions (e.g., media.has_faces, media.nsfw_score)
			if req.Context == nil {
				req.Context = make(map[string]interface{})
			}
			// Flatten first result's signals for policy engine (covers single-image case)
			// For multi-image, policies can use the aggregated worst-case signals
			mediaCtx := map[string]interface{}{
				"has_faces":             false,
				"face_count":            0,
				"has_biometric_data":    false,
				"nsfw_score":            0.0,
				"violence_score":        0.0,
				"content_safe":          true,
				"has_pii":               false,
				"is_sensitive_document": false,
				"has_extracted_text":    false,
				"extracted_text_length": 0,
				"document_type":         "",
				"pii_types":             []string{},
			}
			// Aggregate worst-case signals across all media items
			for _, r := range results {
				if r.HasFaces {
					mediaCtx["has_faces"] = true
				}
				mediaCtx["face_count"] = mediaCtx["face_count"].(int) + r.FaceCount
				if r.HasBiometricData {
					mediaCtx["has_biometric_data"] = true
				}
				if r.NSFWScore > mediaCtx["nsfw_score"].(float64) {
					mediaCtx["nsfw_score"] = r.NSFWScore
				}
				if r.ViolenceScore > mediaCtx["violence_score"].(float64) {
					mediaCtx["violence_score"] = r.ViolenceScore
				}
				if !r.ContentSafe {
					mediaCtx["content_safe"] = false
				}
				if r.HasPII {
					mediaCtx["has_pii"] = true
				}
				if r.IsSensitiveDocument {
					mediaCtx["is_sensitive_document"] = true
				}
				if r.DocumentType != "" {
					mediaCtx["document_type"] = r.DocumentType
				}
				if len(r.PIITypes) > 0 {
					piiSet, _ := mediaCtx["_pii_set"].(map[string]bool)
					if piiSet == nil {
						piiSet = make(map[string]bool)
					}
					for _, pt := range r.PIITypes {
						piiSet[pt] = true
					}
					mediaCtx["_pii_set"] = piiSet
					piiTypes := make([]string, 0, len(piiSet))
					for pt := range piiSet {
						piiTypes = append(piiTypes, pt)
					}
					sort.Strings(piiTypes)
					mediaCtx["pii_types"] = piiTypes
				}
				if r.ExtractedText != "" {
					mediaCtx["has_extracted_text"] = true
					mediaCtx["extracted_text_length"] = mediaCtx["extracted_text_length"].(int) + len(r.ExtractedText)
				}
			}
			delete(mediaCtx, "_pii_set") // Remove temporary dedup set
			req.Context["media_analysis"] = mediaCtx
			log.Printf("[MEDIA] Analysis complete for request %s: %d item(s) analyzed", logutil.Sanitize(req.RequestID), len(results))
		}
	}

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

	// Inject policy routing hints into request context for LLM router (Issue #883)
	// This ensures dynamic policies can enforce strict provider compliance
	if policyResult.PreferredProvider != "" || len(policyResult.AllowedProviders) > 0 {
		if req.Context == nil {
			req.Context = make(map[string]interface{})
		}
		if policyResult.PreferredProvider != "" {
			req.Context["policy_preferred_provider"] = policyResult.PreferredProvider
		}
		if len(policyResult.AllowedProviders) > 0 {
			req.Context["policy_allowed_providers"] = policyResult.AllowedProviders
		}
		if policyResult.RoutingReason != "" {
			req.Context["policy_routing_reason"] = policyResult.RoutingReason
		}
		log.Printf("[POLICY_ROUTING] Injected routing hints: preferred=%s, allowed=%v, reason=%s",
			logutil.Sanitize(policyResult.PreferredProvider), policyResult.AllowedProviders, logutil.Sanitize(policyResult.RoutingReason))
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
			logutil.Sanitize(fmt.Sprintf("%v", req.Context["connector"])), logutil.Sanitize(req.Query))

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
	log.Printf("[LLM] Request received: skip_llm=%v, query=%q", req.SkipLLM, logutil.Sanitize(queryPreview))

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
		llmStartTime := time.Now()
		if llmRouterWrapper == nil {
			err = fmt.Errorf("LLM router not initialized")
			log.Printf("[LLM] ERROR: Router not available")
		} else {
			log.Printf("[LLM] CALLING: Routing to LLM provider (skip_llm=false)")
			llmResponse, providerInfo, err = llmRouterWrapper.RouteRequest(ctx, req)
		}
		llmTime := time.Since(llmStartTime)
		providerName := "unknown"
		if providerInfo != nil {
			providerName = providerInfo.Provider
		}
		log.Printf("[LLM] COMPLETED: provider=%s, latency=%v, err=%v", providerName, llmTime, err)

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

			sendErrorResponse(w, "LLM routing failed", http.StatusInternalServerError)
			return
		}
	}

	// Record successful LLM call
	promLLMCalls.WithLabelValues(providerInfo.Provider, "success").Inc()

	// 3. Process response (PII detection, redaction, etc.)
	processedResponse, redactionInfo := responseProcessor.ProcessResponse(ctx, req.User, llmResponse)

	// Canonical response-plane audit (#2626). The verdict carried by
	// redactionInfo drives BOTH the audit row and the HTTP outcome. correlation_id
	// ties this response row to the request-plane decision (W3C trace_id when the
	// caller propagates traceparent; else the request id); plane=llm + decision_id
	// make the row canonical (#2597/#2611) so the portal feed + lineage exporters
	// pick it up like every other plane.
	correlationID := correlationIDFromRequest(r, req.RequestID)
	ctx = context.WithValue(ctx, ctxKeyCorrelationID, correlationID)
	ctx = context.WithValue(ctx, ctxKeyRedactionInfo, redactionInfo)

	if redactionInfo != nil && redactionInfo.Verdict == responseVerdictBlocked {
		// The response plane WITHHELD the LLM response (validation/governance
		// deny). It is NEVER recorded as "allowed": write the canonical blocked
		// row and return a forbidden response instead of the mislabeled success
		// the old path sent. Audit-write failure cannot fail-open governance here
		// (the response was already withheld) — the row is enqueued fail-safe.
		_ = auditLogger.LogBlockedResponse(ctx, req, policyResult, redactionInfo)

		latencyMs := time.Since(startTime).Milliseconds()
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		promRequestDuration.WithLabelValues("blocked").Observe(float64(latencyMs))
		if orchestratorMetrics != nil {
			orchestratorMetrics.recordRequest(req.RequestType, providerInfo.Provider, latencyMs, false, true, 0, 0)
		}

		response := OrchestratorResponse{
			RequestID:      req.RequestID,
			Success:        false,
			Error:          "Response blocked by response-plane governance",
			Data:           processedResponse,
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

	// 4. Log successful request (verdict "allowed"/"redacted" carried in ctx)
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
		MediaAnalysis:  mediaAnalysisResp,
		ProcessingTime: time.Since(startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func providerStatusHandler(w http.ResponseWriter, r *http.Request) {
	var status map[string]ProviderStatus
	if llmRouterWrapper != nil {
		status = llmRouterWrapper.GetProviderStatus()
	} else {
		status = make(map[string]ProviderStatus)
	}

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

	// Validate weights before passing to router
	if err := validateProviderWeights(weights); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	if llmRouterWrapper == nil {
		sendErrorResponse(w, "LLM router not initialized", http.StatusServiceUnavailable)
		return
	}

	if err := llmRouterWrapper.UpdateProviderWeights(weights); err != nil {
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

// validateProviderWeights validates provider weight configuration.
func validateProviderWeights(weights map[string]float64) error {
	var totalWeight float64
	for provider, weight := range weights {
		if weight < 0 {
			return fmt.Errorf("invalid weight for provider %s: weight cannot be negative", provider)
		}
		if weight > 1 {
			return fmt.Errorf("invalid weight for provider %s: weight cannot exceed 1.0", provider)
		}
		totalWeight += weight
	}
	if totalWeight > 1.0 {
		return fmt.Errorf("invalid weights: total weight (%.2f) exceeds 1.0", totalWeight)
	}
	return nil
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
		TenantID   string    `json:"-"` // force-set from X-Tenant-ID; never client-controlled
		StartTime  time.Time `json:"start_time"`
		EndTime    time.Time `json:"end_time"`
		DecisionID string    `json:"decision_id,omitempty"` // ADR-043: filter by decision_id in policy_details JSONB
		PolicyName  string    `json:"policy_name,omitempty"` // ADR-043: filter by policy_name
		OverrideID  string    `json:"override_id,omitempty"` // ADR-044: filter by override_id in policy_details JSONB
		Action      string    `json:"action,omitempty"`      // filter by policy_decision (e.g. "blocked", "approved")
		Limit       int       `json:"limit,omitempty"`
		Offset      int       `json:"offset,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&searchReq); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Force tenant scoping from the proxy-injected header. Anyone reaching this
	// handler over the customer-portal proxy carries the session's tenant_id;
	// without this filter the query returned every tenant's audit logs to any
	// caller. The header is JSON-tag-ignored on the decoder so a malicious
	// payload can't override it.
	searchReq.TenantID = r.Header.Get("X-Tenant-ID")
	if searchReq.TenantID == "" {
		log.Printf("[audit/search] BLOCKED: missing X-Tenant-ID header from %s", r.RemoteAddr)
		sendErrorResponse(w, "tenant scoping required", http.StatusUnauthorized)
		return
	}

	if searchReq.Limit == 0 {
		searchReq.Limit = 100
	}

	// Enforce tier-based retention window on search start time
	if auditCleanupService != nil {
		cutoff := auditCleanupService.RetentionCutoff()
		if !cutoff.IsZero() && (searchReq.StartTime.IsZero() || searchReq.StartTime.Before(cutoff)) {
			searchReq.StartTime = cutoff
		}
	}

	results, totalCount, err := auditLogger.SearchAuditLogs(searchReq)
	if err != nil {
		sendErrorResponse(w, "Audit search failed", http.StatusInternalServerError)
		return
	}

	// Empty result must serialize as `[]`, not `null`. SearchAuditLogs returns
	// a nil slice when there are no rows, and json.Marshal turns that into
	// `null`, which breaks every client that does `for entry of entries`
	// or `entries.length`.
	if results == nil {
		results = []*AuditEntry{}
	}

	// Return response in SDK-expected format
	response := struct {
		Entries []*AuditEntry `json:"entries"`
		Total   int           `json:"total"`
		Limit   int           `json:"limit"`
		Offset  int           `json:"offset"`
	}{
		Entries: results,
		Total:   totalCount,
		Limit:   searchReq.Limit,
		Offset:  searchReq.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

var auditSummaryHandler *AuditSummaryHandler

func auditSummaryRequestHandler(w http.ResponseWriter, r *http.Request) {
	if auditSummaryHandler == nil {
		var db *sql.DB
		if auditLogger != nil {
			db = auditLogger.db
		}
		auditSummaryHandler = NewAuditSummaryHandler(db)
	}
	auditSummaryHandler.HandleSummary(w, r)
}

func tenantAuditLogsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]

	if tenantID == "" {
		sendErrorResponse(w, "Tenant ID is required", http.StatusBadRequest)
		return
	}

	// Reject any URL-supplied tenant that doesn't match the proxy-injected
	// session tenant. Without this check a portal user for tenant A could
	// read tenant B's audit logs by browsing to /api/v1/audit/tenant/B.
	//
	// Fail-closed on missing session tenant too (#1623 retro): the previous
	// `sessionTenant != ""` gate let callers bypass the cross-check by
	// omitting the X-Tenant-ID header — the AxonFlow Agent gateway always
	// sets it after authentication, so a missing header means an unauthenticated
	// request reached the orchestrator directly.
	sessionTenant := r.Header.Get("X-Tenant-ID")
	if sessionTenant == "" {
		log.Printf("[audit/tenant] BLOCKED: missing X-Tenant-ID header for URL tenant %q from %s",
			logutil.Sanitize(tenantID), r.RemoteAddr)
		sendErrorResponse(w, "X-Tenant-ID header is required", http.StatusUnauthorized)
		return
	}
	if sessionTenant != tenantID {
		log.Printf("[audit/tenant] BLOCKED: URL tenant %q does not match session tenant %q from %s",
			logutil.Sanitize(tenantID), logutil.Sanitize(sessionTenant), r.RemoteAddr)
		sendErrorResponse(w, "tenant scope mismatch", http.StatusForbidden)
		return
	}

	// Accept both limit (preferred) and page_size (deprecated) for backward compatibility
	limit := 50 // default
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	} else if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 1000 {
			limit = ps
		}
	}

	// Search audit logs for specific tenant with retention window
	var startTime time.Time
	if auditCleanupService != nil {
		cutoff := auditCleanupService.RetentionCutoff()
		if !cutoff.IsZero() {
			startTime = cutoff
		}
	}

	searchReq := struct {
		TenantID  string    `json:"tenant_id"`
		Limit     int       `json:"limit"`
		StartTime time.Time `json:"start_time"`
	}{
		TenantID:  tenantID,
		Limit:     limit,
		StartTime: startTime,
	}

	results, _, err := auditLogger.SearchAuditLogs(searchReq)
	if err != nil {
		sendErrorResponse(w, "Failed to fetch tenant audit logs", http.StatusInternalServerError)
		return
	}

	// Return response in SDK-expected format
	response := struct {
		Entries []*AuditEntry `json:"entries"`
		Total   int           `json:"total"`
		Limit   int           `json:"limit"`
		Offset  int           `json:"offset"`
	}{
		Entries: results,
		Total:   len(results),
		Limit:   searchReq.Limit,
		Offset:  0,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

func auditToolCallHandler(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	// Verify request came through the Agent gateway (not direct access).
	// The Agent proxy injects X-Axonflow-Proxy-Auth with an HMAC-signed token.
	// When AXONFLOW_INTERNAL_SERVICE_SECRET is configured, reject unverified requests.
	//
	// In Community mode the secret is optional, so an unset validator is
	// expected and the proxy-auth check is skipped. In any non-Community mode
	// (Enterprise, Community-SaaS) an unset validator means the deployment is
	// misconfigured — fail closed rather than silently accepting unauthenticated
	// requests that could spoof X-Tenant-ID / X-Org-ID for cross-tenant audit
	// attribution.
	proxyToken := r.Header.Get("X-Axonflow-Proxy-Auth")
	if proxyTokenValidator == nil && !isCommunityMode() {
		log.Printf("[AuditToolCall] BLOCKED: %s not configured in non-Community deployment — proxy-auth validation cannot run", serviceauth.SecretEnvVar)
		sendErrorResponse(w, "Unauthorized: internal-service auth not configured", http.StatusForbidden)
		return
	}
	if proxyTokenValidator != nil {
		if proxyToken == "" {
			log.Printf("[AuditToolCall] BLOCKED: missing proxy auth header (direct access attempt)")
			sendErrorResponse(w, "Unauthorized: request must be routed through AxonFlow Agent", http.StatusForbidden)
			return
		}
		valid, _, err := proxyTokenValidator.ValidateToken(proxyToken)
		if !valid {
			log.Printf("[AuditToolCall] BLOCKED: invalid proxy auth token: %v", err)
			sendErrorResponse(w, "Unauthorized: invalid proxy authentication", http.StatusForbidden)
			return
		}
	}

	// Extract client identity: prefer Basic auth, fall back to proxy-injected
	// headers ONLY if proxy auth was validated (proxyTokenValidator != nil and
	// token was valid). Without validated proxy auth, require Basic auth to
	// prevent spoofing of X-Tenant-ID headers.
	proxyAuthValidated := proxyTokenValidator != nil && proxyToken != ""
	clientID, err := extractBasicAuthClientID(r)
	if err != nil {
		if proxyAuthValidated {
			// Request came through validated agent proxy — trust injected headers
			clientID = r.Header.Get("X-Tenant-ID")
			if clientID == "" {
				clientID = r.Header.Get("X-Tenant-ID")
			}
		}
		if clientID == "" {
			sendErrorResponse(w, "Missing authentication", http.StatusUnauthorized)
			return
		}
	}

	var req ToolCallAuditEntry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.ToolName) == "" {
		sendErrorResponse(w, "tool_name is required", http.StatusBadRequest)
		return
	}

	// Derive tenant scope for audit attribution.
	// Priority: X-Tenant-ID header (proxy-injected) > clientID (from Basic auth).
	// SDKs send Basic auth only — tenant is derived from clientID.
	// Agent proxy sets X-Tenant-ID from authenticated client, so it's trusted
	// when proxy auth is validated.
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		// No header — derive from authenticated clientID (SDK direct calls)
		tenantID = clientID
	}
	if tenantID == "" {
		sendErrorResponse(w, "Missing authentication: tenant could not be determined", http.StatusUnauthorized)
		return
	}

	proxyVerified := proxyTokenValidator != nil && r.Header.Get("X-Axonflow-Proxy-Auth") != ""
	if !proxyVerified && clientID != tenantID {
		log.Printf("[AuditToolCall] BLOCKED: clientID %q does not match X-Tenant-ID %q (no proxy auth)", logutil.Sanitize(clientID), logutil.Sanitize(tenantID))
		sendErrorResponse(w, "Client ID does not match tenant scope", http.StatusForbidden)
		return
	}

	req.ClientID = clientID
	req.TenantID = tenantID
	req.OrgID = r.Header.Get("X-Org-ID")

	// Idempotency scope key. The agent-proxy path stamps X-Org-ID from
	// the authenticated client; SDK direct callers (the majority) do
	// NOT — for them, tenantID IS the org scope, mirroring the tenant
	// derivation convention this same handler uses for audit attribution
	// (clientID==tenantID for non-proxy paths). Without this fallback the
	// dedup would log a "lookup error: orgID empty" per retry and skip
	// the cache, defeating #2420 for the majority of callers.
	idempOrgID := req.OrgID
	if idempOrgID == "" {
		idempOrgID = tenantID
	}

	// Wrap the side-effecting LogToolCallAudit + response write in the
	// idempotency dedup helper. Pass-through when no Idempotency-Key
	// header is set or no store is wired. A retry within TTL returns the
	// original audit_id byte-for-byte — no double-counted metrics, no
	// duplicate audit row (#2420).
	idempotency.Wrap(w, r, orchIdempStore, idempOrgID, tenantID, "audit.tool-call", func(w http.ResponseWriter, r *http.Request) {
	auditEntry := auditLogger.LogToolCallAudit(r.Context(), &req)

	auditID := ""
	var ts time.Time
	if auditEntry != nil {
		auditID = auditEntry.ID
		ts = auditEntry.Timestamp
	} else {
		auditID = generateAuditID()
		ts = time.Now().UTC()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"audit_id":  auditID,
		"status":    "recorded",
		"timestamp": ts,
	}); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
	}) // end idempotency.Wrap closure
}

// extractBasicAuthClientID extracts the client ID from an OAuth2 Basic auth header.
// Format: Authorization: Basic base64(clientId:clientSecret)
// Returns the clientID and nil on success, or an error if the header is missing/invalid.
func extractBasicAuthClientID(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", fmt.Errorf("missing or invalid Authorization header")
	}

	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("invalid base64 in Authorization header")
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", fmt.Errorf("invalid Basic auth format: expected clientId:clientSecret")
	}

	return parts[0], nil
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
// convertMediaRequestsToMediaContent converts API media requests to pipeline media types.
func convertMediaRequestsToMediaContent(requests []MediaContentRequest) []media.MediaContent {
	items := make([]media.MediaContent, len(requests))
	for i, r := range requests {
		items[i] = media.MediaContent{
			Source:     media.MediaSourceType(r.Source),
			Base64Data: r.Base64Data,
			URL:        r.URL,
			MIMEType:   r.MIMEType,
		}
	}
	return items
}

// buildMediaAnalysisResponse converts pipeline results to API response format.
func buildMediaAnalysisResponse(results []*media.AggregatedMediaResult) *MediaAnalysisResponse {
	if len(results) == 0 {
		return nil
	}

	resp := &MediaAnalysisResponse{}
	var totalCost float64

	for _, r := range results {
		item := MediaAnalysisItemResponse{
			MediaIndex:          r.MediaIndex,
			SHA256Hash:          r.SHA256Hash,
			HasFaces:            r.HasFaces,
			FaceCount:           r.FaceCount,
			HasBiometricData:    r.HasBiometricData,
			NSFWScore:           r.NSFWScore,
			ViolenceScore:       r.ViolenceScore,
			ContentSafe:         r.ContentSafe,
			DocumentType:        r.DocumentType,
			IsSensitiveDocument: r.IsSensitiveDocument,
			HasPII:              r.HasPII,
			PIITypes:            r.PIITypes,
			HasExtractedText:    r.ExtractedText != "",
			ExtractedTextLength: len(r.ExtractedText),
			EstimatedCostUSD:    r.EstimatedCostUSD,
			Warnings:            r.Warnings,
			StructuredWarnings:  r.StructuredWarnings,
		}
		resp.Results = append(resp.Results, item)
		totalCost += r.EstimatedCostUSD
	}

	resp.TotalCostUSD = totalCost
	return resp
}

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

// planExecutionTimeout returns the context timeout for MAP plan execution.
// Scales to 30s per step (matching single-step resume timeout), minimum 60s.
// Balanced mode groups steps but each LLM call can take 10-20s.
//
// The cap defaults to 300s to stay within the front-door ALB's default
// idle_timeout (configured at 300s in the marketplace and community-saas
// CFN templates). Going above the ALB timeout would let the orchestrator
// keep computing after the client connection was already killed — the
// caller sees a 504 mid-stream and the work is wasted. 300s covers a
// 10-step plan at the scaling rate above.
//
// Operators running long plans (high-step-count MAP workflows) can raise
// the cap by setting AXONFLOW_MAP_MAX_TIMEOUT_SECONDS. The cap is clamped
// to [60s, 1800s] — below 60s would shorten non-plan code paths that
// don't need the env var, above 30 minutes crosses into WCP/human-in-
// the-loop territory where a synchronous HTTP round-trip is the wrong
// model. When bumping the cap, also raise `AlbIdleTimeoutSeconds` on
// the CFN stack (default 300) so the front-door doesn't cut off first.
func planExecutionTimeout(stepCount int) time.Duration {
	timeout := time.Duration(stepCount) * 30 * time.Second
	if timeout < 60*time.Second {
		timeout = 60 * time.Second
	}
	maxTimeout := mapMaxTimeoutFromEnv()
	if timeout > maxTimeout {
		timeout = maxTimeout
	}
	return timeout
}

// mapMaxTimeoutFromEnv reads AXONFLOW_MAP_MAX_TIMEOUT_SECONDS, clamps
// it to [60s, 1800s], and falls back to 300s when unset/invalid. Logs
// once-per-process at startup when a non-default value is chosen.
var (
	mapMaxTimeoutOnce   sync.Once
	mapMaxTimeoutCached time.Duration
)

func mapMaxTimeoutFromEnv() time.Duration {
	mapMaxTimeoutOnce.Do(func() {
		const defaultTimeout = 300 * time.Second
		const minTimeout = 60 * time.Second
		const maxTimeout = 1800 * time.Second
		raw := os.Getenv("AXONFLOW_MAP_MAX_TIMEOUT_SECONDS")
		if raw == "" {
			mapMaxTimeoutCached = defaultTimeout
			return
		}
		secs, err := strconv.Atoi(raw)
		if err != nil || secs <= 0 {
			log.Printf("[MAP] AXONFLOW_MAP_MAX_TIMEOUT_SECONDS=%q is not a positive integer — using default %s", raw, defaultTimeout)
			mapMaxTimeoutCached = defaultTimeout
			return
		}
		chosen := time.Duration(secs) * time.Second
		if chosen < minTimeout {
			log.Printf("[MAP] AXONFLOW_MAP_MAX_TIMEOUT_SECONDS=%d below 60s floor — clamping to 60s", secs)
			chosen = minTimeout
		}
		if chosen > maxTimeout {
			log.Printf("[MAP] AXONFLOW_MAP_MAX_TIMEOUT_SECONDS=%d above 1800s ceiling — clamping to 1800s. Also raise AlbIdleTimeoutSeconds on the CFN stack or the front-door will 504 first.", secs)
			chosen = maxTimeout
		}
		if chosen != defaultTimeout {
			log.Printf("[MAP] planExecutionTimeout cap set to %s via AXONFLOW_MAP_MAX_TIMEOUT_SECONDS", chosen)
		}
		mapMaxTimeoutCached = chosen
	})
	return mapMaxTimeoutCached
}

// isCommunityMode returns true when running in Community mode.
// Community mode: DEPLOYMENT_MODE == "community" or unset (empty string).
// This gates feature access (enterprise-only routes, execution modes).
// Evaluation tier elevates resource limits via LicenseChecker, not feature access —
// evaluation users run the community binary with higher limits, not enterprise features.
func isCommunityMode() bool {
	mode := os.Getenv("DEPLOYMENT_MODE")
	return mode == "community" || mode == ""
}

// isCommunitySaasMode returns true when running as the shared community SaaS
// server. Mirrors platform/agent/run.go's helper of the same name. Used by
// the startup-telemetry path to suppress self-pings on AxonFlow-operated
// stacks (try.getaxonflow.com) — the canonical wiring sets
// DEPLOYMENT_MODE=community-saas via docker-compose.community-saas.yml.
//
// Intentionally NOT a member of isCommunityMode's true set: a csaas
// deployment is its own mode (no license, has registration creds, rate-
// limited differently). Treating them as the same gate would re-enable
// feature surfaces csaas explicitly disables.
func isCommunitySaasMode() bool {
	return os.Getenv("DEPLOYMENT_MODE") == "community-saas"
}

// isMediaGovernanceEnabled resolves whether media governance is active for a request.
// Resolution order: per-tenant override (Enterprise) → tier default → env var.
func isMediaGovernanceEnabled(req *OrchestratorRequest) bool {
	// 1. Per-tenant override (Enterprise only)
	tenantID := req.Client.TenantID
	if tenantID == "" {
		tenantID = req.User.TenantID
	}
	if mediaGovConfigStore != nil && tenantID != "" {
		if cfg := mediaGovConfigStore.Get(tenantID); cfg != nil {
			return cfg.Enabled
		}
	}

	// 2. Tier default from license checker
	if tierChecker != nil && tierChecker.MediaGovernanceEnabled() {
		return true
	}

	// 3. Env var opt-in (Community)
	envVal := os.Getenv("MEDIA_GOVERNANCE_ENABLED")
	return envVal == "true" || envVal == "1"
}

// getAllowedAnalyzers returns the per-tenant allowed analyzer list from config.
// Returns nil if no per-tenant config exists (meaning all analyzers are allowed).
func getAllowedAnalyzers(req *OrchestratorRequest) []string {
	tenantID := req.Client.TenantID
	if tenantID == "" {
		tenantID = req.User.TenantID
	}
	if mediaGovConfigStore != nil && tenantID != "" {
		if cfg := mediaGovConfigStore.Get(tenantID); cfg != nil && len(cfg.AllowedAnalyzers) > 0 {
			return cfg.AllowedAnalyzers
		}
	}
	return nil
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

// correlationIDFromRequest derives the W3C correlation_id (#2611) for a response
// row. It prefers the trace_id from an inbound `traceparent` header (so the
// response-plane row shares a correlation key with the request-plane decision
// when the caller propagates W3C trace context), falling back to the request id
// so the value is never empty.
func correlationIDFromRequest(r *http.Request, fallback string) string {
	if r != nil {
		if tid := traceIDFromTraceparent(r.Header.Get("traceparent")); tid != "" {
			return tid
		}
	}
	return fallback
}

// traceIDFromTraceparent extracts the 32-hex trace_id field from a W3C
// `traceparent` header (version-format `00-<trace_id>-<span_id>-<flags>`).
// Returns "" when the header is absent or malformed.
func traceIDFromTraceparent(h string) string {
	if h == "" {
		return ""
	}
	parts := strings.Split(h, "-")
	if len(parts) < 4 {
		return ""
	}
	traceID := parts[1]
	if len(traceID) != 32 {
		return ""
	}
	for _, c := range traceID {
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return ""
		}
	}
	return traceID
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

	// Identity from agent-set headers takes precedence over the JSON body.
	// req.User.OrgID specifically: the agent's User struct (platform/agent/run.go)
	// has TenantID but NOT OrgID, so even when the agent forwards the body it
	// can't carry the org. Without this header read, the workflow engine's
	// replay recorder writes execution rows with org_id="" while the read-side
	// /api/v1/executions endpoint filters by the agent's X-Org-ID — producing
	// zero matches. TenantID is already in the body but we re-derive from the
	// header for defense-in-depth so direct-orchestrator callers can't claim a
	// different identity than the agent authenticated.
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		req.User.TenantID = tenantID
	}
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		req.User.OrgID = orgID
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

	// Execute workflow - use HITL engine if enabled (Issue #1082)
	var execution interface{}
	var err error

	if hitlEnabled && hitlWorkflowEngine != nil {
		// HITL-aware execution with pause/resume support
		hitlExec, hitlErr := hitlWorkflowEngine.ExecuteWithHITL(r.Context(), req.Workflow, req.Input, req.User)
		if hitlErr != nil {
			// Check if this is a pause for approval (not an error)
			if hitlExec != nil && hitlExec.Status == StatusPaused {
				// Store execution for later resume
				hitlWorkflowEngine.SaveExecution(hitlExec)
				// Return paused status with approval ID
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted) // 202 Accepted - pending human approval
				if err := json.NewEncoder(w).Encode(hitlExec); err != nil {
					log.Printf("Error encoding response: %v", err)
				}
				return
			}
			sendErrorResponse(w, "Workflow execution failed: "+hitlErr.Error(), http.StatusInternalServerError)
			return
		}
		execution = hitlExec
	} else {
		// Standard execution without HITL
		execution, err = workflowEngine.ExecuteWorkflow(r.Context(), req.Workflow, req.Input, req.User)
		if err != nil {
			sendErrorResponse(w, "Workflow execution failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(execution); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// getHITLExecutionStatusHandler returns the HITL status of an execution (Issue #1082)
func getHITLExecutionStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !hitlEnabled || hitlWorkflowEngine == nil {
		sendErrorResponse(w, "HITL not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	executionID := vars["id"]

	if executionID == "" {
		sendErrorResponse(w, "Execution ID is required", http.StatusBadRequest)
		return
	}

	status, err := hitlWorkflowEngine.GetExecutionStatus(r.Context(), executionID)
	if err != nil {
		if err == ErrExecutionNotFound {
			sendErrorResponse(w, "Execution not found", http.StatusNotFound)
		} else {
			sendErrorResponse(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
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

// applyAuthoritativeIdentity overlays X-Org-ID / X-Tenant-ID headers (set by the
// agent's auth chain) onto a PlanRequest's User and Client surfaces.
//
// Why both surfaces: the same handler reads identity from req.User.{OrgID,
// TenantID} for some downstream consumers (replay tracking, plan storage) and
// from req.Client["org_id"] / ["tenant_id"] for others (policy evaluation,
// audit logging). Without normalizing both, a direct-orchestrator caller that
// bypasses the agent could supply a body `client.org_id` that disagrees with
// the header — and policy evaluation would run under the body value while
// replay tracking ran under the header value. The agent's auth chain is the
// only signed source of truth, so headers always win when present.
//
// Headers are applied only when non-empty; missing headers leave the body
// values intact (which is the correct behavior for callers that come through
// the agent — the agent always sets both).
func applyAuthoritativeIdentity(r *http.Request, req *PlanRequest) {
	orgID := r.Header.Get("X-Org-ID")
	tenantID := r.Header.Get("X-Tenant-ID")

	if orgID == "" && tenantID == "" {
		return
	}
	if req.Client == nil {
		req.Client = map[string]interface{}{}
	}

	if orgID != "" {
		req.User.OrgID = orgID
		req.Client["org_id"] = orgID
	}
	if tenantID != "" {
		req.User.TenantID = tenantID
		req.Client["tenant_id"] = tenantID
	}
}

// ResponsePlanStep represents a step in the generated plan (matches SDK PlanStep)
type ResponsePlanStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description,omitempty"`
	DependsOn   []string               `json:"depends_on,omitempty"`
	Agent       string                 `json:"agent,omitempty"`
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// PlanResponse represents the response from a planning request
type PlanResponse struct {
	Success             bool                    `json:"success"`
	PlanID              string                  `json:"plan_id"`
	Steps               []ResponsePlanStep      `json:"steps"`
	WorkflowExecutionID string                  `json:"workflow_execution_id"`
	Result              interface{}             `json:"result"`
	Metadata            PlanMetadata            `json:"metadata"`
	Error               string                  `json:"error,omitempty"`
	PolicyInfo          *PolicyEvaluationResult `json:"policy_info,omitempty"` // Policy evaluation result (Issue #1020)
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

// planRequestHandler handles GeneratePlan requests - generates and stores plan WITHOUT executing
// This is step 1 of MAP two-step execution: GeneratePlan → ExecutePlan
func planRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	log.Println("[GeneratePlan] Received multi-agent planning request")

	// Check if planning engine is available
	if planningEngine == nil {
		sendErrorResponse(w, "Multi-Agent Planning not available - Planning Engine not initialized", http.StatusServiceUnavailable)
		return
	}

	// Check if plan service is available for storing plans
	if planService == nil {
		sendErrorResponse(w, "Plan storage not available - database connection required", http.StatusServiceUnavailable)
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
		log.Printf("[GeneratePlan] BLOCKED: Missing user authentication (request must come through Agent)")
		sendErrorResponse(w, "Authentication required: requests must be routed through AxonFlow Agent", http.StatusUnauthorized)
		return
	}

	// Header-derived identity from the agent's auth chain wins over any body
	// values for org/tenant. Without this, a direct-orchestrator caller could
	// have the plan stored under a different org than the agent authenticated
	// (createReq.OrgID below reads from req.Client["org_id"]).
	applyAuthoritativeIdentity(r, &req)

	// Extract client info for audit logging and multi-tenant logging
	clientName := "unknown"
	clientID := "unknown"
	orgID := ""
	tenantID := ""
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
		if org, ok := req.Client["org_id"].(string); ok {
			orgID = org
		}
		if tenant, ok := req.Client["tenant_id"].(string); ok {
			tenantID = tenant
		}
	}

	log.Printf("[GeneratePlan] Authenticated request - User: %s (ID: %d), Client: %s",
		logutil.Sanitize(req.User.Email), req.User.ID, logutil.Sanitize(clientName))

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
			log.Printf("[GeneratePlan] Domain extracted from context: %s", domain)
		} else {
			req.Domain = "generic"
		}
	}
	if req.ExecutionMode == "" {
		if execMode, ok := req.Context["execution_mode"].(string); ok && execMode != "" {
			req.ExecutionMode = execMode
			log.Printf("[GeneratePlan] ExecutionMode extracted from context: %s", logutil.Sanitize(execMode))
		} else {
			req.ExecutionMode = "auto"
		}
	}

	// Validate execution mode (MAP v1.0)
	isEnterprise := !isCommunityMode()
	if !IsValidExecutionMode(req.ExecutionMode, isEnterprise) {
		sendErrorResponse(w, fmt.Sprintf("Invalid execution mode: %s", req.ExecutionMode), http.StatusBadRequest)
		return
	}

	// Generate plan ID
	planID := fmt.Sprintf("plan_%d_%s", time.Now().Unix(), generateRandomString(8))

	log.Printf("[GeneratePlan] Query: %s, Domain: %s, Mode: %s, PlanID: %s", logutil.Sanitize(req.Query), logutil.Sanitize(req.Domain), logutil.Sanitize(req.ExecutionMode), planID)

	// Step 1: Generate execution plan (without executing)
	planGenReq := PlanGenerationRequest{
		Query:         req.Query,
		Domain:        req.Domain,
		ExecutionMode: req.ExecutionMode,
		ClientID:      clientID,
		RequestID:     planID,
		Context:       req.Context,
	}

	workflow, err := planningEngine.GeneratePlan(r.Context(), planGenReq)
	if err != nil {
		log.Printf("[GeneratePlan] Plan generation failed: %v", err)
		sendErrorResponse(w, "Planning failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[GeneratePlan] Plan generated: %d steps", len(workflow.Spec.Steps))

	// Step 2: Store the plan in database for later execution
	workflowJSON, err := json.Marshal(workflow)
	if err != nil {
		log.Printf("[GeneratePlan] Failed to marshal workflow: %v", err)
		sendErrorResponse(w, "Failed to store plan", http.StatusInternalServerError)
		return
	}

	createReq := &planning.CreatePlanRequest{
		PlanID:             planID,
		Query:              req.Query,
		Domain:             req.Domain,
		ExecutionMode:      req.ExecutionMode,
		WorkflowDefinition: workflowJSON,
		Complexity:         len(workflow.Spec.Steps),
		Parallel:           req.ExecutionMode == "auto" || req.ExecutionMode == "parallel",
		StepCount:          len(workflow.Spec.Steps),
		OrgID:              orgID,
		TenantID:           tenantID,
		UserID:             fmt.Sprintf("%d", req.User.ID),
		ClientID:           clientID,
	}

	storedPlan, err := planService.StorePlan(r.Context(), createReq)
	if err != nil {
		log.Printf("[GeneratePlan] Failed to store plan: %v", err)
		sendErrorResponse(w, "Failed to store plan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 3: Build response (plan info only, no execution result)
	executionTimeMs := time.Since(startTime).Milliseconds()

	// Convert workflow steps to SDK-compatible format
	planSteps := convertWorkflowStepsToResponse(workflow.Spec.Steps)

	response := PlanResponse{
		Success: true,
		PlanID:  storedPlan.PlanID,
		Steps:   planSteps,
		// No WorkflowExecutionID - plan not executed yet
		// No Result - plan not executed yet
		Metadata: PlanMetadata{
			TasksExecuted:   0, // Not executed yet
			ExecutionMode:   req.ExecutionMode,
			ExecutionTimeMs: executionTimeMs,
			Tasks:           []TaskMetadata{}, // Empty - not executed
		},
	}

	log.Printf("[GeneratePlan] Plan stored successfully in %dms: PlanID=%s, Steps=%d, Expires=%v",
		executionTimeMs, storedPlan.PlanID, len(planSteps), storedPlan.ExpiresAt)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// executePlanHandler handles ExecutePlan requests - retrieves and executes a stored plan
// This is step 2 of MAP two-step execution: GeneratePlan → ExecutePlan
func executePlanHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	log.Println("[ExecutePlan] Received execute plan request")

	// Check if workflow engine is available
	if workflowEngine == nil {
		sendErrorResponse(w, "Multi-Agent Planning not available - Workflow Engine not initialized", http.StatusServiceUnavailable)
		return
	}

	// Check if plan service is available
	if planService == nil {
		sendErrorResponse(w, "Plan storage not available - database connection required", http.StatusServiceUnavailable)
		return
	}

	// Parse request
	var req PlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// === GOVERNANCE: Validate Authentication (from Agent) ===
	if req.User.ID == 0 {
		log.Printf("[ExecutePlan] BLOCKED: Missing user authentication (request must come through Agent)")
		sendErrorResponse(w, "Authentication required: requests must be routed through AxonFlow Agent", http.StatusUnauthorized)
		return
	}

	// Extract plan_id from context (SDK sends it here)
	planID := ""
	if req.Context != nil {
		if id, ok := req.Context["plan_id"].(string); ok {
			planID = id
		}
	}

	if planID == "" {
		log.Printf("[ExecutePlan] BLOCKED: Missing plan_id in request context")
		sendErrorResponse(w, "plan_id is required in context", http.StatusBadRequest)
		return
	}

	// Header-derived identity from the agent's auth chain wins over any body
	// values for org/tenant on both User and Client surfaces. Downstream
	// consumers in this handler read from both surfaces — replay tracking
	// uses req.User.OrgID; policy evaluation builds policyClient from
	// req.Client["org_id"] further down — so leaving them out of sync would
	// let a direct-orchestrator caller execute under one org for tracking
	// purposes and have policies evaluated under another.
	applyAuthoritativeIdentity(r, &req)

	// Extract orgID for plan retrieval (GetPlanForExecution authz check).
	// Read from req.Client now that headers have overlaid it.
	orgID := ""
	if req.Client != nil {
		if org, ok := req.Client["org_id"].(string); ok {
			orgID = org
		}
	}

	log.Printf("[ExecutePlan] Authenticated request - User: %s (ID: %d), OrgID: %s, PlanID: %s",
		logutil.Sanitize(req.User.Email), req.User.ID, logutil.Sanitize(orgID), logutil.Sanitize(planID))

	// Step 1: Retrieve plan from database (with authorization check)
	plan, err := planService.GetPlanForExecution(r.Context(), planID, orgID)
	if err != nil {
		log.Printf("[ExecutePlan] Failed to retrieve plan %s: %v", logutil.Sanitize(planID), err)
		if errors.Is(err, planning.ErrPlanNotFound) {
			sendErrorResponse(w, "Plan not found: "+planID, http.StatusNotFound)
		} else if errors.Is(err, planning.ErrPlanExpired) {
			sendErrorResponse(w, "Plan has expired: "+planID, http.StatusGone)
		} else if errors.Is(err, planning.ErrPlanAlreadyRun) {
			sendErrorResponse(w, "Plan has already been executed: "+planID, http.StatusConflict)
		} else if errors.Is(err, planning.ErrPlanCancelled) {
			sendErrorResponse(w, "Plan has been cancelled: "+planID, http.StatusConflict)
		} else {
			sendErrorResponse(w, "Failed to retrieve plan: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[ExecutePlan] Retrieved plan %s (domain: %s, steps: %d)", logutil.Sanitize(planID), logutil.Sanitize(plan.Domain), plan.StepCount)

	// Start unified execution tracking (#1075)
	var unifiedExecID string
	if mapExecutionTracker != nil {
		execStatus, err := mapExecutionTracker.StartPlanExecution(r.Context(), plan)
		if err != nil {
			if errors.Is(err, execution.ErrConcurrentExecutionLimit) {
				limit := 5 // Community default
				upgradeURL := "https://getaxonflow.com/evaluation-license"
				if tierChecker != nil {
					limit = tierChecker.MaxConcurrentExecutions()
					if license.IsEvaluationOrHigher(tierChecker.Tier()) {
						upgradeURL = "https://getaxonflow.com/enterprise"
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error": map[string]interface{}{
						"code":    "CONCURRENT_EXECUTION_LIMIT",
						"message": fmt.Sprintf("Maximum concurrent executions (%d) reached. Upgrade your license for higher limits: %s", limit, upgradeURL),
					},
				})
				return
			}
			log.Printf("[ExecutePlan] Warning: failed to start unified tracking for %s: %v", logutil.Sanitize(planID), err)
		} else {
			unifiedExecID = execStatus.ExecutionID
			log.Printf("[ExecutePlan] Started unified execution tracking: %s", unifiedExecID)

			// Add 80% tier warning header if approaching concurrent execution limit
			if tierChecker != nil && execStatus.TenantID != "" {
				if activeCount, err := executionRepo.CountActive(r.Context(), execStatus.TenantID); err == nil {
					addTierWarningIfNeeded(w, "concurrent_executions", activeCount, tierChecker.MaxConcurrentExecutions())
				}
			}
		}
	}

	// === GOVERNANCE: Policy Evaluation Before Execution (Issue #1020) ===
	// Build OrchestratorRequest from plan for policy evaluation
	// Convert map-based client to ClientContext for policy engine
	policyClient := ClientContext{}
	if req.Client != nil {
		if id, ok := req.Client["id"].(string); ok {
			policyClient.ID = id
		}
		if name, ok := req.Client["name"].(string); ok {
			policyClient.Name = name
		}
		if orgID, ok := req.Client["org_id"].(string); ok {
			policyClient.OrgID = orgID
		}
		if tid, ok := req.Client["tenant_id"].(string); ok {
			policyClient.TenantID = tid
		}
	}

	policyReq := OrchestratorRequest{
		RequestID:   planID,
		Query:       plan.Query,
		RequestType: "map_execution",
		User:        req.User,
		Client:      policyClient,
		Context: map[string]interface{}{
			"plan_id":    plan.PlanID,
			"domain":     plan.Domain,
			"step_count": plan.StepCount,
		},
	}

	policyStartTime := time.Now()
	policyResult := dynamicPolicyEngine.EvaluateDynamicPolicies(r.Context(), policyReq)
	policyEvalTime := time.Since(policyStartTime)

	log.Printf("[ExecutePlan] Policy evaluation completed in %v: allowed=%t, policies=%v",
		policyEvalTime, policyResult.Allowed, policyResult.AppliedPolicies)

	// Record policy evaluation metric
	promPolicyEvaluations.Inc()
	promRequestDuration.WithLabelValues("map_policy").Observe(float64(policyEvalTime.Milliseconds()))

	if !policyResult.Allowed {
		// Log blocked request
		log.Printf("[ExecutePlan] BLOCKED: Plan %s blocked by policy: %v", logutil.Sanitize(planID), policyResult.AppliedPolicies)
		auditLogger.LogBlockedRequest(r.Context(), policyReq, policyResult)

		// Mark plan as failed due to policy block
		_ = planService.MarkPlanFailed(r.Context(), planID, "Blocked by policy: "+strings.Join(policyResult.AppliedPolicies, ", "))
		// Sync unified tracking on policy block (#1075)
		if mapExecutionTracker != nil && unifiedExecID != "" {
			_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusFailed, "Blocked by policy")
		}

		// Record blocked request metrics
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		latencyMs := time.Since(startTime).Milliseconds()
		promRequestDuration.WithLabelValues("map_blocked").Observe(float64(latencyMs))

		// Return 403 Forbidden with policy details
		response := PlanResponse{
			Success:    false,
			PlanID:     planID,
			Error:      "Policy blocked MAP execution",
			PolicyInfo: policyResult,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding blocked response: %v", err)
		}
		return
	}

	// Step 2: Unmarshal workflow definition
	var workflow Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err != nil {
		log.Printf("[ExecutePlan] Failed to unmarshal workflow: %v", err)
		_ = planService.MarkPlanFailed(r.Context(), planID, "Invalid workflow definition")
		// Sync unified tracking on workflow error (#1075)
		if mapExecutionTracker != nil && unifiedExecID != "" {
			_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusFailed, "Invalid workflow definition")
		}
		sendErrorResponse(w, "Invalid workflow definition", http.StatusInternalServerError)
		return
	}

	// Step 3: Execute workflow (with parallel support)
	ctx, cancel := context.WithTimeout(r.Context(), planExecutionTimeout(len(workflow.Spec.Steps)))
	defer cancel()

	// Merge stored context with request context (request context takes precedence)
	execContext := req.Context
	if execContext == nil {
		execContext = make(map[string]interface{})
	}

	// Add policy result to execution context for step snapshots (Issue #1020)
	execContext["_policy_result"] = policyResult

	// Determine execution strategy based on plan's execution mode (MAP v1.0)
	// If HITL is enabled and the mode is not confirm/step (which has its own WCP flow),
	// use the HITL-aware engine for policy-driven pause/resume (#1076)
	if hitlEnabled && hitlWorkflowEngine != nil && plan.ExecutionMode != "confirm" && plan.ExecutionMode != "step" {
		hitlExec, hitlErr := hitlWorkflowEngine.ExecuteWithHITL(ctx, workflow, execContext, req.User)
		if hitlErr != nil {
			if hitlExec != nil && hitlExec.Status == StatusPaused {
				// Store execution for later resume via /plans/{id}/steps/{step_id}/approve
				hitlWorkflowEngine.SaveExecution(hitlExec)
				log.Printf("[ExecutePlan] Plan %s paused for HITL approval at step %d", logutil.Sanitize(planID), hitlExec.PausedAtStep)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"plan_id":        planID,
					"execution_id":   hitlExec.ID,
					"status":         "paused",
					"paused_at_step": hitlExec.PausedAtStep,
					"paused_reason":  hitlExec.PausedReason,
					"approval_id":    hitlExec.ApprovalID.String(),
				})
				return
			}
			log.Printf("[ExecutePlan] HITL execution failed for plan %s: %v", logutil.Sanitize(planID), hitlErr)
			_ = planService.MarkPlanFailed(r.Context(), planID, hitlErr.Error())
			if mapExecutionTracker != nil && unifiedExecID != "" {
				_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusFailed, hitlErr.Error())
			}
			sendErrorResponse(w, "Execution failed: "+hitlErr.Error(), http.StatusInternalServerError)
			return
		}
		// HITL execution completed without pause — convert to standard WorkflowExecution
		if hitlExec != nil && hitlExec.WorkflowExecution != nil {
			execution := hitlExec.WorkflowExecution
			log.Printf("[ExecutePlan] HITL execution completed for plan %s: ExecutionID=%s", logutil.Sanitize(planID), execution.ID)
			var finalResult interface{} = execution.Output
			if execution.Output != nil {
				if result, ok := execution.Output["final_result"]; ok {
					finalResult = result
				}
			}
			_ = planService.MarkPlanCompleted(r.Context(), planID, finalResult)
			if mapExecutionTracker != nil && unifiedExecID != "" {
				if err := mapExecutionTracker.SyncStepResults(r.Context(), planID, execution.Steps, workflowEngine.GetCostEstimator()); err != nil {
					log.Printf("[ExecutePlan] Warning: failed to sync HITL step results: %v", logutil.Sanitize(err.Error()))
				}
				_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusCompleted, "")
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(execution)
			return
		}
	}

	var execution *WorkflowExecution
	switch plan.ExecutionMode {
	case "sequential":
		execution, err = workflowEngine.ExecuteWorkflowWithParallelSupport(ctx, workflow, execContext, req.User, false)
	case "parallel":
		execution, err = workflowEngine.ExecuteWorkflowWithParallelSupport(ctx, workflow, execContext, req.User, true)
	case "balanced":
		execution, err = workflowEngine.ExecuteWorkflowBalanced(ctx, workflow, execContext, req.User)
	case "confirm", "step":
		// Enterprise-only: WCP-gated execution (Phase 3a)
		if isCommunityMode() {
			_ = planService.MarkPlanFailed(r.Context(), planID, "confirm/step mode requires Enterprise license")
			sendErrorResponse(w, "confirm/step execution mode requires Enterprise license", http.StatusForbidden)
			return
		}
		if mapWCPExecutor == nil {
			_ = planService.MarkPlanFailed(r.Context(), planID, "WCP executor not available")
			sendErrorResponse(w, "WCP executor not initialized", http.StatusServiceUnavailable)
			return
		}
		// Dispatch to WCP-gated execution — returns immediately with awaiting_approval status
		var wcpResult *MAPWCPExecutionResult
		if plan.ExecutionMode == "confirm" {
			wcpResult, err = mapWCPExecutor.ExecuteWithConfirm(ctx, plan, &workflow,
				r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"), req.User.Email, r.Header.Get("X-Tenant-ID"))
		} else {
			wcpResult, err = mapWCPExecutor.ExecuteWithStep(ctx, plan, &workflow,
				r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"), req.User.Email, r.Header.Get("X-Tenant-ID"))
		}
		if err != nil {
			log.Printf("[ExecutePlan] WCP execution setup failed for plan %s: %v", logutil.Sanitize(planID), err)
			_ = planService.MarkPlanFailed(r.Context(), planID, err.Error())
			sendErrorResponse(w, "WCP execution setup failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Return immediately — client must call POST /plan/{id}/resume to advance steps
		log.Printf("[ExecutePlan] Plan %s entering %s mode (workflow=%s)", logutil.Sanitize(planID), logutil.Sanitize(plan.ExecutionMode), wcpResult.WorkflowID)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"plan_id":       wcpResult.PlanID,
			"workflow_id":   wcpResult.WorkflowID,
			"status":        wcpResult.Status,
			"current_step":  wcpResult.CurrentStep,
			"total_steps":   wcpResult.TotalSteps,
			"step_name":     wcpResult.StepName,
			"approval_info": wcpResult.ApprovalInfo,
		})
		return
	default:
		// "auto" or empty — backwards compatible with plan.Parallel boolean
		execution, err = workflowEngine.ExecuteWorkflowWithParallelSupport(ctx, workflow, execContext, req.User, plan.Parallel)
	}
	if err != nil {
		log.Printf("[ExecutePlan] Execution failed for plan %s: %v", logutil.Sanitize(planID), err)
		_ = planService.MarkPlanFailed(r.Context(), planID, err.Error())
		// Sync partial step results on failure (steps may have partial data)
		if mapExecutionTracker != nil && unifiedExecID != "" && execution != nil {
			if syncErr := mapExecutionTracker.SyncStepResults(r.Context(), planID, execution.Steps, workflowEngine.GetCostEstimator()); syncErr != nil {
				log.Printf("[ExecutePlan] Warning: failed to sync partial step results: %v", logutil.Sanitize(syncErr.Error()))
			}
		}
		// Sync unified tracking on failure (#1075)
		if mapExecutionTracker != nil && unifiedExecID != "" {
			_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusFailed, err.Error())
		}
		sendErrorResponse(w, "Execution failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[ExecutePlan] Execution completed for plan %s: ExecutionID=%s", logutil.Sanitize(planID), execution.ID)

	// Step 4: Extract final result
	var finalResult interface{}
	if execution.Output != nil {
		if result, ok := execution.Output["final_result"]; ok {
			log.Printf("[ExecutePlan] Found final_result, type: %T, length: %d", result, getResultLength(result))
			finalResult = result
		} else {
			log.Printf("[ExecutePlan] WARNING: final_result key not found, using entire output map")
			finalResult = execution.Output
		}
	} else {
		log.Printf("[ExecutePlan] WARNING: execution.Output is nil")
		finalResult = "Plan executed successfully (no output generated)"
	}

	// Step 5: Mark plan as completed
	if err := planService.MarkPlanCompleted(r.Context(), planID, finalResult); err != nil {
		log.Printf("[ExecutePlan] Warning: failed to mark plan %s as completed: %v", logutil.Sanitize(planID), err)
	}

	// Sync step-level results to unified tracker (provider, model, tokens, cost, status)
	if mapExecutionTracker != nil && unifiedExecID != "" {
		if err := mapExecutionTracker.SyncStepResults(r.Context(), planID, execution.Steps, workflowEngine.GetCostEstimator()); err != nil {
			log.Printf("[ExecutePlan] Warning: failed to sync step results: %v", logutil.Sanitize(err.Error()))
		}
	}

	// Sync unified tracking on success (#1075)
	if mapExecutionTracker != nil && unifiedExecID != "" {
		if err := mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusCompleted, ""); err != nil {
			log.Printf("[ExecutePlan] Warning: failed to sync unified tracking: %v", logutil.Sanitize(err.Error()))
		}
	}

	// Step 6: Build response
	executionTimeMs := time.Since(startTime).Milliseconds()

	// Build task metadata
	tasks := make([]TaskMetadata, len(execution.Steps))
	for i, step := range execution.Steps {
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

	// Convert workflow steps to SDK-compatible format
	planSteps := convertWorkflowStepsToResponse(workflow.Spec.Steps)

	response := PlanResponse{
		Success:             true,
		PlanID:              planID,
		Steps:               planSteps,
		WorkflowExecutionID: execution.ID,
		Result:              finalResult,
		Metadata: PlanMetadata{
			TasksExecuted:   len(execution.Steps),
			ExecutionMode:   plan.ExecutionMode,
			ExecutionTimeMs: executionTimeMs,
			Tasks:           tasks,
		},
		PolicyInfo: policyResult, // Include policy evaluation result (Issue #1020)
	}

	log.Printf("[ExecutePlan] Success in %dms: PlanID=%s, TasksExecuted=%d", executionTimeMs, logutil.Sanitize(planID), len(execution.Steps))

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// getPlanStatusHandler retrieves a stored plan by ID for status checking
// SDK calls: GET /api/v1/plan/{id}
// Updated in #1075 to use unified execution tracking with step-level details
func getPlanStatusHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[GetPlanStatus] Received get plan status request")

	// Check if plan service is available
	if planService == nil {
		sendErrorResponse(w, "Plan storage not available - database connection required", http.StatusServiceUnavailable)
		return
	}

	// Extract plan ID from URL path
	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	// Extract orgID for tenant isolation (consistent with cancelPlanHandler, updatePlanHandler, rollbackPlanHandler)
	orgID := r.Header.Get("X-Org-ID")

	// Always verify tenant ownership via the plan service before returning any data
	plan, err := planService.GetPlan(r.Context(), planID)
	if err != nil {
		log.Printf("[GetPlanStatus] Failed to get plan %s: %v", logutil.Sanitize(planID), err)
		sendErrorResponse(w, "Plan not found: "+err.Error(), http.StatusNotFound)
		return
	}
	if orgID != "" && plan.OrgID != "" && plan.OrgID != orgID {
		log.Printf("[GetPlanStatus] Authorization failed: plan %s belongs to org %s, requested by org %s", logutil.Sanitize(planID), logutil.Sanitize(plan.OrgID), logutil.Sanitize(orgID))
		sendErrorResponse(w, "Plan not found", http.StatusNotFound)
		return
	}

	// Use unified execution tracker if available (#1075)
	if mapExecutionTracker != nil {
		execStatus, err := mapExecutionTracker.GetPlanStatus(r.Context(), planID)
		if err == nil {
			// Return unified execution status with step-level details
			response := buildUnifiedStatusResponse(execStatus)
			log.Printf("[GetPlanStatus] Returning unified status for plan %s: %s (%.1f%% complete)",
				logutil.Sanitize(planID), logutil.Sanitize(string(execStatus.Status)), execStatus.ProgressPercent)

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(response); err != nil {
				log.Printf("Error encoding response: %v", err)
			}
			return
		}
		// Fall through to legacy handler if unified tracking fails
		log.Printf("[GetPlanStatus] Unified tracking not available for %s, using legacy: %v", logutil.Sanitize(planID), err)
	}

	// Convert plan to unified ExecutionStatus, then to API response.
	// This ensures legacy and tracker paths return the same fields:
	// progress_percent, steps[], execution_id, duration, started_at, version,
	// execution_result, workflow_definition (all additive, backward-compatible).
	execStatus := planToExecutionStatus(plan)
	response := buildUnifiedStatusResponse(execStatus)

	log.Printf("[GetPlanStatus] Returning plan %s with status %s (legacy path, %.1f%% complete)",
		logutil.Sanitize(planID), logutil.Sanitize(string(plan.Status)), execStatus.ProgressPercent)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}

// buildUnifiedStatusResponse converts ExecutionStatus to API response format
// This provides step-level details that the legacy handler doesn't have
func buildUnifiedStatusResponse(exec *execution.ExecutionStatus) map[string]interface{} {
	// Calculate completed steps from the steps array if populated,
	// otherwise use CurrentStepIndex (set by planToExecutionStatus based on plan status)
	completedSteps := 0
	if len(exec.Steps) > 0 {
		for _, step := range exec.Steps {
			if step.Status == execution.StepStatusCompleted {
				completedSteps++
			}
		}
	} else {
		completedSteps = exec.CurrentStepIndex
	}

	response := map[string]interface{}{
		"plan_id":          exec.ExecutionID,
		"execution_id":     exec.ExecutionID,
		"status":           string(exec.Status),
		"org_id":           exec.OrgID,
		"tenant_id":        exec.TenantID,
		"query":            exec.Name,
		"domain":           exec.Source,
		"total_steps":      exec.TotalSteps,
		"completed_steps":  completedSteps,
		"progress_percent": exec.ProgressPercent,
		"duration":         exec.Duration,
		"created_at":       exec.CreatedAt,
		"started_at":       exec.StartedAt,
	}

	// Include metadata fields if available
	if exec.Metadata != nil {
		if complexity, ok := exec.Metadata["complexity"]; ok {
			response["complexity"] = complexity
		}
		if expiresAt, ok := exec.Metadata["expires_at"]; ok {
			response["expires_at"] = expiresAt
		}
		if executionMode, ok := exec.Metadata["execution_mode"]; ok {
			response["execution_mode"] = executionMode
		}
		if version, ok := exec.Metadata["version"]; ok {
			response["version"] = version
		}
		if execResult, ok := exec.Metadata["execution_result"]; ok {
			response["execution_result"] = execResult
		}
		if workflowDef, ok := exec.Metadata["workflow_definition"]; ok {
			response["workflow_definition"] = workflowDef
		}
	}

	// Include completed_at if execution is finished
	if exec.CompletedAt != nil {
		response["completed_at"] = exec.CompletedAt
	}

	// Include error if present
	if exec.Error != "" {
		response["error"] = exec.Error
	}

	// Include cost tracking if available
	if exec.EstimatedCostUSD != nil {
		response["estimated_cost_usd"] = *exec.EstimatedCostUSD
	}
	if exec.ActualCostUSD != nil {
		response["actual_cost_usd"] = *exec.ActualCostUSD
	}

	// Include step details for granular progress tracking
	if len(exec.Steps) > 0 {
		steps := make([]map[string]interface{}, len(exec.Steps))
		for i, step := range exec.Steps {
			stepData := map[string]interface{}{
				"step_id":    step.StepID,
				"step_index": step.StepIndex,
				"step_name":  step.StepName,
				"step_type":  string(step.StepType),
				"status":     string(step.Status),
			}
			if step.StartedAt != nil {
				stepData["started_at"] = step.StartedAt
			}
			if step.EndedAt != nil {
				stepData["ended_at"] = step.EndedAt
			}
			if step.Duration != "" {
				stepData["duration"] = step.Duration
			}
			if step.Error != "" {
				stepData["error"] = step.Error
			}
			if step.CostUSD != nil {
				stepData["cost_usd"] = *step.CostUSD
			}
			if step.Model != "" {
				stepData["model"] = step.Model
			}
			if step.Provider != "" {
				stepData["provider"] = step.Provider
			}
			if step.TokensIn != nil {
				stepData["tokens_in"] = *step.TokensIn
			}
			if step.TokensOut != nil {
				stepData["tokens_out"] = *step.TokensOut
			}
			steps[i] = stepData
		}
		response["steps"] = steps
	}

	return response
}

// cancelPlanHandler cancels a pending or executing plan
// SDK calls: POST /api/v1/plan/{id}/cancel
func cancelPlanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[CancelPlan] Received cancel plan request")

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	// Parse optional reason from body
	var req planning.CancelPlanRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Reason == "" {
		req.Reason = "cancelled via API"
	}

	// Extract orgID from headers (set by agent auth)
	orgID := r.Header.Get("X-Org-ID")

	if err := planService.CancelPlan(r.Context(), planID, orgID, req.Reason); err != nil {
		log.Printf("[CancelPlan] Failed to cancel plan %s: %v", logutil.Sanitize(planID), err)
		if errors.Is(err, planning.ErrPlanNotFound) {
			sendErrorResponse(w, "Plan not found", http.StatusNotFound)
			return
		}
		sendErrorResponse(w, "Failed to cancel plan: "+err.Error(), http.StatusConflict)
		return
	}

	// Sync unified tracking
	if mapExecutionTracker != nil {
		_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusCancelled, req.Reason)
	}

	log.Printf("[CancelPlan] Plan %s cancelled: %s", logutil.Sanitize(planID), logutil.Sanitize(req.Reason))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"plan_id": planID,
		"status":  "cancelled",
		"reason":  req.Reason,
		"message": req.Reason,
	})
}

// updatePlanHandler updates a plan with optimistic locking (version conflict detection)
// SDK calls: PUT /api/v1/plan/{id}
func updatePlanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[UpdatePlan] Received update plan request")

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	var req planning.UpdatePlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	req.PlanID = planID
	req.OrgID = r.Header.Get("X-Org-ID")
	req.ChangedBy = r.Header.Get("X-User-ID")

	// Validate execution mode if provided
	if req.ExecutionMode != "" {
		isEnterprise := !isCommunityMode()
		if !IsValidExecutionMode(req.ExecutionMode, isEnterprise) {
			sendErrorResponse(w, "Invalid execution mode: "+req.ExecutionMode, http.StatusBadRequest)
			return
		}
	}

	plan, err := planService.UpdatePlan(r.Context(), &req)
	if err != nil {
		log.Printf("[UpdatePlan] Failed to update plan %s: %v", logutil.Sanitize(planID), err)
		if errors.Is(err, planning.ErrVersionConflict) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "version_conflict",
				"message": err.Error(),
				"plan_id": planID,
			})
			return
		}
		if errors.Is(err, planning.ErrPlanNotFound) {
			sendErrorResponse(w, "Plan not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, planning.ErrMaxPlans) || errors.Is(err, planning.ErrMaxVersions) {
			sendErrorResponse(w, err.Error(), http.StatusForbidden)
			return
		}
		sendErrorResponse(w, "Failed to update plan: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[UpdatePlan] Plan %s updated to version %d", logutil.Sanitize(planID), plan.Version)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"plan_id": plan.PlanID,
		"version": plan.Version,
		"status":  string(plan.Status),
	})
}

// getPlanVersionsHandler retrieves version history for a plan
// SDK calls: GET /api/v1/plan/{id}/versions
func getPlanVersionsHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[GetPlanVersions] Received get plan versions request")

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	orgID := r.Header.Get("X-Org-ID")

	versions, err := planService.GetPlanVersions(r.Context(), planID, orgID)
	if err != nil {
		log.Printf("[GetPlanVersions] Failed to get versions for plan %s: %v", logutil.Sanitize(planID), err)
		if errors.Is(err, planning.ErrPlanNotFound) {
			sendErrorResponse(w, "Plan not found", http.StatusNotFound)
			return
		}
		sendErrorResponse(w, "Failed to get plan versions: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[GetPlanVersions] Returning %d versions for plan %s", len(versions), logutil.Sanitize(planID))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"plan_id":  planID,
		"versions": versions,
	})
}

// resumePlanHandler resumes a paused plan (confirm/step mode, Enterprise only)
// SDK calls: POST /api/v1/plan/{id}/resume
func resumePlanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[ResumePlan] Received resume plan request")

	// Enterprise only
	if isCommunityMode() {
		sendErrorResponse(w, "Resume plan requires Enterprise license (confirm/step mode)", http.StatusForbidden)
		return
	}

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	// Parse resume request
	var req struct {
		Approved *bool `json:"approved"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Default approved to true
	approved := true
	if req.Approved != nil {
		approved = *req.Approved
	}

	if mapWCPExecutor == nil || workflowControlService == nil {
		sendErrorResponse(w, "WCP executor not initialized", http.StatusServiceUnavailable)
		return
	}

	// Get the plan — must be in "executing" status (set during ExecutePlan)
	plan, err := planService.GetPlan(r.Context(), planID)
	if err != nil {
		log.Printf("[ResumePlan] Plan %s not found: %v", logutil.Sanitize(planID), err)
		sendErrorResponse(w, "Plan not found", http.StatusNotFound)
		return
	}
	if plan.Status != planning.PlanStatusExecuting {
		sendErrorResponse(w, fmt.Sprintf("Plan is in %s status, must be executing to resume", plan.Status), http.StatusBadRequest)
		return
	}

	// Find the WCP workflow associated with this plan by naming convention
	// Workflows are named "map-confirm-{planID}" or "map-step-{planID}"
	orgID := r.Header.Get("X-Org-ID")
	mapSource := workflow_control.WorkflowSource("map")
	listResp, err := workflowControlService.ListWorkflows(r.Context(), workflow_control.ListWorkflowsOptions{
		Source:   &mapSource,
		TenantID: r.Header.Get("X-Tenant-ID"),
		OrgID:    orgID,
		Limit:    50,
	})
	if err != nil {
		sendErrorResponse(w, "Failed to list workflows: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[ResumePlan] Searching workflows: source=map, tenantID=%s, orgID=%s", logutil.Sanitize(r.Header.Get("X-Tenant-ID")), logutil.Sanitize(orgID))
	log.Printf("[ResumePlan] Found %d workflows", len(listResp.Workflows))
	for i, wf := range listResp.Workflows {
		log.Printf("[ResumePlan] Workflow[%d]: id=%s name=%s status=%s steps=%d", i, wf.WorkflowID, logutil.Sanitize(wf.WorkflowName), wf.Status, len(wf.Steps))
	}

	// Find the active workflow for this plan by matching workflow name
	var targetWorkflowID string
	var targetCurrentStep int
	var targetSteps []workflow_control.StepInfo
	for _, wf := range listResp.Workflows {
		if (wf.WorkflowName == "map-confirm-"+planID || wf.WorkflowName == "map-step-"+planID) &&
			wf.Status != workflow_control.WorkflowStatusCompleted &&
			wf.Status != workflow_control.WorkflowStatusAborted &&
			wf.Status != workflow_control.WorkflowStatusFailed {
			targetWorkflowID = wf.WorkflowID
			targetCurrentStep = wf.CurrentStepIndex
			targetSteps = wf.Steps
			break
		}
	}
	if targetWorkflowID == "" {
		sendErrorResponse(w, "No active WCP workflow found for this plan", http.StatusNotFound)
		return
	}

	// Handle rejection: abort workflow + fail plan
	if !approved {
		log.Printf("[ResumePlan] Plan %s step rejected, aborting workflow %s", logutil.Sanitize(planID), targetWorkflowID)
		_ = workflowControlService.AbortWorkflow(r.Context(), targetWorkflowID, "Step rejected by user", r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"))
		_ = planService.MarkPlanFailed(r.Context(), planID, "Step rejected by user")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"plan_id":     planID,
			"workflow_id": targetWorkflowID,
			"status":      "rejected",
			"message":     "Step rejected, plan aborted",
		})
		return
	}

	// Handle approval: find pending step, approve it, execute it
	log.Printf("[ResumePlan] Plan %s step approved, executing next step in workflow %s", logutil.Sanitize(planID), targetWorkflowID)

	// Find the pending step from the workflow status response steps
	var pendingStepID string
	for _, step := range targetSteps {
		if step.ApprovalStatus != nil && *step.ApprovalStatus == workflow_control.ApprovalStatusPending {
			pendingStepID = step.StepID
			break
		}
	}

	if pendingStepID != "" {
		// Approve the pending step in WCP
		if err := workflowControlService.ApproveStep(r.Context(), targetWorkflowID, pendingStepID, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"), r.Header.Get("X-User-ID"), "Auto-approved via plan resume"); err != nil {
			log.Printf("[ResumePlan] Failed to approve step %s: %v", pendingStepID, err)
			sendErrorResponse(w, "Failed to approve step: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Execute the step (parse workflow, run through engine)
	var workflow Workflow
	if err := json.Unmarshal(plan.WorkflowDefinition, &workflow); err != nil {
		sendErrorResponse(w, "Invalid workflow definition", http.StatusInternalServerError)
		return
	}

	stepIndex := targetCurrentStep
	if stepIndex >= len(workflow.Spec.Steps) {
		// All steps completed — mark plan as completed
		_ = workflowControlService.CompleteWorkflow(r.Context(), targetWorkflowID, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"))
		_ = planService.MarkPlanCompleted(r.Context(), planID, map[string]interface{}{"status": "all_steps_completed"})
		// Sync unified execution tracker so GetPlanStatus returns correct status
		if mapExecutionTracker != nil {
			_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusCompleted, "All steps completed via confirm mode")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"plan_id":     planID,
			"workflow_id": targetWorkflowID,
			"status":      "completed",
			"message":     "All steps completed",
		})
		return
	}

	// Execute the current step
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	execContext := make(map[string]interface{})
	stepResult, err := mapWCPExecutor.ExecuteSingleStep(ctx, plan, &workflow, stepIndex, execContext, r.Header.Get("X-User-ID"), workflowEngine)
	if err != nil {
		log.Printf("[ResumePlan] Step execution failed: %v", err)
		_ = workflowControlService.AbortWorkflow(r.Context(), targetWorkflowID, err.Error(), r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"))
		_ = planService.MarkPlanFailed(r.Context(), planID, err.Error())
		sendErrorResponse(w, "Step execution failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Mark step as completed in WCP
	stepID := fmt.Sprintf("step_%d_%s", stepIndex, workflow.Spec.Steps[stepIndex].Name)
	_ = workflowControlService.MarkStepCompleted(r.Context(), targetWorkflowID, stepID, nil, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"))

	// Check if there are more steps
	nextStepIndex := stepIndex + 1
	if nextStepIndex >= len(workflow.Spec.Steps) {
		// All steps done
		_ = workflowControlService.CompleteWorkflow(r.Context(), targetWorkflowID, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"))
		_ = planService.MarkPlanCompleted(r.Context(), planID, stepResult.Output)
		if mapExecutionTracker != nil {
			_ = mapExecutionTracker.SyncPlanStatus(r.Context(), planID, planning.PlanStatusCompleted, "All steps completed via confirm mode")
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"plan_id":     planID,
			"workflow_id": targetWorkflowID,
			"status":      "completed",
			"step_result": stepResult,
			"message":     "All steps completed",
		})
		return
	}

	// Gate the next step for approval (confirm/step mode: all subsequent steps need approval)
	nextStep := workflow.Spec.Steps[nextStepIndex]
	requireApproval := workflow_control.GateDecisionRequireApproval
	_, _ = workflowControlService.StepGate(r.Context(), targetWorkflowID,
		fmt.Sprintf("step_%d_%s", nextStepIndex, nextStep.Name),
		&workflow_control.StepGateRequest{
			StepName:     nextStep.Name,
			StepType:     mapStepTypeToWCP(nextStep.Type),
			GateOverride: &requireApproval,
		}, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID"), r.Header.Get("X-User-ID"), r.Header.Get("X-Tenant-ID"))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"plan_id":        planID,
		"workflow_id":    targetWorkflowID,
		"status":         "awaiting_approval",
		"step_result":    stepResult,
		"next_step":      nextStepIndex,
		"next_step_name": nextStep.Name,
		"total_steps":    len(workflow.Spec.Steps),
	})
}

// rollbackPlanHandler rolls back a plan to a previous version.
// Community edition is subject to plan/version limits enforced by the planning service.
// SDK calls: POST /api/v1/plan/{id}/rollback/{version}
func rollbackPlanHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("[RollbackPlan] Received rollback plan request")

	// Enterprise only — rollback requires version history which is an Enterprise feature
	if isCommunityMode() {
		sendErrorResponse(w, "Rollback plan requires Enterprise license", http.StatusForbidden)
		return
	}

	if planService == nil {
		sendErrorResponse(w, "Plan storage not available", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	if planID == "" {
		sendErrorResponse(w, "Plan ID is required", http.StatusBadRequest)
		return
	}

	versionStr := vars["version"]
	targetVersion, err := strconv.Atoi(versionStr)
	if err != nil || targetVersion < 1 {
		sendErrorResponse(w, "Invalid target version", http.StatusBadRequest)
		return
	}

	req := &planning.RollbackPlanRequest{
		PlanID:        planID,
		TargetVersion: targetVersion,
		OrgID:         r.Header.Get("X-Org-ID"),
		RolledBackBy:  r.Header.Get("X-User-ID"),
	}

	plan, err := planService.RollbackPlan(r.Context(), req)
	if err != nil {
		log.Printf("[RollbackPlan] Failed to rollback plan %s: %v", logutil.Sanitize(planID), logutil.Sanitize(err.Error()))
		if errors.Is(err, planning.ErrVersionConflict) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"error":   "version_conflict",
				"message": err.Error(),
				"plan_id": planID,
			})
			return
		}
		if errors.Is(err, planning.ErrVersionNotFound) {
			sendErrorResponse(w, fmt.Sprintf("Version %d not found for plan %s", targetVersion, planID), http.StatusNotFound)
			return
		}
		if errors.Is(err, planning.ErrPlanNotFound) {
			sendErrorResponse(w, "Plan not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, planning.ErrMaxPlans) || errors.Is(err, planning.ErrMaxVersions) {
			sendErrorResponse(w, err.Error(), http.StatusForbidden)
			return
		}
		sendErrorResponse(w, "Failed to rollback plan: "+err.Error(), http.StatusBadRequest)
		return
	}

	log.Printf("[RollbackPlan] Plan %s rolled back to version %d (now v%d)", logutil.Sanitize(planID), targetVersion, plan.Version)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"plan_id":          plan.PlanID,
		"version":          plan.Version,
		"previous_version": plan.Version - 1,
		"status":           string(plan.Status),
		"rolled_back_to":   targetVersion,
	})
}

// convertWorkflowStepsToResponse converts workflow steps to SDK-compatible response format
func convertWorkflowStepsToResponse(steps []WorkflowStep) []ResponsePlanStep {
	if steps == nil {
		return []ResponsePlanStep{}
	}
	result := make([]ResponsePlanStep, len(steps))
	for i, step := range steps {
		// Generate a unique ID for each step (use index for uniqueness, name for readability)
		stepID := fmt.Sprintf("step_%d_%s", i+1, step.Name)

		// Build description from available fields
		description := ""
		if step.Prompt != "" {
			// Truncate long prompts
			if len(step.Prompt) > 100 {
				description = step.Prompt[:100] + "..."
			} else {
				description = step.Prompt
			}
		} else if step.Connector != "" {
			description = fmt.Sprintf("Call %s connector: %s", step.Connector, step.Statement)
		}

		result[i] = ResponsePlanStep{
			ID:          stepID,
			Name:        step.Name,
			Type:        step.Type,
			Description: description,
			DependsOn:   []string{}, // Workflow steps don't have explicit dependencies in current model
			Agent:       step.Connector,
			Parameters:  step.Parameters,
		}
	}
	return result
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
