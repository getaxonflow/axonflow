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
	"sync"
	"time"

	"axonflow/platform/agent/rbi"
	"axonflow/platform/connectors/base"
	"axonflow/platform/orchestrator/cost"
	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

// Outreach log rate limiting - logs once per hour max per category
var (
	outreachLogMu               sync.Mutex
	lastEnforcementLogTime      time.Time
	lastBypassLogTime           time.Time
	outreachLogInterval         = time.Hour
)

// shouldLogEnforcementOutreach returns true if enough time has passed since last enforcement log
func shouldLogEnforcementOutreach() bool {
	outreachLogMu.Lock()
	defer outreachLogMu.Unlock()
	if time.Since(lastEnforcementLogTime) >= outreachLogInterval {
		lastEnforcementLogTime = time.Now()
		return true
	}
	return false
}

// shouldLogBypassOutreach returns true if enough time has passed since last bypass log
func shouldLogBypassOutreach() bool {
	outreachLogMu.Lock()
	defer outreachLogMu.Unlock()
	if time.Since(lastBypassLogTime) >= outreachLogInterval {
		lastBypassLogTime = time.Now()
		return true
	}
	return false
}

// Gateway Mode Prometheus metrics
var (
	gatewayPreCheckRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_precheck_requests_total",
			Help: "Total number of gateway pre-check requests",
		},
		[]string{"status", "approved"},
	)
	gatewayAuditRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_audit_requests_total",
			Help: "Total number of gateway audit requests",
		},
		[]string{"status", "provider"},
	)
	gatewayPreCheckDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "axonflow_gateway_precheck_duration_milliseconds",
			Help:    "Gateway pre-check request duration in milliseconds",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
	)
	gatewayAuditDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "axonflow_gateway_audit_duration_milliseconds",
			Help:    "Gateway audit request duration in milliseconds",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
	)
	gatewayLLMTokensTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_llm_tokens_total",
			Help: "Total LLM tokens tracked via gateway audit",
		},
		[]string{"provider", "model", "type"},
	)
	gatewayLLMCostTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_llm_cost_usd_total",
			Help: "Estimated LLM cost in USD tracked via gateway audit",
		},
		[]string{"provider", "model"},
	)
)

// gatewayMetricsOnce ensures metrics are registered only once
var gatewayMetricsOnce sync.Once

// RBI Kill Switch checker (lazy initialization)
var (
	rbiKillSwitchChecker     *rbi.KillSwitchChecker
	rbiKillSwitchCheckerOnce sync.Once
)

func init() {
	registerGatewayMetrics()
}

// getRBIKillSwitchChecker returns the RBI kill switch checker (lazy initialization)
// Returns nil if kill switch is not enabled (Community mode)
func getRBIKillSwitchChecker() *rbi.KillSwitchChecker {
	rbiKillSwitchCheckerOnce.Do(func() {
		if rbi.KillSwitchEnabled() && authDB != nil {
			rbiKillSwitchChecker = rbi.NewKillSwitchChecker(authDB)
			log.Printf("🛑 [RBI] Kill switch checker initialized (enterprise)")
		}
	})
	return rbiKillSwitchChecker
}

// checkRBIKillSwitch checks if an RBI kill switch is active for the given org/system
func checkRBIKillSwitch(ctx context.Context, orgID, systemID string) *rbi.KillSwitchCheckResult {
	checker := getRBIKillSwitchChecker()
	if checker == nil {
		// Kill switch not enabled (Community mode) - always allow
		return &rbi.KillSwitchCheckResult{IsBlocked: false}
	}
	return checker.CheckKillSwitch(ctx, orgID, systemID)
}

// registerGatewayMetrics registers all gateway metrics once (safe for multiple calls)
func registerGatewayMetrics() {
	gatewayMetricsOnce.Do(func() {
		// Register gateway Prometheus metrics (ignore errors - duplicate registration is OK)
		_ = prometheus.Register(gatewayPreCheckRequests)
		_ = prometheus.Register(gatewayAuditRequests)
		_ = prometheus.Register(gatewayPreCheckDuration)
		_ = prometheus.Register(gatewayAuditDuration)
		_ = prometheus.Register(gatewayLLMTokensTotal)
		_ = prometheus.Register(gatewayLLMCostTotal)
		_ = prometheus.Register(gatewayAuditQueuedTotal)
		_ = prometheus.Register(gatewayAuditFallbackTotal)
		_ = prometheus.Register(gatewayRBIPIIDetected)
	})
}

// Gateway Mode Types - Pre-check and Audit

// PreCheckRequest is sent by SDK to get policy approval before making LLM call
type PreCheckRequest struct {
	UserToken   string                 `json:"user_token"`
	ClientID    string                 `json:"client_id"`
	DataSources []string               `json:"data_sources,omitempty"`
	Query       string                 `json:"query"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// PreCheckResponse is returned to SDK with context and approval status
type PreCheckResponse struct {
	ContextID         string                 `json:"context_id"`
	Approved          bool                   `json:"approved"`
	RequiresRedaction bool                   `json:"requires_redaction,omitempty"`
	ApprovedData      map[string]interface{} `json:"approved_data,omitempty"`
	Policies          []string               `json:"policies"`
	RateLimit         *RateLimitInfo         `json:"rate_limit,omitempty"`
	BudgetInfo        *BudgetInfo            `json:"budget_info,omitempty"` // Issue #1082: Budget status
	ExpiresAt         time.Time              `json:"expires_at"`
	BlockReason       string                 `json:"block_reason,omitempty"`
}

// RateLimitInfo provides rate limiting status to SDK
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// BudgetInfo provides budget status to SDK (Issue #1082)
type BudgetInfo struct {
	BudgetID   string  `json:"budget_id,omitempty"`
	BudgetName string  `json:"budget_name,omitempty"`
	UsedUSD    float64 `json:"used_usd"`
	LimitUSD   float64 `json:"limit_usd"`
	Percentage float64 `json:"percentage"`
	Exceeded   bool    `json:"exceeded"`
	Action     string  `json:"action,omitempty"` // "warn", "block", "downgrade"
}

// TokenUsage tracks LLM token consumption
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// AuditLLMCallRequest is sent by SDK after making LLM call
type AuditLLMCallRequest struct {
	ContextID       string                 `json:"context_id"`
	ClientID        string                 `json:"client_id"`
	ResponseSummary string                 `json:"response_summary"`
	Provider        string                 `json:"provider"`
	Model           string                 `json:"model"`
	TokenUsage      TokenUsage             `json:"token_usage"`
	LatencyMs       int64                  `json:"latency_ms"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AuditLLMCallResponse confirms audit was recorded
type AuditLLMCallResponse struct {
	Success bool   `json:"success"`
	AuditID string `json:"audit_id"`
}

// LLM pricing per 1K tokens (in USD) - used for cost estimation
var llmPricing = map[string]map[string]float64{
	"openai": {
		"gpt-4":         0.03,   // $0.03 per 1K input tokens
		"gpt-4-turbo":   0.01,
		"gpt-4o":        0.005,
		"gpt-3.5-turbo": 0.0005,
	},
	"anthropic": {
		"claude-3-opus":   0.015,
		"claude-3-sonnet": 0.003,
		"claude-3-haiku":  0.00025,
	},
	"bedrock": {
		"anthropic.claude-v2": 0.008,
		"amazon.titan-text":   0.0008,
	},
	"ollama": {
		"default": 0.0, // Local, no cost
	},
}

// Default context expiration (5 minutes)
const defaultContextExpiry = 5 * time.Minute

// Prometheus metrics for audit queue
var (
	gatewayAuditQueuedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_audit_queued_total",
			Help: "Total audit entries queued via AuditQueue",
		},
		[]string{"type", "status"},
	)
	gatewayAuditFallbackTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_audit_fallback_total",
			Help: "Total audit entries that fell back to direct DB write after queue failure",
		},
	)
	gatewayRBIPIIDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_rbi_pii_detected_total",
			Help: "Total RBI PII detections in gateway pre-check",
		},
		[]string{"pii_type", "blocked"},
	)
)

// rbiPIIDetector is the India-specific PII detector for RBI compliance.
// Initialized lazily on first use. In Community builds, this is a no-op.
var (
	rbiPIIDetector     *rbi.IndiaPIIDetector
	rbiPIIDetectorOnce sync.Once
)

// getRBIPIIDetector returns the RBI PII detector, initializing it if needed.
func getRBIPIIDetector() *rbi.IndiaPIIDetector {
	rbiPIIDetectorOnce.Do(func() {
		if rbi.IsEnabled() {
			config := rbi.DefaultIndiaPIIDetectorConfig()
			rbiPIIDetector = rbi.NewIndiaPIIDetector(config)
			log.Printf("🇮🇳 [RBI] India PII detector initialized (enterprise)")
		} else {
			log.Printf("🇮🇳 [RBI] India PII detection disabled (Community mode)")
		}
	})
	return rbiPIIDetector
}

// checkRBIPII checks request query for India-specific PII.
// Returns the check result with detected PII types and blocking recommendation.
// In Community builds, this returns a no-PII result (detection is disabled).
// The blockOnCritical parameter respects PII_ACTION env var (Issue #891):
// - block: blockOnCritical=true (default legacy behavior)
// - redact: blockOnCritical=false (flag for redaction instead of blocking)
func checkRBIPII(query string, blockOnCritical bool) *rbi.RBIPIICheckResult {
	detector := getRBIPIIDetector()
	// Block on critical PII (Aadhaar, PAN, UPI, Bank Account) per RBI FREE-AI guidelines
	// unless PII_ACTION=redact is configured
	return rbi.CheckRequestForPII(detector, query, blockOnCritical)
}

// getGatewayAuditQueue returns the audit queue for Gateway Mode handlers.
// Uses the global AuditManager (preferred), falling back to DatabasePolicyEngine.
func getGatewayAuditQueue() *AuditQueue {
	if auditManager != nil {
		return auditManager.GetQueue()
	}
	if dbPolicyEngine != nil {
		return dbPolicyEngine.GetAuditQueue()
	}
	return nil
}

// handlePolicyPreCheck handles POST /api/policy/pre-check
// This is the first step in Gateway Mode - SDK calls this before making LLM call
func handlePolicyPreCheck(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Printf("📋 [Gateway Mode] Pre-check request received")

	// Parse request
	var req PreCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ [Pre-check] Invalid request body: %v", err)
		sendGatewayError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Query == "" {
		log.Printf("❌ [Pre-check] Missing required field: query")
		sendGatewayError(w, "query field is required", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		log.Printf("❌ [Pre-check] Missing required field: client_id")
		sendGatewayError(w, "client_id field is required", http.StatusBadRequest)
		return
	}

	// Validate credentials from OAuth2 Basic auth header (not required in Community mode)
	clientSecret := extractClientSecret(r)
	if clientSecret == "" && !isCommunityMode() {
		log.Printf("❌ [Pre-check] Missing authentication - no Authorization header")
		sendGatewayError(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized)
		return
	}

	// Validate client
	var client *Client
	var err error
	ctx := r.Context()

	if isCommunityMode() {
		client = &Client{
			ID:          req.ClientID,
			Name:        "Community",
			OrgID:       "community",
			TenantID:    req.ClientID,
			Enabled:     true,
			LicenseTier: "Community",
		}
	} else if authDB != nil {
		client, err = validateClientCredentialsDB(ctx, authDB, req.ClientID, clientSecret)
	} else {
		client, err = validateClientCredentials(ctx, req.ClientID, clientSecret)
	}

	if err != nil {
		log.Printf("❌ [Pre-check] Client validation failed: %v", err)
		sendGatewayError(w, "Authentication failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	if !client.Enabled {
		sendGatewayError(w, "Client disabled", http.StatusForbidden)
		return
	}

	// Validate user token
	user, err := validateUserToken(req.UserToken, client.TenantID)
	if err != nil {
		log.Printf("❌ [Pre-check] User token validation failed: %v", err)
		sendGatewayError(w, "Invalid user token", http.StatusUnauthorized)
		return
	}

	// Verify tenant isolation
	if user.TenantID != client.TenantID {
		log.Printf("❌ [Pre-check] Tenant mismatch: user=%s, client=%s", user.TenantID, client.TenantID)
		sendGatewayError(w, "Tenant mismatch", http.StatusForbidden)
		return
	}

	// RBI FREE-AI Compliance: Check for active kill switches (emergency AI disable)
	// This allows organizations to instantly halt all AI operations per RBI guidelines
	killSwitchResult := checkRBIKillSwitch(ctx, client.OrgID, "")
	if killSwitchResult.IsBlocked {
		log.Printf("🛑 [Pre-check] Request blocked by RBI kill switch: %s", killSwitchResult.Reason)
		gatewayPreCheckRequests.WithLabelValues("success", "false").Inc()
		response := PreCheckResponse{
			ContextID:   uuid.New().String(),
			Approved:    false,
			Policies:    []string{"rbi_kill_switch"},
			BlockReason: killSwitchResult.Reason,
			ExpiresAt:   time.Now(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// RBI FREE-AI Compliance: Check for India-specific PII before policy evaluation
	// This runs in both Community (no-op) and Enterprise (full detection) modes
	// Issue #891: Respect PII_ACTION setting - block only if PII_ACTION=block
	gwDetectionCfg := GetGatewayDetectionConfig()
	rbiPIIRequiresRedaction := false
	blockOnCriticalPII := gwDetectionCfg.Enabled && gwDetectionCfg.PIIAction == DetectionActionBlock
	piiResult := checkRBIPII(req.Query, blockOnCriticalPII)

	if piiResult.BlockRecommended {
		log.Printf("🛑 [Pre-check] Request blocked by RBI PII detection: %s", piiResult.Reason)
		gatewayPreCheckRequests.WithLabelValues("success", "false").Inc()
		// Record metrics for each detected PII type
		for _, piiType := range piiResult.DetectedTypes {
			gatewayRBIPIIDetected.WithLabelValues(string(piiType), "true").Inc()
		}
		response := PreCheckResponse{
			ContextID:   uuid.New().String(),
			Approved:    false,
			Policies:    []string{"rbi_pii_protection"},
			BlockReason: piiResult.Reason,
			ExpiresAt:   time.Now(),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	// Record PII detection metrics even for non-blocking detections
	if piiResult.HasPII {
		for _, piiType := range piiResult.DetectedTypes {
			gatewayRBIPIIDetected.WithLabelValues(string(piiType), "false").Inc()
		}
		// Issue #891: If critical India PII detected but PII_ACTION=redact, flag for redaction
		if gwDetectionCfg.Enabled && piiResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
			log.Printf("🇮🇳 [Pre-check] Critical India PII detected - flagged for redaction (action=redact): %v", piiResult.DetectedTypes)
			rbiPIIRequiresRedaction = true
		} else {
			log.Printf("⚠️ [Pre-check] India PII detected (non-critical): %v", piiResult.DetectedTypes)
		}
	}

	// IMPORTANT: Gateway Mode Design Decision - Static Policies Only
	//
	// Gateway Mode intentionally ONLY evaluates static policies (PII detection, SQL injection,
	// dangerous queries) for lowest latency. It does NOT call the Orchestrator for dynamic
	// policies.
	//
	// This means:
	// - Custom policies created via Customer Portal UI or API are NOT enforced
	// - Policy versioning and testing features are NOT available
	// - Only built-in security patterns are evaluated
	//
	// For full policy support including dynamic policies, users should use Proxy Mode.
	// See: docs.getaxonflow.com/docs/sdk/choosing-a-mode
	//
	// Evaluate policies using unified shared policy engine (Issues #963, #975)
	// The shared engine provides comprehensive PII detection with validators
	// (Luhn, MOD97, Verhoeff, SSN, Aadhaar, PAN) and SQL injection detection.
	var policyResult *StaticPolicyResult

	// Try shared policy engine first for comprehensive PII/SQLi detection
	sharedEngine := sharedpolicy.GetGlobalEngine()
	if !gwDetectionCfg.Enabled {
		// Gateway static policies disabled — skip all policy evaluation
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"gateway_static_policies_disabled"},
		}
	} else if sharedEngine != nil {
		requestResult := sharedEngine.EvaluateRequest(ctx, req.Query, sharedpolicy.EvalOptions{
			TenantID:      user.TenantID,
			ConnectorName: "gateway",
			UserID:        fmt.Sprintf("%d", user.ID),
			Categories: []sharedpolicy.PolicyCategory{
				// Security categories
				sharedpolicy.CategorySecuritySQLi,
				sharedpolicy.CategorySecurityDangerous,
				// PII categories by jurisdiction
				sharedpolicy.CategoryPIIGlobal,
				sharedpolicy.CategoryPIIUS,
				sharedpolicy.CategoryPIIIndia,
				sharedpolicy.CategoryPIIEU,
				sharedpolicy.CategoryPIISingapore,
				// HITL/Compliance categories (Issue #1081)
				sharedpolicy.CategorySensitiveData, // For dynamically created HITL policies
				sharedpolicy.CategoryComplianceRBI,
				sharedpolicy.CategoryComplianceSEBI,
				sharedpolicy.CategoryComplianceEUAIAct,
				sharedpolicy.CategoryComplianceMASFEAT,
			},
			SkipCategories:  gwDetectionCfg.SkipCategories,
			ActionOverrides: gwDetectionCfg.BuildActionOverrides(),
		})
		// Convert to StaticPolicyResult for backward compatibility
		policyResult = convertSharedResultToStatic(requestResult)
		log.Printf("[Gateway] Shared policy engine evaluated %d policies in %dms",
			requestResult.PoliciesEvaluated, requestResult.ProcessingTimeMs)
	} else if dbPolicyEngine != nil {
		// Fallback to database-loaded policy engine
		policyResult = dbPolicyEngine.EvaluateStaticPolicies(user, req.Query, "llm_chat")
	} else if staticPolicyEngine != nil {
		// Fallback to hardcoded static policy engine
		policyResult = staticPolicyEngine.EvaluateStaticPolicies(user, req.Query, "llm_chat")
	} else {
		// No policy engine available - allow by default
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"no_policy_engine"},
		}
		// Log bypass warning - helps teams understand governance gaps
		if shouldLogBypassOutreach() {
			log.Printf("AxonFlow: governance bypassed - no policy engine configured. If intentional, share context privately: founders@getaxonflow.com (no marketing, no follow-ups)")
		}
	}

	// Issue #1082: Check budget limits before allowing request
	// This enforces pre-request budget checks in Gateway Mode
	var budgetInfo *BudgetInfo
	if costService != nil && !policyResult.Blocked {
		budgetDecision, err := costService.CheckBudget(ctx, client.OrgID, "", "", fmt.Sprintf("%d", user.ID), client.TenantID)
		if err != nil {
			log.Printf("⚠️ [Pre-check] Budget check failed: %v (allowing request)", err)
		} else if budgetDecision != nil {
			// Build budget info for response
			budgetInfo = &BudgetInfo{
				BudgetID:   budgetDecision.BudgetID,
				BudgetName: budgetDecision.BudgetName,
				UsedUSD:    budgetDecision.UsedUSD,
				LimitUSD:   budgetDecision.LimitUSD,
				Percentage: budgetDecision.Percentage,
				Exceeded:   !budgetDecision.Allowed || budgetDecision.Percentage >= 100,
				Action:     string(budgetDecision.Action),
			}

			// Check if budget is exceeded and should block
			if !budgetDecision.Allowed {
				log.Printf("💰 [Pre-check] Request blocked by budget: %s", budgetDecision.Message)
				gatewayPreCheckRequests.WithLabelValues("success", "false").Inc()
				response := PreCheckResponse{
					ContextID:   uuid.New().String(),
					Approved:    false,
					Policies:    []string{"budget_exceeded"},
					BlockReason: budgetDecision.Message,
					BudgetInfo:  budgetInfo,
					ExpiresAt:   time.Now(),
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired) // 402 Payment Required
				_ = json.NewEncoder(w).Encode(response)
				return
			}

			// If exceeded but action is warn, add header
			if budgetDecision.Percentage >= 100 && budgetDecision.Action == cost.OnExceedWarn {
				log.Printf("⚠️ [Pre-check] Budget exceeded with warn action: %s", budgetDecision.Message)
				w.Header().Set("X-Budget-Warning", budgetDecision.Message)
			}
		}
	}

	// Generate context ID
	contextID := uuid.New().String()
	expiresAt := time.Now().Add(defaultContextExpiry)

	// Issue #1081: Check if HITL (Human-in-the-Loop) is required
	// HITL is ONLY triggered by policy evaluation returning require_approval action.
	// This is an ENTERPRISE-ONLY feature - in Community mode, require_approval policies auto-approve.
	// Security: We do NOT trust client-provided context (requires_hitl, eu_ai_act_article_14, etc.)
	// as that would allow any client to bypass policy or trigger DoS.
	requiresHITL := policyResult.RequiresApproval && !isCommunityMode()

	// Build response
	// Issue #891: Combine redaction flags from static policies and RBI PII detection
	requiresRedaction := policyResult.RequiresRedaction || rbiPIIRequiresRedaction

	// Determine if request should be blocked
	// Block if: policy blocked OR HITL required (Enterprise only - pending human approval)
	isBlocked := policyResult.Blocked || requiresHITL

	response := PreCheckResponse{
		ContextID:         contextID,
		Approved:          !isBlocked,
		RequiresRedaction: requiresRedaction,
		Policies:          policyResult.TriggeredPolicies,
		BudgetInfo:        budgetInfo, // Issue #1082: Include budget status
		ExpiresAt:         expiresAt,
	}

	// Add RBI PII policy to triggered policies if redaction required
	if rbiPIIRequiresRedaction {
		response.Policies = append(response.Policies, "rbi_pii_protection")
	}

	// Issue #1081: Add HITL policy to triggered policies if HITL required (Enterprise only)
	if requiresHITL {
		response.Policies = append(response.Policies, "hitl_enterprise")
	}

	if policyResult.Blocked {
		response.BlockReason = policyResult.Reason
		log.Printf("⛔ [Pre-check] Request blocked: %s", policyResult.Reason)
	} else if requiresHITL {
		// Issue #1081: HITL required (Enterprise only) - block with require_approval reason
		// This enables EU AI Act Article 14, RBI, SEBI, and other compliance frameworks
		response.BlockReason = "require_approval"
		log.Printf("⏸️ [Pre-check] HITL required (Enterprise) - awaiting human approval (contextID=%s)", contextID)
	} else if requiresRedaction {
		log.Printf("⚠️ [Pre-check] Request approved with redaction required: %s", policyResult.Reason)
	} else {
		// Fetch data from MCP connectors if data sources specified
		if len(req.DataSources) > 0 && mcpRegistry != nil {
			approvedData, err := fetchApprovedData(ctx, req.DataSources, req.Query, user, client)
			if err != nil {
				log.Printf("⚠️ [Pre-check] MCP data fetch warning: %v", err)
			} else {
				response.ApprovedData = approvedData
			}
		}
	}

	// Store context via AuditQueue for reliable persistence
	// Uses retry with exponential backoff and fallback file if DB fails
	if err := queueGatewayContext(contextID, client.ID, req, policyResult, expiresAt); err != nil {
		log.Printf("⚠️ [Pre-check] Failed to queue context: %v (continuing)", err)
		gatewayAuditQueuedTotal.WithLabelValues("gateway_context", "error").Inc()
	} else {
		gatewayAuditQueuedTotal.WithLabelValues("gateway_context", "success").Inc()
	}

	// Record metrics
	latencyMs := time.Since(startTime).Milliseconds()
	gatewayPreCheckDuration.Observe(float64(latencyMs))
	approvedStr := "true"
	if policyResult.Blocked {
		approvedStr = "false"
	}
	gatewayPreCheckRequests.WithLabelValues("success", approvedStr).Inc()
	log.Printf("✅ [Pre-check] Completed in %dms - contextID=%s, approved=%v",
		latencyMs, contextID, response.Approved)

	// Rate-limited outreach log on successful policy enforcement
	// Appears once per hour to real operators, not on every request
	if response.Approved && len(policyResult.TriggeredPolicies) > 0 && shouldLogEnforcementOutreach() {
		log.Printf("AxonFlow: policy enforced in %dms. Evaluating for internal use? Share context privately: founders@getaxonflow.com (no marketing, no follow-ups)", latencyMs)
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("❌ [Pre-check] Failed to encode response: %v", err)
	}
}

// handleAuditLLMCall handles POST /api/audit/llm-call
// This is the second step in Gateway Mode - SDK calls this after making LLM call
func handleAuditLLMCall(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	log.Printf("📝 [Gateway Mode] Audit LLM call request received")

	// Parse request
	var req AuditLLMCallRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("❌ [Audit] Invalid request body: %v", err)
		sendGatewayError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.ContextID == "" {
		log.Printf("❌ [Audit] Missing required field: context_id")
		sendGatewayError(w, "context_id field is required", http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		log.Printf("❌ [Audit] Missing required field: client_id")
		sendGatewayError(w, "client_id field is required", http.StatusBadRequest)
		return
	}
	if req.Provider == "" {
		log.Printf("❌ [Audit] Missing required field: provider")
		sendGatewayError(w, "provider field is required", http.StatusBadRequest)
		return
	}
	if req.Model == "" {
		log.Printf("❌ [Audit] Missing required field: model")
		sendGatewayError(w, "model field is required", http.StatusBadRequest)
		return
	}

	// Validate credentials via OAuth2 Basic auth (not required in Community mode)
	clientSecret := extractClientSecret(r)
	if clientSecret == "" && !isCommunityMode() {
		sendGatewayError(w, "Authentication required: provide Authorization header with Basic auth (clientId:clientSecret)", http.StatusUnauthorized)
		return
	}

	// Validate context exists and is not expired (if DB available)
	if authDB != nil {
		valid, err := validateGatewayContext(authDB, req.ContextID, req.ClientID)
		if err != nil {
			log.Printf("⚠️ [Audit] Context validation warning: %v", err)
		} else if !valid {
			log.Printf("❌ [Audit] Invalid or expired context: %s", req.ContextID)
			sendGatewayError(w, "Invalid or expired context", http.StatusBadRequest)
			return
		}
	}

	// Calculate estimated cost
	estimatedCost := calculateLLMCost(req.Provider, req.Model, req.TokenUsage)

	// Generate audit ID
	auditID := uuid.New().String()

	// Store audit record via AuditQueue for reliable persistence
	// Uses retry with exponential backoff and fallback file if DB fails
	if err := queueLLMCallAudit(auditID, req, estimatedCost); err != nil {
		log.Printf("⚠️ [Audit] Failed to queue audit: %v", err)
		gatewayAuditQueuedTotal.WithLabelValues("llm_call_audit", "error").Inc()
		// Don't fail the request - audit is best-effort but queued for retry
		// This is a key improvement over the previous fail-open behavior
	} else {
		gatewayAuditQueuedTotal.WithLabelValues("llm_call_audit", "success").Inc()
	}

	// Record Prometheus metrics
	latencyMs := time.Since(startTime).Milliseconds()
	gatewayAuditDuration.Observe(float64(latencyMs))
	gatewayAuditRequests.WithLabelValues("success", req.Provider).Inc()
	gatewayLLMTokensTotal.WithLabelValues(req.Provider, req.Model, "prompt").Add(float64(req.TokenUsage.PromptTokens))
	gatewayLLMTokensTotal.WithLabelValues(req.Provider, req.Model, "completion").Add(float64(req.TokenUsage.CompletionTokens))
	gatewayLLMCostTotal.WithLabelValues(req.Provider, req.Model).Add(estimatedCost)
	log.Printf("✅ [Audit] Recorded in %dms - auditID=%s, provider=%s, model=%s, tokens=%d, cost=$%.6f",
		latencyMs, auditID, req.Provider, req.Model, req.TokenUsage.TotalTokens, estimatedCost)

	// Send response
	response := AuditLLMCallResponse{
		Success: true,
		AuditID: auditID,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("❌ [Audit] Failed to encode response: %v", err)
	}
}

// fetchApprovedData fetches data from MCP connectors based on policy-approved sources
// This is optional for pre-check - clients may prefer to fetch data themselves
func fetchApprovedData(ctx context.Context, dataSources []string, query string, user *User, client *Client) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	// If no MCP registry available, return empty result
	if mcpRegistry == nil {
		log.Printf("⚠️ [Pre-check] MCP registry not available, skipping data fetch")
		return result, nil
	}

	for _, source := range dataSources {
		// Check if user has permission for this data source
		hasPermission := false
		for _, perm := range user.Permissions {
			if perm == source || perm == "mcp_query" || perm == "*" {
				hasPermission = true
				break
			}
		}

		if !hasPermission {
			log.Printf("⚠️ [Pre-check] User lacks permission for data source: %s", source)
			continue
		}

		// Get connector from registry
		connector, err := mcpRegistry.Get(source)
		if err != nil {
			log.Printf("⚠️ [Pre-check] Connector not found: %s - %v", source, err)
			continue
		}

		// Build MCP query using base.Query type
		mcpQuery := &base.Query{
			Statement: query,
			Parameters: map[string]interface{}{
				"user_id":   user.ID,
				"tenant_id": user.TenantID,
				"client_id": client.ID,
			},
		}

		// Execute query
		queryResult, err := connector.Query(ctx, mcpQuery)
		if err != nil {
			log.Printf("⚠️ [Pre-check] MCP query failed for %s: %v", source, err)
			continue
		}

		// Add result to approved data
		if queryResult != nil {
			result[source] = map[string]interface{}{
				"rows":        queryResult.Rows,
				"row_count":   queryResult.RowCount,
				"duration_ms": queryResult.Duration.Milliseconds(),
				"cached":      queryResult.Cached,
			}
		}
	}

	return result, nil
}

// storeGatewayContext stores the pre-check context for audit linking
func storeGatewayContext(db *sql.DB, contextID, clientID string, req PreCheckRequest, policyResult *StaticPolicyResult, expiresAt time.Time) error {
	// Hash sensitive data for privacy
	userTokenHash := hashString(req.UserToken)
	queryHash := hashString(req.Query)

	_, err := db.Exec(`
		INSERT INTO gateway_contexts (
			context_id, client_id, user_token_hash, query_hash,
			data_sources, policies_evaluated, approved, block_reason, expires_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, contextID, clientID, userTokenHash, queryHash,
		pq.Array(req.DataSources), pq.Array(policyResult.TriggeredPolicies),
		!policyResult.Blocked, policyResult.Reason, expiresAt)

	return err
}

// validateGatewayContext checks if context exists and is not expired
func validateGatewayContext(db *sql.DB, contextID, clientID string) (bool, error) {
	var expiresAt time.Time
	var storedClientID string

	err := db.QueryRow(`
		SELECT client_id, expires_at FROM gateway_contexts
		WHERE context_id = $1
	`, contextID).Scan(&storedClientID, &expiresAt)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	// Verify client matches
	if storedClientID != clientID {
		return false, fmt.Errorf("client mismatch")
	}

	// Check expiry
	if time.Now().After(expiresAt) {
		return false, nil
	}

	return true, nil
}

// storeLLMCallAudit stores the LLM call audit record
func storeLLMCallAudit(db *sql.DB, auditID string, req AuditLLMCallRequest, estimatedCost float64) error {
	metadataJSON, _ := json.Marshal(req.Metadata)

	_, err := db.Exec(`
		INSERT INTO llm_call_audits (
			audit_id, context_id, client_id, provider, model,
			prompt_tokens, completion_tokens, total_tokens,
			latency_ms, estimated_cost_usd, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, auditID, req.ContextID, req.ClientID, req.Provider, req.Model,
		req.TokenUsage.PromptTokens, req.TokenUsage.CompletionTokens, req.TokenUsage.TotalTokens,
		req.LatencyMs, estimatedCost, metadataJSON)

	return err
}

// calculateLLMCost estimates the cost of an LLM call based on provider, model, and tokens
func calculateLLMCost(provider, model string, usage TokenUsage) float64 {
	providerPricing, ok := llmPricing[provider]
	if !ok {
		// Unknown provider, use conservative estimate
		return float64(usage.TotalTokens) * 0.01 / 1000
	}

	pricePerK, ok := providerPricing[model]
	if !ok {
		// Unknown model for this provider, use default
		if defaultPrice, hasDefault := providerPricing["default"]; hasDefault {
			pricePerK = defaultPrice
		} else {
			pricePerK = 0.01 // Conservative default
		}
	}

	return float64(usage.TotalTokens) * pricePerK / 1000
}

// hashString creates a SHA256 hash of a string (for privacy)
func hashString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}


// sendGatewayError sends a JSON error response
func sendGatewayError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// RegisterGatewayHandlers registers the gateway mode endpoints
func RegisterGatewayHandlers(r *mux.Router) {
	r.HandleFunc("/api/policy/pre-check", handlePolicyPreCheck).Methods("POST")
	r.HandleFunc("/api/audit/llm-call", handleAuditLLMCall).Methods("POST")
	log.Println("✅ Gateway mode endpoints registered: /api/policy/pre-check, /api/audit/llm-call")
}

// queueGatewayContext queues the pre-check context via AuditQueue
// Falls back to direct DB write if queue is unavailable
func queueGatewayContext(contextID, clientID string, req PreCheckRequest, policyResult *StaticPolicyResult, expiresAt time.Time) error {
	// Hash sensitive data for privacy
	userTokenHash := hashString(req.UserToken)
	queryHash := hashString(req.Query)

	// Get the audit queue
	auditQueue := getGatewayAuditQueue()

	// Build the audit entry
	// Use plain slices (not pq.Array) for JSON serialization compatibility
	// The AuditQueue will convert to pq.Array when writing to DB
	entry := AuditEntry{
		Type:      AuditTypeGatewayContext,
		Timestamp: time.Now(),
		ClientID:  clientID,
		Details: map[string]interface{}{
			"context_id":         contextID,
			"user_token_hash":    userTokenHash,
			"query_hash":         queryHash,
			"data_sources":       req.DataSources,
			"policies_evaluated": policyResult.TriggeredPolicies,
			"approved":           !policyResult.Blocked,
			"block_reason":       policyResult.Reason,
			"expires_at":         expiresAt,
		},
	}

	// Use audit queue if available
	if auditQueue != nil {
		if err := auditQueue.LogGatewayContext(entry); err != nil {
			log.Printf("⚠️ [Gateway] AuditQueue failed, falling back to direct write: %v", err)
			gatewayAuditFallbackTotal.Inc()
			// Fall through to direct write
		} else {
			return nil // Successfully queued
		}
	}

	// Fallback to direct DB write (legacy behavior)
	if authDB != nil {
		return storeGatewayContext(authDB, contextID, clientID, req, policyResult, expiresAt)
	}

	return nil // No storage available, but don't fail the request
}

// queueLLMCallAudit queues the LLM call audit via AuditQueue
// Falls back to direct DB write if queue is unavailable
func queueLLMCallAudit(auditID string, req AuditLLMCallRequest, estimatedCost float64) error {
	// Get the audit queue
	auditQueue := getGatewayAuditQueue()

	// Build the audit entry
	entry := AuditEntry{
		Type:      AuditTypeLLMCallAudit,
		Timestamp: time.Now(),
		ClientID:  req.ClientID,
		Details: map[string]interface{}{
			"audit_id":           auditID,
			"context_id":         req.ContextID,
			"provider":           req.Provider,
			"model":              req.Model,
			"prompt_tokens":      req.TokenUsage.PromptTokens,
			"completion_tokens":  req.TokenUsage.CompletionTokens,
			"total_tokens":       req.TokenUsage.TotalTokens,
			"latency_ms":         req.LatencyMs,
			"estimated_cost_usd": estimatedCost,
			"metadata":           req.Metadata,
		},
	}

	// Use audit queue if available
	if auditQueue != nil {
		if err := auditQueue.LogLLMCallAudit(entry); err != nil {
			log.Printf("⚠️ [Gateway] AuditQueue failed, falling back to direct write: %v", err)
			gatewayAuditFallbackTotal.Inc()
			// Fall through to direct write
		} else {
			return nil // Successfully queued
		}
	}

	// Fallback to direct DB write (legacy behavior)
	if authDB != nil {
		return storeLLMCallAudit(authDB, auditID, req, estimatedCost)
	}

	return nil // No storage available, but don't fail the request
}

// convertSharedResultToStatic and isPIICategory moved to policy_result_convert.go

// NOTE: checkHITLRequiredFromContext was REMOVED in Issue #1081 code review.
// HITL enforcement is an ENTERPRISE-ONLY feature.
// HITL is ONLY triggered by policy evaluation returning require_approval action.
// We do NOT trust client-provided context metadata (requires_hitl, eu_ai_act_article_14, etc.)
// as that would allow:
// 1. Any client to bypass licensing (HITL is Enterprise-only)
// 2. DoS attacks by clients setting HITL flags on all requests
// 3. Security bypass by untrusted input controlling enforcement behavior
