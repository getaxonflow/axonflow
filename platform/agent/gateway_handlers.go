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
	"axonflow/platform/shared/llmdefaults"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	logutil "axonflow/platform/shared/logger"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/agent/indonesia"
	"axonflow/platform/agent/rbi"
	"axonflow/platform/agent/telemetry"
	"axonflow/platform/connectors/base"
	"axonflow/platform/orchestrator/cost"
	sharedaudit "axonflow/platform/shared/audit"
	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

// Outreach log rate limiting - logs once per hour max per category
var (
	outreachLogMu          sync.Mutex
	lastEnforcementLogTime time.Time
	lastBypassLogTime      time.Time
	outreachLogInterval    = time.Hour
)

// gatewayPreCheckPolicyCategories is the category whitelist evaluated by
// handlePolicyPreCheck. #2965: the PII portion is sourced from the single
// canonical sharedpolicy.AllTextPIICategories() so no pii-* jurisdiction can be
// dropped from this plane (the class of bug that left pii-indonesia ungoverned
// elsewhere). Covered by TestPlaneWhitelistsCoverAllPII.
var gatewayPreCheckPolicyCategories = append([]sharedpolicy.PolicyCategory{
	sharedpolicy.CategorySecuritySQLi,
	sharedpolicy.CategorySecurityDangerous,
	sharedpolicy.CategorySensitiveData, // For dynamically created HITL policies (#1081)
	sharedpolicy.CategoryComplianceRBI,
	sharedpolicy.CategoryComplianceSEBI,
	sharedpolicy.CategoryComplianceEUAIAct,
	sharedpolicy.CategoryComplianceMASFEAT,
}, sharedpolicy.AllTextPIICategories()...)

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
		_ = prometheus.Register(gatewayIndonesiaPIIDetected)
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
	// TraceID is the W3C OpenTelemetry trace_id emitted by the decision
	// tracer (#2426 WS4). Empty when AXONFLOW_OTEL_ENDPOINT is unset
	// (Community-tier default — OTel is opt-in). Decision-Mode PEPs
	// propagate this id downstream so multi-gateway decisions stitch
	// into one end-to-end trace per ADR-056 §"Trace correlation".
	TraceID string `json:"trace_id,omitempty"`
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
		"gpt-4o":        0.005,
		"gpt-4o-mini":   0.00015,
		"gpt-4":         0.03,
		"gpt-4-turbo":   0.01,   // legacy, kept for backward compat
		"gpt-3.5-turbo": 0.0005, // legacy, kept for backward compat
	},
	"anthropic": {
		llmdefaults.AnthropicModel:   0.0008, // claude-haiku-4-5-20251001 (current default)
		"claude-sonnet-4-5-20250929": 0.003,
		"claude-opus-4-1-20250805":   0.015,
		"claude-opus-4":              0.015,
		"claude-sonnet-4":            0.003,
		"claude-haiku-4.5":           0.0008,
		"claude-3-opus":              0.015, // legacy, kept for backward compat
		"claude-3-sonnet":            0.003, // legacy, kept for backward compat
		"claude-3-haiku":             0.001, // legacy, kept for backward compat
		"claude-3-5-sonnet":          0.003, // legacy, kept for backward compat
		"claude-3-5-haiku":           0.001, // legacy, kept for backward compat
	},
	"bedrock": {
		llmdefaults.BedrockModel:                       0.0008, // us.anthropic.claude-haiku-4-5-20251001-v1:0 (current default)
		"us.anthropic.claude-sonnet-4-5-20250929-v1:0": 0.003,
		"anthropic.claude-sonnet-4-20250514-v1:0":      0.003,  // retired id, kept for historical audit rows
		"anthropic.claude-opus-4-20250514-v1:0":        0.015,  // retired id, kept for historical audit rows
		"anthropic.claude-haiku-4-5-20251001-v1:0":     0.0008, // non-prefixed variant, kept for historical audit rows
		"anthropic.claude-v2":                          0.008,
		"amazon.titan-text":                            0.0008,
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
	gatewayIndonesiaPIIDetected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_gateway_indonesia_pii_detected_total",
			Help: "Total Indonesia PII detections in gateway pre-check",
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

var (
	indonesiaPIIDetector     *indonesia.IndonesiaPIIDetector
	indonesiaPIIDetectorOnce sync.Once
)

func getIndonesiaPIIDetector() *indonesia.IndonesiaPIIDetector {
	indonesiaPIIDetectorOnce.Do(func() {
		if indonesia.IsEnabled() {
			config := indonesia.DefaultIndonesiaPIIDetectorConfig()
			indonesiaPIIDetector = indonesia.NewIndonesiaPIIDetector(config)
			log.Printf("🇮🇩 [OJK] Indonesia PII detector initialized")
		} else {
			log.Printf("🇮🇩 [OJK] Indonesia PII detection disabled (Community Edition — enterprise detector not built in)")
		}
	})
	return indonesiaPIIDetector
}

func checkIndonesiaPII(query string, blockOnCritical bool) *indonesia.IndonesiaPIICheckResult {
	detector := getIndonesiaPIIDetector()
	return indonesia.CheckRequestForPII(detector, query, blockOnCritical)
}

// checkIndonesiaResponsePII runs the SAME checksum-validated Indonesia detector
// on response text. CheckRequestForPII/DetectAll are text-based (not
// request-specific), so the response path reuses them rather than introducing a
// second detector — this is what closes the request/response asymmetry that let
// NIK be governed on input but leak on output (the static sys_pii_indonesia_ktp
// policy is request-phase "menu/spec parity" only; the real checksum validator
// lives here, mirroring the orchestrator's response-side detector).
func checkIndonesiaResponsePII(responseText string, blockOnCritical bool) *indonesia.IndonesiaPIICheckResult {
	detector := getIndonesiaPIIDetector()
	return indonesia.CheckRequestForPII(detector, responseText, blockOnCritical)
}

// indonesiaDetectedTypeNames returns the distinct detected Indonesia PII type
// names from a check result, for the audit trail's redacted-fields record.
func indonesiaDetectedTypeNames(r *indonesia.IndonesiaPIICheckResult) []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.DetectedTypes))
	for _, t := range r.DetectedTypes {
		names = append(names, string(t))
	}
	return names
}

// redactIndonesiaPIIInString masks every Indonesia PII occurrence in s using the
// detector's per-detection MaskedValue (NIK/NPWP/+62/bank). Returns the masked
// string and whether anything changed. Used for the response/check-output redact
// path (PII_ACTION=redact) alongside the block path.
func redactIndonesiaPIIInString(s string) (string, bool) {
	detector := getIndonesiaPIIDetector()
	if detector == nil || s == "" {
		return s, false
	}
	out := s
	for _, d := range detector.DetectAll(s) {
		if d.Value != "" && d.MaskedValue != "" && d.MaskedValue != d.Value {
			out = strings.ReplaceAll(out, d.Value, d.MaskedValue)
		}
	}
	return out, out != s
}

// getGatewayAuditQueue returns the audit queue for Gateway Mode handlers.
func getGatewayAuditQueue() *AuditQueue {
	if auditManager != nil {
		return auditManager.GetQueue()
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

	// Authentication is handled by apiAuthMiddleware — read identity from context.
	// The auth-derived tenant/client is authoritative. In community mode the
	// middleware defaults to "community" when no Basic auth is provided, so we
	// fall back to req.ClientID for backwards compatibility (community users
	// identify themselves via the body, not credentials).
	authClientID := ClientIDFromContext(r.Context())
	tenantID := TenantIDFromContext(r.Context())
	orgID := OrgIDFromContext(r.Context())
	ctx := r.Context()

	effectiveClientID := authClientID
	if isCommunityMode() && (authClientID == "" || authClientID == "community") {
		// Community mode: no credentials → use body client_id for context records
		effectiveClientID = req.ClientID
		tenantID = req.ClientID
	}

	client := &Client{
		ID:       effectiveClientID,
		ClientID: effectiveClientID, // v9 ADR-052: ClientID == ID during compat window
		Name:     effectiveClientID,
		OrgID:    orgID,
		TenantID: tenantID,
		Enabled:  true,
	}

	// Canonical audit identity, built once and threaded into every terminal
	// verdict + early-return deny below (#2642). User fields are filled in after
	// ResolveUser; the deny paths that fire BEFORE resolution (client disabled /
	// invalid token) fall back to writeDecisionAuditLog's NOT-NULL placeholders.
	// plane is stamped PlaneGateway inside recordGatewayPreCheckAudit.
	precheckStage := decisionStageForPreCheck(req)
	preCheckAudit := decisionAuditInput{
		clientID: effectiveClientID,
		query:    req.Query,
		// correlationID groups this decision with the PEP's downstream hops when it
		// propagated a W3C traceparent; absent → "" → NULL → singleton chain.
		correlationID: traceIDFromHeader(r.Header.Get("traceparent")),
	}

	if !client.Enabled {
		// Defense-in-depth: Enabled is hard-set true above today, so this branch is
		// currently unreachable — but if client provisioning ever gates Enabled, the
		// refusal must still be auditable. Canonical row first, then deny (#2642).
		recordGatewayPreCheckAudit(ctx, uuid.New().String(), client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, []string{"client_disabled"}, []string{"Client disabled"}, preCheckAudit)
		sendGatewayError(w, "Client disabled", http.StatusForbidden)
		return
	}

	// Resolve user via unified ResolveUser — consistent with all other handlers.
	// In community/community-saas mode this returns a synthetic user (no JWT needed).
	// In enterprise/evaluation mode this validates the JWT user token.
	authKind := AuthKindFromContext(r.Context())
	authResult := &AuthResult{Kind: authKind, TenantID: tenantID, OrgID: orgID, ClientID: effectiveClientID, Client: client}
	user, userErr := ResolveUser(authResult, req.UserToken)
	if userErr != nil {
		log.Printf("❌ [Pre-check] User resolution failed: %v", userErr.Message)
		// Audit the refusal (#2642). The user token never resolved, so the row
		// carries the writer's user placeholders; org/tenant/client identity is the
		// auth-derived context. Reason is FIXED — no token material on the row.
		recordGatewayPreCheckAudit(ctx, uuid.New().String(), client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, []string{"user_token_invalid"}, []string{"user token validation failed"}, preCheckAudit)
		sendGatewayError(w, userErr.Message, userErr.HTTPStatus)
		return
	}

	// Enrich the audit identity now that the user is resolved — every verdict from
	// here on records the real user (#2642).
	preCheckAudit.userEmail = user.Email
	preCheckAudit.userRole = user.Role
	preCheckAudit.userID = user.ID

	// Verify tenant isolation
	if user.TenantID != client.TenantID {
		log.Printf("❌ [Pre-check] Tenant mismatch: user=%s, client=%s", user.TenantID, client.TenantID)
		// Security-relevant deny: a token whose tenant doesn't match the client it
		// was presented with. Auditable against the client's asserted tenant (#2642).
		recordGatewayPreCheckAudit(ctx, uuid.New().String(), client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, []string{"tenant_mismatch"}, []string{"tenant mismatch"}, preCheckAudit)
		sendGatewayError(w, "Tenant mismatch", http.StatusForbidden)
		return
	}

	// Circuit breaker check — block if circuit is open for this client/tenant/org (#1176)
	if circuitBreakerInstance != nil {
		cbResult, cbErr := circuitBreakerInstance.Check(ctx, circuitbreaker.CheckInput{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ID,
		})
		if cbErr != nil {
			log.Printf("⚠️ [Pre-check] Circuit breaker check error: %v", cbErr)
		} else if !cbResult.Allowed {
			log.Printf("🔴 [Pre-check] Request blocked by circuit breaker: scope=%s reason=%s", cbResult.Scope, cbResult.Reason)
			if retryAfter := circuitBreakerRetryAfter(cbResult.ExpiresAt); retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			// Circuit-breaker is a (transient) deny — the request WAS refused, so it
			// is auditable as blocked; the reason makes the transient nature clear (#2642).
			recordGatewayPreCheckAudit(ctx, uuid.New().String(), client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, []string{"circuit_breaker"}, []string{string(cbResult.Reason)}, preCheckAudit)
			sendGatewayError(w, fmt.Sprintf("Service temporarily unavailable: circuit breaker active (reason: %s)", cbResult.Reason), http.StatusServiceUnavailable)
			return
		}
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
		response.TraceID = recordPreCheckDecision(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, killSwitchResult.Reason, response.Policies, time.Since(startTime).Milliseconds())
		recordGatewayPreCheckAudit(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, response.Policies, []string{killSwitchResult.Reason}, preCheckAudit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}

	// Issue #891: Respect PII_ACTION setting - block only if PII_ACTION=block
	// #2581: resolve per-org posture (org with no override → deployment-global).
	gwDetectionCfg := ResolveGatewayDetectionConfig(ctx, orgID)
	rbiPIIRequiresRedaction := false
	indonesiaPIIRequiresRedaction := false
	blockOnCriticalPII := gwDetectionCfg.Enabled && gwDetectionCfg.PIIAction == DetectionActionBlock

	// OJK/UU PDP Compliance: Check Indonesia-specific PII FIRST (NIK, NPWP, +62, bank accounts).
	// Indonesia detector runs before RBI to prevent the generic RBI bank-account pattern
	// from shadowing Indonesia-specific bank account detection (BCA/Mandiri/BRI/BNI).
	indonesiaPIIResult := checkIndonesiaPII(req.Query, blockOnCriticalPII)
	if indonesiaPIIResult.BlockRecommended {
		log.Printf("🛑 [Pre-check] Request blocked by Indonesia PII detection: %s", indonesiaPIIResult.Reason)
		gatewayPreCheckRequests.WithLabelValues("success", "false").Inc()
		for _, piiType := range indonesiaPIIResult.DetectedTypes {
			gatewayIndonesiaPIIDetected.WithLabelValues(string(piiType), "true").Inc()
		}
		response := PreCheckResponse{
			ContextID:   uuid.New().String(),
			Approved:    false,
			Policies:    []string{"indonesia_pii_protection"},
			BlockReason: indonesiaPIIResult.Reason,
			ExpiresAt:   time.Now(),
		}
		response.TraceID = recordPreCheckDecision(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, indonesiaPIIResult.Reason, response.Policies, time.Since(startTime).Milliseconds())
		recordGatewayPreCheckAudit(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, response.Policies, []string{indonesiaPIIResult.Reason}, preCheckAudit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if indonesiaPIIResult.HasPII {
		for _, piiType := range indonesiaPIIResult.DetectedTypes {
			gatewayIndonesiaPIIDetected.WithLabelValues(string(piiType), "false").Inc()
		}
		if gwDetectionCfg.Enabled && indonesiaPIIResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
			log.Printf("🇮🇩 [Pre-check] Critical Indonesia PII detected - flagged for redaction: %v", indonesiaPIIResult.DetectedTypes)
			indonesiaPIIRequiresRedaction = true
		} else {
			log.Printf("⚠️ [Pre-check] Indonesia PII detected (non-critical): %v", indonesiaPIIResult.DetectedTypes)
		}
	}

	// RBI FREE-AI Compliance: Check for India-specific PII (Aadhaar, PAN, IFSC, bank accounts)
	piiResult := checkRBIPII(req.Query, blockOnCriticalPII)
	if piiResult.BlockRecommended {
		log.Printf("🛑 [Pre-check] Request blocked by RBI PII detection: %s", piiResult.Reason)
		gatewayPreCheckRequests.WithLabelValues("success", "false").Inc()
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
		response.TraceID = recordPreCheckDecision(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, piiResult.Reason, response.Policies, time.Since(startTime).Milliseconds())
		recordGatewayPreCheckAudit(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, response.Policies, []string{piiResult.Reason}, preCheckAudit)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
		return
	}
	if piiResult.HasPII {
		for _, piiType := range piiResult.DetectedTypes {
			gatewayRBIPIIDetected.WithLabelValues(string(piiType), "false").Inc()
		}
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
			TenantID: user.TenantID,
			OrgID:    user.OrgID,
			// #3048 R3 HIGH-3: scope the loader's tenant pass by the
			// validated caller org (org_id may differ from tenant_id).
			OrganizationID:  sharedpolicy.OrgScopePtr(user.OrgID),
			ConnectorName:   "gateway",
			UserID:          fmt.Sprintf("%d", user.ID),
			Categories:      gatewayPreCheckPolicyCategories,
			SkipCategories:  gwDetectionCfg.SkipCategories,
			ActionOverrides: gwDetectionCfg.BuildActionOverrides(),
		})
		// Convert to StaticPolicyResult for backward compatibility
		policyResult = convertSharedResultToStatic(requestResult)
		log.Printf("[Gateway] Shared policy engine evaluated %d policies in %dms",
			requestResult.PoliciesEvaluated, requestResult.ProcessingTimeMs)
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
				response.TraceID = recordPreCheckDecision(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, budgetDecision.Message, response.Policies, time.Since(startTime).Milliseconds())
				recordGatewayPreCheckAudit(ctx, response.ContextID, client.OrgID, client.TenantID, precheckStage, gatewayAuditBlocked, response.Policies, []string{budgetDecision.Message}, preCheckAudit)
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
	// UTC pinned (#2876): gateway_contexts.expires_at was TIMESTAMP (no time
	// zone) until migration 142, and such a column discards the offset — a
	// local-zone time.Now() silently stored a shifted wall clock on non-UTC
	// hosts. The column is TIMESTAMPTZ now; .UTC() keeps this write correct
	// independent of the column type.
	expiresAt := time.Now().UTC().Add(defaultContextExpiry)

	// Issue #1081: Check if HITL (Human-in-the-Loop) is required
	// HITL is ONLY triggered by policy evaluation returning require_approval action.
	// This is an ENTERPRISE-ONLY feature - in Community mode, require_approval policies auto-approve.
	// Security: We do NOT trust client-provided context (requires_hitl, eu_ai_act_article_14, etc.)
	// as that would allow any client to bypass policy or trigger DoS.
	requiresHITL := policyResult.RequiresApproval && !isCommunityMode()

	// Build response
	// Issue #891: Combine redaction flags from static policies and RBI PII detection
	requiresRedaction := policyResult.RequiresRedaction || rbiPIIRequiresRedaction || indonesiaPIIRequiresRedaction

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

	// Add Indonesia PII policy to triggered policies if redaction required.
	// Mirrors the RBI flag above: under PII_ACTION=redact, critical Indonesia
	// PII (NIK / NPWP) must signal redaction the same way India PII does —
	// previously it was detected and logged but never flagged, so NIK slipped
	// through unredacted while SSN/Aadhaar were redacted.
	if indonesiaPIIRequiresRedaction {
		response.Policies = append(response.Policies, "indonesia_pii_protection")
	}

	// Issue #1081: Add HITL policy to triggered policies if HITL required (Enterprise only)
	if requiresHITL {
		response.Policies = append(response.Policies, "hitl_enterprise")
	}

	if requiresHITL {
		// HITL takes precedence over block — the request needs human approval,
		// not an outright deny. SDKs check for the exact "require_approval"
		// sentinel to trigger the HITL polling flow.
		response.BlockReason = "require_approval"
		log.Printf("⏸️ [Pre-check] HITL required (Enterprise) - awaiting human approval (contextID=%s)", contextID)
	} else if policyResult.Blocked {
		response.BlockReason = policyResult.Reason
		log.Printf("⛔ [Pre-check] Request blocked: %s", policyResult.Reason)
	}

	// Record policy violation for auto-trip threshold tracking
	if policyResult.Blocked || requiresHITL {
		if circuitBreakerInstance != nil {
			for _, policyID := range policyResult.TriggeredPolicies {
				if err := circuitBreakerInstance.RecordPolicyViolation(ctx, client.OrgID, client.TenantID, client.ID, policyID); err != nil {
					log.Printf("⚠️ [Pre-check] Circuit breaker RecordPolicyViolation error: %v", err)
				}
			}
		}
	}

	if !policyResult.Blocked && !requiresHITL && requiresRedaction {
		log.Printf("⚠️ [Pre-check] Request approved with redaction required: %s", policyResult.Reason)
	}
	// #2867: prefetch connector data ONLY for a clean-approved request (not
	// blocked, not HITL-pending, no redaction owed). A blocked pre-check must
	// NOT execute the caller's query against the connector — returning
	// approved_data on a deny leaks the data the block was meant to withhold
	// (incl. the #2862 policy-load fail-closed block); a HITL-pending pre-check
	// must not surface connector data before a human approves. The previous
	// else-branch fetched on every outcome except approved-with-redaction.
	if shouldPrefetchApprovedData(policyResult.Blocked, requiresHITL, requiresRedaction) {
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

	// Canonical plane=gateway audit_logs row (#2642), IN ADDITION to the
	// gateway_contexts satellite above. This is the row the portal decisions feed
	// (orchestrator GET /api/v1/decisions) reads: a redaction lands as 'redacted'
	// (DISTINCT from a clean 'allowed' — the split-brain this session closes), a
	// policy-engine block as 'blocked', a HITL hold as 'needs_approval'. Keyed by
	// the same contextID as the satellite so the two records join.
	recordGatewayPreCheckAudit(ctx, contextID, client.OrgID, client.TenantID, precheckStage,
		gatewayPreCheckAuditVerdict(policyResult.Blocked, requiresHITL, requiresRedaction),
		response.Policies, reasonsFromPreCheck(response, policyResult), preCheckAudit)

	// Record metrics
	latencyMs := time.Since(startTime).Milliseconds()
	gatewayPreCheckDuration.Observe(float64(latencyMs))
	approvedStr := "true"
	if policyResult.Blocked {
		approvedStr = "false"
	}
	gatewayPreCheckRequests.WithLabelValues("success", approvedStr).Inc()

	// Emit OTel decision span (#2426 WS4 / Brief 25-C). Reference
	// instrumentation for Session 25-A's POST /api/v1/decide handler —
	// same shape, same attributes, same response field. noop tracer
	// returns "" when AXONFLOW_OTEL_ENDPOINT is unset, which the SDK
	// omits via omitempty.
	if decisionTracerProvider != nil {
		response.TraceID = decisionTracerProvider.Tracer.RecordDecision(ctx, telemetry.DecisionEvent{
			DecisionID: contextID,
			OrgID:      client.OrgID,
			TenantID:   client.TenantID,
			Stage:      precheckStage,
			Verdict:    verdictFromPreCheck(response, requiresHITL),
			PolicyIDs:  response.Policies,
			LatencyMs:  latencyMs,
			Reasons:    reasonsFromPreCheck(response, policyResult),
		})
	}

	// Non-repudiation (#2732): sign + chain this terminal pre-check verdict into
	// decision_chain. Uses the canonical redaction-aware verdict (allowed /
	// blocked / redacted / needs_approval), NOT the three-valued telemetry
	// verdict above, so a redaction is recorded as a distinct, signed outcome
	// rather than collapsed to an allow. Outside the OTel guard so it runs even
	// when no OTel endpoint is configured; best-effort + off the hot path.
	recordSignedDecision(ctx, contextID, client.OrgID, client.TenantID, precheckStage,
		gatewayPreCheckAuditVerdict(policyResult.Blocked, requiresHITL, requiresRedaction),
		response.Policies, reasonsFromPreCheck(response, policyResult), latencyMs)

	log.Printf("✅ [Pre-check] Completed in %dms - contextID=%s, approved=%v, trace_id=%q",
		latencyMs, contextID, response.Approved, response.TraceID)

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

// Canonical audit_logs.policy_decision vocabulary for the Gateway pre-check
// plane (#2642 / ADR-058 bucket D). These are now ALIASES onto the single shared
// vocabulary in platform/shared/audit (#2638 S-WRITERS const-swap) — the same
// past-tense set every plane converges on and which the migration-123 CHECK
// enforces. The Gateway plane needs all four values for a reason specific to
// THIS hole:
//
//  1. A redaction must be DISTINGUISHABLE from a clean allow — the legacy
//     allow|deny wire set has no redaction value and would collapse a redacted
//     pre-check to "allow", the exact split-brain #2642 closed.
//  2. The portal reader (normalizeAuditAction, customer-portal-ui/lib/api.ts)
//     maps allowed→Allowed, blocked→Blocked, redacted→Modified but falls back to
//     "Logged" for the legacy allow/deny — so the canonical past-tense values
//     are the ones that render correctly in the feed.
//
// The Gateway-plane names are retained (provenance + call-site readability); the
// VALUES come from the shared package so they can never drift. needs_approval is
// the HITL outcome; its portal-reader alignment is the frontend slice #2636.
const (
	gatewayAuditAllowed       = sharedaudit.DecisionAllowed
	gatewayAuditBlocked       = sharedaudit.DecisionBlocked
	gatewayAuditRedacted      = sharedaudit.DecisionRedacted
	gatewayAuditNeedsApproval = sharedaudit.DecisionNeedsApproval
)

// gatewayPreCheckAuditVerdict maps a terminal pre-check outcome to the canonical
// audit verdict. HITL takes precedence over a hard block (the request is pending
// human approval, not refused), and a block takes precedence over redaction.
// requiresHITL is passed separately from blocked so HITL maps to needs_approval
// rather than the blocked label even though isBlocked = blocked || requiresHITL
// at the call site.
func gatewayPreCheckAuditVerdict(blocked, requiresHITL, requiresRedaction bool) string {
	switch {
	case requiresHITL:
		return gatewayAuditNeedsApproval
	case blocked:
		return gatewayAuditBlocked
	case requiresRedaction:
		return gatewayAuditRedacted
	default:
		return gatewayAuditAllowed
	}
}

// recordGatewayPreCheckAudit writes the canonical plane=gateway audit_logs
// decision row for a pre-check terminal verdict or early-return deny, IN ADDITION
// to the gateway_contexts satellite (which stays the detailed pre-half record,
// queueGatewayContext). Before #2642 the pre-check persisted ONLY to
// gateway_contexts (approved = !Blocked), which the portal's decisions feed never
// reads — so every redaction collapsed to approved=true (indistinguishable from a
// clean allow) and every early-return deny (kill-switch, circuit-breaker, PII
// block, budget, tenant mismatch, invalid token) wrote no portal-visible row at
// all. This routes the verdict onto the SAME audit_logs surface /api/v1/decide and
// the MCP planes use, keyed by contextID, so the orchestrator GET /api/v1/decisions
// resolves it.
//
// It reuses writeDecisionAuditLog — the DB half of recordDecideDecision — rather
// than recordDecideDecision itself BECAUSE the Gateway handler already emits its
// OTel decision span via the existing tracer path (recordPreCheckDecision and the
// inline tracer call at the main exit); routing through recordDecideDecision would
// double-emit that span. The OTel span's three-valued telemetry verdict
// (allow|deny|needs_approval, verdictFromPreCheck) is a SEPARATE, deliberately
// unchanged contract from this past-tense audit vocabulary.
//
// Fail posture — BEST-EFFORT / fail-open on the WRITE only. The deny verdict is
// ALREADY enforced before this is called (the PEP holds the block; the caller is
// refused regardless of whether the row persists), so a DB hiccup must never turn
// an enforced block into a 500 — writeDecisionAuditLog logs and returns on error.
// This matches every merged canonical writer (#2630 recordDecideDecision /
// writeDecisionAuditLog). Durability for the security-relevant pre-half lives in
// the gateway_contexts satellite, which writes through the retry + fallback-file
// AuditQueue (queueGatewayContext). Net: defense in depth — durable satellite +
// best-effort canonical row — identical to the other planes.
func recordGatewayPreCheckAudit(ctx context.Context, contextID, orgID, tenantID, stage, verdict string, policyIDs, reasons []string, audit decisionAuditInput) {
	audit.plane = PlaneGateway
	// reqContext/contextTruncated are nil/false: the Gateway pre-check does not
	// canonicalize req.Context onto the audit row (that SIEM-join enrichment is a
	// Decision-API feature, #2509). The verdict, policies and reasons are the
	// audit-completeness payload this session guarantees.
	writeDecisionAuditLog(ctx, usageDB, contextID, orgID, tenantID, stage, verdict, policyIDs, reasons, nil, false, audit)
}

// recordPreCheckDecision emits the OTel decision span for an
// early-exit deny path (RBI kill-switch / RBI PII block / budget
// exceeded). Centralised so every short-circuit goes through the same
// attribute mapping; the main exit calls the tracer inline for cheaper
// stack reads. Always-on noop when AXONFLOW_OTEL_ENDPOINT is unset.
func recordPreCheckDecision(ctx context.Context, contextID, orgID, tenantID, stage string, blockReason string, policyIDs []string, latencyMs int64) string {
	// Non-repudiation (#2732): sign + chain this early-return deny (kill-switch /
	// Indonesia-PII / RBI-PII / budget) into decision_chain. First, before the
	// OTel nil-check, so the signed record is written even when no OTel endpoint
	// is configured. Best-effort + off the hot path. "blocked" maps to a signed
	// DecisionOutcomeBlocked.
	recordSignedDecision(ctx, contextID, orgID, tenantID, stage, "blocked", policyIDs, []string{blockReason}, latencyMs)

	if decisionTracerProvider == nil {
		return ""
	}
	return decisionTracerProvider.Tracer.RecordDecision(ctx, telemetry.DecisionEvent{
		DecisionID: contextID,
		OrgID:      orgID,
		TenantID:   tenantID,
		Stage:      stage,
		Verdict:    "deny",
		PolicyIDs:  policyIDs,
		LatencyMs:  latencyMs,
		Reasons:    []string{blockReason},
	})
}

// decisionStageForPreCheck infers the decision-mode stage for a Gateway
// Mode pre-check call. Pre-check fires before the LLM/tool invocation,
// so the stage is the one the *caller* is about to hit. A non-empty
// data_sources list is the strongest signal a tool/connector call is
// next; otherwise this is an LLM-mediated request. Keep this aligned
// with Session 25-A's classification when the Decision API lands.
func decisionStageForPreCheck(req PreCheckRequest) string {
	if len(req.DataSources) > 0 {
		return "tool"
	}
	return "llm"
}

// verdictFromPreCheck maps the PreCheckResponse + HITL flag to the
// three-valued verdict enum the DecisionEvent expects.
func verdictFromPreCheck(resp PreCheckResponse, requiresHITL bool) string {
	if requiresHITL {
		return "needs_approval"
	}
	if !resp.Approved {
		return "deny"
	}
	return "allow"
}

// reasonsFromPreCheck collects the human-readable reasons attached to
// a decision so they land in the OTel span's `decision.reasons`
// attribute. Block reason is authoritative for deny/needs_approval;
// triggered policies double as a reason hint for allowed-with-policy
// outcomes (e.g. redaction).
func reasonsFromPreCheck(resp PreCheckResponse, policyResult *StaticPolicyResult) []string {
	var reasons []string
	if resp.BlockReason != "" {
		reasons = append(reasons, resp.BlockReason)
	}
	if policyResult != nil && policyResult.Reason != "" && policyResult.Reason != resp.BlockReason {
		reasons = append(reasons, policyResult.Reason)
	}
	return reasons
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

	// Authentication is handled by apiAuthMiddleware — identity available via context.
	// Use auth-derived client as the canonical identity for audit records.
	// Body client_id is match-only: reject if it doesn't match auth identity.
	authClientID := ClientIDFromContext(r.Context())
	tenantID := TenantIDFromContext(r.Context())

	effectiveClientID := authClientID
	if isCommunityMode() && (authClientID == "" || authClientID == "community") {
		if req.ClientID != "" {
			effectiveClientID = req.ClientID
			tenantID = req.ClientID
		}
	} else if req.ClientID != "" && req.ClientID != authClientID {
		log.Printf("❌ [Audit] Body client_id '%s' does not match auth-derived '%s'",
			logutil.Sanitize(req.ClientID), logutil.Sanitize(authClientID))
		sendGatewayError(w, "client_id mismatch: body client_id does not match authenticated identity", http.StatusForbidden)
		return
	}

	// Override req.ClientID with auth-derived identity for downstream use
	req.ClientID = effectiveClientID
	_ = tenantID // used by validateGatewayContext via effectiveClientID

	// Validate context exists and is not expired (if DB available)
	if authDB != nil {
		valid, err := validateGatewayContext(authDB, req.ContextID, effectiveClientID)
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

// shouldPrefetchApprovedData reports whether the pre-check may execute the
// caller's query against connectors and return the rows as approved_data.
// #2867: this is allowed ONLY for a clean-approved request — not blocked, not
// HITL-pending, and with no redaction owed. A blocked request must not run the
// query at all (returning data on a deny leaks what the block withheld); a
// HITL-pending request must not surface connector data before human approval;
// an approved-with-redaction request skips the prefetch so raw PII is never
// returned unredacted.
func shouldPrefetchApprovedData(blocked, requiresHITL, requiresRedaction bool) bool {
	return !blocked && !requiresHITL && !requiresRedaction
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

	// Read-only enforcement posture (#2720, epic #2716). The pre-check data fetch
	// runs the caller-supplied `query` through connector.Query, which SQL
	// connectors execute verbatim, so a write DML (or a stacked statement) here
	// would mutate under MCP_READ_ONLY. Classify the statement and refuse the
	// fetch before any connector.Query, fail-closed on an unclassifiable
	// statement. Non-overridable; best-effort canonical "blocked" audit row.
	if readOnlyPostureEnabled() && statementIsWritePath(query) {
		reason := "read-only posture active: write-path pre-check query is blocked; only read-path operations are permitted"
		writeMCPDecisionAudit(ctx, usageDB,
			uuid.New().String(), "",
			user.TenantID, user.OrgID, client.ID, user.Email,
			fmt.Sprintf("%d", user.ID), user.Role,
			"policy_precheck_query", "policy pre-check data fetch", "",
			mcpVerdictBlocked,
			[]string{readOnlyPosturePolicyID},
			[]string{reason},
			nil, "")
		return nil, fmt.Errorf("%s", reason)
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

		// Get connector from registry, scoped to the authenticated user's
		// tenant (#3067 S-1). A pre-check that named another tenant's data
		// source previously resolved it and prefetched rows with the victim's
		// decrypted credentials.
		connector, err := mcpRegistry.Get(user.TenantID, source)
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
			// Read-only posture (#2720, epic #2716): the statement-verb gate above
			// already refuses classified writes; ReadOnly adds FU-4's (#2735)
			// database-enforced backstop (Postgres BEGIN READ ONLY) so a write the
			// parser misses is rejected by the DB at SQLSTATE 25006.
			ReadOnly: readOnlyPostureEnabled(),
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

// validateGatewayContext checks if context exists and is not expired.
//
// #2642 sibling finding #4: this deliberately SELECTs only client_id + expires_at,
// NOT gateway_contexts.approved / block_reason. That is intentional, not a missed
// read. validateGatewayContext gates the SECOND gateway step (POST /api/audit/llm-call)
// purely on identity binding (the same client that pre-checked) + expiry — it is a
// replay/binding guard, not a re-adjudication of the verdict. The authoritative,
// portal-visible decision record is now the canonical plane=gateway audit_logs row
// written by recordGatewayPreCheckAudit at pre-check time; gateway_contexts.approved
// remains as satellite detail for forensic joins. Re-deriving block from
// `approved` here would also be wrong: a pre-check that returned approved=false
// (blocked/HITL) never proceeds to the audit step anyway, so there is no second
// request to gate. Wiring the column would change behavior with no decision it
// could correctly make — hence documented-as-superseded rather than read.
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

// RegisterGatewayHandlers registers the gateway mode endpoints.
// Both endpoints are wrapped with apiAuthMiddleware so auth is handled
// centrally — handlers read identity from context via TenantIDFromContext() etc.
func RegisterGatewayHandlers(r *mux.Router) {
	r.Handle("/api/policy/pre-check", apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck))).Methods("POST")
	r.Handle("/api/audit/llm-call", apiAuthMiddleware(http.HandlerFunc(handleAuditLLMCall))).Methods("POST")
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

// convertSharedResultToStatic moved to policy_result_convert.go. The old
// agent-local isPIICategory switch was deleted in #2965 — PII classification now
// converges on the shared sharedpolicy.IsPIIPolicyCategory prefix predicate.

// NOTE: checkHITLRequiredFromContext was REMOVED in Issue #1081 code review.
// HITL enforcement is an ENTERPRISE-ONLY feature.
// HITL is ONLY triggered by policy evaluation returning require_approval action.
// We do NOT trust client-provided context metadata (requires_hitl, eu_ai_act_article_14, etc.)
// as that would allow:
// 1. Any client to bypass licensing (HITL is Enterprise-only)
// 2. DoS attacks by clients setting HITL flags on all requests
// 3. Security bypass by untrusted input controlling enforcement behavior
