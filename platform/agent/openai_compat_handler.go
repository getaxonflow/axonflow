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

// OpenAI-compatible gateway endpoint (Issue #2351, child of Epic #2360).
//
// POST /v1/chat/completions accepts a standard OpenAI Chat Completions
// request, runs AxonFlow policy checks via the shared policy engine
// (same as Gateway Mode + Decision Mode), forwards to the upstream
// provider, records audit, and returns an OpenAI-compatible response.
//
// The value proposition: baseURL: "http://axonflow:8080/v1" — that's
// the only line the customer changes in their OpenAI SDK setup.
//
// M1 scope: non-streaming chat completions only. stream:true returns a
// clear 400 error. Provider key supplied via X-Provider-Key header.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	openaiCompatPath = "/v1/chat/completions"
)

// OpenAI-compatible request/response types. These mirror the OpenAI Chat
// Completions API wire format so standard OpenAI SDKs parse them without
// modification.

type chatCompletionRequest struct {
	Model               string                  `json:"model"`
	Messages            []chatCompletionMessage `json:"messages"`
	Temperature         *float64                `json:"temperature,omitempty"`
	TopP                *float64                `json:"top_p,omitempty"`
	N                   *int                    `json:"n,omitempty"`
	Stream              *bool                   `json:"stream,omitempty"`
	Stop                interface{}             `json:"stop,omitempty"`
	MaxTokens           *int                    `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int                    `json:"max_completion_tokens,omitempty"`
	PresencePenalty     *float64                `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64                `json:"frequency_penalty,omitempty"`
	User                string                  `json:"user,omitempty"`
	ResponseFormat      interface{}             `json:"response_format,omitempty"`
	Seed                *int                    `json:"seed,omitempty"`
	Tools               interface{}             `json:"tools,omitempty"`
	ToolChoice          interface{}             `json:"tool_choice,omitempty"`
}

type chatCompletionMessage struct {
	Role       string      `json:"role"`
	Content    interface{} `json:"content"`
	Name       string      `json:"name,omitempty"`
	ToolCalls  interface{} `json:"tool_calls,omitempty"`
	ToolCallID string      `json:"tool_call_id,omitempty"`
}

type chatCompletionResponse struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	Model             string                 `json:"model"`
	Choices           []chatCompletionChoice `json:"choices"`
	Usage             *chatCompletionUsage   `json:"usage,omitempty"`
	SystemFingerprint string                 `json:"system_fingerprint,omitempty"`
}

type chatCompletionChoice struct {
	Index        int                         `json:"index"`
	Message      chatCompletionChoiceMessage `json:"message"`
	FinishReason *string                     `json:"finish_reason"`
}

type chatCompletionChoiceMessage struct {
	Role      string      `json:"role"`
	Content   *string     `json:"content"`
	ToolCalls interface{} `json:"tool_calls,omitempty"`
}

type chatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIErrorResponse struct {
	Error openAIErrorBody `json:"error"`
}

type openAIErrorBody struct {
	Message string  `json:"message"`
	Type    string  `json:"type"`
	Param   *string `json:"param"`
	Code    string  `json:"code"`
}

// Prometheus metrics for the OpenAI-compat endpoint.
var (
	openaiCompatRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_openai_compat_requests_total",
			Help: "Total POST /v1/chat/completions requests by status",
		},
		[]string{"status"},
	)
	openaiCompatDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "axonflow_openai_compat_duration_milliseconds",
			Help:    "POST /v1/chat/completions handler duration (ms)",
			Buckets: []float64{10, 50, 100, 200, 500, 1000, 2000, 5000, 10000},
		},
	)
	openaiCompatTokens = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_openai_compat_tokens_total",
			Help: "Tokens processed via /v1/chat/completions",
		},
		[]string{"type", "model"},
	)
)

func init() {
	_ = prometheus.Register(openaiCompatRequests)
	_ = prometheus.Register(openaiCompatDuration)
	_ = prometheus.Register(openaiCompatTokens)
}

// providerEndpoints maps model prefixes to upstream provider base URLs.
// M1 routes to OpenAI only; M3 adds Anthropic/Gemini/Bedrock.
var providerEndpoints = map[string]string{
	"gpt-":     "https://api.openai.com",
	"o1":       "https://api.openai.com",
	"o3":       "https://api.openai.com",
	"o4":       "https://api.openai.com",
	"chatgpt-": "https://api.openai.com",
}

// openaiCompatPolicyCategories is the category whitelist evaluated for
// /openai/v1/* requests. #2965: the PII portion is sourced from the single
// canonical sharedpolicy.AllTextPIICategories() so pii-indonesia (KTP/NIK) is
// evaluated on this plane — the previous hand-listed set omitted it, filtering
// the KTP policy out before evaluation and leaving Indonesian PII ungoverned.
var openaiCompatPolicyCategories = append([]sharedpolicy.PolicyCategory{
	sharedpolicy.CategorySecuritySQLi,
	sharedpolicy.CategorySecurityDangerous,
	sharedpolicy.CategorySensitiveData,
	sharedpolicy.CategoryComplianceRBI,
	sharedpolicy.CategoryComplianceSEBI,
	sharedpolicy.CategoryComplianceEUAIAct,
	sharedpolicy.CategoryComplianceMASFEAT,
}, sharedpolicy.AllTextPIICategories()...)

// resolveProviderBaseURL determines the upstream provider from the model name.
func resolveProviderBaseURL(model string) (baseURL string, provider string, ok bool) {
	lower := strings.ToLower(model)
	for prefix, url := range providerEndpoints {
		if strings.HasPrefix(lower, prefix) {
			return url, "openai", true
		}
	}
	// Default to OpenAI for unknown models in M1. The upstream will
	// return a model-not-found error if the model doesn't exist.
	return "https://api.openai.com", "openai", true
}

// extractTextFromMessages concatenates message content for policy evaluation.
func extractTextFromMessages(messages []chatCompletionMessage) string {
	var parts []string
	for _, msg := range messages {
		switch v := msg.Content.(type) {
		case string:
			parts = append(parts, v)
		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					if text, exists := m["text"]; exists {
						if s, ok := text.(string); ok {
							parts = append(parts, s)
						}
					}
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

// handleOpenAICompat handles POST /v1/chat/completions.
//
// Flow:
//  1. Parse + validate OpenAI-shaped request
//  2. Reject stream:true (M1 scope)
//  3. Validate X-Provider-Key header
//  4. Run shared policy engine (same as Decision Mode + Gateway Mode)
//  5. Forward to upstream provider
//  6. Record audit (tokens, cost, latency, policy decision)
//  7. Emit OTel span via RecordDecision
//  8. Return OpenAI-compatible response
func handleOpenAICompat(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Read the request body so we can both parse it and forward it.
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 10<<20)) // 10MB limit
	if err != nil {
		openaiCompatRequests.WithLabelValues("error").Inc()
		sendOpenAIError(w, "Failed to read request body", "invalid_request_error", "", http.StatusBadRequest)
		return
	}

	var req chatCompletionRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		openaiCompatRequests.WithLabelValues("error").Inc()
		log.Printf("[OpenAI-Compat] JSON parse error: %v", err)
		sendOpenAIError(w, "Invalid JSON request body", "invalid_request_error", "", http.StatusBadRequest)
		return
	}

	// Reject streaming (M1 scope).
	if req.Stream != nil && *req.Stream {
		openaiCompatRequests.WithLabelValues("error").Inc()
		sendOpenAIError(w, "Streaming is not supported in this release. Remove stream: true.", "invalid_request_error", "stream_not_supported", http.StatusBadRequest)
		return
	}

	// Validate required fields.
	if req.Model == "" {
		openaiCompatRequests.WithLabelValues("error").Inc()
		sendOpenAIError(w, "model is required", "invalid_request_error", "missing_model", http.StatusBadRequest)
		return
	}
	if len(req.Messages) == 0 {
		openaiCompatRequests.WithLabelValues("error").Inc()
		sendOpenAIError(w, "messages is required and must be a non-empty array", "invalid_request_error", "missing_messages", http.StatusBadRequest)
		return
	}

	// Provider key from X-Provider-Key header (M1 scope — no vault).
	providerKey := r.Header.Get("X-Provider-Key")
	if providerKey == "" {
		openaiCompatRequests.WithLabelValues("error").Inc()
		sendOpenAIError(w, "X-Provider-Key header is required. Pass your upstream provider API key in this header.", "invalid_request_error", "missing_provider_key", http.StatusBadRequest)
		return
	}

	// Auth-derived identity from apiAuthMiddleware.
	tenantID := TenantIDFromContext(r.Context())
	orgID := OrgIDFromContext(r.Context())
	clientID := ClientIDFromContext(r.Context())
	authKind := AuthKindFromContext(r.Context())
	ctx := r.Context()

	// Generate decision ID + trace ID for audit correlation. Hoisted ABOVE user
	// resolution (#2686) so the auth-failure early-deny below writes a canonical
	// audit_logs row keyed by the same decision_id. correlationID is the inbound
	// traceparent's trace-id (or "" → singleton chain), NOT the minted id.
	correlationID := traceIDFromHeader(r.Header.Get("traceparent"))
	decisionID := uuid.New().String()
	traceID := correlationID
	if traceID == "" {
		traceID = newW3CTraceID()
	}

	// Resolve user (mirrors Decision Mode pattern).
	client := &Client{
		ID:       clientID,
		ClientID: clientID,
		Name:     clientID,
		OrgID:    orgID,
		TenantID: tenantID,
		Enabled:  true,
	}
	authResult := &AuthResult{Kind: authKind, TenantID: tenantID, OrgID: orgID, ClientID: clientID, Client: client}
	user, userErr := ResolveUser(authResult, "")
	if userErr != nil {
		if authKind == AuthKindEnterprise {
			user = &User{
				ID:       0,
				Email:    clientID + "@axonflow.local",
				Name:     clientID,
				TenantID: tenantID,
				OrgID:    orgID,
				Role:     "service",
			}
		} else {
			// #2686: an auth-failure here is a terminal refusal that must leave a
			// canonical audit_logs row, mirroring the gateway pre-check refusal
			// (gateway_handlers.go). Identity is auth-derived from context (never a
			// caller-claimed body value); the reason is a FIXED label — no token
			// material lands on the row.
			recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictDeny,
				[]string{"authentication_error"}, time.Since(startTime).Milliseconds(),
				[]string{"authentication failed"}, traceID, nil, false,
				&decisionAuditInput{clientID: clientID, plane: PlaneOpenAICompat, correlationID: correlationID})
			openaiCompatRequests.WithLabelValues("error").Inc()
			sendOpenAIError(w, userErr.Message, "authentication_error", "", userErr.HTTPStatus)
			return
		}
	}

	// Set AxonFlow headers on response (always, even on deny).
	w.Header().Set("X-AxonFlow-Decision-Id", decisionID)
	w.Header().Set("X-AxonFlow-Trace-Id", traceID)

	// Policy evaluation via the shared policy engine.
	queryText := extractTextFromMessages(req.Messages)
	// #2581: resolve per-org posture (org with no override → deployment-global).
	gwDetectionCfg := ResolveGatewayDetectionConfig(ctx, orgID)

	var policyResult *StaticPolicyResult
	var blockingPolicyID string
	sharedEngine := sharedpolicy.GetGlobalEngine()

	if !gwDetectionCfg.Enabled {
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"gateway_static_policies_disabled"},
		}
	} else if sharedEngine != nil {
		requestResult := sharedEngine.EvaluateRequest(ctx, queryText, sharedpolicy.EvalOptions{
			TenantID: user.TenantID,
			OrgID:    user.OrgID,
			// #3048 R3 HIGH-3: scope the loader's tenant pass by the
			// validated caller org (org_id may differ from tenant_id).
			OrganizationID:  sharedpolicy.OrgScopePtr(user.OrgID),
			ConnectorName:   "openai_compat",
			UserID:          fmt.Sprintf("%d", user.ID),
			Categories:      openaiCompatPolicyCategories,
			SkipCategories:  gwDetectionCfg.SkipCategories,
			ActionOverrides: gwDetectionCfg.BuildActionOverrides(),
		})
		policyResult = convertSharedResultToStatic(requestResult)
		if requestResult != nil && requestResult.BlockedBy != nil {
			blockingPolicyID = requestResult.BlockedBy.PolicyID
		}
	} else {
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"no_policy_engine"},
		}
	}

	// On policy deny, return an OpenAI-compatible error.
	if policyResult.Blocked {
		policyIDs := policyResult.TriggeredPolicies
		if policyIDs == nil {
			policyIDs = []string{}
		}
		if blockingPolicyID != "" {
			policyIDs = hoistBlockingPolicy(policyIDs, blockingPolicyID)
		}

		reasons := []string{}
		if policyResult.Reason != "" {
			reasons = append(reasons, policyResult.Reason)
		}

		// #2686: the policy DENY must write a canonical audit_logs row — the portal
		// /decisions feed, /explain, the audit summary, and the SEBI/EU-AI-Act
		// exporters all read audit_logs, so a SQLi/PII/compliance block here was
		// invisible while ONLY the llm_call_audits satellite (recordOpenAICompatAudit
		// below) was written. Pass a non-nil decisionAuditInput (plane=openai_compat)
		// — the #2642 gateway / #2682 connector-exec pattern. The llm_call_audits row
		// is a DIFFERENT table; the two are complementary, not a double-write.
		auditInput := &decisionAuditInput{
			clientID:      clientID,
			userEmail:     user.Email,
			userRole:      user.Role,
			userID:        user.ID,
			query:         queryText,
			plane:         PlaneOpenAICompat,
			correlationID: correlationID,
		}
		traceID = recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictDeny, policyIDs, time.Since(startTime).Milliseconds(), reasons, traceID, nil, false, auditInput)
		w.Header().Set("X-AxonFlow-Trace-Id", traceID)

		// Record audit for the denied request.
		recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, "openai", req.Model, 0, 0, 0, 0, time.Since(startTime).Milliseconds(), VerdictDeny, blockingPolicyID)

		// Circuit breaker violation recording.
		if circuitBreakerInstance != nil && blockingPolicyID != "" {
			if err := circuitBreakerInstance.RecordPolicyViolation(ctx, orgID, tenantID, clientID, blockingPolicyID); err != nil {
				log.Printf("⚠️ [OpenAI-Compat] Circuit breaker RecordPolicyViolation error: %v", err)
			}
		}

		openaiCompatRequests.WithLabelValues("denied").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))

		sendOpenAIError(w, fmt.Sprintf("Request blocked by policy: %s", policyResult.Reason), "policy_violation", "policy_denied", http.StatusBadRequest)
		return
	}

	// Resolve upstream provider.
	providerBaseURL, providerName, _ := resolveProviderBaseURL(req.Model)

	// Forward the request to the upstream provider.
	upstreamURL := providerBaseURL + "/v1/chat/completions"
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(bodyBytes))
	if err != nil {
		openaiCompatRequests.WithLabelValues("error").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))
		sendOpenAIError(w, "Failed to create upstream request", "server_error", "", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header.Set("Content-Type", "application/json")
	upstreamReq.Header.Set("Authorization", "Bearer "+providerKey)

	providerStart := time.Now()
	httpClient := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	upstreamResp, err := httpClient.Do(upstreamReq)
	providerLatencyMs := time.Since(providerStart).Milliseconds()
	if err != nil {
		openaiCompatRequests.WithLabelValues("error").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))

		_ = recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictAllow, policyResult.TriggeredPolicies, time.Since(startTime).Milliseconds(), []string{}, traceID, nil, false, nil)
		recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, providerName, req.Model, 0, 0, 0, 0, providerLatencyMs, VerdictAllow, "")

		log.Printf("[OpenAI-Compat] upstream request error: %v", err)
		sendOpenAIError(w, "Upstream provider request failed", "server_error", "", http.StatusBadGateway)
		return
	}
	defer upstreamResp.Body.Close()

	// Read the upstream response body.
	upstreamBody, err := io.ReadAll(io.LimitReader(upstreamResp.Body, 10<<20)) // 10MB limit
	if err != nil {
		openaiCompatRequests.WithLabelValues("error").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))
		sendOpenAIError(w, "Failed to read upstream response", "server_error", "", http.StatusBadGateway)
		return
	}

	// If upstream returned a non-2xx status, forward the error as-is.
	if upstreamResp.StatusCode < 200 || upstreamResp.StatusCode >= 300 {
		openaiCompatRequests.WithLabelValues("upstream_error").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))

		_ = recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictAllow, policyResult.TriggeredPolicies, time.Since(startTime).Milliseconds(), []string{}, traceID, nil, false, nil)
		recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, providerName, req.Model, 0, 0, 0, 0, providerLatencyMs, VerdictAllow, "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(upstreamResp.StatusCode)
		_, _ = w.Write(upstreamBody)
		return
	}

	// Parse the upstream response to extract usage for audit.
	var completionResp chatCompletionResponse
	if err := json.Unmarshal(upstreamBody, &completionResp); err != nil {
		// Can't parse response — still return it to the client untouched.
		openaiCompatRequests.WithLabelValues("success").Inc()
		openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))

		_ = recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictAllow, policyResult.TriggeredPolicies, time.Since(startTime).Milliseconds(), []string{}, traceID, nil, false, nil)
		recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, providerName, req.Model, 0, 0, 0, 0, providerLatencyMs, VerdictAllow, "")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
		return
	}

	// Extract usage stats.
	var promptTokens, completionTokens, totalTokens int
	if completionResp.Usage != nil {
		promptTokens = completionResp.Usage.PromptTokens
		completionTokens = completionResp.Usage.CompletionTokens
		totalTokens = completionResp.Usage.TotalTokens
	}

	// Calculate cost.
	estimatedCost := calculateLLMCost(providerName, req.Model, TokenUsage{
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      totalTokens,
	})

	// Record OTel decision span.
	evaluatedPolicies := policyResult.TriggeredPolicies
	if evaluatedPolicies == nil {
		evaluatedPolicies = []string{}
	}
	traceID = recordDecideDecision(ctx, decisionID, orgID, tenantID, DecisionStageLLM, VerdictAllow, evaluatedPolicies, time.Since(startTime).Milliseconds(), []string{}, traceID, nil, false, nil)
	w.Header().Set("X-AxonFlow-Trace-Id", traceID)

	// Record audit.
	recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, providerName, req.Model, promptTokens, completionTokens, totalTokens, estimatedCost, providerLatencyMs, VerdictAllow, "")

	// Record Prometheus token metrics. Use the provider-returned model name
	// (bounded set) rather than user input to prevent label cardinality explosion.
	metricsModel := completionResp.Model
	if metricsModel == "" {
		metricsModel = req.Model
	}
	if totalTokens > 0 {
		openaiCompatTokens.WithLabelValues("prompt", metricsModel).Add(float64(promptTokens))
		openaiCompatTokens.WithLabelValues("completion", metricsModel).Add(float64(completionTokens))
	}

	openaiCompatRequests.WithLabelValues("success").Inc()
	openaiCompatDuration.Observe(float64(time.Since(startTime).Milliseconds()))

	// Return the upstream response to the client.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(upstreamBody)
}

// recordOpenAICompatAudit records the LLM call audit directly into the
// llm_call_audits table. Uses a direct INSERT rather than the gateway
// audit queue because the OpenAI-compat endpoint has no gateway_contexts
// row (context_id has a FK to gateway_contexts — passing a non-NULL
// context_id that doesn't exist in that table violates the constraint).
func recordOpenAICompatAudit(decisionID, clientID, orgID, tenantID, provider, model string, promptTokens, completionTokens, totalTokens int, estimatedCost float64, latencyMs int64, verdict, blockingPolicy string) {
	if authDB == nil {
		return
	}

	metadata := map[string]interface{}{
		"source":          "openai_compat",
		"decision_id":     decisionID,
		"org_id":          orgID,
		"tenant_id":       tenantID,
		"verdict":         verdict,
		"blocking_policy": blockingPolicy,
	}
	metadataJSON, _ := json.Marshal(metadata)

	_, err := authDB.Exec(`
		INSERT INTO llm_call_audits (
			audit_id, context_id, client_id, provider, model,
			prompt_tokens, completion_tokens, total_tokens,
			latency_ms, estimated_cost_usd, metadata, org_id
		) VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`, decisionID, clientID, provider, model,
		promptTokens, completionTokens, totalTokens,
		latencyMs, estimatedCost, metadataJSON, orgID)

	if err != nil {
		log.Printf("⚠️ [OpenAI-Compat] Audit recording failed (non-fatal): %v", err)
	}
}

// sendOpenAIError writes an OpenAI-compatible error response that the
// OpenAI SDK parses as openai.BadRequestError / openai.AuthenticationError.
func sendOpenAIError(w http.ResponseWriter, message, errorType, code string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := openAIErrorResponse{
		Error: openAIErrorBody{
			Message: message,
			Type:    errorType,
			Code:    code,
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// RegisterOpenAICompatHandlers registers the OpenAI-compatible gateway endpoint.
func RegisterOpenAICompatHandlers(r *mux.Router) {
	r.Handle(openaiCompatPath, apiAuthMiddleware(http.HandlerFunc(handleOpenAICompat))).Methods("POST", "OPTIONS")
	log.Printf("✅ OpenAI-compatible gateway endpoint registered: POST %s", openaiCompatPath)
}
