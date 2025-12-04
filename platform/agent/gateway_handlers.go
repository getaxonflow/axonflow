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

package main

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
	"time"

	"axonflow/platform/connectors/base"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus"
)

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

func init() {
	// Register gateway Prometheus metrics
	prometheus.MustRegister(gatewayPreCheckRequests)
	prometheus.MustRegister(gatewayAuditRequests)
	prometheus.MustRegister(gatewayPreCheckDuration)
	prometheus.MustRegister(gatewayAuditDuration)
	prometheus.MustRegister(gatewayLLMTokensTotal)
	prometheus.MustRegister(gatewayLLMCostTotal)
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
	ContextID    string                 `json:"context_id"`
	Approved     bool                   `json:"approved"`
	ApprovedData map[string]interface{} `json:"approved_data,omitempty"`
	Policies     []string               `json:"policies"`
	RateLimit    *RateLimitInfo         `json:"rate_limit,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`
	BlockReason  string                 `json:"block_reason,omitempty"`
}

// RateLimitInfo provides rate limiting status to SDK
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
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

	// Validate license key from header
	licenseKey := r.Header.Get("X-License-Key")
	if licenseKey == "" && os.Getenv("SELF_HOSTED_MODE") != "true" {
		log.Printf("❌ [Pre-check] Missing X-License-Key header")
		sendGatewayError(w, "X-License-Key header required", http.StatusUnauthorized)
		return
	}

	// Validate client
	var client *Client
	var err error
	ctx := r.Context()

	if os.Getenv("SELF_HOSTED_MODE") == "true" {
		client = &Client{
			ID:          req.ClientID,
			Name:        "Self-Hosted",
			OrgID:       "self-hosted",
			TenantID:    req.ClientID,
			Enabled:     true,
			LicenseTier: "OSS",
		}
	} else if authDB != nil {
		client, err = validateClientLicenseDB(ctx, authDB, req.ClientID, licenseKey)
	} else {
		client, err = validateClientLicense(ctx, req.ClientID, licenseKey)
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

	// Evaluate policies (reuse existing policy engine)
	var policyResult *StaticPolicyResult
	if dbPolicyEngine != nil {
		policyResult = dbPolicyEngine.EvaluateStaticPolicies(user, req.Query, "llm_chat")
	} else if staticPolicyEngine != nil {
		policyResult = staticPolicyEngine.EvaluateStaticPolicies(user, req.Query, "llm_chat")
	} else {
		// No policy engine available - allow by default
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"no_policy_engine"},
		}
	}

	// Generate context ID
	contextID := uuid.New().String()
	expiresAt := time.Now().Add(defaultContextExpiry)

	// Build response
	response := PreCheckResponse{
		ContextID: contextID,
		Approved:  !policyResult.Blocked,
		Policies:  policyResult.TriggeredPolicies,
		ExpiresAt: expiresAt,
	}

	if policyResult.Blocked {
		response.BlockReason = policyResult.Reason
		log.Printf("⛔ [Pre-check] Request blocked: %s", policyResult.Reason)
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

	// Store context in database for audit linking
	if authDB != nil {
		if err := storeGatewayContext(authDB, contextID, client.ID, req, policyResult, expiresAt); err != nil {
			log.Printf("⚠️ [Pre-check] Failed to store context: %v (continuing)", err)
		}
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

	// Validate license key
	licenseKey := r.Header.Get("X-License-Key")
	if licenseKey == "" && os.Getenv("SELF_HOSTED_MODE") != "true" {
		sendGatewayError(w, "X-License-Key header required", http.StatusUnauthorized)
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

	// Store audit record
	if authDB != nil {
		if err := storeLLMCallAudit(authDB, auditID, req, estimatedCost); err != nil {
			log.Printf("❌ [Audit] Failed to store audit: %v", err)
			sendGatewayError(w, "Failed to store audit", http.StatusInternalServerError)
			return
		}
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
	json.NewEncoder(w).Encode(map[string]interface{}{
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
