// Package axonflow provides an enterprise-grade Go SDK for the AxonFlow AI governance platform.
// It enables invisible AI governance with production-ready features including retry logic,
// caching, fail-open strategy, and debug mode.
package axonflow

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AxonFlowConfig represents configuration for the AxonFlow client
type AxonFlowConfig struct {
	Endpoint     string        // Required: AxonFlow endpoint URL (Agent proxies all routes since ADR-026)
	ClientID     string        // Optional: Client ID (required for enterprise features)
	ClientSecret string        // Optional: Client secret (required for enterprise features)
	LicenseKey   string        // Optional: License key (alternative to ClientID/ClientSecret)
	Mode         string        // "production" | "sandbox" (default: "production")
	Debug        bool          // Enable debug logging (default: false)
	Timeout      time.Duration // Request timeout (default: 60s)
	MapTimeout   time.Duration // Timeout for MAP operations (default: 120s) - MAP involves multiple LLM calls
	Retry        RetryConfig   // Retry configuration
	Cache        CacheConfig   // Cache configuration
}

// RetryConfig configures retry behavior
type RetryConfig struct {
	Enabled      bool          // Enable retry logic (default: true)
	MaxAttempts  int           // Maximum retry attempts (default: 3)
	InitialDelay time.Duration // Initial delay between retries (default: 1s)
}

// CacheConfig configures caching behavior
type CacheConfig struct {
	Enabled bool          // Enable caching (default: true)
	TTL     time.Duration // Cache TTL (default: 60s)
}

// AxonFlowClient represents the SDK for connecting to AxonFlow platform
type AxonFlowClient struct {
	config        AxonFlowConfig
	httpClient    *http.Client
	mapHttpClient *http.Client // Separate client with longer timeout for MAP operations
	cache         *cache
	sessionCookie string // Session cookie for Customer Portal authentication
}

// ============================================================================
// Portal Authentication Types
// ============================================================================

// PortalLoginRequest represents a login request to the Customer Portal
type PortalLoginRequest struct {
	OrgID    string `json:"org_id"`
	Password string `json:"password"`
}

// PortalLoginResponse represents a login response from the Customer Portal
type PortalLoginResponse struct {
	SessionID string `json:"session_id"`
	OrgID     string `json:"org_id"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	ExpiresAt string `json:"expires_at"`
}

// ClientRequest represents a request to AxonFlow Agent
type ClientRequest struct {
	Query       string                 `json:"query"`
	UserToken   string                 `json:"user_token"`
	ClientID    string                 `json:"client_id"`
	RequestType string                 `json:"request_type"` // "multi-agent-plan", "sql", "chat", "mcp-query"
	Context     map[string]interface{} `json:"context"`
}

// ClientResponse represents response from AxonFlow Agent
type ClientResponse struct {
	Success     bool                   `json:"success"`
	Data        interface{}            `json:"data,omitempty"`
	Result      string                 `json:"result,omitempty"`     // For multi-agent planning
	PlanID      string                 `json:"plan_id,omitempty"`    // For multi-agent planning
	RequestID   string                 `json:"request_id,omitempty"` // Unique request identifier
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Blocked     bool                   `json:"blocked"`
	BlockReason string                 `json:"block_reason,omitempty"`
	PolicyInfo  *PolicyEvaluationInfo  `json:"policy_info,omitempty"`
}

// PolicyEvaluationInfo contains policy evaluation metadata
type PolicyEvaluationInfo struct {
	PoliciesEvaluated []string      `json:"policies_evaluated"`
	StaticChecks      []string      `json:"static_checks"`
	ProcessingTime    string        `json:"processing_time"` // Processing time as duration string (e.g., "17.48s")
	TenantID          string        `json:"tenant_id"`
	CodeArtifact      *CodeArtifact `json:"code_artifact,omitempty"` // Code artifact metadata if code detected
}

// CodeArtifact represents metadata for LLM-generated code detection
type CodeArtifact struct {
	IsCodeOutput    bool     `json:"is_code_output"`   // Whether response contains code
	Language        string   `json:"language"`         // Detected programming language
	CodeType        string   `json:"code_type"`        // Code category (function, class, script, etc.)
	SizeBytes       int      `json:"size_bytes"`       // Size of detected code in bytes
	LineCount       int      `json:"line_count"`       // Number of lines of code
	SecretsDetected int      `json:"secrets_detected"` // Count of potential secrets found
	UnsafePatterns  int      `json:"unsafe_patterns"`  // Count of unsafe code patterns
	PoliciesChecked []string `json:"policies_checked"` // Code governance policies evaluated
}

// ConnectorMetadata represents information about an MCP connector
type ConnectorMetadata struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Version      string                 `json:"version"`
	Description  string                 `json:"description"`
	Category     string                 `json:"category"`
	Icon         string                 `json:"icon"`
	Tags         []string               `json:"tags"`
	Capabilities []string               `json:"capabilities"`
	ConfigSchema map[string]interface{} `json:"config_schema"`
	Installed    bool                   `json:"installed"`
	InstanceName string                 `json:"instance_name,omitempty"` // Name of installed instance
	Healthy      bool                   `json:"healthy,omitempty"`
	LastCheck    string                 `json:"last_check,omitempty"` // When last health check was performed
}

// ConnectorHealthStatus represents the health status of an installed connector
type ConnectorHealthStatus struct {
	Healthy   bool              `json:"healthy"`   // Overall health status
	Latency   int64             `json:"latency"`   // Connection latency in nanoseconds
	Details   map[string]string `json:"details"`   // Additional diagnostic info
	Timestamp string            `json:"timestamp"` // When health check was performed
	Error     string            `json:"error"`     // Error message if unhealthy
}

// ConnectorInstallRequest represents a request to install an MCP connector
type ConnectorInstallRequest struct {
	ConnectorID string                 `json:"connector_id"`
	Name        string                 `json:"name"`
	TenantID    string                 `json:"tenant_id"`
	Options     map[string]interface{} `json:"options"`
	Credentials map[string]string      `json:"credentials"`
}

// ConnectorResponse represents response from an MCP connector query
type ConnectorResponse struct {
	Success bool                   `json:"success"`
	Data    interface{}            `json:"data"`
	Error   string                 `json:"error,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// PlanResponse represents a multi-agent plan generation response
type PlanResponse struct {
	PlanID            string                 `json:"plan_id"`
	Steps             []PlanStep             `json:"steps"`
	Domain            string                 `json:"domain"`
	Complexity        int                    `json:"complexity"`         // Complexity score (1-10)
	Parallel          bool                   `json:"parallel"`           // Whether steps can run in parallel
	EstimatedDuration string                 `json:"estimated_duration"` // Estimated execution time
	Metadata          map[string]interface{} `json:"metadata"`
}

// PlanStep represents a single step in a multi-agent plan
type PlanStep struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Description   string                 `json:"description"`
	Dependencies  []string               `json:"dependencies"` // IDs of steps this depends on
	Agent         string                 `json:"agent"`        // Agent responsible for execution
	Parameters    map[string]interface{} `json:"parameters"`
	EstimatedTime string                 `json:"estimated_time"` // Estimated execution time for this step
}

// ============================================================================
// Gateway Mode Types
// ============================================================================

// TokenUsage represents token usage information for audit logging
type TokenUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// RateLimitInfo represents rate limit information returned from pre-check
type RateLimitInfo struct {
	Limit     int       `json:"limit"`
	Remaining int       `json:"remaining"`
	ResetAt   time.Time `json:"reset_at"`
}

// PolicyApprovalResult represents the result from policy pre-check in Gateway Mode
type PolicyApprovalResult struct {
	// ContextID is a unique ID for correlating pre-check with audit
	ContextID string `json:"context_id"`
	// Approved indicates whether the request was approved
	Approved bool `json:"approved"`
	// RequiresRedaction indicates whether response requires redaction (PII detected with redact action)
	RequiresRedaction bool `json:"requires_redaction,omitempty"`
	// ApprovedData contains filtered/approved data to send to LLM
	ApprovedData map[string]interface{} `json:"approved_data"`
	// Policies lists the policies that were evaluated
	Policies []string `json:"policies"`
	// RateLimitInfo contains rate limit information (if applicable)
	RateLimitInfo *RateLimitInfo `json:"rate_limit_info,omitempty"`
	// ExpiresAt indicates when this approval expires
	ExpiresAt time.Time `json:"expires_at"`
	// BlockReason contains the reason for blocking (if not approved)
	BlockReason string `json:"block_reason,omitempty"`
}

// AuditResult represents the result from audit logging in Gateway Mode
type AuditResult struct {
	// Success indicates whether the audit was logged successfully
	Success bool `json:"success"`
	// AuditID is a unique ID for reference
	AuditID string `json:"audit_id"`
}

// PlanExecutionResponse represents the result of plan execution
type PlanExecutionResponse struct {
	PlanID                 string       `json:"plan_id"`
	Status                 string       `json:"status"` // "running", "completed", "failed", "partial"
	Result                 string       `json:"result,omitempty"`
	StepResults            []StepResult `json:"step_results,omitempty"`
	Error                  string       `json:"error,omitempty"`
	Duration               string       `json:"duration,omitempty"`
	CompletedSteps         int          `json:"completed_steps"`                    // Number of completed steps
	TotalSteps             int          `json:"total_steps"`                        // Total number of steps
	CurrentStep            string       `json:"current_step,omitempty"`             // Currently executing step
	EstimatedTimeRemaining string       `json:"estimated_time_remaining,omitempty"` // For in-progress plans
}

// StepResult represents the result of a single plan step execution
type StepResult struct {
	StepID   string      `json:"step_id"`
	StepName string      `json:"step_name"`
	Status   string      `json:"status"` // "pending", "running", "completed", "failed"
	Result   interface{} `json:"result,omitempty"`
	Error    string      `json:"error,omitempty"`
	Duration string      `json:"duration,omitempty"`
}

// Cache entry
type cacheEntry struct {
	value      interface{}
	expiration time.Time
}

// Simple in-memory cache
type cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

func newCache(ttl time.Duration) *cache {
	c := &cache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
	// Start cleanup goroutine
	go c.cleanup()
	return c
}

func (c *cache) get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiration) {
		return nil, false
	}

	return entry.value, true
}

func (c *cache) set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = &cacheEntry{
		value:      value,
		expiration: time.Now().Add(c.ttl),
	}
}

func (c *cache) cleanup() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiration) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

// NewClient creates a new AxonFlow client with the given configuration
func NewClient(config AxonFlowConfig) *AxonFlowClient {
	// Set defaults
	if config.Mode == "" {
		config.Mode = "production"
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.MapTimeout == 0 {
		config.MapTimeout = 120 * time.Second // 2 minutes for MAP operations
	}
	if config.Retry.InitialDelay == 0 {
		config.Retry.InitialDelay = 1 * time.Second
	}
	if config.Retry.MaxAttempts == 0 {
		config.Retry.MaxAttempts = 3
		config.Retry.Enabled = true
	}
	if config.Cache.TTL == 0 {
		config.Cache.TTL = 60 * time.Second
		config.Cache.Enabled = true
	}

	// Configure TLS
	tlsConfig := &tls.Config{}
	if os.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" {
		tlsConfig.InsecureSkipVerify = true
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	client := &AxonFlowClient{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
		mapHttpClient: &http.Client{
			Timeout:   config.MapTimeout,
			Transport: transport,
		},
	}

	if config.Cache.Enabled {
		client.cache = newCache(config.Cache.TTL)
	}

	if config.Debug {
		log.Printf("[AxonFlow] Client initialized - Mode: %s, Endpoint: %s, MapTimeout: %v", config.Mode, config.Endpoint, config.MapTimeout)
	}

	return client
}

// NewClientSimple creates a client with simple parameters (backward compatible)
func NewClientSimple(endpoint, clientID, clientSecret string) *AxonFlowClient {
	return NewClient(AxonFlowConfig{
		Endpoint:     endpoint,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
}

// Sandbox creates a client in sandbox mode for testing
func Sandbox(apiKey string) *AxonFlowClient {
	if apiKey == "" {
		apiKey = "demo-key"
	}

	return NewClient(AxonFlowConfig{
		Endpoint:     "https://staging-eu.getaxonflow.com",
		ClientID:     apiKey,
		ClientSecret: apiKey,
		Mode:         "sandbox",
		Debug:        true,
	})
}

// ExecuteQuery sends a query through AxonFlow platform with policy enforcement
func (c *AxonFlowClient) ExecuteQuery(userToken, query, requestType string, context map[string]interface{}) (*ClientResponse, error) {
	// Generate cache key
	cacheKey := fmt.Sprintf("%s:%s:%s", requestType, query, userToken)

	// Check cache if enabled
	if c.cache != nil {
		if cached, found := c.cache.get(cacheKey); found {
			if c.config.Debug {
				log.Printf("[AxonFlow] Cache hit for query: %s", query[:min(50, len(query))])
			}
			return cached.(*ClientResponse), nil
		}
	}

	req := ClientRequest{
		Query:       query,
		UserToken:   userToken,
		ClientID:    c.config.ClientID,
		RequestType: requestType,
		Context:     context,
	}

	var resp *ClientResponse
	var err error

	// Execute with retry if enabled
	if c.config.Retry.Enabled {
		resp, err = c.executeWithRetry(req)
	} else {
		resp, err = c.executeRequest(req)
	}

	// Handle fail-open in production mode
	if err != nil && c.config.Mode == "production" && c.isAxonFlowError(err) {
		if c.config.Debug {
			log.Printf("[AxonFlow] AxonFlow unavailable, failing open: %v", err)
		}
		// Return a success response indicating the request was allowed through
		return &ClientResponse{
			Success: true,
			Data:    nil,
			Error:   fmt.Sprintf("AxonFlow unavailable (fail-open): %v", err),
		}, nil
	}

	if err != nil {
		return nil, err
	}

	// Cache successful responses
	if c.cache != nil && resp.Success {
		c.cache.set(cacheKey, resp)
	}

	return resp, nil
}

// executeWithRetry executes a request with exponential backoff retry
func (c *AxonFlowClient) executeWithRetry(req ClientRequest) (*ClientResponse, error) {
	var lastErr error

	for attempt := 0; attempt < c.config.Retry.MaxAttempts; attempt++ {
		if attempt > 0 {
			// Exponential backoff: delay * 2^(attempt-1)
			delay := time.Duration(float64(c.config.Retry.InitialDelay) * math.Pow(2, float64(attempt-1)))
			if c.config.Debug {
				log.Printf("[AxonFlow] Retry attempt %d/%d after %v", attempt+1, c.config.Retry.MaxAttempts, delay)
			}
			time.Sleep(delay)
		}

		resp, err := c.executeRequest(req)
		if err == nil {
			return resp, nil
		}

		lastErr = err

		// Don't retry on client errors (4xx)
		if httpErr, ok := err.(*httpError); ok && httpErr.statusCode >= 400 && httpErr.statusCode < 500 {
			if c.config.Debug {
				log.Printf("[AxonFlow] Client error (4xx), not retrying: %v", err)
			}
			break
		}
	}

	return nil, fmt.Errorf("request failed after %d attempts: %w", c.config.Retry.MaxAttempts, lastErr)
}

// httpError represents an HTTP error with status code
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.statusCode, e.message)
}

// executeRequest executes a single request without retry
func (c *AxonFlowClient) executeRequest(req ClientRequest) (*ClientResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/request", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Sending request - Type: %s, Query: %s", req.RequestType, req.Query[:min(50, len(req.Query))])
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// [DEBUG] Log raw response body before unmarshaling
	log.Printf("[SDK-DEBUG] Raw response body size: %d bytes", len(body))
	if len(body) > 0 && len(body) <= 500 {
		log.Printf("[SDK-DEBUG] Raw response body (full): %s", string(body))
	} else if len(body) > 500 {
		log.Printf("[SDK-DEBUG] Raw response body (first 500 chars): %s...", string(body[:500]))
	}

	// For 403 (Forbidden), the request was blocked by policy - parse the response body
	if resp.StatusCode == http.StatusForbidden {
		var clientResp ClientResponse
		if err := json.Unmarshal(body, &clientResp); err != nil {
			return nil, fmt.Errorf("failed to parse blocked response: %w", err)
		}
		// The response contains blocked=true and block_reason from the agent
		return &clientResp, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var clientResp ClientResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for nested errors in the Data field
	// When orchestrator fails, agent wraps error as: {"success":true, "data":{"success":false, "error":"..."}}
	if clientResp.Data != nil {
		if dataMap, ok := clientResp.Data.(map[string]interface{}); ok {
			// Check if data contains nested success field
			if dataSuccess, hasSuccess := dataMap["success"].(bool); hasSuccess && !dataSuccess {
				// Orchestrator execution failed - extract error message
				if errorMsg, hasError := dataMap["error"].(string); hasError {
					log.Printf("[SDK-DEBUG] Detected orchestrator failure in data.error: %s", errorMsg)
					// Surface the error by setting the Error field and marking success as false
					clientResp.Error = errorMsg
					clientResp.Success = false
				}
			}
			// Also check if data.result or data.data exists and use it if Result is empty
			if clientResp.Result == "" {
				if dataResult, hasResult := dataMap["result"].(string); hasResult && dataResult != "" {
					log.Printf("[SDK-DEBUG] Using data.result field (length: %d)", len(dataResult))
					clientResp.Result = dataResult
				} else if dataData, hasData := dataMap["data"].(string); hasData && dataData != "" {
					log.Printf("[SDK-DEBUG] Using data.data field (length: %d)", len(dataData))
					clientResp.Result = dataData
				}
			}
			// Check if data.plan_id exists and use it if PlanID is empty
			if clientResp.PlanID == "" {
				if dataPlanID, hasPlanID := dataMap["plan_id"].(string); hasPlanID && dataPlanID != "" {
					log.Printf("[SDK-DEBUG] Using data.plan_id field: %s", dataPlanID)
					clientResp.PlanID = dataPlanID
				}
			}
			// Check if data.metadata exists and use it if Metadata is empty
			if clientResp.Metadata == nil {
				if dataMetadata, hasMetadata := dataMap["metadata"].(map[string]interface{}); hasMetadata {
					log.Printf("[SDK-DEBUG] Using data.metadata field")
					clientResp.Metadata = dataMetadata
				}
			}
		}
	}

	// [DEBUG] Log unmarshaled response details
	log.Printf("[SDK-DEBUG] Unmarshaled - Success: %v, Blocked: %v, BlockReason: %s, Result length: %d, PlanID: %s",
		clientResp.Success, clientResp.Blocked, clientResp.BlockReason, len(clientResp.Result), clientResp.PlanID)
	if len(clientResp.Result) > 0 {
		if len(clientResp.Result) <= 100 {
			log.Printf("[SDK-DEBUG] Result (full): %s", clientResp.Result)
		} else {
			log.Printf("[SDK-DEBUG] Result (first 100 chars): %s...", clientResp.Result[:100])
		}
	} else {
		log.Printf("[SDK-DEBUG] Result is empty!")
	}
	log.Printf("[SDK-DEBUG] Metadata keys: %v", getMetadataKeys(clientResp.Metadata))

	// If we detected an error in the data field, log it prominently
	if clientResp.Error != "" {
		log.Printf("[SDK-DEBUG] Error field set: %s", clientResp.Error)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Response received - Success: %v, Duration: %v", clientResp.Success, duration)
	}

	return &clientResp, nil
}

// isAxonFlowError checks if an error is from AxonFlow (vs the AI provider)
func (c *AxonFlowClient) isAxonFlowError(err error) bool {
	errMsg := err.Error()
	return strings.Contains(errMsg, "AxonFlow") ||
		strings.Contains(errMsg, "governance") ||
		strings.Contains(errMsg, "request failed") ||
		strings.Contains(errMsg, "connection refused")
}

// HealthCheck checks if AxonFlow Agent is healthy
func (c *AxonFlowClient) HealthCheck() error {
	resp, err := c.httpClient.Get(c.config.Endpoint + "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent not healthy: status %d", resp.StatusCode)
	}

	if c.config.Debug {
		log.Println("[AxonFlow] Health check passed")
	}

	return nil
}

// OrchestratorHealthCheck checks orchestrator health via Agent proxy.
// Deprecated: Use HealthCheck() instead - Agent proxies all routes since ADR-026.
func (c *AxonFlowClient) OrchestratorHealthCheck() error {
	// Since ADR-026, Agent proxies to Orchestrator, so we just call Agent health
	return c.HealthCheck()
}

// getMetadataKeys returns the keys from a metadata map for debugging
func getMetadataKeys(metadata map[string]interface{}) []string {
	if metadata == nil {
		return []string{}
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	return keys
}

// ListConnectors returns all available MCP connectors from the marketplace
func (c *AxonFlowClient) ListConnectors() ([]ConnectorMetadata, error) {
	resp, err := c.httpClient.Get(c.config.Endpoint + "/api/v1/connectors")
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list connectors failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	// Response is wrapped: {"connectors": [...], "total": N}
	var response struct {
		Connectors []ConnectorMetadata `json:"connectors"`
		Total      int                 `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode connectors: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listed %d connectors", len(response.Connectors))
	}

	return response.Connectors, nil
}

// GetConnector returns details for a specific connector by ID
func (c *AxonFlowClient) GetConnector(connectorID string) (*ConnectorMetadata, error) {
	url := fmt.Sprintf("%s/api/v1/connectors/%s", c.config.Endpoint, connectorID)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("connector not found: %s", connectorID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get connector failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var connector ConnectorMetadata
	if err := json.NewDecoder(resp.Body).Decode(&connector); err != nil {
		return nil, fmt.Errorf("failed to decode connector: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Got connector: %s (installed: %v)", connector.ID, connector.Installed)
	}

	return &connector, nil
}

// GetConnectorHealth returns the health status of an installed connector
func (c *AxonFlowClient) GetConnectorHealth(connectorID string) (*ConnectorHealthStatus, error) {
	url := fmt.Sprintf("%s/api/v1/connectors/%s/health", c.config.Endpoint, connectorID)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to get connector health: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("connector not found: %s", connectorID)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("connector health check failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var status ConnectorHealthStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode health status: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector %s health: %v", connectorID, status.Healthy)
	}

	return &status, nil
}

// InstallConnector installs an MCP connector from the marketplace
func (c *AxonFlowClient) InstallConnector(req ConnectorInstallRequest) error {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal install request: %w", err)
	}

	// Connector install via Agent proxy: POST /api/v1/connectors/{id}/install
	url := fmt.Sprintf("%s/api/v1/connectors/%s/install", c.config.Endpoint, req.ConnectorID)
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create install request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("install request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector installed: %s", req.Name)
	}

	return nil
}

// UninstallConnector removes an installed MCP connector
func (c *AxonFlowClient) UninstallConnector(connectorName string) error {
	url := fmt.Sprintf("%s/api/v1/connectors/%s", c.config.Endpoint, connectorName)
	httpReq, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create uninstall request: %w", err)
	}

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("uninstall request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("uninstall failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector uninstalled: %s", connectorName)
	}

	return nil
}

// QueryConnector executes a query against an installed MCP connector
func (c *AxonFlowClient) QueryConnector(userToken, connectorName, query string, params map[string]interface{}) (*ConnectorResponse, error) {
	context := map[string]interface{}{
		"connector": connectorName,
		"params":    params,
	}

	resp, err := c.ExecuteQuery(userToken, query, "mcp-query", context)
	if err != nil {
		return nil, err
	}

	connResp := &ConnectorResponse{
		Success: resp.Success,
		Data:    resp.Data,
		Error:   resp.Error,
		Meta:    resp.Metadata,
	}

	return connResp, nil
}

// GeneratePlan creates a multi-agent execution plan from a natural language query.
// The userToken parameter is optional; if not provided, it defaults to the client ID.
// Usage: GeneratePlan(query, domain) or GeneratePlan(query, domain, userToken)
// Note: This uses MapTimeout (default 120s) as MAP operations involve multiple LLM calls.
func (c *AxonFlowClient) GeneratePlan(query string, domain string, userToken ...string) (*PlanResponse, error) {
	context := map[string]interface{}{}
	if domain != "" {
		context["domain"] = domain
	}

	// Use client ID as fallback if no user token provided
	token := c.config.ClientID
	if len(userToken) > 0 && userToken[0] != "" {
		token = userToken[0]
	}

	// Use executeMapRequest with longer timeout for MAP operations
	req := ClientRequest{
		Query:       query,
		UserToken:   token,
		ClientID:    c.config.ClientID,
		RequestType: "multi-agent-plan",
		Context:     context,
	}

	resp, err := c.executeMapRequest(req)
	if err != nil {
		return nil, err
	}

	if !resp.Success {
		return nil, fmt.Errorf("plan generation failed: %s", resp.Error)
	}

	// Parse plan from response
	planData, ok := resp.Data.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected plan response format")
	}

	// Convert to PlanResponse
	planBytes, _ := json.Marshal(planData)
	var plan PlanResponse
	if err := json.Unmarshal(planBytes, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse plan: %w", err)
	}

	plan.PlanID = resp.PlanID

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan generated: %s (%d steps)", plan.PlanID, len(plan.Steps))
	}

	return &plan, nil
}

// executeMapRequest executes a MAP request using the mapHttpClient with longer timeout
func (c *AxonFlowClient) executeMapRequest(req ClientRequest) (*ClientResponse, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/request", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] MAP request - Query: %s (timeout: %v)", req.Query[:min(50, len(req.Query))], c.config.MapTimeout)
	}

	startTime := time.Now()
	resp, err := c.mapHttpClient.Do(httpReq) // Use mapHttpClient with longer timeout
	if err != nil {
		return nil, fmt.Errorf("MAP request failed: %w", err)
	}
	defer resp.Body.Close()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] MAP response received in %v", duration)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var clientResp ClientResponse
	if err := json.Unmarshal(body, &clientResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Check for nested errors/data in the Data field (same logic as executeRequest)
	if clientResp.Data != nil {
		if dataMap, ok := clientResp.Data.(map[string]interface{}); ok {
			if dataSuccess, hasSuccess := dataMap["success"].(bool); hasSuccess && !dataSuccess {
				if errorMsg, hasError := dataMap["error"].(string); hasError {
					clientResp.Error = errorMsg
					clientResp.Success = false
				}
			}
			if clientResp.Result == "" {
				if dataResult, hasResult := dataMap["result"].(string); hasResult && dataResult != "" {
					clientResp.Result = dataResult
				}
			}
			if clientResp.PlanID == "" {
				if dataPlanID, hasPlanID := dataMap["plan_id"].(string); hasPlanID && dataPlanID != "" {
					clientResp.PlanID = dataPlanID
				}
			}
			if clientResp.Metadata == nil {
				if dataMetadata, hasMetadata := dataMap["metadata"].(map[string]interface{}); hasMetadata {
					clientResp.Metadata = dataMetadata
				}
			}
		}
	}

	return &clientResp, nil
}

// ExecutePlan executes a previously generated multi-agent plan.
// The userToken parameter is optional; if not provided, it defaults to the client ID.
// Usage: ExecutePlan(planID) or ExecutePlan(planID, userToken)
func (c *AxonFlowClient) ExecutePlan(planID string, userToken ...string) (*PlanExecutionResponse, error) {
	context := map[string]interface{}{
		"plan_id": planID,
	}

	// Use client ID as fallback if no user token provided
	token := c.config.ClientID
	if len(userToken) > 0 && userToken[0] != "" {
		token = userToken[0]
	}

	resp, err := c.ExecuteQuery(token, "", "execute-plan", context)
	if err != nil {
		return nil, err
	}

	execResp := &PlanExecutionResponse{
		PlanID: planID,
		Status: "completed",
		Result: resp.Result,
		Error:  resp.Error,
	}

	if resp.Metadata != nil {
		if duration, ok := resp.Metadata["duration"].(string); ok {
			execResp.Duration = duration
		}
		if stepResults, ok := resp.Metadata["step_results"].([]interface{}); ok {
			// Convert to StepResult slice
			for _, sr := range stepResults {
				if srMap, ok := sr.(map[string]interface{}); ok {
					stepResult := StepResult{}
					if id, ok := srMap["step_id"].(string); ok {
						stepResult.StepID = id
					}
					if name, ok := srMap["step_name"].(string); ok {
						stepResult.StepName = name
					}
					if status, ok := srMap["status"].(string); ok {
						stepResult.Status = status
					}
					if result, ok := srMap["result"]; ok {
						stepResult.Result = result
					}
					if errStr, ok := srMap["error"].(string); ok {
						stepResult.Error = errStr
					}
					if dur, ok := srMap["duration"].(string); ok {
						stepResult.Duration = dur
					}
					execResp.StepResults = append(execResp.StepResults, stepResult)
				}
			}
		}
		if completed, ok := resp.Metadata["completed_steps"].(float64); ok {
			execResp.CompletedSteps = int(completed)
		}
		if total, ok := resp.Metadata["total_steps"].(float64); ok {
			execResp.TotalSteps = int(total)
		}
	}

	if !resp.Success {
		execResp.Status = "failed"
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Plan executed: %s - Status: %s", planID, execResp.Status)
	}

	return execResp, nil
}

// GetPlanStatus retrieves the status of a running or completed plan
func (c *AxonFlowClient) GetPlanStatus(planID string) (*PlanExecutionResponse, error) {
	resp, err := c.httpClient.Get(c.config.Endpoint + "/api/plans/" + planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan status: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get plan status failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var status PlanExecutionResponse
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to decode plan status: %w", err)
	}

	return &status, nil
}

// ============================================================================
// Gateway Mode Methods
// ============================================================================

// PreCheck is an alias for GetPolicyApprovedContext for simpler API.
func (c *AxonFlowClient) PreCheck(
	userToken string,
	query string,
	dataSources []string,
	context map[string]interface{},
) (*PolicyApprovalResult, error) {
	return c.GetPolicyApprovedContext(userToken, query, dataSources, context)
}

// GetPolicyApprovedContext performs a policy pre-check before making a direct LLM call.
//
// Use Gateway Mode when you want to:
//   - Make direct LLM calls (not through AxonFlow proxy)
//   - Have full control over your LLM provider/model selection
//   - Minimize latency by calling LLM directly
//
// Example:
//
//	ctx, err := client.GetPolicyApprovedContext(userToken, query, []string{"postgres"}, nil)
//	if err != nil {
//	    return err
//	}
//	if !ctx.Approved {
//	    return fmt.Errorf("blocked: %s", ctx.BlockReason)
//	}
//
//	// Make direct LLM call with ctx.ApprovedData
//	resp, err := openai.CreateCompletion(...)
//
//	// Audit the call
//	client.AuditLLMCall(ctx.ContextID, "summary", "openai", "gpt-4", tokenUsage, latencyMs, nil)

// requireCredentials checks if credentials are configured and returns an error if not.
// Enterprise features like Gateway Mode require authentication.
func (c *AxonFlowClient) requireCredentials(feature string) error {
	if c.config.LicenseKey == "" && c.config.ClientSecret == "" {
		return fmt.Errorf("%s requires credentials. Set LicenseKey or ClientID/ClientSecret", feature)
	}
	return nil
}

func (c *AxonFlowClient) GetPolicyApprovedContext(
	userToken string,
	query string,
	dataSources []string,
	context map[string]interface{},
) (*PolicyApprovalResult, error) {
	// Gateway Mode requires credentials (enterprise feature)
	if err := c.requireCredentials("Gateway Mode (GetPolicyApprovedContext)"); err != nil {
		return nil, err
	}

	if dataSources == nil {
		dataSources = []string{}
	}
	if context == nil {
		context = map[string]interface{}{}
	}

	reqBody := map[string]interface{}{
		"user_token":   userToken,
		"client_id":    c.config.ClientID,
		"query":        query,
		"data_sources": dataSources,
		"context":      context,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pre-check request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/policy/pre-check", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-check request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Pre-check for query: %s", query[:min(50, len(query))])
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pre-check request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read pre-check response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	// Parse response
	var rawResp struct {
		ContextID         string                 `json:"context_id"`
		Approved          bool                   `json:"approved"`
		RequiresRedaction bool                   `json:"requires_redaction"`
		ApprovedData      map[string]interface{} `json:"approved_data"`
		Policies          []string               `json:"policies"`
		RateLimit         *struct {
			Limit     int    `json:"limit"`
			Remaining int    `json:"remaining"`
			ResetAt   string `json:"reset_at"`
		} `json:"rate_limit,omitempty"`
		ExpiresAt   string `json:"expires_at"`
		BlockReason string `json:"block_reason,omitempty"`
	}

	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-check response: %w", err)
	}

	// Parse expiration time (supports both RFC3339 and RFC3339Nano formats)
	expiresAt, err := parseTimeWithFallback(rawResp.ExpiresAt)
	if err != nil {
		// Use a default expiration if parsing fails
		expiresAt = time.Now().Add(5 * time.Minute)
		if c.config.Debug {
			log.Printf("[AxonFlow] Warning: Failed to parse expires_at '%s', using default 5 minute expiration", rawResp.ExpiresAt)
		}
	}

	result := &PolicyApprovalResult{
		ContextID:         rawResp.ContextID,
		Approved:          rawResp.Approved,
		RequiresRedaction: rawResp.RequiresRedaction,
		ApprovedData:      rawResp.ApprovedData,
		Policies:          rawResp.Policies,
		ExpiresAt:         expiresAt,
		BlockReason:       rawResp.BlockReason,
	}

	// Parse rate limit info if present
	if rawResp.RateLimit != nil {
		resetAt, err := parseTimeWithFallback(rawResp.RateLimit.ResetAt)
		if err != nil && c.config.Debug {
			log.Printf("[AxonFlow] Warning: Failed to parse rate_limit.reset_at '%s'", rawResp.RateLimit.ResetAt)
		}
		result.RateLimitInfo = &RateLimitInfo{
			Limit:     rawResp.RateLimit.Limit,
			Remaining: rawResp.RateLimit.Remaining,
			ResetAt:   resetAt,
		}
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Pre-check result - Approved: %v, ContextID: %s, Policies: %d",
			result.Approved, result.ContextID, len(result.Policies))
	}

	return result, nil
}

// AuditLLMCall logs an audit trail after making a direct LLM call.
//
// This is required for compliance and monitoring when using Gateway Mode.
// Call this after making your direct LLM call to ensure the audit trail is complete.
//
// Example:
//
//	result, err := client.AuditLLMCall(
//	    ctx.ContextID,
//	    "Generated report with 5 items",
//	    "openai",
//	    "gpt-4",
//	    TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
//	    250, // latency in ms
//	    nil, // optional metadata
//	)
func (c *AxonFlowClient) AuditLLMCall(
	contextID string,
	responseSummary string,
	provider string,
	model string,
	tokenUsage TokenUsage,
	latencyMs int64,
	metadata map[string]interface{},
) (*AuditResult, error) {
	// Gateway Mode requires credentials (enterprise feature)
	if err := c.requireCredentials("Gateway Mode (AuditLLMCall)"); err != nil {
		return nil, err
	}

	if metadata == nil {
		metadata = map[string]interface{}{}
	}

	reqBody := map[string]interface{}{
		"context_id":       contextID,
		"client_id":        c.config.ClientID,
		"response_summary": responseSummary,
		"provider":         provider,
		"model":            model,
		"token_usage": map[string]int{
			"prompt_tokens":     tokenUsage.PromptTokens,
			"completion_tokens": tokenUsage.CompletionTokens,
			"total_tokens":      tokenUsage.TotalTokens,
		},
		"latency_ms": latencyMs,
		"metadata":   metadata,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.Endpoint+"/api/audit/llm-call", bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Audit - ContextID: %s, Provider: %s, Model: %s",
			contextID, provider, model)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(body),
		}
	}

	var rawResp struct {
		Success bool   `json:"success"`
		AuditID string `json:"audit_id"`
	}

	if err := json.Unmarshal(body, &rawResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit response: %w", err)
	}

	result := &AuditResult{
		Success: rawResp.Success,
		AuditID: rawResp.AuditID,
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Gateway Mode: Audit logged - AuditID: %s", result.AuditID)
	}

	return result, nil
}

// Helper functions

// parseTimeWithFallback tries to parse a time string using RFC3339Nano first (with fractional seconds),
// then falls back to RFC3339 (without fractional seconds). This handles timestamps from the server
// that may or may not include nanosecond precision.
func parseTimeWithFallback(value string) (time.Time, error) {
	// Try RFC3339Nano first (supports fractional seconds up to nanosecond precision)
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t, nil
	}
	// Fall back to RFC3339 (no fractional seconds)
	return time.Parse(time.RFC3339, value)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// Portal Authentication Methods
// ============================================================================

// LoginToPortal authenticates with the Customer Portal and stores the session cookie.
// This is required for enterprise features like Code Governance PR workflow.
//
// Example:
//
//	resp, err := client.LoginToPortal("test-org-001", "test123")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Logged in as %s\n", resp.Name)
//
//	// Now you can use Code Governance methods
//	providers, err := client.ListGitProviders()
func (c *AxonFlowClient) LoginToPortal(orgID, password string) (*PortalLoginResponse, error) {
	reqBody := PortalLoginRequest{
		OrgID:    orgID,
		Password: password,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	fullURL := c.config.Endpoint + "/api/v1/auth/login"

	req, err := http.NewRequest("POST", fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	if c.config.Debug {
		log.Printf("[AxonFlow] Portal login for org: %s", orgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	var loginResp PortalLoginResponse
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	// Extract session cookie from response and store it
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "axonflow_session" {
			c.sessionCookie = cookie.Value
			if c.config.Debug {
				log.Printf("[AxonFlow] Portal session established for %s", orgID)
			}
			break
		}
	}

	// If no cookie in response, use session_id from JSON response
	if c.sessionCookie == "" && loginResp.SessionID != "" {
		c.sessionCookie = loginResp.SessionID
		if c.config.Debug {
			log.Printf("[AxonFlow] Portal session established from response body for %s", orgID)
		}
	}

	return &loginResp, nil
}

// LogoutFromPortal logs out from the Customer Portal and clears the session cookie.
func (c *AxonFlowClient) LogoutFromPortal() error {
	if c.sessionCookie == "" {
		return nil // Already logged out
	}

	fullURL := c.config.Endpoint + "/api/v1/auth/logout"

	req, err := http.NewRequest("POST", fullURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create logout request: %w", err)
	}

	req.AddCookie(&http.Cookie{
		Name:  "axonflow_session",
		Value: c.sessionCookie,
	})

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}
	defer resp.Body.Close()

	c.sessionCookie = ""

	if c.config.Debug {
		log.Printf("[AxonFlow] Portal session ended")
	}

	return nil
}

// IsLoggedIn returns true if the client has an active portal session.
func (c *AxonFlowClient) IsLoggedIn() bool {
	return c.sessionCookie != ""
}

// makeJSONRequest is a generic helper for making JSON HTTP requests
func (c *AxonFlowClient) makeJSONRequest(ctx context.Context, method, fullURL string, body interface{}, result interface{}) error {
	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add auth headers only when credentials are provided
	// Community/self-hosted mode works without credentials
	if c.config.LicenseKey != "" {
		req.Header.Set("X-License-Key", c.config.LicenseKey)
	}
	if c.config.ClientSecret != "" {
		req.Header.Set("X-Client-Secret", c.config.ClientSecret)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] JSON request: %s %s", method, fullURL)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return &httpError{
			statusCode: resp.StatusCode,
			message:    string(respBody),
		}
	}

	// Handle no-content responses
	if resp.StatusCode == 204 || len(respBody) == 0 {
		return nil
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}
