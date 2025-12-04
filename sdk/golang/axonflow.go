package axonflow

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sync"
	"time"
)

// AxonFlowConfig represents configuration for the AxonFlow client
type AxonFlowConfig struct {
	AgentURL           string        // Required: AxonFlow Agent URL
	ClientID           string        // Required: Client ID for authentication
	ClientSecret       string        // Required: Client secret for authentication
	LicenseKey         string        // Optional: License key for organization-level authentication
	Mode               string        // "production" | "sandbox" (default: "production")
	Debug              bool          // Enable debug logging (default: false)
	Timeout            time.Duration // Request timeout (default: 60s)
	InsecureSkipVerify bool          // Skip TLS certificate verification (default: false) - use only for development/testing
	Retry              RetryConfig   // Retry configuration
	Cache              CacheConfig   // Cache configuration
}

// RetryConfig configures retry behavior
type RetryConfig struct {
	Enabled     bool          // Enable retry logic (default: true)
	MaxAttempts int           // Maximum retry attempts (default: 3)
	InitialDelay time.Duration // Initial delay between retries (default: 1s)
}

// CacheConfig configures caching behavior
type CacheConfig struct {
	Enabled bool          // Enable caching (default: true)
	TTL     time.Duration // Cache TTL (default: 60s)
}

// AxonFlowClient represents the SDK for connecting to AxonFlow platform
type AxonFlowClient struct {
	config     AxonFlowConfig
	httpClient *http.Client
	cache      *cache
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
	Success      bool                   `json:"success"`
	Data         interface{}            `json:"data,omitempty"`
	Result       string                 `json:"result,omitempty"` // For multi-agent planning
	PlanID       string                 `json:"plan_id,omitempty"` // For multi-agent planning
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Blocked      bool                   `json:"blocked"`
	BlockReason  string                 `json:"block_reason,omitempty"`
	PolicyInfo   *PolicyEvaluationInfo  `json:"policy_info,omitempty"`
}

// PolicyEvaluationInfo contains policy evaluation metadata
type PolicyEvaluationInfo struct {
	PoliciesEvaluated []string `json:"policies_evaluated"`
	StaticChecks      []string `json:"static_checks"`
	ProcessingTime    string   `json:"processing_time"`
	TenantID          string   `json:"tenant_id"`
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
	Healthy      bool                   `json:"healthy,omitempty"`
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
	PlanID      string                 `json:"plan_id"`
	Steps       []PlanStep             `json:"steps"`
	Domain      string                 `json:"domain"`
	Complexity  int                    `json:"complexity"`
	Parallel    bool                   `json:"parallel"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PlanStep represents a single step in a multi-agent plan
type PlanStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	DependsOn   []string               `json:"depends_on"`
	Agent       string                 `json:"agent"`
	Parameters  map[string]interface{} `json:"parameters"`
}

// PlanExecutionResponse represents the result of plan execution
type PlanExecutionResponse struct {
	PlanID       string                 `json:"plan_id"`
	Status       string                 `json:"status"` // "running", "completed", "failed"
	Result       string                 `json:"result,omitempty"`
	StepResults  map[string]interface{} `json:"step_results,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Duration     string                 `json:"duration,omitempty"`
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
	if os.Getenv("NODE_TLS_REJECT_UNAUTHORIZED") == "0" || config.InsecureSkipVerify {
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
	}

	if config.Cache.Enabled {
		client.cache = newCache(config.Cache.TTL)
	}

	if config.Debug {
		log.Printf("[AxonFlow] Client initialized - Mode: %s, Endpoint: %s", config.Mode, config.AgentURL)
	}

	return client
}

// NewClientSimple creates a client with simple parameters (backward compatible)
func NewClientSimple(agentURL, clientID, clientSecret string) *AxonFlowClient {
	return NewClient(AxonFlowConfig{
		AgentURL:     agentURL,
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
		AgentURL:     "https://staging-eu.getaxonflow.com",
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

	httpReq, err := http.NewRequest("POST", c.config.AgentURL+"/api/request", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Sending request - Type: %s, Query: %s", req.RequestType, req.Query[:min(50, len(req.Query))])
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
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

	if c.config.Debug {
		log.Printf("[AxonFlow] Response received - Success: %v, Duration: %v", clientResp.Success, duration)
	}

	return &clientResp, nil
}

// isAxonFlowError checks if an error is from AxonFlow (vs the AI provider)
func (c *AxonFlowClient) isAxonFlowError(err error) bool {
	errMsg := err.Error()
	return contains(errMsg, "AxonFlow") ||
		contains(errMsg, "governance") ||
		contains(errMsg, "request failed") ||
		contains(errMsg, "connection refused")
}

// HealthCheck checks if AxonFlow Agent is healthy
func (c *AxonFlowClient) HealthCheck() error {
	resp, err := c.httpClient.Get(c.config.AgentURL + "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent not healthy: status %d", resp.StatusCode)
	}

	if c.config.Debug {
		log.Println("[AxonFlow] Health check passed")
	}

	return nil
}

// ListConnectors returns all available MCP connectors from the marketplace
func (c *AxonFlowClient) ListConnectors() ([]ConnectorMetadata, error) {
	resp, err := c.httpClient.Get(c.config.AgentURL + "/api/connectors")
	if err != nil {
		return nil, fmt.Errorf("failed to list connectors: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list connectors failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var connectors []ConnectorMetadata
	if err := json.NewDecoder(resp.Body).Decode(&connectors); err != nil {
		return nil, fmt.Errorf("failed to decode connectors: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Listed %d connectors", len(connectors))
	}

	return connectors, nil
}

// InstallConnector installs an MCP connector from the marketplace
func (c *AxonFlowClient) InstallConnector(req ConnectorInstallRequest) error {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal install request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.AgentURL+"/api/connectors/install", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create install request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("install request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("install failed: HTTP %d: %s", resp.StatusCode, string(body))
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Connector installed: %s", req.Name)
	}

	return nil
}

// QueryConnector executes a query against an installed MCP connector
// Calls the MCP endpoint directly (/mcp/resources/query) instead of going through the LLM handler
func (c *AxonFlowClient) QueryConnector(userToken, connectorName, operation string, params map[string]interface{}) (*ConnectorResponse, error) {
	// Build MCP query request (matches MCPQueryRequest in agent/mcp_handler.go)
	mcpReq := map[string]interface{}{
		"client_id":  c.config.ClientID,
		"user_token": userToken,
		"connector":  connectorName,
		"operation":  operation,
		"parameters": params,
	}

	// Add license key if configured (required for service permissions)
	if c.config.LicenseKey != "" {
		mcpReq["license_key"] = c.config.LicenseKey
	}

	reqBody, err := json.Marshal(mcpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal MCP request: %w", err)
	}

	// Make HTTP POST to /mcp/resources/query
	httpReq, err := http.NewRequest("POST", c.config.AgentURL+"/mcp/resources/query", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create MCP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MCP] Querying connector: %s, operation: %s", connectorName, operation)
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("MCP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(startTime)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read MCP response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MCP request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse MCP response
	var mcpResp map[string]interface{}
	if err := json.Unmarshal(body, &mcpResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow MCP] Response received - Duration: %v", duration)
	}

	// Convert to ConnectorResponse
	connResp := &ConnectorResponse{
		Success: getBool(mcpResp, "success"),
		Data:    mcpResp["data"],
		Error:   getString(mcpResp, "error"),
		Meta:    getMap(mcpResp, "meta"),
	}

	return connResp, nil
}

// Helper functions to safely extract values from map
func getBool(m map[string]interface{}, key string) bool {
	if v, ok := m[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if v, ok := m[key]; ok {
		if m, ok := v.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

// GeneratePlan creates a multi-agent execution plan from a natural language query
func (c *AxonFlowClient) GeneratePlan(query string, domain string) (*PlanResponse, error) {
	context := map[string]interface{}{}
	if domain != "" {
		context["domain"] = domain
	}

	resp, err := c.ExecuteQuery("", query, "multi-agent-plan", context)
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

// ExecutePlan executes a previously generated multi-agent plan
func (c *AxonFlowClient) ExecutePlan(planID string) (*PlanExecutionResponse, error) {
	context := map[string]interface{}{
		"plan_id": planID,
	}

	resp, err := c.ExecuteQuery("", "", "execute-plan", context)
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
		if stepResults, ok := resp.Metadata["step_results"].(map[string]interface{}); ok {
			execResp.StepResults = stepResults
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
	resp, err := c.httpClient.Get(c.config.AgentURL + "/api/plans/" + planID)
	if err != nil {
		return nil, fmt.Errorf("failed to get plan status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

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

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && s != "" && substr != "" &&
		(s == substr || (len(s) > len(substr) && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// =============================================================================
// Gateway Mode SDK Methods
// =============================================================================
// Gateway Mode allows clients to make LLM calls directly while still using
// AxonFlow for policy enforcement and audit logging.
//
// Usage:
//   1. Call GetPolicyApprovedContext() before making LLM call
//   2. Make LLM call directly to your provider (using returned approved data)
//   3. Call AuditLLMCall() after to record the call for compliance
//
// Example:
//   ctx, err := client.GetPolicyApprovedContext(userToken, []string{"postgres"}, query, nil)
//   if err != nil || !ctx.Approved { return }
//
//   llmResp := callOpenAI(ctx.ApprovedData)  // Your LLM call
//
//   client.AuditLLMCall(ctx.ContextID, "summary", "openai", "gpt-4", tokenUsage, latencyMs, nil)

// PolicyApprovalResult contains the pre-check result from AxonFlow
type PolicyApprovalResult struct {
	ContextID    string                 `json:"context_id"`     // Links pre-check to audit
	Approved     bool                   `json:"approved"`       // Policy decision
	ApprovedData map[string]interface{} `json:"approved_data"`  // Filtered data from connectors
	Policies     []string               `json:"policies"`       // Policies evaluated
	RateLimitInfo *RateLimitInfo        `json:"rate_limit,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`     // Context validity window
	BlockReason  string                 `json:"block_reason,omitempty"`
}

// RateLimitInfo provides rate limiting status
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

// AuditResult confirms audit was recorded
type AuditResult struct {
	Success bool   `json:"success"`
	AuditID string `json:"audit_id"`
}

// GetPolicyApprovedContext performs policy pre-check before client makes LLM call
// This is the first step in Gateway Mode.
//
// Parameters:
//   - userToken: JWT token for the user making the request
//   - dataSources: Optional list of MCP connectors to fetch data from
//   - query: The query/prompt that will be sent to the LLM
//   - context: Optional additional context for policy evaluation
//
// Returns:
//   - PolicyApprovalResult with context ID and approved data (if any)
//   - error if the request fails
//
// Example:
//   result, err := client.GetPolicyApprovedContext(userToken, []string{"postgres"}, "Find patients with diabetes", nil)
//   if err != nil { return err }
//   if !result.Approved { return fmt.Errorf("blocked: %s", result.BlockReason) }
//   // Now use result.ApprovedData to build your LLM prompt
func (c *AxonFlowClient) GetPolicyApprovedContext(
	userToken string,
	dataSources []string,
	query string,
	context map[string]interface{},
) (*PolicyApprovalResult, error) {
	// Build pre-check request
	reqBody := map[string]interface{}{
		"user_token":   userToken,
		"client_id":    c.config.ClientID,
		"query":        query,
		"data_sources": dataSources,
	}
	if context != nil {
		reqBody["context"] = context
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pre-check request: %w", err)
	}

	// Make HTTP request to pre-check endpoint
	httpReq, err := http.NewRequest("POST", c.config.AgentURL+"/api/policy/pre-check", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create pre-check request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow Gateway] Pre-check request - Query: %s, DataSources: %v", query[:min(50, len(query))], dataSources)
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("pre-check request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(startTime)

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

	var result PolicyApprovalResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pre-check response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow Gateway] Pre-check complete - ContextID: %s, Approved: %v, Duration: %v",
			result.ContextID, result.Approved, duration)
	}

	return &result, nil
}

// AuditLLMCall reports LLM call details back to AxonFlow for audit logging
// This is the second step in Gateway Mode, called after making the LLM call.
//
// Parameters:
//   - contextID: The context ID from GetPolicyApprovedContext()
//   - responseSummary: A brief summary of the LLM response (not the full response for privacy)
//   - provider: LLM provider name ("openai", "anthropic", "bedrock", "ollama")
//   - model: Model name ("gpt-4", "claude-3-sonnet", etc.)
//   - tokenUsage: Token counts from the LLM response
//   - latencyMs: Time taken for the LLM call in milliseconds
//   - metadata: Optional additional metadata to log
//
// Returns:
//   - AuditResult with audit ID confirmation
//   - error if the audit fails
//
// Example:
//   usage := TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150}
//   result, err := client.AuditLLMCall(ctx.ContextID, "Found 5 patients", "openai", "gpt-4", usage, 250, nil)
func (c *AxonFlowClient) AuditLLMCall(
	contextID string,
	responseSummary string,
	provider string,
	model string,
	tokenUsage TokenUsage,
	latencyMs int64,
	metadata map[string]interface{},
) (*AuditResult, error) {
	// Build audit request
	reqBody := map[string]interface{}{
		"context_id":       contextID,
		"client_id":        c.config.ClientID,
		"response_summary": responseSummary,
		"provider":         provider,
		"model":            model,
		"token_usage": map[string]interface{}{
			"prompt_tokens":     tokenUsage.PromptTokens,
			"completion_tokens": tokenUsage.CompletionTokens,
			"total_tokens":      tokenUsage.TotalTokens,
		},
		"latency_ms": latencyMs,
	}
	if metadata != nil {
		reqBody["metadata"] = metadata
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal audit request: %w", err)
	}

	// Make HTTP request to audit endpoint
	httpReq, err := http.NewRequest("POST", c.config.AgentURL+"/api/audit/llm-call", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create audit request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Secret", c.config.ClientSecret)
	if c.config.LicenseKey != "" {
		httpReq.Header.Set("X-License-Key", c.config.LicenseKey)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow Gateway] Audit request - ContextID: %s, Provider: %s, Model: %s, Tokens: %d",
			contextID, provider, model, tokenUsage.TotalTokens)
	}

	startTime := time.Now()
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("audit request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	duration := time.Since(startTime)

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

	var result AuditResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal audit response: %w", err)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow Gateway] Audit recorded - AuditID: %s, Duration: %v", result.AuditID, duration)
	}

	return &result, nil
}
