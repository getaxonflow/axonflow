// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DynamicPolicyEvaluator handles optional Orchestrator calls for dynamic policies.
// Dynamic policies support rate limiting, budget controls, time-based access, and role-based access.
//
// Thread Safety: All methods are safe for concurrent use.
//
// Usage:
//
//	evaluator := NewDynamicPolicyEvaluator(DefaultDynamicPolicyConfig())
//	if evaluator.IsEnabled("postgres") {
//	    resp, err := evaluator.Evaluate(ctx, request)
//	    if err != nil { /* handle graceful degradation */ }
//	    if !resp.Allowed { /* block request */ }
//	}
type DynamicPolicyEvaluator struct {
	config     DynamicPolicyConfig
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewDynamicPolicyEvaluator creates a new dynamic policy evaluator.
func NewDynamicPolicyEvaluator(config DynamicPolicyConfig) *DynamicPolicyEvaluator {
	return &DynamicPolicyEvaluator{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// NewDynamicPolicyEvaluatorFromEnv creates a DynamicPolicyEvaluator configured from environment variables.
//
// Environment variables:
//   - MCP_DYNAMIC_POLICIES_ENABLED: Enable/disable (default: false)
//   - MCP_DYNAMIC_POLICIES_TIMEOUT: Timeout in seconds (default: 5)
//   - MCP_DYNAMIC_POLICIES_GRACEFUL: Graceful degradation (default: true)
//   - MCP_DYNAMIC_POLICIES_CONNECTORS: Comma-separated connectors (empty = all)
//
// Note: The Orchestrator endpoint is NOT configured here. Call SetOrchestratorEndpoint()
// after initialization to set it using the Agent's standard orchestrator URL resolution.
func NewDynamicPolicyEvaluatorFromEnv() *DynamicPolicyEvaluator {
	config := DefaultDynamicPolicyConfig()

	// Parse MCP_DYNAMIC_POLICIES_ENABLED
	if val := os.Getenv("MCP_DYNAMIC_POLICIES_ENABLED"); val != "" {
		config.Enabled = val == "true" || val == "1" || val == "yes"
	}

	// Parse MCP_DYNAMIC_POLICIES_TIMEOUT
	if val := os.Getenv("MCP_DYNAMIC_POLICIES_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			config.Timeout = d
		} else {
			log.Printf("[DynamicPolicyEvaluator] Invalid MCP_DYNAMIC_POLICIES_TIMEOUT: %s, using default", val)
		}
	}

	// Parse MCP_DYNAMIC_POLICIES_GRACEFUL
	if val := os.Getenv("MCP_DYNAMIC_POLICIES_GRACEFUL"); val != "" {
		config.GracefulDegradation = val == "true" || val == "1" || val == "yes"
	}

	// Parse MCP_DYNAMIC_POLICIES_CONNECTORS
	if val := os.Getenv("MCP_DYNAMIC_POLICIES_CONNECTORS"); val != "" {
		connectors := strings.Split(val, ",")
		for i, c := range connectors {
			connectors[i] = strings.TrimSpace(c)
		}
		config.EnabledConnectors = connectors
	}

	// Enforce custom policy connector limit — truncate to tier limit
	config.EnabledConnectors = EnforceCustomPolicyConnectorLimit(config)

	log.Printf("[DynamicPolicyEvaluator] Initialized: enabled=%v, endpoint=%s, timeout=%v, graceful=%v, connectors=%v",
		config.Enabled, config.OrchestratorEndpoint, config.Timeout, config.GracefulDegradation, config.EnabledConnectors)

	return NewDynamicPolicyEvaluator(config)
}

// IsEnabled returns whether dynamic policy evaluation is enabled for a connector.
func (e *DynamicPolicyEvaluator) IsEnabled(connectorName string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.config.Enabled {
		return false
	}

	// Empty EnabledConnectors means all are enabled
	if len(e.config.EnabledConnectors) == 0 {
		return true
	}

	// Check if connector is in the enabled list
	for _, c := range e.config.EnabledConnectors {
		if c == connectorName {
			return true
		}
	}

	return false
}

// Evaluate sends a request to Orchestrator for dynamic policy evaluation.
// Returns the policy decision and any error encountered.
//
// Error handling follows graceful degradation setting:
//   - If GracefulDegradation is true, errors are logged but don't block the request
//   - If GracefulDegradation is false, errors should block the request
func (e *DynamicPolicyEvaluator) Evaluate(ctx context.Context, req DynamicPolicyRequest) (*DynamicPolicyResponse, error) {
	e.mu.RLock()
	config := e.config
	e.mu.RUnlock()

	startTime := time.Now()

	// Ensure request time is set
	if req.RequestTime.IsZero() {
		req.RequestTime = startTime
	}

	// Build request URL
	url := fmt.Sprintf("%s/api/v1/mcp/evaluate-policies", config.OrchestratorEndpoint)

	// Marshal request body
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Request-Source", "mcp-agent")

	// Execute request
	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("orchestrator request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for non-2xx status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("orchestrator returned status %d: %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	var policyResp DynamicPolicyResponse
	if err := json.Unmarshal(respBody, &policyResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Set processing time
	policyResp.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	return &policyResp, nil
}

// EvaluateWithGracefulDegradation wraps Evaluate with graceful degradation handling.
// Returns (response, info, error). If error is nil, check response.Allowed.
// If error is not nil and GracefulDegradation is true, request should proceed.
func (e *DynamicPolicyEvaluator) EvaluateWithGracefulDegradation(ctx context.Context, req DynamicPolicyRequest) (*DynamicPolicyResponse, *DynamicPolicyInfo, error) {
	e.mu.RLock()
	graceful := e.config.GracefulDegradation
	e.mu.RUnlock()

	startTime := time.Now()

	resp, err := e.Evaluate(ctx, req)

	// Build info structure regardless of success
	info := &DynamicPolicyInfo{
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		info.OrchestratorReachable = false
		log.Printf("[DynamicPolicyEvaluator] Evaluation failed: %v (graceful=%v)", err, graceful)

		if graceful {
			// Return empty response, let request proceed
			return &DynamicPolicyResponse{
				Allowed:           true,
				PoliciesEvaluated: 0,
			}, info, nil
		}
		return nil, info, err
	}

	info.OrchestratorReachable = true
	info.PoliciesEvaluated = resp.PoliciesEvaluated
	info.MatchedPolicies = resp.MatchedPolicies

	return resp, info, nil
}

// GetConfig returns the current configuration.
// Returns a copy to prevent external modification.
func (e *DynamicPolicyEvaluator) GetConfig() DynamicPolicyConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config
}

// resolveConnectorLimitTier determines the license tier for connector limit enforcement.
// DEPLOYMENT_MODE controls feature gating (community vs enterprise deployment).
// AXONFLOW_LICENSE_KEY determines resource limits within community mode.
// Enterprise deployment modes (saas, in-vpc-enterprise, etc.) get unlimited connectors.
func resolveConnectorLimitTier() (tier string) {
	mode := os.Getenv("DEPLOYMENT_MODE")
	// Enterprise deployment modes → unlimited
	if mode != "community" && mode != "" {
		return "enterprise"
	}
	// Community deployment mode: extract tier from license key payload
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		return "community"
	}
	if t := extractTierFromLicenseKey(licenseKey); t != "" {
		return strings.ToLower(t)
	}
	return "evaluation" // fallback for unparseable keys
}

// extractTierFromLicenseKey reads the tier field from the license payload
// without full validation (signature is verified elsewhere at startup).
func extractTierFromLicenseKey(key string) string {
	if !strings.HasPrefix(key, "AXON-") {
		return ""
	}
	rest := key[5:]
	dotIdx := strings.LastIndex(rest, ".")
	if dotIdx < 1 {
		return ""
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(rest[:dotIdx])
	if err != nil {
		return ""
	}
	var p struct {
		Tier string `json:"tier"`
	}
	if json.Unmarshal(payloadJSON, &p) != nil {
		return ""
	}
	return p.Tier
}

// ValidateCustomPolicyConnectorLimit checks if the enabled connectors exceed the tier's
// custom policy connector limit. All connectors can be registered in all tiers, but
// tenant-level policies (rate limiting, budgets, time/role access) are limited by tier.
// Returns an error if the limit is exceeded for the current tier.
func ValidateCustomPolicyConnectorLimit(config DynamicPolicyConfig) error {
	tier := resolveConnectorLimitTier()
	var limit int

	switch tier {
	case "enterprise":
		return nil // Unlimited
	case "evaluation":
		limit = config.MaxCustomPolicyConnectorsEvaluation
	default: // community
		limit = config.MaxCustomPolicyConnectorsCommunity
	}

	if limit > 0 && len(config.EnabledConnectors) > limit {
		return fmt.Errorf("%s tier supports custom policies on a maximum of %d connectors, got %d. Register unlimited connectors, but connectors with custom policies (rate limiting, budgets, time/role access) are limited to %d; upgrade to Enterprise for unlimited connectors with custom policies",
			tier, limit, len(config.EnabledConnectors), limit)
	}
	return nil
}

// EnforceCustomPolicyConnectorLimit truncates the enabled connectors list to the tier's
// custom policy limit. Connectors beyond the limit are dropped and logged.
// Returns the (possibly truncated) list of enabled connectors.
func EnforceCustomPolicyConnectorLimit(config DynamicPolicyConfig) []string {
	tier := resolveConnectorLimitTier()
	var limit int

	switch tier {
	case "enterprise":
		return config.EnabledConnectors // Unlimited
	case "evaluation":
		limit = config.MaxCustomPolicyConnectorsEvaluation
	default: // community
		limit = config.MaxCustomPolicyConnectorsCommunity
	}

	if limit > 0 && len(config.EnabledConnectors) > limit {
		rejected := config.EnabledConnectors[limit:]
		kept := config.EnabledConnectors[:limit]
		log.Printf("[DynamicPolicyEvaluator] %s tier: custom policies limited to %d connectors. Enabled: %v. Rejected (over limit): %v. Order is based on config; reorder MCP_DYNAMIC_POLICIES_CONNECTORS to change priority. Upgrade to Enterprise for unlimited.",
			tier, limit, kept, rejected)
		return kept
	}
	return config.EnabledConnectors
}

// UpdateConfig updates the configuration.
// Thread-safe; takes effect immediately for subsequent evaluations.
// Returns an error if the connector limit is exceeded.
func (e *DynamicPolicyEvaluator) UpdateConfig(config DynamicPolicyConfig) error {
	if err := ValidateCustomPolicyConnectorLimit(config); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = config
	e.httpClient.Timeout = config.Timeout
	log.Printf("[DynamicPolicyEvaluator] Config updated: enabled=%v, endpoint=%s, timeout=%v",
		config.Enabled, config.OrchestratorEndpoint, config.Timeout)
	return nil
}

// IsGracefulDegradationEnabled returns whether graceful degradation is enabled.
func (e *DynamicPolicyEvaluator) IsGracefulDegradationEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.GracefulDegradation
}

// SetOrchestratorEndpoint sets the Orchestrator endpoint URL.
// This should be called after initialization to set the endpoint using
// the Agent's standard orchestrator URL resolution logic.
func (e *DynamicPolicyEvaluator) SetOrchestratorEndpoint(endpoint string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config.OrchestratorEndpoint = endpoint
	log.Printf("[DynamicPolicyEvaluator] Orchestrator endpoint set: %s", endpoint)
}

// =============================================================================
// Global DynamicPolicyEvaluator Instance (Singleton Pattern)
// =============================================================================

var (
	globalDynamicEvaluator   *DynamicPolicyEvaluator
	globalDynamicEvaluatorMu sync.RWMutex
)

// InitGlobalDynamicPolicyEvaluator initializes the global dynamic policy evaluator.
// This should be called once during application startup.
// If not called, GetGlobalDynamicPolicyEvaluator returns nil (dynamic evaluation disabled).
func InitGlobalDynamicPolicyEvaluator() {
	globalDynamicEvaluatorMu.Lock()
	defer globalDynamicEvaluatorMu.Unlock()

	if globalDynamicEvaluator == nil {
		globalDynamicEvaluator = NewDynamicPolicyEvaluatorFromEnv()
	}
}

// InitGlobalDynamicPolicyEvaluatorWithConfig initializes with specific config (for testing).
func InitGlobalDynamicPolicyEvaluatorWithConfig(config DynamicPolicyConfig) {
	globalDynamicEvaluatorMu.Lock()
	defer globalDynamicEvaluatorMu.Unlock()

	globalDynamicEvaluator = NewDynamicPolicyEvaluator(config)
}

// GetGlobalDynamicPolicyEvaluator returns the global dynamic policy evaluator.
// Returns nil if not initialized (dynamic evaluation is skipped).
func GetGlobalDynamicPolicyEvaluator() *DynamicPolicyEvaluator {
	globalDynamicEvaluatorMu.RLock()
	defer globalDynamicEvaluatorMu.RUnlock()
	return globalDynamicEvaluator
}

// SetGlobalDynamicPolicyEvaluator sets the global evaluator (for testing).
func SetGlobalDynamicPolicyEvaluator(evaluator *DynamicPolicyEvaluator) {
	globalDynamicEvaluatorMu.Lock()
	defer globalDynamicEvaluatorMu.Unlock()
	globalDynamicEvaluator = evaluator
}

// ResetGlobalDynamicPolicyEvaluator resets the global evaluator (for testing).
func ResetGlobalDynamicPolicyEvaluator() {
	globalDynamicEvaluatorMu.Lock()
	defer globalDynamicEvaluatorMu.Unlock()
	globalDynamicEvaluator = nil
}

// SetGlobalOrchestratorEndpoint sets the Orchestrator endpoint on the global evaluator.
// This should be called after InitGlobalDynamicPolicyEvaluator() to configure
// the endpoint using the Agent's standard orchestrator URL resolution.
func SetGlobalOrchestratorEndpoint(endpoint string) {
	globalDynamicEvaluatorMu.RLock()
	evaluator := globalDynamicEvaluator
	globalDynamicEvaluatorMu.RUnlock()

	if evaluator != nil {
		evaluator.SetOrchestratorEndpoint(endpoint)
	}
}
