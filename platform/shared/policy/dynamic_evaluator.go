// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"axonflow/platform/shared/secretenv"
	"axonflow/platform/shared/serviceauth"
)

// errOrchestratorAuthRejected marks an orchestrator response of 401/403 on the
// agent→orchestrator dynamic-policy hop (#3068).
//
// It exists so EvaluateWithGracefulDegradation can tell a PERMANENT condition
// apart from a transient one. Graceful degradation is a liveness feature: it
// absorbs an orchestrator that is briefly down, restarting or slow, on the
// theory that the next call will succeed. An authentication rejection is the
// opposite — it is deterministic and will 403 on every retry for the life of
// the process. Absorbing it converts MCP connector policy enforcement into
// silent allow-all with policies_evaluated: 0, the exact shape of #3048/#3049.
//
// Reaching this state requires no operator error at all: the proxy-auth token
// is timestamp-signed with serviceauth.DefaultClockSkew, so NTP failure on
// either the agent or the orchestrator host produces the identical permanent
// 403. So do secret rotation skew, two task definitions that drifted, and one
// side reading the secret from Secrets Manager while the other reads env.
//
// Always wrap this with %w, and never re-wrap the result in a way that drops
// the chain — EvaluateWithGracefulDegradation matches it with errors.Is.
var errOrchestratorAuthRejected = errors.New("orchestrator rejected the internal-service credential")

// ErrOrchestratorAuthRejected exposes the sentinel above to callers outside
// this package that need to distinguish a permanent authentication failure
// from a transient outage. Use errors.Is, never string matching.
var ErrOrchestratorAuthRejected = errOrchestratorAuthRejected

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
	// tokenGen signs the X-Axonflow-Proxy-Auth header on the
	// agent→orchestrator hop (#3068). Built once at construction from
	// AXONFLOW_INTERNAL_SERVICE_SECRET; nil when the secret is unset.
	//
	// This is a governance-critical hop with a fail-OPEN default: the
	// orchestrator refuses token-less requests, Evaluate turns that into an
	// error, and EvaluateWithGracefulDegradation converts the error into
	// {Allowed: true, PoliciesEvaluated: 0} because GracefulDegradation
	// defaults to true. Without a token, MCP dynamic policy enforcement would
	// therefore degrade SILENTLY to allow-all — the same failure shape as
	// #3048/#3049. Hence newProxyTokenGenerator's loud one-time warning.
	tokenGen *serviceauth.TokenGenerator
}

// newProxyTokenGenerator builds the internal-service token generator from the
// shared secret, warning loudly (once) if it is absent — see the tokenGen field
// comment for why a missing token is worse here than a plain failure.
//
// secretenv.Get trims Secrets-Manager-derived whitespace so the HMAC this
// computes matches what the orchestrator's validator computes from the same
// logical secret.
func newProxyTokenGenerator() *serviceauth.TokenGenerator {
	secret := secretenv.Get(serviceauth.SecretEnvVar)
	if secret == "" {
		dynamicEvaluatorSecretWarnOnce.Do(func() {
			log.Printf("[DynamicPolicyEvaluator] [SECURITY] %s is not set. The orchestrator will REFUSE "+
				"dynamic-policy evaluation calls, and with MCP_DYNAMIC_POLICIES_GRACEFUL enabled (default) "+
				"every connector request will be ALLOWED with 0 policies evaluated. Set %s to the same "+
				"value on the agent and the orchestrator, or set MCP_DYNAMIC_POLICIES_GRACEFUL=false to "+
				"fail closed instead.", serviceauth.SecretEnvVar, serviceauth.SecretEnvVar)
		})
		return nil
	}
	return serviceauth.NewTokenGenerator(secret, nil)
}

var dynamicEvaluatorSecretWarnOnce sync.Once

// dynamicEvaluatorAuthRejectWarnOnce keeps the "the orchestrator refused our
// credential" banner to one line per process instead of one per request.
var dynamicEvaluatorAuthRejectWarnOnce sync.Once

// NewDynamicPolicyEvaluator creates a new dynamic policy evaluator.
func NewDynamicPolicyEvaluator(config DynamicPolicyConfig) *DynamicPolicyEvaluator {
	return &DynamicPolicyEvaluator{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		tokenGen: newProxyTokenGenerator(),
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
	// Snapshot the config AND the client under one read lock. The client must
	// be read under the lock because UpdateConfig replaces it: reading the field
	// unsynchronized raced with that write (`go test -race` on this package
	// flagged it, pre-existing).
	e.mu.RLock()
	config := e.config
	httpClient := e.httpClient
	tokenGen := e.tokenGen
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
	// #3068: authenticate the agent→orchestrator hop. Without this the
	// orchestrator's router-level gate refuses the call and graceful
	// degradation silently allows the connector request with zero policies
	// evaluated. See the tokenGen field comment.
	if tokenGen != nil {
		httpReq.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(tokenGen))
	}

	// Execute request
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("orchestrator request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for non-2xx status.
	//
	// #3068: 401/403 is singled out and wrapped with errOrchestratorAuthRejected
	// so graceful degradation can refuse to absorb it. See that sentinel's doc
	// comment. The wrap uses %w and is the outermost wrap on this path, so
	// errors.Is works for every caller.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: orchestrator returned status %d: %s",
			errOrchestratorAuthRejected, resp.StatusCode, string(respBody))
	}
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
	tokenGen := e.tokenGen
	e.mu.RUnlock()

	// #3068: graceful degradation exists to absorb a TRANSIENT orchestrator
	// outage. A missing internal-service secret is not transient — it is a
	// permanent, deterministic 403 on every call, so letting graceful
	// degradation absorb it would convert policy enforcement into allow-all for
	// the life of the process, silently, with policies_evaluated: 0.
	//
	// Before this change a secret-less deployment WORKED, because the
	// orchestrator had no authentication gate. It must not now degrade to
	// allow-all instead — that would be a strictly worse outcome than the bug
	// being fixed. Fail CLOSED so the misconfiguration is loud and blocking;
	// the boot-time warning from newProxyTokenGenerator names the remedy.
	// GracefulDegradation still applies normally once a secret is configured.
	if tokenGen == nil {
		graceful = false
	}

	startTime := time.Now()

	resp, err := e.Evaluate(ctx, req)

	// Build info structure regardless of success
	info := &DynamicPolicyInfo{
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
	}

	if err != nil {
		// #3068 B-1: an authentication rejection is PERMANENT. A present-but-
		// wrong secret, a rotation skew, drifted task definitions, or plain
		// clock drift past serviceauth.DefaultClockSkew all produce a
		// deterministic 403 that will never succeed on retry. Letting graceful
		// degradation absorb it would silently turn connector policy
		// enforcement into allow-all with policies_evaluated: 0 — the shape of
		// #3048/#3049 and strictly worse than the bug #3068 fixes. The
		// tokenGen == nil case above is the same rule for the missing-secret
		// spelling; this covers every other way the credential can be refused.
		if errors.Is(err, errOrchestratorAuthRejected) {
			graceful = false
			dynamicEvaluatorAuthRejectWarnOnce.Do(func() {
				log.Printf("[DynamicPolicyEvaluator] [SECURITY] the orchestrator REJECTED this agent's "+
					"internal-service credential. This is permanent, not transient, so graceful degradation "+
					"is being overridden and MCP dynamic policy evaluation will FAIL CLOSED. Check that %s is "+
					"byte-identical on the agent and the orchestrator, and that both hosts' clocks agree to "+
					"within %s.", serviceauth.SecretEnvVar, serviceauth.DefaultClockSkew)
			})
		}

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
		upgradeHint := "get a free Evaluation license for 5 connectors at https://getaxonflow.com/evaluation-license"
		if tier == "evaluation" {
			upgradeHint = "upgrade to Enterprise for unlimited connectors at https://getaxonflow.com/enterprise"
		}
		return fmt.Errorf("%s tier supports custom policies on a maximum of %d connectors, got %d. Register unlimited connectors, but connectors with custom policies (rate limiting, budgets, time/role access) are limited to %d; %s",
			tier, limit, len(config.EnabledConnectors), limit, upgradeHint)
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
		upgradeHint := "Get a free Evaluation license for 5 connectors at https://getaxonflow.com/evaluation-license"
		if tier == "evaluation" {
			upgradeHint = "Upgrade to Enterprise for unlimited connectors at https://getaxonflow.com/enterprise"
		}
		log.Printf("[DynamicPolicyEvaluator] %s tier: custom policies limited to %d connectors. Enabled: %v. Rejected (over limit): %v. Order is based on config; reorder MCP_DYNAMIC_POLICIES_CONNECTORS to change priority. %s",
			tier, limit, kept, rejected, upgradeHint)
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
	// REPLACE the client rather than mutating http.Client.Timeout in place: an
	// in-flight Evaluate holds no lock while inside client.Do, so writing the
	// field raced with net/http reading it (pre-existing, caught by -race).
	// Replacing under the write lock leaves any in-flight request on the old
	// client, which is correct — a config change applies from the next call.
	e.httpClient = &http.Client{Timeout: config.Timeout}
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
