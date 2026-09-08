// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/serviceauth"
)

// Note: Internal service authentication is handled by the shared serviceauth package.

// MCPQueryRouter handles routing MCP queries to agent's MCP handler
// This bridges the gap between SDK "mcp-query" requests and agent MCP endpoints
type MCPQueryRouter struct {
	agentEndpoint string
	httpClient    *http.Client
}

// NewMCPQueryRouter creates a new MCP query router
func NewMCPQueryRouter(agentEndpoint string) *MCPQueryRouter {
	return NewMCPQueryRouterWithTLS(agentEndpoint, false)
}

// NewMCPQueryRouterWithTLS creates a new MCP query router with configurable TLS verification
// insecureSkipVerify should only be true in development/testing environments
func NewMCPQueryRouterWithTLS(agentEndpoint string, insecureSkipVerify bool) *MCPQueryRouter {
	// SECURITY: Default to secure TLS verification. Only skip in explicit dev scenarios.
	// In production, proper certificates should be configured.
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if insecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	return &MCPQueryRouter{
		agentEndpoint: agentEndpoint,
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // MCP queries can take time (e.g., Amadeus API)
			Transport: &http.Transport{
				TLSClientConfig:     tlsConfig,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// RouteToAgent forwards an MCP query request to the agent's MCP handler
// This is called when orchestrator receives a request with RequestType == "mcp-query"
func (r *MCPQueryRouter) RouteToAgent(ctx context.Context, req OrchestratorRequest) (*OrchestratorResponse, error) {
	startTime := time.Now()

	// Extract MCP parameters from context
	connector, ok := req.Context["connector"].(string)
	if !ok || connector == "" {
		return nil, fmt.Errorf("missing 'connector' in context")
	}

	params, ok := req.Context["params"].(map[string]interface{})
	if !ok {
		params = make(map[string]interface{})
	}

	log.Printf("[MCPRouter] Routing query to agent - connector: %s, query: %s, user: %s",
		logutil.Sanitize(connector), logutil.Sanitize(req.Query), logutil.Sanitize(req.User.Email))

	tenantID := req.User.TenantID
	if tenantID == "" {
		tenantID = req.Client.TenantID
	}

	// THE ORGANIZATION, ON THE SAME TWO RUNGS AS THE TENANT (#3828).
	//
	// This hop rebuilds the agent request from scratch, and it used to carry
	// tenancy but not the organization. The agent's internal-service branch
	// reads the org from X-Org-ID, and this function is the one internal-service
	// caller that never set it.
	//
	// An earlier revision of this comment quoted authenticator.go's "trusted
	// because internal service auth already proved the caller is the
	// orchestrator via HMAC" as the warrant. That sentence is TRUE on an
	// enterprise deployment and FALSE on community / community-SaaS, where
	// allowFallback admits the PUBLIC fallback constants when no
	// AXONFLOW_INTERNAL_SERVICE_SECRET is configured - so it was deleted from
	// authenticator.go in this change, and quoting it here kept it alive.
	//
	// The bound that holds on every edition: X-Org-ID selects a per-organization
	// POSTURE and POLICY SCOPE. It is not an authorization decision on its own,
	// and it cannot widen tenancy - the tenant comes from hints.TenantID and
	// GetConnectorForTenant keys on that, not on this header.
	//
	// The consequence was not a broken request. It was a SILENTLY EMPTY
	// WINDOW: with no org, the MCP call sites evaluate with orgID="",
	// OrgScopePtr("") returns nil, orgScopeOf falls back to the tenant id, and
	// the decision shadow's Observe refuses every observation on the `mcp`
	// plane as "an org scope but no org id". Ten of ten on the v10.4.0 gate (b)
	// run. And it is invisible exactly where it is compensated: the refusal
	// branch only runs where a per-organization mode store is wired, which is
	// enterprise-only, so identical traffic COMPARED on community-SaaS and
	// recorded nothing on production-US.
	//
	// The same two rungs as the tenant above, and in the same order, because
	// the two facts travel together: a request whose user context carries one
	// carries the other, and a fall-back to a DIFFERENT source for each would
	// pair a user's tenant with a client's org.
	orgID := req.User.OrgID
	if orgID == "" {
		orgID = req.Client.OrgID
	}

	// Build agent MCP request
	// Format matches platform/agent/mcp_handler.go:228-242 (MCPQueryRequest)
	// Use internal service credentials for orchestrator-to-agent authentication.
	// This allows the agent to recognize this as an internal service call and bypass
	// normal client validation (see serviceauth.IsValidInternalServiceRequest).
	agentReq := map[string]interface{}{
		"client_id":  serviceauth.ClientID,
		"user_token": serviceauth.GetInternalServiceToken(internalTokenGenerator),
		"tenant_id":  tenantID,
		"connector":  connector,
		"statement":  req.Query, // e.g., "search_flights", "search_hotels"
		"parameters": params,
		"timeout":    "30s",
	}

	// Marshal request
	reqBody, err := json.Marshal(agentReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal agent request: %w", err)
	}

	// Make HTTP request to agent MCP handler
	// Agent registers MCP query endpoint at /mcp/resources/query (see platform/agent/mcp_handler.go:152)
	url := fmt.Sprintf("%s/mcp/resources/query", r.agentEndpoint)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	// #3828: the organization, on the channel the agent already trusts for it.
	//
	// A HEADER RATHER THAN A BODY FIELD, deliberately. agentReq above is a
	// plain JSON body, and a body-borne org_id would be a second spelling of a
	// tenancy selector on a handler that also serves external callers - the
	// shape X-Tenant-ID was deprecated for. X-Org-ID is read ONLY inside the
	// agent's internal-service branch.
	//
	// THAT BRANCH IS HMAC-GATED ON AN ENTERPRISE DEPLOYMENT AND NOT ON A
	// COMMUNITY ONE (R3 rounds 1-3, F11/G14/H2): `allowFallback` accepts the
	// public fallback constants where no shared secret is configured.
	//
	// DO NOT SUMMARISE THE BOUND HERE. Three revisions of a one-line summary
	// were wrong in three different ways, the last claiming the org "grants
	// nothing" when a per-org posture row can flip an action to block. The
	// agent-side comment on ResolveUser carries the traced version, and one
	// place stating it is the point. The header is still the right channel.
	//
	// Set only when non-empty: an empty header and an absent one both read as
	// "no organization" at the agent, and sending the empty one would put a
	// meaningless header on every community-mode hop.
	if orgID != "" {
		httpReq.Header.Set("X-Org-ID", orgID)
	}

	// Execute request
	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("agent MCP request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read agent response: %w", err)
	}

	// Parse agent response
	var agentResp map[string]interface{}
	if err := json.Unmarshal(respBody, &agentResp); err != nil {
		return nil, fmt.Errorf("failed to parse agent response: %w", err)
	}

	duration := time.Since(startTime)

	// Check for errors
	if resp.StatusCode != http.StatusOK {
		errMsg, _ := agentResp["error"].(string)
		if errMsg == "" {
			errMsg = fmt.Sprintf("agent returned status %d", resp.StatusCode)
		}
		log.Printf("[MCPRouter] Agent MCP query failed: %s (duration: %v)", logutil.Sanitize(errMsg), duration)
		return &OrchestratorResponse{
			RequestID:      req.RequestID,
			Success:        false,
			Error:          errMsg,
			ProcessingTime: duration.String(),
		}, nil
	}

	// Extract response data
	// Agent returns "data" array (see agent mcp_handler.go)
	success, _ := agentResp["success"].(bool)
	rows, _ := agentResp["data"].([]interface{})    // Agent uses "data" for results
	rowCount, _ := agentResp["row_count"].(float64) // JSON numbers are float64
	durationMs, _ := agentResp["duration_ms"].(float64)

	log.Printf("[MCPRouter] Agent MCP query succeeded - connector: %s, rows: %d, agent_duration: %.0fms, total_duration: %v",
		logutil.Sanitize(connector), int(rowCount), durationMs, duration)

	// Build orchestrator response
	// Format matches OrchestratorResponse structure
	return &OrchestratorResponse{
		RequestID: req.RequestID,
		Success:   success,
		Data: map[string]interface{}{
			"connector": connector,
			"rows":      rows,
			"row_count": int(rowCount),
			"duration":  fmt.Sprintf("%.0fms", durationMs),
			"metadata": map[string]interface{}{
				"processed_at":       time.Now().Format(time.RFC3339),
				"processed_for_role": req.User.Role,
				"request_id":         req.RequestID,
			},
		},
		ProcessingTime: duration.String(),
		PolicyInfo: &PolicyEvaluationResult{
			Allowed:          true,
			AppliedPolicies:  []string{}, // MCP queries go through agent's policy enforcement
			ProcessingTimeMs: duration.Milliseconds(),
		},
	}, nil
}

// IsHealthy checks if the MCP query router can reach the agent
func (r *MCPQueryRouter) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/health", r.agentEndpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("Error closing response body: %v", err)
		}
	}()

	return resp.StatusCode == http.StatusOK
}
