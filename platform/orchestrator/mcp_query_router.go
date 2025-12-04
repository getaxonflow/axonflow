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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// MCPQueryRouter handles routing MCP queries to agent's MCP handler
// This bridges the gap between SDK "mcp-query" requests and agent MCP endpoints
type MCPQueryRouter struct {
	agentEndpoint string
	httpClient    *http.Client
}

// NewMCPQueryRouter creates a new MCP query router
func NewMCPQueryRouter(agentEndpoint string) *MCPQueryRouter {
	return &MCPQueryRouter{
		agentEndpoint: agentEndpoint,
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // MCP queries can take time (e.g., Amadeus API)
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Agent uses self-signed certs in current setup
				},
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
		connector, req.Query, req.User.Email)

	// Build agent MCP request
	// Format matches platform/agent/mcp_handler.go:228-242 (MCPQueryRequest)
	// Note: OrchestratorRequest doesn't have UserToken field - it's in the SDK layer
	// Extract user token from context if provided, otherwise use empty string
	userToken, _ := req.Context["user_token"].(string)

	agentReq := map[string]interface{}{
		"client_id":  req.Client.ID,
		"user_token": userToken,
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
		log.Printf("[MCPRouter] Agent MCP query failed: %s (duration: %v)", errMsg, duration)
		return &OrchestratorResponse{
			RequestID:      req.RequestID,
			Success:        false,
			Error:          errMsg,
			ProcessingTime: duration.String(),
		}, nil
	}

	// Extract response data
	success, _ := agentResp["success"].(bool)
	rows, _ := agentResp["rows"].([]interface{})
	rowCount, _ := agentResp["row_count"].(float64) // JSON numbers are float64
	durationMs, _ := agentResp["duration_ms"].(float64)

	log.Printf("[MCPRouter] Agent MCP query succeeded - connector: %s, rows: %d, agent_duration: %.0fms, total_duration: %v",
		connector, int(rowCount), durationMs, duration)

	// Build orchestrator response
	// Format matches OrchestratorResponse structure
	return &OrchestratorResponse{
		RequestID: req.RequestID,
		Success:   success,
		Data: map[string]interface{}{
			"connector":  connector,
			"rows":       rows,
			"row_count":  int(rowCount),
			"duration":   fmt.Sprintf("%.0fms", durationMs),
			"metadata": map[string]interface{}{
				"processed_at":      time.Now().Format(time.RFC3339),
				"processed_for_role": req.User.Role,
				"request_id":        req.RequestID,
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
