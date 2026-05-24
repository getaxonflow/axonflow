// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const maxRequestBodyBytes = 10 << 20  // 10 MB
const maxResponseBodyBytes = 1 << 20  // 1 MB

// JSON-RPC 2.0 structures for MCP protocol (HTTP transport).

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// AxonFlow Decision API structures — mirrors POST /api/v1/decide contract.

type DecideRequest struct {
	Stage          string                 `json:"stage"`
	CallerIdentity CallerIdentity         `json:"caller_identity"`
	Target         DecisionTarget         `json:"target"`
	Query          string                 `json:"query"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

type CallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

type DecisionTarget struct {
	Type string `json:"type,omitempty"`
	Tool string `json:"tool,omitempty"`
}

type DecideResponse struct {
	Verdict           string               `json:"verdict"`
	DecisionID        string               `json:"decision_id"`
	TraceID           string               `json:"trace_id"`
	Reasons           []string             `json:"reasons,omitempty"`
	Obligations       []DecisionObligation `json:"obligations"`
	EvaluatedPolicies []string             `json:"evaluated_policies"`
	Stage             string               `json:"stage,omitempty"`
	ExpiresAt         string               `json:"expires_at"`
}

type DecisionObligation struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
}

type AdapterConfig struct {
	ListenAddr       string
	MCPServerURL     string
	AxonFlowEndpoint string
	GatewayID        string
	OrgID            string
	TenantID         string
	FailOpen         bool
	InterceptMethods map[string]bool
	ClientID         string
	ClientSecret     string
	RequestTimeout   time.Duration
}

func loadConfig() AdapterConfig {
	interceptRaw := envOr("MCP_INTERCEPT_METHODS", "tools/call")
	methods := make(map[string]bool)
	for _, m := range strings.Split(interceptRaw, ",") {
		m = strings.TrimSpace(m)
		if m != "" {
			methods[m] = true
		}
	}

	timeout, err := time.ParseDuration(envOr("MCP_REQUEST_TIMEOUT", "10s"))
	if err != nil {
		timeout = 10 * time.Second
	}

	return AdapterConfig{
		ListenAddr:       envOr("MCP_ADAPTER_LISTEN", ":9090"),
		MCPServerURL:     envOr("MCP_SERVER_URL", "http://localhost:9091"),
		AxonFlowEndpoint: envOr("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		GatewayID:        envOr("MCP_GATEWAY_ID", "mcp-gateway"),
		OrgID:            envOr("AXONFLOW_ORG_ID", ""),
		TenantID:         envOr("AXONFLOW_TENANT_ID", ""),
		FailOpen:         envOr("MCP_FAIL_MODE", "closed") == "open",
		InterceptMethods: methods,
		ClientID:         envOr("AXONFLOW_CLIENT_ID", "mcp-adapter"),
		ClientSecret:     envOr("AXONFLOW_CLIENT_SECRET", ""),
		RequestTimeout:   timeout,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	cfg := loadConfig()

	log.Printf("MCP PEP Adapter starting on %s", cfg.ListenAddr)
	log.Printf("  AxonFlow endpoint: %s", cfg.AxonFlowEndpoint)
	log.Printf("  MCP server:        %s", cfg.MCPServerURL)
	log.Printf("  Gateway ID:        %s", cfg.GatewayID)
	log.Printf("  Fail mode:         %s", failModeLabel(cfg.FailOpen))
	log.Printf("  Intercepted:       %v", interceptedList(cfg.InterceptMethods))

	handler := &mcpAdapter{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.RequestTimeout},
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func failModeLabel(open bool) string {
	if open {
		return "open"
	}
	return "closed"
}

func interceptedList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type mcpAdapter struct {
	cfg    AdapterConfig
	client *http.Client
}

func (a *mcpAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "healthy",
			"service": "mcp-pep-adapter",
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBodyBytes))
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "failed to read request body", http.StatusBadRequest)
		return
	}

	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		writeJSONRPCError(w, nil, -32700, "invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

	if rpcReq.JSONRPC != "2.0" {
		writeJSONRPCError(w, rpcReq.ID, -32600, "jsonrpc must be \"2.0\"", http.StatusBadRequest)
		return
	}

	if !a.cfg.InterceptMethods[rpcReq.Method] {
		a.forwardToMCP(w, r, body)
		return
	}

	a.handleInterceptedCall(w, r, body, &rpcReq)
}

// clientError is returned by callDecisionAPI for 4xx responses. Fail-open
// never applies to client errors — they indicate misconfiguration.
type clientError struct {
	StatusCode int
	Body       string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("decision API returned %d: %s", e.StatusCode, e.Body)
}

func (a *mcpAdapter) handleInterceptedCall(w http.ResponseWriter, r *http.Request, rawBody []byte, rpcReq *JSONRPCRequest) {
	var params ToolCallParams
	if err := json.Unmarshal(rpcReq.Params, &params); err != nil {
		writeJSONRPCError(w, rpcReq.ID, -32602, "invalid tools/call params", http.StatusBadRequest)
		return
	}

	query := buildQuery(params)

	decideReq := DecideRequest{
		Stage: "tool",
		CallerIdentity: CallerIdentity{
			GatewayID: a.cfg.GatewayID,
			OrgID:     a.cfg.OrgID,
			TenantID:  a.cfg.TenantID,
		},
		Target: DecisionTarget{
			Type: "tool",
			Tool: params.Name,
		},
		Query: query,
		Context: map[string]interface{}{
			"tool_name":      params.Name,
			"tool_arguments": params.Arguments,
			"protocol":       "mcp",
		},
	}

	decideResp, statusCode, err := a.callDecisionAPI(r.Context(), decideReq, r.Header.Get("Traceparent"))
	if err != nil {
		log.Printf("Decision API error: %v", err)
		var ce *clientError
		if errors.As(err, &ce) {
			writeJSONRPCError(w, rpcReq.ID, -32003, fmt.Sprintf("policy service client error (%d)", ce.StatusCode), http.StatusOK)
			return
		}
		if a.cfg.FailOpen {
			log.Printf("Fail-open: forwarding despite Decision API error")
			a.forwardToMCP(w, r, rawBody)
			return
		}
		writeJSONRPCError(w, rpcReq.ID, -32003, "policy service unavailable (fail-closed)", http.StatusOK)
		return
	}

	if statusCode == http.StatusServiceUnavailable {
		log.Printf("Decision API circuit breaker tripped (503)")
		if a.cfg.FailOpen {
			log.Printf("Fail-open: forwarding despite circuit breaker trip")
			a.forwardToMCP(w, r, rawBody)
			return
		}
		writeJSONRPCErrorWithData(w, rpcReq.ID, -32003, "policy service circuit breaker tripped (fail-closed)", map[string]interface{}{"trace_id": decideResp.TraceID}, http.StatusOK)
		return
	}

	switch decideResp.Verdict {
	case "allow":
		log.Printf("ALLOW tool=%s decision_id=%s trace_id=%s", params.Name, decideResp.DecisionID, decideResp.TraceID)
		a.forwardToMCPWithTrace(w, r, rawBody, decideResp.TraceID)
	case "deny":
		reason := "request blocked by policy"
		if len(decideResp.Reasons) > 0 {
			reason = decideResp.Reasons[0]
		}
		log.Printf("DENY tool=%s decision_id=%s trace_id=%s reason=%s", params.Name, decideResp.DecisionID, decideResp.TraceID, reason)

		denyData := map[string]interface{}{
			"decision_id":        decideResp.DecisionID,
			"trace_id":           decideResp.TraceID,
			"evaluated_policies": decideResp.EvaluatedPolicies,
			"reasons":            decideResp.Reasons,
		}
		writeJSONRPCErrorWithData(w, rpcReq.ID, -32001, reason, denyData, http.StatusOK)
	case "needs_approval":
		log.Printf("NEEDS_APPROVAL tool=%s decision_id=%s trace_id=%s", params.Name, decideResp.DecisionID, decideResp.TraceID)
		writeJSONRPCErrorWithData(w, rpcReq.ID, -32002, "tool call requires approval", map[string]interface{}{"trace_id": decideResp.TraceID}, http.StatusOK)
	default:
		log.Printf("UNKNOWN verdict=%s tool=%s decision_id=%s", decideResp.Verdict, params.Name, decideResp.DecisionID)
		if a.cfg.FailOpen {
			a.forwardToMCPWithTrace(w, r, rawBody, decideResp.TraceID)
			return
		}
		writeJSONRPCError(w, rpcReq.ID, -32003, "unknown verdict from policy service (fail-closed)", http.StatusOK)
	}
}

func buildQuery(params ToolCallParams) string {
	if params.Arguments == nil {
		return fmt.Sprintf("tool_call: %s", params.Name)
	}
	argBytes, err := json.Marshal(params.Arguments)
	if err != nil {
		return fmt.Sprintf("tool_call: %s", params.Name)
	}
	return fmt.Sprintf("tool_call: %s args: %s", params.Name, string(argBytes))
}

func (a *mcpAdapter) callDecisionAPI(ctx context.Context, req DecideRequest, traceparent string) (*DecideResponse, int, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal decide request: %w", err)
	}

	url := strings.TrimRight(a.cfg.AxonFlowEndpoint, "/") + "/api/v1/decide"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Id", a.cfg.ClientID)
	if a.cfg.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", a.cfg.ClientSecret)
	}
	if traceparent != "" {
		httpReq.Header.Set("Traceparent", traceparent)
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("decision API call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read decision response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, resp.StatusCode, &clientError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return nil, resp.StatusCode, fmt.Errorf("decision API returned %d: %s", resp.StatusCode, string(respBody))
	}

	var decideResp DecideResponse
	if err := json.Unmarshal(respBody, &decideResp); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode decision response: %w", err)
	}

	return &decideResp, resp.StatusCode, nil
}

func (a *mcpAdapter) forwardToMCP(w http.ResponseWriter, r *http.Request, body []byte) {
	a.forwardToMCPWithTrace(w, r, body, "")
}

func (a *mcpAdapter) forwardToMCPWithTrace(w http.ResponseWriter, r *http.Request, body []byte, traceID string) {
	httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, a.cfg.MCPServerURL, bytes.NewReader(body))
	if err != nil {
		writeJSONRPCError(w, nil, -32603, "internal proxy error", http.StatusInternalServerError)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if traceID != "" {
		httpReq.Header.Set("Traceparent", fmt.Sprintf("00-%s-%s-01", traceID, randomSpanID()))
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		writeJSONRPCError(w, nil, -32603, "MCP server unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		writeJSONRPCError(w, nil, -32603, "failed to read MCP response", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if traceID != "" {
		w.Header().Set("X-Trace-Id", traceID)
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func randomSpanID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "0000000000000001"
	}
	return hex.EncodeToString(b)
}

func writeJSONRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string, httpStatus int) {
	writeJSONRPCErrorWithData(w, id, code, message, nil, httpStatus)
}

func writeJSONRPCErrorWithData(w http.ResponseWriter, id json.RawMessage, code int, message string, data map[string]interface{}, httpStatus int) {
	rpcErr := &JSONRPCError{
		Code:    code,
		Message: message,
	}

	if data != nil {
		dataBytes, _ := json.Marshal(data)
		rpcErr.Data = dataBytes
	}

	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   rpcErr,
	}

	var traceID string
	if data != nil {
		traceID, _ = data["trace_id"].(string)
	}
	w.Header().Set("Content-Type", "application/json")
	if traceID != "" {
		w.Header().Set("X-Trace-Id", traceID)
	}
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(resp)
}
