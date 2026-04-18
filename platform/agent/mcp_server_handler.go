// Copyright 2025-2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/serviceauth"

	"github.com/gorilla/mux"
)

// =============================================================================
// MCP Server Protocol Handler
//
// Exposes AxonFlow as a standards-compliant MCP server (JSON-RPC 2.0 over HTTP).
// Follows the Streamable HTTP transport spec (2025-06-18).
//
// Tools:
//   check_policy    → evaluateInputPolicies() (Agent-internal, ~3-10ms)
//   check_output    → evaluateOutputPolicies() (Agent-internal, ~3-10ms)
//   audit_tool_call → POST /api/v1/audit/tool-call (Orchestrator, ~50-100ms)
//   list_policies   → GET /api/v1/static-policies (Orchestrator, ~50-100ms)
//   get_policy_stats→ GET /api/v1/audit/summary (Orchestrator, ~50-100ms)
//
// Reference: https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
// Epic: getaxonflow/axonflow-enterprise#1484
// =============================================================================

const (
	mcpProtocolVersion  = "2025-06-18"
	mcpProtocolLegacy   = "2024-11-05"
	mcpServerName       = "axonflow"
	mcpServerVersion    = "1.0.0"
	mcpSessionHeaderKey = "Mcp-Session-Id"
	mcpProtocolHeader   = "MCP-Protocol-Version"
	mcpSessionTTL       = 24 * time.Hour
	mcpMaxSessions      = 1000
	mcpMaxRequestBody   = 1 << 20 // 1 MB
	mcpMaxResponseBody  = 10 << 20 // 10 MB from orchestrator
)

// orchestratorHTTPClient is reused across all Orchestrator proxy calls.
var orchestratorHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Custom JSON-RPC error code for authentication failures.
const jsonRPCAuthError = -32001

// --- JSON-RPC 2.0 Types ---

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      interface{}   `json:"id,omitempty"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *jsonRPCError `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

const (
	jsonRPCParseError     = -32700
	jsonRPCInvalidRequest = -32600
	jsonRPCMethodNotFound = -32601
	jsonRPCInvalidParams  = -32602
	jsonRPCInternalError  = -32603
)

// --- MCP Protocol Types ---

type mcpInitializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	Capabilities    struct {
		Tools *struct {
			ListChanged bool `json:"listChanged,omitempty"`
		} `json:"tools,omitempty"`
	} `json:"capabilities"`
	ServerInfo struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type mcpToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolCallResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

// --- Session Management ---

type mcpSession struct {
	id        string
	createdAt time.Time
	lastUsed  time.Time
	tenantID  string
	userID    string
	userEmail string // per-user identity from X-User-Email header; distinct from userID so Plugin Batch 1 endpoints scope by real email, not synthetic "0".
	userRole  string
	clientID  string
}

var (
	mcpSessions   = make(map[string]*mcpSession)
	mcpSessionsMu sync.RWMutex
)

// generateSecureSessionID produces a cryptographically secure session ID.
// Format: axonflow-{24 hex chars} (96 bits of entropy).
// Panics if the system CSPRNG is broken — this is intentional; a degraded
// fallback would silently produce guessable IDs.
func generateSecureSessionID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		// CSPRNG failure is a fatal condition — do not silently degrade.
		log.Fatalf("[MCP-Server] FATAL: crypto/rand.Read failed: %v", err)
	}
	return "axonflow-" + hex.EncodeToString(b)
}

// evictStaleSessions removes sessions older than mcpSessionTTL and enforces
// mcpMaxSessions. Called under write lock.
func evictStaleSessions() {
	cutoff := time.Now().Add(-mcpSessionTTL)
	for id, s := range mcpSessions {
		if s.lastUsed.Before(cutoff) {
			delete(mcpSessions, id)
		}
	}
	// If still over limit, remove oldest by lastUsed
	for len(mcpSessions) > mcpMaxSessions {
		var oldestID string
		var oldestTime time.Time
		for id, s := range mcpSessions {
			if oldestID == "" || s.lastUsed.Before(oldestTime) {
				oldestID = id
				oldestTime = s.lastUsed
			}
		}
		if oldestID != "" {
			delete(mcpSessions, oldestID)
		}
	}
}

// --- Tool Definitions ---

func getMCPTools() []mcpTool {
	return []mcpTool{
		{
			Name:        "check_policy",
			Description: "Evaluate tool inputs against AxonFlow governance policies before execution. Returns whether the operation is allowed or blocked, with policy details.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"connector_type": map[string]interface{}{
						"type":        "string",
						"description": "Tool identifier (e.g., claude_code.Bash, claude_code.Write)",
					},
					"statement": map[string]interface{}{
						"type":        "string",
						"description": "The tool input to evaluate (command, query, file content)",
					},
					"operation": map[string]interface{}{
						"type":    "string",
						"enum":    []string{"execute", "query"},
						"default": "execute",
					},
					"parameters": map[string]interface{}{
						"type": "object",
					},
				},
				"required": []string{"connector_type", "statement"},
			},
		},
		{
			Name:        "check_output",
			Description: "Scan tool output for PII, secrets, and policy violations. Returns whether output is allowed, with redacted data if PII was found.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"connector_type": map[string]interface{}{
						"type":        "string",
						"description": "Tool identifier that produced this output",
					},
					"response_data": map[string]interface{}{
						"type":  "array",
						"items": map[string]interface{}{"type": "object"},
					},
					"message": map[string]interface{}{
						"type":        "string",
						"description": "Text content to scan for PII and secrets",
					},
				},
				"required": []string{"connector_type"},
			},
		},
		{
			Name:        "audit_tool_call",
			Description: "Record a tool execution in AxonFlow's audit trail for compliance evidence.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"tool_name": map[string]interface{}{
						"type": "string",
					},
					"tool_type": map[string]interface{}{
						"type":    "string",
						"default": "claude_code",
					},
					"input": map[string]interface{}{
						"type": "object",
					},
					"output": map[string]interface{}{
						"type": "object",
					},
					"success": map[string]interface{}{
						"type": "boolean",
					},
					"error_message": map[string]interface{}{
						"type": "string",
					},
					"duration_ms": map[string]interface{}{
						"type": "number",
					},
				},
				"required": []string{"tool_name", "input", "success"},
			},
		},
		{
			Name:        "list_policies",
			Description: "List active governance policies. Returns policy names, categories, patterns, and severity levels.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"category": map[string]interface{}{
						"type": "string",
					},
					"severity": map[string]interface{}{
						"type": "string",
						"enum": []string{"critical", "high", "medium", "low"},
					},
				},
			},
		},
		{
			Name:        "get_policy_stats",
			Description: "Get governance activity summary: total checks, blocks, allows, and top triggered policies.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"from": map[string]interface{}{
						"type":        "string",
						"description": "Start date (ISO 8601)",
					},
					"to": map[string]interface{}{
						"type":        "string",
						"description": "End date (ISO 8601)",
					},
					"connector_type": map[string]interface{}{
						"type": "string",
					},
				},
			},
		},
		{
			Name:        "search_audit_events",
			Description: "Search individual audit event records. Returns tool call details, policy evaluations, and timestamps for compliance evidence and debugging.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"from": map[string]interface{}{
						"type":        "string",
						"description": "Start time (ISO 8601). Defaults to last 15 minutes.",
					},
					"to": map[string]interface{}{
						"type":        "string",
						"description": "End time (ISO 8601). Defaults to now.",
					},
					"request_type": map[string]interface{}{
						"type":        "string",
						"description": "Filter by request type (e.g., tool_call_audit, llm_call)",
					},
					"limit": map[string]interface{}{
						"type":        "number",
						"description": "Max events to return (default: 20, max: 100)",
						"default":     20,
					},
				},
			},
		},
		// --- Plugin Batch 1 (ADR-044 + ADR-043) ---
		// These MCP tools proxy to the new platform HTTP endpoints so
		// agents running in Claude Code / Cursor / Codex / OpenClaw can
		// drive the override lifecycle + explainability without leaving
		// the MCP surface.
		{
			Name:        "explain_decision",
			Description: "Explain a previously-made policy decision (ADR-043). Returns matched policies, risk level, reason, override availability, and a rolling 24h hit count. Use this to answer 'why was this blocked?' when a user sees a deny.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"decision_id": map[string]interface{}{
						"type":        "string",
						"description": "Global decision identifier returned in the original step gate or policy evaluation response.",
					},
				},
				"required": []string{"decision_id"},
			},
		},
		{
			Name:        "create_override",
			Description: "Create a governed session override for a policy that would otherwise deny (ADR-044). Requires a mandatory free-text justification. TTL clamped server-side (default 60m, hard cap 24h, 0 for critical risk). Critical-risk and allow_override=false policies are rejected.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"policy_id": map[string]interface{}{
						"type":        "string",
						"description": "Policy to override.",
					},
					"policy_type": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"static", "dynamic"},
						"description": "Policy type.",
					},
					"override_reason": map[string]interface{}{
						"type":        "string",
						"description": "Mandatory free-text justification (1-500 chars).",
					},
					"tool_signature": map[string]interface{}{
						"type":        "string",
						"description": "Optional: restrict override to a specific tool name.",
					},
					"ttl_seconds": map[string]interface{}{
						"type":        "number",
						"description": "Requested TTL in seconds. Clamped server-side (default 3600, min 60, max 86400).",
					},
				},
				"required": []string{"policy_id", "policy_type", "override_reason"},
			},
		},
		{
			Name:        "delete_override",
			Description: "Revoke an active session override (ADR-044). Next policy evaluation after revocation will not consult this override. Emits override_revoked audit event.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"override_id": map[string]interface{}{
						"type":        "string",
						"description": "Override ID returned by create_override.",
					},
				},
				"required": []string{"override_id"},
			},
		},
		{
			Name:        "list_overrides",
			Description: "List active session overrides scoped to the caller's tenant (ADR-044). Use to audit or revoke dangling overrides.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"policy_id": map[string]interface{}{
						"type":        "string",
						"description": "Filter to overrides for a specific policy.",
					},
					"include_revoked": map[string]interface{}{
						"type":        "boolean",
						"description": "Include already-revoked overrides in results. Default false.",
					},
				},
			},
		},
	}
}

// --- Registration ---

// RegisterMCPServerHandler registers the MCP server protocol endpoint.
func RegisterMCPServerHandler(r *mux.Router) {
	r.HandleFunc("/api/v1/mcp-server", mcpServerHandler).Methods("POST", "GET", "DELETE", "OPTIONS")
	log.Println("[MCP-Server] Registered MCP server protocol endpoint at /api/v1/mcp-server")
}

// --- Main Handler ---

func mcpServerHandler(w http.ResponseWriter, r *http.Request) {
	// CORS preflight
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Mcp-Session-Id, MCP-Protocol-Version")
		w.Header().Set("Vary", "Origin")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.Method {
	case http.MethodPost:
		handleMCPPost(w, r)
	case http.MethodGet:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		handleMCPSessionDelete(w, r)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func handleMCPPost(w http.ResponseWriter, r *http.Request) {
	// Validate Content-Type (MCP spec: MUST be application/json)
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(ct, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: jsonRPCInvalidRequest, Message: "Content-Type must be application/json"},
		})
		return
	}

	// Validate protocol version header if present.
	// Accept both current (2025-06-18) and legacy (2024-11-05) MCP versions
	// so that clients on either spec revision can connect.
	if pv := r.Header.Get(mcpProtocolHeader); pv != "" && pv != mcpProtocolVersion && pv != mcpProtocolLegacy {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &jsonRPCError{Code: jsonRPCInvalidRequest, Message: fmt.Sprintf("Unsupported protocol version: %s (supported: %s, %s)", pv, mcpProtocolVersion, mcpProtocolLegacy)},
		})
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, mcpMaxRequestBody)

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPCError(w, nil, jsonRPCParseError, "Parse error: invalid JSON")
		return
	}

	if req.JSONRPC != "2.0" {
		writeJSONRPCError(w, req.ID, jsonRPCInvalidRequest, "Invalid JSON-RPC version")
		return
	}

	// Notifications (no ID) — accept silently per spec
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	log.Printf("[MCP-Server] → %s (id=%v, session=%s)", logutil.Sanitize(req.Method), req.ID, logutil.Sanitize(r.Header.Get(mcpSessionHeaderKey)))

	switch req.Method {
	case "initialize":
		handleMCPInitialize(w, r, &req)
	case "tools/list":
		handleMCPToolsList(w, r, &req)
	case "tools/call":
		handleMCPToolsCall(w, r, &req)
	case "ping":
		handleMCPPing(w, r, &req)
	default:
		writeJSONRPCError(w, req.ID, jsonRPCMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func handleMCPSessionDelete(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(mcpSessionHeaderKey)
	if sessionID == "" {
		http.Error(w, "Bad Request: missing session ID", http.StatusBadRequest)
		return
	}

	// Authenticate the delete request — only the session owner can delete
	session := getSessionByID(sessionID)
	if session == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Verify the caller has valid credentials for this session's tenant
	_, _, _, _, clientID, err := authenticateMCPServerRequest(r)
	if err != nil && !isCommunityMode() {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !isCommunityMode() && clientID != session.clientID {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	mcpSessionsMu.Lock()
	delete(mcpSessions, sessionID)
	mcpSessionsMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// --- Method Handlers ---

func handleMCPInitialize(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	tenantID, userID, userEmail, userRole, clientID, err := authenticateMCPServerRequest(r)
	if err != nil {
		writeJSONRPCAuthError(w, req.ID, err.Error())
		return
	}

	now := time.Now()
	sessionID := generateSecureSessionID()
	session := &mcpSession{
		id:        sessionID,
		createdAt: now,
		lastUsed:  now,
		tenantID:  tenantID,
		userID:    userID,
		userEmail: userEmail,
		userRole:  userRole,
		clientID:  clientID,
	}

	mcpSessionsMu.Lock()
	evictStaleSessions()
	mcpSessions[sessionID] = session
	mcpSessionsMu.Unlock()

	log.Printf("[MCP-Server] Session created: %s (tenant=%s, client=%s)", logutil.Sanitize(sessionID), logutil.Sanitize(tenantID), logutil.Sanitize(clientID))

	// Parse initialize params for clientInfo and protocolVersion
	var clientProtocolVersion string
	if req.Params != nil {
		var initParams struct {
			ProtocolVersion string `json:"protocolVersion"`
			ClientInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"clientInfo"`
		}
		if err := json.Unmarshal(req.Params, &initParams); err == nil {
			clientProtocolVersion = initParams.ProtocolVersion
			if initParams.ClientInfo.Name != "" {
				AutoDetectFromClientInfo(usageDB, initParams.ClientInfo.Name)
				log.Printf("[MCP-Server] Client: %s %s", logutil.Sanitize(initParams.ClientInfo.Name), logutil.Sanitize(initParams.ClientInfo.Version))
			}
		}
	}

	// Negotiate protocol version: echo back the client's version if supported.
	// Check both the header and the initialize params (MCP spec sends it in params).
	negotiatedVersion := mcpProtocolVersion
	if pv := r.Header.Get(mcpProtocolHeader); pv == mcpProtocolLegacy {
		negotiatedVersion = mcpProtocolLegacy
	} else if clientProtocolVersion == mcpProtocolLegacy {
		negotiatedVersion = mcpProtocolLegacy
	}

	result := mcpInitializeResult{}
	result.ProtocolVersion = negotiatedVersion
	result.Capabilities.Tools = &struct {
		ListChanged bool `json:"listChanged,omitempty"`
	}{ListChanged: false}
	result.ServerInfo.Name = mcpServerName
	result.ServerInfo.Version = mcpServerVersion

	w.Header().Set(mcpSessionHeaderKey, sessionID)
	writeJSONRPCResult(w, req.ID, result)
}

// handleMCPToolsList requires authentication (prevents information disclosure in enterprise mode).
func handleMCPToolsList(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	if session := requireMCPAuth(w, r, req); session == nil {
		return
	}
	writeJSONRPCResult(w, req.ID, map[string]interface{}{
		"tools": getMCPTools(),
	})
}

// handleMCPPing requires authentication to prevent endpoint discovery.
func handleMCPPing(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	if session := requireMCPAuth(w, r, req); session == nil {
		return
	}
	writeJSONRPCResult(w, req.ID, map[string]interface{}{})
}

func handleMCPToolsCall(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	session := requireMCPAuth(w, r, req)
	if session == nil {
		return
	}

	var params mcpToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, req.ID, jsonRPCInvalidParams, "Invalid tool call parameters")
		return
	}

	if params.Name == "" {
		writeJSONRPCError(w, req.ID, jsonRPCInvalidParams, "Missing tool name in tools/call")
		return
	}

	var result interface{}
	var toolErr error

	switch params.Name {
	case "check_policy":
		result, toolErr = mcpToolCheckPolicy(r.Context(), session, params.Arguments)
	case "check_output":
		result, toolErr = mcpToolCheckOutput(r.Context(), session, params.Arguments)
	case "audit_tool_call":
		result, toolErr = mcpToolAuditCall(session, params.Arguments)
	case "list_policies":
		result, toolErr = mcpToolListPolicies(session, params.Arguments)
	case "get_policy_stats":
		result, toolErr = mcpToolGetPolicyStats(session, params.Arguments)
	case "search_audit_events":
		result, toolErr = mcpToolSearchAuditEvents(session, params.Arguments)
	// Plugin Batch 1: ADR-044 + ADR-043 governance tools.
	case "explain_decision":
		result, toolErr = mcpToolExplainDecision(session, params.Arguments)
	case "create_override":
		result, toolErr = mcpToolCreateOverride(session, params.Arguments)
	case "delete_override":
		result, toolErr = mcpToolDeleteOverride(session, params.Arguments)
	case "list_overrides":
		result, toolErr = mcpToolListOverrides(session, params.Arguments)
	default:
		writeJSONRPCError(w, req.ID, jsonRPCInvalidParams, fmt.Sprintf("Unknown tool: %s", params.Name))
		return
	}

	if toolErr != nil {
		writeJSONRPCResult(w, req.ID, mcpToolCallResult{
			Content: []mcpContent{{Type: "text", Text: toolErr.Error()}},
			IsError: true,
		})
		return
	}

	resultJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		writeJSONRPCResult(w, req.ID, mcpToolCallResult{
			Content: []mcpContent{{Type: "text", Text: fmt.Sprintf("Failed to serialize result: %v", err)}},
			IsError: true,
		})
		return
	}
	writeJSONRPCResult(w, req.ID, mcpToolCallResult{
		Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
	})
}

// --- Auth Helpers ---

// requireMCPAuth resolves a session or authenticates the request. Returns nil
// and writes an error response if authentication fails.
func requireMCPAuth(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) *mcpSession {
	session := resolveMCPSession(r)
	if session == nil {
		writeJSONRPCAuthError(w, req.ID, "Authentication required")
		return nil
	}
	return session
}

// authenticateMCPServerRequest validates request credentials using the unified
// Authenticate() function. Supports all 4 deployment modes.
// Note: previously only called validateClientCredentials (whitelist) — now uses
// Authenticate() which also checks authDB (DB-backed), fixing a latent bug
// where DB-registered enterprise clients couldn't use the MCP server protocol.
//
// Plugin Batch 1 (explainability + session overrides) requires per-user
// identity: the override owner and explain caller must be a real person, not
// a synthetic user ID. Clients supply the end-user's email via X-User-Email
// (and optionally X-User-ID). When present, the session carries them forward
// to the orchestrator so access control and scoping work per-user. Absent —
// legacy clients — we fall back to a client-scoped pseudo-identity rather
// than a shared synthetic "0" to avoid cross-user aliasing on the MCP path.
func authenticateMCPServerRequest(r *http.Request) (tenantID, userID, userEmail, userRole, clientID string, err error) {
	auth, authErr := Authenticate(r, nil)
	if authErr != nil {
		return "", "", "", "", "", fmt.Errorf("%s", authErr.Message)
	}
	// Populate telemetry identity for community-saas tracking
	SetTelemetryTenantID(r.Context(), auth.TenantID)

	// Extract per-user identity from request headers (Plugin Batch 1). Plugins
	// that don't set these headers get a client-scoped pseudo-email — not a
	// shared "0" — so overrides created by one legacy caller don't leak onto
	// another legacy caller on the same client.
	headerEmail := strings.TrimSpace(r.Header.Get("X-User-Email"))
	headerUserID := strings.TrimSpace(r.Header.Get("X-User-ID"))

	resolvedEmail := headerEmail
	if resolvedEmail == "" {
		resolvedEmail = headerUserID
	}
	if resolvedEmail == "" {
		resolvedEmail = fmt.Sprintf("mcp-client:%s", auth.ClientID)
	}

	resolvedUserID := headerUserID
	if resolvedUserID == "" {
		resolvedUserID = resolvedEmail
	}

	return auth.TenantID, resolvedUserID, resolvedEmail, "admin", auth.ClientID, nil
}

// resolveMCPSession resolves auth from session header or credentials.
// Session ID is verified to belong to the same client (prevents session hijacking)
// and checked against the TTL (24h).
func resolveMCPSession(r *http.Request) *mcpSession {
	sessionID := r.Header.Get(mcpSessionHeaderKey)
	if sessionID != "" {
		session := getSessionByID(sessionID)
		if session != nil {
			// Enforce TTL on lookup
			if time.Since(session.lastUsed) > mcpSessionTTL {
				log.Printf("[MCP-Server] Session %s expired (last used %v ago)", logutil.Sanitize(sessionID), time.Since(session.lastUsed))
				mcpSessionsMu.Lock()
				delete(mcpSessions, sessionID)
				mcpSessionsMu.Unlock()
				// Fall through to re-auth
			} else {
				// In enterprise/community-saas mode, verify the caller matches the session owner
				if !isCommunityMode() {
					callerClientID := extractClientID(r)
					if callerClientID != "" && callerClientID != session.clientID {
						log.Printf("[MCP-Server] Session %s: client ID mismatch (session=%s, caller=%s)",
							logutil.Sanitize(sessionID), logutil.Sanitize(session.clientID), logutil.Sanitize(callerClientID))
						return nil
					}
				}
				// Refresh lastUsed
				mcpSessionsMu.Lock()
				session.lastUsed = time.Now()
				mcpSessionsMu.Unlock()
				// Populate telemetry for cached sessions (container is per-request)
				SetTelemetryTenantID(r.Context(), session.tenantID)
				return session
			}
		}
	}

	// Fall back to direct auth
	tenantID, userID, userEmail, userRole, clientID, err := authenticateMCPServerRequest(r)
	if err != nil {
		return nil
	}
	return &mcpSession{
		tenantID:  tenantID,
		userID:    userID,
		userEmail: userEmail,
		userRole:  userRole,
		clientID:  clientID,
	}
}

func getSessionByID(id string) *mcpSession {
	mcpSessionsMu.RLock()
	defer mcpSessionsMu.RUnlock()
	return mcpSessions[id]
}

// --- Tool Implementations ---

// check_policy: uses Agent-internal evaluateInputPolicies() directly.
func mcpToolCheckPolicy(ctx context.Context, session *mcpSession, args map[string]interface{}) (interface{}, error) {
	connectorType, _ := args["connector_type"].(string)
	statement, _ := args["statement"].(string)
	operation, _ := args["operation"].(string)
	if operation == "" {
		operation = "execute"
	}
	if connectorType == "" || statement == "" {
		return nil, fmt.Errorf("connector_type and statement are required")
	}

	// Auto-detect integration from connector type (first call activates policies)
	AutoDetectIntegration(usageDB, connectorType)

	var params map[string]interface{}
	if p, ok := args["parameters"].(map[string]interface{}); ok {
		params = p
	}

	outcome := evaluateInputPolicies(
		ctx,
		session.tenantID,
		session.userID,
		session.userRole,
		connectorType,
		operation,
		statement,
		params,
	)

	if outcome.EvalUnavailable {
		return nil, fmt.Errorf("policy evaluation temporarily unavailable")
	}

	blocked := outcome.DynamicBlocked || (outcome.StaticResult != nil && outcome.StaticResult.Blocked)

	resp := map[string]interface{}{
		"allowed": !blocked,
	}

	if outcome.DynamicBlocked {
		resp["block_reason"] = outcome.DynamicBlockReason
	} else if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		resp["block_reason"] = outcome.StaticResult.BlockReason
		resp["blocked_by"] = outcome.StaticResult.BlockedBy.PolicyID
	}

	if outcome.StaticResult != nil {
		resp["policies_evaluated"] = outcome.StaticResult.PoliciesEvaluated
	}
	if outcome.DynamicInfo != nil {
		resp["dynamic_info"] = outcome.DynamicInfo
	}

	return resp, nil
}

// check_output: uses Agent-internal evaluateOutputPolicies() directly.
func mcpToolCheckOutput(ctx context.Context, session *mcpSession, args map[string]interface{}) (interface{}, error) {
	connectorType, _ := args["connector_type"].(string)
	if connectorType == "" {
		return nil, fmt.Errorf("connector_type is required")
	}

	message, _ := args["message"].(string)

	var rows []map[string]interface{}
	if rd, ok := args["response_data"].([]interface{}); ok {
		for _, item := range rd {
			if m, ok := item.(map[string]interface{}); ok {
				rows = append(rows, m)
			}
		}
	}

	rowCount := len(rows)
	checkExfil := rows != nil

	outcome := evaluateOutputPolicies(
		ctx,
		session.tenantID,
		session.userID,
		connectorType,
		rows,
		message,
		nil, // messageMetadata
		rowCount,
		checkExfil,
	)

	blocked := outcome.SQLiBlocked || (outcome.StaticResult != nil && outcome.StaticResult.Blocked)

	resp := map[string]interface{}{
		"allowed": !blocked,
	}

	if outcome.SQLiBlocked {
		resp["block_reason"] = fmt.Sprintf("SQL injection detected: %s", outcome.SQLiPattern)
	} else if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		resp["block_reason"] = outcome.StaticResult.BlockReason
	}

	if outcome.StaticResult != nil {
		resp["policies_evaluated"] = outcome.StaticResult.PoliciesEvaluated
		if outcome.RedactedRows != nil {
			resp["redacted_data"] = outcome.RedactedRows
		}
		if outcome.RedactedMessage != "" {
			resp["redacted_message"] = outcome.RedactedMessage
		}
	}

	if outcome.ExfilInfo != nil {
		resp["exfiltration_info"] = outcome.ExfilInfo
	}

	return resp, nil
}

// audit_tool_call: proxies to Orchestrator.
func mcpToolAuditCall(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	toolName, _ := args["tool_name"].(string)
	if toolName == "" {
		return nil, fmt.Errorf("tool_name is required")
	}

	toolType, _ := args["tool_type"].(string)
	if toolType == "" {
		toolType = "claude_code"
	}

	body := map[string]interface{}{
		"tool_name":     toolName,
		"tool_type":     toolType,
		"input":         args["input"],
		"output":        args["output"],
		"success":       args["success"],
		"error_message": args["error_message"],
		"duration_ms":   args["duration_ms"],
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/audit/tool-call", body)
	if err != nil {
		return nil, fmt.Errorf("audit recording failed: %w", err)
	}

	return map[string]interface{}{
		"recorded":  true,
		"tool_name": toolName,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"details":   resp,
	}, nil
}

// list_policies: fetches both static and dynamic policies from Orchestrator.
// Both APIs return {policies: [...], pagination: {...}}. We request limit=200
// to get all policies in one call (typical deployments have <200 policies).
func mcpToolListPolicies(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	// Static policies are served by the Agent itself (not the Orchestrator).
	// Dynamic policies are served by the Orchestrator.
	agentPort := getEnv("PORT", "8080")
	staticResp, staticErr := mcpProxyToLocal(session, "GET", "http://localhost:"+agentPort+"/api/v1/static-policies?limit=200")
	dynamicResp, dynamicErr := mcpProxyToLocal(session, "GET", "http://localhost:"+agentPort+"/api/v1/dynamic-policies?limit=200")

	if staticErr != nil && dynamicErr != nil {
		return nil, fmt.Errorf("failed to list policies: static: %v, dynamic: %v", staticErr, dynamicErr)
	}
	if staticErr != nil {
		log.Printf("[MCP-Server] list_policies: static fetch failed (continuing with dynamic only): %v", staticErr)
	}
	if dynamicErr != nil {
		log.Printf("[MCP-Server] list_policies: dynamic fetch failed (continuing with static only): %v", dynamicErr)
	}

	var allPolicies []interface{}

	// Extract policies from paginated response: {policies: [...], pagination: {...}}
	extractPolicies := func(resp interface{}, source string) {
		if resp == nil {
			return
		}
		respMap, ok := resp.(map[string]interface{})
		if !ok {
			return
		}
		policies, ok := respMap["policies"].([]interface{})
		if !ok {
			return
		}
		for _, p := range policies {
			if pm, ok := p.(map[string]interface{}); ok {
				pm["source"] = source
				allPolicies = append(allPolicies, pm)
			}
		}
	}

	extractPolicies(staticResp, "static")
	extractPolicies(dynamicResp, "dynamic")

	category, _ := args["category"].(string)
	severity, _ := args["severity"].(string)

	if category == "" && severity == "" {
		return map[string]interface{}{"policies": allPolicies, "count": len(allPolicies)}, nil
	}

	var filtered []interface{}
	for _, p := range allPolicies {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		if category != "" {
			if pc, _ := pm["category"].(string); pc != category {
				continue
			}
		}
		if severity != "" {
			if ps, _ := pm["severity"].(string); ps != severity {
				continue
			}
		}
		filtered = append(filtered, p)
	}

	return map[string]interface{}{"policies": filtered, "count": len(filtered)}, nil
}

// get_policy_stats: proxies to Orchestrator audit summary (POST).
// Defaults to last 24 hours if no date range is provided, because the
// backend requires start_time and end_time.
func mcpToolGetPolicyStats(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	now := time.Now().UTC()

	from, _ := args["from"].(string)
	to, _ := args["to"].(string)

	// Default to last 24 hours if not provided
	if from == "" {
		from = now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z")
	} else if len(from) == 10 {
		from += "T00:00:00Z"
	}
	if to == "" {
		to = now.Format("2006-01-02T15:04:05Z")
	} else if len(to) == 10 {
		to += "T23:59:59Z"
	}

	body := map[string]interface{}{
		"start_time": from,
		"end_time":   to,
	}
	if ct, ok := args["connector_type"].(string); ok && ct != "" {
		body["connector_type"] = ct
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/audit/summary", body)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy stats: %w", err)
	}
	return resp, nil
}

// --- Internal HTTP Calls ---

// mcpProxyToAgent makes an HTTP call to the Agent's own proxy endpoints (localhost).
// Used for endpoints that are proxied through the Agent (audit, static policies).
// Authenticates using Basic auth so the Agent's proxy middleware resolves the client
// and sets internal headers (X-Tenant-ID, X-Axonflow-Proxy-Auth) before forwarding.
// search_audit_events: searches individual audit records via Orchestrator.
func mcpToolSearchAuditEvents(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	now := time.Now().UTC()

	from, _ := args["from"].(string)
	to, _ := args["to"].(string)

	// Default to last 15 minutes if not provided (keeps response size manageable)
	if from == "" {
		from = now.Add(-15 * time.Minute).Format("2006-01-02T15:04:05Z")
	} else if len(from) == 10 {
		from += "T00:00:00Z"
	}
	if to == "" {
		to = now.Format("2006-01-02T15:04:05Z")
	} else if len(to) == 10 {
		to += "T23:59:59Z"
	}

	limit := 20
	if l, ok := args["limit"].(float64); ok && l > 0 {
		limit = int(l)
		if limit > 100 {
			limit = 100
		}
	}

	body := map[string]interface{}{
		"start_time": from,
		"end_time":   to,
		"limit":      limit,
	}
	if rt, ok := args["request_type"].(string); ok && rt != "" {
		body["request_type"] = rt
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/audit/search", body)
	if err != nil {
		return nil, fmt.Errorf("audit search failed: %w", err)
	}

	// Trim response to keep output size manageable. The orchestrator returns
	// full request/response payloads per event which can be 10KB+ each.
	// Strip large fields and keep only what's useful for debugging/compliance.
	if respMap, ok := resp.(map[string]interface{}); ok {
		if entries, ok := respMap["entries"].([]interface{}); ok {
			for i, entry := range entries {
				if e, ok := entry.(map[string]interface{}); ok {
					delete(e, "request_body")
					delete(e, "response_body")
					delete(e, "raw_request")
					delete(e, "raw_response")
					if q, ok := e["query"].(string); ok && len(q) > 200 {
						e["query"] = q[:200] + "...(truncated)"
					}
					entries[i] = e
				}
			}
			respMap["entries"] = entries
		}
	}

	return resp, nil
}

func mcpProxyToAgent(session *mcpSession, method, url string, body interface{}) (interface{}, error) {
	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", session.tenantID)
	// Basic auth required by the Orchestrator's audit handler even when proxied
	// through the Agent. In community mode any credentials work.
	req.SetBasicAuth(session.clientID, "internal")

	// Use internal service auth for Agent-internal calls
	if proxyTokenGenerator != nil {
		req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(proxyTokenGenerator))
	}

	resp, err := orchestratorHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, mcpMaxResponseBody)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("agent returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return string(respBody), nil
	}
	return result, nil
}

// mcpProxyToLocal makes an HTTP call to the Agent's own endpoints (localhost).
// Used for read-only endpoints like static policies that don't need a body.
func mcpProxyToLocal(session *mcpSession, method, url string) (interface{}, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", session.tenantID)

	resp, err := orchestratorHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("local request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, mcpMaxResponseBody)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("agent returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return string(respBody), nil
	}
	return result, nil
}

// =============================================================================
// Plugin Batch 1 (ADR-044 + ADR-043) MCP tool handlers.
// Reviewer-caught: pre-existing PR shipped the HTTP endpoints but forgot to
// register these MCP tools even though plugin messages point users to them.
// =============================================================================

// mcpToolExplainDecision proxies to GET /api/v1/decisions/:id/explain.
func mcpToolExplainDecision(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	decisionID, _ := args["decision_id"].(string)
	if decisionID == "" {
		return nil, fmt.Errorf("decision_id is required")
	}
	// url.PathEscape is used here to guard against IDs containing "/".
	path := "/api/v1/decisions/" + url.PathEscape(decisionID) + "/explain"
	resp, err := mcpProxyToOrchestrator(session, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("explain decision failed: %w", err)
	}
	return resp, nil
}

// mcpToolCreateOverride proxies to POST /api/v1/overrides.
// Mandatory fields (per ADR-044): policy_id, policy_type, override_reason.
func mcpToolCreateOverride(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	policyID, _ := args["policy_id"].(string)
	policyType, _ := args["policy_type"].(string)
	reason, _ := args["override_reason"].(string)
	if policyID == "" || policyType == "" || reason == "" {
		return nil, fmt.Errorf("policy_id, policy_type, and override_reason are required")
	}

	body := map[string]interface{}{
		"policy_id":       policyID,
		"policy_type":     policyType,
		"override_reason": reason,
	}
	if toolSig, ok := args["tool_signature"].(string); ok && toolSig != "" {
		body["tool_signature"] = toolSig
	}
	if ttl, ok := args["ttl_seconds"].(float64); ok {
		body["ttl_seconds"] = int64(ttl)
	}

	resp, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/overrides", body)
	if err != nil {
		return nil, fmt.Errorf("create override failed: %w", err)
	}
	return resp, nil
}

// mcpToolDeleteOverride proxies to DELETE /api/v1/overrides/:id.
func mcpToolDeleteOverride(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	overrideID, _ := args["override_id"].(string)
	if overrideID == "" {
		return nil, fmt.Errorf("override_id is required")
	}
	path := "/api/v1/overrides/" + url.PathEscape(overrideID)
	resp, err := mcpProxyToOrchestrator(session, "DELETE", path, nil)
	if err != nil {
		return nil, fmt.Errorf("delete override failed: %w", err)
	}
	return resp, nil
}

// mcpToolListOverrides proxies to GET /api/v1/overrides with query params.
func mcpToolListOverrides(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	query := url.Values{}
	if policyID, ok := args["policy_id"].(string); ok && policyID != "" {
		query.Set("policy_id", policyID)
	}
	if includeRevoked, ok := args["include_revoked"].(bool); ok && includeRevoked {
		query.Set("include_revoked", "true")
	}
	path := "/api/v1/overrides"
	if qs := query.Encode(); qs != "" {
		path += "?" + qs
	}
	resp, err := mcpProxyToOrchestrator(session, "GET", path, nil)
	if err != nil {
		return nil, fmt.Errorf("list overrides failed: %w", err)
	}
	return resp, nil
}

// --- Internal Orchestrator Proxy ---

func mcpProxyToOrchestrator(session *mcpSession, method, path string, body interface{}) (interface{}, error) {
	if orchestratorURL == "" {
		return nil, fmt.Errorf("orchestrator not configured")
	}

	target := orchestratorURL + path

	var reqBody io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, target, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", session.tenantID)
	// Plugin Batch 1 endpoints (/api/v1/overrides, /api/v1/decisions/*)
	// require an authenticated user identity per ADR-044. Forward the
	// per-user identity captured at authenticate time — userID and
	// userEmail are now distinct so the orchestrator can scope explain
	// access control, historical hit count, and override ownership by
	// real caller rather than a shared synthetic ID.
	if session.userID != "" {
		req.Header.Set("X-User-ID", session.userID)
	}
	if session.userEmail != "" {
		req.Header.Set("X-User-Email", session.userEmail)
	}
	// Basic auth required by Orchestrator audit endpoints. Use tenantID as
	// clientID to pass the Orchestrator's client/tenant scope validation.
	req.SetBasicAuth(session.tenantID, "internal")

	if proxyTokenGenerator != nil {
		req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(proxyTokenGenerator))
	}

	resp, err := orchestratorHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("orchestrator request failed: %w", err)
	}
	defer resp.Body.Close()

	// Limit response body to prevent OOM
	limited := io.LimitReader(resp.Body, mcpMaxResponseBody)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return string(respBody), nil
	}
	return result, nil
}

// --- Response Helpers ---

func writeJSONRPCResult(w http.ResponseWriter, id interface{}, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}); err != nil {
		log.Printf("[MCP-Server] Failed to write JSON-RPC result: %v", err)
	}
}

func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if code == jsonRPCParseError || code == jsonRPCInvalidRequest {
		w.WriteHeader(http.StatusBadRequest)
	}
	if err := json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	}); err != nil {
		log.Printf("[MCP-Server] Failed to write JSON-RPC error: %v", err)
	}
}

func writeJSONRPCAuthError(w http.ResponseWriter, id interface{}, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Basic realm=\"AxonFlow MCP Server\"")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: jsonRPCAuthError, Message: message},
	}); err != nil {
		log.Printf("[MCP-Server] Failed to write JSON-RPC auth error: %v", err)
	}
}
