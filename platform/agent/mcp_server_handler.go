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

	sharedaudit "axonflow/platform/shared/audit"
	logutil "axonflow/platform/shared/logger"

	"axonflow/platform/shared/serviceauth"
	"github.com/google/uuid"

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
	mcpMaxRequestBody   = 1 << 20  // 1 MB
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

	// V1 Plugin Pro tier-gating fields (umbrella #1958). Both default
	// zero/nil so existing tools are unchanged — backward compat. PR2 of
	// the umbrella opts each new Pro-only / graduated-limit tool in.
	//
	// json:"-" keeps these out of the tools/list wire response — they are
	// internal dispatch config, not part of the MCP protocol surface.
	RequiredTier   string          `json:"-"` // "" (all tiers) | "Pro" (Pro+) | "Premium" (Premium only)
	FreeUsageLimit *FreeUsageLimit `json:"-"` // nil = no graduated Free-tier cap
}

// FreeUsageLimit defines a graduated cap that Free-tier callers must obey on
// a given MCP tool. Used by tools/call dispatch (PR2 of umbrella #1958) to
// enforce object-count limits ("2 active custom policies") and rolling-
// window action limits ("1 HITL approval per 7 days").
//
// Zero-valued fields are ignored:
//   - MaxCount=0 means no object-count cap (use WindowSeconds+MaxInWindow instead)
//   - WindowSeconds=0 means no time-window cap (use MaxCount instead)
//
// LimitType drives the response envelope rendering — must match one of the
// LimitType* constants in community_saas_ratelimit_response.go so plugin-side
// parsers see a consistent shape.
type FreeUsageLimit struct {
	MaxCount      int    // for object-creation limits (e.g. 2 active policies)
	WindowSeconds int    // for time-windowed action limits (e.g. 604800 = 7d)
	MaxInWindow   int    // count threshold within window
	LimitType     string // one of LimitType* constants — passed to writeFreeLimitError on enforcement
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
	// orgID is the v9 customer/account identity (ADR-052) captured at
	// session-create time. Audit writers (writeExplainableAuditLog,
	// writeOverrideUsedEvent) read this so audit_logs rows carry a
	// non-empty org_id; passing "" here was the bug that produced empty
	// org_id rows on the MCP path (see Epic #2230 Phase 0 callout).
	orgID     string
	userID    string
	userEmail string // per-user identity from X-User-Email header; distinct from userID so Plugin Batch 1 endpoints scope by real email, not synthetic "0".
	userRole  string
	clientID  string

	// V1 Plugin Pro tier (umbrella #1958). Captured from auth.Client.EffectiveTier
	// at session-create time. One of "Free" / "Pro" / "Premium" for SaaS
	// Plugin callers; empty for self-hosted enterprise (gating framework
	// only applies to SaaS Plugin — empty tier means tools/list returns
	// everything and tools/call enforces no gates).
	tier string

	// v9 Brief 11.5 (#2305 Item 4): captured at session-create so cache-hit
	// replays + cache-miss fallback can both stamp r.Context() via
	// stampAuthContext(ctx, client, authKind) without re-authenticating.
	// Closes the latent bug from PR #2342 R3-MEDIUM-1 where the cache-miss
	// path was identified as not stamping.
	client   *Client
	authKind AuthKind
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
		// V1.1 decision-list (issue #1982). Companion to explain_decision —
		// surfaces the caller's recent decisions for "what just got blocked"
		// UX, "appeal a block" flows, and forensic decision-history tracing.
		// Tier-gated server-side: the platform's GET /api/v1/decisions
		// returns 429 with the V1 upgrade envelope when the caller's tier
		// page-cap is exceeded; this MCP tool preserves that envelope in
		// the result so the host LLM / UI can render the upgrade prompt
		// rather than swallowing it as a generic error.
		{
			Name:        "list_recent_decisions",
			Description: "List recent governance decisions made by AxonFlow for the current user/tenant. Useful for surfacing 'what just got blocked' UX, appealing a block, or tracing a workflow's decision history. Tier-throttled per the platform's Free/Pro window+limit.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"since": map[string]interface{}{
						"type":        "string",
						"format":      "date-time",
						"description": "Optional RFC3339 lower bound (e.g. 2026-05-01T00:00:00Z). Silently clamped to the tier's lookback window when reaching further back.",
					},
					"decision": map[string]interface{}{
						"type": "string",
						// Forwarded verbatim to GET /api/v1/decisions, whose
						// ?decision= filter accepts ONLY the canonical audit
						// verdicts (decisions_list_handler.go: !audit.IsCanonical
						// → 400). Advertising the legacy allow/deny/require_approval
						// spellings here made every host-supplied filter 400 after
						// the #2638/#2653 canonical-vocab cutover. Build the enum
						// from the single source of truth so it can never drift.
						"enum":        sharedaudit.All(),
						"description": "Filter to decisions of this canonical audit verdict: allowed, blocked, redacted, needs_approval, or error.",
					},
					"policy_id": map[string]interface{}{
						"type":        "string",
						"description": "Filter to decisions matching this policy_id.",
					},
					"tool_signature": map[string]interface{}{
						"type":        "string",
						"description": "Filter to decisions scoped to this tool signature.",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"minimum":     1,
						"maximum":     1000,
						"description": "Max rows to return. Caller-supplied limits exceeding the tier's max page emit the V1 upgrade envelope at 429 instead of capping silently.",
					},
				},
			},
		},
	}
}

// getMCPToolsForCaller returns the MCP tool list filtered by the caller's
// effective tier (V1 Plugin Pro umbrella #1958). Free callers don't see
// Pro-only tools (they'd be useless); empty tier (self-hosted enterprise
// or internal-service) sees everything because the gating framework only
// applies to SaaS Plugin tiers.
func getMCPToolsForCaller(callerTier string) []mcpTool {
	all := append(getMCPTools(), v1ProMCPTools()...)
	return filterMCPToolsByTier(all, callerTier)
}

// --- Registration ---

// RegisterMCPServerHandler registers the MCP server protocol endpoint.
func RegisterMCPServerHandler(r *mux.Router) {
	r.HandleFunc("/api/v1/mcp-server", mcpServerHandler).Methods("POST", "GET", "DELETE", "OPTIONS")
	log.Println("[MCP-Server] Registered MCP server protocol endpoint at /api/v1/mcp-server")

	// OAuth-discovery well-known endpoints. The MCP server authenticates with
	// HTTP Basic (base64(org_id:license_key)) — see writeJSONRPCAuthError's
	// WWW-Authenticate: Basic challenge — NOT OAuth. But some MCP clients
	// (e.g. Claude Code) respond to a 401 by probing RFC 9728 / RFC 8414
	// discovery endpoints regardless of the WWW-Authenticate scheme. Without
	// these routes those probes hit the router's default handler, which
	// returns Go's plaintext "404 page not found"; the client then tries to
	// parse that as an OAuth error JSON and surfaces the inscrutable
	// "HTTP 404: Invalid OAuth error response ... Raw body: 404 page not
	// found" (and marks the server failed). We instead return a PARSEABLE
	// OAuth-error-shaped JSON (404) that names the real auth mechanism, and we
	// deliberately advertise no authorization server, so the client surfaces a
	// clear "use Basic auth" message instead of crashing — and never starts an
	// OAuth flow this server can't complete.
	// PathPrefix (not exact): RFC 9728 clients request BOTH the bare
	// `/.well-known/oauth-protected-resource` AND the resource-path-suffixed
	// `/.well-known/oauth-protected-resource/api/v1/mcp-server`. Claude Code
	// uses the suffixed form, so an exact route would still leak the plaintext
	// 404. PathPrefix covers every variant under both well-known roots.
	r.PathPrefix("/.well-known/oauth-protected-resource").HandlerFunc(mcpOAuthDiscoveryHandler).Methods("GET")
	r.PathPrefix("/.well-known/oauth-authorization-server").HandlerFunc(mcpOAuthDiscoveryHandler).Methods("GET")
	log.Println("[MCP-Server] Registered OAuth-discovery well-known endpoints (Basic-auth advisory)")
}

// mcpOAuthDiscoveryHandler answers OAuth-discovery probes with a parseable,
// machine-readable advisory instead of a plaintext 404. The MCP server is
// Basic-auth, not OAuth.
func mcpOAuthDiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// 404: the resource genuinely has no OAuth metadata. The body is JSON so a
	// client that parses 401/404 bodies as OAuth errors does not choke; the
	// shape (error/error_description) matches RFC 6749 §5.2 so it renders
	// cleanly. No authorization_servers are advertised → no OAuth flow.
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": "oauth_not_supported",
		"error_description": "AxonFlow's MCP server uses HTTP Basic authentication " +
			"(base64(org_id:license_key)), not OAuth. Set AXONFLOW_ENDPOINT and " +
			"AXONFLOW_AUTH in the environment that launches your MCP client. See " +
			"https://docs.getaxonflow.com/docs/integration/claude-code#self-hosted--enterprise-authentication",
	})
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

	log.Printf("[MCP-Server] → %s (id=%v, session=%s)", logutil.Sanitize(req.Method), req.ID, logutil.MaskSecret(logutil.Sanitize(r.Header.Get(mcpSessionHeaderKey)), 8))

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
	_, _, _, _, _, clientID, _, auth, err := authenticateMCPServerRequest(r)
	if err != nil && !isCommunityMode() {
		// #2641 (MCPSRV-SESSIONDELETE-AUTHZ, unauth arm): an unauthenticated DELETE
		// against an existing session is a denied attempt. Record it against the
		// TARGET session's tenant (the resource being protected) for security audit.
		auditMCPServerDeny(r.Context(), session, "mcp_session_delete", "delete_session",
			mcpVerdictBlocked, "unauthenticated session delete attempt", []string{"unauthenticated"})
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !isCommunityMode() && clientID != session.clientID {
		// #2641 (MCPSRV-SESSIONDELETE-AUTHZ): a cross-client session-delete attempt is
		// an authz refusal that previously left no audit trail. Record the "blocked"
		// decision against the target session's tenant.
		auditMCPServerDeny(r.Context(), session, "mcp_session_delete", "delete_session",
			mcpVerdictBlocked, "cross-client session delete denied", []string{"session_authz"})
		w.WriteHeader(http.StatusForbidden)
		return
	}
	// Stamp auth context for downstream telemetry/audit consistency (#2328 +
	// AST audit at authenticate_caller_stamp_audit_test.go).
	if auth != nil && auth.Client != nil {
		r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))
	}
	_ = r // r reassignment kept for future handlers in this scope; intentional

	mcpSessionsMu.Lock()
	delete(mcpSessions, sessionID)
	mcpSessionsMu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// --- Method Handlers ---

func handleMCPInitialize(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	tenantID, orgID, userID, userEmail, userRole, clientID, tier, auth, err := authenticateMCPServerRequest(r)
	if err != nil {
		writeJSONRPCAuthError(w, req.ID, err.Error())
		return
	}
	// Stamp auth context (#2328 + AST audit). r is reassigned so any
	// downstream code in this handler observes stamped context.
	if auth != nil && auth.Client != nil {
		r = r.WithContext(stampAuthContext(r.Context(), auth.Client, auth.Kind))
	}
	_ = r

	now := time.Now()
	sessionID := generateSecureSessionID()
	// v9 Brief 11.5 (#2305 Item 4): capture *Client + AuthKind so cache-hit
	// replays in resolveMCPSession can stamp r.Context() without
	// re-authenticating. auth.Client may be nil for legacy internal-service
	// auth — keep nil and let stampAuthContext's caller-side nil-guard
	// handle.
	var sessClient *Client
	var sessAuthKind AuthKind
	if auth != nil {
		sessClient = auth.Client
		sessAuthKind = auth.Kind
	}
	session := &mcpSession{
		id:        sessionID,
		createdAt: now,
		lastUsed:  now,
		tenantID:  tenantID,
		orgID:     orgID,
		userID:    userID,
		userEmail: userEmail,
		userRole:  userRole,
		clientID:  clientID,
		tier:      tier, // V1 Plugin Pro tier for tools/list filtering + tools/call gating
		client:    sessClient,
		authKind:  sessAuthKind,
	}

	mcpSessionsMu.Lock()
	evictStaleSessions()
	mcpSessions[sessionID] = session
	mcpSessionsMu.Unlock()

	// sessionID is a bearer-style session handle: log only a short prefix so a
	// leaked log line cannot be replayed as a session token (go/clear-text-logging).
	log.Printf("[MCP-Server] Session created: %s (tenant=%s, client=%s)", logutil.MaskSecret(sessionID, 8), logutil.Sanitize(tenantID), logutil.Sanitize(clientID))

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
//
// V1 Plugin Pro umbrella #1958: tools list is filtered by the caller's
// effective tier — Free callers don't see Pro-only tools, since they
// can't call them anyway. Empty tier (self-hosted / internal) sees the
// full list. The filter is honest visibility, not security: a determined
// Free caller could still attempt tools/call by-name, and the dispatch
// re-enforces the gate there.
func handleMCPToolsList(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	session, r := requireMCPAuth(w, r, req)
	if session == nil {
		return
	}
	_ = r // r stamped by requireMCPAuth; tools/list doesn't consume r below
	writeJSONRPCResult(w, req.ID, map[string]interface{}{
		"tools": getMCPToolsForCaller(session.tier),
	})
}

// handleMCPPing requires authentication to prevent endpoint discovery.
func handleMCPPing(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	session, _ := requireMCPAuth(w, r, req)
	if session == nil {
		return
	}
	writeJSONRPCResult(w, req.ID, map[string]interface{}{})
}

// auditMCPServerDeny records a canonical audit_logs row for a JSON-RPC MCP-server
// tools/call deny that never reaches (or completes) policy evaluation (#2641:
// MCPSRV-DAILYCAP-DENY, MCPSRV-TIERGATE-DENY, MCPSRV-TOOLERR-FAILCLOSED,
// MCPSRV-SESSIONDELETE-AUTHZ). Identity comes from the authenticated session, so
// the row lands in that tenant's portal decisions feed. Best-effort; mints its own
// decision_id. query is a non-PII descriptor — no tool arguments are recorded.
func auditMCPServerDeny(ctx context.Context, session *mcpSession, requestType, toolName, verdict, reason string, policyIDs []string) {
	if session == nil {
		return
	}
	writeMCPDecisionAudit(ctx, usageDB,
		uuid.New().String(), "",
		session.tenantID, session.orgID, session.clientID, session.userEmail,
		session.userID, session.userRole,
		requestType, fmt.Sprintf("mcp tools/call: %s", toolName), "",
		verdict, policyIDs, []string{reason}, nil, "")
}

func handleMCPToolsCall(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) {
	session, r := requireMCPAuth(w, r, req)
	if session == nil {
		// #2641 (MCPSRV-UNAUTH-JSONRPC): an unauthenticated tools/call is a denied
		// governance attempt that previously left no audit trail. Record it under the
		// `mcpUnauthenticatedTenant` sentinel (NOT a caller-claimed tenant → no
		// spoofing) with the credential the caller presented, for security audit.
		// Scoped to tools/call (the governance-bearing method) to bound volume.
		writeMCPDecisionAudit(r.Context(), usageDB,
			uuid.New().String(), "",
			mcpUnauthenticatedTenant, "", extractClientID(r), "",
			"", "service",
			"mcp_tools_call", "mcp tools/call: unauthenticated", "",
			mcpVerdictBlocked,
			[]string{"unauthenticated"},
			[]string{"authentication required for tools/call"},
			nil,
			"")
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

	// Populate telemetry identity container BEFORE the daily-cap
	// check so the outer telemetry middleware records 429 events
	// alongside successful tool calls. Same fix as the auth.go path
	// (#2011 phase B0); the MCP tools/call site was missed in that PR
	// and surfaced via runtime test on community-saas staging
	// 2026-05-08. The (auth, proxy, mcp) trio of cap-check call sites
	// must each hoist this populate step ahead of the cap-enforcement
	// helper.
	if session != nil && session.tenantID != "" {
		SetTelemetryTenantID(r.Context(), session.tenantID)
	}

	// V1 Plugin Pro daily-cap enforcement (umbrella #1958 + #1976):
	// /api/v1/mcp-server registers directly on globalRouter with no
	// daily-cap middleware (apiAuthMiddleware / proxyAuthMiddleware
	// don't wrap MCP), so we run the cap check here at tools/call
	// before the per-tool gate. Affects every governance call —
	// plugins' pre/post-tool hooks all flow through tools/call. The
	// matrix harness at runtime-e2e/v1_pro_full_matrix exercises this
	// path on real wire traffic.
	if enforceMCPSessionDailyCap(w, req, session) {
		// #2641 (MCPSRV-DAILYCAP-DENY): the daily-cap 429 was portal-invisible.
		auditMCPServerDeny(r.Context(), session, "mcp_tools_call", params.Name,
			mcpVerdictBlocked, "daily usage cap exceeded", []string{"daily_cap"})
		return
	}

	// V1 Plugin Pro tier-gating (umbrella #1958): look up the tool's
	// RequiredTier + FreeUsageLimit and enforce the gate before running
	// the body. enforceMCPToolGate writes the structured envelope on
	// rejection and returns true; we return early. Skipping gate check
	// for non-V1 (legacy) tools by checking only the V1 tool list — the
	// existing tools (check_policy, check_output, audit_tool_call,
	// list_policies, get_policy_stats, search_audit_events,
	// explain_decision, create_override, delete_override, list_overrides)
	// have RequiredTier="" + FreeUsageLimit=nil so the gate is a no-op
	// for them anyway, but we explicitly run it via the V1 tool lookup
	// so future additions to legacy tools that opt into gating Just Work.
	for _, t := range append(getMCPTools(), v1ProMCPTools()...) {
		if t.Name == params.Name {
			if enforceMCPToolGate(r.Context(), w, req, session, t, authDB) {
				// #2641 (MCPSRV-TIERGATE-DENY): the tier/usage-limit rejection was
				// portal-invisible.
				auditMCPServerDeny(r.Context(), session, "mcp_tools_call", params.Name,
					mcpVerdictBlocked, "tier/usage gate denied tool access", []string{"tier_gate"})
				return
			}
			break
		}
	}

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
	case "list_recent_decisions":
		result, toolErr = mcpToolListRecentDecisions(session, params.Arguments)
	// V1 Plugin Pro tools (umbrella #1958, PR2).
	case mcpToolNameGetTenantID:
		result, toolErr = mcpToolGetTenantID(session)
	case mcpToolNameRequestApproval:
		result, toolErr = mcpToolRequestApproval(r.Context(), authDB, session, params.Arguments)
	case mcpToolNameCreateTenantPolicy:
		result, toolErr = mcpToolCreateTenantPolicy(r.Context(), session, params.Arguments)
	case mcpToolNameGetCostEstimate:
		result, toolErr = mcpToolGetCostEstimate(session, params.Arguments)
	case mcpToolNameListProFeatures:
		result, toolErr = mcpToolListProFeatures(session)
	default:
		writeJSONRPCError(w, req.ID, jsonRPCInvalidParams, fmt.Sprintf("Unknown tool: %s", params.Name))
		return
	}

	if toolErr != nil {
		// #2641 (MCPSRV-TOOLERR-FAILCLOSED): when a GOVERNANCE tool (check_policy /
		// check_output) errors, the caller gets IsError and must not proceed — a
		// fail-closed deny. It previously left no audit trail. Record an "error" row so
		// the unrendered governance decision is portal-visible. Scoped to the two
		// governance tools: a benign proxy/validation error on a non-governance tool
		// (e.g. list_policies) is not a fail-closed governance verdict.
		if params.Name == "check_policy" || params.Name == "check_output" {
			auditMCPServerDeny(r.Context(), session, "mcp_tools_call", params.Name,
				mcpVerdictError, "governance tool error (fail-closed): "+toolErr.Error(),
				[]string{"tool_error"})
		}
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

// requireMCPAuth resolves a session or authenticates the request. Returns
// (nil, r) and writes an error response if authentication fails.
//
// v9 Brief 11.5 (#2305 Item 4): returns the (potentially stamped) request
// alongside the session. The cache-miss fallback path now stamps the four
// auth context keys (TenantID/OrgID/ClientID/AuthKind) via
// stampAuthContext so downstream readers of AuthKindFromContext etc. see
// the authenticated identity. Cache-hit path stamps from the cached
// session's *Client + authKind fields (populated at session-create).
//
// Callers MUST use the returned *http.Request for downstream calls so the
// stamped context propagates.
func requireMCPAuth(w http.ResponseWriter, r *http.Request, req *jsonRPCRequest) (*mcpSession, *http.Request) {
	session := resolveMCPSession(r)
	if session == nil {
		writeJSONRPCAuthError(w, req.ID, "Authentication required")
		return nil, r
	}
	// Stamp auth context for downstream telemetry/audit consistency.
	// session.client may be nil for legacy sessions (created pre-#2305-finish);
	// in that case we skip stamping rather than panic.
	if session.client != nil {
		r = r.WithContext(stampAuthContext(r.Context(), session.client, session.authKind))
	}
	return session, r
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
// v9 issue #2328: returns *AuthResult alongside the scalar fields so callers
// can stamp the request context via stampAuthContext(ctx, auth.Client, auth.Kind).
// The 7 scalar returns are kept for backwards-compat with the existing 3
// production callers + 4 test callers — the new *AuthResult is APPENDED at
// position 8 (before err) so signature changes are additive. Callers that
// don't need to stamp ignore via `_`.
func authenticateMCPServerRequest(r *http.Request) (tenantID, orgID, userID, userEmail, userRole, clientID, tier string, auth *AuthResult, err error) {
	authResult, authErr := Authenticate(r, nil)
	if authErr != nil {
		return "", "", "", "", "", "", "", nil, fmt.Errorf("%s", authErr.Message)
	}
	auth = authResult
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

	// V1 Plugin Pro tier capture (umbrella #1958). For community-saas auth
	// the validateCommunitySaasAuth flow has already resolved the tier from
	// X-License-Token + plugin_user_licenses lookup. For non-SaaS auth
	// (enterprise self-hosted, internal-service) auth.Client may be nil and
	// tier stays empty — that's fine, downstream tier-gating treats empty
	// tier as "ungated" so self-hosted enterprise sees every tool.
	resolvedTier := ""
	if auth.Client != nil {
		resolvedTier = auth.Client.EffectiveTier
	}

	// MCP server protocol has no real per-user role lookup — the caller's
	// X-User-Email/X-User-ID identifies the principal but not their authz
	// role. Fabricating "admin" on every audit row corrupts the trail (a
	// reader can't distinguish a real privileged action from an MCP-path
	// default). Stamp "unknown" so the audit record is honest about not
	// having resolved a role; downstream auditors should treat "unknown"
	// distinct from "admin" / "viewer" / "operator".
	return auth.TenantID, auth.OrgID, resolvedUserID, resolvedEmail, "unknown", auth.ClientID, resolvedTier, auth, nil
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
				log.Printf("[MCP-Server] Session %s expired (last used %v ago)", logutil.MaskSecret(sessionID, 8), time.Since(session.lastUsed))
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
							logutil.MaskSecret(sessionID, 8), logutil.Sanitize(session.clientID), logutil.Sanitize(callerClientID))
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

	// Fall back to direct auth. resolveMCPSession returns *mcpSession to
	// its caller; the *http.Request stays in the caller's scope and is
	// what carries context to downstream code.
	//
	// v9 Brief 11.5 (#2305 Item 4): closes the gap PR D R3-MEDIUM-1
	// surfaced. The cache-miss session now stashes *Client + AuthKind so
	// requireMCPAuth's caller can stamp r.Context() via stampAuthContext
	// before invoking downstream handlers.
	tenantID, orgID, userID, userEmail, userRole, clientID, tier, auth, err := authenticateMCPServerRequest(r)
	if err != nil {
		return nil
	}
	var sessClient *Client
	var sessAuthKind AuthKind
	if auth != nil {
		sessClient = auth.Client
		sessAuthKind = auth.Kind
	}
	return &mcpSession{
		tenantID:  tenantID,
		orgID:     orgID,
		userID:    userID,
		userEmail: userEmail,
		userRole:  userRole,
		clientID:  clientID,
		tier:      tier,
		client:    sessClient,
		authKind:  sessAuthKind,
	}
}

func getSessionByID(id string) *mcpSession {
	mcpSessionsMu.RLock()
	defer mcpSessionsMu.RUnlock()
	return mcpSessions[id]
}

// --- Tool Implementations ---

// check_policy: uses Agent-internal evaluateInputPolicies() directly.
//
// Plugin Batch 1 parity: the response includes decision_id + risk_level +
// policy_matches + override_available/override_existing_id on blocks, and
// consults active session overrides to flip deny -> allow. Claude Code /
// Cursor / Codex plugins all read these fields from the MCP tool response
// to render a useful block message; without them every plugin block comes
// back as a terse 'blocked' string.
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

	// Read-only enforcement posture (#2720, epic #2716). When MCP_READ_ONLY is
	// on, every write-path tool call is blocked at the gate before any other
	// policy evaluation or session-override flow runs: a deployment-wide
	// read-only boundary that is intentionally NOT overridable (ADR-044).
	// Read-path calls fall through to normal governance. See
	// mcp_readonly_posture.go for the classification rule.
	if readOnlyPostureEnabled() && classifyMCPCall(connectorType, operation) == mcpAccessWrite {
		decisionID := uuid.New().String()
		reason := fmt.Sprintf("read-only posture active: write-path tool call %q is blocked; only read-path operations are permitted", connectorType)
		// Canonical "blocked" audit row so the deny is visible in the portal
		// decisions feed. query is a non-PII descriptor (the raw statement MUST
		// NOT land in audit_logs.query).
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_policy", fmt.Sprintf("mcp check_policy: %s", connectorType), "",
			mcpVerdictBlocked,
			[]string{readOnlyPosturePolicyID},
			[]string{reason},
			nil,
			"") // MCP-server session has no inbound traceparent → singleton
		return map[string]interface{}{
			"allowed":           false,
			"decision_id":       decisionID,
			"block_reason":      reason,
			"blocked_by":        readOnlyPosturePolicyID,
			"read_only_posture": true,
		}, nil
	}

	var params map[string]interface{}
	if p, ok := args["parameters"].(map[string]interface{}); ok {
		params = p
	}

	// v9 Phase 8 #2384 PR-C1: orgID plumbed through for RLS-aware audit writes.
	outcome := evaluateInputPolicies(
		ctx,
		session.tenantID,
		session.orgID,
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

	// Mint decision_id up front. Plugin Batch 1 / ADR-042 / ADR-043
	// require it on every governance decision (allow + deny + redact)
	// so callers can correlate the decision back to /explain/{id}
	// without an extra round-trip. Allowed responses surface the same
	// id even though there's no audit-log dual-write needed.
	decisionID := uuid.New().String()
	resp := map[string]interface{}{
		"allowed":     !blocked,
		"decision_id": decisionID,
	}

	if outcome.StaticResult != nil {
		resp["policies_evaluated"] = outcome.StaticResult.PoliciesEvaluated
	}
	if outcome.DynamicInfo != nil {
		resp["dynamic_info"] = outcome.DynamicInfo
	}

	// Allowed — no richer-context fields needed, nothing to explain.
	if !blocked {
		return resp, nil
	}

	// Block path. Build richer context + dual-write audit_logs + apply any
	// active override. Same helpers the HTTP /api/v1/mcp/check-input handler
	// uses, so plugin-visible shape is consistent across the two surfaces.

	if outcome.DynamicBlocked {
		resp["block_reason"] = outcome.DynamicBlockReason
		// #2641 (MCPSRV-CHECKPOLICY-DYNAMIC-ONLY-BLOCK): a dynamic-only block carries
		// no StaticResult, so the audit write below (gated on StaticResult.Blocked)
		// never fired — the block was invisible to the portal decisions feed. Emit the
		// canonical "blocked" row here. Dynamic blocks have no override flow (overrides
		// are static-policy-only), so this is the single terminal write for this branch.
		// query is a non-PII descriptor — the raw statement MUST NOT land in audit_logs.query.
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_policy", fmt.Sprintf("mcp check_policy: %s", connectorType), "",
			mcpVerdictBlocked,
			extractDynamicPolicyIDs(outcome.DynamicInfo),
			[]string{outcome.DynamicBlockReason},
			nil,
			"") // MCP-server session has no inbound traceparent → singleton
	} else if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		resp["block_reason"] = outcome.StaticResult.BlockReason
		resp["blocked_by"] = outcome.StaticResult.BlockedBy.PolicyID
	}

	// Only static matches carry richer policy metadata; dynamic block
	// reasons don't produce MatchedPolicies.
	var matches []RicherPolicyMatch
	var topRisk string
	var overrideAvail *bool
	var overrideExistingID string
	if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		matches, topRisk, overrideAvail, overrideExistingID =
			buildRicherCheckInputBlock(ctx, usageDB, session.tenantID, session.userEmail,
				outcome.StaticResult.MatchedPolicies)

		// ADR-044: if the caller has an active session override on any
		// overridable matched policy, flip deny -> allow and emit an
		// override_used event. Consistent with the HTTP path.
		if usedOverrideID, overriddenMatch, applied := applyOverrideToCheckInputBlock(
			ctx, usageDB, session.tenantID, session.userEmail, matches,
		); applied {
			var overriddenPolicyID string
			var overriddenPolicyVersion int
			if overriddenMatch != nil {
				overriddenPolicyID = overriddenMatch.PolicyID
				overriddenPolicyVersion = overriddenMatch.Version
			}
			writeOverrideUsedEvent(ctx, usageDB, usedOverrideID,
				decisionID, session.tenantID, session.orgID, session.clientID, session.userEmail,
				overriddenPolicyID, overriddenPolicyVersion,
				"") // #2598: MCP-server session has no inbound traceparent → singleton
			resp["allowed"] = true
			resp["override_existing_id"] = usedOverrideID
			delete(resp, "block_reason")
			delete(resp, "blocked_by")
			return resp, nil
		}

		// Dual-write so explainDecision(id) resolves against audit_logs.
		// #2641 (R3 Finding 12 / PII safety): the `query` column gets a NON-PII
		// descriptor, never the raw statement (the /explain + /decisions endpoints
		// read policy_details, not this column; the StatementHash preserves
		// correlation).
		writeExplainableAuditLog(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_policy", fmt.Sprintf("mcp check_policy: %s", connectorType), computeStatementHash(statement),
			outcome.StaticResult.BlockReason, topRisk, matches,
			"") // #2598: MCP-server session has no inbound traceparent → singleton
	}

	if topRisk != "" {
		resp["risk_level"] = topRisk
	}
	if len(matches) > 0 {
		resp["policy_matches"] = matches
	}
	if overrideAvail != nil {
		resp["override_available"] = *overrideAvail
	}
	if overrideExistingID != "" {
		resp["override_existing_id"] = overrideExistingID
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
		true, // isGateway: check_output is a PEP/gateway caller (no managed connector)
	)

	blocked := outcome.SQLiBlocked || (outcome.StaticResult != nil && outcome.StaticResult.Blocked)

	// Mint decision_id up front for the same reason as
	// mcpToolCheckPolicy — surface it on every decision (allow + deny
	// + redact) per Plugin Batch 1 / ADR-042 / ADR-043.
	decisionID := uuid.New().String()
	resp := map[string]interface{}{
		"allowed":     !blocked,
		"decision_id": decisionID,
	}

	if outcome.StaticResult != nil {
		resp["policies_evaluated"] = outcome.StaticResult.PoliciesEvaluated
	}
	// Redacted content is surfaced independently of StaticResult: an Indonesia-only
	// redaction (the OJK/UU-PDP NIK path) leaves StaticResult nil, and gating the
	// masked data on StaticResult would forward the UNMASKED original to the MCP
	// client (#2563 round-2 leak). RedactedRows/RedactedMessage are set whenever
	// any source redacted.
	if outcome.RedactedRows != nil {
		resp["redacted_data"] = outcome.RedactedRows
	}
	if outcome.RedactedMessage != "" {
		resp["redacted_message"] = outcome.RedactedMessage
	}

	if outcome.ExfilInfo != nil {
		resp["exfiltration_info"] = outcome.ExfilInfo
	}

	// #2641 (MCPSRV-CHECKOUTPUT-REDACT-NO-AUDIT — the worst writer): a
	// redact-and-allow leaves blocked=false and early-returns below, writing ZERO
	// audit rows, so an OJK NIK/NPWP response mask was completely invisible to the
	// portal. Emit the canonical "redacted" row (with redacted_fields) before the
	// allow return. query is a non-PII descriptor — raw response_data MUST NOT land
	// in audit_logs.query.
	if !blocked && outcome.WasRedacted() {
		_, redactPolicyIDs, redactReasons := mcpOutputDecisionVerdict(outcome)
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_output", fmt.Sprintf("mcp check_output: %s", connectorType), "",
			mcpVerdictRedacted, redactPolicyIDs, redactReasons, outcome.RedactedFieldNames(),
			"") // MCP-server session has no inbound traceparent → singleton
	}

	// Allowed — no richer context or override flow needed.
	if !blocked {
		return resp, nil
	}

	// Block path. Mirror mcpToolCheckPolicy's richer-context + override-
	// apply + audit dual-write so check_output behaves consistently with
	// check_policy across the MCP surface.
	if outcome.SQLiBlocked {
		resp["block_reason"] = fmt.Sprintf("SQL injection detected: %s", outcome.SQLiPattern)
		// #2641 (MCPSRV-CHECKOUTPUT-SQLI-NO-AUDIT): a SQLi block carries no
		// StaticResult, so the writeExplainableAuditLog call below (gated on
		// StaticResult.Blocked) never fired — the block was portal-invisible. Emit the
		// canonical "blocked" row here. SQLi blocks have no override flow.
		writeMCPDecisionAudit(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_output", fmt.Sprintf("mcp check_output: %s", connectorType), "",
			mcpVerdictBlocked,
			[]string{"sqli_response_scan"},
			[]string{fmt.Sprintf("SQL injection detected in response: %s", outcome.SQLiPattern)},
			nil,
			"") // MCP-server session has no inbound traceparent → singleton
	} else if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		resp["block_reason"] = outcome.StaticResult.BlockReason
	}

	var matches []RicherPolicyMatch
	var topRisk string
	var overrideAvail *bool
	var overrideExistingID string
	if outcome.StaticResult != nil && outcome.StaticResult.Blocked {
		matches, topRisk, overrideAvail, overrideExistingID =
			buildRicherCheckInputBlock(ctx, usageDB, session.tenantID, session.userEmail,
				outcome.StaticResult.MatchedPolicies)

		if usedOverrideID, overriddenMatch, applied := applyOverrideToCheckInputBlock(
			ctx, usageDB, session.tenantID, session.userEmail, matches,
		); applied {
			var overriddenPolicyID string
			var overriddenPolicyVersion int
			if overriddenMatch != nil {
				overriddenPolicyID = overriddenMatch.PolicyID
				overriddenPolicyVersion = overriddenMatch.Version
			}
			writeOverrideUsedEvent(ctx, usageDB, usedOverrideID,
				decisionID, session.tenantID, session.orgID, session.clientID, session.userEmail,
				overriddenPolicyID, overriddenPolicyVersion,
				"") // #2598: MCP-server session has no inbound traceparent → singleton
			resp["allowed"] = true
			resp["override_existing_id"] = usedOverrideID
			delete(resp, "block_reason")
			return resp, nil
		}

		// Dual-write for explainability. #2641 (R3 Finding 12 / PII safety): hash the
		// actual response content for correlation, but record only a NON-PII
		// descriptor in the `query` column (the /explain + /decisions endpoints read
		// policy_details, not this column) so a PII-bearing response never lands in a
		// long-retained audit column.
		hashed := message
		if hashed == "" {
			hashed = fmt.Sprintf("(rows=%d)", rowCount)
		}
		writeExplainableAuditLog(ctx, usageDB,
			decisionID, uuid.New().String(),
			session.tenantID, session.orgID, session.clientID, session.userEmail,
			session.userID, session.userRole,
			"mcp_check_output", fmt.Sprintf("mcp check_output: %s", connectorType), computeStatementHash(hashed),
			outcome.StaticResult.BlockReason, topRisk, matches,
			"") // #2598: MCP-server session has no inbound traceparent → singleton
	}

	if topRisk != "" {
		resp["risk_level"] = topRisk
	}
	if len(matches) > 0 {
		resp["policy_matches"] = matches
	}
	if overrideAvail != nil {
		resp["override_available"] = *overrideAvail
	}
	if overrideExistingID != "" {
		resp["override_existing_id"] = overrideExistingID
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
	// v9 identity wire (ADR-052 §5 / ADR-053 §Step 2): X-Client-ID is the
	// canonical credential identity; X-Tenant-ID is the deprecated alias.
	// X-Org-ID is the RLS boundary (Phase 4 + future Phase 8 RLS roll-in).
	req.Header.Set("X-Tenant-ID", session.tenantID)
	req.Header.Set("X-Client-ID", session.clientID)
	req.Header.Set("X-Org-ID", session.orgID)
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
	// v9 identity wire (ADR-052 §5): forward all three so local proxy
	// callees can read either alias during compat.
	req.Header.Set("X-Tenant-ID", session.tenantID)
	req.Header.Set("X-Client-ID", session.clientID)
	req.Header.Set("X-Org-ID", session.orgID)

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

// mcpToolListRecentDecisions proxies to GET /api/v1/decisions with the
// caller's filters, preserving the V1 429 upgrade envelope as a structured
// result so plugin hosts (Cursor / Claude / Codex / OpenClaw) can render the
// upgrade prompt — never swallow it as a generic error per
// feedback_429_no_upgrade_hint_is_conversion_gap.md.
//
// Does NOT use the shared mcpProxyToOrchestrator helper because that helper
// collapses every non-2xx into a Go error string, which would drop the
// envelope on the floor. This function does its own GET, branches on 429
// to return {envelope: ..., upgrade_required: true} as the result, and
// otherwise mirrors the orchestrator response directly.
func mcpToolListRecentDecisions(session *mcpSession, args map[string]interface{}) (interface{}, error) {
	if orchestratorURL == "" {
		return nil, fmt.Errorf("orchestrator not configured")
	}

	query := url.Values{}
	if v, ok := args["since"].(string); ok && v != "" {
		query.Set("since", v)
	}
	if v, ok := args["decision"].(string); ok && v != "" {
		query.Set("decision", v)
	}
	if v, ok := args["policy_id"].(string); ok && v != "" {
		query.Set("policy_id", v)
	}
	if v, ok := args["tool_signature"].(string); ok && v != "" {
		query.Set("tool_signature", v)
	}
	// JSON numbers decode as float64 in encoding/json default mode; cast
	// to int for the query string. Negative / zero values are server-side
	// rejected (400) which we forward through.
	if v, ok := args["limit"].(float64); ok && v > 0 {
		query.Set("limit", fmt.Sprintf("%d", int(v)))
	}
	target := orchestratorURL + "/api/v1/decisions"
	if qs := query.Encode(); qs != "" {
		target += "?" + qs
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// v9 identity wire (ADR-052 §5 / ADR-053 §Step 2).
	req.Header.Set("X-Tenant-ID", session.tenantID)
	req.Header.Set("X-Client-ID", session.clientID)
	req.Header.Set("X-Org-ID", session.orgID)
	if session.userID != "" {
		req.Header.Set("X-User-ID", session.userID)
	}
	if session.userEmail != "" {
		req.Header.Set("X-User-Email", session.userEmail)
	}
	// Forward the per-tenant SaaS Plugin tier so the orchestrator-side
	// resolveDecisionListTier picks Free/Pro/Premium correctly. The agent
	// captured this tier at authenticate time from the X-License-Token
	// DB lookup; mcpSession persists it across the MCP session lifetime.
	if session.tier != "" {
		req.Header.Set("X-Axonflow-Effective-Tier", session.tier)
	}
	// ADR-052 §5: BasicAuth username is the credential identity (clientID),
	// not the tenant scope. Matches sibling forwarder mcpProxyToAgent at
	// line 1497 so all three orchestrator forwarders agree.
	req.SetBasicAuth(session.clientID, "internal")
	if proxyTokenGenerator != nil {
		req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(proxyTokenGenerator))
	}

	resp, err := orchestratorHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("orchestrator request failed: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, mcpMaxResponseBody)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// 429 is the V1 cap-hit envelope path. Preserve the structured body
	// so the host LLM/UI can render upgrade.compare_url + the wording.
	// Wrap with `upgrade_required: true` so a host parser doesn't have
	// to introspect the limit_type field to know this is a paywall hit.
	if resp.StatusCode == http.StatusTooManyRequests {
		var envelope map[string]interface{}
		if jsonErr := json.Unmarshal(respBody, &envelope); jsonErr != nil {
			// Bare 429 with no envelope — pre-V1.1 deployment or a
			// transport-layer rejection. Surface the raw body so the
			// host gets at least the textual upgrade prompt.
			envelope = map[string]interface{}{"error": string(respBody)}
		}
		return map[string]interface{}{
			"upgrade_required": true,
			"envelope":         envelope,
		}, nil
	}

	if resp.StatusCode >= 400 {
		// Non-429 4xx/5xx — forward as a structured error string. Tests
		// covering 401/400 paths rely on this.
		return nil, fmt.Errorf("orchestrator returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result interface{}
	if jsonErr := json.Unmarshal(respBody, &result); jsonErr != nil {
		return string(respBody), nil
	}
	return result, nil
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
	// v9 identity wire (ADR-052 §5 / ADR-053 §Step 2).
	req.Header.Set("X-Tenant-ID", session.tenantID)
	req.Header.Set("X-Client-ID", session.clientID)
	req.Header.Set("X-Org-ID", session.orgID)
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
	// Basic auth required by Orchestrator audit endpoints. ADR-052 §5: the
	// BasicAuth username is the credential identity (clientID), not the
	// tenant scope. Matches sibling forwarder mcpProxyToAgent (line 1497)
	// so all three orchestrator forwarders agree.
	req.SetBasicAuth(session.clientID, "internal")

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
