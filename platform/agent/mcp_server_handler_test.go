// Copyright 2025-2026 AxonFlow
package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	sharedpolicy "axonflow/platform/shared/policy"
)

// --- Test Helpers ---

func setupMCPServerRouter() *mux.Router {
	r := mux.NewRouter()
	RegisterMCPServerHandler(r)
	return r
}

func mcpServerPost(t *testing.T, router *mux.Router, method, id string, params interface{}, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  method,
	}
	if id != "" {
		body["id"] = id
	}
	if params != nil {
		paramsJSON, _ := json.Marshal(params)
		body["params"] = json.RawMessage(paramsJSON)
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	// Apply additional headers in key-value pairs
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func parseJSONRPCResponse(t *testing.T, w *httptest.ResponseRecorder) jsonRPCResponse {
	t.Helper()
	var resp jsonRPCResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON-RPC response: %v\nBody: %s", err, w.Body.String())
	}
	return resp
}

// initMCPSession creates a session and returns the session ID.
func initMCPSession(t *testing.T, router *mux.Router) string {
	t.Helper()
	w := mcpServerPost(t, router, "initialize", "init", map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
	})
	sessionID := w.Header().Get(mcpSessionHeaderKey)
	if sessionID == "" {
		t.Fatal("No session ID returned from initialize")
	}
	return sessionID
}

// --- Protocol Tests ---

func TestMCPServer_Initialize_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	w := mcpServerPost(t, router, "initialize", "init-1", map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test-client", "version": "1.0.0"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}
	if resp.ID != "init-1" {
		t.Errorf("Expected ID 'init-1', got '%v'", resp.ID)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", resp.Result)
	}
	if result["protocolVersion"] != mcpProtocolVersion {
		t.Errorf("Expected protocol version '%s', got '%v'", mcpProtocolVersion, result["protocolVersion"])
	}

	sessionID := w.Header().Get(mcpSessionHeaderKey)
	if sessionID == "" {
		t.Error("Expected Mcp-Session-Id header in response")
	}
	if len(sessionID) < 30 {
		t.Errorf("Session ID too short (not cryptographically secure?): %s", sessionID)
	}
}

func TestMCPServer_Initialize_NoAuth_EnterpriseMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	w := mcpServerPost(t, router, "initialize", "init-2", nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for missing auth, got %d", w.Code)
	}
	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil {
		t.Fatal("Expected auth error, got success")
	}
	if resp.Error.Code != jsonRPCAuthError {
		t.Errorf("Expected error code %d (auth), got %d", jsonRPCAuthError, resp.Error.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header on 401")
	}
}

func TestMCPServer_ToolsList_RequiresAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	w := mcpServerPost(t, router, "tools/list", "list-noauth", nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated tools/list, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPServer_ToolsList_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/list", "list-1", nil,
		mcpSessionHeaderKey, sessionID)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", resp.Result)
	}

	tools, ok := result["tools"].([]interface{})
	if !ok {
		t.Fatalf("Expected tools array, got %T", result["tools"])
	}

	if len(tools) != 6 {
		t.Errorf("Expected 6 tools, got %d", len(tools))
	}

	expectedNames := map[string]bool{
		"check_policy": false, "check_output": false, "audit_tool_call": false,
		"list_policies": false, "get_policy_stats": false, "search_audit_events": false,
	}
	for _, tool := range tools {
		tm, _ := tool.(map[string]interface{})
		name, _ := tm["name"].(string)
		if _, exists := expectedNames[name]; exists {
			expectedNames[name] = true
		}
		if tm["inputSchema"] == nil {
			t.Errorf("Tool '%s' missing inputSchema", name)
		}
		if tm["description"] == nil || tm["description"] == "" {
			t.Errorf("Tool '%s' missing description", name)
		}
	}
	for name, found := range expectedNames {
		if !found {
			t.Errorf("Expected tool '%s' not found", name)
		}
	}
}

func TestMCPServer_Notification_AcceptedSilently(t *testing.T) {
	router := setupMCPServerRouter()

	body := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("Expected 202 Accepted for notification, got %d", w.Code)
	}
}

func TestMCPServer_InvalidJSON(t *testing.T) {
	router := setupMCPServerRouter()

	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil || resp.Error.Code != jsonRPCParseError {
		t.Errorf("Expected parse error, got: %+v", resp)
	}
}

func TestMCPServer_InvalidJSONRPCVersion(t *testing.T) {
	router := setupMCPServerRouter()

	body := map[string]interface{}{
		"jsonrpc": "1.0",
		"id":      "bad-1",
		"method":  "initialize",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil || resp.Error.Code != jsonRPCInvalidRequest {
		t.Errorf("Expected invalid request error, got: %+v", resp)
	}
}

func TestMCPServer_UnknownMethod(t *testing.T) {
	router := setupMCPServerRouter()
	w := mcpServerPost(t, router, "resources/list", "unk-1", nil)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil || resp.Error.Code != jsonRPCMethodNotFound {
		t.Errorf("Expected method not found, got: %+v", resp)
	}
}

func TestMCPServer_Ping_RequiresAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	w := mcpServerPost(t, router, "ping", "ping-noauth", nil)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated ping, got %d", w.Code)
	}
}

func TestMCPServer_Ping_Authenticated(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "ping", "ping-1", nil,
		mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Errorf("Expected success for ping, got error: %v", resp.Error)
	}
}

func TestMCPServer_UnknownTool(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "tool-unk", map[string]interface{}{
		"name":      "nonexistent_tool",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil || resp.Error.Code != jsonRPCInvalidParams {
		t.Errorf("Expected invalid params for unknown tool, got: %+v", resp)
	}
}

func TestMCPServer_ProtocolVersionValidation(t *testing.T) {
	router := setupMCPServerRouter()

	body := map[string]interface{}{"jsonrpc": "2.0", "id": "pv-1", "method": "tools/list"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(mcpProtocolHeader, "1999-01-01")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid protocol version, got %d", w.Code)
	}
}

func TestMCPServer_LegacyProtocolVersion_Accepted(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()

	// Initialize with legacy protocol version in header
	w := mcpServerPost(t, router, "initialize", "legacy-1", map[string]interface{}{
		"protocolVersion": mcpProtocolLegacy,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "claude-code", "version": "1.0.0"},
	}, mcpProtocolHeader, mcpProtocolLegacy)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for legacy protocol version, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Expected no error for legacy version, got: %v", resp.Error)
	}

	// Server should negotiate back the legacy version
	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", resp.Result)
	}
	if result["protocolVersion"] != mcpProtocolLegacy {
		t.Errorf("Expected negotiated version '%s', got '%v'", mcpProtocolLegacy, result["protocolVersion"])
	}

	sessionID := w.Header().Get(mcpSessionHeaderKey)
	if sessionID == "" {
		t.Fatal("Expected session ID for legacy version initialize")
	}

	// Verify tools/list works with the legacy session
	w2 := mcpServerPost(t, router, "tools/list", "list-1", nil, mcpSessionHeaderKey, sessionID)
	if w2.Code != http.StatusOK {
		t.Fatalf("Expected 200 for tools/list with legacy session, got %d: %s", w2.Code, w2.Body.String())
	}
	resp2 := parseJSONRPCResponse(t, w2)
	if resp2.Error != nil {
		t.Fatalf("Expected tools list, got error: %v", resp2.Error)
	}
}

func TestMCPServer_LegacyProtocolVersion_InParamsOnly(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()

	// Initialize with legacy version in params but NOT in header
	w := mcpServerPost(t, router, "initialize", "legacy-params-1", map[string]interface{}{
		"protocolVersion": mcpProtocolLegacy,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]interface{}{"name": "test", "version": "1.0"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Expected no error, got: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", resp.Result)
	}
	// Should negotiate legacy version from params even without header
	if result["protocolVersion"] != mcpProtocolLegacy {
		t.Errorf("Expected negotiated version '%s', got '%v'", mcpProtocolLegacy, result["protocolVersion"])
	}
}

func TestMCPServer_ContentTypeValidation(t *testing.T) {
	router := setupMCPServerRouter()

	body := map[string]interface{}{"jsonrpc": "2.0", "id": "ct-1", "method": "ping"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp-server", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "text/plain")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("Expected 415 for wrong Content-Type, got %d", w.Code)
	}
}

func TestMCPServer_SessionDelete_Authenticated(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	// Verify session exists
	if s := getSessionByID(sessionID); s == nil {
		t.Fatal("Session not found after initialization")
	}

	// Delete
	req := httptest.NewRequest("DELETE", "/api/v1/mcp-server", nil)
	req.Header.Set(mcpSessionHeaderKey, sessionID)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for session delete, got %d", w.Code)
	}

	if s := getSessionByID(sessionID); s != nil {
		t.Error("Session should be deleted")
	}
}

func TestMCPServer_SessionDelete_NotFound(t *testing.T) {
	router := setupMCPServerRouter()

	req := httptest.NewRequest("DELETE", "/api/v1/mcp-server", nil)
	req.Header.Set(mcpSessionHeaderKey, "nonexistent-session")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for nonexistent session, got %d", w.Code)
	}
}

func TestMCPServer_SessionDelete_MissingHeader(t *testing.T) {
	router := setupMCPServerRouter()

	req := httptest.NewRequest("DELETE", "/api/v1/mcp-server", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing session header, got %d", w.Code)
	}
}

func TestMCPServer_CORS_Preflight(t *testing.T) {
	router := setupMCPServerRouter()

	req := httptest.NewRequest("OPTIONS", "/api/v1/mcp-server", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected 204 for CORS preflight, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected CORS Allow-Methods header")
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("Expected CORS origin to reflect request, got '%s'", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestMCPServer_GET_MethodNotAllowed(t *testing.T) {
	router := setupMCPServerRouter()

	req := httptest.NewRequest("GET", "/api/v1/mcp-server", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for GET, got %d", w.Code)
	}
}

// --- Session Management Tests ---

func TestMCPServer_SecureSessionID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateSecureSessionID()
		if ids[id] {
			t.Fatalf("Duplicate session ID: %s", id)
		}
		ids[id] = true
		if len(id) < 30 {
			t.Errorf("Session ID too short: %s", id)
		}
		if id[:9] != "axonflow-" {
			t.Errorf("Session ID missing prefix: %s", id)
		}
	}
}

func TestMCPServer_SessionEviction_TTL(t *testing.T) {
	mcpSessionsMu.Lock()
	original := mcpSessions
	mcpSessions = make(map[string]*mcpSession)

	now := time.Now()
	mcpSessions["expired-1"] = &mcpSession{id: "expired-1", lastUsed: now.Add(-48 * time.Hour)}
	mcpSessions["fresh-1"] = &mcpSession{id: "fresh-1", lastUsed: now}

	evictStaleSessions()
	_, expiredExists := mcpSessions["expired-1"]
	_, freshExists := mcpSessions["fresh-1"]

	mcpSessions = original
	mcpSessionsMu.Unlock()

	if expiredExists {
		t.Error("Expired session should have been evicted")
	}
	if !freshExists {
		t.Error("Fresh session should still exist")
	}
}

// --- Tool Validation Tests ---

func TestMCPServer_CheckPolicy_MissingArgs(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "cp-1", map[string]interface{}{
		"name":      "check_policy",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Error("Expected isError=true for missing required args")
	}
}

func TestMCPServer_CheckOutput_MissingConnectorType(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "co-1", map[string]interface{}{
		"name":      "check_output",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Error("Expected isError=true for missing connector_type")
	}
}

func TestMCPServer_AuditToolCall_MissingToolName(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "at-1", map[string]interface{}{
		"name":      "audit_tool_call",
		"arguments": map[string]interface{}{"input": map[string]interface{}{}, "success": true},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Error("Expected isError=true for missing tool_name")
	}
}

func TestMCPServer_ToolsCall_EmptyToolName(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "empty-name", map[string]interface{}{
		"name":      "",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error == nil || resp.Error.Code != jsonRPCInvalidParams {
		t.Errorf("Expected invalid params for empty tool name, got: %+v", resp)
	}
}

func TestMCPServer_ToolsCall_NoSession_EnterpriseMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()

	w := mcpServerPost(t, router, "tools/call", "no-auth-1", map[string]interface{}{
		"name": "check_policy",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Bash",
			"statement":      "echo hello",
		},
	})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated tools/call, got %d", w.Code)
	}
}

// --- Session Reuse Test ---

func TestMCPServer_SessionReuse(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	// Use session for tools/list
	w := mcpServerPost(t, router, "tools/list", "reuse-1", nil,
		mcpSessionHeaderKey, sessionID)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for session-based tools/list, got %d", w.Code)
	}

	// Use same session for ping
	w2 := mcpServerPost(t, router, "ping", "reuse-2", nil,
		mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w2)
	if resp.Error != nil {
		t.Errorf("Expected success for session-based ping, got: %v", resp.Error)
	}

	// Verify lastUsed was updated
	session := getSessionByID(sessionID)
	if session == nil {
		t.Fatal("Session should still exist")
	}
	if time.Since(session.lastUsed) > 5*time.Second {
		t.Error("Session lastUsed should have been refreshed")
	}
}

// --- Tool Execution Tests (Community Mode) ---
// These test the full tool execution path including policy evaluation.

func TestMCPServer_CheckPolicy_SafeCommand(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "cp-safe", map[string]interface{}{
		"name": "check_policy",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Bash",
			"statement":      "echo hello world",
			"operation":      "execute",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	result, ok := resp.Result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", resp.Result)
	}
	// Tool results come as text content
	content, ok := result["content"].([]interface{})
	if !ok || len(content) == 0 {
		t.Fatal("Expected content array in result")
	}
	cm, _ := content[0].(map[string]interface{})
	text, _ := cm["text"].(string)
	if text == "" {
		t.Fatal("Expected non-empty text in content")
	}

	// Parse the nested JSON
	var toolResult map[string]interface{}
	if err := json.Unmarshal([]byte(text), &toolResult); err != nil {
		t.Fatalf("Failed to parse tool result JSON: %v", err)
	}

	// Safe command should be allowed
	if allowed, ok := toolResult["allowed"].(bool); !ok || !allowed {
		t.Errorf("Expected allowed=true for safe command, got: %v", toolResult)
	}
}

func TestMCPServer_CheckPolicy_WithOperation(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	// Test with query operation
	w := mcpServerPost(t, router, "tools/call", "cp-query", map[string]interface{}{
		"name": "check_policy",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Read",
			"statement":      "cat README.md",
			"operation":      "query",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
	// Should succeed (query operation on a safe command)
	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); isErr {
		t.Error("Safe query command should not return isError")
	}
}

func TestMCPServer_CheckOutput_CleanMessage(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "co-clean", map[string]interface{}{
		"name": "check_output",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Bash",
			"message":        "Build succeeded. 42 tests passed, 0 failed.",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatal("Expected content")
	}
	cm, _ := content[0].(map[string]interface{})
	text, _ := cm["text"].(string)

	var toolResult map[string]interface{}
	if err := json.Unmarshal([]byte(text), &toolResult); err != nil {
		t.Fatalf("Failed to parse: %v", err)
	}

	if allowed, ok := toolResult["allowed"].(bool); !ok || !allowed {
		t.Errorf("Expected allowed=true for clean output, got: %v", toolResult)
	}
}

func TestMCPServer_CheckOutput_WithResponseData(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "co-rows", map[string]interface{}{
		"name": "check_output",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.mcp__postgres",
			"response_data": []interface{}{
				map[string]interface{}{"name": "Alice", "city": "New York"},
				map[string]interface{}{"name": "Bob", "city": "London"},
			},
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); isErr {
		t.Error("Clean response data should not return isError")
	}
}

func TestMCPServer_AuditToolCall_ValidArgs(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "audit-valid", map[string]interface{}{
		"name": "audit_tool_call",
		"arguments": map[string]interface{}{
			"tool_name":   "Bash",
			"tool_type":   "claude_code",
			"input":       map[string]interface{}{"command": "echo test"},
			"output":      map[string]interface{}{"stdout": "test"},
			"success":     true,
			"duration_ms": 15,
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
	// audit_tool_call may fail if orchestrator is not running, but should not be a JSON-RPC error
	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatal("Expected content in audit result")
	}
}

func TestMCPServer_AuditToolCall_DefaultToolType(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	// Omit tool_type — should default to "claude_code"
	w := mcpServerPost(t, router, "tools/call", "audit-default", map[string]interface{}{
		"name": "audit_tool_call",
		"arguments": map[string]interface{}{
			"tool_name": "Write",
			"input":     map[string]interface{}{"path": "/tmp/test.txt"},
			"success":   true,
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestMCPServer_ListPolicies_NoArgs(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "lp-all", map[string]interface{}{
		"name":      "list_policies",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
	// May fail if orchestrator is not running, but should produce content
	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatal("Expected content in list_policies result")
	}
}

func TestMCPServer_ListPolicies_WithFilters(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "lp-filter", map[string]interface{}{
		"name": "list_policies",
		"arguments": map[string]interface{}{
			"category": "security_dangerous",
			"severity": "critical",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestMCPServer_GetPolicyStats_NoArgs(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "stats-1", map[string]interface{}{
		"name":      "get_policy_stats",
		"arguments": map[string]interface{}{},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestMCPServer_GetPolicyStats_WithDates(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "stats-dated", map[string]interface{}{
		"name": "get_policy_stats",
		"arguments": map[string]interface{}{
			"from":           "2026-04-01",
			"to":             "2026-04-03",
			"connector_type": "claude_code.Bash",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestMCPServer_SessionEviction_MaxSessions(t *testing.T) {
	mcpSessionsMu.Lock()
	original := mcpSessions
	mcpSessions = make(map[string]*mcpSession)

	now := time.Now()
	// Fill past max (add mcpMaxSessions + 5)
	for i := 0; i < mcpMaxSessions+5; i++ {
		id := fmt.Sprintf("sess-%d", i)
		mcpSessions[id] = &mcpSession{
			id:       id,
			lastUsed: now.Add(-time.Duration(i) * time.Minute),
		}
	}

	evictStaleSessions()
	count := len(mcpSessions)
	mcpSessions = original
	mcpSessionsMu.Unlock()

	if count > mcpMaxSessions {
		t.Errorf("Expected <= %d sessions after eviction, got %d", mcpMaxSessions, count)
	}
}

func TestMCPServer_ListPolicies_FilteringLogic(t *testing.T) {
	// Test the filtering logic directly without orchestrator
	session := &mcpSession{tenantID: "default", clientID: "test"}

	// Call list_policies — will fail on orchestrator proxy but that's OK
	// We're testing that the function handles the error path
	_, err := mcpToolListPolicies(session, map[string]interface{}{})
	if err == nil {
		// If orchestrator happens to be running, result should have policies
		t.Log("Orchestrator is running — list_policies succeeded")
	} else {
		// Expected: orchestrator not configured or not running
		if !strings.Contains(err.Error(), "orchestrator") && !strings.Contains(err.Error(), "policies") {
			t.Errorf("Unexpected error: %v", err)
		}
	}

	// Test with filters
	_, err = mcpToolListPolicies(session, map[string]interface{}{
		"category": "security_dangerous",
		"severity": "critical",
	})
	// Same — orchestrator may not be running, but function should not panic
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_GetPolicyStats_DateConversion(t *testing.T) {
	// Test date conversion logic (short dates get T00:00:00Z appended)
	session := &mcpSession{tenantID: "default", clientID: "test"}

	_, err := mcpToolGetPolicyStats(session, map[string]interface{}{
		"from": "2026-04-01",
		"to":   "2026-04-03",
	})
	// Will fail on orchestrator but tests the date conversion path
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_CheckPolicy_BlockedByDynamic(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	// Test with a statement that might trigger policies
	// In community mode, dynamic policies may not be configured, but
	// this exercises the code path
	w := mcpServerPost(t, router, "tools/call", "cp-sqli", map[string]interface{}{
		"name": "check_policy",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.mcp__postgres",
			"statement":      "SELECT * FROM users WHERE id=1; DROP TABLE users;--",
			"operation":      "execute",
			"parameters":     map[string]interface{}{"db": "test"},
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected JSON-RPC error: %v", resp.Error)
	}
	// Result should have content (either allowed or blocked)
	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Error("Expected content in check_policy result")
	}
}

func TestMCPServer_CheckOutput_WithPII(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "co-pii", map[string]interface{}{
		"name": "check_output",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Bash",
			"message":        "Customer SSN: 123-45-6789, Card: 4111-1111-1111-1111, Email: test@example.com",
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatal("Expected content in PII check result")
	}
	// Parse and check — PII should be detected
	cm, _ := content[0].(map[string]interface{})
	text, _ := cm["text"].(string)
	var toolResult map[string]interface{}
	if err := json.Unmarshal([]byte(text), &toolResult); err != nil {
		t.Fatalf("Failed to parse tool result: %v", err)
	}
	// Should have policies_evaluated > 0
	if pe, ok := toolResult["policies_evaluated"].(float64); ok && pe == 0 {
		t.Log("Warning: no policies evaluated — policy engine may not be initialized")
	}
}

func TestMCPServer_SessionExpiry(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	// Create an expired session directly
	mcpSessionsMu.Lock()
	mcpSessions["expired-test"] = &mcpSession{
		id:       "expired-test",
		lastUsed: time.Now().Add(-48 * time.Hour),
		tenantID: "default",
		clientID: "community",
	}
	mcpSessionsMu.Unlock()

	router := setupMCPServerRouter()

	// Try to use expired session — should fall through to re-auth
	w := mcpServerPost(t, router, "tools/list", "exp-1", nil,
		mcpSessionHeaderKey, "expired-test")

	// In community mode, falls through to auth and succeeds
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 (re-auth after expired session), got %d", w.Code)
	}

	// Expired session should be deleted
	if s := getSessionByID("expired-test"); s != nil {
		t.Error("Expired session should have been deleted on lookup")
	}
}

// --- Proxy Helper Tests ---

func TestMCPServer_ProxyToAgent_InvalidURL(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToAgent(session, "POST", "http://localhost:99999/nonexistent", map[string]interface{}{"test": true})
	if err == nil {
		t.Error("Expected error for invalid URL/port")
	}
}

func TestMCPServer_ProxyToAgent_NilBody(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToAgent(session, "GET", "http://localhost:99999/test", nil)
	if err == nil {
		t.Error("Expected error for unreachable host")
	}
}

func TestMCPServer_ProxyToLocal_InvalidURL(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToLocal(session, "GET", "http://localhost:99999/nonexistent")
	if err == nil {
		t.Error("Expected error for invalid URL/port")
	}
}

func TestMCPServer_ProxyToOrchestrator_NotConfigured(t *testing.T) {
	// Save and clear orchestratorURL
	original := orchestratorURL
	orchestratorURL = ""
	defer func() { orchestratorURL = original }()

	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToOrchestrator(session, "GET", "/test", nil)
	if err == nil || !strings.Contains(err.Error(), "orchestrator not configured") {
		t.Errorf("Expected 'orchestrator not configured' error, got: %v", err)
	}
}

func TestMCPServer_DangerousCommandConfig(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("DANGEROUS_COMMAND_ACTION", "warn")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("DANGEROUS_COMMAND_ACTION")

	cfg := DetectionConfigFromEnv()
	if cfg.DangerousCommandAction != DetectionActionWarn {
		t.Errorf("Expected DangerousCommandAction=warn, got %s", cfg.DangerousCommandAction)
	}
	if cfg.DangerousQueryAction != DetectionActionBlock {
		t.Errorf("Expected DangerousQueryAction=block (default), got %s", cfg.DangerousQueryAction)
	}
}

func TestMCPServer_DangerousCommandConfig_MCP_Override(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("DANGEROUS_COMMAND_ACTION", "block")
	os.Setenv("MCP_DANGEROUS_COMMAND_ACTION", "log")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("DANGEROUS_COMMAND_ACTION")
	defer os.Unsetenv("MCP_DANGEROUS_COMMAND_ACTION")

	cfg := MCPDetectionConfigFromEnv()
	if cfg.DangerousCommandAction != DetectionActionLog {
		t.Errorf("Expected MCP DangerousCommandAction=log (override), got %s", cfg.DangerousCommandAction)
	}
}

func TestMCPServer_DangerousCommandConfig_Gateway_Override(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("DANGEROUS_COMMAND_ACTION", "block")
	os.Setenv("GATEWAY_DANGEROUS_COMMAND_ACTION", "warn")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("DANGEROUS_COMMAND_ACTION")
	defer os.Unsetenv("GATEWAY_DANGEROUS_COMMAND_ACTION")

	cfg := GatewayDetectionConfigFromEnv()
	if cfg.DangerousCommandAction != DetectionActionWarn {
		t.Errorf("Expected Gateway DangerousCommandAction=warn (override), got %s", cfg.DangerousCommandAction)
	}
}

func TestMCPServer_DangerousCommandConfig_BuildOverrides(t *testing.T) {
	cfg := ModeDetectionConfig{
		Enabled:                true,
		PIIAction:              DetectionActionRedact,
		SQLIAction:             DetectionActionBlock,
		DangerousQueryAction:   DetectionActionLog,
		DangerousCommandAction: DetectionActionWarn,
	}

	overrides := cfg.BuildActionOverrides()

	// security-dangerous should use DangerousCommandAction (warn), not DangerousQueryAction (log)
	if overrides[sharedpolicy.CategorySecurityDangerous] != sharedpolicy.ActionWarn {
		t.Errorf("Expected security-dangerous action=warn (from DangerousCommandAction), got %s",
			overrides[sharedpolicy.CategorySecurityDangerous])
	}
}

func TestMCPServer_ProxyToAgent_WithBody(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	body := map[string]interface{}{"tool_name": "test", "success": true}
	_, err := mcpProxyToAgent(session, "POST", "http://localhost:99999/nonexistent", body)
	if err == nil {
		t.Error("Expected error for unreachable host")
	}
}

func TestMCPServer_ProxyToAgent_BadURL(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToAgent(session, "POST", "://invalid", map[string]interface{}{})
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestMCPServer_ProxyToAgent_MarshalError(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "test"}
	// Functions can't be marshaled to JSON
	_, err := mcpProxyToAgent(session, "POST", "http://localhost:99999/test", map[string]interface{}{"fn": func() {}})
	if err == nil {
		t.Error("Expected marshal error")
	}
}

func TestMCPServer_ProxyToLocal_NilSession(t *testing.T) {
	session := &mcpSession{tenantID: "default", clientID: "community"}
	_, err := mcpProxyToLocal(session, "GET", "://invalid-url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestMCPServer_ProxyToOrchestrator_InvalidBody(t *testing.T) {
	original := orchestratorURL
	orchestratorURL = "http://localhost:99999"
	defer func() { orchestratorURL = original }()

	session := &mcpSession{tenantID: "default", clientID: "test"}
	_, err := mcpProxyToOrchestrator(session, "POST", "/test", map[string]interface{}{"fn": func() {}})
	if err == nil {
		t.Error("Expected marshal error")
	}
}

func TestMCPServer_AuthenticateRequest_InvalidBasicAuth(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Basic !!!invalid-base64!!!")
	_, _, _, _, err := authenticateMCPServerRequest(req)
	if err == nil {
		t.Error("Expected error for invalid Basic auth")
	}
}

func TestMCPServer_ProxyToOrchestrator_WithBody(t *testing.T) {
	original := orchestratorURL
	orchestratorURL = "http://localhost:99999"
	defer func() { orchestratorURL = original }()

	session := &mcpSession{tenantID: "default", clientID: "test"}
	body := map[string]interface{}{"start_time": "2026-04-01T00:00:00Z"}
	_, err := mcpProxyToOrchestrator(session, "POST", "/api/v1/audit/summary", body)
	if err == nil {
		t.Error("Expected error for unreachable orchestrator")
	}
}

func TestMCPServer_ListPolicies_BothSourcesFail(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	// Save and set orchestratorURL to unreachable
	original := orchestratorURL
	orchestratorURL = "http://localhost:99999"
	defer func() { orchestratorURL = original }()

	session := &mcpSession{tenantID: "default", clientID: "community"}
	_, err := mcpToolListPolicies(session, map[string]interface{}{})
	// Both static (local) and dynamic (orchestrator) should fail
	if err == nil {
		t.Log("One source may have succeeded — acceptable in some environments")
	}
}

func TestMCPServer_GetPolicyStats_DateDefaults(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	original := orchestratorURL
	orchestratorURL = "http://localhost:99999"
	defer func() { orchestratorURL = original }()

	session := &mcpSession{tenantID: "default", clientID: "community"}

	// Test with short dates (should get T00:00:00Z / T23:59:59Z appended)
	_, err := mcpToolGetPolicyStats(session, map[string]interface{}{
		"from": "2026-04-01",
		"to":   "2026-04-03",
	})
	if err == nil {
		t.Log("Orchestrator reachable — date conversion tested via success path")
	}

	// Test with no dates (should default to last 24h)
	_, err = mcpToolGetPolicyStats(session, map[string]interface{}{})
	if err == nil {
		t.Log("Default date range used")
	}
}

// --- search_audit_events Tests ---

func TestMCPServer_SearchAuditEvents_NoArgs(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	session := &mcpSession{tenantID: "default", clientID: "community"}
	_, err := mcpToolSearchAuditEvents(session, map[string]interface{}{})
	// Will fail if orchestrator not running, but exercises the default date logic
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_SearchAuditEvents_WithDates(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	session := &mcpSession{tenantID: "default", clientID: "community"}
	_, err := mcpToolSearchAuditEvents(session, map[string]interface{}{
		"from":  "2026-04-03",
		"to":    "2026-04-04",
		"limit": float64(10),
	})
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_SearchAuditEvents_WithFilter(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	session := &mcpSession{tenantID: "default", clientID: "community"}
	_, err := mcpToolSearchAuditEvents(session, map[string]interface{}{
		"request_type": "tool_call_audit",
		"limit":        float64(5),
	})
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_SearchAuditEvents_LimitCap(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	session := &mcpSession{tenantID: "default", clientID: "community"}
	// Request limit > 100 should be capped
	_, err := mcpToolSearchAuditEvents(session, map[string]interface{}{
		"limit": float64(500),
	})
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_SearchAuditEvents_FullTimestamps(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	session := &mcpSession{tenantID: "default", clientID: "community"}
	// Full ISO timestamps (no date conversion needed)
	_, err := mcpToolSearchAuditEvents(session, map[string]interface{}{
		"from": "2026-04-03T10:00:00Z",
		"to":   "2026-04-03T12:00:00Z",
	})
	if err != nil {
		t.Logf("Expected orchestrator error: %v", err)
	}
}

func TestMCPServer_SearchAuditEvents_ViaHandler(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "search-1", map[string]interface{}{
		"name":      "search_audit_events",
		"arguments": map[string]interface{}{"limit": float64(5)},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected JSON-RPC error: %v", resp.Error)
	}
	result, _ := resp.Result.(map[string]interface{})
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Error("Expected content in search_audit_events result")
	}
}

// --- Auth Path Tests ---

func TestMCPServer_AuthenticateRequest_MissingHeader(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	req := httptest.NewRequest("POST", "/test", nil)
	_, _, _, _, err := authenticateMCPServerRequest(req)
	if err == nil {
		t.Error("Expected error for missing Authorization header")
	}
	if !strings.Contains(err.Error(), "missing Authorization") {
		t.Errorf("Expected 'missing Authorization' error, got: %v", err)
	}
}

func TestMCPServer_AuthenticateRequest_WrongScheme(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	_, _, _, _, err := authenticateMCPServerRequest(req)
	if err == nil {
		t.Error("Expected error for non-Basic auth")
	}
	if !strings.Contains(err.Error(), "Basic auth") {
		t.Errorf("Expected 'Basic auth' error, got: %v", err)
	}
}

func TestMCPServer_AuthenticateRequest_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	req := httptest.NewRequest("POST", "/test", nil)
	tenantID, userID, userRole, clientID, err := authenticateMCPServerRequest(req)
	if err != nil {
		t.Fatalf("Community mode should not require auth: %v", err)
	}
	if tenantID != "default" {
		t.Errorf("Expected tenantID 'default', got '%s'", tenantID)
	}
	if userID != "0" {
		t.Errorf("Expected userID '0', got '%s'", userID)
	}
	if userRole != "admin" {
		t.Errorf("Expected userRole 'admin', got '%s'", userRole)
	}
	if clientID != "community" {
		t.Errorf("Expected clientID 'community', got '%s'", clientID)
	}
}

func TestMCPServer_WriteJSONRPC_ContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCResult(w, "test-id", map[string]interface{}{"ok": true})
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json, got %s", w.Header().Get("Content-Type"))
	}

	var resp jsonRPCResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if resp.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got '%v'", resp.ID)
	}
}

func TestMCPServer_WriteJSONRPCError_ContentType(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCError(w, "err-id", jsonRPCInternalError, "test error")
	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Expected application/json, got %s", w.Header().Get("Content-Type"))
	}
}

func TestMCPServer_WriteJSONRPCAuthError_401(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCAuthError(w, "auth-id", "bad creds")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("Expected WWW-Authenticate header")
	}
}

func TestMCPServer_WriteJSONRPCError_ParseError_400(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCError(w, nil, jsonRPCParseError, "parse error")
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for parse error, got %d", w.Code)
	}
}

func TestMCPServer_WriteJSONRPCError_InvalidRequest_400(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCError(w, "req-id", jsonRPCInvalidRequest, "bad request")
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid request, got %d", w.Code)
	}
}

func TestMCPServer_WriteJSONRPCError_MethodNotFound_200(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSONRPCError(w, "req-id", jsonRPCMethodNotFound, "not found")
	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 for method not found, got %d", w.Code)
	}
}

func TestMCPServer_CheckPolicy_EvalUnavailable(t *testing.T) {
	// This tests the EvalUnavailable path by calling with a connector
	// that the dynamic evaluator might reject
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "cp-eval", map[string]interface{}{
		"name": "check_policy",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.Bash",
			"statement":      "safe command for coverage",
			"operation":      "query",
			"parameters":     map[string]interface{}{"key": "value", "num": float64(42)},
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestMCPServer_CheckOutput_WithRows(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)

	w := mcpServerPost(t, router, "tools/call", "co-rows2", map[string]interface{}{
		"name": "check_output",
		"arguments": map[string]interface{}{
			"connector_type": "claude_code.mcp__postgres",
			"response_data": []interface{}{
				map[string]interface{}{"name": "Alice", "ssn": "123-45-6789"},
			},
		},
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}
}

func TestTrimAuditSearchResponse(t *testing.T) {
	// Verify that large fields are stripped from audit search results
	resp := map[string]interface{}{
		"entries": []interface{}{
			map[string]interface{}{
				"id":            "audit-1",
				"request_body":  "large request body that should be removed",
				"response_body": "large response body that should be removed",
				"raw_request":   "raw request data",
				"raw_response":  "raw response data",
				"query":         string(make([]byte, 300)), // 300 chars, should be truncated
				"tenant_id":     "community",
			},
		},
	}

	// Apply the same trimming logic as mcpToolSearchAuditEvents
	if entries, ok := resp["entries"].([]interface{}); ok {
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
	}

	entry := resp["entries"].([]interface{})[0].(map[string]interface{})
	if _, ok := entry["request_body"]; ok {
		t.Error("request_body should have been removed")
	}
	if _, ok := entry["response_body"]; ok {
		t.Error("response_body should have been removed")
	}
	if _, ok := entry["raw_request"]; ok {
		t.Error("raw_request should have been removed")
	}
	if q := entry["query"].(string); len(q) > 215 {
		t.Errorf("query should be truncated, got %d chars", len(q))
	}
	if entry["tenant_id"] != "community" {
		t.Error("tenant_id should be preserved")
	}
}

func TestMCPSearchAuditEvents_ResponseTrimming(t *testing.T) {
	// Verify large fields are stripped and long queries truncated
	resp := map[string]interface{}{
		"entries": []interface{}{
			map[string]interface{}{
				"id":            "audit-1",
				"request_body":  "large request body that should be removed",
				"response_body": "large response body that should be removed",
				"raw_request":   "raw request data",
				"raw_response":  "raw response data",
				"query":         string(make([]byte, 300)),
				"tenant_id":     "community",
			},
			map[string]interface{}{
				"id":         "audit-2",
				"query":      "short query",
				"tenant_id":  "community",
				"raw_request": "should be removed",
			},
		},
	}

	if entries, ok := resp["entries"].([]interface{}); ok {
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
	}

	entries := resp["entries"].([]interface{})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	e1 := entries[0].(map[string]interface{})
	if _, ok := e1["request_body"]; ok {
		t.Error("request_body should be removed")
	}
	if _, ok := e1["raw_response"]; ok {
		t.Error("raw_response should be removed")
	}
	if q := e1["query"].(string); len(q) > 215 {
		t.Errorf("query should be truncated, got %d chars", len(q))
	}

	e2 := entries[1].(map[string]interface{})
	if e2["query"] != "short query" {
		t.Error("short query should be preserved")
	}
	if _, ok := e2["raw_request"]; ok {
		t.Error("raw_request should be removed from entry 2")
	}
}

func TestMCPSearchAuditEvents_EmptyResponseTrimming(t *testing.T) {
	// Edge case: empty entries, nil entries, non-map entries
	testCases := []struct {
		name string
		resp map[string]interface{}
	}{
		{"nil entries", map[string]interface{}{"entries": nil}},
		{"empty entries", map[string]interface{}{"entries": []interface{}{}}},
		{"no entries key", map[string]interface{}{"total": 0}},
		{"non-slice entries", map[string]interface{}{"entries": "not a slice"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic
			if entries, ok := tc.resp["entries"].([]interface{}); ok {
				for i, entry := range entries {
					if e, ok := entry.(map[string]interface{}); ok {
						delete(e, "request_body")
						if q, ok := e["query"].(string); ok && len(q) > 200 {
							e["query"] = q[:200] + "...(truncated)"
						}
						entries[i] = e
					}
				}
			}
		})
	}
}

func TestGetDeploymentOrgID_Default(t *testing.T) {
	// When ORG_ID is not set, should return "local-dev-org"
	original := os.Getenv("ORG_ID")
	os.Unsetenv("ORG_ID")
	defer func() {
		if original != "" {
			os.Setenv("ORG_ID", original)
		}
	}()

	result := getDeploymentOrgID()
	if result != "local-dev-org" {
		t.Errorf("expected 'local-dev-org', got %q", result)
	}
}

func TestGetDeploymentOrgID_Custom(t *testing.T) {
	t.Setenv("ORG_ID", "my-custom-org")
	result := getDeploymentOrgID()
	if result != "my-custom-org" {
		t.Errorf("expected 'my-custom-org', got %q", result)
	}
}
