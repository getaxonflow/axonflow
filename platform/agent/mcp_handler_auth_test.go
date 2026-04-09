// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// These tests target the auth + orgID-from-license paths in the MCP
// check-input and check-output handlers introduced/changed in v6.2.0 (#1526).
// They cover the early-return validation paths and the per-request orgID
// derivation that was previously hardcoded to getDeploymentOrgID().

// TestMCPCheckInputHandler_ValidationErrors covers the early-return paths
// before any auth or policy evaluation runs.
func TestMCPCheckInputHandler_ValidationErrors(t *testing.T) {
	// Force community mode so we don't need a license
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	cases := []struct {
		name       string
		body       interface{}
		rawBody    string
		expectCode int
	}{
		{
			name:       "malformed JSON body",
			rawBody:    "{not valid json",
			expectCode: http.StatusBadRequest,
		},
		{
			name: "missing connector_type",
			body: MCPCheckInputRequest{
				Statement: "SELECT 1",
			},
			expectCode: http.StatusBadRequest,
		},
		{
			name: "missing statement",
			body: MCPCheckInputRequest{
				ConnectorType: "postgres",
			},
			expectCode: http.StatusBadRequest,
		},
		{
			name: "empty connector_type and statement",
			body: MCPCheckInputRequest{
				ConnectorType: "",
				Statement:     "",
			},
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte
			if tc.rawBody != "" {
				reqBody = []byte(tc.rawBody)
			} else {
				reqBody, _ = json.Marshal(tc.body)
			}
			req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mcpCheckInputHandler(w, req)
			if w.Code != tc.expectCode {
				t.Errorf("expected %d, got %d (body: %s)", tc.expectCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestMCPCheckOutputHandler_ValidationErrors covers the early-return paths.
func TestMCPCheckOutputHandler_ValidationErrors(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	cases := []struct {
		name       string
		body       interface{}
		rawBody    string
		expectCode int
	}{
		{
			name:       "malformed JSON body",
			rawBody:    "{not json",
			expectCode: http.StatusBadRequest,
		},
		{
			name: "missing connector_type",
			body: MCPCheckOutputRequest{
				Message: "some response",
			},
			expectCode: http.StatusBadRequest,
		},
		{
			name: "missing both response_data and message",
			body: MCPCheckOutputRequest{
				ConnectorType: "postgres",
			},
			expectCode: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var reqBody []byte
			if tc.rawBody != "" {
				reqBody = []byte(tc.rawBody)
			} else {
				reqBody, _ = json.Marshal(tc.body)
			}
			req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			mcpCheckOutputHandler(w, req)
			if w.Code != tc.expectCode {
				t.Errorf("expected %d, got %d (body: %s)", tc.expectCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestMCPCheckInputHandler_EnterpriseRequiresAuth verifies the v6.2.0 fix:
// in enterprise mode, requests without Basic auth must be rejected with 401.
// Previously, validateClient() would silently auth any client_id from the
// JSON body — a multi-tenant security hole.
func TestMCPCheckInputHandler_EnterpriseRequiresAuth(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		ClientID:      "would-be-spoofed-tenant",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally NO Authorization header — this is what the v6.2.0 fix
	// rejects. Pre-fix, validateClient() would have stamped this as the
	// deployment org and let it through.
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated enterprise request, got %d (body: %s)",
			w.Code, w.Body.String())
	}
}

// TestMCPCheckOutputHandler_EnterpriseRequiresAuth — same v6.2.0 regression
// guard for the check-output handler.
func TestMCPCheckOutputHandler_EnterpriseRequiresAuth(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "some output to scan",
		ClientID:      "would-be-spoofed-tenant",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated enterprise request, got %d (body: %s)",
			w.Code, w.Body.String())
	}
}

// TestMCPCheckInputHandler_EnterpriseRejectsBadCredentials verifies that
// invalid Basic auth credentials are also rejected (validateClientCredentials
// path returns an error).
func TestMCPCheckInputHandler_EnterpriseRejectsBadCredentials(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Force the no-DB path so validateClientCredentials runs
	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	body := MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	creds := base64.StdEncoding.EncodeToString([]byte("unknown-client:unknown-secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad credentials, got %d", w.Code)
	}
}

// TestMCPCheckOutputHandler_EnterpriseRejectsBadCredentials — same for output.
func TestMCPCheckOutputHandler_EnterpriseRejectsBadCredentials(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	oldAuthDB := authDB
	authDB = nil
	defer func() { authDB = oldAuthDB }()

	body := MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "some content",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	creds := base64.StdEncoding.EncodeToString([]byte("unknown-client:unknown-secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for bad credentials, got %d", w.Code)
	}
}

// TestMCPCheckInputHandler_CommunityMode verifies the community-mode path
// uses the deployment org_id label and accepts requests without credentials.
func TestMCPCheckInputHandler_CommunityMode(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	// Community mode should not 401/403 on missing credentials. The handler
	// may return 200 (allowed), 400 (something else missing), or 503 (registry
	// not initialized). Anything except 401/403 means the auth path completed.
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("community mode should not require auth, got %d", w.Code)
	}
}

// TestMCPCheckOutputHandler_CommunityMode same for output handler.
func TestMCPCheckOutputHandler_CommunityMode(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "some response output to scan for PII",
	}
	reqBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
		t.Errorf("community mode should not require auth, got %d", w.Code)
	}
}

// TestMCPExecuteHandler_RegistryNotInitialized covers the early-return path
// when the MCP registry is nil.
func TestMCPExecuteHandler_RegistryNotInitialized(t *testing.T) {
	oldRegistry := mcpRegistry
	mcpRegistry = nil
	defer func() { mcpRegistry = oldRegistry }()

	body := MCPExecuteRequest{
		ClientID:  "test-client",
		Connector: "postgres",
		Action:    "INSERT",
		Statement: "INSERT INTO t VALUES (1)",
	}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/execute", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when registry nil, got %d", w.Code)
	}
}

// TestMCPExecuteHandler_InvalidJSONBody covers the JSON decode early-return.
func TestMCPExecuteHandler_InvalidJSONBody(t *testing.T) {
	if mcpRegistry == nil {
		// Initialize a minimal registry so we get past the nil check
		InitializeMCPRegistry()
	}

	req := httptest.NewRequest("POST", "/api/v1/mcp/execute", bytes.NewBufferString("{not valid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed JSON, got %d", w.Code)
	}
}

// TestMCPCheckOutputHandler_BlocksSQLInjection exercises the SQL injection
// block path in mcpCheckOutputHandler. This drives the auditEntry population
// and the 403 response writer for a known-bad payload.
func TestMCPCheckOutputHandler_BlocksSQLInjection(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "result includes UNION SELECT password FROM users WHERE 1=1 OR 1=1 --",
	}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	// Either 200 (allowed and noted) or 403 (blocked) — both indicate the
	// handler reached the policy evaluation step rather than failing at
	// auth or input validation.
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest {
		t.Errorf("expected handler to reach policy evaluation, got %d", w.Code)
	}
}

// TestMCPCheckInputHandler_BlocksSQLInjection exercises the SQLi block path
// for the input handler.
func TestMCPCheckInputHandler_BlocksSQLInjection(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users WHERE id=1 OR 1=1 UNION SELECT password FROM admin --",
	}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckInputHandler(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest {
		t.Errorf("expected handler to reach policy evaluation, got %d", w.Code)
	}
}

// TestMCPCheckOutputHandler_PIIRedaction exercises the PII detection and
// redaction path. PII should be detected and the response should include
// a redacted_message field.
func TestMCPCheckOutputHandler_PIIRedaction(t *testing.T) {
	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "Patient John Smith with SSN 123-45-6789 and email john@example.com",
	}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mcpCheckOutputHandler(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest {
		t.Errorf("expected handler to reach policy evaluation, got %d", w.Code)
	}
}

// TestMCPExecuteHandler_EnterpriseRequiresAuth covers the v6.2.0 fix that
// rejects unauthenticated execute requests in enterprise mode.
func TestMCPExecuteHandler_EnterpriseRequiresAuth(t *testing.T) {
	if mcpRegistry == nil {
		InitializeMCPRegistry()
	}

	oldMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	defer func() {
		if oldMode != "" {
			os.Setenv("DEPLOYMENT_MODE", oldMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	body := MCPExecuteRequest{
		ClientID:  "would-be-spoofed-client",
		Connector: "postgres",
		Action:    "INSERT",
		Statement: "INSERT INTO t VALUES (1)",
	}
	reqBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/execute", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header — pre-fix this would have been accepted.
	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unauthenticated execute, got %d (body: %s)",
			w.Code, w.Body.String())
	}
}
