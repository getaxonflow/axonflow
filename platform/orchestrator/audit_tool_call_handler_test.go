// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/shared/serviceauth"
)

// setBasicAuth adds a valid Basic Authorization header and matching X-Tenant-ID.
func setBasicAuth(req *http.Request) {
	creds := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("X-Tenant-ID", "test-client")
}

func TestAuditToolCallHandler_AllFields(t *testing.T) {
	// Save and restore global auditLogger
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name":        "getUserInfo",
		"tool_type":        "mcp",
		"input":            map[string]interface{}{"user": "test"},
		"output":           map[string]interface{}{"name": "Test User"},
		"workflow_id":      "wf_abc123",
		"step_id":          "step-3",
		"user_id":          "user@example.com",
		"duration_ms":      45,
		"policies_applied": []string{"pii_check", "data_access"},
		"success":          true,
		"error_message":    "",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "recorded" {
		t.Errorf("Expected status 'recorded', got %v", resp["status"])
	}
	if resp["audit_id"] == nil || resp["audit_id"] == "" {
		t.Error("Expected non-empty audit_id")
	}
	if resp["timestamp"] == nil || resp["timestamp"] == "" {
		t.Error("Expected non-empty timestamp")
	}
	auditID, ok := resp["audit_id"].(string)
	if !ok || !strings.HasPrefix(auditID, "audit_") {
		t.Errorf("Expected audit_id to start with 'audit_', got %v", resp["audit_id"])
	}
}

func TestAuditToolCallHandler_RequiredFieldsOnly(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "simpleCheck",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "recorded" {
		t.Errorf("Expected status 'recorded', got %v", resp["status"])
	}
}

func TestAuditToolCallHandler_MissingToolName(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_type": "mcp",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuditToolCallHandler_EmptyToolName(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuditToolCallHandler_WhitespaceToolName(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "   ",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuditToolCallHandler_InvalidJSON(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

func TestAuditToolCallHandler_FailedToolCall(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name":     "failingTool",
		"success":       false,
		"error_message": "connection refused",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["status"] != "recorded" {
		t.Errorf("Expected status 'recorded', got %v", resp["status"])
	}
}

func TestAuditToolCallHandler_MissingAuth(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// No Authorization header

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp["error"] != "Missing authentication" {
		t.Errorf("Expected error 'Missing authentication', got %v", resp["error"])
	}
}

func TestAuditToolCallHandler_MissingTenantID(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// Set auth but no X-Tenant-ID
	creds := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	req.Header.Set("Authorization", "Basic "+creds)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_TenantMismatch(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// Auth with client "test-client" but tenant "other-tenant"
	creds := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("X-Tenant-ID", "other-tenant")

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_ProxyAuthRequired(t *testing.T) {
	// When proxyTokenValidator is set, requests without X-Axonflow-Proxy-Auth are rejected
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	origValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator("test-secret-32-chars-minimum-ok!", nil, serviceauth.DefaultClockSkew)
	defer func() {
		auditLogger = origLogger
		proxyTokenValidator = origValidator
	}()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	// No X-Axonflow-Proxy-Auth header — simulates direct access

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for missing proxy auth, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_ProxyAuthValid(t *testing.T) {
	// When proxyTokenValidator is set, requests with valid HMAC token pass
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	secret := "test-secret-32-chars-minimum-ok!"
	origValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(secret, nil, serviceauth.DefaultClockSkew)
	defer func() {
		auditLogger = origLogger
		proxyTokenValidator = origValidator
	}()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	// Add valid HMAC proxy token
	gen := serviceauth.NewTokenGenerator(secret, nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", gen.GenerateToken())

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 with valid proxy auth, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_ProxyAuthTenantDiffers(t *testing.T) {
	// When proxy auth is verified, clientID != tenantID is allowed because
	// the Agent set X-Tenant-ID from the authenticated client's tenant config
	// (e.g., clientID="healthcare-demo", tenantID="healthcare_tenant").
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	secret := "test-secret-32-chars-minimum-ok!"
	origValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(secret, nil, serviceauth.DefaultClockSkew)
	defer func() {
		auditLogger = origLogger
		proxyTokenValidator = origValidator
	}()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	// clientID="test-client" but tenantID="different-tenant"
	creds := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	req.Header.Set("Authorization", "Basic "+creds)
	req.Header.Set("X-Tenant-ID", "different-tenant")
	// Valid proxy token proves Agent already authenticated the caller
	gen := serviceauth.NewTokenGenerator(secret, nil)
	req.Header.Set("X-Axonflow-Proxy-Auth", gen.GenerateToken())

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 with proxy-verified different tenant, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_NoProxyAuthNeededWithoutSecret(t *testing.T) {
	// When proxyTokenValidator is nil (no AXONFLOW_INTERNAL_SERVICE_SECRET), proxy auth is skipped.
	// This is the community/dev mode where orchestrator is accessed directly.
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	origValidator := proxyTokenValidator
	proxyTokenValidator = nil // Explicitly nil — community mode
	defer func() {
		auditLogger = origLogger
		proxyTokenValidator = origValidator
	}()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	// No X-Axonflow-Proxy-Auth — should still work in community mode

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 in community mode without proxy auth, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestAuditToolCallHandler_ProxyAuthFallbackRejected(t *testing.T) {
	// When proxyTokenValidator is set, the static fallback token must be rejected
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	origValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator("test-secret-32-chars-minimum-ok!", nil, serviceauth.DefaultClockSkew)
	defer func() {
		auditLogger = origLogger
		proxyTokenValidator = origValidator
	}()

	body := map[string]interface{}{
		"tool_name": "getUserInfo",
	}

	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	// Set the known fallback token — this should be rejected when secret is configured
	req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.TokenFallback)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for fallback token with validator active, got %d. Body: %s", rr.Code, rr.Body.String())
	}
}

func TestLogToolCallAudit(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	successVal := true
	entry := &ToolCallAuditEntry{
		ToolName:        "getUserInfo",
		ToolType:        "mcp",
		Input:           map[string]interface{}{"user": "test"},
		Output:          map[string]interface{}{"name": "Test User"},
		WorkflowID:      "wf_abc123",
		StepID:          "step-3",
		UserID:          "user@example.com",
		DurationMs:      45,
		PoliciesApplied: []string{"pii_check"},
		Success:         &successVal,
		TenantID:        "tenant-1",
		ClientID:        "client-1",
	}

	result := logger.LogToolCallAudit(context.Background(), entry)

	if result == nil {
		t.Fatal("Expected non-nil audit entry")
	}
	if result.RequestType != "tool_call_audit" {
		t.Errorf("Expected RequestType 'tool_call_audit', got %s", result.RequestType)
	}
	if result.TenantID != "tenant-1" {
		t.Errorf("Expected TenantID 'tenant-1', got %s", result.TenantID)
	}
	if result.ClientID != "client-1" {
		t.Errorf("Expected ClientID 'client-1', got %s", result.ClientID)
	}
	if result.PolicyDecision != "allowed" {
		t.Errorf("Expected PolicyDecision 'allowed', got %s", result.PolicyDecision)
	}
	if result.UserEmail != "user@example.com" {
		t.Errorf("Expected UserEmail 'user@example.com', got %s", result.UserEmail)
	}
	if result.Query != "Tool: getUserInfo" {
		t.Errorf("Expected Query 'Tool: getUserInfo', got %s", result.Query)
	}

	// Verify policy details
	if result.PolicyDetails["tool_name"] != "getUserInfo" {
		t.Errorf("Expected tool_name in policy details, got %v", result.PolicyDetails["tool_name"])
	}
	if result.PolicyDetails["tool_type"] != "mcp" {
		t.Errorf("Expected tool_type in policy details, got %v", result.PolicyDetails["tool_type"])
	}
	if result.PolicyDetails["duration_ms"] != int64(45) {
		t.Errorf("Expected duration_ms 45 in policy details, got %v", result.PolicyDetails["duration_ms"])
	}
}

func TestLogToolCallAudit_FailedCall(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	failVal := false
	entry := &ToolCallAuditEntry{
		ToolName:     "failingTool",
		Success:      &failVal,
		ErrorMessage: "timeout",
	}

	result := logger.LogToolCallAudit(context.Background(), entry)

	if result == nil {
		t.Fatal("Expected non-nil audit entry")
	}
	if result.PolicyDecision != "error" {
		t.Errorf("Expected PolicyDecision 'error' for failed call, got %s", result.PolicyDecision)
	}
	if result.ErrorMessage != "timeout" {
		t.Errorf("Expected ErrorMessage 'timeout', got %s", result.ErrorMessage)
	}
}

func TestLogToolCallAudit_NilLogger(t *testing.T) {
	var logger *AuditLogger
	entry := &ToolCallAuditEntry{
		ToolName: "test",
	}
	result := logger.LogToolCallAudit(context.Background(), entry)
	if result != nil {
		t.Error("Expected nil result from nil logger")
	}
}
