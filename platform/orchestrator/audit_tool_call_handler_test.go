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

// TestAuditToolCallHandler_UserEmailFromHeader is the #2754 core regression:
// the post-tool audit_tool_call row must carry the real developer email that
// the Agent proxy forwards as X-User-Email, landing in audit_logs.user_email.
// Before the fix, auditToolCallHandler never read the header and user_email was
// written from the (empty) UserID → the portal User column showed NULL/N/A.
func TestAuditToolCallHandler_UserEmailFromHeader(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{
		"tool_name": "Bash",
		"tool_type": "claude_code",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	req.Header.Set("X-User-Email", "alice@example.com")
	req.Header.Set("X-Session-Id", "sess-xyz-789") // #2753 sibling identity

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}

	// Drain the enqueued audit entry and assert BOTH the developer email and the
	// session id landed in the DB-backed columns (the DoD paste-evidence shape).
	select {
	case entry := <-auditLogger.auditQueue:
		if entry.UserEmail != "alice@example.com" {
			t.Errorf("Expected user_email 'alice@example.com', got %q", entry.UserEmail)
		}
		if entry.SessionID != "sess-xyz-789" {
			t.Errorf("Expected session_id 'sess-xyz-789', got %q", entry.SessionID)
		}
	default:
		t.Fatal("Expected an audit entry to be enqueued")
	}
}

// TestAuditToolCallHandler_NoUserEmailHeader proves graceful degradation: with
// no X-User-Email header (no identity configured) the row is still written with
// an empty user_email — never a spoofed or copy-paste value.
func TestAuditToolCallHandler_NoUserEmailHeader(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	body := map[string]interface{}{"tool_name": "Bash", "tool_type": "claude_code"}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)
	// deliberately no X-User-Email header

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	select {
	case entry := <-auditLogger.auditQueue:
		if entry.UserEmail != "" {
			t.Errorf("Expected empty user_email with no header, got %q", entry.UserEmail)
		}
	default:
		t.Fatal("Expected an audit entry to be enqueued")
	}
}

// TestAuditToolCallHandler_UserEmailNotSpoofableViaBody proves the identity is
// header-sourced only: a user_email placed in the JSON request body is ignored
// (UserEmail has json:"-"), so a caller cannot forge the attributed developer.
func TestAuditToolCallHandler_UserEmailNotSpoofableViaBody(t *testing.T) {
	origLogger := auditLogger
	auditLogger = &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}
	defer func() { auditLogger = origLogger }()

	// Attacker puts a forged user_email in the body but sends no header.
	body := map[string]interface{}{
		"tool_name":  "Bash",
		"tool_type":  "claude_code",
		"user_email": "attacker@evil.com",
	}
	bodyBytes, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	setBasicAuth(req)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("Expected status 201, got %d. Body: %s", rr.Code, rr.Body.String())
	}
	select {
	case entry := <-auditLogger.auditQueue:
		if entry.UserEmail == "attacker@evil.com" {
			t.Errorf("user_email must not be settable from the request body (#2754 spoofing guard)")
		}
		if entry.UserEmail != "" {
			t.Errorf("Expected empty user_email (body value ignored), got %q", entry.UserEmail)
		}
	default:
		t.Fatal("Expected an audit entry to be enqueued")
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

func TestAuditToolCallHandler_TenantDerivedFromBasicAuth(t *testing.T) {
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
	// Basic auth but no X-Tenant-ID — tenant should be derived from clientID
	creds := base64.StdEncoding.EncodeToString([]byte("test-client:test-secret"))
	req.Header.Set("Authorization", "Basic "+creds)

	rr := httptest.NewRecorder()
	auditToolCallHandler(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("Expected status 201 (tenant derived from Basic auth), got %d. Body: %s", rr.Code, rr.Body.String())
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
	t.Setenv("DEPLOYMENT_MODE", "community")
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

func TestAuditToolCallHandler_FailsClosedWhenSecretMissingInEnterpriseMode(t *testing.T) {
	// When proxyTokenValidator is nil AND we are NOT in Community mode, every
	// request must be rejected. Otherwise an Enterprise/SaaS rollout that forgot
	// to set AXONFLOW_INTERNAL_SERVICE_SECRET would silently accept any caller
	// who can reach the orchestrator directly, letting them spoof X-Org-ID for
	// audit attribution against another tenant.
	for _, mode := range []string{"enterprise", "community-saas", "in-vpc-enterprise"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			origLogger := auditLogger
			auditLogger = &AuditLogger{
				auditQueue:   make(chan *AuditEntry, 100),
				shutdownChan: make(chan struct{}),
			}
			origValidator := proxyTokenValidator
			proxyTokenValidator = nil // simulate missing secret
			defer func() {
				auditLogger = origLogger
				proxyTokenValidator = origValidator
			}()

			body, _ := json.Marshal(map[string]interface{}{"tool_name": "getUserInfo"})
			req := httptest.NewRequest("POST", "/api/v1/audit/tool-call", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			setBasicAuth(req)

			rr := httptest.NewRecorder()
			auditToolCallHandler(rr, req)

			if rr.Code != http.StatusForbidden {
				t.Errorf("expected 403 when proxyTokenValidator is nil in %s mode, got %d. Body: %s",
					mode, rr.Code, rr.Body.String())
			}
		})
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
		ToolName:   "getUserInfo",
		ToolType:   "mcp",
		Input:      map[string]interface{}{"user": "test"},
		Output:     map[string]interface{}{"name": "Test User"},
		WorkflowID: "wf_abc123",
		StepID:     "step-3",
		// #2754: UserID and UserEmail are distinct on purpose. user_email must
		// come from UserEmail (the X-User-Email header), NOT from UserID — the
		// pre-fix copy-paste bug wrote entry.UserID (empty in practice) into
		// user_email, producing the NULL/N/A portal column.
		UserID:          "synthetic-user-id",
		UserEmail:       "alice@example.com",
		SessionID:       "sess-xyz-789",
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
	if result.UserEmail != "alice@example.com" {
		t.Errorf("Expected UserEmail 'alice@example.com', got %s", result.UserEmail)
	}
	// Regression guard for the #2754 copy-paste bug: UserID must never leak
	// into user_email. If this ever equals the UserID again, the bug is back.
	if result.UserEmail == entry.UserID {
		t.Errorf("UserEmail must not be derived from UserID (#2754 regression): got %s", result.UserEmail)
	}
	if result.SessionID != "sess-xyz-789" {
		t.Errorf("Expected SessionID 'sess-xyz-789', got %s", result.SessionID)
	}
	if result.Query != "Tool: getUserInfo" {
		t.Errorf("Expected Query 'Tool: getUserInfo', got %s", result.Query)
	}

	// Verify policy details
	if result.PolicyDetails["tool_name"] != "getUserInfo" {
		t.Errorf("Expected tool_name in policy details, got %v", result.PolicyDetails["tool_name"])
	}
	// #2912: no CallerName supplied, so the legacy ToolType ("mcp") is the
	// fallback source for caller_name. policy_details.tool_type is no longer
	// written at all — only policy_details.caller_name.
	if result.PolicyDetails["caller_name"] != "mcp" {
		t.Errorf("Expected caller_name (falling back to legacy ToolType) in policy details, got %v", result.PolicyDetails["caller_name"])
	}
	if _, present := result.PolicyDetails["tool_type"]; present {
		t.Errorf("policy_details.tool_type must not be written for new rows (#2912), got %v", result.PolicyDetails["tool_type"])
	}
	if result.PolicyDetails["duration_ms"] != int64(45) {
		t.Errorf("Expected duration_ms 45 in policy details, got %v", result.PolicyDetails["duration_ms"])
	}
}

// TestLogToolCallAudit_CallerNamePreferredOverToolType (#2912): when a caller
// sends BOTH the new CallerName and the legacy ToolType, CallerName wins.
func TestLogToolCallAudit_CallerNamePreferredOverToolType(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	successVal := true
	entry := &ToolCallAuditEntry{
		ToolName:   "getUserInfo",
		CallerName: "claude_code",
		ToolType:   "mcp", // legacy value; must be ignored when CallerName is set
		Success:    &successVal,
	}

	result := logger.LogToolCallAudit(context.Background(), entry)

	if result == nil {
		t.Fatal("Expected non-nil audit entry")
	}
	if result.PolicyDetails["caller_name"] != "claude_code" {
		t.Errorf("Expected caller_name 'claude_code' (preferred over legacy tool_type), got %v", result.PolicyDetails["caller_name"])
	}
	if _, present := result.PolicyDetails["tool_type"]; present {
		t.Errorf("policy_details.tool_type must not be written for new rows (#2912), got %v", result.PolicyDetails["tool_type"])
	}
}

// TestLogToolCallAudit_DefaultCallerNameWhenNeitherSupplied (#2912/#2903): when
// neither CallerName nor ToolType is supplied the fallback default is "unknown"
// — an unidentified caller must NOT be silently attributed to the specific
// client "claude_code" (#2903).
func TestLogToolCallAudit_DefaultCallerNameWhenNeitherSupplied(t *testing.T) {
	logger := &AuditLogger{
		auditQueue:   make(chan *AuditEntry, 100),
		shutdownChan: make(chan struct{}),
	}

	successVal := true
	entry := &ToolCallAuditEntry{
		ToolName: "getUserInfo",
		Success:  &successVal,
	}

	result := logger.LogToolCallAudit(context.Background(), entry)

	if result == nil {
		t.Fatal("Expected non-nil audit entry")
	}
	if result.PolicyDetails["caller_name"] != "unknown" {
		t.Errorf("Expected default caller_name 'unknown' (#2903), got %v", result.PolicyDetails["caller_name"])
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
