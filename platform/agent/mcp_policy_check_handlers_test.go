// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	sharedpolicy "axonflow/platform/shared/policy"
)

// =============================================================================
// Route registration (Issue #1258)
// =============================================================================

func TestRegisterMCPHandlers_CheckEndpoints(t *testing.T) {
	router := mux.NewRouter()
	RegisterMCPHandlers(router)

	for _, tc := range []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/mcp/check-input"},
		{"POST", "/api/v1/mcp/check-output"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		match := &mux.RouteMatch{}
		if !router.Match(req, match) {
			t.Errorf("route not registered: %s %s", tc.method, tc.path)
		}
	}
}

// =============================================================================
// POST /api/v1/mcp/check-input
// =============================================================================

func TestMCPCheckInputHandler_CommunityMode_Allowed(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines → everything passes
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
	// Plugin Batch 1 / ADR-042 / ADR-043: every governance decision must
	// surface decision_id, allow paths included.
	if resp.DecisionID == "" {
		t.Error("allow path must emit decision_id (#1746 regression guard)")
	}
}

// TestMCPCheckInputHandler_AllowEmitsDecisionID is a focused regression
// guard for #1746: the allow path of /api/v1/mcp/check-input must emit
// decision_id in the response body. Plugin Batch 1 / ADR-042 / ADR-043
// require it on every governance decision so callers can correlate the
// decision back to the audit log via /explain/{id} without an extra
// round-trip. The deny path was always covered; this test pins the
// allow path so the regression cannot silently re-occur.
func TestMCPCheckInputHandler_AllowEmitsDecisionID(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT id, email FROM users LIMIT 10",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
	if resp.DecisionID == "" {
		t.Error("allow path must emit decision_id (Plugin Batch 1)")
	}
}

// TestMCPCheckOutputHandler_AllowEmitsDecisionID is the same regression
// guard for /api/v1/mcp/check-output: allow path must emit decision_id.
// The MCPCheckOutputResponse struct gained the field in this PR; this
// test pins the contract so it cannot regress.
func TestMCPCheckOutputHandler_AllowEmitsDecisionID(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "OK",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Allowed {
		t.Fatalf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
	if resp.DecisionID == "" {
		t.Error("allow path must emit decision_id (Plugin Batch 1)")
	}
}

func TestMCPCheckInputHandler_MissingConnectorType(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	body, _ := json.Marshal(MCPCheckInputRequest{
		Statement: "SELECT 1",
		TenantID:  "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMCPCheckInputHandler_MissingStatement(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMCPCheckInputHandler_DynamicPolicyBlocks(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	// Orchestrator denies the request
	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           false,
		BlockReason:       "Rate limit exceeded",
		PoliciesEvaluated: 1,
	})
	defer server.Close()

	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Allowed {
		t.Error("expected allowed=false")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty block_reason")
	}
}

func TestMCPCheckInputHandler_WithEngineNoPolicies_Allowed(t *testing.T) {
	// Verifies the handler doesn't crash and returns allowed=true when a policy engine
	// is configured but has no policies loaded (nil DB → empty cache).
	// Static policy blocking with live policies is exercised by shared/policy engine_test.go.
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	// Engine with nil DB has an empty policy cache → all requests pass
	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, sharedpolicy.DefaultEngineConfig(), nil)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	defer engine.Stop()

	t.Setenv("MCP_DETECTION_ENABLED", "true")

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

func TestMCPCheckInputHandler_DefaultOperation(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	// No operation field → should default to "query" without error
	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
		// Operation intentionally omitted
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// =============================================================================
// POST /api/v1/mcp/check-output
// =============================================================================

func TestMCPCheckOutputHandler_CommunityMode_Allowed(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  []map[string]interface{}{{"id": 1, "name": "Alice"}},
		RowCount:      1,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

func TestMCPCheckOutputHandler_MissingConnectorType(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ResponseData: []map[string]interface{}{{"id": 1}},
		TenantID:     "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMCPCheckOutputHandler_MissingResponseDataAndMessage(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		TenantID:      "default",
		// Both ResponseData and Message are empty
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMCPCheckOutputHandler_ExfiltrationExceeded(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  2,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	// 5 rows exceeds the limit of 2
	rows := []map[string]interface{}{
		{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}, {"id": 5},
	}
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  rows,
		RowCount:      5,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if resp.Allowed {
		t.Error("expected allowed=false")
	}
	if resp.BlockReason == "" {
		t.Error("expected non-empty block_reason")
	}
}

func TestMCPCheckOutputHandler_MessageAccepted(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Use message (execute-style) instead of response_data
	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "1 row affected",
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckOutputHandler_WithEngineNoPolicies_Allowed(t *testing.T) {
	// Verifies the handler doesn't crash and returns allowed=true when a policy engine
	// is configured but has no policies loaded (nil DB → empty cache).
	// Static policy blocking with live policies is exercised by shared/policy engine_test.go.
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, sharedpolicy.DefaultEngineConfig(), nil)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	defer engine.Stop()

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	t.Setenv("MCP_DETECTION_ENABLED", "true")

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  []map[string]interface{}{{"id": 1}},
		RowCount:      1,
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

func TestMCPCheckOutputHandler_InvalidBody(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMCPCheckInputHandler_InvalidBody(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// =============================================================================
// Enterprise-mode authentication (non-community)
// =============================================================================

func TestMCPCheckInputHandler_EnterpriseMode_NoClientID(t *testing.T) {
	// Enterprise mode requires valid client_id + user_token; missing client → 401
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "tenant-1",
		// No ClientID, no UserToken
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckOutputHandler_EnterpriseMode_NoClientID(t *testing.T) {
	// Enterprise mode requires valid client_id + user_token; missing client → 401
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  []map[string]interface{}{{"id": 1}},
		RowCount:      1,
		TenantID:      "tenant-1",
		// No ClientID, no UserToken
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckInputHandler_EnterpriseMode_InvalidToken(t *testing.T) {
	// Valid client_id (validateClient returns mock client) but invalid JWT token → 401
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckInputRequest{
		ClientID:      "test-client",
		UserToken:     "invalid-jwt-token",
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "test-client",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckOutputHandler_EnterpriseMode_InvalidToken(t *testing.T) {
	// Valid client_id but invalid JWT token → 401
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ClientID:      "test-client",
		UserToken:     "invalid-jwt-token",
		ConnectorType: "postgres",
		ResponseData:  []map[string]interface{}{{"id": 1}},
		RowCount:      1,
		TenantID:      "test-client",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckInputHandler_EnterpriseMode_MissingTenantID(t *testing.T) {
	// Enterprise mode requires auth — missing credentials returns 401 before tenant_id check
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		// TenantID intentionally omitted, no auth
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	// Without auth, enterprise mode returns 401 (auth checked before tenant_id)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth in enterprise mode, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMCPCheckOutputHandler_EnterpriseMode_MissingTenantID(t *testing.T) {
	// Enterprise mode requires auth — missing credentials returns 401 before tenant_id check
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		ResponseData:  []map[string]interface{}{{"id": 1}},
		RowCount:      1,
		// TenantID intentionally omitted, no auth
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	// Without auth, enterprise mode returns 401 (auth checked before tenant_id)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing auth in enterprise mode, got %d: %s", w.Code, w.Body.String())
	}
}

// =============================================================================
// check-input with explicit operation="execute"
// =============================================================================

func TestMCPCheckInputHandler_ExplicitExecuteOperation(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "INSERT INTO users VALUES (1, 'Alice')",
		TenantID:      "default",
		Operation:     "execute",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// =============================================================================
// check-output: message-only should NOT trigger exfiltration
// =============================================================================

func TestMCPCheckOutputHandler_MessageOnly_NoExfiltration(t *testing.T) {
	// With strict exfiltration limits, a message-only response should NOT be blocked
	// because exfiltration checking is disabled for execute-style outputs.
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	// Set very strict limit — would block any query-style response
	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  1,
		MaxBytesPerQuery: 10,
		Enabled:          true,
	})

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "5 rows affected",
		RowCount:      5, // Would exceed MaxRowsPerQuery if exfiltration was checked
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (exfiltration skipped for message-only), got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckOutputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

// =============================================================================
// check-output: metadata is passed through to SQLi scanning
// =============================================================================

func TestMCPCheckOutputHandler_WithMetadata(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	body, _ := json.Marshal(MCPCheckOutputRequest{
		ConnectorType: "postgres",
		Message:       "OK",
		Metadata:      map[string]interface{}{"source": "external"},
		TenantID:      "default",
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckOutputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// =============================================================================
// evaluateInputPolicies — direct helper tests
// =============================================================================

func TestEvaluateInputPolicies_NilEvaluator_NilEngine(t *testing.T) {
	// When both dynamic evaluator and static engine are nil, outcome is clean
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	ctx := context.Background()
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT 1", nil)

	if out.EvalUnavailable {
		t.Error("expected EvalUnavailable=false")
	}
	if out.DynamicBlocked {
		t.Error("expected DynamicBlocked=false")
	}
	if out.StaticResult != nil {
		t.Error("expected StaticResult=nil")
	}
}

func TestEvaluateInputPolicies_DynamicAllowed(t *testing.T) {
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:           true,
		PoliciesEvaluated: 3,
	})
	defer server.Close()

	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	ctx := context.Background()
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT 1", nil)

	if out.EvalUnavailable {
		t.Error("expected EvalUnavailable=false")
	}
	if out.DynamicBlocked {
		t.Error("expected DynamicBlocked=false")
	}
	if out.DynamicInfo == nil {
		t.Error("expected DynamicInfo to be populated")
	}
}

func TestEvaluateInputPolicies_DynamicBlocked(t *testing.T) {
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed:     false,
		BlockReason: "Budget exceeded",
	})
	defer server.Close()

	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"postgres"},
	})

	ctx := context.Background()
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT 1", nil)

	if !out.DynamicBlocked {
		t.Error("expected DynamicBlocked=true")
	}
	if out.DynamicBlockReason != "Budget exceeded" {
		t.Errorf("expected block reason 'Budget exceeded', got %q", out.DynamicBlockReason)
	}
}

func TestEvaluateInputPolicies_ConnectorNotEnabled(t *testing.T) {
	// Dynamic evaluator is configured but connector is not in the enabled list
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	server := mockOrchestratorServer(t, sharedpolicy.DynamicPolicyResponse{
		Allowed: false,
		BlockReason: "Should not reach",
	})
	defer server.Close()

	sharedpolicy.InitGlobalDynamicPolicyEvaluatorWithConfig(sharedpolicy.DynamicPolicyConfig{
		Enabled:              true,
		OrchestratorEndpoint: server.URL,
		Timeout:              5 * time.Second,
		GracefulDegradation:  false,
		EnabledConnectors:    []string{"mysql"}, // NOT postgres
	})

	ctx := context.Background()
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT 1", nil)

	if out.DynamicBlocked {
		t.Error("expected DynamicBlocked=false when connector not enabled")
	}
}

func TestEvaluateInputPolicies_WithStaticEngine(t *testing.T) {
	// Static engine with no loaded policies should return a result with PoliciesEvaluated=0
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, sharedpolicy.DefaultEngineConfig(), nil)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	defer engine.Stop()

	t.Setenv("MCP_DETECTION_ENABLED", "true")

	ctx := context.Background()
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT 1", nil)

	if out.StaticResult == nil {
		t.Fatal("expected StaticResult to be non-nil when engine is active")
	}
	if out.StaticResult.Blocked {
		t.Error("expected not blocked with empty policy cache")
	}
}

// =============================================================================
// evaluateOutputPolicies — direct helper tests
// =============================================================================

func TestEvaluateOutputPolicies_NilEngine_NilChecker(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	ctx := context.Background()
	rows := []map[string]interface{}{{"id": 1}}
	out := evaluateOutputPolicies(ctx, "t1", "u1", "postgres", rows, "", nil, 1, true)

	if out.SQLiBlocked {
		t.Error("expected SQLiBlocked=false")
	}
	if out.StaticResult != nil {
		t.Error("expected StaticResult=nil")
	}
	if out.ExfilResult != nil {
		t.Error("expected ExfilResult=nil")
	}
}

func TestEvaluateOutputPolicies_MessageOnly(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	ctx := context.Background()
	out := evaluateOutputPolicies(ctx, "t1", "u1", "postgres", nil, "3 rows affected", nil, 3, false)

	if out.SQLiBlocked {
		t.Error("expected SQLiBlocked=false")
	}
}

func TestEvaluateOutputPolicies_ExfiltrationExceeded(t *testing.T) {
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  1,
		MaxBytesPerQuery: 10 * 1024 * 1024,
		Enabled:          true,
	})

	ctx := context.Background()
	rows := []map[string]interface{}{{"id": 1}, {"id": 2}, {"id": 3}}
	out := evaluateOutputPolicies(ctx, "t1", "u1", "postgres", rows, "", nil, 3, true)

	if out.ExfilResult == nil {
		t.Fatal("expected ExfilResult to be non-nil")
	}
	if !out.ExfilResult.Exceeded {
		t.Error("expected exfiltration to be exceeded")
	}
	if out.ExfilInfo == nil {
		t.Error("expected ExfilInfo to be populated")
	}
}

func TestEvaluateOutputPolicies_ExfiltrationNotChecked(t *testing.T) {
	// When checkExfiltration=false, even with strict limits, exfiltration is skipped
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	sharedpolicy.InitGlobalExfiltrationCheckerWithLimits(sharedpolicy.ExfiltrationLimits{
		MaxRowsPerQuery:  1,
		MaxBytesPerQuery: 10,
		Enabled:          true,
	})

	ctx := context.Background()
	rows := []map[string]interface{}{{"id": 1}, {"id": 2}, {"id": 3}}
	out := evaluateOutputPolicies(ctx, "t1", "u1", "postgres", rows, "", nil, 3, false)

	if out.ExfilResult != nil {
		t.Error("expected ExfilResult=nil when checkExfiltration=false")
	}
}

func TestEvaluateOutputPolicies_WithStaticEngine(t *testing.T) {
	// Static engine with empty cache should evaluate but not block
	engine := sharedpolicy.NewUnifiedPolicyEngine(nil, sharedpolicy.DefaultEngineConfig(), nil)
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(originalEngine)
	defer engine.Stop()

	originalChecker := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.SetGlobalExfiltrationChecker(nil)
	defer sharedpolicy.SetGlobalExfiltrationChecker(originalChecker)

	t.Setenv("MCP_DETECTION_ENABLED", "true")

	ctx := context.Background()
	rows := []map[string]interface{}{{"name": "Alice"}}
	out := evaluateOutputPolicies(ctx, "t1", "u1", "postgres", rows, "", nil, 1, false)

	if out.StaticResult == nil {
		t.Fatal("expected StaticResult to be non-nil when engine is active")
	}
	if out.StaticResult.Blocked {
		t.Error("expected not blocked with empty policy cache")
	}
}

// =============================================================================
// Response type validation
// =============================================================================

func TestMCPCheckInputResponse_Fields(t *testing.T) {
	resp := MCPCheckInputResponse{
		Allowed:           true,
		PoliciesEvaluated: 5,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded["allowed"] != true {
		t.Error("expected allowed=true")
	}
	if int(decoded["policies_evaluated"].(float64)) != 5 {
		t.Error("expected policies_evaluated=5")
	}
	// block_reason should be omitted when empty
	if _, exists := decoded["block_reason"]; exists {
		t.Error("expected block_reason to be omitted when empty")
	}
}

func TestMCPCheckOutputResponse_Fields(t *testing.T) {
	resp := MCPCheckOutputResponse{
		Allowed:           true,
		PoliciesEvaluated: 3,
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if decoded["allowed"] != true {
		t.Error("expected allowed=true")
	}
	// redacted_data, block_reason should be omitted
	if _, exists := decoded["redacted_data"]; exists {
		t.Error("expected redacted_data to be omitted when nil")
	}
}

// Suppress unused import warning - context and fmt are used above
var _ = context.Background
var _ = fmt.Sprintf

// =============================================================================
// Parameter scanning handler tests
// =============================================================================

func TestMCPCheckInputHandler_WithParameters_Allowed(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines → everything passes
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT * FROM users WHERE id = $1",
		TenantID:      "default",
		Parameters:    map[string]interface{}{"1": "safe-value-123"},
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

func TestMCPCheckInputHandler_EmptyParameters(t *testing.T) {
	cleanup := setupCommunityModeForTest(t)
	defer cleanup()

	// No policy engines → everything passes
	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)

	body, _ := json.Marshal(MCPCheckInputRequest{
		ConnectorType: "postgres",
		Statement:     "SELECT 1",
		TenantID:      "default",
		Parameters:    map[string]interface{}{},
	})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	mcpCheckInputHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp MCPCheckInputResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed=true, got false (block_reason=%q)", resp.BlockReason)
	}
}

func TestEvaluateInputPolicies_WithParameters(t *testing.T) {
	// When both dynamic evaluator and static engine are nil, params don't cause issues
	originalEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(nil)
	defer sharedpolicy.SetGlobalDynamicPolicyEvaluator(originalEval)

	originalEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(nil)
	defer sharedpolicy.SetGlobalEngine(originalEngine)

	ctx := context.Background()
	params := map[string]interface{}{
		"1": "1 OR 1=1; DROP TABLE users--",
		"2": "normal-value",
	}
	out := evaluateInputPolicies(ctx, "t1", "u1", "admin", "postgres", "query", "SELECT * FROM users WHERE id = $1", params)

	if out.EvalUnavailable {
		t.Error("expected EvalUnavailable=false")
	}
	if out.DynamicBlocked {
		t.Error("expected DynamicBlocked=false")
	}
	if out.StaticResult != nil {
		t.Error("expected StaticResult=nil")
	}
}
