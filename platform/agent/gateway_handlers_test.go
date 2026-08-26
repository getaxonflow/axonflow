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

package agent

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
	"axonflow/platform/orchestrator/cost"
	sharedpolicy "axonflow/platform/shared/policy"
)

// TestPreCheckHandler_CommunityMode tests pre-check in community mode
func TestPreCheckHandler_CommunityMode(t *testing.T) {
	// Enable community mode with required safeguards
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine for testing
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Create request
	reqBody := PreCheckRequest{
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:    "test-client",
		Query:       "What is the weather today?",
		DataSources: []string{},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	// Record response
	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	// Check status code
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		return
	}

	// Parse response
	var resp PreCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response: %v", err)
		return
	}

	// Verify response
	if resp.ContextID == "" {
		t.Error("Expected non-empty context ID")
	}
	if !resp.Approved {
		t.Errorf("Expected request to be approved, got blocked: %s", resp.BlockReason)
	}
	if resp.ExpiresAt.Before(time.Now()) {
		t.Error("Expected expires_at to be in the future")
	}
}

// TestPreCheckHandler_CircuitBreakerAllowed tests pre-check passes through CB check
func TestPreCheckHandler_CircuitBreakerAllowed(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Set up circuit breaker (community stub — always allows)
	oldCB := circuitBreakerInstance
	circuitBreakerInstance = circuitbreaker.New(circuitbreaker.NewRepository(nil), circuitbreaker.Config{})
	defer func() { circuitBreakerInstance = oldCB }()

	reqBody := PreCheckRequest{
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:    "test-client",
		Query:       "What is the weather today?",
		DataSources: []string{},
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		return
	}

	var resp PreCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	if !resp.Approved {
		t.Errorf("Expected approved with CB allowing, got blocked: %s", resp.BlockReason)
	}
}

// TestPreCheckHandler_PolicyBlock tests pre-check blocking by policy
func TestPreCheckHandler_PolicyBlock(t *testing.T) {
	// TODO(#1488): SQL injection detection now requires DB-seeded policies (migration 031).
	// The legacy engine had hardcoded SQLI patterns; the shared engine loads them from DB.
	// This test needs a mock DB with seeded SQLI policies. Tracked in #1488.
	t.Skip("Requires DB-seeded SQLI policies — tracked in #1488")
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize shared engine with mock DB for SQL injection detection
	mockDB, mockSQL, _ := sqlmock.New()
	defer mockDB.Close()
	mockSQL.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "name", "pattern", "category", "severity", "action", "enabled", "tier", "tenant_id", "description", "metadata"}))
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{}, nil)
	oldEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(oldEngine)

	// Set up circuit breaker so RecordPolicyViolation is called on policy block (#1176)
	oldCB := circuitBreakerInstance
	circuitBreakerInstance = circuitbreaker.New(circuitbreaker.NewRepository(nil), circuitbreaker.Config{})
	defer func() { circuitBreakerInstance = oldCB }()

	// Create request with SQL injection attempt
	reqBody := PreCheckRequest{
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:    "test-client",
		Query:       "SELECT * FROM users UNION SELECT * FROM passwords",
		DataSources: []string{},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response: %v", err)
		return
	}

	// Should be blocked by SQL injection policy
	if resp.Approved {
		t.Error("Expected request to be blocked due to SQL injection")
	}
	if resp.BlockReason == "" {
		t.Error("Expected block reason to be set")
	}
}

// TestPreCheckHandler_InvalidBody tests pre-check with invalid request body
func TestPreCheckHandler_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestPreCheckHandler_MissingLicenseKey tests pre-check without license key in enterprise mode
func TestPreCheckHandler_MissingLicenseKey(t *testing.T) {
	// Set enterprise mode to require authentication
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	reqBody := PreCheckRequest{
		UserToken: "test-token",
		ClientID:  "test-client",
		Query:     "Test query",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Note: No X-License-Key header

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

// TestAuditLLMCallHandler_SelfHostedMode tests audit in community mode
func TestAuditLLMCallHandler_SelfHostedMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID:       "test-context-123",
		ClientID:        "test-client",
		ResponseSummary: "The weather is sunny.",
		Provider:        "openai",
		Model:           "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		LatencyMs: 500,
		Metadata: map[string]interface{}{
			"session_id": "session-123",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	// Without database, audit should still succeed (just not persisted)
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		return
	}

	var resp AuditLLMCallResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse response: %v", err)
		return
	}

	if !resp.Success {
		t.Error("Expected success to be true")
	}
	if resp.AuditID == "" {
		t.Error("Expected non-empty audit ID")
	}
}

// TestAuditLLMCallHandler_InvalidBody tests audit with invalid request body
func TestAuditLLMCallHandler_InvalidBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestAuditLLMCallHandler_MissingLicenseKey tests audit without license key in enterprise mode
func TestAuditLLMCallHandler_MissingLicenseKey(t *testing.T) {
	// Set enterprise mode to require authentication
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	reqBody := AuditLLMCallRequest{
		ContextID: "test-context",
		ClientID:  "test-client",
		Provider:  "openai",
		Model:     "gpt-4",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := apiAuthMiddleware(http.HandlerFunc(handleAuditLLMCall))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", rr.Code)
	}
}

// TestCalculateLLMCost tests cost calculation for different providers
func TestCalculateLLMCost(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		tokens   int
		minCost  float64
		maxCost  float64
	}{
		{
			name:     "OpenAI GPT-4",
			provider: "openai",
			model:    "gpt-4",
			tokens:   1000,
			minCost:  0.02,
			maxCost:  0.04,
		},
		{
			name:     "OpenAI GPT-4o-mini",
			provider: "openai",
			model:    "gpt-4o-mini",
			tokens:   1000,
			minCost:  0.0001,
			maxCost:  0.0002,
		},
		{
			name:     "Anthropic Claude Sonnet",
			provider: "anthropic",
			model:    "claude-sonnet-4",
			tokens:   1000,
			minCost:  0.002,
			maxCost:  0.005,
		},
		{
			name:     "Ollama (free)",
			provider: "ollama",
			model:    "default",
			tokens:   1000,
			minCost:  0.0,
			maxCost:  0.0,
		},
		{
			name:     "Unknown provider",
			provider: "unknown",
			model:    "unknown",
			tokens:   1000,
			minCost:  0.005, // Conservative estimate
			maxCost:  0.015,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			usage := TokenUsage{TotalTokens: tt.tokens}
			cost := calculateLLMCost(tt.provider, tt.model, usage)

			if cost < tt.minCost {
				t.Errorf("Cost %f is less than expected minimum %f", cost, tt.minCost)
			}
			if cost > tt.maxCost {
				t.Errorf("Cost %f is greater than expected maximum %f", cost, tt.maxCost)
			}
		})
	}
}

// TestHashString tests the hash function
func TestHashString(t *testing.T) {
	tests := []struct {
		input    string
		expected int // Expected hash length
	}{
		{"test", 64},
		{"", 64},
		{"a very long string with special characters !@#$%^&*()", 64},
	}

	for _, tt := range tests {
		hash := hashString(tt.input)
		if len(hash) != tt.expected {
			t.Errorf("Expected hash length %d, got %d", tt.expected, len(hash))
		}
	}

	// Same input should produce same hash
	hash1 := hashString("consistent")
	hash2 := hashString("consistent")
	if hash1 != hash2 {
		t.Error("Same input should produce same hash")
	}

	// Different input should produce different hash
	hash3 := hashString("different")
	if hash1 == hash3 {
		t.Error("Different input should produce different hash")
	}
}

// Note: pqArray and joinStrings functions were removed in favor of pq.Array
// from the github.com/lib/pq package for proper SQL escaping

// TestRateLimitInfo tests RateLimitInfo struct
func TestRateLimitInfo(t *testing.T) {
	info := RateLimitInfo{
		Limit:     100,
		Remaining: 50,
		ResetAt:   time.Now().Add(time.Hour),
	}

	if info.Limit != 100 {
		t.Errorf("Expected limit 100, got %d", info.Limit)
	}
	if info.Remaining != 50 {
		t.Errorf("Expected remaining 50, got %d", info.Remaining)
	}
}

// TestTokenUsage tests TokenUsage struct
func TestTokenUsage(t *testing.T) {
	usage := TokenUsage{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	if usage.PromptTokens != 100 {
		t.Errorf("Expected prompt tokens 100, got %d", usage.PromptTokens)
	}
	if usage.CompletionTokens != 50 {
		t.Errorf("Expected completion tokens 50, got %d", usage.CompletionTokens)
	}
	if usage.TotalTokens != 150 {
		t.Errorf("Expected total tokens 150, got %d", usage.TotalTokens)
	}
}

// TestPreCheckResponse_JSON tests PreCheckResponse JSON marshaling
func TestPreCheckResponse_JSON(t *testing.T) {
	resp := PreCheckResponse{
		ContextID: "ctx-123",
		Approved:  true,
		Policies:  []string{"policy1", "policy2"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("Failed to marshal: %v", err)
		return
	}

	var parsed PreCheckResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Failed to unmarshal: %v", err)
		return
	}

	if parsed.ContextID != resp.ContextID {
		t.Error("ContextID mismatch after marshal/unmarshal")
	}
	if parsed.Approved != resp.Approved {
		t.Error("Approved mismatch after marshal/unmarshal")
	}
	if len(parsed.Policies) != len(resp.Policies) {
		t.Error("Policies length mismatch after marshal/unmarshal")
	}
}

// TestAuditLLMCallRequest_JSON tests AuditLLMCallRequest JSON marshaling
func TestAuditLLMCallRequest_JSON(t *testing.T) {
	req := AuditLLMCallRequest{
		ContextID:       "ctx-123",
		ClientID:        "client-456",
		ResponseSummary: "Summary text",
		Provider:        "openai",
		Model:           "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		LatencyMs: 250,
		Metadata: map[string]interface{}{
			"key": "value",
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Errorf("Failed to marshal: %v", err)
		return
	}

	var parsed AuditLLMCallRequest
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Errorf("Failed to unmarshal: %v", err)
		return
	}

	if parsed.ContextID != req.ContextID {
		t.Error("ContextID mismatch")
	}
	if parsed.Provider != req.Provider {
		t.Error("Provider mismatch")
	}
	if parsed.TokenUsage.TotalTokens != req.TokenUsage.TotalTokens {
		t.Error("TotalTokens mismatch")
	}
}

// TestSendGatewayError tests error response helper
func TestSendGatewayError(t *testing.T) {
	rr := httptest.NewRecorder()
	sendGatewayError(rr, "Test error", http.StatusBadRequest)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Errorf("Failed to parse error response: %v", err)
		return
	}

	if resp["success"] != false {
		t.Error("Expected success to be false")
	}
	if resp["error"] != "Test error" {
		t.Errorf("Expected error message 'Test error', got '%v'", resp["error"])
	}
}

// BenchmarkCalculateLLMCost benchmarks cost calculation
func BenchmarkCalculateLLMCost(b *testing.B) {
	usage := TokenUsage{TotalTokens: 1000}
	for i := 0; i < b.N; i++ {
		calculateLLMCost("openai", "gpt-4", usage)
	}
}

// BenchmarkHashString benchmarks hashing
func BenchmarkHashString(b *testing.B) {
	input := "This is a test string for hashing"
	for i := 0; i < b.N; i++ {
		hashString(input)
	}
}

// TestRegisterGatewayHandlers tests endpoint registration
func TestRegisterGatewayHandlers(t *testing.T) {
	router := mux.NewRouter()
	RegisterGatewayHandlers(router)

	// Test that pre-check route was registered
	preCheckReq := httptest.NewRequest("POST", "/api/policy/pre-check", nil)
	match := &mux.RouteMatch{}
	if !router.Match(preCheckReq, match) {
		t.Error("Expected /api/policy/pre-check route to be registered")
	}

	// Test that audit route was registered
	auditReq := httptest.NewRequest("POST", "/api/audit/llm-call", nil)
	if !router.Match(auditReq, match) {
		t.Error("Expected /api/audit/llm-call route to be registered")
	}
}

// TestPreCheckHandler_InvalidJSON tests handling of invalid JSON
func TestPreCheckHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestPreCheckHandler_NoSelfHostedNoLicense tests missing license key in enterprise mode
func TestPreCheckHandler_NoSelfHostedNoLicense(t *testing.T) {
	// Set enterprise mode to require authentication
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	reqBody := PreCheckRequest{
		UserToken: "token",
		ClientID:  "test-client",
		Query:     "test query",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally not setting X-License-Key header

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for missing license key, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAuditHandler_InvalidJSON tests handling of invalid JSON
func TestAuditHandler_InvalidJSON(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBufferString("not json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestAuditHandler_MissingLicenseKey tests missing license key in enterprise mode
func TestAuditHandler_MissingLicenseKey(t *testing.T) {
	// Set enterprise mode to require authentication
	t.Setenv("DEPLOYMENT_MODE", "enterprise")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "test-client",
		Provider:  "openai",
		Model:     "gpt-4",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := apiAuthMiddleware(http.HandlerFunc(handleAuditLLMCall))
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for missing license key, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestCalculateLLMCost_AllProviders tests cost calculation for various providers
func TestCalculateLLMCost_AllProviders(t *testing.T) {
	tests := []struct {
		provider string
		model    string
		tokens   int
		minCost  float64
		maxCost  float64
	}{
		{"openai", "gpt-4", 1000, 0.029, 0.031},
		{"openai", "gpt-4o", 1000, 0.004, 0.006},
		{"openai", "gpt-4o-mini", 1000, 0.0001, 0.0002},
		{"anthropic", "claude-opus-4", 1000, 0.014, 0.016},
		{"anthropic", "claude-sonnet-4", 1000, 0.002, 0.004},
		{"anthropic", "claude-haiku-4.5", 1000, 0.0007, 0.0009},
		{"bedrock", "anthropic.claude-v2", 1000, 0.007, 0.009},
		{"bedrock", "amazon.titan-text", 1000, 0.0007, 0.0009},
		{"ollama", "llama3.2", 1000, 0.0, 0.0},
		{"ollama", "default", 1000, 0.0, 0.0},
		{"unknown", "unknown", 1000, 0.009, 0.011}, // Conservative default
	}

	for _, tc := range tests {
		t.Run(tc.provider+"/"+tc.model, func(t *testing.T) {
			usage := TokenUsage{TotalTokens: tc.tokens}
			cost := calculateLLMCost(tc.provider, tc.model, usage)

			if cost < tc.minCost {
				t.Errorf("Cost %f is less than expected minimum %f", cost, tc.minCost)
			}
			if cost > tc.maxCost {
				t.Errorf("Cost %f is greater than expected maximum %f", cost, tc.maxCost)
			}
		})
	}
}

// TestLLMPricing verifies pricing table has expected providers
func TestLLMPricing(t *testing.T) {
	providers := []string{"openai", "anthropic", "bedrock", "ollama"}
	for _, provider := range providers {
		if _, ok := llmPricing[provider]; !ok {
			t.Errorf("Expected provider %s in pricing table", provider)
		}
	}
}

// TestPreCheckHandler_MissingQuery tests pre-check with missing query
func TestPreCheckHandler_MissingQuery(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := PreCheckRequest{
		UserToken: "test-token",
		ClientID:  "test-client",
		// Query intentionally missing
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "query field is required" {
		t.Errorf("Expected 'query field is required' error, got '%v'", resp["error"])
	}
}

// TestPreCheckHandler_MissingClientID tests pre-check with missing client_id
func TestPreCheckHandler_MissingClientID(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := PreCheckRequest{
		UserToken: "test-token",
		Query:     "test query",
		// ClientID intentionally missing
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "client_id field is required" {
		t.Errorf("Expected 'client_id field is required' error, got '%v'", resp["error"])
	}
}

// TestAuditHandler_MissingContextID tests audit with missing context_id
func TestAuditHandler_MissingContextID(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ClientID: "test-client",
		Provider: "openai",
		Model:    "gpt-4",
		// ContextID intentionally missing
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "context_id field is required" {
		t.Errorf("Expected 'context_id field is required' error, got '%v'", resp["error"])
	}
}

// TestAuditHandler_MissingBodyClientID_CommunityMode tests that body client_id
// is optional in community mode — auth-derived identity is used instead.
func TestAuditHandler_MissingBodyClientID_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		Provider:  "openai",
		Model:     "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		// ClientID intentionally missing — auth-derived "community" identity is used
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Simulate apiAuthMiddleware setting context
	ctx := context.WithValue(req.Context(), ContextKeyClientID, "community")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "community")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	// In community mode, missing body client_id is OK — succeeds with auth identity
	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200 (community mode, auth-derived identity), got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAuditHandler_ClientIDMismatch_RejectsOverride tests that non-community mode
// rejects body client_id that doesn't match auth-derived identity.
func TestAuditHandler_ClientIDMismatch_RejectsOverride(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "attacker-client",
		Provider:  "openai",
		Model:     "gpt-4",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Simulate apiAuthMiddleware having authenticated as "real-client"
	ctx := context.WithValue(req.Context(), ContextKeyClientID, "real-client")
	ctx = context.WithValue(ctx, ContextKeyTenantID, "real-tenant")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for client_id mismatch, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestAuditHandler_MissingProvider tests audit with missing provider
func TestAuditHandler_MissingProvider(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "test-client",
		Model:     "gpt-4",
		// Provider intentionally missing
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "provider field is required" {
		t.Errorf("Expected 'provider field is required' error, got '%v'", resp["error"])
	}
}

// TestAuditHandler_MissingModel tests audit with missing model
func TestAuditHandler_MissingModel(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "test-client",
		Provider:  "openai",
		// Model intentionally missing
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "model field is required" {
		t.Errorf("Expected 'model field is required' error, got '%v'", resp["error"])
	}
}

// TestPreCheckHandler_WithDataSources tests pre-check with data sources
func TestPreCheckHandler_WithDataSources(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Policy evaluation uses unified shared engine (legacy engine removed)

	reqBody := PreCheckRequest{
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:    "test-client",
		Query:       "Show me my orders",
		DataSources: []string{"postgres", "mysql"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		return
	}

	var resp PreCheckResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.ContextID == "" {
		t.Error("Expected context_id to be set")
	}
	if !resp.Approved {
		t.Errorf("Expected approved=true, got blocked: %s", resp.BlockReason)
	}
}

// TestPreCheckHandler_PIIDetection tests PII detection (redacts PII by default)
// DEPRECATED: PII detection in Gateway pre-check now uses shared policy engine
func TestPreCheckHandler_PIIDetection(t *testing.T) {
	t.Skip("PII detection migrated to shared policy engine (platform/shared/policy/) - Issues #963, #975")
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Policy evaluation uses unified shared engine
	// Legacy engine removed — unified shared engine handles all policy evaluation
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Request with SSN (critical PII - flagged for redaction by default with PII_ACTION=redact)
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "My SSN is 123-45-6789, what can you tell me?",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Critical PII (SSN) is now approved with redaction by default (PII_ACTION=redact)
	if !resp.Approved {
		t.Error("Expected request to be approved (PII_ACTION=redact allows request with redaction flag)")
	}

	// Should require redaction for PII
	if !resp.RequiresRedaction {
		t.Error("Expected RequiresRedaction=true for SSN detection")
	}

	// Should have triggered PII policy
	hasPIIPolicy := false
	for _, policy := range resp.Policies {
		if policy == "ssn_detection" {
			hasPIIPolicy = true
			break
		}
	}
	if !hasPIIPolicy {
		t.Error("Expected SSN detection policy to be triggered")
	}
}

// TestPreCheckHandler_PIIDetection_BlockMode tests that PII blocks when PII_ACTION=block
func TestPreCheckHandler_PIIDetection_BlockMode(t *testing.T) {
	t.Skip("PII detection migrated to shared policy engine (platform/shared/policy/) - Issues #963, #975")
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	os.Setenv("PII_ACTION", "block") // Enable PII blocking
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")
	defer os.Unsetenv("PII_ACTION")

	// Policy evaluation uses unified shared engine
	// Legacy engine removed — unified shared engine handles all policy evaluation
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Request with SSN (should be blocked when PII_ACTION=block)
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "My SSN is 123-45-6789, what can you tell me?",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Critical PII (SSN) blocks when PII_ACTION=block
	if resp.Approved {
		t.Error("Expected request to be blocked (critical PII detected, PII_ACTION=block)")
	}
}

// TestPreCheckHandler_PIIDetection_LogOnly tests PII in log-only mode (no block, no redact)
func TestPreCheckHandler_PIIDetection_LogOnly(t *testing.T) {
	t.Skip("PII detection migrated to shared policy engine (platform/shared/policy/) - Issues #963, #975")
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	os.Setenv("PII_ACTION", "log") // Log-only mode (no blocking or redaction)
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")
	defer os.Unsetenv("PII_ACTION")

	// Policy evaluation uses unified shared engine
	// Legacy engine removed — unified shared engine handles all policy evaluation
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Request with SSN (should NOT be blocked when PII_ACTION=log)
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "My SSN is 123-45-6789, what can you tell me?",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// With PII_ACTION=log, request should be approved without redaction
	if !resp.Approved {
		t.Errorf("Expected request to be approved when PII_ACTION=log, got blocked: %s", resp.BlockReason)
	}

	// Should NOT require redaction in log-only mode
	if resp.RequiresRedaction {
		t.Error("Expected RequiresRedaction=false when PII_ACTION=log")
	}

	// Should still have triggered PII policy (detection still happens)
	hasPIIPolicy := false
	for _, policy := range resp.Policies {
		if policy == "ssn_detection" {
			hasPIIPolicy = true
			break
		}
	}
	if !hasPIIPolicy {
		t.Error("Expected SSN detection policy to be triggered even in log-only mode")
	}
}

// TestPreCheckHandler_DangerousQuery tests dangerous query blocking (DROP TABLE)
func TestPreCheckHandler_DangerousQuery(t *testing.T) {
	// TODO(#1488): Dangerous query detection now requires DB-seeded policies (migration 031).
	t.Skip("Requires DB-seeded dangerous query policies — tracked in #1488")
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize shared engine with mock DB for SQL injection detection
	mockDB2, mockSQL2, _ := sqlmock.New()
	defer mockDB2.Close()
	mockSQL2.ExpectQuery("SELECT").WillReturnRows(sqlmock.NewRows([]string{"id", "name", "pattern", "category", "severity", "action", "enabled", "tier", "tenant_id", "description", "metadata"}))
	engine2 := sharedpolicy.NewUnifiedPolicyEngine(mockDB2, sharedpolicy.EngineConfig{}, nil)
	oldEngine2 := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine2)
	defer sharedpolicy.SetGlobalEngine(oldEngine2)

	// Request with DROP TABLE attempt
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "DROP TABLE users; SELECT * FROM orders",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	// Should be blocked due to DROP TABLE
	if resp.Approved {
		t.Error("Expected request to be blocked due to DROP TABLE")
	}
	if resp.BlockReason == "" {
		t.Error("Expected block reason to be set")
	}
}

// TestAuditHandler_WithMetadata tests audit with metadata
func TestAuditHandler_WithMetadata(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID:       "ctx-with-metadata",
		ClientID:        "test-client",
		ResponseSummary: "The answer is 42",
		Provider:        "anthropic",
		Model:           "claude-sonnet-4",
		TokenUsage: TokenUsage{
			PromptTokens:     200,
			CompletionTokens: 100,
			TotalTokens:      300,
		},
		LatencyMs: 750,
		Metadata: map[string]interface{}{
			"session_id": "sess-456",
			"user_agent": "Mozilla/5.0",
			"ip_address": "192.168.1.1",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		return
	}

	var resp AuditLLMCallResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)

	if !resp.Success {
		t.Error("Expected success=true")
	}
	if resp.AuditID == "" {
		t.Error("Expected audit_id to be set")
	}
}

// TestCalculateLLMCost_ZeroTokens tests cost calculation with zero tokens
func TestCalculateLLMCost_ZeroTokens(t *testing.T) {
	usage := TokenUsage{TotalTokens: 0}
	cost := calculateLLMCost("openai", "gpt-4", usage)

	if cost != 0 {
		t.Errorf("Expected cost 0 for zero tokens, got %f", cost)
	}
}

// TestCalculateLLMCost_UnknownModel tests cost calculation with unknown model
func TestCalculateLLMCost_UnknownModel(t *testing.T) {
	usage := TokenUsage{TotalTokens: 1000}
	cost := calculateLLMCost("openai", "unknown-model", usage)

	// Should use conservative default (0.01 per 1K tokens)
	if cost != 0.01 {
		t.Errorf("Expected cost 0.01 for unknown model, got %f", cost)
	}
}

// TestPreCheckHandler_EmptyBody tests pre-check with empty body
func TestPreCheckHandler_EmptyBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer([]byte{}))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestAuditHandler_EmptyBody tests audit with empty body
func TestAuditHandler_EmptyBody(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewBuffer([]byte{}))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handleAuditLLMCall)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", rr.Code)
	}
}

// TestFetchApprovedData tests data fetching from MCP connectors
func TestFetchApprovedData(t *testing.T) {
	ctx := context.Background()

	user := &User{
		ID:          1,
		Email:       "test@example.com",
		TenantID:    "test-tenant",
		Permissions: []string{"salesforce", "mcp_query"},
	}

	client := &Client{
		ID:       "test-client",
		TenantID: "test-tenant",
	}

	tests := []struct {
		name        string
		dataSources []string
		query       string
	}{
		{
			name:        "nil MCP registry",
			dataSources: []string{"salesforce"},
			query:       "test query",
		},
		{
			name:        "empty data sources",
			dataSources: []string{},
			query:       "test query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Temporarily set mcpRegistry to nil
			oldRegistry := mcpRegistry
			mcpRegistry = nil
			defer func() { mcpRegistry = oldRegistry }()

			result, err := fetchApprovedData(ctx, tt.dataSources, tt.query, user, client, time.Now())

			// Should not error even with nil registry
			if err != nil {
				t.Errorf("fetchApprovedData() error = %v, want nil", err)
			}

			if result == nil {
				t.Error("fetchApprovedData() returned nil, want non-nil map")
			}
		})
	}
}

// TestStoreGatewayContext tests storing gateway context
func TestStoreGatewayContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	req := PreCheckRequest{
		UserToken:   "test-token",
		ClientID:    "test-client",
		DataSources: []string{"source1", "source2"},
		Query:       "SELECT * FROM users",
	}

	policyResult := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{"policy1"},
	}

	expiresAt := time.Now().Add(5 * time.Minute)

	// Expect INSERT query
	mock.ExpectExec("INSERT INTO gateway_contexts").
		WithArgs(
			sqlmock.AnyArg(), // context_id
			"test-client",
			sqlmock.AnyArg(), // user_token_hash
			sqlmock.AnyArg(), // query_hash
			sqlmock.AnyArg(), // data_sources
			sqlmock.AnyArg(), // policies_evaluated
			true,             // approved
			"",               // block_reason
			sqlmock.AnyArg(), // expires_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeGatewayContext(db, "ctx-123", "test-client", req, policyResult, expiresAt)
	if err != nil {
		t.Errorf("storeGatewayContext() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestValidateGatewayContext tests context validation
func TestValidateGatewayContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name          string
		contextID     string
		clientID      string
		setupMock     func()
		expectedValid bool
		expectError   bool
	}{
		{
			name:      "valid context",
			contextID: "ctx-123",
			clientID:  "client-1",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"client_id", "expires_at"}).
					AddRow("client-1", time.Now().Add(5*time.Minute))
				mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
					WithArgs("ctx-123").
					WillReturnRows(rows)
			},
			expectedValid: true,
			expectError:   false,
		},
		{
			name:      "context not found",
			contextID: "ctx-404",
			clientID:  "client-1",
			setupMock: func() {
				mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
					WithArgs("ctx-404").
					WillReturnError(sql.ErrNoRows)
			},
			expectedValid: false,
			expectError:   false,
		},
		{
			name:      "expired context",
			contextID: "ctx-old",
			clientID:  "client-1",
			setupMock: func() {
				rows := sqlmock.NewRows([]string{"client_id", "expires_at"}).
					AddRow("client-1", time.Now().Add(-10*time.Minute))
				mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
					WithArgs("ctx-old").
					WillReturnRows(rows)
			},
			expectedValid: false,
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			valid, err := validateGatewayContext(db, tt.contextID, tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if valid != tt.expectedValid {
				t.Errorf("Expected valid = %v, got %v", tt.expectedValid, valid)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestStoreLLMCallAudit tests storing LLM call audit records
func TestStoreLLMCallAudit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	req := AuditLLMCallRequest{
		ContextID:       "ctx-123",
		ClientID:        "client-1",
		ResponseSummary: "Test response",
		Provider:        "openai",
		Model:           "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 200,
			TotalTokens:      300,
		},
		LatencyMs: 1500,
		Metadata: map[string]interface{}{
			"temperature": 0.7,
		},
	}

	// Expect INSERT query
	mock.ExpectExec("INSERT INTO llm_call_audits").
		WithArgs(
			"audit-123",
			"ctx-123",
			"client-1",
			"openai",
			"gpt-4",
			100,
			200,
			300,
			int64(1500),
			sqlmock.AnyArg(), // estimated_cost_usd
			sqlmock.AnyArg(), // metadata
			// #3435: org_id is now stamped, so an org-scoped regulator export
			// can reach the row. It was omitted entirely before.
			"org-1",
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeLLMCallAudit(db, "audit-123", req, 0.009, "org-1")
	if err != nil {
		t.Errorf("storeLLMCallAudit() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestStoreLLMCallAudit_WithError tests error handling
func TestStoreLLMCallAudit_WithError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer db.Close()

	req := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "client-1",
		Provider:  "openai",
		Model:     "gpt-4",
		TokenUsage: TokenUsage{
			TotalTokens: 100,
		},
	}

	// Expect INSERT to fail
	mock.ExpectExec("INSERT INTO llm_call_audits").
		WillReturnError(fmt.Errorf("database error"))

	err = storeLLMCallAudit(db, "audit-456", req, 0.003, "org-1")
	if err == nil {
		t.Error("Expected error, got nil")
	}
}

// TestQueueGatewayContext_WithAuditQueue tests queueing gateway context with AuditQueue
func TestQueueGatewayContext_WithAuditQueue(t *testing.T) {
	// Setup mock DB for AuditQueue
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create temp fallback file
	fallbackPath := os.TempDir() + "/test-queue-gateway-context.log"
	defer func() { _ = os.Remove(fallbackPath) }()

	// Create AuditQueue
	auditQueue, err := NewAuditQueue(AuditModeCompliance, 100, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	// Create mock policy engine with the audit queue
	oldAuditManager := auditManager
	auditManager = &AuditManager{queue: auditQueue}
	defer func() { auditManager = oldAuditManager }()

	// Setup mock expectation for gateway context insert
	mock.ExpectExec("INSERT INTO gateway_contexts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := PreCheckRequest{
		UserToken:   "test-token",
		ClientID:    "test-client",
		DataSources: []string{"source1"},
		Query:       "test query",
	}

	policyResult := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{"policy1"},
	}

	expiresAt := time.Now().Add(5 * time.Minute)

	// Queue the context
	err = queueGatewayContext("ctx-queue-test", "test-client", req, policyResult, expiresAt)
	if err != nil {
		t.Errorf("queueGatewayContext() error = %v", err)
	}

	// Shutdown queue to ensure processing
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = auditQueue.Shutdown(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestQueueLLMCallAudit_WithAuditQueue tests queueing LLM audit with AuditQueue
func TestQueueLLMCallAudit_WithAuditQueue(t *testing.T) {
	// Setup mock DB for AuditQueue
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create temp fallback file
	fallbackPath := os.TempDir() + "/test-queue-llm-audit.log"
	defer func() { _ = os.Remove(fallbackPath) }()

	// Create AuditQueue
	auditQueue, err := NewAuditQueue(AuditModeCompliance, 100, 1, db, fallbackPath)
	if err != nil {
		t.Fatalf("Failed to create audit queue: %v", err)
	}

	// Create mock policy engine with the audit queue
	oldAuditManager := auditManager
	auditManager = &AuditManager{queue: auditQueue}
	defer func() { auditManager = oldAuditManager }()

	// Setup mock expectation for LLM audit insert
	mock.ExpectExec("INSERT INTO llm_call_audits").
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := AuditLLMCallRequest{
		ContextID:       "ctx-123",
		ClientID:        "client-1",
		ResponseSummary: "Test response",
		Provider:        "openai",
		Model:           "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 200,
			TotalTokens:      300,
		},
		LatencyMs: 1500,
	}

	// Queue the audit
	err = queueLLMCallAudit("audit-queue-test", req, 0.009, "org-1")
	if err != nil {
		t.Errorf("queueLLMCallAudit() error = %v", err)
	}

	// Shutdown queue to ensure processing
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = auditQueue.Shutdown(ctx)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestQueueGatewayContext_FallbackToDirectDB tests fallback when no queue
func TestQueueGatewayContext_FallbackToDirectDB(t *testing.T) {
	// Setup mock DB for direct access
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Set authDB for direct fallback
	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	// Set auditManager to nil to simulate no queue available
	oldAuditManager := auditManager
	// Legacy engine removed — unified shared engine handles all policy evaluation
	defer func() { auditManager = oldAuditManager }()

	// Expect direct DB insert via storeGatewayContext
	mock.ExpectExec("INSERT INTO gateway_contexts").
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := PreCheckRequest{
		UserToken:   "test-token",
		ClientID:    "test-client",
		DataSources: []string{},
		Query:       "test query",
	}

	policyResult := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
	}

	expiresAt := time.Now().Add(5 * time.Minute)

	// Should fallback to direct DB write
	err = queueGatewayContext("ctx-fallback-test", "test-client", req, policyResult, expiresAt)
	if err != nil {
		t.Errorf("queueGatewayContext() error = %v (expected fallback to direct DB)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestQueueLLMCallAudit_FallbackToDirectDB tests fallback when no queue
func TestQueueLLMCallAudit_FallbackToDirectDB(t *testing.T) {
	// Setup mock DB for direct access
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Set authDB for direct fallback
	oldAuthDB := authDB
	authDB = db
	defer func() { authDB = oldAuthDB }()

	// Set auditManager to nil to simulate no queue available
	oldAuditManager := auditManager
	// Legacy engine removed — unified shared engine handles all policy evaluation
	defer func() { auditManager = oldAuditManager }()

	// Expect direct DB insert via storeLLMCallAudit
	mock.ExpectExec("INSERT INTO llm_call_audits").
		WillReturnResult(sqlmock.NewResult(1, 1))

	req := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "client-1",
		Provider:  "openai",
		Model:     "gpt-4",
		TokenUsage: TokenUsage{
			TotalTokens: 100,
		},
	}

	// Should fallback to direct DB write
	err = queueLLMCallAudit("audit-fallback-test", req, 0.003, "org-1")
	if err != nil {
		t.Errorf("queueLLMCallAudit() error = %v (expected fallback to direct DB)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestQueueGatewayContext_NoStorageAvailable tests when no storage is available
func TestQueueGatewayContext_NoStorageAvailable(t *testing.T) {
	// Set both auditManager and authDB to nil
	oldAuditManager := auditManager
	oldAuthDB := authDB
	// Legacy engine removed — unified shared engine handles all policy evaluation
	authDB = nil
	defer func() {
		auditManager = oldAuditManager
		authDB = oldAuthDB
	}()

	req := PreCheckRequest{
		UserToken:   "test-token",
		ClientID:    "test-client",
		DataSources: []string{},
		Query:       "test query",
	}

	policyResult := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
	}

	expiresAt := time.Now().Add(5 * time.Minute)

	// Should not error even with no storage available
	err := queueGatewayContext("ctx-no-storage", "test-client", req, policyResult, expiresAt)
	if err != nil {
		t.Errorf("queueGatewayContext() should not error with no storage, got: %v", err)
	}
}

// TestQueueLLMCallAudit_NoStorageAvailable tests when no storage is available
func TestQueueLLMCallAudit_NoStorageAvailable(t *testing.T) {
	// Set both auditManager and authDB to nil
	oldAuditManager := auditManager
	oldAuthDB := authDB
	// Legacy engine removed — unified shared engine handles all policy evaluation
	authDB = nil
	defer func() {
		auditManager = oldAuditManager
		authDB = oldAuthDB
	}()

	req := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "client-1",
		Provider:  "openai",
		Model:     "gpt-4",
	}

	// Should not error even with no storage available
	err := queueLLMCallAudit("audit-no-storage", req, 0.003, "org-1")
	if err != nil {
		t.Errorf("queueLLMCallAudit() should not error with no storage, got: %v", err)
	}
}

// TestGetGatewayAuditQueue tests retrieval of audit queue
func TestGetGatewayAuditQueue(t *testing.T) {
	t.Run("nil policy engine", func(t *testing.T) {
		oldAuditManager := auditManager
		// Legacy engine removed — unified shared engine handles all policy evaluation
		defer func() { auditManager = oldAuditManager }()

		queue := getGatewayAuditQueue()
		if queue != nil {
			t.Error("Expected nil queue when policy engine is nil")
		}
	})

	t.Run("with policy engine", func(t *testing.T) {
		db, _, err := sqlmock.New()
		if err != nil {
			t.Fatalf("Failed to create mock DB: %v", err)
		}
		defer func() { _ = db.Close() }()

		fallbackPath := os.TempDir() + "/test-get-queue.log"
		defer func() { _ = os.Remove(fallbackPath) }()

		auditQueue, _ := NewAuditQueue(AuditModePerformance, 10, 1, db, fallbackPath)

		oldAuditManager := auditManager
		auditManager = &AuditManager{queue: auditQueue}
		defer func() { auditManager = oldAuditManager }()

		queue := getGatewayAuditQueue()
		if queue == nil {
			t.Error("Expected non-nil queue when policy engine has queue")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_ = auditQueue.Shutdown(ctx)
	})
}

// ==================================================================
// ADDITIONAL TESTS FOR LOW COVERAGE FUNCTIONS
// Tests for fetchApprovedData and related gateway functionality
// ==================================================================

// TestFetchApprovedData_NilRegistry tests fetchApprovedData with nil MCP registry
func TestFetchApprovedData_NilRegistry(t *testing.T) {
	// Save and clear mcpRegistry
	oldRegistry := mcpRegistry
	mcpRegistry = nil
	defer func() { mcpRegistry = oldRegistry }()

	ctx := context.Background()
	user := &User{
		ID:          1,
		Permissions: []string{"mcp_query"},
	}
	client := &Client{
		ID: "test-client",
	}

	result, err := fetchApprovedData(ctx, []string{"test-source"}, "test query", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error with nil registry, got: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected empty result with nil registry, got: %v", result)
	}
}

// TestFetchApprovedData_EmptyDataSources tests fetchApprovedData with empty data sources
func TestFetchApprovedData_EmptyDataSources(t *testing.T) {
	ctx := context.Background()
	user := &User{
		ID:          1,
		Permissions: []string{"mcp_query"},
	}
	client := &Client{
		ID: "test-client",
	}

	result, err := fetchApprovedData(ctx, []string{}, "test query", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error with empty sources, got: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("Expected empty result with empty sources, got: %v", result)
	}
}

// TestFetchApprovedData_NoPermission tests fetchApprovedData when user lacks permission
func TestFetchApprovedData_NoPermission(t *testing.T) {
	// Save and clear mcpRegistry
	oldRegistry := mcpRegistry
	mcpRegistry = nil
	defer func() { mcpRegistry = oldRegistry }()

	ctx := context.Background()
	user := &User{
		ID:          1,
		Permissions: []string{"read_only"}, // No mcp_query permission
	}
	client := &Client{
		ID: "test-client",
	}

	// Should not fetch because user lacks permission
	result, err := fetchApprovedData(ctx, []string{"test-source"}, "test query", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	// Result should be empty because user lacks permission
	if len(result) != 0 {
		t.Errorf("Expected empty result without permission, got: %v", result)
	}
}

// TestStoreGatewayContext_Success tests successful context storage
func TestStoreGatewayContext_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	req := PreCheckRequest{
		UserToken:   "test-token",
		Query:       "test query",
		DataSources: []string{"source1"},
	}

	policyResult := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{"policy1"},
	}

	// Expect INSERT
	mock.ExpectExec("INSERT INTO gateway_contexts").
		WithArgs(
			"test-context-id",
			"test-client",
			sqlmock.AnyArg(), // user token hash
			sqlmock.AnyArg(), // query hash
			sqlmock.AnyArg(), // data sources array
			sqlmock.AnyArg(), // policies evaluated array
			true,             // approved
			"",               // block reason (empty for approved)
			sqlmock.AnyArg(), // expires_at
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeGatewayContext(db, "test-context-id", "test-client", req, policyResult, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Errorf("storeGatewayContext failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestStoreGatewayContext_DBError tests context storage with DB error
func TestStoreGatewayContext_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	req := PreCheckRequest{
		UserToken:   "test-token",
		Query:       "test query",
		DataSources: []string{},
	}

	policyResult := &StaticPolicyResult{
		Blocked: false,
	}

	mock.ExpectExec("INSERT INTO gateway_contexts").
		WillReturnError(fmt.Errorf("database error"))

	err = storeGatewayContext(db, "test-context-id", "test-client", req, policyResult, time.Now().Add(5*time.Minute))
	if err == nil {
		t.Error("Expected error when DB insert fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestValidateGatewayContext_NotFound tests context validation when not found
func TestValidateGatewayContext_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
		WithArgs("nonexistent-context").
		WillReturnError(sql.ErrNoRows)

	valid, err := validateGatewayContext(db, "nonexistent-context", "test-client")
	if err != nil {
		t.Errorf("Expected no error for not found, got: %v", err)
	}
	if valid {
		t.Error("Expected invalid for not found context")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestValidateGatewayContext_Expired tests context validation when expired
func TestValidateGatewayContext_Expired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"client_id", "expires_at"}).
		AddRow("test-client", time.Now().Add(-1*time.Hour)) // Expired 1 hour ago

	mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
		WithArgs("expired-context").
		WillReturnRows(rows)

	valid, err := validateGatewayContext(db, "expired-context", "test-client")
	if err != nil {
		t.Errorf("Expected no error for expired, got: %v", err)
	}
	if valid {
		t.Error("Expected invalid for expired context")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestValidateGatewayContext_ClientMismatch tests context validation with wrong client
func TestValidateGatewayContext_ClientMismatch(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"client_id", "expires_at"}).
		AddRow("different-client", time.Now().Add(5*time.Minute))

	mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
		WithArgs("test-context").
		WillReturnRows(rows)

	_, err = validateGatewayContext(db, "test-context", "wrong-client")
	if err == nil {
		t.Error("Expected error for client mismatch")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestValidateGatewayContext_Valid tests successful context validation
func TestValidateGatewayContext_Valid(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{"client_id", "expires_at"}).
		AddRow("test-client", time.Now().Add(5*time.Minute))

	mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
		WithArgs("valid-context").
		WillReturnRows(rows)

	valid, err := validateGatewayContext(db, "valid-context", "test-client")
	if err != nil {
		t.Errorf("Expected no error for valid context, got: %v", err)
	}
	if !valid {
		t.Error("Expected valid for valid context")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestStoreLLMCallAudit_Success tests successful LLM call audit storage
func TestStoreLLMCallAudit_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	req := AuditLLMCallRequest{
		ContextID: "test-context",
		ClientID:  "test-client",
		Provider:  "openai",
		Model:     "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		LatencyMs: 1500,
		Metadata:  map[string]interface{}{"key": "value"},
	}

	mock.ExpectExec("INSERT INTO llm_call_audits").
		WithArgs(
			"test-audit-id",
			"test-context",
			"test-client",
			"openai",
			"gpt-4",
			int64(100),
			int64(50),
			int64(150),
			int64(1500),
			sqlmock.AnyArg(), // estimated cost
			sqlmock.AnyArg(), // metadata JSON
			"org-1",          // #3435: org_id, stamped from the authenticated identity
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeLLMCallAudit(db, "test-audit-id", req, 0.005, "org-1")
	if err != nil {
		t.Errorf("storeLLMCallAudit failed: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestStoreLLMCallAudit_DBError tests LLM call audit storage with DB error
func TestStoreLLMCallAudit_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	req := AuditLLMCallRequest{
		ContextID: "test-context",
		ClientID:  "test-client",
		Provider:  "openai",
		Model:     "gpt-4",
		TokenUsage: TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		LatencyMs: 1500,
	}

	mock.ExpectExec("INSERT INTO llm_call_audits").
		WillReturnError(fmt.Errorf("database error"))

	err = storeLLMCallAudit(db, "test-audit-id", req, 0.005, "org-1")
	if err == nil {
		t.Error("Expected error when DB insert fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestCalculateLLMCost_KnownProviders tests cost calculation for known providers
func TestCalculateLLMCost_KnownProviders(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		model    string
		usage    TokenUsage
	}{
		{
			name:     "OpenAI GPT-4",
			provider: "openai",
			model:    "gpt-4",
			usage:    TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
		},
		{
			name:     "OpenAI GPT-4o-mini",
			provider: "openai",
			model:    "gpt-4o-mini",
			usage:    TokenUsage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
		{
			name:     "Anthropic Claude",
			provider: "anthropic",
			model:    "claude-opus-4",
			usage:    TokenUsage{PromptTokens: 200, CompletionTokens: 100, TotalTokens: 300},
		},
		{
			name:     "Unknown provider",
			provider: "unknown",
			model:    "some-model",
			usage:    TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := calculateLLMCost(tt.provider, tt.model, tt.usage)
			if cost < 0 {
				t.Errorf("Cost should not be negative, got: %f", cost)
			}
			t.Logf("Cost for %s/%s: $%.6f", tt.provider, tt.model, cost)
		})
	}
}

// TestHashString_Extended tests the hash function with more cases
func TestHashString_Extended(t *testing.T) {
	tests := []struct {
		input string
	}{
		{""},
		{"hello"},
		{"test input with spaces"},
		{"special chars: !@#$%^&*()"},
		{"unicode: 你好世界"},
		{"very long string " + string(make([]byte, 1000))},
	}

	for _, tt := range tests {
		t.Run(tt.input[:min(len(tt.input), 20)], func(t *testing.T) {
			hash := hashString(tt.input)
			if hash == "" {
				t.Error("Hash should not be empty")
			}
			// Hash should be consistent
			hash2 := hashString(tt.input)
			if hash != hash2 {
				t.Error("Hash should be deterministic")
			}
		})
	}
}

// TestSendGatewayError_Extended tests error response function with more cases
func TestSendGatewayError_Extended(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		message    string
	}{
		{
			name:       "Bad Request Extended",
			statusCode: http.StatusBadRequest,
			message:    "Invalid request format",
		},
		{
			name:       "Forbidden",
			statusCode: http.StatusForbidden,
			message:    "Access denied",
		},
		{
			name:       "Not Found",
			statusCode: http.StatusNotFound,
			message:    "Resource not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			sendGatewayError(rr, tt.message, tt.statusCode)

			if rr.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, rr.Code)
			}

			var resp map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Errorf("Failed to parse response: %v", err)
			}

			if resp["error"] != tt.message {
				t.Errorf("Expected error message %q, got %q", tt.message, resp["error"])
			}
		})
	}
}

// TestValidateGatewayContext_DBError tests context validation with DB error
func TestValidateGatewayContext_DBError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock DB: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT client_id, expires_at FROM gateway_contexts").
		WithArgs("test-context").
		WillReturnError(fmt.Errorf("database error"))

	_, err = validateGatewayContext(db, "test-context", "test-client")
	if err == nil {
		t.Error("Expected error when DB query fails")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// ==================================================================
// Mock Connector for fetchApprovedData Tests
// ==================================================================

// testMockConnector implements base.Connector for testing fetchApprovedData
type testMockConnector struct {
	name      string
	connType  string
	queryErr  error
	queryRows []map[string]interface{}
}

func (m *testMockConnector) Connect(ctx context.Context, config *base.ConnectorConfig) error {
	return nil
}

func (m *testMockConnector) Disconnect(ctx context.Context) error {
	return nil
}

func (m *testMockConnector) HealthCheck(ctx context.Context) (*base.HealthStatus, error) {
	return &base.HealthStatus{
		Healthy:   true,
		Latency:   10 * time.Millisecond,
		Timestamp: time.Now(),
	}, nil
}

func (m *testMockConnector) Query(ctx context.Context, query *base.Query) (*base.QueryResult, error) {
	if m.queryErr != nil {
		return nil, m.queryErr
	}
	return &base.QueryResult{
		Rows:      m.queryRows,
		RowCount:  len(m.queryRows),
		Duration:  5 * time.Millisecond,
		Cached:    false,
		Connector: m.name,
	}, nil
}

func (m *testMockConnector) Execute(ctx context.Context, cmd *base.Command) (*base.CommandResult, error) {
	return &base.CommandResult{Success: true}, nil
}

func (m *testMockConnector) Name() string           { return m.name }
func (m *testMockConnector) Type() string           { return m.connType }
func (m *testMockConnector) Version() string        { return "1.0.0-test" }
func (m *testMockConnector) Capabilities() []string { return []string{"query"} }

// TestFetchApprovedData_WithMockConnector tests fetchApprovedData with a real connector
func TestFetchApprovedData_WithMockConnector(t *testing.T) {
	// Save original registry
	oldRegistry := mcpRegistry
	defer func() { mcpRegistry = oldRegistry }()

	// Create a new registry and register mock connector
	mcpRegistry = registry.NewRegistry()

	mockConn := &testMockConnector{
		name:     "test-postgres",
		connType: "postgres",
		queryRows: []map[string]interface{}{
			{"id": 1, "name": "Alice"},
			{"id": 2, "name": "Bob"},
		},
	}

	config := &base.ConnectorConfig{
		Name:    "test-postgres",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	err := mcpRegistry.Register("test-postgres", mockConn, config)
	if err != nil {
		t.Fatalf("Failed to register mock connector: %v", err)
	}

	ctx := context.Background()
	user := &User{
		ID:          1,
		TenantID:    "test-tenant",
		Permissions: []string{"test-postgres"}, // Has permission for this source
	}
	client := &Client{ID: "test-client"}

	result, err := fetchApprovedData(ctx, []string{"test-postgres"}, "SELECT * FROM users", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should have result for test-postgres
	if len(result) != 1 {
		t.Errorf("Expected 1 result, got: %d", len(result))
	}

	pgResult, ok := result["test-postgres"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result for test-postgres")
	}

	// Check row count
	if rowCount, ok := pgResult["row_count"].(int); !ok || rowCount != 2 {
		t.Errorf("Expected row_count=2, got: %v", pgResult["row_count"])
	}
}

// TestFetchApprovedData_ConnectorQueryError tests fetchApprovedData when connector query fails
func TestFetchApprovedData_ConnectorQueryError(t *testing.T) {
	// Save original registry
	oldRegistry := mcpRegistry
	defer func() { mcpRegistry = oldRegistry }()

	// Create a new registry and register mock connector that returns error
	mcpRegistry = registry.NewRegistry()

	mockConn := &testMockConnector{
		name:     "failing-connector",
		connType: "postgres",
		queryErr: errors.New("connection timeout"),
	}

	config := &base.ConnectorConfig{
		Name:    "failing-connector",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	}

	err := mcpRegistry.Register("failing-connector", mockConn, config)
	if err != nil {
		t.Fatalf("Failed to register mock connector: %v", err)
	}

	ctx := context.Background()
	user := &User{
		ID:          1,
		TenantID:    "test-tenant",
		Permissions: []string{"failing-connector"},
	}
	client := &Client{ID: "test-client"}

	result, err := fetchApprovedData(ctx, []string{"failing-connector"}, "SELECT * FROM users", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error even when query fails (should continue), got: %v", err)
	}

	// Result should be empty because query failed
	if len(result) != 0 {
		t.Errorf("Expected empty result when query fails, got: %v", result)
	}
}

// TestFetchApprovedData_ConnectorNotFound tests fetchApprovedData when connector doesn't exist
func TestFetchApprovedData_ConnectorNotFound(t *testing.T) {
	// Save original registry
	oldRegistry := mcpRegistry
	defer func() { mcpRegistry = oldRegistry }()

	// Create an empty registry (no connectors registered)
	mcpRegistry = registry.NewRegistry()

	ctx := context.Background()
	user := &User{
		ID:          1,
		TenantID:    "test-tenant",
		Permissions: []string{"*"}, // Wildcard permission
	}
	client := &Client{ID: "test-client"}

	result, err := fetchApprovedData(ctx, []string{"nonexistent-connector"}, "SELECT * FROM users", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error when connector not found, got: %v", err)
	}

	// Result should be empty because connector doesn't exist
	if len(result) != 0 {
		t.Errorf("Expected empty result for missing connector, got: %v", result)
	}
}

// TestFetchApprovedData_MultipleConnectors tests with multiple data sources
func TestFetchApprovedData_MultipleConnectors(t *testing.T) {
	// Save original registry
	oldRegistry := mcpRegistry
	defer func() { mcpRegistry = oldRegistry }()

	mcpRegistry = registry.NewRegistry()

	// Register two connectors - one succeeds, one fails
	mockConn1 := &testMockConnector{
		name:     "pg1",
		connType: "postgres",
		queryRows: []map[string]interface{}{
			{"id": 1, "data": "value1"},
		},
	}
	mockConn2 := &testMockConnector{
		name:     "pg2",
		connType: "postgres",
		queryErr: errors.New("error"),
	}

	_ = mcpRegistry.Register("pg1", mockConn1, &base.ConnectorConfig{Name: "pg1", Type: "postgres", Timeout: 5 * time.Second})
	_ = mcpRegistry.Register("pg2", mockConn2, &base.ConnectorConfig{Name: "pg2", Type: "postgres", Timeout: 5 * time.Second})

	ctx := context.Background()
	user := &User{
		ID:          1,
		TenantID:    "test-tenant",
		Permissions: []string{"pg1", "pg2"},
	}
	client := &Client{ID: "test-client"}

	result, err := fetchApprovedData(ctx, []string{"pg1", "pg2"}, "SELECT 1", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Should have result for pg1 only (pg2 failed)
	if len(result) != 1 {
		t.Errorf("Expected 1 result (pg1 only), got: %d", len(result))
	}

	if _, ok := result["pg1"]; !ok {
		t.Error("Expected result for pg1")
	}
	if _, ok := result["pg2"]; ok {
		t.Error("Did not expect result for pg2 (should have failed)")
	}
}

// TestFetchApprovedData_MCPQueryPermission tests with mcp_query permission
func TestFetchApprovedData_MCPQueryPermission(t *testing.T) {
	// Save original registry
	oldRegistry := mcpRegistry
	defer func() { mcpRegistry = oldRegistry }()

	mcpRegistry = registry.NewRegistry()

	mockConn := &testMockConnector{
		name:     "test-db",
		connType: "postgres",
		queryRows: []map[string]interface{}{
			{"value": 42},
		},
	}

	_ = mcpRegistry.Register("test-db", mockConn, &base.ConnectorConfig{
		Name:    "test-db",
		Type:    "postgres",
		Timeout: 5 * time.Second,
	})

	ctx := context.Background()
	user := &User{
		ID:          1,
		TenantID:    "test-tenant",
		Permissions: []string{"mcp_query"}, // Generic MCP query permission
	}
	client := &Client{ID: "test-client"}

	result, err := fetchApprovedData(ctx, []string{"test-db"}, "SELECT 42 as value", user, client, time.Now())
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result with mcp_query permission, got: %d", len(result))
	}
}

// ==================================================================
// RBI Kill Switch Tests (Community stub behavior)
// ==================================================================

// TestCheckRBIKillSwitch_Community tests that kill switch returns not blocked in Community mode
func TestCheckRBIKillSwitch_Community(t *testing.T) {
	ctx := context.Background()

	// In Community mode, kill switch should always return not blocked
	result := checkRBIKillSwitch(ctx, "org-123", "system-456")

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.IsBlocked {
		t.Error("Community stub should never block (expected IsBlocked=false)")
	}
}

// TestGetRBIKillSwitchChecker tests lazy initialization of kill switch checker
func TestGetRBIKillSwitchChecker(t *testing.T) {
	// First call initializes
	checker := getRBIKillSwitchChecker()

	// Second call should return the same instance
	checker2 := getRBIKillSwitchChecker()

	// In Community mode, checker will be nil because KillSwitchEnabled() returns false
	// But the function should be consistent
	if checker != checker2 {
		t.Error("getRBIKillSwitchChecker should return the same instance on subsequent calls")
	}
}

// TestPreCheckHandler_KillSwitchIntegration tests that kill switch check is integrated into pre-check flow
// In Community mode, kill switch is not enforced, so requests pass through. In enterprise mode, active kill switches block requests.
func TestPreCheckHandler_KillSwitchIntegration(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Normal request - should pass in Community mode (kill switch not enforced)
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "What is the status of my order?",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(handlePolicyPreCheck)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
		return
	}

	var resp PreCheckResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// In Community mode, kill switch check always returns not blocked
	if !resp.Approved {
		t.Errorf("Expected Approved=true (Community mode doesn't enforce kill switch), got Approved=false. BlockReason: %s",
			resp.BlockReason)
	}
}

// ==================================================================
// RBI PII Detection Tests (Community edition behavior)
// ==================================================================

// TestCheckRBIPII_Community tests RBI PII check in Community mode (pattern-based detection)
func TestCheckRBIPII_Community(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("tests community PII pattern detection; enterprise uses checksum validation with different detection results")
	}
	// Community edition detects India PII using pattern-based detection
	tests := []struct {
		name              string
		query             string
		expectHasPII      bool
		expectCriticalPII bool
	}{
		{
			name:              "Normal query",
			query:             "What is the weather today?",
			expectHasPII:      false,
			expectCriticalPII: false,
		},
		{
			name:              "Query with Aadhaar number (detected - critical)",
			query:             "My Aadhaar number is 2234 5678 9012",
			expectHasPII:      true,
			expectCriticalPII: true,
		},
		{
			name:              "Query with PAN number (detected - critical)",
			query:             "My PAN is ABCDE1234F",
			expectHasPII:      true,
			expectCriticalPII: true,
		},
		{
			name:              "Query with UPI ID (detected - critical)",
			query:             "Send payment to user@paytm",
			expectHasPII:      true,
			expectCriticalPII: true,
		},
		{
			name:              "Query with IFSC code (detected - non-critical)",
			query:             "Transfer to IFSC SBIN0001234",
			expectHasPII:      true,
			expectCriticalPII: false, // IFSC code is medium severity, not critical
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pass false for blockOnCritical - we're testing detection, not blocking behavior
			result := checkRBIPII(tt.query, false)

			// Community edition detects India PII with pattern matching
			if result.HasPII != tt.expectHasPII {
				t.Errorf("Expected HasPII=%v, got %v for: %s", tt.expectHasPII, result.HasPII, tt.query)
			}
			if result.CriticalPII != tt.expectCriticalPII {
				t.Errorf("Expected CriticalPII=%v, got %v for: %s", tt.expectCriticalPII, result.CriticalPII, tt.query)
			}
		})
	}
}

// TestGetRBIPIIDetector tests the lazy initialization of PII detector
func TestGetRBIPIIDetector(t *testing.T) {
	// Community edition returns a pattern-based detector
	// Enterprise edition returns a full-featured detector with Verhoeff validation
	detector := getRBIPIIDetector()

	if detector != nil {
		t.Log("Detector returned (Community or Enterprise build)")
	} else {
		t.Log("Detector is nil (unexpected)")
	}

	// Calling again should return same result (lazy initialization)
	detector2 := getRBIPIIDetector()
	if detector != detector2 {
		t.Error("getRBIPIIDetector should return same instance on subsequent calls")
	}
}

// TestPreCheckHandler_RBIPIIIntegration tests that RBI PII detection is integrated into pre-check flow
// Both Community and Enterprise editions detect critical India PII (Aadhaar, PAN, UPI, Bank Account).
// Sets PII_ACTION=redact explicitly to test the redact path (the v6.2.0 default is warn).
func TestPreCheckHandler_RBIPIIIntegration(t *testing.T) {
	if !isCommunityBuild {
		t.Skip("tests community PII pattern detection; enterprise uses checksum validation with different detection results")
	}
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	os.Setenv("PII_ACTION", "redact")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")
	defer os.Unsetenv("PII_ACTION")
	ResetDetectionConfigCache()
	defer ResetDetectionConfigCache()

	// Policy evaluation uses unified shared engine (legacy engine removed)

	tests := []struct {
		name            string
		query           string
		expectApproved  bool // With PII_ACTION=redact (default), all approved but PII flagged
		expectRedaction bool // Whether redaction is required
	}{
		{
			name:            "Normal query without India PII",
			query:           "What is the GDP of India?",
			expectApproved:  true,
			expectRedaction: false,
		},
		{
			name:            "Query with Aadhaar number (approved with redaction)",
			query:           "My Aadhaar is 2234 5678 9012",
			expectApproved:  true, // Default PII_ACTION=redact approves with flag
			expectRedaction: true,
		},
		{
			name:            "Query with PAN number (approved with redaction)",
			query:           "My PAN number is ABCDE1234F",
			expectApproved:  true, // Default PII_ACTION=redact approves with flag
			expectRedaction: true,
		},
		{
			name:            "Query with UPI ID (approved with redaction)",
			query:           "Send money to user@ybl",
			expectApproved:  true, // Default PII_ACTION=redact approves with flag
			expectRedaction: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqBody := PreCheckRequest{
				UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
				ClientID:  "test-client",
				Query:     tt.query,
			}
			body, _ := json.Marshal(reqBody)

			req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(handlePolicyPreCheck)
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", rr.Code)
				return
			}

			var resp PreCheckResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}

			if resp.Approved != tt.expectApproved {
				t.Errorf("Expected Approved=%v, got %v. BlockReason: %s",
					tt.expectApproved, resp.Approved, resp.BlockReason)
			}

			if resp.RequiresRedaction != tt.expectRedaction {
				t.Errorf("Expected RequiresRedaction=%v, got %v",
					tt.expectRedaction, resp.RequiresRedaction)
			}
		})
	}
}

// TestConvertSharedResultToStatic tests the conversion from shared policy engine
// results to StaticPolicyResult for backward compatibility.
//
// #2965: the mapping is now ACTION-AWARE. A non-blocking PII match produces a
// redaction obligation ONLY when its resolved action is redact; warn/log
// produce an advisory reason and NO redaction. The cases below were rewritten
// from the pre-#2965 shape, where ANY non-blocking PII match (even warn) set
// RequiresRedaction — that was the sibling bug (warn/log postures silently
// redacted). expectAdvisory pins the new warn/log signal.
func TestConvertSharedResultToStatic(t *testing.T) {
	tests := []struct {
		name              string
		input             *sharedpolicy.RequestResult
		expectBlocked     bool
		expectRedaction   bool
		expectAdvisory    bool
		expectPolicyCount int
	}{
		{
			name:              "nil result returns empty non-blocking result",
			input:             nil,
			expectBlocked:     false,
			expectRedaction:   false,
			expectPolicyCount: 0,
		},
		{
			name: "blocked SQLi result",
			input: &sharedpolicy.RequestResult{
				Blocked:     true,
				BlockReason: "SQL injection detected",
				BlockedBy: &sharedpolicy.CompiledPolicy{
					PolicyID: "sqli_union",
					Severity: sharedpolicy.SeverityCritical,
				},
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sqli_union",
						Category: sharedpolicy.CategorySecuritySQLi,
						Action:   sharedpolicy.ActionBlock,
					},
				},
				ProcessingTimeMs: 5,
			},
			expectBlocked:     true,
			expectRedaction:   false,
			expectPolicyCount: 1,
		},
		{
			// #2965: warn action no longer redacts — it yields an advisory reason.
			name: "PII detection with warn action yields advisory reason, not redaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false, // Not blocked because action is warn
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_ssn",
						Category: sharedpolicy.CategoryPIIUS,
						Action:   sharedpolicy.ActionWarn,
					},
				},
				ProcessingTimeMs: 3,
			},
			expectBlocked:     false,
			expectRedaction:   false,
			expectAdvisory:    true,
			expectPolicyCount: 1,
		},
		{
			name: "PII US redact action sets RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_ssn",
						Category: sharedpolicy.CategoryPIIUS,
						Action:   sharedpolicy.ActionRedact,
					},
				},
				ProcessingTimeMs: 3,
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 1,
		},
		{
			name: "PII India redact action sets RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_aadhaar",
						Category: sharedpolicy.CategoryPIIIndia,
						Action:   sharedpolicy.ActionRedact,
					},
				},
				ProcessingTimeMs: 2,
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 1,
		},
		{
			name: "PII EU redact action sets RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_eu_vat",
						Category: sharedpolicy.CategoryPIIEU,
						Action:   sharedpolicy.ActionRedact,
					},
				},
				ProcessingTimeMs: 2,
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 1,
		},
		{
			name: "PII Global redact action sets RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_email",
						Category: sharedpolicy.CategoryPIIGlobal,
						Action:   sharedpolicy.ActionRedact,
					},
				},
				ProcessingTimeMs: 2,
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 1,
		},
		{
			// #2965 direct regression at the convert layer: pii-indonesia under
			// the default redact posture MUST set RequiresRedaction (it silently
			// did not before the fix — the omitted-category bug).
			name: "PII Indonesia redact action sets RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_indonesia_ktp",
						Category: sharedpolicy.CategoryPIIIndonesia,
						Action:   sharedpolicy.ActionRedact,
					},
				},
				ProcessingTimeMs: 2,
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 1,
		},
		{
			name: "blocked PII does not set RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked:     true,
				BlockReason: "PII blocked",
				BlockedBy: &sharedpolicy.CompiledPolicy{
					PolicyID: "sys_pii_ssn",
					Severity: sharedpolicy.SeverityCritical,
				},
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "sys_pii_ssn",
						Category: sharedpolicy.CategoryPIIUS,
						Action:   sharedpolicy.ActionBlock,
					},
				},
			},
			expectBlocked:     true,
			expectRedaction:   false,
			expectPolicyCount: 1,
		},
		{
			name: "non-PII policy does not set RequiresRedaction",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "admin_access",
						Category: sharedpolicy.CategoryAdminAccess,
						Action:   sharedpolicy.ActionWarn,
					},
				},
			},
			expectBlocked:     false,
			expectRedaction:   false,
			expectPolicyCount: 1,
		},
		{
			// admin-access (non-PII, log) contributes no PII signal; the PII
			// match resolves to redact, so RequiresRedaction is set. Both are
			// still counted in TriggeredPolicies.
			name: "multiple policies including a redacting PII match",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "admin_access",
						Category: sharedpolicy.CategoryAdminAccess,
						Action:   sharedpolicy.ActionLog,
					},
					{
						PolicyID: "sys_pii_ssn",
						Category: sharedpolicy.CategoryPIIUS,
						Action:   sharedpolicy.ActionRedact,
					},
				},
			},
			expectBlocked:     false,
			expectRedaction:   true,
			expectPolicyCount: 2,
		},
		{
			// #2965 sibling-bug regression: a PII match resolved to log yields an
			// advisory reason and NO redaction. A non-PII log match (admin) is
			// counted but contributes no PII signal.
			name: "PII log action yields advisory reason, non-PII log ignored",
			input: &sharedpolicy.RequestResult{
				Blocked: false,
				MatchedPolicies: []sharedpolicy.PolicyMatch{
					{
						PolicyID: "admin_access",
						Category: sharedpolicy.CategoryAdminAccess,
						Action:   sharedpolicy.ActionLog,
					},
					{
						PolicyID: "sys_pii_ssn",
						Category: sharedpolicy.CategoryPIIUS,
						Action:   sharedpolicy.ActionLog,
					},
				},
			},
			expectBlocked:     false,
			expectRedaction:   false,
			expectAdvisory:    true,
			expectPolicyCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertSharedResultToStatic(tt.input)

			if result.Blocked != tt.expectBlocked {
				t.Errorf("Blocked = %v, want %v", result.Blocked, tt.expectBlocked)
			}

			if result.RequiresRedaction != tt.expectRedaction {
				t.Errorf("RequiresRedaction = %v, want %v", result.RequiresRedaction, tt.expectRedaction)
			}

			if gotAdvisory := len(result.AdvisoryReasons) > 0; gotAdvisory != tt.expectAdvisory {
				t.Errorf("advisory reasons present = %v (%v), want %v", gotAdvisory, result.AdvisoryReasons, tt.expectAdvisory)
			}

			if len(result.TriggeredPolicies) != tt.expectPolicyCount {
				t.Errorf("TriggeredPolicies count = %d, want %d", len(result.TriggeredPolicies), tt.expectPolicyCount)
			}
		})
	}
}

// TestAgentPIICategoryConvergence pins that the agent's /decide obligation
// bridge classifies PII by the SHARED prefix predicate sharedpolicy.
// IsPIIPolicyCategory — including pii-indonesia, whose omission from the old
// agent-local switch was the #2965 bug — and NOT a duplicate enumerated switch.
// The predicate's own behavior is exhaustively pinned in
// shared/policy TestIsPIIPolicyCategory_Convention; this test guards the
// convergence: every pii-* category (Indonesia included) is PII to the agent.
func TestAgentPIICategoryConvergence(t *testing.T) {
	tests := []struct {
		category sharedpolicy.PolicyCategory
		expected bool
	}{
		{sharedpolicy.CategoryPIIGlobal, true},
		{sharedpolicy.CategoryPIIUS, true},
		{sharedpolicy.CategoryPIIIndia, true},
		{sharedpolicy.CategoryPIIEU, true},
		{sharedpolicy.CategoryPIISingapore, true},
		{sharedpolicy.CategoryPIIIndonesia, true}, // #2965: previously omitted → silent allow
		{sharedpolicy.CategorySecuritySQLi, false},
		{sharedpolicy.CategorySecurityDangerous, false},
		{sharedpolicy.CategoryAdminAccess, false},
		{sharedpolicy.CategoryDataExfiltration, false},
		{sharedpolicy.CategoryComplianceGDPR, false},
		{sharedpolicy.CategoryComplianceHIPAA, false},
		{sharedpolicy.CategoryComplianceRBI, false},
		{sharedpolicy.CategoryComplianceSEBI, false},
		{sharedpolicy.CategoryMediaPII, false}, // OCR subsystem, not the text engine
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			result := sharedpolicy.IsPIIPolicyCategory(tt.category)
			if result != tt.expected {
				t.Errorf("IsPIIPolicyCategory(%s) = %v, want %v", tt.category, result, tt.expected)
			}
		})
	}
}

// TestPreCheckHandler_BudgetEnforcement tests budget blocking in pre-check (Issue #1082)
func TestPreCheckHandler_BudgetEnforcement(t *testing.T) {
	// Enable community mode
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Save original costService and restore after test
	originalCostService := costService
	defer func() { costService = originalCostService }()

	// Create a mock cost service that returns a blocked budget decision
	// Use getDeploymentOrgID() to match what the middleware sets in community mode
	testOrgID := getDeploymentOrgID()
	mockRepo := &mockCostRepository{
		budgets: map[string]*cost.Budget{
			"test-budget-1": {
				ID:       "test-budget-1",
				Name:     "Test Budget",
				Scope:    cost.ScopeOrganization,
				ScopeID:  testOrgID,
				LimitUSD: 100.0,
				Period:   cost.PeriodMonthly,
				OnExceed: cost.OnExceedBlock,
				OrgID:    testOrgID,
				TenantID: "test-client",
				Enabled:  true,
			},
		},
		usageSum: map[string]float64{
			"organization:" + testOrgID: 150.0, // Exceeded budget
		},
	}
	costService = cost.NewService(mockRepo, nil)

	t.Run("budget exceeded with block action returns 402", func(t *testing.T) {
		reqBody := PreCheckRequest{
			UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
			ClientID:  "test-client",
			Query:     "Hello world",
		}
		body, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck))
		handler.ServeHTTP(rr, req)

		// Should return 402 Payment Required
		if rr.Code != http.StatusPaymentRequired {
			t.Errorf("Expected status 402, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var resp PreCheckResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if resp.Approved {
			t.Error("Expected Approved=false for exceeded budget")
		}

		if resp.BudgetInfo == nil {
			t.Error("Expected BudgetInfo to be present")
		} else {
			if !resp.BudgetInfo.Exceeded {
				t.Error("Expected BudgetInfo.Exceeded=true")
			}
			if resp.BudgetInfo.Percentage < 100 {
				t.Errorf("Expected Percentage >= 100, got %.1f", resp.BudgetInfo.Percentage)
			}
		}

		// Verify budget_exceeded policy is in the list
		found := false
		for _, p := range resp.Policies {
			if p == "budget_exceeded" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected 'budget_exceeded' in policies, got %v", resp.Policies)
		}
	})

	t.Run("budget under limit allows request", func(t *testing.T) {
		// Update mock to return non-exceeded budget
		mockRepo.usageSum["organization:community"] = 50.0 // Under budget

		reqBody := PreCheckRequest{
			UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
			ClientID:  "test-client",
			Query:     "Hello world",
		}
		body, _ := json.Marshal(reqBody)

		req, err := http.NewRequest("POST", "/api/policy/pre-check", bytes.NewBuffer(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		handler := http.HandlerFunc(handlePolicyPreCheck)
		handler.ServeHTTP(rr, req)

		// Should return 200 OK
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d. Body: %s", rr.Code, rr.Body.String())
		}

		var resp PreCheckResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if !resp.Approved {
			t.Errorf("Expected Approved=true, got false. BlockReason: %s", resp.BlockReason)
		}

		if resp.BudgetInfo != nil {
			if resp.BudgetInfo.Exceeded {
				t.Error("Expected BudgetInfo.Exceeded=false")
			}
		}
	})
}

// mockCostRepository is a minimal mock for cost.Repository
type mockCostRepository struct {
	budgets  map[string]*cost.Budget
	usageSum map[string]float64
}

func (m *mockCostRepository) CreateBudget(ctx context.Context, budget *cost.Budget) error {
	return nil
}

func (m *mockCostRepository) GetBudget(ctx context.Context, id string) (*cost.Budget, error) {
	if b, ok := m.budgets[id]; ok {
		return b, nil
	}
	return nil, errors.New("budget not found")
}

// GetBudgetScoped / DeleteBudgetScoped satisfy the org/tenant-scoped read path
// added in #2934; the agent-side mock does not exercise scoping, so they defer
// to the unscoped variants.
func (m *mockCostRepository) GetBudgetScoped(ctx context.Context, id, orgID, tenantID string) (*cost.Budget, error) {
	return m.GetBudget(ctx, id)
}

func (m *mockCostRepository) UpdateBudget(ctx context.Context, budget *cost.Budget) error {
	return nil
}

func (m *mockCostRepository) DeleteBudget(ctx context.Context, id string) error {
	return nil
}

func (m *mockCostRepository) DeleteBudgetScoped(ctx context.Context, id, orgID, tenantID string) error {
	return nil
}

func (m *mockCostRepository) ListBudgets(ctx context.Context, opts cost.ListBudgetsOptions) ([]cost.Budget, int, error) {
	return nil, 0, nil
}

func (m *mockCostRepository) GetBudgetsForScope(ctx context.Context, scope cost.BudgetScope, scopeID string, orgID, tenantID string) ([]cost.Budget, error) {
	var result []cost.Budget
	for _, b := range m.budgets {
		if b.Scope == scope && (scopeID == "" || b.ScopeID == scopeID) {
			result = append(result, *b)
		}
	}
	return result, nil
}

func (m *mockCostRepository) SaveUsage(ctx context.Context, record *cost.UsageRecord) error {
	return nil
}

func (m *mockCostRepository) GetUsageForPeriod(ctx context.Context, scope cost.BudgetScope, scopeID string, periodStart time.Time, orgID, tenantID string) (float64, error) {
	key := string(scope) + ":" + scopeID
	if sum, ok := m.usageSum[key]; ok {
		return sum, nil
	}
	return 0, nil
}

func (m *mockCostRepository) GetUsageSummary(ctx context.Context, opts cost.UsageQueryOptions) (*cost.UsageSummary, error) {
	return &cost.UsageSummary{}, nil
}

func (m *mockCostRepository) GetUsageBreakdown(ctx context.Context, groupBy string, opts cost.UsageQueryOptions) (*cost.UsageBreakdown, error) {
	return &cost.UsageBreakdown{}, nil
}

func (m *mockCostRepository) ListUsageRecords(ctx context.Context, opts cost.UsageQueryOptions) ([]cost.UsageRecord, int, error) {
	return nil, 0, nil
}

func (m *mockCostRepository) UpdateAggregate(ctx context.Context, agg *cost.UsageAggregate) error {
	return nil
}

func (m *mockCostRepository) GetAggregate(ctx context.Context, scope, scopeID string, period cost.AggregatePeriod, periodStart time.Time, orgID, tenantID string) (*cost.UsageAggregate, error) {
	return nil, nil
}

func (m *mockCostRepository) ListAggregates(ctx context.Context, scope, scopeID string, period cost.AggregatePeriod, startTime, endTime time.Time, orgID, tenantID string) ([]cost.UsageAggregate, error) {
	return nil, nil
}

func (m *mockCostRepository) SaveAlert(ctx context.Context, alert *cost.BudgetAlert) error {
	return nil
}

func (m *mockCostRepository) GetRecentAlerts(ctx context.Context, budgetID string, limit int) ([]cost.BudgetAlert, error) {
	return nil, nil
}

func (m *mockCostRepository) GetUnacknowledgedAlerts(ctx context.Context, budgetID string) ([]cost.BudgetAlert, error) {
	return nil, nil
}

func (m *mockCostRepository) AcknowledgeAlert(ctx context.Context, alertID int64, acknowledgedBy string) error {
	return nil
}

func (m *mockCostRepository) Ping(ctx context.Context) error {
	return nil
}

// =============================================================================
// HITL (Human-in-the-Loop) Tests - Issue #1081
// =============================================================================
//
// NOTE: Tests for checkHITLRequiredFromContext, isComplianceFramework, and isRegulator
// were REMOVED as part of the Issue #1081 security fix. These functions trusted
// client-provided context which was a security vulnerability and licensing bypass.
//
// HITL is now ENTERPRISE-ONLY and triggered ONLY by policies with require_approval action.
// See the PreCheckHandler tests below for policy-based HITL testing.

// TestPreCheckHandler_HITLNotTriggeredInCommunityMode tests that HITL does NOT
// trigger in Community mode, even if client sends HITL context flags.
// HITL is an ENTERPRISE-ONLY feature that requires policy-based triggering.
func TestPreCheckHandler_HITLNotTriggeredInCommunityMode(t *testing.T) {
	// Enable community mode
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine for testing
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Create request with HITL context flags (which should be IGNORED in Community mode)
	// This tests that clients cannot bypass licensing by sending HITL flags
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "Evaluate loan application for €50,000 - high risk decision",
		Context: map[string]interface{}{
			"requires_hitl":        true,
			"compliance_framework": "EU_AI_ACT",
			"risk_level":           "high",
			"eu_ai_act_article_14": true, // Should be ignored - HITL is Enterprise-only
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck)).ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var preCheckResp PreCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&preCheckResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// In Community mode, HITL should NOT trigger - request should be approved
	// (unless blocked by other policies like PII detection)
	if preCheckResp.BlockReason == "require_approval" {
		t.Error("HITL should NOT trigger in Community mode - this is an Enterprise-only feature")
	}
}

// TestPreCheckHandler_HITLNotRequired tests that normal requests are not blocked
func TestPreCheckHandler_HITLNotRequired(t *testing.T) {
	// Enable community mode with required safeguards
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine for testing
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Create request without HITL context
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "What are the office hours for customer support?",
		Context: map[string]interface{}{
			"risk_level": "low",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck)).ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var preCheckResp PreCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&preCheckResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Normal request should be approved
	if !preCheckResp.Approved {
		t.Error("Expected Approved=true for normal request")
	}

	if preCheckResp.BlockReason != "" {
		t.Errorf("Expected empty BlockReason, got %q", preCheckResp.BlockReason)
	}
}

// TestPreCheckHandler_RBI_SEBI_HITLNotTriggeredInCommunity tests that RBI-SEBI
// HITL context flags are IGNORED in Community mode (Enterprise-only feature).
func TestPreCheckHandler_RBI_SEBI_HITLNotTriggeredInCommunity(t *testing.T) {
	// Enable community mode
	os.Setenv("DEPLOYMENT_MODE", "community")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("DEPLOYMENT_MODE")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine for testing
	// Policy evaluation uses unified shared engine (legacy engine removed)

	// Create request with RBI-SEBI HITL context (should be IGNORED in Community mode)
	reqBody := PreCheckRequest{
		UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.test",
		ClientID:  "test-client",
		Query:     "Evaluate loan application for ₹10,00,000",
		Context: map[string]interface{}{
			"requires_hitl":        true,
			"regulator":            "RBI",
			"compliance_framework": "RBI_SEBI_INDIA",
		},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	apiAuthMiddleware(http.HandlerFunc(handlePolicyPreCheck)).ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var preCheckResp PreCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&preCheckResp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// In Community mode, HITL should NOT trigger - context flags should be ignored
	if preCheckResp.BlockReason == "require_approval" {
		t.Error("HITL should NOT trigger in Community mode for RBI-SEBI - this is an Enterprise-only feature")
	}
}

// TestShouldLogBypassOutreach tests the rate-limited bypass logging function
func TestShouldLogBypassOutreach(t *testing.T) {
	// Reset the last log time to ensure predictable behavior
	outreachLogMu.Lock()
	lastBypassLogTime = time.Time{} // Reset to zero time
	outreachLogMu.Unlock()

	// First call should return true (rate limit not hit)
	if !shouldLogBypassOutreach() {
		t.Error("First call should return true - rate limit not yet hit")
	}

	// Immediate second call should return false (rate limited)
	if shouldLogBypassOutreach() {
		t.Error("Immediate second call should return false - rate limited")
	}

	// Multiple rapid calls should all return false
	for i := 0; i < 5; i++ {
		if shouldLogBypassOutreach() {
			t.Errorf("Rapid call %d should return false - rate limited", i)
		}
	}
}

// TestShouldLogEnforcementOutreach tests the rate-limited enforcement logging function
func TestShouldLogEnforcementOutreach(t *testing.T) {
	// Reset the last log time to ensure predictable behavior
	outreachLogMu.Lock()
	lastEnforcementLogTime = time.Time{} // Reset to zero time
	outreachLogMu.Unlock()

	// First call should return true (rate limit not hit)
	if !shouldLogEnforcementOutreach() {
		t.Error("First call should return true - rate limit not yet hit")
	}

	// Immediate second call should return false (rate limited)
	if shouldLogEnforcementOutreach() {
		t.Error("Immediate second call should return false - rate limited")
	}
}

// TestConvertSharedResultToStatic_NilInput tests nil handling
func TestConvertSharedResultToStatic_NilInput(t *testing.T) {
	result := convertSharedResultToStatic(nil)
	if result == nil {
		t.Fatal("Expected non-nil result for nil input")
	}
	if result.Blocked {
		t.Error("Expected Blocked=false for nil input")
	}
	if len(result.TriggeredPolicies) != 0 {
		t.Error("Expected empty TriggeredPolicies for nil input")
	}
}

// TestConvertSharedResultToStatic_RequireApproval tests HITL action conversion
func TestConvertSharedResultToStatic_RequireApproval(t *testing.T) {
	sharedResult := &sharedpolicy.RequestResult{
		Blocked:           false,
		BlockReason:       "",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "hitl_credit_scoring",
				Action:   sharedpolicy.ActionRequireApproval,
				Category: sharedpolicy.CategorySensitiveData,
				Severity: sharedpolicy.SeverityCritical,
			},
		},
	}

	result := convertSharedResultToStatic(sharedResult)

	if !result.RequiresApproval {
		t.Error("Expected RequiresApproval=true for ActionRequireApproval")
	}
	if len(result.TriggeredPolicies) != 1 {
		t.Errorf("Expected 1 triggered policy, got %d", len(result.TriggeredPolicies))
	}
	if result.TriggeredPolicies[0] != "hitl_credit_scoring" {
		t.Errorf("Expected policy ID 'hitl_credit_scoring', got '%s'", result.TriggeredPolicies[0])
	}
}

// TestConvertSharedResultToStatic_RequireApprovalWithBlocked tests that
// RequiresApproval is set correctly even when the shared engine also sets
// Blocked=true (the shared engine sets Blocked=true for require_approval
// policies because the request IS blocked pending human approval).
func TestConvertSharedResultToStatic_RequireApprovalWithBlocked(t *testing.T) {
	sharedResult := &sharedpolicy.RequestResult{
		Blocked:           true,
		BlockReason:       "Policy description text",
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "custom_hitl_policy",
				Action:   sharedpolicy.ActionRequireApproval,
				Category: sharedpolicy.CategorySensitiveData,
				Severity: sharedpolicy.SeverityHigh,
			},
		},
	}

	result := convertSharedResultToStatic(sharedResult)

	if !result.RequiresApproval {
		t.Error("Expected RequiresApproval=true even when Blocked=true")
	}
	if !result.Blocked {
		t.Error("Expected Blocked=true (request is blocked pending approval)")
	}
}

// TestIsPIICategory tests the PII category detection helper
