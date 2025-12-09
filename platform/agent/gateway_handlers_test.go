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

	"axonflow/platform/connectors/base"
	"axonflow/platform/connectors/registry"
)

// TestPreCheckHandler_SelfHostedMode tests pre-check in self-hosted mode
func TestPreCheckHandler_SelfHostedMode(t *testing.T) {
	// Enable self-hosted mode with required safeguards
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	// Initialize policy engine for testing
	staticPolicyEngine = NewStaticPolicyEngine()

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

// TestPreCheckHandler_PolicyBlock tests pre-check blocking by policy
func TestPreCheckHandler_PolicyBlock(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	staticPolicyEngine = NewStaticPolicyEngine()

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

// TestPreCheckHandler_MissingLicenseKey tests pre-check without license key
func TestPreCheckHandler_MissingLicenseKey(t *testing.T) {
	// Ensure self-hosted mode is disabled
	os.Unsetenv("SELF_HOSTED_MODE")

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

// TestAuditLLMCallHandler_SelfHostedMode tests audit in self-hosted mode
func TestAuditLLMCallHandler_SelfHostedMode(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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

// TestAuditLLMCallHandler_MissingLicenseKey tests audit without license key
func TestAuditLLMCallHandler_MissingLicenseKey(t *testing.T) {
	os.Unsetenv("SELF_HOSTED_MODE")

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
	handler := http.HandlerFunc(handleAuditLLMCall)
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
			name:     "OpenAI GPT-3.5",
			provider: "openai",
			model:    "gpt-3.5-turbo",
			tokens:   1000,
			minCost:  0.0004,
			maxCost:  0.001,
		},
		{
			name:     "Anthropic Claude Sonnet",
			provider: "anthropic",
			model:    "claude-3-sonnet",
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

// TestPreCheckHandler_NoSelfHostedNoLicense tests missing license key without self-hosted mode
func TestPreCheckHandler_NoSelfHostedNoLicense(t *testing.T) {
	// Ensure self-hosted mode is disabled
	os.Unsetenv("SELF_HOSTED_MODE")

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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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

// TestAuditHandler_MissingLicenseKey tests missing license key without self-hosted mode
func TestAuditHandler_MissingLicenseKey(t *testing.T) {
	// Ensure self-hosted mode is disabled
	os.Unsetenv("SELF_HOSTED_MODE")

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
	handler := http.HandlerFunc(handleAuditLLMCall)
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
		{"openai", "gpt-4-turbo", 1000, 0.009, 0.011},
		{"openai", "gpt-4o", 1000, 0.004, 0.006},
		{"openai", "gpt-3.5-turbo", 1000, 0.0004, 0.0006},
		{"anthropic", "claude-3-opus", 1000, 0.014, 0.016},
		{"anthropic", "claude-3-sonnet", 1000, 0.002, 0.004},
		{"anthropic", "claude-3-haiku", 1000, 0.00024, 0.00026},
		{"bedrock", "anthropic.claude-v2", 1000, 0.007, 0.009},
		{"bedrock", "amazon.titan-text", 1000, 0.0007, 0.0009},
		{"ollama", "llama2", 1000, 0.0, 0.0},
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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

// TestAuditHandler_MissingClientID tests audit with missing client_id
func TestAuditHandler_MissingClientID(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID: "ctx-123",
		Provider:  "openai",
		Model:     "gpt-4",
		// ClientID intentionally missing
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
	if resp["error"] != "client_id field is required" {
		t.Errorf("Expected 'client_id field is required' error, got '%v'", resp["error"])
	}
}

// TestAuditHandler_MissingProvider tests audit with missing provider
func TestAuditHandler_MissingProvider(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	staticPolicyEngine = NewStaticPolicyEngine()

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

// TestPreCheckHandler_PIIDetection tests PII detection (allowed with redaction flag)
func TestPreCheckHandler_PIIDetection(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	staticPolicyEngine = NewStaticPolicyEngine()

	// Request with SSN (detected but not blocked - redaction flagged)
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

	// PII detection doesn't block - it flags for redaction
	if !resp.Approved {
		t.Errorf("Expected request to be approved (PII detected but not blocked): %s", resp.BlockReason)
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

// TestPreCheckHandler_DangerousQuery tests dangerous query blocking (DROP TABLE)
func TestPreCheckHandler_DangerousQuery(t *testing.T) {
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	staticPolicyEngine = NewStaticPolicyEngine()

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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
	defer os.Unsetenv("ENVIRONMENT")

	reqBody := AuditLLMCallRequest{
		ContextID:       "ctx-with-metadata",
		ClientID:        "test-client",
		ResponseSummary: "The answer is 42",
		Provider:        "anthropic",
		Model:           "claude-3-sonnet",
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
	os.Setenv("SELF_HOSTED_MODE", "true")
	os.Setenv("SELF_HOSTED_MODE_ACKNOWLEDGED", "I_UNDERSTAND_NO_AUTH")
	os.Setenv("ENVIRONMENT", "development")
	defer os.Unsetenv("SELF_HOSTED_MODE")
	defer os.Unsetenv("SELF_HOSTED_MODE_ACKNOWLEDGED")
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

			result, err := fetchApprovedData(ctx, tt.dataSources, tt.query, user, client)

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
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeLLMCallAudit(db, "audit-123", req, 0.009)
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

	err = storeLLMCallAudit(db, "audit-456", req, 0.003)
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
	oldDbPolicyEngine := dbPolicyEngine
	dbPolicyEngine = &DatabasePolicyEngine{
		auditQueue: auditQueue,
	}
	defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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
	oldDbPolicyEngine := dbPolicyEngine
	dbPolicyEngine = &DatabasePolicyEngine{
		auditQueue: auditQueue,
	}
	defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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
	err = queueLLMCallAudit("audit-queue-test", req, 0.009)
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

	// Set dbPolicyEngine to nil to simulate no queue available
	oldDbPolicyEngine := dbPolicyEngine
	dbPolicyEngine = nil
	defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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

	// Set dbPolicyEngine to nil to simulate no queue available
	oldDbPolicyEngine := dbPolicyEngine
	dbPolicyEngine = nil
	defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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
	err = queueLLMCallAudit("audit-fallback-test", req, 0.003)
	if err != nil {
		t.Errorf("queueLLMCallAudit() error = %v (expected fallback to direct DB)", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestQueueGatewayContext_NoStorageAvailable tests when no storage is available
func TestQueueGatewayContext_NoStorageAvailable(t *testing.T) {
	// Set both dbPolicyEngine and authDB to nil
	oldDbPolicyEngine := dbPolicyEngine
	oldAuthDB := authDB
	dbPolicyEngine = nil
	authDB = nil
	defer func() {
		dbPolicyEngine = oldDbPolicyEngine
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
	// Set both dbPolicyEngine and authDB to nil
	oldDbPolicyEngine := dbPolicyEngine
	oldAuthDB := authDB
	dbPolicyEngine = nil
	authDB = nil
	defer func() {
		dbPolicyEngine = oldDbPolicyEngine
		authDB = oldAuthDB
	}()

	req := AuditLLMCallRequest{
		ContextID: "ctx-123",
		ClientID:  "client-1",
		Provider:  "openai",
		Model:     "gpt-4",
	}

	// Should not error even with no storage available
	err := queueLLMCallAudit("audit-no-storage", req, 0.003)
	if err != nil {
		t.Errorf("queueLLMCallAudit() should not error with no storage, got: %v", err)
	}
}

// TestGetGatewayAuditQueue tests retrieval of audit queue
func TestGetGatewayAuditQueue(t *testing.T) {
	t.Run("nil policy engine", func(t *testing.T) {
		oldDbPolicyEngine := dbPolicyEngine
		dbPolicyEngine = nil
		defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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

		oldDbPolicyEngine := dbPolicyEngine
		dbPolicyEngine = &DatabasePolicyEngine{
			auditQueue: auditQueue,
		}
		defer func() { dbPolicyEngine = oldDbPolicyEngine }()

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

	result, err := fetchApprovedData(ctx, []string{"test-source"}, "test query", user, client)
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

	result, err := fetchApprovedData(ctx, []string{}, "test query", user, client)
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
	result, err := fetchApprovedData(ctx, []string{"test-source"}, "test query", user, client)
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
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storeLLMCallAudit(db, "test-audit-id", req, 0.005)
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

	err = storeLLMCallAudit(db, "test-audit-id", req, 0.005)
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
			name:     "OpenAI GPT-3.5",
			provider: "openai",
			model:    "gpt-3.5-turbo",
			usage:    TokenUsage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		},
		{
			name:     "Anthropic Claude",
			provider: "anthropic",
			model:    "claude-3-opus",
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
	name       string
	connType   string
	queryErr   error
	queryRows  []map[string]interface{}
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

func (m *testMockConnector) Name() string         { return m.name }
func (m *testMockConnector) Type() string         { return m.connType }
func (m *testMockConnector) Version() string      { return "1.0.0-test" }
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

	result, err := fetchApprovedData(ctx, []string{"test-postgres"}, "SELECT * FROM users", user, client)
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

	result, err := fetchApprovedData(ctx, []string{"failing-connector"}, "SELECT * FROM users", user, client)
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

	result, err := fetchApprovedData(ctx, []string{"nonexistent-connector"}, "SELECT * FROM users", user, client)
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

	result, err := fetchApprovedData(ctx, []string{"pg1", "pg2"}, "SELECT 1", user, client)
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

	result, err := fetchApprovedData(ctx, []string{"test-db"}, "SELECT 42 as value", user, client)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if len(result) != 1 {
		t.Errorf("Expected 1 result with mcp_query permission, got: %d", len(result))
	}
}


