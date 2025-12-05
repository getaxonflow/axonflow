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

package main

import (
	"context"
	"testing"
	"time"
)

// TestOpenAIProvider_GetName verifies OpenAI provider returns correct name
func TestOpenAIProvider_GetName(t *testing.T) {
	p := &OpenAIProvider{APIKey: "test-key", Model: "gpt-3.5-turbo"}
	if name := p.GetName(); name != "openai" {
		t.Errorf("GetName() = %s, want openai", name)
	}
}

// TestOpenAIProvider_IsAvailable verifies availability based on API key
func TestOpenAIProvider_IsAvailable(t *testing.T) {
	tests := []struct {
		name      string
		apiKey    string
		available bool
	}{
		{"With API key", "sk-test-key", true},
		{"Without API key", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OpenAIProvider{APIKey: tt.apiKey}
			if got := p.IsAvailable(); got != tt.available {
				t.Errorf("IsAvailable() = %v, want %v", got, tt.available)
			}
		})
	}
}

// TestAnthropicProvider_GetName verifies Anthropic provider returns correct name
func TestAnthropicProvider_GetName(t *testing.T) {
	p := &AnthropicProvider{APIKey: "test-key", Model: "claude-3-5-sonnet-20241022"}
	if name := p.GetName(); name != "anthropic" {
		t.Errorf("GetName() = %s, want anthropic", name)
	}
}

// TestAnthropicProvider_IsAvailable verifies Anthropic is always available (has mock fallback)
func TestAnthropicProvider_IsAvailable(t *testing.T) {
	// Anthropic always returns true because it falls back to mock
	p := &AnthropicProvider{}
	if !p.IsAvailable() {
		t.Error("Anthropic should always be available (has mock fallback)")
	}
}

// TestLocalProvider_GetName verifies Local provider returns correct name
func TestLocalProvider_GetName(t *testing.T) {
	p := &LocalProvider{ModelPath: "/models/local"}
	if name := p.GetName(); name != "local" {
		t.Errorf("GetName() = %s, want local", name)
	}
}

// TestLocalProvider_IsAvailable verifies Local provider is always available
func TestLocalProvider_IsAvailable(t *testing.T) {
	p := &LocalProvider{}
	if !p.IsAvailable() {
		t.Error("Local provider should always be available")
	}
}

// TestLocalProvider_SendRequest verifies Local provider returns mock responses
func TestLocalProvider_SendRequest(t *testing.T) {
	p := &LocalProvider{ModelPath: "/models/local"}
	ctx := context.Background()

	req := &LLMRequest{
		Prompt:      "Test prompt",
		MaxTokens:   100,
		Temperature: 0.7,
		User:        User{Email: "test@example.com"},
	}

	resp, err := p.SendRequest(ctx, req)
	if err != nil {
		t.Fatalf("SendRequest failed: %v", err)
	}

	if resp.Provider != "local" {
		t.Errorf("Provider = %s, want local", resp.Provider)
	}
	if resp.Content == "" {
		t.Error("Expected non-empty content")
	}
	if resp.Duration == 0 {
		t.Error("Expected non-zero duration")
	}
}

// TestSelectProviderWithReason_EURegion tests GDPR compliance routing
func TestSelectProviderWithReason_EURegion(t *testing.T) {
	router := createTestRouter()

	tests := []struct {
		name     string
		region   string
		expected string
	}{
		{"EU West region", "eu-west-1", "local"},
		{"EU Central region", "eu-central-1", "local"},
		{"EU lowercase", "eu", "local"},
		{"US region", "us-east-1", "anthropic"}, // Depends on role/content
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &LLMRequest{
				Prompt: "Show me customer data",
				User: User{
					Email:  "test@example.com",
					Region: tt.region,
					Role:   "agent",
				},
			}

			result := router.selectProviderWithReason(req)
			if result.Provider != tt.expected {
				t.Errorf("Provider = %s, want %s (reason: %s)", result.Provider, tt.expected, result.Reason)
			}
		})
	}
}

// TestSelectProviderWithReason_PIIDetection tests PII-based routing to local
func TestSelectProviderWithReason_PIIDetection(t *testing.T) {
	router := createTestRouter()

	tests := []struct {
		name     string
		prompt   string
		expected string
	}{
		{"SSN query", "Show me customers with SSN", "local"},
		{"Credit card query", "Find credit card numbers", "local"},
		{"Phone query", "Get customer phone numbers", "local"},
		{"Email query", "List customer email addresses", "local"},
		{"Non-PII query", "Show open tickets", "anthropic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &LLMRequest{
				Prompt: tt.prompt,
				User: User{
					Email:  "test@example.com",
					Region: "us-east-1",
					Role:   "agent",
				},
			}

			result := router.selectProviderWithReason(req)
			if result.Provider != tt.expected {
				t.Errorf("Provider = %s, want %s (prompt: %s)", result.Provider, tt.expected, tt.prompt)
			}
		})
	}
}

// TestSelectProviderWithReason_ConfidentialData tests confidential data routing
func TestSelectProviderWithReason_ConfidentialData(t *testing.T) {
	router := createTestRouter()

	tests := []struct {
		name     string
		prompt   string
		expected string
	}{
		{"Confidential query", "Show confidential enterprise data", "anthropic"},
		{"Internal query", "Get internal escalation tickets", "anthropic"},
		{"Proprietary query", "Find proprietary customer info", "anthropic"},
		{"Regular query", "Show open tickets", "anthropic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &LLMRequest{
				Prompt: tt.prompt,
				User: User{
					Email:  "test@example.com",
					Region: "us-east-1",
					Role:   "agent",
				},
			}

			result := router.selectProviderWithReason(req)
			if result.Provider != tt.expected {
				t.Errorf("Provider = %s, want %s", result.Provider, tt.expected)
			}
		})
	}
}

// TestSelectProviderWithReason_RoleBased tests role-based routing
func TestSelectProviderWithReason_RoleBased(t *testing.T) {
	router := createTestRouter()

	tests := []struct {
		name     string
		role     string
		expected string
	}{
		{"Agent role", "agent", "anthropic"},
		{"Manager role", "manager", "openai"},
		{"Admin role", "admin", "openai"},
		{"Unknown role", "unknown", "anthropic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &LLMRequest{
				Prompt: "Show me open tickets", // Non-PII, non-confidential
				User: User{
					Email:  "test@example.com",
					Region: "us-east-1",
					Role:   tt.role,
				},
			}

			result := router.selectProviderWithReason(req)
			if result.Provider != tt.expected {
				t.Errorf("Provider = %s, want %s for role %s", result.Provider, tt.expected, tt.role)
			}
		})
	}
}

// TestApplyPermissionFiltering tests that context is filtered based on permissions
func TestApplyPermissionFiltering(t *testing.T) {
	router := createTestRouter()

	tests := []struct {
		name           string
		permissions    []string
		contextValue   string
		expectRedacted bool
	}{
		{
			name:           "User without read_pii permission",
			permissions:    []string{"query"},
			contextValue:   "Customer SSN: 123-45-6789",
			expectRedacted: true,
		},
		{
			name:           "User with read_pii permission",
			permissions:    []string{"read_pii"},
			contextValue:   "Customer SSN: 123-45-6789",
			expectRedacted: false,
		},
		{
			name:           "No PII in context",
			permissions:    []string{"query"},
			contextValue:   "Customer name: John Doe",
			expectRedacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &LLMRequest{
				Prompt: "Test prompt",
				User: User{
					Email:       "test@example.com",
					Permissions: tt.permissions,
				},
				Context: map[string]string{
					"customer_data": tt.contextValue,
				},
			}

			filtered := router.applyPermissionFiltering(req)

			// Check if value was redacted
			filteredValue := filtered.Context["customer_data"]
			wasRedacted := filteredValue != tt.contextValue

			if wasRedacted != tt.expectRedacted {
				t.Errorf("Redaction = %v, want %v (value: %s)", wasRedacted, tt.expectRedacted, filteredValue)
			}
		})
	}
}

// TestLLMRequest_Struct verifies LLMRequest struct fields
func TestLLMRequest_Struct(t *testing.T) {
	req := &LLMRequest{
		Prompt:      "Test prompt",
		MaxTokens:   1000,
		Temperature: 0.7,
		User: User{
			Email: "test@example.com",
			Role:  "agent",
		},
		Context: map[string]string{
			"key": "value",
		},
		DataSources: []string{"customers", "tickets"},
	}

	if req.Prompt != "Test prompt" {
		t.Error("Prompt field not set correctly")
	}
	if req.MaxTokens != 1000 {
		t.Error("MaxTokens field not set correctly")
	}
	if req.Temperature != 0.7 {
		t.Error("Temperature field not set correctly")
	}
	if req.User.Email != "test@example.com" {
		t.Error("User field not set correctly")
	}
	if len(req.DataSources) != 2 {
		t.Error("DataSources field not set correctly")
	}
}

// TestLLMResponse_Struct verifies LLMResponse struct fields
func TestLLMResponse_Struct(t *testing.T) {
	resp := &LLMResponse{
		Content:      "Test response",
		Provider:     "openai",
		TokensUsed:   150,
		Duration:     time.Second,
		Cached:       false,
		PIIDetected:  []string{"ssn"},
		DataAccessed: []string{"customers"},
	}

	if resp.Content != "Test response" {
		t.Error("Content field not set correctly")
	}
	if resp.Provider != "openai" {
		t.Error("Provider field not set correctly")
	}
	if resp.TokensUsed != 150 {
		t.Error("TokensUsed field not set correctly")
	}
	if resp.Duration != time.Second {
		t.Error("Duration field not set correctly")
	}
}

// TestRoutingPolicy_Struct verifies RoutingPolicy struct
func TestRoutingPolicy_Struct(t *testing.T) {
	policy := &RoutingPolicy{
		DefaultProvider: "anthropic",
		SensitiveDataRules: map[string]string{
			"pii":       "local",
			"financial": "local",
		},
		UserRules: map[string]string{
			"admin": "openai",
		},
		FallbackChain: []string{"openai", "anthropic", "local"},
	}

	if policy.DefaultProvider != "anthropic" {
		t.Error("DefaultProvider not set correctly")
	}
	if len(policy.SensitiveDataRules) != 2 {
		t.Error("SensitiveDataRules not set correctly")
	}
	if len(policy.FallbackChain) != 3 {
		t.Error("FallbackChain not set correctly")
	}
}

// TestAnthropicProvider_GenerateMockSQL tests SQL generation patterns
func TestAnthropicProvider_GenerateMockSQL(t *testing.T) {
	p := &AnthropicProvider{}

	tests := []struct {
		name        string
		prompt      string
		expectSQL   string
		description string
	}{
		{
			name:        "Open tickets",
			prompt:      "Natural Language: \"show open tickets\"",
			expectSQL:   "SELECT st.* FROM support_tickets st WHERE st.status = 'open'",
			description: "Should generate open tickets query",
		},
		{
			name:        "Premium customers",
			prompt:      "Natural Language: \"find premium customers\"",
			expectSQL:   "SELECT c.* FROM customers c WHERE c.support_tier = 'premium'",
			description: "Should generate premium customers query",
		},
		{
			name:        "High priority tickets",
			prompt:      "Natural Language: \"get high priority tickets\"",
			expectSQL:   "SELECT st.* FROM support_tickets st WHERE st.priority = 'high'",
			description: "Should generate high priority query",
		},
		{
			name:        "Enterprise customers",
			prompt:      "Natural Language: \"list enterprise customers\"",
			expectSQL:   "SELECT c.* FROM customers c WHERE c.support_tier = 'enterprise'",
			description: "Should generate enterprise customers query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql := p.generateMockSQL(tt.prompt)
			if sql != tt.expectSQL {
				t.Errorf("generateMockSQL() = %s, want %s", sql, tt.expectSQL)
			}
		})
	}
}

// TestLocalProvider_GenerateMockSQL tests local provider SQL generation
func TestLocalProvider_GenerateMockSQL(t *testing.T) {
	p := &LocalProvider{}

	tests := []struct {
		name      string
		prompt    string
		expectSQL string
	}{
		{
			name:      "SSN query",
			prompt:    "Natural Language: \"find customers with SSN\"",
			expectSQL: "SELECT id, name, email, phone, ssn FROM customers WHERE ssn = '123-45-6789' LIMIT 5",
		},
		{
			name:      "Credit card query",
			prompt:    "Natural Language: \"get credit card info\"",
			expectSQL: "SELECT id, name, email, credit_card FROM customers WHERE credit_card IS NOT NULL LIMIT 5",
		},
		{
			name:      "Open tickets",
			prompt:    "Natural Language: \"show open tickets\"",
			expectSQL: "SELECT st.* FROM support_tickets st WHERE st.status = 'open'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sql := p.generateMockSQL(tt.prompt)
			if sql != tt.expectSQL {
				t.Errorf("generateMockSQL() = %s, want %s", sql, tt.expectSQL)
			}
		})
	}
}

// TestProviderPriorityOrder tests that routing follows correct priority
func TestProviderPriorityOrder(t *testing.T) {
	router := createTestRouter()

	// Priority should be: EU region > PII > Confidential > Role
	tests := []struct {
		name     string
		req      *LLMRequest
		expected string
		reason   string
	}{
		{
			name: "EU region overrides everything",
			req: &LLMRequest{
				Prompt: "Show confidential SSN data", // Has both PII and confidential
				User:   User{Region: "eu-west-1", Role: "admin"},
			},
			expected: "local",
			reason:   "EU region should override PII and role",
		},
		{
			name: "PII overrides confidential and role",
			req: &LLMRequest{
				Prompt: "Show confidential customer SSN", // Has PII
				User:   User{Region: "us-east-1", Role: "admin"},
			},
			expected: "local",
			reason:   "PII should route to local even for admin",
		},
		{
			name: "Confidential routes to anthropic for managers",
			req: &LLMRequest{
				Prompt: "Show confidential reports",
				User:   User{Region: "us-east-1", Role: "manager"},
			},
			expected: "anthropic",
			reason:   "Confidential data should use Anthropic",
		},
		{
			name: "Manager with regular query gets OpenAI",
			req: &LLMRequest{
				Prompt: "Show open tickets",
				User:   User{Region: "us-east-1", Role: "manager"},
			},
			expected: "openai",
			reason:   "Manager with regular query should get OpenAI",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := router.selectProviderWithReason(tt.req)
			if result.Provider != tt.expected {
				t.Errorf("Provider = %s, want %s (%s)", result.Provider, tt.expected, tt.reason)
			}
		})
	}
}

// createTestRouter creates a router for testing without real API keys
func createTestRouter() *LLMRouter {
	providers := map[string]LLMProvider{
		"openai": &OpenAIProvider{
			APIKey: "test-key",
			Model:  "gpt-3.5-turbo",
		},
		"anthropic": &AnthropicProvider{
			APIKey: "test-key",
			Model:  "claude-3-5-sonnet-20241022",
		},
		"local": &LocalProvider{
			ModelPath: "/models/local",
		},
	}

	policies := &RoutingPolicy{
		DefaultProvider: "anthropic",
		SensitiveDataRules: map[string]string{
			"pii":          "local",
			"financial":    "local",
			"medical":      "local",
			"confidential": "anthropic",
		},
		FallbackChain: []string{"openai", "anthropic", "local"},
	}

	return &LLMRouter{
		providers: providers,
		policies:  policies,
	}
}
