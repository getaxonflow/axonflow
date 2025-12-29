// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import (
	"testing"
	"time"
)

func TestRequestContextToCompletionRequest(t *testing.T) {
	tests := []struct {
		name     string
		ctx      RequestContext
		wantReq  CompletionRequest
		checkFn  func(t *testing.T, got CompletionRequest)
	}{
		{
			name: "full context conversion",
			ctx: RequestContext{
				Query:           "What is the weather?",
				RequestType:     "simple_query",
				UserRole:        "admin",
				UserPermissions: []string{"read", "write"},
				ClientID:        "client-123",
				OrgID:           "org-456",
				TenantID:        "tenant-789",
				Provider:        "openai",
				Model:           "gpt-4",
				MaxTokens:       1000,
				Temperature:     0.7,
				SystemPrompt:    "You are a weather assistant.",
			},
			checkFn: func(t *testing.T, got CompletionRequest) {
				if got.Prompt != "What is the weather?" {
					t.Errorf("Prompt = %q, want %q", got.Prompt, "What is the weather?")
				}
				if got.SystemPrompt != "You are a weather assistant." {
					t.Errorf("SystemPrompt = %q, want %q", got.SystemPrompt, "You are a weather assistant.")
				}
				if got.MaxTokens != 1000 {
					t.Errorf("MaxTokens = %d, want %d", got.MaxTokens, 1000)
				}
				if got.Temperature != 0.7 {
					t.Errorf("Temperature = %f, want %f", got.Temperature, 0.7)
				}
				if got.Model != "gpt-4" {
					t.Errorf("Model = %q, want %q", got.Model, "gpt-4")
				}
				if got.Metadata["request_type"] != "simple_query" {
					t.Errorf("Metadata[request_type] = %v, want %q", got.Metadata["request_type"], "simple_query")
				}
				if got.Metadata["client_id"] != "client-123" {
					t.Errorf("Metadata[client_id] = %v, want %q", got.Metadata["client_id"], "client-123")
				}
			},
		},
		{
			name: "default system prompt with user role",
			ctx: RequestContext{
				Query:    "Hello",
				UserRole: "viewer",
			},
			checkFn: func(t *testing.T, got CompletionRequest) {
				if got.Prompt != "Hello" {
					t.Errorf("Prompt = %q, want %q", got.Prompt, "Hello")
				}
				expectedPrompt := "You are an AI assistant. User Role: viewer"
				if got.SystemPrompt != expectedPrompt {
					t.Errorf("SystemPrompt = %q, want %q", got.SystemPrompt, expectedPrompt)
				}
			},
		},
		{
			name: "default system prompt without user role",
			ctx: RequestContext{
				Query: "Hello",
			},
			checkFn: func(t *testing.T, got CompletionRequest) {
				expectedPrompt := "You are an AI assistant helping with user queries."
				if got.SystemPrompt != expectedPrompt {
					t.Errorf("SystemPrompt = %q, want %q", got.SystemPrompt, expectedPrompt)
				}
			},
		},
		{
			name: "empty context",
			ctx:  RequestContext{},
			checkFn: func(t *testing.T, got CompletionRequest) {
				if got.Prompt != "" {
					t.Errorf("Prompt = %q, want empty", got.Prompt)
				}
				if got.Metadata == nil {
					t.Error("Metadata should not be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RequestContextToCompletionRequest(tt.ctx)
			if tt.checkFn != nil {
				tt.checkFn(t, got)
			}
		})
	}
}

func TestCompletionResponseToLegacyResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *CompletionResponse
		want *LegacyLLMResponse
	}{
		{
			name: "nil response",
			resp: nil,
			want: nil,
		},
		{
			name: "full response",
			resp: &CompletionResponse{
				Content: "Hello, world!",
				Model:   "gpt-4",
				Usage: UsageStats{
					PromptTokens:     10,
					CompletionTokens: 5,
					TotalTokens:      15,
				},
				Latency:      100 * time.Millisecond,
				FinishReason: "stop",
			},
			want: &LegacyLLMResponse{
				Content:      "Hello, world!",
				Model:        "gpt-4",
				TokensUsed:   15,
				ResponseTime: 100 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompletionResponseToLegacyResponse(tt.resp)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("got nil, want non-nil")
			}

			if got.Content != tt.want.Content {
				t.Errorf("Content = %q, want %q", got.Content, tt.want.Content)
			}
			if got.Model != tt.want.Model {
				t.Errorf("Model = %q, want %q", got.Model, tt.want.Model)
			}
			if got.TokensUsed != tt.want.TokensUsed {
				t.Errorf("TokensUsed = %d, want %d", got.TokensUsed, tt.want.TokensUsed)
			}
			if got.ResponseTime != tt.want.ResponseTime {
				t.Errorf("ResponseTime = %v, want %v", got.ResponseTime, tt.want.ResponseTime)
			}
			if got.Metadata == nil {
				t.Error("Metadata should not be nil")
			}
		})
	}
}

func TestLegacyResponseToCompletionResponse(t *testing.T) {
	tests := []struct {
		name string
		resp *LegacyLLMResponse
		want *CompletionResponse
	}{
		{
			name: "nil response",
			resp: nil,
			want: nil,
		},
		{
			name: "response with metadata tokens",
			resp: &LegacyLLMResponse{
				Content:      "Test response",
				Model:        "claude-3",
				TokensUsed:   100,
				ResponseTime: 50 * time.Millisecond,
				Metadata: map[string]any{
					"prompt_tokens":     30,
					"completion_tokens": 70,
					"finish_reason":     "max_tokens",
				},
			},
			want: &CompletionResponse{
				Content:      "Test response",
				Model:        "claude-3",
				FinishReason: "max_tokens",
				Usage: UsageStats{
					PromptTokens:     30,
					CompletionTokens: 70,
					TotalTokens:      100,
				},
				Latency: 50 * time.Millisecond,
			},
		},
		{
			name: "response without metadata",
			resp: &LegacyLLMResponse{
				Content:      "Test",
				Model:        "test-model",
				TokensUsed:   90,
				ResponseTime: 10 * time.Millisecond,
			},
			want: &CompletionResponse{
				Content:      "Test",
				Model:        "test-model",
				FinishReason: "stop",
				Usage: UsageStats{
					PromptTokens:     30, // 90/3
					CompletionTokens: 60, // 90 - 30
					TotalTokens:      90,
				},
				Latency: 10 * time.Millisecond,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LegacyResponseToCompletionResponse(tt.resp)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("got nil, want non-nil")
			}

			if got.Content != tt.want.Content {
				t.Errorf("Content = %q, want %q", got.Content, tt.want.Content)
			}
			if got.Model != tt.want.Model {
				t.Errorf("Model = %q, want %q", got.Model, tt.want.Model)
			}
			if got.FinishReason != tt.want.FinishReason {
				t.Errorf("FinishReason = %q, want %q", got.FinishReason, tt.want.FinishReason)
			}
			if got.Usage.TotalTokens != tt.want.Usage.TotalTokens {
				t.Errorf("TotalTokens = %d, want %d", got.Usage.TotalTokens, tt.want.Usage.TotalTokens)
			}
			if got.Usage.PromptTokens != tt.want.Usage.PromptTokens {
				t.Errorf("PromptTokens = %d, want %d", got.Usage.PromptTokens, tt.want.Usage.PromptTokens)
			}
			if got.Usage.CompletionTokens != tt.want.Usage.CompletionTokens {
				t.Errorf("CompletionTokens = %d, want %d", got.Usage.CompletionTokens, tt.want.Usage.CompletionTokens)
			}
		})
	}
}

func TestRouteInfoToLegacyProviderInfo(t *testing.T) {
	tests := []struct {
		name string
		info *RouteInfo
		want *LegacyProviderInfo
	}{
		{
			name: "nil info",
			info: nil,
			want: nil,
		},
		{
			name: "full info",
			info: &RouteInfo{
				ProviderName:   "openai",
				ProviderType:   ProviderTypeOpenAI,
				Model:          "gpt-4",
				ResponseTimeMs: 150,
				TokensUsed:     200,
				EstimatedCost:  0.05,
			},
			want: &LegacyProviderInfo{
				Provider:       "openai",
				Model:          "gpt-4",
				ResponseTimeMs: 150,
				TokensUsed:     200,
				Cost:           0.05,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RouteInfoToLegacyProviderInfo(tt.info)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("got nil, want non-nil")
			}

			if got.Provider != tt.want.Provider {
				t.Errorf("Provider = %q, want %q", got.Provider, tt.want.Provider)
			}
			if got.Model != tt.want.Model {
				t.Errorf("Model = %q, want %q", got.Model, tt.want.Model)
			}
			if got.ResponseTimeMs != tt.want.ResponseTimeMs {
				t.Errorf("ResponseTimeMs = %d, want %d", got.ResponseTimeMs, tt.want.ResponseTimeMs)
			}
			if got.TokensUsed != tt.want.TokensUsed {
				t.Errorf("TokensUsed = %d, want %d", got.TokensUsed, tt.want.TokensUsed)
			}
			if got.Cost != tt.want.Cost {
				t.Errorf("Cost = %f, want %f", got.Cost, tt.want.Cost)
			}
		})
	}
}

func TestLegacyProviderInfoToRouteInfo(t *testing.T) {
	tests := []struct {
		name         string
		info         *LegacyProviderInfo
		providerType ProviderType
		want         *RouteInfo
	}{
		{
			name: "nil info",
			info: nil,
			want: nil,
		},
		{
			name: "anthropic provider",
			info: &LegacyProviderInfo{
				Provider:       "anthropic",
				Model:          "claude-3-5-sonnet",
				ResponseTimeMs: 200,
				TokensUsed:     150,
				Cost:           0.03,
			},
			providerType: ProviderTypeAnthropic,
			want: &RouteInfo{
				ProviderName:   "anthropic",
				ProviderType:   ProviderTypeAnthropic,
				Model:          "claude-3-5-sonnet",
				ResponseTimeMs: 200,
				TokensUsed:     150,
				EstimatedCost:  0.03,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LegacyProviderInfoToRouteInfo(tt.info, tt.providerType)
			if tt.want == nil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatal("got nil, want non-nil")
			}

			if got.ProviderName != tt.want.ProviderName {
				t.Errorf("ProviderName = %q, want %q", got.ProviderName, tt.want.ProviderName)
			}
			if got.ProviderType != tt.want.ProviderType {
				t.Errorf("ProviderType = %v, want %v", got.ProviderType, tt.want.ProviderType)
			}
			if got.Model != tt.want.Model {
				t.Errorf("Model = %q, want %q", got.Model, tt.want.Model)
			}
			if got.ResponseTimeMs != tt.want.ResponseTimeMs {
				t.Errorf("ResponseTimeMs = %d, want %d", got.ResponseTimeMs, tt.want.ResponseTimeMs)
			}
		})
	}
}

func TestExtractProviderType(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		want         ProviderType
	}{
		{"openai", "openai", ProviderTypeOpenAI},
		{"anthropic", "anthropic", ProviderTypeAnthropic},
		{"bedrock", "bedrock", ProviderTypeBedrock},
		{"ollama", "ollama", ProviderTypeOllama},
		{"local", "local", ProviderTypeOllama},
		{"gemini", "gemini", ProviderTypeGemini},
		{"unknown", "unknown", ProviderTypeCustom},
		{"empty", "", ProviderTypeCustom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractProviderType(tt.providerName)
			if got != tt.want {
				t.Errorf("ExtractProviderType(%q) = %v, want %v", tt.providerName, got, tt.want)
			}
		})
	}
}

func TestBuildDefaultSystemPrompt(t *testing.T) {
	tests := []struct {
		name string
		ctx  RequestContext
		want string
	}{
		{
			name: "with user role",
			ctx:  RequestContext{UserRole: "admin"},
			want: "You are an AI assistant. User Role: admin",
		},
		{
			name: "without user role",
			ctx:  RequestContext{},
			want: "You are an AI assistant helping with user queries.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDefaultSystemPrompt(tt.ctx)
			if got != tt.want {
				t.Errorf("buildDefaultSystemPrompt() = %q, want %q", got, tt.want)
			}
		})
	}
}
