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

package llm

import (
	"context"
	"testing"
	"time"
)

// MockProvider is a mock implementation of the Provider interface for testing.
type MockProvider struct {
	name            string
	providerType    ProviderType
	capabilities    []Capability
	streaming       bool
	healthStatus    HealthStatus
	completeResp    *CompletionResponse
	completeErr     error
	healthCheckResp *HealthCheckResult
	healthCheckErr  error
	costEstimate    *CostEstimate
}

// Name implements Provider.
func (m *MockProvider) Name() string {
	return m.name
}

// Type implements Provider.
func (m *MockProvider) Type() ProviderType {
	return m.providerType
}

// Complete implements Provider.
func (m *MockProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	if m.completeErr != nil {
		return nil, m.completeErr
	}
	if m.completeResp != nil {
		return m.completeResp, nil
	}
	return &CompletionResponse{
		Content: "Mock response to: " + req.Prompt,
		Model:   "mock-model",
		Usage: UsageStats{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
		Latency: 100 * time.Millisecond,
	}, nil
}

// HealthCheck implements Provider.
func (m *MockProvider) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	if m.healthCheckErr != nil {
		return nil, m.healthCheckErr
	}
	if m.healthCheckResp != nil {
		return m.healthCheckResp, nil
	}
	return &HealthCheckResult{
		Status:      m.healthStatus,
		Latency:     50 * time.Millisecond,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities implements Provider.
func (m *MockProvider) Capabilities() []Capability {
	if m.capabilities != nil {
		return m.capabilities
	}
	return []Capability{CapabilityChat, CapabilityCompletion}
}

// SupportsStreaming implements Provider.
func (m *MockProvider) SupportsStreaming() bool {
	return m.streaming
}

// EstimateCost implements Provider.
func (m *MockProvider) EstimateCost(req CompletionRequest) *CostEstimate {
	return m.costEstimate
}

// NewMockProvider creates a new mock provider for testing.
func NewMockProvider(name string, providerType ProviderType) *MockProvider {
	return &MockProvider{
		name:         name,
		providerType: providerType,
		healthStatus: HealthStatusHealthy,
	}
}

// TestProviderInterface verifies that MockProvider correctly implements Provider.
func TestProviderInterface(t *testing.T) {
	var _ Provider = (*MockProvider)(nil)
}

func TestMockProvider_Name(t *testing.T) {
	provider := NewMockProvider("test-provider", ProviderTypeOpenAI)
	if provider.Name() != "test-provider" {
		t.Errorf("Name() = %q, want %q", provider.Name(), "test-provider")
	}
}

func TestMockProvider_Type(t *testing.T) {
	tests := []struct {
		name         string
		providerType ProviderType
	}{
		{"OpenAI", ProviderTypeOpenAI},
		{"Anthropic", ProviderTypeAnthropic},
		{"Bedrock", ProviderTypeBedrock},
		{"Ollama", ProviderTypeOllama},
		{"Custom", ProviderTypeCustom},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewMockProvider("test", tt.providerType)
			if provider.Type() != tt.providerType {
				t.Errorf("Type() = %v, want %v", provider.Type(), tt.providerType)
			}
		})
	}
}

func TestMockProvider_Complete(t *testing.T) {
	ctx := context.Background()

	t.Run("successful completion", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		req := CompletionRequest{Prompt: "Hello, world!"}

		resp, err := provider.Complete(ctx, req)
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if resp == nil {
			t.Fatal("Complete() returned nil response")
		}
		if resp.Content == "" {
			t.Error("Complete() returned empty content")
		}
	})

	t.Run("custom response", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeAnthropic)
		provider.completeResp = &CompletionResponse{
			Content: "Custom response",
			Model:   "claude-3-5-sonnet",
			Usage: UsageStats{
				PromptTokens:     100,
				CompletionTokens: 200,
				TotalTokens:      300,
			},
		}

		req := CompletionRequest{Prompt: "Test"}
		resp, err := provider.Complete(ctx, req)
		if err != nil {
			t.Fatalf("Complete() error = %v", err)
		}
		if resp.Content != "Custom response" {
			t.Errorf("Content = %q, want %q", resp.Content, "Custom response")
		}
		if resp.Usage.TotalTokens != 300 {
			t.Errorf("TotalTokens = %d, want %d", resp.Usage.TotalTokens, 300)
		}
	})

	t.Run("error response", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		provider.completeErr = NewProviderError("openai", ErrCodeRateLimit, "rate limit exceeded")

		req := CompletionRequest{Prompt: "Test"}
		_, err := provider.Complete(ctx, req)
		if err == nil {
			t.Fatal("Complete() expected error, got nil")
		}

		var provErr *ProviderError
		if !errorAs(err, &provErr) {
			t.Fatalf("expected ProviderError, got %T", err)
		}
		if provErr.Code != ErrCodeRateLimit {
			t.Errorf("error code = %q, want %q", provErr.Code, ErrCodeRateLimit)
		}
	})
}

func TestMockProvider_HealthCheck(t *testing.T) {
	ctx := context.Background()

	t.Run("healthy provider", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		provider.healthStatus = HealthStatusHealthy

		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}
		if result.Status != HealthStatusHealthy {
			t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
		}
	})

	t.Run("unhealthy provider", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeAnthropic)
		provider.healthStatus = HealthStatusUnhealthy

		result, err := provider.HealthCheck(ctx)
		if err != nil {
			t.Fatalf("HealthCheck() error = %v", err)
		}
		if result.Status != HealthStatusUnhealthy {
			t.Errorf("Status = %v, want %v", result.Status, HealthStatusUnhealthy)
		}
	})

	t.Run("health check error", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeBedrock)
		provider.healthCheckErr = NewProviderError("bedrock", ErrCodeUnavailable, "service unavailable")

		_, err := provider.HealthCheck(ctx)
		if err == nil {
			t.Fatal("HealthCheck() expected error, got nil")
		}
	})
}

func TestMockProvider_Capabilities(t *testing.T) {
	t.Run("default capabilities", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		caps := provider.Capabilities()
		if len(caps) != 2 {
			t.Errorf("Capabilities() length = %d, want %d", len(caps), 2)
		}
	})

	t.Run("custom capabilities", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeAnthropic)
		provider.capabilities = []Capability{
			CapabilityChat,
			CapabilityStreaming,
			CapabilityVision,
			CapabilityLongContext,
		}

		caps := provider.Capabilities()
		if len(caps) != 4 {
			t.Errorf("Capabilities() length = %d, want %d", len(caps), 4)
		}

		// Verify specific capabilities
		hasVision := false
		for _, cap := range caps {
			if cap == CapabilityVision {
				hasVision = true
			}
		}
		if !hasVision {
			t.Error("expected CapabilityVision in capabilities")
		}
	})
}

func TestMockProvider_SupportsStreaming(t *testing.T) {
	t.Run("streaming disabled", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		if provider.SupportsStreaming() {
			t.Error("SupportsStreaming() = true, want false")
		}
	})

	t.Run("streaming enabled", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeAnthropic)
		provider.streaming = true
		if !provider.SupportsStreaming() {
			t.Error("SupportsStreaming() = false, want true")
		}
	})
}

func TestMockProvider_EstimateCost(t *testing.T) {
	t.Run("no cost estimate", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOllama)
		estimate := provider.EstimateCost(CompletionRequest{Prompt: "Test"})
		if estimate != nil {
			t.Error("EstimateCost() expected nil for Ollama")
		}
	})

	t.Run("with cost estimate", func(t *testing.T) {
		provider := NewMockProvider("test", ProviderTypeOpenAI)
		provider.costEstimate = &CostEstimate{
			InputCostPer1K:  0.01,
			OutputCostPer1K: 0.03,
			TotalEstimate:   0.05,
			Currency:        "USD",
		}

		estimate := provider.EstimateCost(CompletionRequest{Prompt: "Test"})
		if estimate == nil {
			t.Fatal("EstimateCost() returned nil")
		}
		if estimate.TotalEstimate != 0.05 {
			t.Errorf("TotalEstimate = %f, want %f", estimate.TotalEstimate, 0.05)
		}
	})
}

func TestProviderConfig_Fields(t *testing.T) {
	config := ProviderConfig{
		Name:           "anthropic-primary",
		Type:           ProviderTypeAnthropic,
		APIKey:         "sk-test-key",
		Endpoint:       "https://api.anthropic.com",
		Model:          "claude-3-5-sonnet-20241022",
		Enabled:        true,
		Priority:       100,
		Weight:         50,
		RateLimit:      1000,
		TimeoutSeconds: 30,
		Settings: map[string]any{
			"max_retries": 3,
		},
	}

	if config.Name != "anthropic-primary" {
		t.Errorf("Name = %q, want %q", config.Name, "anthropic-primary")
	}
	if config.Type != ProviderTypeAnthropic {
		t.Errorf("Type = %v, want %v", config.Type, ProviderTypeAnthropic)
	}
	if !config.Enabled {
		t.Error("Enabled = false, want true")
	}
	if config.Settings["max_retries"] != 3 {
		t.Errorf("Settings[max_retries] = %v, want 3", config.Settings["max_retries"])
	}
}

// MockStreamingProvider implements StreamingProvider for testing.
type MockStreamingProvider struct {
	MockProvider
	streamChunks []StreamChunk
	streamErr    error
}

// CompleteStream implements StreamingProvider.
func (m *MockStreamingProvider) CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error) {
	if m.streamErr != nil {
		return nil, m.streamErr
	}

	for _, chunk := range m.streamChunks {
		if err := handler(chunk); err != nil {
			return nil, err
		}
	}

	return &CompletionResponse{
		Content: "Streamed response",
		Model:   "mock-model",
		Usage: UsageStats{
			PromptTokens:     10,
			CompletionTokens: 5,
			TotalTokens:      15,
		},
	}, nil
}

// TestStreamingProviderInterface verifies that MockStreamingProvider implements StreamingProvider.
func TestStreamingProviderInterface(t *testing.T) {
	var _ StreamingProvider = (*MockStreamingProvider)(nil)
}

func TestMockStreamingProvider_CompleteStream(t *testing.T) {
	ctx := context.Background()

	t.Run("successful stream", func(t *testing.T) {
		provider := &MockStreamingProvider{
			MockProvider: *NewMockProvider("test", ProviderTypeAnthropic),
			streamChunks: []StreamChunk{
				{Type: "content", Content: "Hello", Done: false},
				{Type: "content", Content: " world", Done: false},
				{Type: "done", Done: true},
			},
		}
		provider.streaming = true

		var receivedContent string
		handler := func(chunk StreamChunk) error {
			receivedContent += chunk.Content
			return nil
		}

		req := CompletionRequest{Prompt: "Test", Stream: true}
		resp, err := provider.CompleteStream(ctx, req, handler)
		if err != nil {
			t.Fatalf("CompleteStream() error = %v", err)
		}
		if resp == nil {
			t.Fatal("CompleteStream() returned nil response")
		}
		if receivedContent != "Hello world" {
			t.Errorf("received content = %q, want %q", receivedContent, "Hello world")
		}
	})

	t.Run("stream error", func(t *testing.T) {
		provider := &MockStreamingProvider{
			MockProvider: *NewMockProvider("test", ProviderTypeAnthropic),
			streamErr:    NewProviderError("anthropic", ErrCodeServerError, "stream interrupted"),
		}

		handler := func(chunk StreamChunk) error { return nil }

		req := CompletionRequest{Prompt: "Test", Stream: true}
		_, err := provider.CompleteStream(ctx, req, handler)
		if err == nil {
			t.Fatal("CompleteStream() expected error, got nil")
		}
	})
}

// errorAs is a helper for testing error types (simplified errors.As).
func errorAs(err error, target interface{}) bool {
	if err == nil {
		return false
	}
	switch t := target.(type) {
	case **ProviderError:
		if pe, ok := err.(*ProviderError); ok {
			*t = pe
			return true
		}
	}
	return false
}
