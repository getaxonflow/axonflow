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
	"errors"
	"testing"
)

func TestProviderType_Values(t *testing.T) {
	tests := []struct {
		name     string
		pt       ProviderType
		expected string
	}{
		{"OpenAI", ProviderTypeOpenAI, "openai"},
		{"Anthropic", ProviderTypeAnthropic, "anthropic"},
		{"Bedrock", ProviderTypeBedrock, "bedrock"},
		{"Ollama", ProviderTypeOllama, "ollama"},
		{"Gemini", ProviderTypeGemini, "gemini"},
		{"Custom", ProviderTypeCustom, "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.pt) != tt.expected {
				t.Errorf("ProviderType %s = %q, want %q", tt.name, tt.pt, tt.expected)
			}
		})
	}
}

func TestHealthStatus_Values(t *testing.T) {
	tests := []struct {
		name     string
		status   HealthStatus
		expected string
	}{
		{"Healthy", HealthStatusHealthy, "healthy"},
		{"Degraded", HealthStatusDegraded, "degraded"},
		{"Unhealthy", HealthStatusUnhealthy, "unhealthy"},
		{"Unknown", HealthStatusUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.status) != tt.expected {
				t.Errorf("HealthStatus %s = %q, want %q", tt.name, tt.status, tt.expected)
			}
		})
	}
}

func TestCapability_Values(t *testing.T) {
	tests := []struct {
		name       string
		capability Capability
		expected   string
	}{
		{"Chat", CapabilityChat, "chat"},
		{"Completion", CapabilityCompletion, "completion"},
		{"Streaming", CapabilityStreaming, "streaming"},
		{"Vision", CapabilityVision, "vision"},
		{"FunctionCalling", CapabilityFunctionCalling, "function_calling"},
		{"Embeddings", CapabilityEmbeddings, "embeddings"},
		{"CodeGeneration", CapabilityCodeGeneration, "code_generation"},
		{"LongContext", CapabilityLongContext, "long_context"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.capability) != tt.expected {
				t.Errorf("Capability %s = %q, want %q", tt.name, tt.capability, tt.expected)
			}
		})
	}
}

func TestProviderError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ProviderError
		expected string
	}{
		{
			name: "basic error without status code",
			err: &ProviderError{
				Provider: "openai",
				Code:     ErrCodeRateLimit,
				Message:  "rate limit exceeded",
			},
			expected: "openai error: rate limit exceeded",
		},
		{
			name: "error with status code",
			err: &ProviderError{
				Provider:   "anthropic",
				Code:       ErrCodeAuth,
				Message:    "invalid API key",
				StatusCode: 401,
			},
			expected: "anthropic error (status 401): invalid API key",
		},
		{
			name: "error with 500 status code",
			err: &ProviderError{
				Provider:   "bedrock",
				Code:       ErrCodeServerError,
				Message:    "internal server error",
				StatusCode: 500,
			},
			expected: "bedrock error (status 500): internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			if errStr != tt.expected {
				t.Errorf("Error() = %q, want %q", errStr, tt.expected)
			}
		})
	}
}

func TestProviderError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &ProviderError{
		Provider: "test",
		Code:     ErrCodeServerError,
		Message:  "server error",
		Cause:    cause,
	}

	unwrapped := err.Unwrap()
	if unwrapped != cause {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
	}
}

func TestNewProviderError(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		code         string
		message      string
		wantRetryable bool
	}{
		{
			name:         "rate limit is retryable",
			provider:     "openai",
			code:         ErrCodeRateLimit,
			message:      "rate limit exceeded",
			wantRetryable: true,
		},
		{
			name:         "server error is retryable",
			provider:     "anthropic",
			code:         ErrCodeServerError,
			message:      "internal server error",
			wantRetryable: true,
		},
		{
			name:         "timeout is retryable",
			provider:     "bedrock",
			code:         ErrCodeTimeout,
			message:      "request timed out",
			wantRetryable: true,
		},
		{
			name:         "unavailable is retryable",
			provider:     "ollama",
			code:         ErrCodeUnavailable,
			message:      "service unavailable",
			wantRetryable: true,
		},
		{
			name:         "auth error is not retryable",
			provider:     "openai",
			code:         ErrCodeAuth,
			message:      "invalid API key",
			wantRetryable: false,
		},
		{
			name:         "invalid request is not retryable",
			provider:     "anthropic",
			code:         ErrCodeInvalidRequest,
			message:      "malformed request",
			wantRetryable: false,
		},
		{
			name:         "model not found is not retryable",
			provider:     "bedrock",
			code:         ErrCodeModelNotFound,
			message:      "model not found",
			wantRetryable: false,
		},
		{
			name:         "context length is not retryable",
			provider:     "openai",
			code:         ErrCodeContextLength,
			message:      "context too long",
			wantRetryable: false,
		},
		{
			name:         "content filter is not retryable",
			provider:     "anthropic",
			code:         ErrCodeContentFilter,
			message:      "content filtered",
			wantRetryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewProviderError(tt.provider, tt.code, tt.message)

			if err.Provider != tt.provider {
				t.Errorf("Provider = %q, want %q", err.Provider, tt.provider)
			}
			if err.Code != tt.code {
				t.Errorf("Code = %q, want %q", err.Code, tt.code)
			}
			if err.Message != tt.message {
				t.Errorf("Message = %q, want %q", err.Message, tt.message)
			}
			if err.Retryable != tt.wantRetryable {
				t.Errorf("Retryable = %v, want %v", err.Retryable, tt.wantRetryable)
			}
		})
	}
}

func TestCompletionRequest_Defaults(t *testing.T) {
	req := CompletionRequest{
		Prompt: "Hello, world!",
	}

	// Verify zero values for optional fields
	if req.MaxTokens != 0 {
		t.Errorf("MaxTokens default = %d, want 0", req.MaxTokens)
	}
	if req.Temperature != 0 {
		t.Errorf("Temperature default = %f, want 0", req.Temperature)
	}
	if req.Model != "" {
		t.Errorf("Model default = %q, want empty", req.Model)
	}
	if req.Stream {
		t.Error("Stream default = true, want false")
	}
}

func TestUsageStats_TotalTokens(t *testing.T) {
	usage := UsageStats{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	if usage.TotalTokens != usage.PromptTokens+usage.CompletionTokens {
		t.Errorf("TotalTokens = %d, want %d", usage.TotalTokens, usage.PromptTokens+usage.CompletionTokens)
	}
}

func TestStreamChunk_Done(t *testing.T) {
	tests := []struct {
		name  string
		chunk StreamChunk
		done  bool
	}{
		{
			name: "content chunk",
			chunk: StreamChunk{
				Type:    "content",
				Content: "Hello",
				Done:    false,
			},
			done: false,
		},
		{
			name: "final chunk",
			chunk: StreamChunk{
				Type: "done",
				Done: true,
			},
			done: true,
		},
		{
			name: "error chunk",
			chunk: StreamChunk{
				Type:  "error",
				Error: "connection lost",
				Done:  true,
			},
			done: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.chunk.Done != tt.done {
				t.Errorf("Done = %v, want %v", tt.chunk.Done, tt.done)
			}
		})
	}
}

func TestCostEstimate_Calculation(t *testing.T) {
	estimate := CostEstimate{
		InputCostPer1K:        0.003,  // $3 per 1M tokens
		OutputCostPer1K:       0.015,  // $15 per 1M tokens
		EstimatedInputTokens:  1000,
		EstimatedOutputTokens: 500,
		TotalEstimate:         0.0105, // 0.003 + 0.0075
		Currency:              "USD",
	}

	expectedTotal := (float64(estimate.EstimatedInputTokens) / 1000 * estimate.InputCostPer1K) +
		(float64(estimate.EstimatedOutputTokens) / 1000 * estimate.OutputCostPer1K)

	// Use tolerance for floating point comparison
	tolerance := 0.000001
	diff := estimate.TotalEstimate - expectedTotal
	if diff < 0 {
		diff = -diff
	}
	if diff > tolerance {
		t.Errorf("TotalEstimate = %f, want %f (diff: %f)", estimate.TotalEstimate, expectedTotal, diff)
	}
}

func TestHealthCheckResult_Status(t *testing.T) {
	tests := []struct {
		name   string
		result HealthCheckResult
		healthy bool
	}{
		{
			name: "healthy provider",
			result: HealthCheckResult{
				Status:  HealthStatusHealthy,
				Message: "OK",
			},
			healthy: true,
		},
		{
			name: "degraded provider",
			result: HealthCheckResult{
				Status:  HealthStatusDegraded,
				Message: "high latency",
			},
			healthy: false,
		},
		{
			name: "unhealthy provider",
			result: HealthCheckResult{
				Status:              HealthStatusUnhealthy,
				Message:             "connection refused",
				ConsecutiveFailures: 3,
			},
			healthy: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isHealthy := tt.result.Status == HealthStatusHealthy
			if isHealthy != tt.healthy {
				t.Errorf("isHealthy = %v, want %v", isHealthy, tt.healthy)
			}
		})
	}
}

func TestProviderInfo_Capabilities(t *testing.T) {
	info := ProviderInfo{
		Name:         "anthropic-primary",
		Type:         ProviderTypeAnthropic,
		Capabilities: []Capability{CapabilityChat, CapabilityStreaming, CapabilityVision},
		DefaultModel: "claude-3-5-sonnet-20241022",
	}

	// Check capabilities
	hasChat := false
	hasStreaming := false
	hasVision := false
	for _, cap := range info.Capabilities {
		switch cap {
		case CapabilityChat:
			hasChat = true
		case CapabilityStreaming:
			hasStreaming = true
		case CapabilityVision:
			hasVision = true
		}
	}

	if !hasChat {
		t.Error("expected CapabilityChat")
	}
	if !hasStreaming {
		t.Error("expected CapabilityStreaming")
	}
	if !hasVision {
		t.Error("expected CapabilityVision")
	}
}
