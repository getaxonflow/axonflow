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

// Package llm provides a unified interface and types for LLM (Large Language Model) providers.
// This package defines the common abstractions used across all LLM integrations in AxonFlow,
// enabling pluggable provider implementations.
package llm

import (
	"fmt"
	"time"
)

// ProviderType identifies the type of LLM provider.
// Standard types are defined as constants, but custom types can be used
// for third-party or self-hosted providers.
type ProviderType string

// Standard provider types supported out of the box.
const (
	// ProviderTypeOpenAI represents OpenAI's GPT models.
	ProviderTypeOpenAI ProviderType = "openai"

	// ProviderTypeAnthropic represents Anthropic's Claude models.
	ProviderTypeAnthropic ProviderType = "anthropic"

	// ProviderTypeBedrock represents AWS Bedrock managed models.
	ProviderTypeBedrock ProviderType = "bedrock"

	// ProviderTypeOllama represents self-hosted Ollama models.
	ProviderTypeOllama ProviderType = "ollama"

	// ProviderTypeGemini represents Google's Gemini models.
	ProviderTypeGemini ProviderType = "gemini"

	// ProviderTypeAzureOpenAI represents Azure OpenAI Service models.
	ProviderTypeAzureOpenAI ProviderType = "azure-openai"

	// ProviderTypeCustom represents a custom/third-party provider.
	ProviderTypeCustom ProviderType = "custom"
)

// CompletionRequest encapsulates all parameters for an LLM completion request.
// This is the unified request type used across all providers.
type CompletionRequest struct {
	// Prompt is the user's input text/question.
	Prompt string `json:"prompt"`

	// SystemPrompt is an optional system message that sets context/behavior.
	// Not all providers support system prompts.
	SystemPrompt string `json:"system_prompt,omitempty"`

	// MaxTokens limits the maximum number of tokens in the response.
	// If 0, provider defaults are used.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Temperature controls randomness (0.0 = deterministic, 1.0 = creative).
	// Valid range is 0.0 to 2.0 for most providers.
	Temperature float64 `json:"temperature,omitempty"`

	// TopP is nucleus sampling parameter (alternative to temperature).
	// Valid range is 0.0 to 1.0.
	TopP float64 `json:"top_p,omitempty"`

	// TopK limits sampling to top K tokens.
	// Only supported by some providers (Anthropic, Ollama).
	TopK int `json:"top_k,omitempty"`

	// Model overrides the provider's default model.
	// Format is provider-specific (e.g., "gpt-4", "claude-3-5-sonnet-20241022").
	Model string `json:"model,omitempty"`

	// StopSequences are strings that cause generation to stop.
	StopSequences []string `json:"stop_sequences,omitempty"`

	// Stream enables streaming response mode.
	// When true, use CompleteStream instead of Complete.
	Stream bool `json:"stream,omitempty"`

	// Metadata contains provider-specific options.
	// Use this for features not covered by standard fields.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CompletionResponse contains the result of an LLM completion.
type CompletionResponse struct {
	// Content is the generated text response.
	Content string `json:"content"`

	// Model is the actual model used (may differ from requested).
	Model string `json:"model"`

	// Usage contains token usage statistics.
	Usage UsageStats `json:"usage"`

	// Latency is the time taken to generate the response.
	Latency time.Duration `json:"latency"`

	// FinishReason indicates why generation stopped.
	// Common values: "stop", "max_tokens", "content_filter".
	FinishReason string `json:"finish_reason,omitempty"`

	// Metadata contains provider-specific response data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// UsageStats tracks token usage for billing and monitoring.
type UsageStats struct {
	// PromptTokens is the number of tokens in the input.
	PromptTokens int `json:"prompt_tokens"`

	// CompletionTokens is the number of tokens generated.
	CompletionTokens int `json:"completion_tokens"`

	// TotalTokens is the sum of prompt and completion tokens.
	TotalTokens int `json:"total_tokens"`
}

// StreamChunk represents a single chunk in a streaming response.
type StreamChunk struct {
	// Type identifies the chunk type for processing.
	// Common values: "content", "done", "error".
	Type string `json:"type"`

	// Content is the text content of this chunk.
	Content string `json:"content,omitempty"`

	// Done indicates this is the final chunk.
	Done bool `json:"done"`

	// Error contains error information if Type is "error".
	Error string `json:"error,omitempty"`

	// Metadata contains provider-specific chunk data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// StreamHandler is a callback function for processing streaming chunks.
// Return an error to abort the stream.
type StreamHandler func(chunk StreamChunk) error

// HealthStatus represents the health state of a provider.
type HealthStatus string

const (
	// HealthStatusHealthy indicates the provider is operational.
	HealthStatusHealthy HealthStatus = "healthy"

	// HealthStatusDegraded indicates the provider is working but with issues.
	HealthStatusDegraded HealthStatus = "degraded"

	// HealthStatusUnhealthy indicates the provider is not operational.
	HealthStatusUnhealthy HealthStatus = "unhealthy"

	// HealthStatusUnknown indicates health status hasn't been checked.
	HealthStatusUnknown HealthStatus = "unknown"
)

// HealthCheckResult contains detailed health check information.
type HealthCheckResult struct {
	// Status is the overall health status.
	Status HealthStatus `json:"status"`

	// Latency is the time taken for the health check.
	Latency time.Duration `json:"latency"`

	// Message provides additional context about the status.
	Message string `json:"message,omitempty"`

	// LastChecked is when the health check was performed.
	LastChecked time.Time `json:"last_checked"`

	// ConsecutiveFailures tracks recent failures for circuit breaker logic.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`
}

// Capability represents a specific feature supported by a provider.
type Capability string

// Standard capabilities that providers may support.
const (
	// CapabilityChat indicates support for conversational chat.
	CapabilityChat Capability = "chat"

	// CapabilityCompletion indicates support for text completion.
	CapabilityCompletion Capability = "completion"

	// CapabilityStreaming indicates support for streaming responses.
	CapabilityStreaming Capability = "streaming"

	// CapabilityVision indicates support for image input.
	CapabilityVision Capability = "vision"

	// CapabilityFunctionCalling indicates support for function/tool calling.
	CapabilityFunctionCalling Capability = "function_calling"

	// CapabilityEmbeddings indicates support for text embeddings.
	CapabilityEmbeddings Capability = "embeddings"

	// CapabilityCodeGeneration indicates optimized code generation.
	CapabilityCodeGeneration Capability = "code_generation"

	// CapabilityLongContext indicates support for >32K context windows.
	CapabilityLongContext Capability = "long_context"
)

// ProviderInfo contains metadata about a registered provider.
type ProviderInfo struct {
	// Name is the unique identifier for this provider instance.
	Name string `json:"name"`

	// Type identifies the provider implementation.
	Type ProviderType `json:"type"`

	// Capabilities lists supported features.
	Capabilities []Capability `json:"capabilities"`

	// DefaultModel is the model used when none is specified.
	DefaultModel string `json:"default_model"`

	// SupportedModels lists all available models.
	SupportedModels []string `json:"supported_models,omitempty"`

	// Health is the current health status.
	Health HealthCheckResult `json:"health"`

	// Metadata contains provider-specific information.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// CostEstimate provides estimated costs for a request.
type CostEstimate struct {
	// InputCostPer1K is the cost per 1000 input tokens.
	InputCostPer1K float64 `json:"input_cost_per_1k"`

	// OutputCostPer1K is the cost per 1000 output tokens.
	OutputCostPer1K float64 `json:"output_cost_per_1k"`

	// EstimatedInputTokens is the estimated input token count.
	EstimatedInputTokens int `json:"estimated_input_tokens"`

	// EstimatedOutputTokens is the estimated output token count.
	EstimatedOutputTokens int `json:"estimated_output_tokens"`

	// TotalEstimate is the total estimated cost.
	TotalEstimate float64 `json:"total_estimate"`

	// Currency is the currency for costs (default: "USD").
	Currency string `json:"currency"`
}

// Error types for provider operations.

// ProviderError represents an error from an LLM provider.
type ProviderError struct {
	// Provider is the name of the provider that returned the error.
	Provider string `json:"provider"`

	// Code is a machine-readable error code.
	Code string `json:"code"`

	// Message is a human-readable error message.
	Message string `json:"message"`

	// StatusCode is the HTTP status code (if applicable).
	StatusCode int `json:"status_code,omitempty"`

	// Retryable indicates if the request can be retried.
	Retryable bool `json:"retryable"`

	// Cause is the underlying error (if any).
	Cause error `json:"-"`
}

// Error implements the error interface.
func (e *ProviderError) Error() string {
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s error (status %d): %s", e.Provider, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("%s error: %s", e.Provider, e.Message)
}

// Unwrap returns the underlying error.
func (e *ProviderError) Unwrap() error {
	return e.Cause
}

// Common error codes.
const (
	// ErrCodeRateLimit indicates rate limiting.
	ErrCodeRateLimit = "rate_limit"

	// ErrCodeAuth indicates authentication failure.
	ErrCodeAuth = "authentication_error"

	// ErrCodeInvalidRequest indicates malformed request.
	ErrCodeInvalidRequest = "invalid_request"

	// ErrCodeModelNotFound indicates requested model doesn't exist.
	ErrCodeModelNotFound = "model_not_found"

	// ErrCodeContextLength indicates input exceeds context window.
	ErrCodeContextLength = "context_length_exceeded"

	// ErrCodeContentFilter indicates content was filtered.
	ErrCodeContentFilter = "content_filter"

	// ErrCodeServerError indicates provider server error.
	ErrCodeServerError = "server_error"

	// ErrCodeTimeout indicates request timeout.
	ErrCodeTimeout = "timeout"

	// ErrCodeUnavailable indicates provider is unavailable.
	ErrCodeUnavailable = "unavailable"
)

// NewProviderError creates a new ProviderError.
func NewProviderError(provider, code, message string) *ProviderError {
	return &ProviderError{
		Provider:  provider,
		Code:      code,
		Message:   message,
		Retryable: isRetryableCode(code),
	}
}

// isRetryableCode determines if an error code is retryable.
func isRetryableCode(code string) bool {
	switch code {
	case ErrCodeRateLimit, ErrCodeServerError, ErrCodeTimeout, ErrCodeUnavailable:
		return true
	default:
		return false
	}
}
