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

package anthropic

import (
	"context"
	"time"
)

// LLMProviderAdapter adapts the Anthropic Provider to the LLMProvider interface
// used by the orchestrator's LLMRouter.
type LLMProviderAdapter struct {
	provider *Provider
}

// LLMResponse represents a response from an LLM provider (matches orchestrator interface)
type LLMResponse struct {
	Content      string                 `json:"content"`
	Model        string                 `json:"model"`
	TokensUsed   int                    `json:"tokens_used"`
	Metadata     map[string]interface{} `json:"metadata"`
	ResponseTime time.Duration          `json:"response_time"`
}

// QueryOptions contains options for LLM queries (matches orchestrator interface)
type QueryOptions struct {
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
	Model        string  `json:"model"`
	SystemPrompt string  `json:"system_prompt"`
}

// NewLLMProviderAdapter creates a new adapter from an Anthropic provider
func NewLLMProviderAdapter(provider *Provider) *LLMProviderAdapter {
	return &LLMProviderAdapter{provider: provider}
}

// NewLLMProvider creates a new Anthropic LLM provider adapter from API key
func NewLLMProvider(apiKey string) (*LLMProviderAdapter, error) {
	if apiKey == "" {
		return nil, nil // Return nil for empty key, let router handle mock fallback
	}

	provider, err := NewProvider(Config{
		APIKey: apiKey,
	})
	if err != nil {
		return nil, err
	}

	return NewLLMProviderAdapter(provider), nil
}

// Name returns the provider name
func (a *LLMProviderAdapter) Name() string {
	return a.provider.Name()
}

// Query performs an LLM query (implements LLMProvider interface)
func (a *LLMProviderAdapter) Query(ctx context.Context, prompt string, options QueryOptions) (*LLMResponse, error) {
	req := CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        options.Model,
		SystemPrompt: options.SystemPrompt,
	}

	resp, err := a.provider.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency,
		Metadata: map[string]interface{}{
			"provider":      "anthropic",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
		},
	}, nil
}

// QueryStream performs a streaming LLM query
func (a *LLMProviderAdapter) QueryStream(ctx context.Context, prompt string, options QueryOptions, handler func(chunk string) error) (*LLMResponse, error) {
	req := CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        options.Model,
		SystemPrompt: options.SystemPrompt,
		Stream:       true,
	}

	resp, err := a.provider.CompleteStream(ctx, req, func(chunk StreamChunk) error {
		if chunk.Content != "" {
			return handler(chunk.Content)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency,
		Metadata: map[string]interface{}{
			"provider":      "anthropic",
			"stop_reason":   resp.StopReason,
			"input_tokens":  resp.Usage.InputTokens,
			"output_tokens": resp.Usage.OutputTokens,
			"streamed":      true,
		},
	}, nil
}

// IsHealthy returns whether the provider is healthy
func (a *LLMProviderAdapter) IsHealthy() bool {
	return a.provider.IsHealthy()
}

// GetCapabilities returns the provider's capabilities
func (a *LLMProviderAdapter) GetCapabilities() []string {
	return a.provider.GetCapabilities()
}

// EstimateCost estimates the cost for a given number of tokens
func (a *LLMProviderAdapter) EstimateCost(tokens int) float64 {
	return a.provider.EstimateCost(tokens)
}

// GetProvider returns the underlying Anthropic provider
func (a *LLMProviderAdapter) GetProvider() *Provider {
	return a.provider
}
