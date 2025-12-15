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
	"time"
)

// LegacyProvider is the old provider interface used by LLMRouter.
// This interface is being phased out in favor of the new Provider interface.
// Use the adapters below for backward compatibility.
type LegacyProvider interface {
	Name() string
	Query(ctx context.Context, prompt string, options LegacyQueryOptions) (*LegacyResponse, error)
	IsHealthy() bool
	GetCapabilities() []string
	EstimateCost(tokens int) float64
}

// LegacyQueryOptions represents the old query options format.
type LegacyQueryOptions struct {
	MaxTokens    int     `json:"max_tokens"`
	Temperature  float64 `json:"temperature"`
	Model        string  `json:"model"`
	SystemPrompt string  `json:"system_prompt"`
}

// LegacyResponse represents the old response format.
type LegacyResponse struct {
	Content      string         `json:"content"`
	Model        string         `json:"model"`
	TokensUsed   int            `json:"tokens_used"`
	Metadata     map[string]any `json:"metadata"`
	ResponseTime time.Duration  `json:"response_time"`
}

// ProviderAdapter adapts a new Provider to the legacy LegacyProvider interface.
// This allows gradual migration without breaking existing code.
type ProviderAdapter struct {
	provider Provider
}

// NewProviderAdapter creates an adapter from the new Provider to LegacyProvider.
func NewProviderAdapter(p Provider) *ProviderAdapter {
	return &ProviderAdapter{provider: p}
}

// Name implements LegacyProvider.
func (a *ProviderAdapter) Name() string {
	return a.provider.Name()
}

// Query implements LegacyProvider by delegating to the new Provider.Complete.
func (a *ProviderAdapter) Query(ctx context.Context, prompt string, options LegacyQueryOptions) (*LegacyResponse, error) {
	// Convert legacy options to new format
	req := CompletionRequest{
		Prompt:       prompt,
		MaxTokens:    options.MaxTokens,
		Temperature:  options.Temperature,
		Model:        options.Model,
		SystemPrompt: options.SystemPrompt,
	}

	start := time.Now()
	resp, err := a.provider.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	// Convert new response to legacy format
	return &LegacyResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: time.Since(start),
		Metadata: map[string]any{
			"provider":      string(a.provider.Type()),
			"input_tokens":  resp.Usage.PromptTokens,
			"output_tokens": resp.Usage.CompletionTokens,
			"finish_reason": resp.FinishReason,
		},
	}, nil
}

// IsHealthy implements LegacyProvider.
func (a *ProviderAdapter) IsHealthy() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := a.provider.HealthCheck(ctx)
	if err != nil {
		return false
	}
	return result.Status == HealthStatusHealthy || result.Status == HealthStatusDegraded
}

// GetCapabilities implements LegacyProvider.
func (a *ProviderAdapter) GetCapabilities() []string {
	caps := a.provider.Capabilities()
	result := make([]string, len(caps))
	for i, cap := range caps {
		result[i] = string(cap)
	}
	return result
}

// EstimateCost implements LegacyProvider.
func (a *ProviderAdapter) EstimateCost(tokens int) float64 {
	req := CompletionRequest{
		Prompt: "", // Placeholder for estimation
	}
	// Use average input/output split
	estimate := a.provider.EstimateCost(req)
	if estimate == nil {
		return 0
	}
	// Calculate based on token count
	return (estimate.InputCostPer1K + estimate.OutputCostPer1K) * float64(tokens) / 1000 / 2
}

// Provider returns the underlying Provider.
func (a *ProviderAdapter) Provider() Provider {
	return a.provider
}

// LegacyAdapter adapts a LegacyProvider to the new Provider interface.
// This allows old providers to work with the new registry.
type LegacyAdapter struct {
	legacy       LegacyProvider
	providerType ProviderType
}

// NewLegacyAdapter creates an adapter from LegacyProvider to Provider.
func NewLegacyAdapter(legacy LegacyProvider, providerType ProviderType) *LegacyAdapter {
	return &LegacyAdapter{
		legacy:       legacy,
		providerType: providerType,
	}
}

// Name implements Provider.
func (a *LegacyAdapter) Name() string {
	return a.legacy.Name()
}

// Type implements Provider.
func (a *LegacyAdapter) Type() ProviderType {
	return a.providerType
}

// Complete implements Provider by delegating to LegacyProvider.Query.
func (a *LegacyAdapter) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	// Convert new request to legacy format
	options := LegacyQueryOptions{
		MaxTokens:    req.MaxTokens,
		Temperature:  req.Temperature,
		Model:        req.Model,
		SystemPrompt: req.SystemPrompt,
	}

	resp, err := a.legacy.Query(ctx, req.Prompt, options)
	if err != nil {
		return nil, err
	}

	// Convert legacy response to new format
	return &CompletionResponse{
		Content: resp.Content,
		Model:   resp.Model,
		Usage: UsageStats{
			TotalTokens: resp.TokensUsed,
			// Estimate split
			PromptTokens:     resp.TokensUsed / 3,
			CompletionTokens: resp.TokensUsed - resp.TokensUsed/3,
		},
		FinishReason: "stop",
	}, nil
}

// HealthCheck implements Provider.
func (a *LegacyAdapter) HealthCheck(ctx context.Context) (*HealthCheckResult, error) {
	// Check for context cancellation first
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	healthy := a.legacy.IsHealthy()
	status := HealthStatusUnhealthy
	if healthy {
		status = HealthStatusHealthy
	}

	return &HealthCheckResult{
		Status:      status,
		LastChecked: time.Now(),
	}, nil
}

// Capabilities implements Provider.
func (a *LegacyAdapter) Capabilities() []Capability {
	caps := a.legacy.GetCapabilities()
	result := make([]Capability, len(caps))
	for i, cap := range caps {
		result[i] = Capability(cap)
	}
	return result
}

// SupportsStreaming implements Provider.
func (a *LegacyAdapter) SupportsStreaming() bool {
	// Legacy providers don't support streaming through the standard interface
	return false
}

// EstimateCost implements Provider.
func (a *LegacyAdapter) EstimateCost(req CompletionRequest) *CostEstimate {
	// Estimate tokens from prompt length (minimum 1 to avoid division by zero)
	estimatedInputTokens := len(req.Prompt) / 4
	if estimatedInputTokens == 0 {
		estimatedInputTokens = 1
	}
	estimatedOutputTokens := req.MaxTokens
	if estimatedOutputTokens == 0 {
		estimatedOutputTokens = 1000
	}

	totalTokens := estimatedInputTokens + estimatedOutputTokens
	cost := a.legacy.EstimateCost(totalTokens)

	// Calculate per-1K costs (safe from division by zero since totalTokens >= 1)
	costPer1K := cost * 1000 / float64(totalTokens) / 2

	return &CostEstimate{
		InputCostPer1K:        costPer1K,
		OutputCostPer1K:       costPer1K,
		EstimatedInputTokens:  estimatedInputTokens,
		EstimatedOutputTokens: estimatedOutputTokens,
		TotalEstimate:         cost,
		Currency:              "USD",
	}
}

// Verify interface compliance at compile time.
var (
	_ LegacyProvider = (*ProviderAdapter)(nil)
	_ Provider       = (*LegacyAdapter)(nil)
)
