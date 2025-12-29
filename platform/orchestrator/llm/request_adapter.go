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
	"time"
)

// RequestContext contains contextual information from an orchestrator request.
// This is used to pass through metadata that the new router needs to process.
type RequestContext struct {
	// Query is the user's query text
	Query string

	// RequestType identifies the type of request (e.g., "trip-planning", "mcp-query")
	RequestType string

	// UserRole is the role of the user making the request
	UserRole string

	// UserPermissions are the permissions of the user
	UserPermissions []string

	// ClientID identifies the client making the request
	ClientID string

	// OrgID is the organization ID for usage tracking
	OrgID string

	// TenantID identifies the tenant
	TenantID string

	// Provider is the explicitly requested provider name (if any)
	Provider string

	// Model is the explicitly requested model (if any)
	Model string

	// MaxTokens limits the response tokens
	MaxTokens int

	// Temperature controls randomness
	Temperature float64

	// SystemPrompt provides context for the LLM
	SystemPrompt string

	// AllowLocal indicates if local/ollama providers are acceptable
	AllowLocal bool

	// Metadata contains additional request-specific data
	Metadata map[string]any
}

// LegacyProviderInfo represents the legacy ProviderInfo format from run.go.
// This is used for backward compatibility with existing code that expects
// the old provider info format.
type LegacyProviderInfo struct {
	Provider       string  `json:"provider"`
	Model          string  `json:"model"`
	ResponseTimeMs int64   `json:"response_time_ms"`
	TokensUsed     int     `json:"tokens_used,omitempty"`
	Cost           float64 `json:"cost,omitempty"`
}

// LegacyLLMResponse represents the old LLMResponse format from llm_router.go.
// This maintains backward compatibility with existing consumers.
type LegacyLLMResponse struct {
	Content      string         `json:"content"`
	Model        string         `json:"model"`
	TokensUsed   int            `json:"tokens_used"`
	Metadata     map[string]any `json:"metadata"`
	ResponseTime time.Duration  `json:"response_time"`
}

// RequestContextToCompletionRequest converts RequestContext to CompletionRequest.
// This is the primary adapter for converting orchestrator requests to the new format.
func RequestContextToCompletionRequest(ctx RequestContext) CompletionRequest {
	// Build system prompt if not provided
	systemPrompt := ctx.SystemPrompt
	if systemPrompt == "" {
		systemPrompt = buildDefaultSystemPrompt(ctx)
	}

	return CompletionRequest{
		Prompt:       ctx.Query,
		SystemPrompt: systemPrompt,
		MaxTokens:    ctx.MaxTokens,
		Temperature:  ctx.Temperature,
		Model:        ctx.Model,
		Metadata: map[string]any{
			"request_type": ctx.RequestType,
			"user_role":    ctx.UserRole,
			"client_id":    ctx.ClientID,
			"org_id":       ctx.OrgID,
			"tenant_id":    ctx.TenantID,
		},
	}
}

// buildDefaultSystemPrompt creates a default system prompt based on context.
func buildDefaultSystemPrompt(ctx RequestContext) string {
	if ctx.UserRole != "" {
		return "You are an AI assistant. User Role: " + ctx.UserRole
	}
	return "You are an AI assistant helping with user queries."
}

// CompletionResponseToLegacyResponse converts CompletionResponse to LegacyLLMResponse.
func CompletionResponseToLegacyResponse(resp *CompletionResponse) *LegacyLLMResponse {
	if resp == nil {
		return nil
	}

	return &LegacyLLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.Usage.TotalTokens,
		ResponseTime: resp.Latency,
		Metadata: map[string]any{
			"prompt_tokens":     resp.Usage.PromptTokens,
			"completion_tokens": resp.Usage.CompletionTokens,
			"finish_reason":     resp.FinishReason,
		},
	}
}

// LegacyResponseToCompletionResponse converts LegacyLLMResponse to CompletionResponse.
func LegacyResponseToCompletionResponse(resp *LegacyLLMResponse) *CompletionResponse {
	if resp == nil {
		return nil
	}

	// Try to extract token breakdown from metadata
	promptTokens := resp.TokensUsed / 3 // Default estimate
	completionTokens := resp.TokensUsed - promptTokens

	if resp.Metadata != nil {
		if pt, ok := resp.Metadata["prompt_tokens"].(int); ok {
			promptTokens = pt
		}
		if ct, ok := resp.Metadata["completion_tokens"].(int); ok {
			completionTokens = ct
		}
	}

	finishReason := "stop"
	if resp.Metadata != nil {
		if fr, ok := resp.Metadata["finish_reason"].(string); ok && fr != "" {
			finishReason = fr
		}
	}

	return &CompletionResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		Latency:      resp.ResponseTime,
		FinishReason: finishReason,
		Usage: UsageStats{
			PromptTokens:     promptTokens,
			CompletionTokens: completionTokens,
			TotalTokens:      resp.TokensUsed,
		},
		Metadata: resp.Metadata,
	}
}

// RouteInfoToLegacyProviderInfo converts RouteInfo to LegacyProviderInfo.
func RouteInfoToLegacyProviderInfo(info *RouteInfo) *LegacyProviderInfo {
	if info == nil {
		return nil
	}

	return &LegacyProviderInfo{
		Provider:       info.ProviderName,
		Model:          info.Model,
		ResponseTimeMs: info.ResponseTimeMs,
		TokensUsed:     info.TokensUsed,
		Cost:           info.EstimatedCost,
	}
}

// LegacyProviderInfoToRouteInfo converts LegacyProviderInfo to RouteInfo.
func LegacyProviderInfoToRouteInfo(info *LegacyProviderInfo, providerType ProviderType) *RouteInfo {
	if info == nil {
		return nil
	}

	return &RouteInfo{
		ProviderName:   info.Provider,
		ProviderType:   providerType,
		Model:          info.Model,
		ResponseTimeMs: info.ResponseTimeMs,
		TokensUsed:     info.TokensUsed,
		EstimatedCost:  info.Cost,
	}
}

// ExtractProviderType infers the ProviderType from a provider name.
func ExtractProviderType(providerName string) ProviderType {
	switch providerName {
	case "openai":
		return ProviderTypeOpenAI
	case "anthropic":
		return ProviderTypeAnthropic
	case "bedrock":
		return ProviderTypeBedrock
	case "ollama", "local":
		return ProviderTypeOllama
	case "gemini":
		return ProviderTypeGemini
	default:
		return ProviderTypeCustom
	}
}
