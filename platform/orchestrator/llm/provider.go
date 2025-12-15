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
)

// Provider is the unified interface for all LLM providers.
// Implementations must be safe for concurrent use.
//
// This interface unifies the previously separate OSS and Enterprise provider
// interfaces, enabling pluggable providers that work across both editions.
//
// Minimal implementation requires: Name(), Type(), Complete(), and HealthCheck().
// Optional methods can be implemented via type assertion for advanced features.
type Provider interface {
	// Name returns the unique identifier for this provider instance.
	// This is used for routing, logging, and metrics.
	// Example: "anthropic-primary", "openai-backup"
	Name() string

	// Type returns the provider type (e.g., "openai", "anthropic", "bedrock").
	// This identifies the underlying implementation.
	Type() ProviderType

	// Complete generates a completion for the given request.
	// This is the primary method for non-streaming LLM interactions.
	// The context should be used for cancellation and timeout.
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)

	// HealthCheck verifies the provider is operational.
	// Implementations should check API connectivity and authentication.
	// This method should complete within a reasonable timeout (e.g., 10s).
	HealthCheck(ctx context.Context) (*HealthCheckResult, error)

	// Capabilities returns the list of features this provider supports.
	// Used by the router to determine if a provider can handle a request.
	Capabilities() []Capability

	// SupportsStreaming indicates if the provider supports streaming responses.
	// If true, the provider should also implement StreamingProvider.
	SupportsStreaming() bool

	// EstimateCost provides a cost estimate for a given request.
	// Returns nil if cost estimation is not supported.
	EstimateCost(req CompletionRequest) *CostEstimate
}

// StreamingProvider extends Provider with streaming support.
// Providers that return SupportsStreaming() == true should implement this.
type StreamingProvider interface {
	Provider

	// CompleteStream generates a streaming completion.
	// The handler is called for each chunk received.
	// Returns the final aggregated response.
	CompleteStream(ctx context.Context, req CompletionRequest, handler StreamHandler) (*CompletionResponse, error)
}

// ConfigurableProvider extends Provider with runtime configuration.
// Implement this interface to allow providers to be reconfigured without restart.
type ConfigurableProvider interface {
	Provider

	// Configure updates the provider configuration.
	// This should be safe to call while the provider is in use.
	Configure(config ProviderConfig) error

	// GetConfig returns the current provider configuration.
	GetConfig() ProviderConfig
}

// ProviderConfig contains configuration for creating or updating a provider.
// This is the unified configuration format stored in the database.
type ProviderConfig struct {
	// Name is the unique identifier for this provider instance.
	Name string `json:"name"`

	// Type identifies the provider implementation to use.
	Type ProviderType `json:"type"`

	// APIKey is the authentication key for the provider API.
	// For AWS Bedrock, this may be empty (uses IAM).
	APIKey string `json:"api_key,omitempty"`

	// APIKeySecretARN is the AWS Secrets Manager ARN for the API key.
	// Used instead of APIKey for production deployments.
	APIKeySecretARN string `json:"api_key_secret_arn,omitempty"`

	// Endpoint is the API endpoint URL.
	// If empty, provider defaults are used.
	Endpoint string `json:"endpoint,omitempty"`

	// Model is the default model to use.
	Model string `json:"model,omitempty"`

	// Region is the cloud region (for AWS Bedrock).
	Region string `json:"region,omitempty"`

	// Enabled indicates if this provider is available for routing.
	Enabled bool `json:"enabled"`

	// Priority determines routing preference (higher = more preferred).
	Priority int `json:"priority,omitempty"`

	// Weight is used for weighted routing strategies.
	Weight int `json:"weight,omitempty"`

	// RateLimit is the max requests per minute (0 = unlimited).
	RateLimit int `json:"rate_limit,omitempty"`

	// TimeoutSeconds is the request timeout (0 = default).
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`

	// Settings contains provider-specific configuration.
	Settings map[string]any `json:"settings,omitempty"`
}

// ProviderWithInfo extends Provider with info retrieval.
type ProviderWithInfo interface {
	Provider

	// Info returns detailed information about the provider.
	Info() ProviderInfo
}

// Note: Compile-time interface compliance checks are in adapter.go
// (for adapters) and provider_test.go (for mock implementations).
