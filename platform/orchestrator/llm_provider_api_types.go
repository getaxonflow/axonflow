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

package orchestrator

import (
	"time"

	"axonflow/platform/orchestrator/llm"
)

// LLMProviderResource represents an LLM provider for the API.
type LLMProviderResource struct {
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Endpoint       string                 `json:"endpoint,omitempty"`
	Model          string                 `json:"model,omitempty"`
	Region         string                 `json:"region,omitempty"`
	Enabled        bool                   `json:"enabled"`
	Priority       int                    `json:"priority"`
	Weight         int                    `json:"weight"`
	RateLimit      int                    `json:"rate_limit,omitempty"`
	TimeoutSeconds int                    `json:"timeout_seconds,omitempty"`
	HasAPIKey      bool                   `json:"has_api_key"`
	Settings       map[string]interface{} `json:"settings,omitempty"`
	Health         *LLMProviderHealthInfo `json:"health,omitempty"`
}

// LLMProviderHealthInfo contains health information for a provider.
type LLMProviderHealthInfo struct {
	Status      string    `json:"status"`
	Message     string    `json:"message,omitempty"`
	LastChecked time.Time `json:"last_checked,omitempty"`
}

// CreateLLMProviderRequest for POST /api/v1/llm-providers.
type CreateLLMProviderRequest struct {
	Name            string                 `json:"name"`
	Type            string                 `json:"type"`
	APIKey          string                 `json:"api_key,omitempty"`
	APIKeySecretARN string                 `json:"api_key_secret_arn,omitempty"`
	Endpoint        string                 `json:"endpoint,omitempty"`
	Model           string                 `json:"model,omitempty"`
	Region          string                 `json:"region,omitempty"`
	Enabled         bool                   `json:"enabled"`
	Priority        int                    `json:"priority,omitempty"`
	Weight          int                    `json:"weight,omitempty"`
	RateLimit       int                    `json:"rate_limit,omitempty"`
	TimeoutSeconds  int                    `json:"timeout_seconds,omitempty"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
}

// UpdateLLMProviderRequest for PUT /api/v1/llm-providers/{name}.
type UpdateLLMProviderRequest struct {
	APIKey          *string                `json:"api_key,omitempty"`
	APIKeySecretARN *string                `json:"api_key_secret_arn,omitempty"`
	Endpoint        *string                `json:"endpoint,omitempty"`
	Model           *string                `json:"model,omitempty"`
	Region          *string                `json:"region,omitempty"`
	Enabled         *bool                  `json:"enabled,omitempty"`
	Priority        *int                   `json:"priority,omitempty"`
	Weight          *int                   `json:"weight,omitempty"`
	RateLimit       *int                   `json:"rate_limit,omitempty"`
	TimeoutSeconds  *int                   `json:"timeout_seconds,omitempty"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
}

// LLMProviderListParams for GET /api/v1/llm-providers query params.
type LLMProviderListParams struct {
	Type     llm.ProviderType `json:"type,omitempty"`
	Enabled  *bool            `json:"enabled,omitempty"`
	Page     int              `json:"page"`
	PageSize int              `json:"page_size"`
}

// LLMProviderResponse for single provider responses.
type LLMProviderResponse struct {
	Provider *LLMProviderResource `json:"provider"`
}

// LLMProviderListResponse for paginated list.
type LLMProviderListResponse struct {
	Providers  []LLMProviderResource `json:"providers"`
	Pagination PaginationMeta        `json:"pagination"`
}

// LLMProviderHealthResponse for single provider health check.
type LLMProviderHealthResponse struct {
	Name   string                 `json:"name"`
	Health *llm.HealthCheckResult `json:"health"`
}

// LLMProviderHealthAllResponse for all providers health check.
type LLMProviderHealthAllResponse struct {
	Providers map[string]*llm.HealthCheckResult `json:"providers"`
}

// LLMRoutingConfigResponse for routing configuration.
type LLMRoutingConfigResponse struct {
	Weights map[string]int `json:"weights"`
}

// UpdateLLMRoutingRequest for PUT /api/v1/llm-providers/routing.
type UpdateLLMRoutingRequest struct {
	Weights map[string]int `json:"weights"`
}

// LLMProviderAPIError for error responses.
type LLMProviderAPIError struct {
	Error LLMProviderAPIErrorDetail `json:"error"`
}

// LLMProviderAPIErrorDetail contains error details.
type LLMProviderAPIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
