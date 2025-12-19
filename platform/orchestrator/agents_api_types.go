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
)

// AgentResource represents an agent configuration for API responses.
// This provides a read-only view of agents registered in the system.
type AgentResource struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Domain      string           `json:"domain,omitempty"`
	Description string           `json:"description,omitempty"`
	Spec        *AgentConfigSpec `json:"spec,omitempty"`
	Version     int              `json:"version,omitempty"`
	IsActive    bool             `json:"is_active"`
	Source      string           `json:"source"` // "file" or "database"
	CreatedAt   *time.Time       `json:"created_at,omitempty"`
	UpdatedAt   *time.Time       `json:"updated_at,omitempty"`
}

// AgentListResponse for paginated list of agents (Community).
type AgentListResponse struct {
	Agents     []AgentResource       `json:"agents"`
	Pagination AgentPaginationMeta   `json:"pagination"`
}

// AgentPaginationMeta contains pagination metadata.
type AgentPaginationMeta struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// AgentResponse wraps a single agent for API responses.
type AgentResponse struct {
	Agent *AgentResource `json:"agent"`
}

// ListAgentsParams contains query parameters for listing agents.
type ListAgentsParams struct {
	Domain   string `json:"domain,omitempty"`
	IsActive *bool  `json:"is_active,omitempty"`
	Search   string `json:"search,omitempty"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

// ValidateAgentConfigRequest for POST /api/v1/agents/validate (Community).
type ValidateAgentConfigRequest struct {
	Config AgentConfigSpec `json:"config"`
	Domain string          `json:"domain,omitempty"`
	Name   string          `json:"name,omitempty"`
}

// ValidateAgentConfigResponse contains validation results.
type ValidateAgentConfigResponse struct {
	Valid   bool                     `json:"valid"`
	Errors  []AgentValidationError   `json:"errors,omitempty"`
	Summary string                   `json:"summary,omitempty"`
}

// AgentValidationError represents a single validation error.
type AgentValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// AgentAPIError for API errors.
type AgentAPIError struct {
	Error AgentAPIErrorDetail `json:"error"`
}

// AgentAPIErrorDetail contains error information.
type AgentAPIErrorDetail struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details []AgentValidationError `json:"details,omitempty"`
}

// AgentsServicer defines the interface for agent read operations (Community).
// This is a subset of the full enterprise service, providing read-only access.
type AgentsServicer interface {
	// ListAgents returns agents from the registry with optional filtering
	ListAgents(domain string, isActive *bool, page, pageSize int) (*AgentListResponse, error)

	// GetAgent returns a single agent by ID
	GetAgent(agentID string) (*AgentResource, error)

	// GetAgentByName returns an agent by domain and name
	GetAgentByName(domain, name string) (*AgentResource, error)

	// ValidateAgentConfig validates an agent configuration without persisting
	ValidateAgentConfig(req *ValidateAgentConfigRequest) (*ValidateAgentConfigResponse, error)
}

// Default pagination values for agents API
const (
	DefaultAgentPage     = 1
	DefaultAgentPageSize = 20
	MaxAgentPageSize     = 100
)

// FromAgentConfigFile creates an AgentResource from an AgentConfigFile.
func FromAgentConfigFile(config *AgentConfigFile, source string) *AgentResource {
	if config == nil {
		return nil
	}

	return &AgentResource{
		ID:          config.Metadata.Name, // Use name as ID for file-based configs
		Name:        config.Metadata.Name,
		Domain:      config.Metadata.Domain,
		Description: config.Metadata.Description,
		Spec:        &config.Spec,
		IsActive:    true, // File-based configs are always active
		Source:      source,
	}
}
