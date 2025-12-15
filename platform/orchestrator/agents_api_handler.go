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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// AgentsAPIHandler handles HTTP requests for agent management (OSS read-only endpoints).
// This handler provides read access to agents registered in the AgentRegistry.
type AgentsAPIHandler struct {
	registry *AgentRegistry
}

// NewAgentsAPIHandler creates a new agents API handler.
func NewAgentsAPIHandler(registry *AgentRegistry) *AgentsAPIHandler {
	return &AgentsAPIHandler{registry: registry}
}

// RegisterRoutes registers agent API routes with the provided mux.
// OSS Distribution: Read-only endpoints
//   - GET /api/v1/agents - List all agents
//   - GET /api/v1/agents/{id} - Get agent by ID
//   - GET /api/v1/agents/domain/{domain} - List agents by domain
//   - POST /api/v1/agents/validate - Validate agent configuration
func (h *AgentsAPIHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/agents", h.handleAgents)
	mux.HandleFunc("/api/v1/agents/", h.handleAgentByID)
	mux.HandleFunc("/api/v1/agents/validate", h.handleValidate)
	mux.HandleFunc("/api/v1/agents/domain/", h.handleAgentsByDomain)
}

// handleAgents handles GET /api/v1/agents
func (h *AgentsAPIHandler) handleAgents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAgents(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleAgentByID handles GET /api/v1/agents/{id}
func (h *AgentsAPIHandler) handleAgentByID(w http.ResponseWriter, r *http.Request) {
	// Skip handling for sub-paths handled by other handlers.
	// These paths are registered separately and will be handled by their own handlers.
	// We return early to avoid double-handling (the other handler will respond).
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	if strings.HasPrefix(path, "domain/") || path == "validate" {
		// Let the more specific handler handle this request
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.getAgent(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleAgentsByDomain handles GET /api/v1/agents/domain/{domain}
func (h *AgentsAPIHandler) handleAgentsByDomain(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.listAgentsByDomain(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleValidate handles POST /api/v1/agents/validate
func (h *AgentsAPIHandler) handleValidate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.validateConfig(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// listAgents handles GET /api/v1/agents
func (h *AgentsAPIHandler) listAgents(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	params := h.parseListParams(r)

	// Get all agents from registry
	agents := h.getAgentsFromRegistry(params.Domain, params.IsActive)

	// Apply pagination
	total := len(agents)
	start := (params.Page - 1) * params.PageSize
	end := start + params.PageSize

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginatedAgents := agents[start:end]

	// Safely calculate total pages (guard against division by zero)
	totalPages := 0
	if params.PageSize > 0 {
		totalPages = total / params.PageSize
		if total%params.PageSize > 0 {
			totalPages++
		}
	}

	response := AgentListResponse{
		Agents: paginatedAgents,
		Pagination: AgentPaginationMeta{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: total,
			TotalPages: totalPages,
		},
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getAgent handles GET /api/v1/agents/{id}
func (h *AgentsAPIHandler) getAgent(w http.ResponseWriter, r *http.Request) {
	// Extract agent ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Agent ID is required")
		return
	}

	agentID := parts[0]

	// Try to find agent by qualified name (domain/name) or simple name
	agent, err := h.registry.GetAgent(agentID)
	if err != nil {
		// Try to find by searching through all agents
		agent = h.findAgentByID(agentID)
		if agent == nil {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Agent not found")
			return
		}
	}

	// Find the domain for this agent
	domain := h.findDomainForAgent(agent.Name)

	// Use qualified ID (domain/name) for consistency with list endpoint
	agentQualifiedID := agent.Name
	if domain != "" {
		agentQualifiedID = fmt.Sprintf("%s/%s", domain, agent.Name)
	}

	resource := &AgentResource{
		ID:          agentQualifiedID,
		Name:        agent.Name,
		Domain:      domain,
		Description: agent.Description,
		IsActive:    true,
		Source:      "file",
	}

	h.writeJSON(w, http.StatusOK, AgentResponse{Agent: resource})
}

// listAgentsByDomain handles GET /api/v1/agents/domain/{domain}
func (h *AgentsAPIHandler) listAgentsByDomain(w http.ResponseWriter, r *http.Request) {
	// Extract domain from path
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/agents/domain/")
	if path == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Domain is required")
		return
	}

	domain := strings.Split(path, "/")[0]

	// Get config for domain
	config, err := h.registry.GetConfig(domain)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	// Convert to resources with qualified IDs (domain/name) for consistency
	agents := make([]AgentResource, 0, len(config.Spec.Agents))
	for _, agent := range config.Spec.Agents {
		agents = append(agents, AgentResource{
			ID:          fmt.Sprintf("%s/%s", domain, agent.Name),
			Name:        agent.Name,
			Domain:      domain,
			Description: agent.Description,
			IsActive:    true,
			Source:      "file",
		})
	}

	response := AgentListResponse{
		Agents: agents,
		Pagination: AgentPaginationMeta{
			Page:       1,
			PageSize:   len(agents),
			TotalItems: len(agents),
			TotalPages: 1,
		},
	}

	h.writeJSON(w, http.StatusOK, response)
}

// validateConfig handles POST /api/v1/agents/validate
func (h *AgentsAPIHandler) validateConfig(w http.ResponseWriter, r *http.Request) {
	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	var req ValidateAgentConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	response := h.performValidation(&req)
	h.writeJSON(w, http.StatusOK, response)
}

// performValidation validates an agent configuration.
func (h *AgentsAPIHandler) performValidation(req *ValidateAgentConfigRequest) *ValidateAgentConfigResponse {
	response := &ValidateAgentConfigResponse{
		Valid:  true,
		Errors: []AgentValidationError{},
	}

	// Validate name if provided
	if req.Name != "" && !isValidAgentIdentifier(req.Name) {
		response.Valid = false
		response.Errors = append(response.Errors, AgentValidationError{
			Field:   "name",
			Message: "must be lowercase alphanumeric with hyphens and underscores",
		})
	}

	// Validate domain if provided
	if req.Domain != "" && !isValidAgentIdentifier(req.Domain) {
		response.Valid = false
		response.Errors = append(response.Errors, AgentValidationError{
			Field:   "domain",
			Message: "must be lowercase alphanumeric with hyphens and underscores",
		})
	}

	// Validate config spec
	specErrors := h.validateConfigSpec(&req.Config)
	if len(specErrors) > 0 {
		response.Valid = false
		response.Errors = append(response.Errors, specErrors...)
	}

	if response.Valid {
		response.Summary = "Configuration is valid"
	} else {
		response.Summary = fmt.Sprintf("Found %d validation error(s)", len(response.Errors))
	}

	return response
}

// validateConfigSpec validates an AgentConfigSpec.
func (h *AgentsAPIHandler) validateConfigSpec(spec *AgentConfigSpec) []AgentValidationError {
	var errors []AgentValidationError

	// Validate execution config
	if spec.Execution.DefaultMode != "" && !ValidExecutionModes[spec.Execution.DefaultMode] {
		errors = append(errors, AgentValidationError{
			Field:   "config.execution.default_mode",
			Message: "must be one of: sequential, parallel, auto",
		})
	}

	if spec.Execution.MaxParallelTasks < 0 {
		errors = append(errors, AgentValidationError{
			Field:   "config.execution.max_parallel_tasks",
			Message: "cannot be negative",
		})
	}

	if spec.Execution.TimeoutSeconds < 0 {
		errors = append(errors, AgentValidationError{
			Field:   "config.execution.timeout_seconds",
			Message: "cannot be negative",
		})
	}

	// Validate agents
	if len(spec.Agents) == 0 {
		errors = append(errors, AgentValidationError{
			Field:   "config.agents",
			Message: "at least one agent is required",
		})
	}

	agentNames := make(map[string]bool)
	for i, agent := range spec.Agents {
		prefix := fmt.Sprintf("config.agents[%d]", i)

		if agent.Name == "" {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".name",
				Message: "name is required",
			})
		} else {
			if agentNames[agent.Name] {
				errors = append(errors, AgentValidationError{
					Field:   prefix + ".name",
					Message: fmt.Sprintf("duplicate agent name: %s", agent.Name),
				})
			}
			agentNames[agent.Name] = true

			if !isValidAgentIdentifier(agent.Name) {
				errors = append(errors, AgentValidationError{
					Field:   prefix + ".name",
					Message: "must be lowercase alphanumeric with hyphens and underscores",
				})
			}
		}

		if agent.Type == "" {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".type",
				Message: "type is required",
			})
		} else if !ValidAgentTypes[agent.Type] {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".type",
				Message: "must be one of: llm-call, connector-call",
			})
		}

		// Type-specific validation
		if agent.Type == "llm-call" {
			if agent.LLM == nil && agent.PromptTemplate == "" {
				errors = append(errors, AgentValidationError{
					Field:   prefix,
					Message: "llm-call requires llm config or prompt_template",
				})
			}
			if agent.LLM != nil {
				if agent.LLM.Provider == "" {
					errors = append(errors, AgentValidationError{
						Field:   prefix + ".llm.provider",
						Message: "provider is required",
					})
				}
				if agent.LLM.Model == "" {
					errors = append(errors, AgentValidationError{
						Field:   prefix + ".llm.model",
						Message: "model is required",
					})
				}
				if agent.LLM.Temperature < 0 || agent.LLM.Temperature > MaxLLMTemperature {
					errors = append(errors, AgentValidationError{
						Field:   prefix + ".llm.temperature",
						Message: fmt.Sprintf("must be between 0 and %.1f", MaxLLMTemperature),
					})
				}
			}
		}

		if agent.Type == "connector-call" {
			if agent.Connector == nil {
				errors = append(errors, AgentValidationError{
					Field:   prefix,
					Message: "connector-call requires connector config",
				})
			} else {
				if agent.Connector.Name == "" {
					errors = append(errors, AgentValidationError{
						Field:   prefix + ".connector.name",
						Message: "connector name is required",
					})
				}
				if agent.Connector.Operation == "" {
					errors = append(errors, AgentValidationError{
						Field:   prefix + ".connector.operation",
						Message: "connector operation is required",
					})
				}
			}
		}
	}

	// Validate routing rules
	for i, rule := range spec.Routing {
		prefix := fmt.Sprintf("config.routing[%d]", i)

		if rule.Pattern == "" {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".pattern",
				Message: "pattern is required",
			})
		} else {
			if len(rule.Pattern) > MaxPatternLength {
				errors = append(errors, AgentValidationError{
					Field:   prefix + ".pattern",
					Message: fmt.Sprintf("pattern too long (max %d characters)", MaxPatternLength),
				})
			}
			// Try to compile regex
			if _, err := regexp.Compile(rule.Pattern); err != nil {
				errors = append(errors, AgentValidationError{
					Field:   prefix + ".pattern",
					Message: fmt.Sprintf("invalid regex pattern: %v", err),
				})
			}
		}

		if rule.Agent == "" {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".agent",
				Message: "agent is required",
			})
		} else if !agentNames[rule.Agent] {
			errors = append(errors, AgentValidationError{
				Field:   prefix + ".agent",
				Message: fmt.Sprintf("agent '%s' not found in agents list", rule.Agent),
			})
		}
	}

	return errors
}

// getAgentsFromRegistry retrieves agents from the registry with optional filtering.
func (h *AgentsAPIHandler) getAgentsFromRegistry(domain string, isActive *bool) []AgentResource {
	var agents []AgentResource

	if domain != "" {
		// Get agents for specific domain
		config, err := h.registry.GetConfig(domain)
		if err != nil {
			return agents
		}
		for _, agent := range config.Spec.Agents {
			agents = append(agents, AgentResource{
				ID:          fmt.Sprintf("%s/%s", domain, agent.Name),
				Name:        agent.Name,
				Domain:      domain,
				Description: agent.Description,
				IsActive:    true,
				Source:      "file",
			})
		}
	} else {
		// Get all agents from all domains
		domains := h.registry.ListDomains()
		for _, d := range domains {
			config, err := h.registry.GetConfig(d)
			if err != nil {
				continue
			}
			for _, agent := range config.Spec.Agents {
				agents = append(agents, AgentResource{
					ID:          fmt.Sprintf("%s/%s", d, agent.Name),
					Name:        agent.Name,
					Domain:      d,
					Description: agent.Description,
					IsActive:    true,
					Source:      "file",
				})
			}
		}
	}

	// Filter by isActive if specified
	if isActive != nil {
		filtered := make([]AgentResource, 0)
		for _, a := range agents {
			if a.IsActive == *isActive {
				filtered = append(filtered, a)
			}
		}
		return filtered
	}

	return agents
}

// findAgentByID searches for an agent by ID across all domains.
func (h *AgentsAPIHandler) findAgentByID(agentID string) *AgentDef {
	domains := h.registry.ListDomains()
	for _, domain := range domains {
		config, err := h.registry.GetConfig(domain)
		if err != nil {
			continue
		}
		for i := range config.Spec.Agents {
			agent := &config.Spec.Agents[i]
			if agent.Name == agentID {
				return agent
			}
		}
	}
	return nil
}

// findDomainForAgent finds the domain that contains the given agent.
func (h *AgentsAPIHandler) findDomainForAgent(agentName string) string {
	domains := h.registry.ListDomains()
	for _, domain := range domains {
		config, err := h.registry.GetConfig(domain)
		if err != nil {
			continue
		}
		for _, agent := range config.Spec.Agents {
			if agent.Name == agentName {
				return domain
			}
		}
	}
	return ""
}

// parseListParams extracts list parameters from the request.
func (h *AgentsAPIHandler) parseListParams(r *http.Request) ListAgentsParams {
	params := ListAgentsParams{
		Domain:   r.URL.Query().Get("domain"),
		Page:     DefaultAgentPage,
		PageSize: DefaultAgentPageSize,
	}

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			params.Page = page
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 && pageSize <= MaxAgentPageSize {
			params.PageSize = pageSize
		}
	}

	if activeStr := r.URL.Query().Get("is_active"); activeStr != "" {
		isActive := activeStr == "true"
		params.IsActive = &isActive
	}

	return params
}

// handleCORS sets CORS headers for OPTIONS requests.
func (h *AgentsAPIHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response.
func (h *AgentsAPIHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[AgentsAPI] Failed to encode response: %v", err)
	}
}

// writeError writes an error response.
func (h *AgentsAPIHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, AgentAPIError{
		Error: AgentAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// isValidAgentIdentifier checks if a string is a valid identifier.
func isValidAgentIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c >= 'a' && c <= 'z' {
			continue
		}
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '-' || c == '_' {
			if i == 0 {
				return false
			}
			continue
		}
		return false
	}
	return true
}
