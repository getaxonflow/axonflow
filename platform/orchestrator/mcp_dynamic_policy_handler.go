// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// MCPDynamicPolicyHandler handles dynamic policy evaluation requests from MCP Agent.
// This is the Orchestrator endpoint that the Agent calls for Issue #968.
//
// Endpoint: POST /api/v1/mcp/evaluate-policies
type MCPDynamicPolicyHandler struct {
	policyEngine *DynamicPolicyEngine
}

// NewMCPDynamicPolicyHandler creates a new MCP dynamic policy handler.
func NewMCPDynamicPolicyHandler(engine *DynamicPolicyEngine) *MCPDynamicPolicyHandler {
	return &MCPDynamicPolicyHandler{
		policyEngine: engine,
	}
}

// RegisterRoutes registers MCP dynamic policy routes.
func (h *MCPDynamicPolicyHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/mcp/evaluate-policies", h.handleEvaluatePolicies).Methods("POST", "OPTIONS")
	log.Println("[MCPDynamicPolicy] Routes registered for /api/v1/mcp/evaluate-policies")
}

// MCPPolicyEvaluationRequest matches the DynamicPolicyRequest from shared/policy.
type MCPPolicyEvaluationRequest struct {
	TenantID       string                 `json:"tenant_id"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	UserID         string                 `json:"user_id"`
	UserRole       string                 `json:"user_role,omitempty"`
	ConnectorName  string                 `json:"connector_name"`
	Operation      string                 `json:"operation"`
	Statement      string                 `json:"statement"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	RequestTime    time.Time              `json:"request_time"`
	ClientIP       string                 `json:"client_ip,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// MCPPolicyEvaluationResponse matches the DynamicPolicyResponse from shared/policy.
type MCPPolicyEvaluationResponse struct {
	Allowed           bool                       `json:"allowed"`
	BlockReason       string                     `json:"block_reason,omitempty"`
	PoliciesEvaluated int                        `json:"policies_evaluated"`
	MatchedPolicies   []MCPDynamicPolicyMatch    `json:"matched_policies,omitempty"`
	ProcessingTimeMs  int64                      `json:"processing_time_ms"`
	Metadata          map[string]interface{}     `json:"metadata,omitempty"`
}

// MCPDynamicPolicyMatch represents a matched dynamic policy.
type MCPDynamicPolicyMatch struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"`
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
}

// handleEvaluatePolicies evaluates dynamic policies for an MCP request.
// POST /api/v1/mcp/evaluate-policies
func (h *MCPDynamicPolicyHandler) handleEvaluatePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	startTime := time.Now()

	// Parse request
	var req MCPPolicyEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// Validate required fields
	if req.TenantID == "" {
		h.writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}
	if req.ConnectorName == "" {
		h.writeError(w, http.StatusBadRequest, "connector_name is required")
		return
	}

	// Get applicable dynamic policies for this tenant/connector
	policies, err := h.getPoliciesForMCP(req)
	if err != nil {
		log.Printf("[MCPDynamicPolicy] Error loading policies: %v", err)
		h.writeError(w, http.StatusInternalServerError, "Failed to load policies")
		return
	}

	// Evaluate each policy
	response := MCPPolicyEvaluationResponse{
		Allowed:           true,
		PoliciesEvaluated: len(policies),
		MatchedPolicies:   []MCPDynamicPolicyMatch{},
	}

	for _, policy := range policies {
		match, allowed, reason := h.evaluatePolicy(policy, req)
		if match {
			actionType := ""
			if len(policy.Actions) > 0 {
				actionType = policy.Actions[0].Type
			}
			response.MatchedPolicies = append(response.MatchedPolicies, MCPDynamicPolicyMatch{
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				PolicyType: policy.Type,
				Action:     actionType,
				Reason:     reason,
			})

			if !allowed {
				response.Allowed = false
				response.BlockReason = reason
				break // Stop on first blocking policy
			}
		}
	}

	response.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)

	log.Printf("[MCPDynamicPolicy] Evaluated %d policies for connector=%s, allowed=%v, time=%dms",
		response.PoliciesEvaluated, req.ConnectorName, response.Allowed, response.ProcessingTimeMs)
}

// getPoliciesForMCP retrieves applicable dynamic policies for the MCP request.
func (h *MCPDynamicPolicyHandler) getPoliciesForMCP(req MCPPolicyEvaluationRequest) ([]DynamicPolicy, error) {
	if h.policyEngine == nil {
		return []DynamicPolicy{}, nil
	}

	// Get dynamic policies for this tenant
	policies := h.policyEngine.ListActivePolicies()

	// Filter by tenant
	var filtered []DynamicPolicy
	for _, p := range policies {
		// Match tenant (empty tenant means global)
		if p.TenantID != "" && p.TenantID != req.TenantID {
			continue
		}
		// Only include enabled policies
		if !p.Enabled {
			continue
		}
		// Only include policies with MCP-related types
		if p.Type == "mcp" || p.Type == "connector" || p.Type == "rate-limit" ||
			p.Type == "budget" || p.Type == "time-access" || p.Type == "role-access" {
			filtered = append(filtered, p)
		}
	}

	return filtered, nil
}

// evaluatePolicy evaluates a single policy against the request.
// Returns (matched, allowed, reason).
func (h *MCPDynamicPolicyHandler) evaluatePolicy(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Check policy type and evaluate accordingly
	switch policy.Type {
	case "rate-limit":
		return h.evaluateRateLimit(policy, req)
	case "budget":
		return h.evaluateBudget(policy, req)
	case "time-access":
		return h.evaluateTimeAccess(policy, req)
	case "role-access":
		return h.evaluateRoleAccess(policy, req)
	case "mcp", "connector":
		return h.evaluateConditions(policy, req)
	default:
		// Unknown policy type, skip
		return false, true, ""
	}
}

// evaluateConditions evaluates policy conditions.
func (h *MCPDynamicPolicyHandler) evaluateConditions(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	for _, cond := range policy.Conditions {
		if !h.evaluateCondition(cond, req) {
			return false, true, ""
		}
	}
	// All conditions matched, check action
	for _, action := range policy.Actions {
		if action.Type == "block" {
			reason := "Policy blocked request"
			if action.Config != nil {
				if r, ok := action.Config["reason"].(string); ok {
					reason = r
				}
			}
			return true, false, reason
		}
	}
	return true, true, ""
}

// evaluateCondition evaluates a single condition.
func (h *MCPDynamicPolicyHandler) evaluateCondition(cond PolicyCondition, req MCPPolicyEvaluationRequest) bool {
	var fieldValue interface{}

	switch cond.Field {
	case "connector":
		fieldValue = req.ConnectorName
	case "operation":
		fieldValue = req.Operation
	case "user.role":
		fieldValue = req.UserRole
	case "tenant_id":
		fieldValue = req.TenantID
	default:
		return false
	}

	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", cond.Value)
	case "not_equals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", cond.Value))
	default:
		return false
	}
}

// evaluateRateLimit checks rate limiting policies.
func (h *MCPDynamicPolicyHandler) evaluateRateLimit(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Rate limiting would check against a counter in Redis/DB
	// For MVP, we'll implement basic support
	// TODO: Implement actual rate limiting with counters
	return true, true, ""
}

// evaluateBudget checks budget/cost control policies.
func (h *MCPDynamicPolicyHandler) evaluateBudget(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Budget checks would verify against cost tracking
	// For MVP, we'll implement basic support
	// TODO: Implement actual budget tracking
	return true, true, ""
}

// evaluateTimeAccess checks time-based access policies.
func (h *MCPDynamicPolicyHandler) evaluateTimeAccess(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	now := time.Now()
	if req.RequestTime.IsZero() {
		req.RequestTime = now
	}

	// Check conditions for time-based policies
	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "hour":
			currentHour := now.Hour()
			if cond.Operator == "greater_than" {
				if limit, ok := cond.Value.(float64); ok {
					if currentHour <= int(limit) {
						return true, false, "Access denied: Outside allowed hours"
					}
				}
			}
			if cond.Operator == "less_than" {
				if limit, ok := cond.Value.(float64); ok {
					if currentHour >= int(limit) {
						return true, false, "Access denied: Outside allowed hours"
					}
				}
			}
		case "day":
			currentDay := now.Weekday().String()
			if cond.Operator == "in" {
				if days, ok := cond.Value.([]interface{}); ok {
					found := false
					for _, day := range days {
						if day == currentDay {
							found = true
							break
						}
					}
					if !found {
						return true, false, "Access denied: Outside allowed days"
					}
				}
			}
		}
	}

	return true, true, ""
}

// evaluateRoleAccess checks role-based access policies.
func (h *MCPDynamicPolicyHandler) evaluateRoleAccess(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	for _, cond := range policy.Conditions {
		if cond.Field == "user.role" {
			switch cond.Operator {
			case "in":
				// Check if user role is in allowed list
				if roles, ok := cond.Value.([]interface{}); ok {
					found := false
					for _, role := range roles {
						if role == req.UserRole || role == "*" {
							found = true
							break
						}
					}
					if !found {
						return true, false, "Access denied: Insufficient role permissions"
					}
				}
			case "not_in":
				// Check if user role is in denied list
				if roles, ok := cond.Value.([]interface{}); ok {
					for _, role := range roles {
						if role == req.UserRole {
							return true, false, "Access denied: Role explicitly blocked"
						}
					}
				}
			case "equals":
				if cond.Value != req.UserRole {
					return true, false, "Access denied: Role mismatch"
				}
			}
		}
	}

	return true, true, ""
}

// handleCORS sets CORS headers.
func (h *MCPDynamicPolicyHandler) handleCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// writeError writes an error response.
func (h *MCPDynamicPolicyHandler) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// Global MCP dynamic policy handler
var globalMCPDynamicPolicyHandler *MCPDynamicPolicyHandler

// InitMCPDynamicPolicyHandler initializes the global handler.
func InitMCPDynamicPolicyHandler(engine *DynamicPolicyEngine) {
	globalMCPDynamicPolicyHandler = NewMCPDynamicPolicyHandler(engine)
}

// GetMCPDynamicPolicyHandler returns the global handler.
func GetMCPDynamicPolicyHandler() *MCPDynamicPolicyHandler {
	return globalMCPDynamicPolicyHandler
}
