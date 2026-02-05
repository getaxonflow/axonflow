// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"

	"axonflow/platform/orchestrator/llm"
)

func strictProviderDefaultFromEnv() bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv("LLM_STRICT_PROVIDER_DEFAULT")))
	if raw == "" {
		return false
	}

	switch raw {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			log.Printf("[LLM_ADAPTER] Ignoring invalid LLM_STRICT_PROVIDER_DEFAULT value %q (expected true/false)", raw)
			return false
		}
		return parsed
	}
}

func parseStrictProviderFlag(ctx map[string]interface{}) (bool, bool) {
	if ctx == nil {
		return false, false
	}

	raw, ok := ctx["strict_provider"]
	if !ok {
		return false, false
	}

	switch v := raw.(type) {
	case bool:
		return v, true
	case string:
		normalized := strings.TrimSpace(strings.ToLower(v))
		switch normalized {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		default:
			log.Printf("[LLM_ADAPTER] Ignoring invalid context.strict_provider value %q (expected boolean)", v)
			return false, false
		}
	default:
		log.Printf("[LLM_ADAPTER] Ignoring non-boolean context.strict_provider value of type %T", raw)
		return false, false
	}
}

// LLMRouterInterface defines the interface for LLM routing that components
// like PlanningEngine, ResultAggregator, and WorkflowEngine depend on.
// This enables migration from the legacy LLMRouter to UnifiedRouter.
type LLMRouterInterface interface {
	// RouteRequest routes an LLM request and returns the response.
	RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error)

	// IsHealthy returns whether the router has at least one healthy provider.
	IsHealthy() bool

	// GetProviderStatus returns the status of all providers.
	GetProviderStatus() map[string]ProviderStatus

	// UpdateProviderWeights updates the routing weights for providers.
	UpdateProviderWeights(weights map[string]float64) error
}

// Note: Compile-time verification for legacy LLMRouter removed in v2.3.0.
// UnifiedRouterWrapper is now the only implementation of LLMRouterInterface.
var _ LLMRouterInterface = (*UnifiedRouterWrapper)(nil)

// UnifiedRouterWrapper wraps llm.UnifiedRouter to implement LLMRouterInterface.
// This enables the UnifiedRouter to be used as a drop-in replacement for LLMRouter.
type UnifiedRouterWrapper struct {
	router *llm.UnifiedRouter
}

// NewUnifiedRouterWrapper creates a new wrapper around UnifiedRouter.
func NewUnifiedRouterWrapper(router *llm.UnifiedRouter) *UnifiedRouterWrapper {
	return &UnifiedRouterWrapper{router: router}
}

// RouteRequest implements LLMRouterInterface.
func (w *UnifiedRouterWrapper) RouteRequest(ctx context.Context, req OrchestratorRequest) (*LLMResponse, *ProviderInfo, error) {
	// Convert orchestrator request to LLM request context
	reqCtx := OrchestratorRequestToLLMContext(req)

	// Route through unified router
	legacyResp, legacyInfo, err := w.router.RouteRequest(ctx, reqCtx)
	if err != nil {
		return nil, nil, err
	}

	// Convert back to orchestrator types
	return LegacyResponseToLLMResponse(legacyResp), LegacyProviderInfoToProviderInfo(legacyInfo), nil
}

// IsHealthy implements LLMRouterInterface.
func (w *UnifiedRouterWrapper) IsHealthy() bool {
	return w.router.IsHealthy()
}

// GetProviderStatus implements LLMRouterInterface.
func (w *UnifiedRouterWrapper) GetProviderStatus() map[string]ProviderStatus {
	return LegacyStatusToProviderStatus(w.router.GetLegacyProviderStatus())
}

// UpdateProviderWeights implements LLMRouterInterface.
func (w *UnifiedRouterWrapper) UpdateProviderWeights(weights map[string]float64) error {
	return w.router.UpdateProviderWeights(weights)
}

// Underlying returns the underlying UnifiedRouter for advanced usage.
func (w *UnifiedRouterWrapper) Underlying() *llm.UnifiedRouter {
	return w.router
}

// OrchestratorRequestToLLMContext converts an OrchestratorRequest to llm.RequestContext.
// This is the bridge between the orchestrator's request format and the UnifiedRouter's expected input.
func OrchestratorRequestToLLMContext(req OrchestratorRequest) llm.RequestContext {
	// Extract provider and model from context if specified
	provider := ""
	model := ""
	maxTokens := 0
	temperature := 0.0
	systemPrompt := ""
	strictProvider := strictProviderDefaultFromEnv()

	// Policy routing hints (Issue #883 - strict provider enforcement)
	policyPreferredProvider := ""
	var policyAllowedProviders []string
	policyRoutingReason := ""

	// Debug: Log the context to trace policy routing
	if req.Context != nil && (req.Context["policy_preferred_provider"] != nil || req.Context["policy_allowed_providers"] != nil) {
		log.Printf("[LLM_ADAPTER] Policy routing context detected: preferred=%v, allowed=%v, reason=%v",
			req.Context["policy_preferred_provider"],
			req.Context["policy_allowed_providers"],
			req.Context["policy_routing_reason"])
	}

	if req.Context != nil {
		if p, ok := req.Context["provider"].(string); ok {
			provider = p
		}
		if m, ok := req.Context["model"].(string); ok {
			model = m
		}
		if mt, ok := req.Context["max_tokens"].(int); ok {
			maxTokens = mt
		}
		if mt, ok := req.Context["max_tokens"].(float64); ok {
			maxTokens = int(mt)
		}
		if t, ok := req.Context["temperature"].(float64); ok {
			temperature = t
		}
		if sp, ok := req.Context["system_prompt"].(string); ok {
			systemPrompt = sp
		}
		if strict, provided := parseStrictProviderFlag(req.Context); provided {
			strictProvider = strict
		}

		// Extract policy routing hints injected by dynamic policy evaluation
		if pp, ok := req.Context["policy_preferred_provider"].(string); ok {
			policyPreferredProvider = pp
		}
		if ap, ok := req.Context["policy_allowed_providers"].([]string); ok {
			policyAllowedProviders = ap
		}
		if pr, ok := req.Context["policy_routing_reason"].(string); ok {
			policyRoutingReason = pr
		}
	}

	return llm.RequestContext{
		Query:                   req.Query,
		RequestType:             req.RequestType,
		UserRole:                req.User.Role,
		UserPermissions:         req.User.Permissions,
		ClientID:                req.Client.ID,
		OrgID:                   req.Client.OrgID,
		TenantID:                req.Client.TenantID,
		Provider:                provider,
		StrictProvider:          strictProvider,
		Model:                   model,
		MaxTokens:               maxTokens,
		Temperature:             temperature,
		SystemPrompt:            systemPrompt,
		AllowLocal:              true, // Allow local/ollama by default
		Metadata:                req.Context,
		PolicyPreferredProvider: policyPreferredProvider,
		PolicyAllowedProviders:  policyAllowedProviders,
		PolicyRoutingReason:     policyRoutingReason,
	}
}

// LegacyResponseToLLMResponse converts llm.LegacyLLMResponse to LLMResponse.
// This ensures backward compatibility with existing code that uses LLMResponse.
func LegacyResponseToLLMResponse(resp *llm.LegacyLLMResponse) *LLMResponse {
	if resp == nil {
		return nil
	}
	return &LLMResponse{
		Content:      resp.Content,
		Model:        resp.Model,
		TokensUsed:   resp.TokensUsed,
		Metadata:     resp.Metadata,
		ResponseTime: resp.ResponseTime,
	}
}

// LegacyProviderInfoToProviderInfo converts llm.LegacyProviderInfo to ProviderInfo.
func LegacyProviderInfoToProviderInfo(info *llm.LegacyProviderInfo) *ProviderInfo {
	if info == nil {
		return nil
	}
	return &ProviderInfo{
		Provider:       info.Provider,
		Model:          info.Model,
		ResponseTimeMs: info.ResponseTimeMs,
		TokensUsed:     info.TokensUsed,
		Cost:           info.Cost,
	}
}

// LegacyStatusToProviderStatus converts llm.LegacyProviderStatus to ProviderStatus.
func LegacyStatusToProviderStatus(status map[string]llm.LegacyProviderStatus) map[string]ProviderStatus {
	result := make(map[string]ProviderStatus)
	for name, s := range status {
		result[name] = ProviderStatus{
			Name:         s.Name,
			Healthy:      s.Healthy,
			Weight:       s.Weight,
			RequestCount: s.RequestCount,
			ErrorCount:   s.ErrorCount,
			AvgLatency:   s.AvgLatency,
			LastUsed:     s.LastUsed,
		}
	}
	return result
}
