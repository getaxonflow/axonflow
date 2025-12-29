// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"

	"axonflow/platform/orchestrator/llm"
)

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

// Compile-time verification that LLMRouter implements LLMRouterInterface
var _ LLMRouterInterface = (*LLMRouter)(nil)

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
	}

	return llm.RequestContext{
		Query:           req.Query,
		RequestType:     req.RequestType,
		UserRole:        req.User.Role,
		UserPermissions: req.User.Permissions,
		ClientID:        req.Client.ID,
		OrgID:           req.Client.OrgID,
		TenantID:        req.Client.TenantID,
		Provider:        provider,
		Model:           model,
		MaxTokens:       maxTokens,
		Temperature:     temperature,
		SystemPrompt:    systemPrompt,
		AllowLocal:      true, // Allow local/ollama by default
		Metadata:        req.Context,
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
