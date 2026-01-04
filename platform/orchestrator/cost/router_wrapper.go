// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"log"
	"time"

	"axonflow/platform/orchestrator/llm"
)

// CostTrackingRouter wraps an LLM router to automatically track usage and costs
type CostTrackingRouter struct {
	router  *llm.UnifiedRouter
	service *Service
	logger  *log.Logger
}

// NewCostTrackingRouter creates a new cost tracking wrapper around a router
func NewCostTrackingRouter(router *llm.UnifiedRouter, service *Service, logger *log.Logger) *CostTrackingRouter {
	if logger == nil {
		logger = log.Default()
	}
	return &CostTrackingRouter{
		router:  router,
		service: service,
		logger:  logger,
	}
}

// RouteRequest routes a request and records usage
func (c *CostTrackingRouter) RouteRequest(ctx context.Context, reqCtx llm.RequestContext) (*llm.LegacyLLMResponse, *llm.LegacyProviderInfo, error) {
	resp, info, err := c.router.RouteRequest(ctx, reqCtx)
	if err != nil {
		return resp, info, err
	}

	// Record usage asynchronously
	if c.service != nil && resp != nil && info != nil {
		go c.recordUsage(ctx, reqCtx, resp, info)
	}

	return resp, info, nil
}

// RouteCompletionRequest routes a completion request and records usage
func (c *CostTrackingRouter) RouteCompletionRequest(ctx context.Context, req llm.CompletionRequest, opts ...llm.RouteOption) (*llm.CompletionResponse, *llm.RouteInfo, error) {
	resp, info, err := c.router.RouteCompletionRequest(ctx, req, opts...)
	if err != nil {
		return resp, info, err
	}

	// Record usage asynchronously
	if c.service != nil && resp != nil && info != nil {
		go c.recordCompletionUsage(ctx, req, resp, info)
	}

	return resp, info, nil
}

func (c *CostTrackingRouter) recordUsage(ctx context.Context, reqCtx llm.RequestContext, resp *llm.LegacyLLMResponse, info *llm.LegacyProviderInfo) {
	// Use ClientID as request ID if available, otherwise generate one
	requestID := reqCtx.ClientID
	if requestID == "" {
		requestID = generateRequestID()
	}

	// Legacy response only has TokensUsed (total), not separate in/out
	// We'll estimate 25% input, 75% output as a reasonable approximation
	tokensIn := resp.TokensUsed / 4
	tokensOut := resp.TokensUsed - tokensIn

	record := &UsageRecord{
		RequestID:   requestID,
		Timestamp:   time.Now().UTC(),
		OrgID:       firstOf(reqCtx.OrgID, getStringFromContext(ctx, "org_id")),
		TenantID:    firstOf(reqCtx.TenantID, getStringFromContext(ctx, "tenant_id")),
		TeamID:      getStringFromContext(ctx, "team_id"),
		AgentID:     getStringFromContext(ctx, "agent_id"),
		UserID:      getStringFromContext(ctx, "user_id"),
		Provider:    info.Provider,
		Model:       info.Model,
		TokensIn:    tokensIn,
		TokensOut:   tokensOut,
		CostUSD:     0, // Will be calculated by service
		RequestType: "completion",
	}

	if err := c.service.RecordUsage(context.Background(), record); err != nil {
		c.logger.Printf("[Cost] Failed to record usage: %v", err)
	}
}

func (c *CostTrackingRouter) recordCompletionUsage(ctx context.Context, req llm.CompletionRequest, resp *llm.CompletionResponse, info *llm.RouteInfo) {
	record := &UsageRecord{
		RequestID:   generateRequestID(),
		Timestamp:   time.Now().UTC(),
		OrgID:       getStringFromContext(ctx, "org_id"),
		TenantID:    getStringFromContext(ctx, "tenant_id"),
		TeamID:      getStringFromContext(ctx, "team_id"),
		AgentID:     getStringFromContext(ctx, "agent_id"),
		UserID:      getStringFromContext(ctx, "user_id"),
		Provider:    info.ProviderName,
		Model:       info.Model,
		TokensIn:    resp.Usage.PromptTokens,
		TokensOut:   resp.Usage.CompletionTokens,
		CostUSD:     0, // Will be calculated by service
		RequestType: "completion",
	}

	if err := c.service.RecordUsage(context.Background(), record); err != nil {
		c.logger.Printf("[Cost] Failed to record usage: %v", err)
	}
}

// Router returns the underlying router
func (c *CostTrackingRouter) Router() *llm.UnifiedRouter {
	return c.router
}

// Service returns the cost service
func (c *CostTrackingRouter) Service() *Service {
	return c.service
}

// Delegate all other UnifiedRouter methods

func (c *CostTrackingRouter) GetProviderStatus(ctx context.Context) map[string]*llm.ProviderStatus {
	return c.router.GetProviderStatus(ctx)
}

func (c *CostTrackingRouter) GetLegacyProviderStatus() map[string]llm.LegacyProviderStatus {
	return c.router.GetLegacyProviderStatus()
}

func (c *CostTrackingRouter) UpdateProviderWeights(weights map[string]float64) error {
	return c.router.UpdateProviderWeights(weights)
}

func (c *CostTrackingRouter) GetRoutingStrategy() llm.RoutingStrategy {
	return c.router.GetRoutingStrategy()
}

func (c *CostTrackingRouter) SetRoutingStrategy(strategy llm.RoutingStrategy) {
	c.router.SetRoutingStrategy(strategy)
}

func (c *CostTrackingRouter) GetDefaultProvider() string {
	return c.router.GetDefaultProvider()
}

func (c *CostTrackingRouter) SetDefaultProvider(provider string) {
	c.router.SetDefaultProvider(provider)
}

func (c *CostTrackingRouter) IsHealthy() bool {
	return c.router.IsHealthy()
}

func (c *CostTrackingRouter) Registry() *llm.Registry {
	return c.router.Registry()
}

func (c *CostTrackingRouter) Close() error {
	return c.router.Close()
}

func (c *CostTrackingRouter) RegisterProvider(config llm.ProviderConfig) error {
	return c.router.RegisterProvider(config)
}

func (c *CostTrackingRouter) EnableProvider(name string) error {
	return c.router.EnableProvider(name)
}

func (c *CostTrackingRouter) DisableProvider(name string) error {
	return c.router.DisableProvider(name)
}

func (c *CostTrackingRouter) GetProvider(ctx context.Context, name string) (llm.Provider, error) {
	return c.router.GetProvider(ctx, name)
}

func (c *CostTrackingRouter) ListProviders() []string {
	return c.router.ListProviders()
}

func (c *CostTrackingRouter) ListEnabledProviders() []string {
	return c.router.ListEnabledProviders()
}

func (c *CostTrackingRouter) ListHealthyProviders() []string {
	return c.router.ListHealthyProviders()
}

// Helper functions

func getStringFromContext(ctx context.Context, key string) string {
	if v := ctx.Value(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func generateRequestID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
	}
	return string(b)
}
