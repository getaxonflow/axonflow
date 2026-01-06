// Cost Controls types and methods for AxonFlow SDK
package axonflow

import (
	"context"
	"fmt"
	"log"
	"net/url"
)

// ============================================================================
// Budget Types
// ============================================================================

// CreateBudgetRequest represents a request to create a new budget
type CreateBudgetRequest struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Scope           string  `json:"scope"` // organization, team, agent, workflow, user
	LimitUSD        float64 `json:"limit_usd"`
	Period          string  `json:"period"`    // daily, weekly, monthly, quarterly, yearly
	OnExceed        string  `json:"on_exceed"` // warn, block, downgrade
	AlertThresholds []int   `json:"alert_thresholds,omitempty"`
	ScopeID         string  `json:"scope_id,omitempty"`
}

// UpdateBudgetRequest represents a request to update an existing budget
type UpdateBudgetRequest struct {
	Name            *string  `json:"name,omitempty"`
	LimitUSD        *float64 `json:"limit_usd,omitempty"`
	OnExceed        *string  `json:"on_exceed,omitempty"`
	AlertThresholds []int    `json:"alert_thresholds,omitempty"`
}

// ListBudgetsOptions represents options for listing budgets
type ListBudgetsOptions struct {
	Scope  string
	Limit  int
	Offset int
}

// Budget represents a budget entity
type Budget struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Scope           string  `json:"scope"`
	LimitUSD        float64 `json:"limit_usd"`
	Period          string  `json:"period"`
	OnExceed        string  `json:"on_exceed"`
	AlertThresholds []int   `json:"alert_thresholds"`
	Enabled         bool    `json:"enabled"`
	ScopeID         string  `json:"scope_id,omitempty"`
	CreatedAt       string  `json:"created_at,omitempty"`
	UpdatedAt       string  `json:"updated_at,omitempty"`
}

// BudgetsResponse represents a list of budgets response
type BudgetsResponse struct {
	Budgets []Budget `json:"budgets"`
	Total   int      `json:"total"`
}

// ============================================================================
// Budget Status Types
// ============================================================================

// BudgetStatus represents the current status of a budget
type BudgetStatus struct {
	Budget       Budget  `json:"budget"`
	UsedUSD      float64 `json:"used_usd"`
	RemainingUSD float64 `json:"remaining_usd"`
	Percentage   float64 `json:"percentage"`
	IsExceeded   bool    `json:"is_exceeded"`
	IsBlocked    bool    `json:"is_blocked"`
	PeriodStart  string  `json:"period_start"`
	PeriodEnd    string  `json:"period_end"`
}

// ============================================================================
// Budget Alert Types
// ============================================================================

// BudgetAlert represents a budget alert
type BudgetAlert struct {
	ID                string  `json:"id"`
	BudgetID          string  `json:"budget_id"`
	AlertType         string  `json:"alert_type"`
	Threshold         int     `json:"threshold"`
	PercentageReached float64 `json:"percentage_reached"`
	AmountUSD         float64 `json:"amount_usd"`
	Message           string  `json:"message"`
	CreatedAt         string  `json:"created_at"`
}

// BudgetAlertsResponse represents a list of budget alerts
type BudgetAlertsResponse struct {
	Alerts []BudgetAlert `json:"alerts"`
	Count  int           `json:"count"`
}

// ============================================================================
// Budget Check Types
// ============================================================================

// CheckBudgetRequest represents a request to check budget availability
type CheckBudgetRequest struct {
	OrgID      string `json:"org_id,omitempty"`
	TeamID     string `json:"team_id,omitempty"`
	AgentID    string `json:"agent_id,omitempty"`
	WorkflowID string `json:"workflow_id,omitempty"`
	UserID     string `json:"user_id,omitempty"`
}

// BudgetDecision represents the result of a budget check
type BudgetDecision struct {
	Allowed bool     `json:"allowed"`
	Action  string   `json:"action,omitempty"`
	Message string   `json:"message,omitempty"`
	Budgets []Budget `json:"budgets,omitempty"`
}

// ============================================================================
// Usage Types
// ============================================================================

// UsageQueryOptions represents options for usage queries
type UsageQueryOptions struct {
	Period   string
	Provider string
	Model    string
	Limit    int
	Offset   int
}

// UsageSummary represents aggregated usage data
type UsageSummary struct {
	TotalCostUSD          float64 `json:"total_cost_usd"`
	TotalRequests         int     `json:"total_requests"`
	TotalTokensIn         int     `json:"total_tokens_in"`
	TotalTokensOut        int     `json:"total_tokens_out"`
	AverageCostPerRequest float64 `json:"average_cost_per_request"`
	Period                string  `json:"period"`
	PeriodStart           string  `json:"period_start"`
	PeriodEnd             string  `json:"period_end"`
}

// UsageBreakdownItem represents a single item in usage breakdown
type UsageBreakdownItem struct {
	GroupValue   string  `json:"group_value"`
	CostUSD      float64 `json:"cost_usd"`
	Percentage   float64 `json:"percentage"`
	RequestCount int     `json:"request_count"`
	TokensIn     int     `json:"tokens_in"`
	TokensOut    int     `json:"tokens_out"`
}

// UsageBreakdown represents usage broken down by a dimension
type UsageBreakdown struct {
	GroupBy      string               `json:"group_by"`
	TotalCostUSD float64              `json:"total_cost_usd"`
	Items        []UsageBreakdownItem `json:"items"`
	Period       string               `json:"period"`
	PeriodStart  string               `json:"period_start"`
	PeriodEnd    string               `json:"period_end"`
}

// UsageRecord represents a single usage record
type UsageRecord struct {
	ID        string  `json:"id"`
	Provider  string  `json:"provider"`
	Model     string  `json:"model"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`
	RequestID string  `json:"request_id,omitempty"`
	OrgID     string  `json:"org_id,omitempty"`
	AgentID   string  `json:"agent_id,omitempty"`
	Timestamp string  `json:"timestamp,omitempty"`
}

// UsageRecordsResponse represents a list of usage records
type UsageRecordsResponse struct {
	Records []UsageRecord `json:"records"`
	Total   int           `json:"total"`
}

// ============================================================================
// Pricing Types
// ============================================================================

// ModelPricing represents pricing for a model
type ModelPricing struct {
	InputPer1K  float64 `json:"input_per_1k"`
	OutputPer1K float64 `json:"output_per_1k"`
}

// PricingInfo represents pricing information for a provider/model
type PricingInfo struct {
	Provider string       `json:"provider"`
	Model    string       `json:"model"`
	Pricing  ModelPricing `json:"pricing"`
}

// PricingListResponse represents a list of pricing info
type PricingListResponse struct {
	Pricing []PricingInfo `json:"pricing"`
}

// ============================================================================
// Budget Methods
// ============================================================================

// CreateBudget creates a new budget
func (c *AxonFlowClient) CreateBudget(ctx context.Context, req CreateBudgetRequest) (*Budget, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Creating budget: %s", req.ID)
	}

	var budget Budget
	if err := c.costRequest(ctx, "POST", "/api/v1/budgets", req, &budget); err != nil {
		return nil, err
	}

	return &budget, nil
}

// GetBudget retrieves a budget by ID
func (c *AxonFlowClient) GetBudget(ctx context.Context, id string) (*Budget, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting budget: %s", id)
	}

	var budget Budget
	if err := c.costRequest(ctx, "GET", "/api/v1/budgets/"+id, nil, &budget); err != nil {
		return nil, err
	}

	return &budget, nil
}

// ListBudgets lists all budgets with optional filtering
func (c *AxonFlowClient) ListBudgets(ctx context.Context, options ListBudgetsOptions) (*BudgetsResponse, error) {
	path := "/api/v1/budgets" + options.buildQueryParams()

	if c.config.Debug {
		log.Printf("[AxonFlow] Listing budgets: %s", path)
	}

	var response BudgetsResponse
	if err := c.costRequest(ctx, "GET", path, nil, &response); err != nil {
		return nil, err
	}

	return &response, nil
}

// UpdateBudget updates an existing budget
func (c *AxonFlowClient) UpdateBudget(ctx context.Context, budget *Budget) (*Budget, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Updating budget: %s", budget.ID)
	}

	// Convert Budget to update request format
	updateReq := map[string]interface{}{
		"name":             budget.Name,
		"limit_usd":        budget.LimitUSD,
		"on_exceed":        budget.OnExceed,
		"alert_thresholds": budget.AlertThresholds,
	}

	var updatedBudget Budget
	if err := c.costRequest(ctx, "PUT", "/api/v1/budgets/"+budget.ID, updateReq, &updatedBudget); err != nil {
		return nil, err
	}

	return &updatedBudget, nil
}

// DeleteBudget deletes a budget by ID
func (c *AxonFlowClient) DeleteBudget(ctx context.Context, id string) error {
	if c.config.Debug {
		log.Printf("[AxonFlow] Deleting budget: %s", id)
	}

	return c.costRequest(ctx, "DELETE", "/api/v1/budgets/"+id, nil, nil)
}

// ============================================================================
// Budget Status & Alerts Methods
// ============================================================================

// GetBudgetStatus retrieves the current status of a budget
func (c *AxonFlowClient) GetBudgetStatus(ctx context.Context, id string) (*BudgetStatus, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Getting budget status: %s", id)
	}

	var status BudgetStatus
	if err := c.costRequest(ctx, "GET", "/api/v1/budgets/"+id+"/status", nil, &status); err != nil {
		return nil, err
	}

	return &status, nil
}

// GetBudgetAlerts retrieves alerts for a budget
func (c *AxonFlowClient) GetBudgetAlerts(ctx context.Context, id string, limit int) (*BudgetAlertsResponse, error) {
	path := fmt.Sprintf("/api/v1/budgets/%s/alerts", id)
	if limit > 0 {
		path += fmt.Sprintf("?limit=%d", limit)
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting budget alerts: %s", path)
	}

	var response BudgetAlertsResponse
	if err := c.costRequest(ctx, "GET", path, nil, &response); err != nil {
		return nil, err
	}

	// Handle null alerts from API
	if response.Alerts == nil {
		response.Alerts = []BudgetAlert{}
	}

	return &response, nil
}

// CheckBudget performs a pre-flight budget check
func (c *AxonFlowClient) CheckBudget(ctx context.Context, req CheckBudgetRequest) (*BudgetDecision, error) {
	if c.config.Debug {
		log.Printf("[AxonFlow] Checking budget")
	}

	var decision BudgetDecision
	if err := c.costRequest(ctx, "POST", "/api/v1/budgets/check", req, &decision); err != nil {
		return nil, err
	}

	return &decision, nil
}

// ============================================================================
// Usage Methods
// ============================================================================

// GetUsageSummary retrieves aggregated usage data
func (c *AxonFlowClient) GetUsageSummary(ctx context.Context, options UsageQueryOptions) (*UsageSummary, error) {
	path := "/api/v1/usage" + options.buildQueryParamsForSummary()

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting usage summary: %s", path)
	}

	var summary UsageSummary
	if err := c.costRequest(ctx, "GET", path, nil, &summary); err != nil {
		return nil, err
	}

	return &summary, nil
}

// GetUsageBreakdown retrieves usage broken down by a dimension
func (c *AxonFlowClient) GetUsageBreakdown(ctx context.Context, groupBy string, options UsageQueryOptions) (*UsageBreakdown, error) {
	path := "/api/v1/usage/breakdown" + options.buildQueryParamsForBreakdown(groupBy)

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting usage breakdown: %s", path)
	}

	var breakdown UsageBreakdown
	if err := c.costRequest(ctx, "GET", path, nil, &breakdown); err != nil {
		return nil, err
	}

	// Handle null items from API
	if breakdown.Items == nil {
		breakdown.Items = []UsageBreakdownItem{}
	}

	return &breakdown, nil
}

// ListUsageRecords lists recent usage records
func (c *AxonFlowClient) ListUsageRecords(ctx context.Context, options UsageQueryOptions) (*UsageRecordsResponse, error) {
	path := "/api/v1/usage/records" + options.buildQueryParamsForRecords()

	if c.config.Debug {
		log.Printf("[AxonFlow] Listing usage records: %s", path)
	}

	var response UsageRecordsResponse
	if err := c.costRequest(ctx, "GET", path, nil, &response); err != nil {
		return nil, err
	}

	// Handle null records from API
	if response.Records == nil {
		response.Records = []UsageRecord{}
	}

	return &response, nil
}

// ============================================================================
// Pricing Methods
// ============================================================================

// GetPricing retrieves pricing information for a provider/model
func (c *AxonFlowClient) GetPricing(ctx context.Context, provider, model string) (*PricingInfo, error) {
	params := url.Values{}
	if provider != "" {
		params.Set("provider", provider)
	}
	if model != "" {
		params.Set("model", model)
	}

	path := "/api/v1/pricing"
	if encoded := params.Encode(); encoded != "" {
		path += "?" + encoded
	}

	if c.config.Debug {
		log.Printf("[AxonFlow] Getting pricing: %s", path)
	}

	// API may return single object or array
	var pricing PricingInfo
	if err := c.costRequest(ctx, "GET", path, nil, &pricing); err != nil {
		return nil, err
	}

	return &pricing, nil
}

// ============================================================================
// HTTP Helper for Cost Requests
// ============================================================================

// costRequest makes an HTTP request to the cost control API via Agent proxy
func (c *AxonFlowClient) costRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	// All routes go through Agent endpoint since ADR-026
	return c.makeJSONRequest(ctx, method, c.config.Endpoint+path, body, result)
}

// buildQueryParams builds query string for ListBudgetsOptions
func (o ListBudgetsOptions) buildQueryParams() string {
	params := url.Values{}
	if o.Scope != "" {
		params.Set("scope", o.Scope)
	}
	if o.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", o.Limit))
	}
	if o.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", o.Offset))
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// buildQueryParamsForSummary builds query string for usage summary
func (o UsageQueryOptions) buildQueryParamsForSummary() string {
	params := url.Values{}
	if o.Period != "" {
		params.Set("period", o.Period)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// buildQueryParamsForBreakdown builds query string for usage breakdown
func (o UsageQueryOptions) buildQueryParamsForBreakdown(groupBy string) string {
	params := url.Values{}
	if groupBy != "" {
		params.Set("group_by", groupBy)
	}
	if o.Period != "" {
		params.Set("period", o.Period)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// buildQueryParamsForRecords builds query string for usage records
func (o UsageQueryOptions) buildQueryParamsForRecords() string {
	params := url.Values{}
	if o.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", o.Limit))
	}
	if o.Offset > 0 {
		params.Set("offset", fmt.Sprintf("%d", o.Offset))
	}
	if o.Provider != "" {
		params.Set("provider", o.Provider)
	}
	if o.Model != "" {
		params.Set("model", o.Model)
	}
	if encoded := params.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// lastIndex returns the last index of sep in s, or -1 if not found
func lastIndex(s, sep string) int {
	for i := len(s) - len(sep); i >= 0; i-- {
		if s[i:i+len(sep)] == sep {
			return i
		}
	}
	return -1
}
