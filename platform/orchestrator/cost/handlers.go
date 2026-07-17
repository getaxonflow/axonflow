// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// Handler provides HTTP handlers for cost management APIs
type Handler struct {
	service *Service
}

// NewHandler creates a new cost handler
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers all cost control routes with a gorilla/mux router.
// This registers both community and enterprise routes for backward compatibility.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	h.RegisterCommunityRoutes(r)
	h.RegisterEnterpriseRoutes(r)
}

// RegisterCommunityRoutes registers pricing and basic usage summary routes (community tier).
func (h *Handler) RegisterCommunityRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/pricing", h.GetPricing).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/usage", h.GetUsageSummary).Methods("GET", "OPTIONS")
}

// RegisterEnterpriseRoutes registers budget management and analytics routes (enterprise tier).
func (h *Handler) RegisterEnterpriseRoutes(r *mux.Router) {
	// Budget CRUD endpoints
	r.HandleFunc("/api/v1/budgets", h.CreateBudget).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/budgets", h.ListBudgets).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/check", h.CheckBudget).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.GetBudget).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.UpdateBudget).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.DeleteBudget).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}/status", h.GetBudgetStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}/alerts", h.GetBudgetAlerts).Methods("GET", "OPTIONS")

	// Usage analytics endpoints
	r.HandleFunc("/api/v1/usage/breakdown", h.GetUsageBreakdown).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/usage/records", h.ListUsageRecords).Methods("GET", "OPTIONS")
}

// CreateBudgetRequest is the request body for creating a budget
type CreateBudgetRequest struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Description     string         `json:"description,omitempty"`
	Scope           BudgetScope    `json:"scope"`
	ScopeID         string         `json:"scope_id,omitempty"`
	LimitUSD        float64        `json:"limit_usd"`
	Period          BudgetPeriod   `json:"period"`
	OnExceed        OnExceedAction `json:"on_exceed,omitempty"`
	AlertThresholds []int          `json:"alert_thresholds,omitempty"`
}

// CreateBudget handles POST /api/v1/budgets
func (h *Handler) CreateBudget(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req CreateBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	budget := &Budget{
		ID:              req.ID,
		Name:            req.Name,
		Description:     req.Description,
		Scope:           req.Scope,
		ScopeID:         req.ScopeID,
		LimitUSD:        req.LimitUSD,
		Period:          req.Period,
		OnExceed:        req.OnExceed,
		AlertThresholds: req.AlertThresholds,
		Enabled:         true,
		OrgID:           r.Header.Get("X-Org-ID"),
		TenantID:        r.Header.Get("X-Tenant-ID"),
		CreatedBy:       r.Header.Get("X-User-ID"),
	}

	// Set defaults
	if budget.OnExceed == "" {
		budget.OnExceed = OnExceedWarn
	}
	if budget.Scope == "" {
		budget.Scope = ScopeOrganization
	}
	if len(budget.AlertThresholds) == 0 {
		budget.AlertThresholds = []int{50, 80, 100}
	}

	if err := h.service.CreateBudget(r.Context(), budget); err != nil {
		if err == ErrBudgetExists {
			h.writeError(w, "Budget already exists", http.StatusConflict)
			return
		}
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(budget)
}

// ListBudgets handles GET /api/v1/budgets
func (h *Handler) ListBudgets(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	query := r.URL.Query()

	opts := ListBudgetsOptions{
		OrgID:    firstOrDefault(r.Header.Get("X-Org-ID"), query.Get("org_id")),
		TenantID: firstOrDefault(r.Header.Get("X-Tenant-ID"), query.Get("tenant_id")),
		Scope:    BudgetScope(query.Get("scope")),
		ScopeID:  query.Get("scope_id"),
	}

	opts.Limit = 50 // Default limit
	if limit := query.Get("limit"); limit != "" {
		opts.Limit, _ = strconv.Atoi(limit)
	}
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 50
	}
	if offset := query.Get("offset"); offset != "" {
		opts.Offset, _ = strconv.Atoi(offset)
	}
	if enabled := query.Get("enabled"); enabled != "" {
		e := enabled == "true"
		opts.Enabled = &e
	}

	budgets, total, err := h.service.ListBudgets(r.Context(), opts)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"budgets": budgets,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// GetBudget handles GET /api/v1/budgets/{id}
func (h *Handler) GetBudget(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	budget, err := h.service.GetBudgetScoped(r.Context(), budgetID, h.callerOrgID(r), h.callerTenantID(r))
	if err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(budget)
}

// UpdateBudget handles PUT /api/v1/budgets/{id}
// Supports partial updates - only non-zero fields are updated
func (h *Handler) UpdateBudget(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	// First, fetch the existing budget — org/tenant-scoped, so a cross-org
	// id is a 404 before any mutation (#2934)
	existing, err := h.service.GetBudgetScoped(r.Context(), budgetID, h.callerOrgID(r), h.callerTenantID(r))
	if err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Decode the update request
	var update Budget
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Merge non-zero values from update into existing budget
	if update.Name != "" {
		existing.Name = update.Name
	}
	if update.LimitUSD > 0 {
		existing.LimitUSD = update.LimitUSD
	}
	if update.OnExceed != "" {
		existing.OnExceed = update.OnExceed
	}
	if len(update.AlertThresholds) > 0 {
		existing.AlertThresholds = update.AlertThresholds
	}
	existing.UpdatedBy = r.Header.Get("X-User-ID")

	if err := h.service.UpdateBudget(r.Context(), existing); err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(existing)
}

// DeleteBudget handles DELETE /api/v1/budgets/{id}
func (h *Handler) DeleteBudget(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	if err := h.service.DeleteBudgetScoped(r.Context(), budgetID, h.callerOrgID(r), h.callerTenantID(r)); err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetBudgetStatus handles GET /api/v1/budgets/{id}/status
func (h *Handler) GetBudgetStatus(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	status, err := h.service.GetBudgetStatusScoped(r.Context(), budgetID, h.callerOrgID(r), h.callerTenantID(r))
	if err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// GetBudgetAlerts handles GET /api/v1/budgets/{id}/alerts
func (h *Handler) GetBudgetAlerts(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		limit, _ = strconv.Atoi(l)
	}

	alerts, err := h.service.GetRecentAlertsScoped(r.Context(), budgetID, h.callerOrgID(r), h.callerTenantID(r), limit)
	if err != nil {
		if err == ErrBudgetNotFound {
			h.writeError(w, "Budget not found", http.StatusNotFound)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

// GetUsageSummary handles GET /api/v1/usage
func (h *Handler) GetUsageSummary(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	query := r.URL.Query()

	opts := UsageQueryOptions{
		OrgID:    firstOrDefault(r.Header.Get("X-Org-ID"), query.Get("org_id")),
		TenantID: firstOrDefault(r.Header.Get("X-Tenant-ID"), query.Get("tenant_id")),
		TeamID:   query.Get("team_id"),
		AgentID:  query.Get("agent_id"),
		Provider: query.Get("provider"),
		Model:    query.Get("model"),
		Period:   query.Get("period"),
	}

	// Parse time range
	if start := query.Get("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			opts.StartTime = t
		}
	}
	if end := query.Get("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			opts.EndTime = t
		}
	}

	// Default to current month if no period specified
	if opts.Period == "" && opts.StartTime.IsZero() {
		opts.Period = "monthly"
	}

	summary, err := h.service.GetUsageSummary(r.Context(), opts)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(summary)
}

// GetUsageBreakdown handles GET /api/v1/usage/breakdown
func (h *Handler) GetUsageBreakdown(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	query := r.URL.Query()

	groupBy := query.Get("group_by")
	if groupBy == "" {
		groupBy = "provider"
	}

	opts := UsageQueryOptions{
		OrgID:    firstOrDefault(r.Header.Get("X-Org-ID"), query.Get("org_id")),
		TenantID: firstOrDefault(r.Header.Get("X-Tenant-ID"), query.Get("tenant_id")),
		Period:   query.Get("period"),
	}

	// Parse time range
	if start := query.Get("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			opts.StartTime = t
		}
	}
	if end := query.Get("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			opts.EndTime = t
		}
	}

	// Default to current month
	if opts.Period == "" && opts.StartTime.IsZero() {
		opts.Period = "monthly"
	}

	breakdown, err := h.service.GetUsageBreakdown(r.Context(), groupBy, opts)
	if err != nil {
		if err == ErrInvalidGroupBy {
			h.writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(breakdown)
}

// ListUsageRecords handles GET /api/v1/usage/records
func (h *Handler) ListUsageRecords(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	query := r.URL.Query()

	opts := UsageQueryOptions{
		OrgID:    firstOrDefault(r.Header.Get("X-Org-ID"), query.Get("org_id")),
		TenantID: firstOrDefault(r.Header.Get("X-Tenant-ID"), query.Get("tenant_id")),
		TeamID:   query.Get("team_id"),
		AgentID:  query.Get("agent_id"),
		Provider: query.Get("provider"),
		Model:    query.Get("model"),
	}

	opts.Limit = 100 // Default limit
	if limit := query.Get("limit"); limit != "" {
		opts.Limit, _ = strconv.Atoi(limit)
	}
	if opts.Limit <= 0 || opts.Limit > 1000 {
		opts.Limit = 100
	}
	if offset := query.Get("offset"); offset != "" {
		opts.Offset, _ = strconv.Atoi(offset)
	}

	// Parse time range
	if start := query.Get("start_time"); start != "" {
		if t, err := time.Parse(time.RFC3339, start); err == nil {
			opts.StartTime = t
		}
	}
	if end := query.Get("end_time"); end != "" {
		if t, err := time.Parse(time.RFC3339, end); err == nil {
			opts.EndTime = t
		}
	}

	records, total, err := h.service.ListUsageRecords(r.Context(), opts)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"records": records,
		"total":   total,
		"limit":   opts.Limit,
		"offset":  opts.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// GetPricing handles GET /api/v1/pricing
func (h *Handler) GetPricing(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	pricing := h.service.GetPricing()

	query := r.URL.Query()
	provider := query.Get("provider")
	model := query.Get("model")

	// If specific model requested, return just that pricing
	if provider != "" && model != "" {
		modelPricing, found := pricing.GetModelPricing(provider, model)
		if !found {
			h.writeError(w, "Model pricing not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": provider,
			"model":    model,
			"pricing":  modelPricing,
		})
		return
	}

	// If just provider requested, return all models for that provider
	if provider != "" {
		models := pricing.ListModels(provider)
		if len(models) == 0 {
			h.writeError(w, "Provider not found", http.StatusNotFound)
			return
		}

		providerPricing := make(map[string]ModelPricing)
		for _, m := range models {
			if p, ok := pricing.GetModelPricing(provider, m); ok {
				providerPricing[m] = p
			}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"provider": provider,
			"models":   providerPricing,
		})
		return
	}

	// Return all pricing
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"providers": pricing.Providers,
	})
}

// CheckBudgetRequest is the request body for budget check
type CheckBudgetRequest struct {
	OrgID    string `json:"org_id"`
	TeamID   string `json:"team_id"`
	AgentID  string `json:"agent_id"`
	UserID   string `json:"user_id"`
	TenantID string `json:"tenant_id"`
}

// CheckBudget handles POST /api/v1/budgets/check
func (h *Handler) CheckBudget(w http.ResponseWriter, r *http.Request) {
	h.setCORSHeaders(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req CheckBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use headers as defaults
	if req.OrgID == "" {
		req.OrgID = r.Header.Get("X-Org-ID")
	}
	if req.TenantID == "" {
		req.TenantID = r.Header.Get("X-Tenant-ID")
	}

	// #2934: a non-tenant-wide caller reaches this endpoint (it is the
	// deliberate enforcement-plane exemption), so the body org_id/tenant_id
	// are a forgeable channel — a fleet developer could POST another org's id
	// and, even with spend figures redacted, learn its budget name +
	// exceeded status. For a redacted (non-tenant-wide) caller, pin the check
	// to the authenticated identity the agent stamped, ignoring any body
	// override. Tenant-wide (admin) callers keep the body-driven cross-scope
	// check they use for oversight.
	if SpendRedactionRequested(r.Context()) {
		if hdrOrg := r.Header.Get("X-Org-ID"); hdrOrg != "" {
			req.OrgID = hdrOrg
		}
		if hdrTenant := r.Header.Get("X-Tenant-ID"); hdrTenant != "" {
			req.TenantID = hdrTenant
		}
	}

	decision, err := h.service.CheckBudget(r.Context(), req.OrgID, req.TeamID, req.AgentID, req.UserID, req.TenantID)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// #2934: budget-check stays reachable to non-admin callers (it is the
	// enforcement plane), but they only get the verdict — the tenant's
	// absolute spend figures are stripped.
	if SpendRedactionRequested(r.Context()) {
		decision.redactSpend()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// Helper functions

// callerOrgID / callerTenantID resolve the caller's org/tenant scope for the
// by-id budget routes (#2934). Behind the agent gateway the headers are Set
// (not Add) from the cryptographically validated license, so a governed
// caller cannot pick another org; the query-param fallback matches
// ListBudgets' existing semantics for direct in-VPC callers.
func (h *Handler) callerOrgID(r *http.Request) string {
	return firstOrDefault(r.Header.Get("X-Org-ID"), r.URL.Query().Get("org_id"))
}

func (h *Handler) callerTenantID(r *http.Request) string {
	return firstOrDefault(r.Header.Get("X-Tenant-ID"), r.URL.Query().Get("tenant_id"))
}

// setCORSHeaders sets CORS headers on all responses (not just OPTIONS)
func (h *Handler) setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Org-ID, X-Tenant-ID, X-User-ID, Authorization")
}

func (h *Handler) writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   http.StatusText(status),
		"message": message,
	})
}

func firstOrDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
