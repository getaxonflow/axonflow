// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/tenantscope"
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

	scope, ok := h.requireScope(w, r)
	if !ok {
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
		// #3065: stamped from the bound scope, so a budget can never be
		// persisted with the empty org that made it everyone's row.
		OrgID:     scope.OrgID,
		TenantID:  scope.TenantID,
		CreatedBy: r.Header.Get("X-User-ID"),
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

	// #3065: the listing scope is the AUTHENTICATED scope. It used to fall
	// back to `?org_id=` / `?tenant_id=`, and an omitted value disabled the
	// SQL predicate entirely — so an unscoped call listed every tenant's
	// budgets.
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	opts := ListBudgetsOptions{
		OrgID:    scope.OrgID,
		TenantID: scope.TenantID,
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	budget, err := h.service.GetBudgetScoped(r.Context(), budgetID, scope.OrgID, scope.TenantID)
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

	scope, ok := h.requireScope(w, r)
	if !ok {
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
	existing, err := h.service.GetBudgetScoped(r.Context(), budgetID, scope.OrgID, scope.TenantID)
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	if err := h.service.DeleteBudgetScoped(r.Context(), budgetID, scope.OrgID, scope.TenantID); err != nil {
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	budgetID := vars["id"]
	if budgetID == "" {
		h.writeError(w, "Budget ID required", http.StatusBadRequest)
		return
	}

	status, err := h.service.GetBudgetStatusScoped(r.Context(), budgetID, scope.OrgID, scope.TenantID)
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

	scope, ok := h.requireScope(w, r)
	if !ok {
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

	alerts, err := h.service.GetRecentAlertsScoped(r.Context(), budgetID, scope.OrgID, scope.TenantID, limit)
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()

	opts := UsageQueryOptions{
		// #3065: authenticated scope only — the `?org_id=` / `?tenant_id=`
		// fallback let a direct caller name the tenancy it wanted to read.
		OrgID:    scope.OrgID,
		TenantID: scope.TenantID,
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()

	groupBy := query.Get("group_by")
	if groupBy == "" {
		groupBy = "provider"
	}

	opts := UsageQueryOptions{
		// #3065: authenticated scope only — the `?org_id=` / `?tenant_id=`
		// fallback let a direct caller name the tenancy it wanted to read.
		OrgID:    scope.OrgID,
		TenantID: scope.TenantID,
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

	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	query := r.URL.Query()

	opts := UsageQueryOptions{
		// #3065: authenticated scope only — the `?org_id=` / `?tenant_id=`
		// fallback let a direct caller name the tenancy it wanted to read.
		OrgID:    scope.OrgID,
		TenantID: scope.TenantID,
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

	// #2934 established that the body org_id/tenant_id are a forgeable channel
	// on this endpoint — a caller could POST another org's id and, even with
	// spend figures redacted, learn its budget name + exceeded status. Its fix
	// pinned the check to the authenticated headers ONLY when
	// SpendRedactionRequested(ctx) was true, i.e. only for callers the
	// read-authority middleware had already marked as non-tenant-wide.
	//
	// #3065 (R3 round 1): that flag defaults to FALSE. A tenant-wide caller —
	// or any request that reaches this handler without that middleware — still
	// selected its own scope from the request body and received another org's
	// budget_name / limit_usd / used_usd / percentage UNREDACTED. Body-
	// selectable tenancy is this issue's own class, so the scope is now the
	// authenticated scope, unconditionally. The body fields are ignored.
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	var req CheckBudgetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	req.OrgID = scope.OrgID
	req.TenantID = scope.TenantID

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

// requireScope resolves the caller's authenticated org/tenant for the by-id
// budget routes, writing a 401 and returning ok=false when there is none.
//
// #3065 (F4): this replaces callerOrgID / callerTenantID, which read
//
//	firstOrDefault(r.Header.Get("X-Org-ID"), r.URL.Query().Get("org_id"))
//
// — a QUERY PARAMETER fallback. Combined with the fail-open SQL predicate
// that used to sit in budgetOrgScopeSQL, a caller who supplied neither the
// header nor the parameter matched every budget row: `DELETE
// /api/v1/budgets/{id}` deleted another tenant's budget. Behind the agent
// gateway (and the customer portal proxy) both headers are Set from a
// validated credential on every request, so nothing legitimate depended on
// the parameter; only a direct in-VPC caller could reach it, which is exactly
// the caller that must not choose its own org.
func (h *Handler) requireScope(w http.ResponseWriter, r *http.Request) (tenantscope.Scope, bool) {
	scope, err := tenantscope.Bind(r)
	if err != nil {
		h.writeError(w, "Missing tenant or org identity", http.StatusUnauthorized)
		return tenantscope.Scope{}, false
	}
	return scope, true
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
