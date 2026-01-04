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

// RegisterRoutes registers all cost control routes with a gorilla/mux router
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Budget endpoints
	r.HandleFunc("/api/v1/budgets", h.CreateBudget).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/budgets", h.ListBudgets).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/check", h.CheckBudget).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.GetBudget).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.UpdateBudget).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}", h.DeleteBudget).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}/status", h.GetBudgetStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/budgets/{id}/alerts", h.GetBudgetAlerts).Methods("GET", "OPTIONS")

	// Usage endpoints
	r.HandleFunc("/api/v1/usage", h.GetUsageSummary).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/usage/breakdown", h.GetUsageBreakdown).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/usage/records", h.ListUsageRecords).Methods("GET", "OPTIONS")

	// Pricing endpoint
	r.HandleFunc("/api/v1/pricing", h.GetPricing).Methods("GET", "OPTIONS")
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

	budget, err := h.service.GetBudget(r.Context(), budgetID)
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

	// First, fetch the existing budget
	existing, err := h.service.GetBudget(r.Context(), budgetID)
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

	if err := h.service.DeleteBudget(r.Context(), budgetID); err != nil {
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

	status, err := h.service.GetBudgetStatus(r.Context(), budgetID)
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

	alerts, err := h.service.GetRecentAlerts(r.Context(), budgetID, limit)
	if err != nil {
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

	decision, err := h.service.CheckBudget(r.Context(), req.OrgID, req.TeamID, req.AgentID, req.UserID, req.TenantID)
	if err != nil {
		h.writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

// Helper functions

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
