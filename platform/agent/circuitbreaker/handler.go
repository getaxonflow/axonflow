// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - Circuit Breaker HTTP Handler
// EU AI Act Article 14: Human Oversight API

//go:build enterprise

package circuitbreaker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics for handler
var (
	handlerRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_circuit_breaker_api_requests_total",
			Help: "Total number of circuit breaker API requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	handlerRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_circuit_breaker_api_duration_seconds",
			Help:    "Circuit breaker API request duration",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(handlerRequestsTotal)
	prometheus.MustRegister(handlerRequestDuration)
}

// Handler provides HTTP handlers for circuit breaker operations
type Handler struct {
	cb    *CircuitBreaker
	notif *NotificationService
}

// NewHandler creates a new circuit breaker handler
func NewHandler(cb *CircuitBreaker) *Handler {
	return &Handler{cb: cb}
}

// SetNotificationService sets the notification service for CRUD endpoints
func (h *Handler) SetNotificationService(ns *NotificationService) {
	h.notif = ns
}

// RegisterRoutes registers circuit breaker routes
func (h *Handler) RegisterRoutes(r *mux.Router, middlewares ...mux.MiddlewareFunc) {
	// Create a subrouter so middleware applies to all circuit breaker routes
	sub := r.PathPrefix("/api/v1/circuit-breaker").Subrouter()
	for _, mw := range middlewares {
		sub.Use(mw)
	}

	// Emergency stop (Article 14 compliance)
	sub.HandleFunc("/trip", h.Trip).Methods("POST")
	sub.HandleFunc("/reset", h.Reset).Methods("POST")
	sub.HandleFunc("/check", h.Check).Methods("POST")
	sub.HandleFunc("/status", h.Status).Methods("GET")
	sub.HandleFunc("/history", h.History).Methods("GET")

	// Per-tenant config (#1176 Phase 2B)
	sub.HandleFunc("/config", h.GetConfig).Methods("GET")
	sub.HandleFunc("/config", h.UpdateConfig).Methods("PUT")

	// Notification CRUD (#1176 Phase 2B)
	sub.HandleFunc("/notifications", h.ListNotifications).Methods("GET")
	sub.HandleFunc("/notifications", h.CreateNotification).Methods("POST")
	sub.HandleFunc("/notifications/{id}", h.UpdateNotification).Methods("PUT")
	sub.HandleFunc("/notifications/{id}", h.DeleteNotification).Methods("DELETE")

	// Emergency stop aliases (clearer naming for Article 14)
	// These share the same subrouter prefix, so register on a separate auth-protected subrouter
	emergSub := r.PathPrefix("/api/v1/emergency-stop").Subrouter()
	for _, mw := range middlewares {
		emergSub.Use(mw)
	}
	emergSub.HandleFunc("", h.Trip).Methods("POST")
	emergSub.HandleFunc("/release", h.Reset).Methods("POST")
}

// APIResponse is the standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// TripRequest is the request body for tripping a circuit
type TripRequest struct {
	Scope          string `json:"scope"`           // global, tenant, client, policy
	ScopeID        string `json:"scope_id"`        // ID for non-global scopes
	Reason         string `json:"reason"`          // manual, policy_violation, risk_level, error_rate
	Comment        string `json:"comment"`         // Required for audit trail
	DurationMinutes int   `json:"duration_minutes"` // 0 = indefinite
}

// Trip handles POST /api/v1/circuit-breaker/trip
// Emergency stop - immediately halt AI operations
func (h *Handler) Trip(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("POST", "/api/v1/circuit-breaker/trip").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	userID := r.Header.Get("X-User-ID")
	userEmail := r.Header.Get("X-User-Email")

	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}
	if userID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-User-ID header (required for Article 14 audit trail)")
		return
	}

	var req TripRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Default to global scope
	scope := ScopeGlobal
	if req.Scope != "" {
		scope = Scope(req.Scope)
	}

	// Validate scope
	validScopes := map[Scope]bool{
		ScopeGlobal: true,
		ScopeTenant: true,
		ScopeClient: true,
		ScopePolicy: true,
	}
	if !validScopes[scope] {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid scope: %s", req.Scope))
		return
	}

	// Non-global scopes require scope_id
	if scope != ScopeGlobal && req.ScopeID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "scope_id required for non-global scope")
		return
	}

	// Reason defaults to manual
	reason := ReasonManual
	if req.Reason != "" {
		reason = TripReason(req.Reason)
	}

	// Calculate duration
	var duration time.Duration
	if req.DurationMinutes > 0 {
		duration = time.Duration(req.DurationMinutes) * time.Minute
	}

	circuit, err := h.cb.Trip(r.Context(), TripInput{
		OrgID:          orgID,
		Scope:          scope,
		ScopeID:        req.ScopeID,
		Reason:         reason,
		TrippedBy:      userID,
		TrippedByEmail: userEmail,
		Comment:        req.Comment,
		Duration:       duration,
	})
	if err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/trip", "success").Inc()
	h.writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"circuit_id": circuit.ID,
			"state":      circuit.State,
			"scope":      circuit.Scope,
			"scope_id":   circuit.ScopeID,
			"tripped_at": circuit.TrippedAt,
			"expires_at": circuit.ExpiresAt,
			"message":    "Emergency stop activated. All matching requests will be blocked.",
		},
	})
}

// ResetRequest is the request body for resetting a circuit
type ResetRequest struct {
	Scope   string `json:"scope"`
	ScopeID string `json:"scope_id"`
	Comment string `json:"comment"`
}

// Reset handles POST /api/v1/circuit-breaker/reset
// Release emergency stop - resume normal operations
func (h *Handler) Reset(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("POST", "/api/v1/circuit-breaker/reset").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	userID := r.Header.Get("X-User-ID")

	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/reset", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}
	if userID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/reset", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-User-ID header (required for audit trail)")
		return
	}

	var req ResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/reset", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	scope := ScopeGlobal
	if req.Scope != "" {
		scope = Scope(req.Scope)
	}

	err := h.cb.Reset(r.Context(), ResetInput{
		OrgID:   orgID,
		Scope:   scope,
		ScopeID: req.ScopeID,
		ResetBy: userID,
		Comment: req.Comment,
	})
	if err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/reset", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/reset", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"scope":    scope,
			"scope_id": req.ScopeID,
			"state":    "closed",
			"message":  "Circuit reset. Normal operations resumed.",
		},
	})
}

// CheckRequest is the request body for checking circuit state
type CheckRequest struct {
	TenantID string `json:"tenant_id"`
	ClientID string `json:"client_id"`
	PolicyID string `json:"policy_id"`
}

// Check handles POST /api/v1/circuit-breaker/check
// Check if a request should be allowed
func (h *Handler) Check(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("POST", "/api/v1/circuit-breaker/check").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/check", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/check", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	result, err := h.cb.Check(r.Context(), CheckInput{
		OrgID:    orgID,
		TenantID: req.TenantID,
		ClientID: req.ClientID,
		PolicyID: req.PolicyID,
	})
	if err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/check", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/check", "success").Inc()

	if result.Allowed {
		h.writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"allowed": true,
			},
		})
	} else {
		h.writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"allowed":    false,
				"circuit_id": result.CircuitID,
				"scope":      result.Scope,
				"scope_id":   result.ScopeID,
				"reason":     result.Reason,
				"tripped_by": result.TrippedBy,
				"tripped_at": result.TrippedAt,
				"expires_at": result.ExpiresAt,
				"comment":    result.Comment,
			},
		})
	}
}

// Status handles GET /api/v1/circuit-breaker/status
// Get all active circuits for an org
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("GET", "/api/v1/circuit-breaker/status").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/status", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	circuits, err := h.cb.GetActiveCircuits(r.Context(), orgID)
	if err != nil {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/status", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/status", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"active_circuits": circuits,
			"count":           len(circuits),
			"emergency_stop_active": len(circuits) > 0,
		},
	})
}

// History handles GET /api/v1/circuit-breaker/history
// Get circuit breaker history for audit
func (h *Handler) History(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("GET", "/api/v1/circuit-breaker/history").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/history", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	circuits, err := h.cb.GetCircuitHistory(r.Context(), orgID, limit)
	if err != nil {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/history", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/history", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"history": circuits,
			"count":   len(circuits),
		},
	})
}

// --- Notification CRUD handlers ---

// NotificationCreateRequest is the request body for creating a notification config
type NotificationCreateRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	Secret   string `json:"secret,omitempty"`
	Active   *bool  `json:"active,omitempty"`
}

// NotificationUpdateRequest is the request body for updating a notification config
type NotificationUpdateRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
	Type     string `json:"type,omitempty"`
	URL      string `json:"url,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Active   *bool  `json:"active,omitempty"`
}

// ListNotifications handles GET /api/v1/circuit-breaker/notifications
func (h *Handler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("GET", "/api/v1/circuit-breaker/notifications").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	configs, err := h.cb.repo.GetNotificationConfigs(r.Context(), orgID)
	if err != nil {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Mask secrets in response
	for _, c := range configs {
		if c.Secret != "" {
			c.Secret = "***"
		}
	}

	handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/notifications", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"notifications": configs,
			"count":         len(configs),
		},
	})
}

// CreateNotification handles POST /api/v1/circuit-breaker/notifications
func (h *Handler) CreateNotification(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	var req NotificationCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Validate type
	validTypes := map[string]bool{"webhook": true, "slack": true, "pagerduty": true}
	if !validTypes[req.Type] {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "type must be one of: webhook, slack, pagerduty")
		return
	}

	if req.URL == "" {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "url is required")
		return
	}

	if !isValidURL(req.URL) {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "url must be a valid HTTP/HTTPS URL")
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	config := &NotificationConfig{
		OrgID:    orgID,
		TenantID: req.TenantID,
		Type:     NotificationType(req.Type),
		URL:      req.URL,
		Secret:   req.Secret,
		Active:   active,
	}

	if err := h.cb.repo.CreateNotificationConfig(r.Context(), config); err != nil {
		handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("POST", "/api/v1/circuit-breaker/notifications", "success").Inc()
	h.writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"id":      config.ID,
			"type":    config.Type,
			"url":     config.URL,
			"active":  config.Active,
			"message": "Notification config created",
		},
	})
}

// UpdateNotification handles PUT /api/v1/circuit-breaker/notifications/{id}
func (h *Handler) UpdateNotification(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	var req NotificationUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Fetch existing config
	existing, err := h.cb.repo.GetNotificationConfig(r.Context(), id, orgID)
	if err != nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusNotFound, "notification config not found")
		return
	}

	// Apply updates
	if req.Type != "" {
		validTypes := map[string]bool{"webhook": true, "slack": true, "pagerduty": true}
		if !validTypes[req.Type] {
			handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
			h.writeError(w, http.StatusBadRequest, "type must be one of: webhook, slack, pagerduty")
			return
		}
		existing.Type = NotificationType(req.Type)
	}
	if req.URL != "" {
		if !isValidURL(req.URL) {
			handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
			h.writeError(w, http.StatusBadRequest, "url must be a valid HTTP/HTTPS URL")
			return
		}
		existing.URL = req.URL
	}
	if req.Secret != "" {
		existing.Secret = req.Secret
	}
	if req.Active != nil {
		existing.Active = *req.Active
	}
	if req.TenantID != "" {
		existing.TenantID = req.TenantID
	}

	if err := h.cb.repo.UpdateNotificationConfig(r.Context(), existing); err != nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/notifications/{id}", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"id":      existing.ID,
			"message": "Notification config updated",
		},
	})
}

// DeleteNotification handles DELETE /api/v1/circuit-breaker/notifications/{id}
func (h *Handler) DeleteNotification(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("DELETE", "/api/v1/circuit-breaker/notifications/{id}").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("DELETE", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	vars := mux.Vars(r)
	id := vars["id"]

	if err := h.cb.repo.DeleteNotificationConfig(r.Context(), id, orgID); err != nil {
		handlerRequestsTotal.WithLabelValues("DELETE", "/api/v1/circuit-breaker/notifications/{id}", "error").Inc()
		if err.Error() == "notification config not found" {
			h.writeError(w, http.StatusNotFound, err.Error())
		} else {
			h.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	handlerRequestsTotal.WithLabelValues("DELETE", "/api/v1/circuit-breaker/notifications/{id}", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"id":      id,
			"message": "Notification config deleted",
		},
	})
}

// ConfigUpdateRequest is the request body for updating tenant config
type ConfigUpdateRequest struct {
	TenantID              string `json:"tenant_id"`
	ErrorThreshold        *int   `json:"error_threshold,omitempty"`
	ViolationThreshold    *int   `json:"violation_threshold,omitempty"`
	WindowSeconds         *int   `json:"window_seconds,omitempty"`
	DefaultTimeoutSeconds *int   `json:"default_timeout_seconds,omitempty"`
	MaxTimeoutSeconds     *int   `json:"max_timeout_seconds,omitempty"`
	EnableAutoRecovery    *bool  `json:"enable_auto_recovery,omitempty"`
}

// GetConfig handles GET /api/v1/circuit-breaker/config
// Returns effective config for a tenant, or global defaults if no tenant_id
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("GET", "/api/v1/circuit-breaker/config").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")
	if tenantID == "" {
		// Return global defaults
		globalConfig := h.cb.GetConfig()
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/config", "success").Inc()
		h.writeJSON(w, http.StatusOK, APIResponse{
			Success: true,
			Data: map[string]interface{}{
				"source":                  "global",
				"error_threshold":         globalConfig.ErrorThreshold,
				"violation_threshold":     globalConfig.PolicyViolationThreshold,
				"window_seconds":          int(globalConfig.PolicyViolationWindow.Seconds()),
				"default_timeout_seconds": int(globalConfig.DefaultTimeout.Seconds()),
				"max_timeout_seconds":     int(globalConfig.MaxTimeout.Seconds()),
				"enable_auto_recovery":    globalConfig.EnableAutoRecovery,
			},
		})
		return
	}

	// Return tenant-specific config (with global fallbacks noted)
	tc, err := h.cb.GetTenantConfig(r.Context(), orgID, tenantID)
	if err != nil {
		handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	globalConfig := h.cb.GetConfig()
	data := map[string]interface{}{
		"tenant_id":               tenantID,
		"error_threshold":         globalConfig.ErrorThreshold,
		"violation_threshold":     globalConfig.PolicyViolationThreshold,
		"window_seconds":          int(globalConfig.PolicyViolationWindow.Seconds()),
		"default_timeout_seconds": int(globalConfig.DefaultTimeout.Seconds()),
		"max_timeout_seconds":     int(globalConfig.MaxTimeout.Seconds()),
		"enable_auto_recovery":    globalConfig.EnableAutoRecovery,
	}

	if tc != nil {
		data["source"] = "tenant"
		data["overrides"] = tc
		// Apply overrides for display
		if tc.ErrorThreshold != nil {
			data["error_threshold"] = *tc.ErrorThreshold
		}
		if tc.ViolationThreshold != nil {
			data["violation_threshold"] = *tc.ViolationThreshold
		}
		if tc.WindowSeconds != nil {
			data["window_seconds"] = *tc.WindowSeconds
		}
		if tc.DefaultTimeoutSeconds != nil {
			data["default_timeout_seconds"] = *tc.DefaultTimeoutSeconds
		}
		if tc.MaxTimeoutSeconds != nil {
			data["max_timeout_seconds"] = *tc.MaxTimeoutSeconds
		}
		if tc.EnableAutoRecovery != nil {
			data["enable_auto_recovery"] = *tc.EnableAutoRecovery
		}
	} else {
		data["source"] = "global"
	}

	handlerRequestsTotal.WithLabelValues("GET", "/api/v1/circuit-breaker/config", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// UpdateConfig handles PUT /api/v1/circuit-breaker/config
// Updates per-tenant circuit breaker config overrides
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		handlerRequestDuration.WithLabelValues("PUT", "/api/v1/circuit-breaker/config").Observe(time.Since(start).Seconds())
	}()

	orgID := resolveOrgID(r)
	if orgID == "" {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	var req ConfigUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	if req.TenantID == "" {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "tenant_id is required")
		return
	}

	// Validate threshold bounds to prevent panics in eventWindow (maxSize = 2*threshold)
	if req.ErrorThreshold != nil && *req.ErrorThreshold < 1 {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "error_threshold must be at least 1")
		return
	}
	if req.ViolationThreshold != nil && *req.ViolationThreshold < 1 {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "violation_threshold must be at least 1")
		return
	}
	if req.WindowSeconds != nil && *req.WindowSeconds < 1 {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "window_seconds must be at least 1")
		return
	}
	if req.DefaultTimeoutSeconds != nil && *req.DefaultTimeoutSeconds < 1 {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "default_timeout_seconds must be at least 1")
		return
	}
	if req.MaxTimeoutSeconds != nil && *req.MaxTimeoutSeconds < 1 {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "max_timeout_seconds must be at least 1")
		return
	}

	tc := &TenantConfig{
		OrgID:                 orgID,
		TenantID:              req.TenantID,
		ErrorThreshold:        req.ErrorThreshold,
		ViolationThreshold:    req.ViolationThreshold,
		WindowSeconds:         req.WindowSeconds,
		DefaultTimeoutSeconds: req.DefaultTimeoutSeconds,
		MaxTimeoutSeconds:     req.MaxTimeoutSeconds,
		EnableAutoRecovery:    req.EnableAutoRecovery,
	}

	if err := h.cb.UpsertTenantConfig(r.Context(), tc); err != nil {
		handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	handlerRequestsTotal.WithLabelValues("PUT", "/api/v1/circuit-breaker/config", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data: map[string]interface{}{
			"tenant_id": req.TenantID,
			"message":   "Circuit breaker config updated for tenant",
		},
	})
}

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// resolveOrgID extracts org ID from request headers.
// Falls back to X-Tenant-ID if X-Org-ID is not set, since in most
// deployments the client ID serves as both tenant and org identifier.
func resolveOrgID(r *http.Request) string {
	// Headers are set by apiAuthMiddleware from OAuth2 credentials
	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	return orgID
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, APIResponse{
		Success: false,
		Error:   message,
	})
}
