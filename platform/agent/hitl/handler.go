// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Enterprise Edition - HITL Queue HTTP Handler
// EU AI Act Article 14 - Human Oversight REST API

//go:build enterprise

package hitl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics for HITL API
var (
	hitlRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_hitl_requests_total",
			Help: "Total number of HITL API requests",
		},
		[]string{"method", "endpoint", "status"},
	)
	hitlRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_hitl_request_duration_seconds",
			Help:    "HITL API request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint"},
	)
	hitlPendingGauge = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "axonflow_hitl_pending_requests",
			Help: "Number of pending HITL approval requests",
		},
		[]string{"org_id", "severity"},
	)
)

func init() {
	prometheus.MustRegister(hitlRequestsTotal)
	prometheus.MustRegister(hitlRequestDuration)
	prometheus.MustRegister(hitlPendingGauge)
}

// Handler provides HTTP handlers for HITL queue operations.
type Handler struct {
	service *Service
}

// NewHandler creates a new HITL handler.
func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

// RegisterRoutes registers HITL routes with a mux router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Queue management
	r.HandleFunc("/api/v1/hitl/queue", h.ListRequests).Methods("GET")
	r.HandleFunc("/api/v1/hitl/queue", h.CreateRequest).Methods("POST")
	r.HandleFunc("/api/v1/hitl/queue/{id}", h.GetRequest).Methods("GET")
	r.HandleFunc("/api/v1/hitl/queue/{id}/approve", h.ApproveRequest).Methods("POST")
	r.HandleFunc("/api/v1/hitl/queue/{id}/reject", h.RejectRequest).Methods("POST")
	r.HandleFunc("/api/v1/hitl/queue/{id}/override", h.OverrideRequest).Methods("POST")
	r.HandleFunc("/api/v1/hitl/queue/{id}/history", h.GetRequestHistory).Methods("GET")

	// Dashboard & metrics
	r.HandleFunc("/api/v1/hitl/stats", h.GetStats).Methods("GET")
	r.HandleFunc("/api/v1/hitl/status", h.GetStatus).Methods("GET")
	r.HandleFunc("/api/v1/hitl/expire", h.ExpireStale).Methods("POST")
}

// CreateRequestInput is the JSON input for creating an approval request.
type CreateRequestInput struct {
	ClientID            string                 `json:"client_id"`
	UserID              string                 `json:"user_id,omitempty"`
	OriginalQuery       string                 `json:"original_query"`
	RequestType         string                 `json:"request_type"`
	RequestContext      map[string]interface{} `json:"request_context,omitempty"`
	TriggeredPolicyID   string                 `json:"triggered_policy_id"`
	TriggeredPolicyName string                 `json:"triggered_policy_name"`
	TriggerReason       string                 `json:"trigger_reason"`
	Severity            string                 `json:"severity,omitempty"`
	EUAIActArticle      string                 `json:"eu_ai_act_article,omitempty"`
	ComplianceFramework string                 `json:"compliance_framework,omitempty"`
	RiskClassification  string                 `json:"risk_classification,omitempty"`
	ExpiresInSeconds    int                    `json:"expires_in_seconds,omitempty"`
}

// ReviewInput is the JSON input for approving/rejecting a request.
type ReviewInput struct {
	ReviewerID    string `json:"reviewer_id"`
	ReviewerEmail string `json:"reviewer_email"`
	ReviewerRole  string `json:"reviewer_role,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

// OverrideInput is the JSON input for overriding a request.
type OverrideInput struct {
	Justification    string `json:"justification"`
	AuthorizedByID   string `json:"authorized_by_id"`
	AuthorizedByEmail string `json:"authorized_by_email"`
	AuthorizedByRole string `json:"authorized_by_role,omitempty"`
}

// APIResponse is the standard API response structure.
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    *MetaInfo   `json:"meta,omitempty"`
}

// MetaInfo provides pagination and additional metadata.
type MetaInfo struct {
	Total  int64 `json:"total,omitempty"`
	Limit  int   `json:"limit,omitempty"`
	Offset int   `json:"offset,omitempty"`
}

// ListRequests handles GET /api/v1/hitl/queue
func (h *Handler) ListRequests(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("GET", "/api/v1/hitl/queue").Observe(time.Since(start).Seconds())
	}()

	// Parse query parameters
	filter := ListFilter{
		Limit:    parseInt(r.URL.Query().Get("limit"), 50),
		Offset:   parseInt(r.URL.Query().Get("offset"), 0),
		OrderBy:  r.URL.Query().Get("order_by"),
		OrderDir: r.URL.Query().Get("order_dir"),
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filter.Status = strings.Split(status, ",")
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = strings.Split(severity, ",")
	}
	filter.PolicyID = r.URL.Query().Get("policy_id")
	filter.ClientID = r.URL.Query().Get("client_id")
	filter.UserID = r.URL.Query().Get("user_id")

	requests, total, err := h.service.ListApprovalRequests(r.Context(), filter)
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    requests,
		Meta: &MetaInfo{
			Total:  total,
			Limit:  filter.Limit,
			Offset: filter.Offset,
		},
	})
}

// CreateRequest handles POST /api/v1/hitl/queue
func (h *Handler) CreateRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("POST", "/api/v1/hitl/queue").Observe(time.Since(start).Seconds())
	}()

	// Get org/tenant from headers (set by auth middleware)
	orgID := r.Header.Get("X-Org-ID")
	tenantID := r.Header.Get("X-Tenant-ID")
	if orgID == "" || tenantID == "" {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID or X-Tenant-ID header")
		return
	}

	var input CreateRequestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	createInput := CreateApprovalInput{
		OrgID:               orgID,
		TenantID:            tenantID,
		ClientID:            input.ClientID,
		UserID:              input.UserID,
		OriginalQuery:       input.OriginalQuery,
		RequestType:         input.RequestType,
		RequestContext:      input.RequestContext,
		TriggeredPolicyID:   input.TriggeredPolicyID,
		TriggeredPolicyName: input.TriggeredPolicyName,
		TriggerReason:       input.TriggerReason,
		Severity:            input.Severity,
		EUAIActArticle:      input.EUAIActArticle,
		ComplianceFramework: input.ComplianceFramework,
		RiskClassification:  input.RiskClassification,
	}
	if input.ExpiresInSeconds > 0 {
		createInput.ExpiresIn = time.Duration(input.ExpiresInSeconds) * time.Second
	}

	req, err := h.service.CreateApprovalRequest(r.Context(), createInput)
	if err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue", "error").Inc()
		switch {
		case errors.Is(err, ErrHITLApprovalDisabledByTier):
			// 403 Forbidden — tier gate; the request shape is fine, the
			// running license tier is what's denying it. Surfaces a clear
			// upgrade pointer in the body.
			h.writeError(w, http.StatusForbidden, err.Error())
		case errors.Is(err, ErrPendingApprovalLimitExceeded):
			h.writeError(w, http.StatusTooManyRequests, err.Error())
		default:
			h.writeError(w, http.StatusBadRequest, err.Error())
		}
		return
	}

	hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue", "success").Inc()
	h.writeJSON(w, http.StatusCreated, APIResponse{
		Success: true,
		Data:    req,
	})
}

// GetRequest handles GET /api/v1/hitl/queue/{id}
func (h *Handler) GetRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("GET", "/api/v1/hitl/queue/{id}").Observe(time.Since(start).Seconds())
	}()

	vars := mux.Vars(r)
	requestID, err := uuid.Parse(vars["id"])
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	req, err := h.service.GetApprovalRequest(r.Context(), requestID)
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}", "error").Inc()
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, err.Error())
		} else {
			h.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    req,
	})
}

// ApproveRequest handles POST /api/v1/hitl/queue/{id}/approve
func (h *Handler) ApproveRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/approve").Observe(time.Since(start).Seconds())
	}()

	vars := mux.Vars(r)
	requestID, err := uuid.Parse(vars["id"])
	if err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/approve", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	var input ReviewInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/approve", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	reviewer := &Reviewer{
		ID:    input.ReviewerID,
		Email: input.ReviewerEmail,
		Role:  input.ReviewerRole,
		IP:    getClientIP(r),
	}

	if err := h.service.ApproveRequest(r.Context(), requestID, reviewer, input.Comment); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/approve", "error").Inc()
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "cannot approve") || strings.Contains(err.Error(), "expired") {
			h.writeError(w, http.StatusConflict, err.Error())
		} else {
			h.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/approve", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "approved"},
	})
}

// RejectRequest handles POST /api/v1/hitl/queue/{id}/reject
func (h *Handler) RejectRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/reject").Observe(time.Since(start).Seconds())
	}()

	vars := mux.Vars(r)
	requestID, err := uuid.Parse(vars["id"])
	if err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/reject", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	var input ReviewInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/reject", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	reviewer := &Reviewer{
		ID:    input.ReviewerID,
		Email: input.ReviewerEmail,
		Role:  input.ReviewerRole,
		IP:    getClientIP(r),
	}

	if err := h.service.RejectRequest(r.Context(), requestID, reviewer, input.Comment); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/reject", "error").Inc()
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "cannot reject") {
			h.writeError(w, http.StatusConflict, err.Error())
		} else {
			h.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/reject", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "rejected"},
	})
}

// OverrideRequest handles POST /api/v1/hitl/queue/{id}/override
func (h *Handler) OverrideRequest(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/override").Observe(time.Since(start).Seconds())
	}()

	vars := mux.Vars(r)
	requestID, err := uuid.Parse(vars["id"])
	if err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/override", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	var input OverrideInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/override", "error").Inc()
		h.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	authorizedBy := &Reviewer{
		ID:    input.AuthorizedByID,
		Email: input.AuthorizedByEmail,
		Role:  input.AuthorizedByRole,
		IP:    getClientIP(r),
	}

	if err := h.service.OverrideRequest(r.Context(), requestID, input.Justification, authorizedBy); err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/override", "error").Inc()
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, err.Error())
		} else if strings.Contains(err.Error(), "cannot override") || strings.Contains(err.Error(), "required") {
			h.writeError(w, http.StatusBadRequest, err.Error())
		} else {
			h.writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}

	hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/queue/{id}/override", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]string{"status": "overridden"},
	})
}

// GetRequestHistory handles GET /api/v1/hitl/queue/{id}/history
func (h *Handler) GetRequestHistory(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("GET", "/api/v1/hitl/queue/{id}/history").Observe(time.Since(start).Seconds())
	}()

	vars := mux.Vars(r)
	requestID, err := uuid.Parse(vars["id"])
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}/history", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "invalid request ID")
		return
	}

	history, err := h.service.GetRequestHistory(r.Context(), requestID)
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}/history", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/queue/{id}/history", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    history,
	})
}

// GetStats handles GET /api/v1/hitl/stats
func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("GET", "/api/v1/hitl/stats").Observe(time.Since(start).Seconds())
	}()

	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/stats", "error").Inc()
		h.writeError(w, http.StatusBadRequest, "missing X-Org-ID header")
		return
	}

	stats, err := h.service.GetPendingStats(r.Context(), orgID)
	if err != nil {
		hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/stats", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Update Prometheus gauges
	hitlPendingGauge.WithLabelValues(orgID, "high").Set(float64(stats.HighPriority))
	hitlPendingGauge.WithLabelValues(orgID, "critical").Set(float64(stats.CriticalPriority))
	hitlPendingGauge.WithLabelValues(orgID, "total").Set(float64(stats.TotalPending))

	hitlRequestsTotal.WithLabelValues("GET", "/api/v1/hitl/stats", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    stats,
	})
}

// ExpireStale handles POST /api/v1/hitl/expire (admin only)
func (h *Handler) ExpireStale(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		hitlRequestDuration.WithLabelValues("POST", "/api/v1/hitl/expire").Observe(time.Since(start).Seconds())
	}()

	count, err := h.service.ExpireStaleRequests(r.Context())
	if err != nil {
		hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/expire", "error").Inc()
		h.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hitlRequestsTotal.WithLabelValues("POST", "/api/v1/hitl/expire", "success").Inc()
	h.writeJSON(w, http.StatusOK, APIResponse{
		Success: true,
		Data:    map[string]int{"expired_count": count},
	})
}

// Helper functions

func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) writeError(w http.ResponseWriter, status int, message string) {
	h.writeJSON(w, status, APIResponse{
		Success: false,
		Error:   message,
	})
}

func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return val
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For first (for proxied requests)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return strings.Split(r.RemoteAddr, ":")[0]
}

// GetStatus returns the HITL feature status for the enterprise edition.
func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled": true,
		"mode":    "enterprise",
		"features": map[string]bool{
			"queue":           true,
			"approve_reject":  true,
			"override":        true,
			"expiration":      true,
			"audit_history":   true,
			"pending_summary": true,
		},
	})
}
