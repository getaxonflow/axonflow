// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// AccuracyHandler handles HTTP requests for accuracy tracking.
type AccuracyHandler struct {
	service *AccuracyService
}

// NewAccuracyHandler creates a new accuracy handler.
func NewAccuracyHandler(service *AccuracyService) *AccuracyHandler {
	return &AccuracyHandler{service: service}
}

// RegisterRoutes registers accuracy routes on the given mux.
func (h *AccuracyHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/euaiact/accuracy", h.handleAccuracy)
	mux.HandleFunc("/api/v1/euaiact/accuracy/record", h.handleRecordMetric)
	mux.HandleFunc("/api/v1/euaiact/accuracy/bias", h.handleRecordBias)
	mux.HandleFunc("/api/v1/euaiact/accuracy/history", h.handleAccuracyHistory)
	mux.HandleFunc("/api/v1/euaiact/accuracy/alerts", h.handleAlerts)
	mux.HandleFunc("/api/v1/euaiact/accuracy/alerts/", h.handleAlertByID)
}

// handleAccuracy handles GET /api/v1/euaiact/accuracy.
func (h *AccuracyHandler) handleAccuracy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	summary, err := h.service.GetAccuracySummary(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, summary)
}

// handleRecordMetric handles POST /api/v1/euaiact/accuracy/record.
func (h *AccuracyHandler) handleRecordMetric(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	var req RecordAccuracyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	// Parse dates
	var windowStart, windowEnd time.Time
	if req.WindowStart != "" {
		var err error
		windowStart, err = time.Parse(time.RFC3339, req.WindowStart)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid window_start format, use RFC3339")
			return
		}
	}
	if req.WindowEnd != "" {
		var err error
		windowEnd, err = time.Parse(time.RFC3339, req.WindowEnd)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid window_end format, use RFC3339")
			return
		}
	}

	input := RecordMetricInput{
		OrgID:       orgID,
		ModelID:     req.ModelID,
		MetricType:  MetricType(req.MetricType),
		Value:       req.Value,
		SampleSize:  req.SampleSize,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
		Metadata:    req.Metadata,
	}

	metric, err := h.service.RecordMetric(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, metric)
}

// handleRecordBias handles POST /api/v1/euaiact/accuracy/bias.
func (h *AccuracyHandler) handleRecordBias(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	var req RecordBiasRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	// Parse dates
	var windowStart, windowEnd time.Time
	if req.WindowStart != "" {
		var err error
		windowStart, err = time.Parse(time.RFC3339, req.WindowStart)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid window_start format, use RFC3339")
			return
		}
	}
	if req.WindowEnd != "" {
		var err error
		windowEnd, err = time.Parse(time.RFC3339, req.WindowEnd)
		if err != nil {
			writeError(w, http.StatusBadRequest, "Invalid window_end format, use RFC3339")
			return
		}
	}

	input := RecordBiasInput{
		OrgID:       orgID,
		ModelID:     req.ModelID,
		Category:    BiasCategory(req.Category),
		GroupA:      req.GroupA,
		GroupB:      req.GroupB,
		GroupARate:  req.GroupARate,
		GroupBRate:  req.GroupBRate,
		SampleSize:  req.SampleSize,
		WindowStart: windowStart,
		WindowEnd:   windowEnd,
		Metadata:    req.Metadata,
	}

	record, err := h.service.RecordBias(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, record)
}

// handleAccuracyHistory handles GET /api/v1/euaiact/accuracy/history.
func (h *AccuracyHandler) handleAccuracyHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	params := AccuracyMetricsParams{
		ModelID:    r.URL.Query().Get("model_id"),
		MetricType: r.URL.Query().Get("metric_type"),
		From:       r.URL.Query().Get("from"),
		To:         r.URL.Query().Get("to"),
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		limit, err := strconv.Atoi(limitStr)
		if err == nil && limit > 0 && limit <= MaxListLimit {
			params.Limit = limit
		}
	}
	if params.Limit == 0 {
		params.Limit = DefaultMetricsListLimit
	}

	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		offset, err := strconv.Atoi(offsetStr)
		if err == nil && offset >= 0 {
			params.Offset = offset
		}
	}

	metrics, total, err := h.service.GetMetrics(r.Context(), orgID, params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	response := map[string]interface{}{
		"metrics": metrics,
		"total":   total,
		"limit":   params.Limit,
		"offset":  params.Offset,
	}

	writeJSON(w, http.StatusOK, response)
}

// handleAlerts handles GET /api/v1/euaiact/accuracy/alerts.
func (h *AccuracyHandler) handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	orgID := getOrgIDFromRequest(r)
	if orgID == "" {
		writeError(w, http.StatusBadRequest, "X-Org-ID or X-Tenant-ID header required")
		return
	}

	alerts, err := h.service.GetActiveAlerts(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"total":  len(alerts),
	})
}

// handleAlertByID handles operations on a specific alert.
func (h *AccuracyHandler) handleAlertByID(w http.ResponseWriter, r *http.Request) {
	// Extract path after /api/v1/euaiact/accuracy/alerts/
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/euaiact/accuracy/alerts/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Alert ID required", http.StatusBadRequest)
		return
	}

	alertID := parts[0]

	// Check for action
	var action string
	if len(parts) > 1 {
		action = parts[1]
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "system"
	}

	switch action {
	case "acknowledge":
		if err := h.service.AcknowledgeAlert(r.Context(), alertID, userID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})

	case "resolve":
		if err := h.service.ResolveAlert(r.Context(), alertID, userID); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})

	default:
		http.Error(w, "Invalid action, use 'acknowledge' or 'resolve'", http.StatusBadRequest)
	}
}
