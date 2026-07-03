// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const evalDisclaimer = "NOT FOR REGULATORY SUBMISSION - EVALUATION LICENSE"

// EvidenceExportHandler handles evidence export and summary endpoints.
// Available to Evaluation tier and above.
type EvidenceExportHandler struct {
	db          *sql.DB
	tierChecker LicenseChecker
	rateLimiter *exportRateLimiter
}

// exportRateLimiter tracks daily export usage per tenant.
// NOTE: This is per-process in-memory state. In multi-replica deployments,
// each replica enforces its own limit independently.
type exportRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int // tenant → count
	resetAt time.Time      // when to reset (start of next UTC day)
}

var expRateLimiter = &exportRateLimiter{
	counts:  make(map[string]int),
	resetAt: nextUTCMidnight(),
}

func (rl *exportRateLimiter) tryConsume(tenantID string, limit int) (bool, int) {
	if limit < 0 { // unlimited (-1)
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Now().UTC().After(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = nextUTCMidnight()
	}

	current := rl.counts[tenantID]
	if current >= limit {
		return false, current
	}

	rl.counts[tenantID]++
	return true, current + 1
}

// resolveTenantOrFail resolves the tenant scope for a compliance/evidence
// request. The X-Tenant-ID header is the trusted, proxy-injected value (set by
// apiAuthMiddleware after authentication); the request context is a
// belt-and-braces fallback for paths that don't traverse the proxy.
//
// If neither produces a non-empty tenant, the function writes a 401 to w and
// returns "". Callers MUST early-return on the empty result. We fail closed:
// the alternative (running the SQL with `tenant_id = ”`) currently happens to
// return zero rows but quietly burns the daily export quota for an empty
// tenant bucket and would silently leak data the moment a downstream query
// stops filtering on tenant_id. Per #1623 retro: explicit 401, no implicit
// degrade.
func resolveTenantOrFail(w http.ResponseWriter, r *http.Request, endpoint string) string {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		if tid, ok := r.Context().Value("tenant_id").(string); ok {
			tenantID = tid
		}
	}
	if tenantID == "" {
		log.Printf("[%s] BLOCKED: tenant scope missing from X-Tenant-ID header and request context", endpoint)
		writeJSONError(w, http.StatusUnauthorized, "TENANT_REQUIRED",
			"X-Tenant-ID header is required for this endpoint (set by the AxonFlow Agent gateway).")
		return ""
	}
	return tenantID
}

// NewEvidenceExportHandler creates a new evidence export handler.
func NewEvidenceExportHandler(db *sql.DB, tierChecker LicenseChecker) *EvidenceExportHandler {
	return &EvidenceExportHandler{
		db:          db,
		tierChecker: tierChecker,
		rateLimiter: expRateLimiter,
	}
}

// RegisterRoutes registers evidence export endpoints.
func (h *EvidenceExportHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/evidence/export", h.ExportEvidence).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/evidence/summary", h.GetEvidenceSummary).Methods("GET", "OPTIONS")
}

// ExportEvidence handles POST /api/v1/evidence/export.
// Exports audit logs, workflow steps, and HITL approvals as a bundled JSON pack.
func (h *EvidenceExportHandler) ExportEvidence(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// License gate
	if !h.tierChecker.IsEvidenceExportEnabled() {
		writeJSONError(w, http.StatusForbidden, ErrCodeFeatureRequiresEvaluation,
			"Evidence export requires an Evaluation or Enterprise license. Get a free eval license: https://getaxonflow.com/evaluation-license")
		return
	}

	var req EvidenceExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	if req.StartDate == "" {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "start_date is required")
		return
	}

	tenantID := resolveTenantOrFail(w, r, "evidence/export")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}

	// Parse dates BEFORE consuming a rate-limit slot — a malformed date is a
	// 400 the caller will retry after fixing, and burning one of the tier's
	// daily export slots on a typo double-penalized the mistake.
	startTime, err := parseDate(req.StartDate)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid start_date format (use YYYY-MM-DD or RFC3339)")
		return
	}
	endTime := time.Now()
	if req.EndDate != "" {
		et, endIsDateOnly, err := parseEndDate(req.EndDate)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid end_date format (use YYYY-MM-DD or RFC3339)")
			return
		}
		// A date-only end_date means "through the end of that day". Parsing
		// it as midnight silently excluded the ENTIRE end day — the portal
		// defaults end_date to today, so every default export was missing
		// the current day's evidence (record_count 0 on a day-old org). Extend
		// to the LAST microsecond of that day (not next-day 00:00:00, which
		// the `created_at <= end` bound would over-include and which would
		// misreport the exported date_range metadata as the following day).
		if endIsDateOnly {
			et = et.AddDate(0, 0, 1).Add(-time.Microsecond)
		}
		endTime = et
	}

	// Rate limit
	limit := h.tierChecker.MaxEvidenceExportsPerDay()
	allowed, current := h.rateLimiter.tryConsume(tenantID, limit)
	if !allowed {
		writeJSONError(w, http.StatusTooManyRequests, ErrCodeEvidenceExportLimitExceeded,
			"Daily export limit reached ("+strconv.Itoa(current)+"/"+strconv.Itoa(limit)+"). Upgrade to Enterprise for unlimited exports: https://getaxonflow.com/pricing")
		return
	}

	// Enforce window limit
	windowDays := h.tierChecker.MaxEvidenceWindowDays()
	if windowDays > 0 {
		earliest := time.Now().AddDate(0, 0, -windowDays)
		if startTime.Before(earliest) {
			startTime = earliest
		}
	}

	// Enforce record limit
	recordLimit := h.tierChecker.MaxEvidenceExportRecords()
	if recordLimit < 0 {
		recordLimit = 100000 // Sane max for unlimited tier
	}
	if req.Limit > 0 && req.Limit < recordLimit {
		recordLimit = req.Limit
	}

	// Determine which types to export
	types := req.Types
	if len(types) == 0 {
		types = []string{"audit_logs", "workflow_steps", "hitl_approvals"}
	}

	exportID := uuid.New().String()
	resp := EvidenceExportResponse{
		ExportID:  exportID,
		TenantID:  tenantID,
		Tier:      string(h.tierChecker.Tier()),
		DateRange: EvidenceDateRange{Start: startTime, End: endTime},
	}

	// Add watermark for eval tier
	if !h.tierChecker.IsEnterprise() {
		resp.Disclaimer = evalDisclaimer
	}

	perTypeLimit := recordLimit / len(types)
	if perTypeLimit < 1 {
		perTypeLimit = 1
	}

	totalRecords := 0
	for _, t := range types {
		switch t {
		case "audit_logs":
			rows, err := h.queryAuditLogs(r, tenantID, startTime, endTime, perTypeLimit)
			if err != nil {
				log.Printf("[EvidenceExport] audit_logs query error: %v", err)
			} else {
				resp.AuditLogs = rows
				totalRecords += len(rows)
			}
		case "workflow_steps":
			rows, err := h.queryWorkflowSteps(r, tenantID, startTime, endTime, perTypeLimit)
			if err != nil {
				log.Printf("[EvidenceExport] workflow_steps query error: %v", err)
			} else {
				resp.WorkflowSteps = rows
				totalRecords += len(rows)
			}
		case "hitl_approvals":
			rows, err := h.queryHITLApprovals(r, tenantID, startTime, endTime, perTypeLimit)
			if err != nil {
				log.Printf("[EvidenceExport] hitl_approvals query error: %v", err)
			} else {
				resp.HITLApprovals = rows
				totalRecords += len(rows)
			}
		}
	}

	resp.RecordCount = totalRecords
	resp.ExportedAt = time.Now()

	// Track export usage
	if limit > 0 {
		resp.DailyUsage = &ExportDailyUsage{
			Used:  current,
			Limit: limit,
		}
	}

	// Record the export in evidence_exports table
	h.recordExport(exportID, tenantID, resp)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetEvidenceSummary handles GET /api/v1/evidence/summary.
// Returns counts of evidence records by type.
func (h *EvidenceExportHandler) GetEvidenceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// License gate
	if !h.tierChecker.IsEvidenceExportEnabled() {
		writeJSONError(w, http.StatusForbidden, ErrCodeFeatureRequiresEvaluation,
			"Evidence summary requires an Evaluation or Enterprise license. Get a free eval license: https://getaxonflow.com/evaluation-license")
		return
	}

	tenantID := resolveTenantOrFail(w, r, "evidence/summary")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}

	windowDays := h.tierChecker.MaxEvidenceWindowDays()
	if windowDays < 0 {
		windowDays = 3650 // ~10 years for unlimited
	}
	since := time.Now().AddDate(0, 0, -windowDays)

	var counts EvidenceCounts

	_ = h.db.QueryRow(
		`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND created_at >= $2`,
		tenantID, since,
	).Scan(&counts.AuditLogs)

	_ = h.db.QueryRow(
		`SELECT COUNT(*) FROM workflow_steps ws
		 JOIN workflows w ON ws.workflow_id = w.workflow_id
		 WHERE w.tenant_id = $1 AND ws.gate_checked_at >= $2`,
		tenantID, since,
	).Scan(&counts.WorkflowSteps)

	_ = h.db.QueryRow(
		`SELECT COUNT(*) FROM hitl_approval_queue WHERE tenant_id = $1 AND created_at >= $2`,
		tenantID, since,
	).Scan(&counts.HITLApprovals)

	counts.Total = counts.AuditLogs + counts.WorkflowSteps + counts.HITLApprovals

	resp := EvidenceSummaryResponse{
		TenantID:    tenantID,
		Tier:        string(h.tierChecker.Tier()),
		WindowDays:  windowDays,
		Counts:      counts,
		GeneratedAt: time.Now(),
	}

	if !h.tierChecker.IsEnterprise() {
		resp.Disclaimer = evalDisclaimer
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// queryAuditLogs queries audit_logs for the given tenant and date range.
//
// #2784: audit_logs has no `blocked`/`risk_score` columns, so the original
// SELECT errored ("column blocked does not exist") and every export silently
// dropped ALL audit evidence (returned 200 with an empty audit_logs array).
// `blocked` is derived from the canonical `policy_decision` vocab (migs 122/123),
// and `risk_score` is read from the `policy_details` JSONB (NULL when absent).
func (h *EvidenceExportHandler) queryAuditLogs(r *http.Request, tenantID string, start, end time.Time, limit int) ([]map[string]interface{}, error) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, tenant_id, client_id, request_type, query,
		        (policy_decision = 'blocked') AS blocked,
		        policy_details->>'risk_score' AS risk_score,
		        created_at
		 FROM audit_logs
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		tenantID, start, end, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsToMaps(rows)
}

// queryWorkflowSteps queries workflow_steps for the given tenant and date range.
// Note: workflow_steps doesn't have tenant_id directly — we join through workflows.
func (h *EvidenceExportHandler) queryWorkflowSteps(r *http.Request, tenantID string, start, end time.Time, limit int) ([]map[string]interface{}, error) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT ws.id, ws.workflow_id, ws.step_id, ws.step_type, ws.decision AS status, w.tenant_id, ws.gate_checked_at AS started_at, ws.step_completed_at AS completed_at
		 FROM workflow_steps ws
		 JOIN workflows w ON ws.workflow_id = w.workflow_id
		 WHERE w.tenant_id = $1 AND ws.gate_checked_at >= $2 AND ws.gate_checked_at <= $3
		 ORDER BY ws.gate_checked_at DESC
		 LIMIT $4`,
		tenantID, start, end, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsToMaps(rows)
}

// queryHITLApprovals queries hitl_approval_queue for the given tenant and date range.
func (h *EvidenceExportHandler) queryHITLApprovals(r *http.Request, tenantID string, start, end time.Time, limit int) ([]map[string]interface{}, error) {
	rows, err := h.db.QueryContext(r.Context(),
		`SELECT id, request_id, tenant_id, original_query, request_type, status, severity, created_at, expires_at, reviewed_at
		 FROM hitl_approval_queue
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		tenantID, start, end, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsToMaps(rows)
}

// scanRowsToMaps converts sql.Rows to a slice of maps.
func scanRowsToMaps(rows *sql.Rows) ([]map[string]interface{}, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var result []map[string]interface{}
	for rows.Next() {
		values := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}

		row := make(map[string]interface{}, len(cols))
		for i, col := range cols {
			val := values[i]
			// Convert byte slices to strings for JSON marshaling
			if b, ok := val.([]byte); ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

// recordExport saves the export metadata to the evidence_exports table.
func (h *EvidenceExportHandler) recordExport(exportID, tenantID string, resp EvidenceExportResponse) {
	_, err := h.db.Exec(
		`INSERT INTO evidence_exports (id, tenant_id, export_type, record_count, date_range_start, date_range_end, tier, disclaimer, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		exportID, tenantID, "bundled", resp.RecordCount,
		resp.DateRange.Start, resp.DateRange.End,
		resp.Tier, resp.Disclaimer, resp.ExportedAt,
	)
	if err != nil {
		log.Printf("[EvidenceExport] Failed to record export: %v", err)
	}
}

// parseDate parses a date string in YYYY-MM-DD or RFC3339 format.
func parseDate(s string) (time.Time, error) {
	// Try RFC3339 first
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	// Try YYYY-MM-DD
	return time.Parse("2006-01-02", s)
}

// parseEndDate parses an end-bound date and reports whether it was date-only
// (YYYY-MM-DD). Callers treat a date-only end as INCLUSIVE of that day; an
// RFC3339 timestamp is an exact bound.
func parseEndDate(s string) (time.Time, bool, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, false, nil
	}
	t, err := time.Parse("2006-01-02", s)
	return t, err == nil, err
}
