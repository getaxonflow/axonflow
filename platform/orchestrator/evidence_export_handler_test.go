// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
)

func TestExportEvidence_CommunityForbidden(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierCommunity,
		evidenceExportEnabled: false,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", w.Code)
	}
}

func TestExportEvidence_MissingStartDate(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 3,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    14,
	}
	handler := NewEvidenceExportHandler(nil, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(EvidenceExportRequest{})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportEvidence_RateLimit(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 3,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    14,
	}
	handler := NewEvidenceExportHandler(nil, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  map[string]int{"test-tenant": 3}, // Already at limit
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("Expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportEvidence_OPTIONS(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	req := httptest.NewRequest("OPTIONS", "/api/v1/evidence/export", nil)
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for OPTIONS, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("Expected empty body for OPTIONS")
	}
}

func TestExportEvidence_InvalidJSON(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader([]byte("{bad json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid JSON, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["code"] != "BAD_REQUEST" {
		t.Errorf("Expected code 'BAD_REQUEST', got %q", errResp["code"])
	}
}

func TestExportEvidence_InvalidStartDate(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    14,
	}
	handler := NewEvidenceExportHandler(nil, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "not-a-date"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for invalid start_date, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["message"] != "Invalid start_date format (use YYYY-MM-DD or RFC3339)" {
		t.Errorf("Unexpected error message: %q", errResp["message"])
	}
}

func TestExportEvidence_WithEndDate(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	// Expect queries for all 3 evidence types (default when no types specified)
	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))

	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))

	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))

	// Expect the recordExport INSERT
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{
		StartDate: "2026-02-01",
		EndDate:   "2026-02-15",
	})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceExportResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Disclaimer != evalDisclaimer {
		t.Errorf("Expected eval disclaimer, got %q", resp.Disclaimer)
	}
	if resp.RecordCount != 0 {
		t.Errorf("Expected 0 records (empty mock), got %d", resp.RecordCount)
	}
	if resp.DailyUsage == nil {
		t.Error("Expected daily_usage to be present")
	}
}

func TestExportEvidence_EnterpriseTierNoDisclaimer(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEnterprise,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: -1, // unlimited
		maxEvidenceExportRecords: -1, // unlimited
		maxEvidenceWindowDays:    -1, // unlimited
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))

	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))

	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))

	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "enterprise-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceExportResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Disclaimer != "" {
		t.Errorf("Expected no disclaimer for Enterprise tier, got %q", resp.Disclaimer)
	}
	if resp.DailyUsage != nil {
		t.Error("Expected nil daily_usage for unlimited tier")
	}
	if resp.Tier != string(license.TierEnterprise) {
		t.Errorf("Expected tier %q, got %q", license.TierEnterprise, resp.Tier)
	}
}

func TestNewEvidenceExportHandler(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	if handler == nil {
		t.Fatal("NewEvidenceExportHandler returned nil")
	}
	if handler.tierChecker != checker {
		t.Error("tierChecker not set correctly")
	}
	if handler.rateLimiter == nil {
		t.Error("rateLimiter should not be nil")
	}
}

func TestEvidenceExportHandler_RegisterRoutes(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Verify export route is registered
	exportRoute := r.Get("")
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", nil)
	var match mux.RouteMatch
	if !r.Match(req, &match) {
		t.Error("Expected /api/v1/evidence/export POST to match a route")
	}

	// Verify summary route is registered
	req = httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	if !r.Match(req, &match) {
		t.Error("Expected /api/v1/evidence/summary GET to match a route")
	}

	_ = exportRoute // suppress unused warning
}

func TestGetEvidenceSummary_OPTIONS(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	req := httptest.NewRequest("OPTIONS", "/api/v1/evidence/summary", nil)
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 for OPTIONS, got %d", w.Code)
	}
	if w.Body.Len() != 0 {
		t.Error("Expected empty body for OPTIONS")
	}
}

func TestGetEvidenceSummary_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
		maxEvidenceWindowDays: 14,
	}
	handler := NewEvidenceExportHandler(db, checker)

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(42))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(15))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(3))

	req := httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceSummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Counts.AuditLogs != 42 {
		t.Errorf("Expected 42 audit_logs, got %d", resp.Counts.AuditLogs)
	}
	if resp.Counts.WorkflowSteps != 15 {
		t.Errorf("Expected 15 workflow_steps, got %d", resp.Counts.WorkflowSteps)
	}
	if resp.Counts.HITLApprovals != 3 {
		t.Errorf("Expected 3 hitl_approvals, got %d", resp.Counts.HITLApprovals)
	}
	if resp.Counts.Total != 60 {
		t.Errorf("Expected total 60, got %d", resp.Counts.Total)
	}
	if resp.WindowDays != 14 {
		t.Errorf("Expected window_days 14, got %d", resp.WindowDays)
	}
	if resp.Disclaimer != evalDisclaimer {
		t.Errorf("Expected eval disclaimer, got %q", resp.Disclaimer)
	}
}

func TestGetEvidenceSummary_EnterpriseTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEnterprise,
		evidenceExportEnabled: true,
		maxEvidenceWindowDays: -1,
	}
	handler := NewEvidenceExportHandler(db, checker)

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(50))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(10))

	req := httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	req.Header.Set("X-Tenant-ID", "enterprise-tenant")
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceSummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Disclaimer != "" {
		t.Errorf("Expected no disclaimer for Enterprise, got %q", resp.Disclaimer)
	}
	if resp.WindowDays != 3650 {
		t.Errorf("Expected window_days 3650 for unlimited, got %d", resp.WindowDays)
	}
}

func TestExportEvidence_WithDataRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(
		sqlmock.NewRows(auditCols).
			AddRow("log-1", "t1", "c1", "chat", "hello", false, 0.1, "2026-02-10T00:00:00Z").
			AddRow("log-2", "t1", "c1", "chat", "world", true, 0.9, "2026-02-11T00:00:00Z"),
	)

	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(
		sqlmock.NewRows(stepCols).
			AddRow("ws-1", "wf-1", "s1", "llm_call", "completed", "t1", "2026-02-10T00:00:00Z", "2026-02-10T00:01:00Z"),
	)

	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))

	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "t1")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceExportResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.RecordCount != 3 {
		t.Errorf("Expected 3 records (2 audit + 1 step), got %d", resp.RecordCount)
	}
	if len(resp.AuditLogs) != 2 {
		t.Errorf("Expected 2 audit logs, got %d", len(resp.AuditLogs))
	}
	if len(resp.WorkflowSteps) != 1 {
		t.Errorf("Expected 1 workflow step, got %d", len(resp.WorkflowSteps))
	}
}

func TestExportEvidence_SpecificTypes(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	// Only requesting audit_logs type
	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{
		StartDate: "2026-02-01",
		Types:     []string{"audit_logs"},
	})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportEvidence_TenantFromContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))
	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))
	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	ctx := context.WithValue(req.Context(), "tenant_id", "ctx-tenant")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportEvidence_RequestLimit(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))
	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))
	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{
		StartDate: "2026-02-01",
		Limit:     100,
	})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExportRateLimiter_TryConsume(t *testing.T) {
	rl := &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	// First consumption should succeed
	allowed, count := rl.tryConsume("tenant-1", 3)
	if !allowed || count != 1 {
		t.Errorf("First consume: allowed=%v, count=%d (expected true, 1)", allowed, count)
	}

	// Second and third
	rl.tryConsume("tenant-1", 3)
	allowed, count = rl.tryConsume("tenant-1", 3)
	if !allowed || count != 3 {
		t.Errorf("Third consume: allowed=%v, count=%d (expected true, 3)", allowed, count)
	}

	// Fourth should fail
	allowed, count = rl.tryConsume("tenant-1", 3)
	if allowed {
		t.Error("Fourth consume should be rejected (at limit)")
	}

	// Different tenant should be independent
	allowed, count = rl.tryConsume("tenant-2", 3)
	if !allowed || count != 1 {
		t.Errorf("Different tenant: allowed=%v, count=%d (expected true, 1)", allowed, count)
	}

	// Unlimited (-1) should always succeed
	allowed, _ = rl.tryConsume("tenant-3", -1)
	if !allowed {
		t.Error("Unlimited tier should always be allowed")
	}
}

func TestSimulationRateLimiter_TryConsume(t *testing.T) {
	rl := &simulationRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	allowed, count := rl.tryConsume("t1", 2)
	if !allowed || count != 1 {
		t.Errorf("First: allowed=%v, count=%d", allowed, count)
	}

	allowed, count = rl.tryConsume("t1", 2)
	if !allowed || count != 2 {
		t.Errorf("Second: allowed=%v, count=%d", allowed, count)
	}

	allowed, _ = rl.tryConsume("t1", 2)
	if allowed {
		t.Error("Third should be rejected")
	}
}

func TestGetEvidenceSummary_TenantFromContext(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
		maxEvidenceWindowDays: 14,
	}
	handler := NewEvidenceExportHandler(db, checker)

	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(2))
	mock.ExpectQuery("SELECT COUNT").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))

	req := httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	ctx := context.WithValue(req.Context(), "tenant_id", "ctx-tenant")
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceSummaryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if resp.TenantID != "ctx-tenant" {
		t.Errorf("Expected tenant_id 'ctx-tenant', got %q", resp.TenantID)
	}
}

func TestExportEvidence_DBQueryError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	// Simulate DB errors for all query types (should log and continue)
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnError(err)
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnError(err)
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnError(err)
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	// Should still return 200 with 0 records (errors logged, not propagated)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 despite DB errors, got %d: %s", w.Code, w.Body.String())
	}

	var resp EvidenceExportResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}
	if resp.RecordCount != 0 {
		t.Errorf("Expected 0 records when DB errors, got %d", resp.RecordCount)
	}
}

func TestExportEvidence_RecordExportError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    90,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").WillReturnRows(sqlmock.NewRows(auditCols))
	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))
	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))
	// recordExport fails — should still return 200 (error only logged)
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnError(err)

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200 despite recordExport error, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGetEvidenceSummary_CommunityForbidden(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierCommunity,
		evidenceExportEnabled: false,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	req := httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("Expected 403, got %d", w.Code)
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{"2026-02-01", false},
		{"2026-02-01T12:00:00Z", false},
		{"invalid", true},
		{"", true},
	}

	for _, tt := range tests {
		_, err := parseDate(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("parseDate(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
		}
	}
}

func TestEvalDisclaimer(t *testing.T) {
	if evalDisclaimer == "" {
		t.Error("evalDisclaimer should not be empty")
	}
	if evalDisclaimer != "NOT FOR REGULATORY SUBMISSION - EVALUATION LICENSE" {
		t.Errorf("Unexpected disclaimer: %s", evalDisclaimer)
	}
}

func TestExportEvidence_RequiresTenant(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEvaluation,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 3,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    14,
	}
	handler := NewEvidenceExportHandler(nil, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	body, _ := json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01"})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	// Deliberately do NOT set X-Tenant-ID and do NOT seed tenant_id in context.
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 when tenant scope is missing, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["code"] != "TENANT_REQUIRED" {
		t.Errorf("Expected error code TENANT_REQUIRED, got %q", errResp["code"])
	}

	// Confirm rate limiter was NOT bumped — would have cost the empty bucket
	// a slot under the old behavior.
	if got := handler.rateLimiter.counts[""]; got != 0 {
		t.Errorf("Expected empty-tenant bucket to remain at 0, got %d", got)
	}
}

func TestGetEvidenceSummary_RequiresTenant(t *testing.T) {
	checker := &mockLicenseCheckerForSim{
		tier:                  license.TierEvaluation,
		evidenceExportEnabled: true,
		maxEvidenceWindowDays: 14,
	}
	handler := NewEvidenceExportHandler(nil, checker)

	req := httptest.NewRequest("GET", "/api/v1/evidence/summary", nil)
	// Deliberately no tenant header, no context.
	w := httptest.NewRecorder()

	handler.GetEvidenceSummary(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 when tenant scope is missing, got %d: %s", w.Code, w.Body.String())
	}

	var errResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
		t.Fatalf("Failed to decode error response: %v", err)
	}
	if errResp["code"] != "TENANT_REQUIRED" {
		t.Errorf("Expected error code TENANT_REQUIRED, got %q", errResp["code"])
	}
}

// TestExportEvidence_DateOnlyEndDateIncludesThatDay pins the #2808 E-6 fix:
// a date-only end_date means "through the end of that day". The handler used
// to parse it as midnight and pass it straight to `created_at <= $3`, so the
// ENTIRE end day was excluded — and since the portal defaults end_date to
// today, the default evidence bundle always missed the current day
// (record_count 0 on a day-old org). The audit query must now receive
// end = start-of-NEXT-day.
func TestExportEvidence_DateOnlyEndDateIncludesThatDay(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEnterprise,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    0, // no window clamp — keep start_time exact
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	wantStart, _ := time.Parse("2006-01-02", "2026-02-01")
	// 2026-02-15 inclusive → last microsecond of that day.
	wantEnd, _ := time.Parse("2006-01-02", "2026-02-16")
	wantEnd = wantEnd.Add(-time.Microsecond)

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").
		WithArgs("test-tenant", wantStart, wantEnd, 5000/3). // record cap split across the 3 evidence types
		WillReturnRows(sqlmock.NewRows(auditCols))

	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))

	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))

	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{
		StartDate: "2026-02-01",
		EndDate:   "2026-02-15",
	})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	handler.ExportEvidence(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("audit query did not receive the inclusive end-of-day bound: %v", err)
	}
}

// TestExportEvidence_RFC3339EndDateExactBound pins that an RFC3339 end_date
// stays an EXACT bound (no day extension), and a malformed end_date is now a
// 400 like start_date instead of being silently replaced with time.Now().
func TestExportEvidence_RFC3339EndDateExactBound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create sqlmock: %v", err)
	}
	defer db.Close()

	checker := &mockLicenseCheckerForSim{
		tier:                     license.TierEnterprise,
		evidenceExportEnabled:    true,
		maxEvidenceExportsPerDay: 10,
		maxEvidenceExportRecords: 5000,
		maxEvidenceWindowDays:    0,
	}
	handler := NewEvidenceExportHandler(db, checker)
	handler.rateLimiter = &exportRateLimiter{
		counts:  make(map[string]int),
		resetAt: nextUTCMidnight(),
	}

	wantStart, _ := time.Parse("2006-01-02", "2026-02-01")
	wantEnd, _ := time.Parse(time.RFC3339, "2026-02-15T13:45:00Z")

	auditCols := []string{"id", "tenant_id", "client_id", "request_type", "query", "blocked", "risk_score", "created_at"}
	mock.ExpectQuery("SELECT .+ FROM audit_logs").
		WithArgs("test-tenant", wantStart, wantEnd, 5000/3). // record cap split across the 3 evidence types
		WillReturnRows(sqlmock.NewRows(auditCols))
	stepCols := []string{"id", "workflow_id", "step_id", "step_type", "status", "tenant_id", "started_at", "completed_at"}
	mock.ExpectQuery("SELECT .+ FROM workflow_steps").WillReturnRows(sqlmock.NewRows(stepCols))
	hitlCols := []string{"id", "request_id", "tenant_id", "original_query", "request_type", "status", "severity", "created_at", "expires_at", "reviewed_at"}
	mock.ExpectQuery("SELECT .+ FROM hitl_approval_queue").WillReturnRows(sqlmock.NewRows(hitlCols))
	mock.ExpectExec("INSERT INTO evidence_exports").WillReturnResult(sqlmock.NewResult(1, 1))

	body, _ := json.Marshal(EvidenceExportRequest{
		StartDate: "2026-02-01",
		EndDate:   "2026-02-15T13:45:00Z",
	})
	req := httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()
	handler.ExportEvidence(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("RFC3339 end bound must be exact: %v", err)
	}

	// Malformed end_date → 400 (was: silently time.Now()).
	body, _ = json.Marshal(EvidenceExportRequest{StartDate: "2026-02-01", EndDate: "garbage"})
	req = httptest.NewRequest("POST", "/api/v1/evidence/export", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w = httptest.NewRecorder()
	handler.ExportEvidence(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 for malformed end_date, got %d: %s", w.Code, w.Body.String())
	}
}
