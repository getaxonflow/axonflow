// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "time"

// EvidenceExportRequest is the request body for POST /api/v1/evidence/export.
type EvidenceExportRequest struct {
	StartDate string   `json:"start_date"`         // RFC3339 or YYYY-MM-DD
	EndDate   string   `json:"end_date,omitempty"` // Defaults to now
	Types     []string `json:"types,omitempty"`    // audit_logs, workflow_steps, hitl_approvals (all if empty)
	Limit     int      `json:"limit,omitempty"`    // Max records (capped by tier)
}

// EvidenceExportResponse is the response for POST /api/v1/evidence/export.
type EvidenceExportResponse struct {
	ExportID      string                   `json:"export_id"`
	TenantID      string                   `json:"tenant_id"`
	Tier          string                   `json:"tier"`
	DateRange     EvidenceDateRange        `json:"date_range"`
	Disclaimer    string                   `json:"disclaimer,omitempty"`
	RecordCount   int                      `json:"record_count"`
	AuditLogs     []map[string]interface{} `json:"audit_logs,omitempty"`
	WorkflowSteps []map[string]interface{} `json:"workflow_steps,omitempty"`
	HITLApprovals []map[string]interface{} `json:"hitl_approvals,omitempty"`
	ExportedAt    time.Time                `json:"exported_at"`
	DailyUsage    *ExportDailyUsage        `json:"daily_usage,omitempty"`
}

// EvidenceDateRange represents the date range of the export.
type EvidenceDateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ExportDailyUsage tracks export quota usage.
type ExportDailyUsage struct {
	Used  int `json:"used"`
	Limit int `json:"limit"` // -1 = unlimited
}

// EvidenceSummaryResponse is the response for GET /api/v1/evidence/summary.
type EvidenceSummaryResponse struct {
	TenantID    string         `json:"tenant_id"`
	Tier        string         `json:"tier"`
	WindowDays  int            `json:"window_days"`
	Counts      EvidenceCounts `json:"counts"`
	GeneratedAt time.Time      `json:"generated_at"`
	Disclaimer  string         `json:"disclaimer,omitempty"`
}

// EvidenceCounts holds counts per evidence type.
type EvidenceCounts struct {
	AuditLogs     int `json:"audit_logs"`
	WorkflowSteps int `json:"workflow_steps"`
	HITLApprovals int `json:"hitl_approvals"`
	Total         int `json:"total"`
}
