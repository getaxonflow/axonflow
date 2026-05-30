//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"time"
)

// OJKComplianceFramework represents the Indonesian regulatory framework scope.
type OJKComplianceFramework string

const (
	OJKFrameworkAIGovernance OJKComplianceFramework = "OJK_AI_GOVERNANCE"
	OJKFrameworkUUPDP       OJKComplianceFramework = "UU_PDP"
	OJKFrameworkBIPJP       OJKComplianceFramework = "BI_PJP"
	OJKFrameworkCombined    OJKComplianceFramework = "OJK_BI_COMBINED"
)

// OJKExportFormat represents the output format for audit exports.
type OJKExportFormat string

const (
	OJKFormatJSON OJKExportFormat = "json"
	OJKFormatCSV  OJKExportFormat = "csv"
	OJKFormatXML  OJKExportFormat = "xml"
)

// OJKAuditDataType represents the type of audit data to export.
type OJKAuditDataType string

const (
	OJKDataTypePolicyViolations  OJKAuditDataType = "policy_violations"
	OJKDataTypeLLMCalls          OJKAuditDataType = "llm_calls"
	OJKDataTypeDecisionChain     OJKAuditDataType = "decision_chain"
	OJKDataTypeHITLOversight     OJKAuditDataType = "hitl_oversight"
	OJKDataTypePIIRedactions     OJKAuditDataType = "pii_redactions"
	OJKDataTypeCrossBorder       OJKAuditDataType = "cross_border_transfers"
	OJKDataTypeBreachNotify      OJKAuditDataType = "breach_notifications"
	OJKDataTypeAll               OJKAuditDataType = "all"
)

// OJKAuditExportRequest is the request body for audit export.
type OJKAuditExportRequest struct {
	StartDate   string                 `json:"start_date"`
	EndDate     string                 `json:"end_date"`
	Format      OJKExportFormat        `json:"format,omitempty"`
	Framework   OJKComplianceFramework `json:"framework,omitempty"`
	DataTypes   []OJKAuditDataType     `json:"data_types,omitempty"`
	Filters     *OJKAuditExportFilters `json:"filters,omitempty"`
	IncludePII  bool                   `json:"include_pii,omitempty"`
}

// OJKAuditExportFilters contains optional filtering criteria.
type OJKAuditExportFilters struct {
	AgentIDs    []string `json:"agent_ids,omitempty"`
	UserIDs     []string `json:"user_ids,omitempty"`
	Severity    []string `json:"severity,omitempty"`
	PolicyTypes []string `json:"policy_types,omitempty"`
}

// OJKAuditExportResponse is returned from audit export endpoints.
type OJKAuditExportResponse struct {
	ExportID    string                 `json:"export_id"`
	Status      string                 `json:"status"`
	Framework   OJKComplianceFramework `json:"framework"`
	Format      OJKExportFormat        `json:"format"`
	Summary     *OJKAuditExportSummary `json:"summary,omitempty"`
	Data        *OJKAuditExportData    `json:"data,omitempty"`
	DownloadURL string                 `json:"download_url,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    *OJKExportMetadata     `json:"metadata,omitempty"`
}

// OJKAuditExportSummary contains statistics about the exported data.
type OJKAuditExportSummary struct {
	TotalRecords     int                    `json:"total_records"`
	RecordsByType    map[string]int         `json:"records_by_type"`
	DateRange        DateRange              `json:"date_range"`
	ComplianceScore  float64                `json:"compliance_score"`
}

// DateRange represents a time range.
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// OJKAuditExportData contains the exported audit data.
type OJKAuditExportData struct {
	PolicyViolations []OJKPolicyViolationRecord `json:"policy_violations,omitempty"`
	LLMCalls         []OJKLLMCallRecord         `json:"llm_calls,omitempty"`
	DecisionChains   []OJKDecisionChainRecord   `json:"decision_chains,omitempty"`
	HITLRecords      []OJKHITLRecord            `json:"hitl_records,omitempty"`
	PIIRedactions    []OJKPIIRedactionRecord    `json:"pii_redactions,omitempty"`
	CrossBorder      []CrossBorderTransferRecord `json:"cross_border_transfers,omitempty"`
}

// OJKPolicyViolationRecord is a single policy violation audit entry.
type OJKPolicyViolationRecord struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	PolicyID    string    `json:"policy_id"`
	PolicyName  string    `json:"policy_name"`
	Severity    string    `json:"severity"`
	Action      string    `json:"action"`
	Description string    `json:"description"`
	TenantID    string    `json:"tenant_id,omitempty"`
}

// OJKLLMCallRecord is a single LLM call audit entry.
type OJKLLMCallRecord struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	ModelID        string    `json:"model_id"`
	Provider       string    `json:"provider"`
	InputTokens    int       `json:"input_tokens"`
	OutputTokens   int       `json:"output_tokens"`
	Cost           float64   `json:"cost"`
	LatencyMS      int64     `json:"latency_ms"`
	PolicyDecision string    `json:"policy_decision"`
}

// OJKDecisionChainRecord is a single decision chain audit entry.
type OJKDecisionChainRecord struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DecisionID   string    `json:"decision_id"`
	RiskLevel    string    `json:"risk_level"`
	ModelID      string    `json:"model_id,omitempty"`
	RequiresReview bool   `json:"requires_review"`
}

// OJKHITLRecord is a single human-in-the-loop oversight entry.
type OJKHITLRecord struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	TriggerReason string    `json:"trigger_reason"`
	ReviewerID    string    `json:"reviewer_id,omitempty"`
	Decision      string    `json:"decision"`
	ReviewTimeMS  int64     `json:"review_time_ms"`
}

// OJKPIIRedactionRecord is a single PII redaction activity entry.
type OJKPIIRedactionRecord struct {
	ID              string    `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	PIIType         string    `json:"pii_type"`
	RedactionMethod string    `json:"redaction_method"`
	Confidence      float64   `json:"confidence"`
}

// CrossBorderTransferRecord tracks data transfers for UU PDP Art. 56.
type CrossBorderTransferRecord struct {
	ID               string    `json:"id"`
	Timestamp        time.Time `json:"timestamp"`
	DataResidency    string    `json:"data_residency"`
	// TransferBasis is the legal basis for cross-border data transfer per
	// UU PDP Pasal 56:
	//   - "adequacy"      → Pasal 56(a): country with equivalent protection
	//   - "safeguards"    → Pasal 56(b): binding legal instrument (DPA);
	//                       semantic equivalent of "pasal_56b_dpa"
	//   - "pasal_56b_dpa" → Pasal 56(b) explicit tag (preferred form for
	//                       Indonesia-deployment auditor surfacing)
	//   - "consent"       → Pasal 56(c): explicit data subject consent
	//
	// "safeguards" and "pasal_56b_dpa" are semantic equivalents; both are
	// accepted on input and surfaced verbatim on export (never auto-translated)
	// so an auditor sees exactly the value recorded at decision time.
	TransferBasis    string    `json:"transfer_basis"`
	DestinationCountry string  `json:"destination_country"`
	DataCategories   []string  `json:"data_categories,omitempty"`
	ApprovalStatus   string    `json:"approval_status,omitempty"`
}

// Cross-border transfer-basis values recognized under UU PDP Pasal 56.
const (
	TransferBasisAdequacy    = "adequacy"      // Pasal 56(a): adequacy determination
	TransferBasisSafeguards  = "safeguards"    // Pasal 56(b): binding legal instrument (generic label)
	TransferBasisPasal56bDPA = "pasal_56b_dpa" // Pasal 56(b): binding legal instrument (explicit DPA tag)
	TransferBasisConsent     = "consent"       // Pasal 56(c): explicit data-subject consent
)

// TransferBasisCanonicalForms returns the set of accepted transfer_basis
// values for cross-border data transfers under UU PDP Pasal 56. Order is
// stable (adequacy, safeguards, pasal_56b_dpa, consent) for deterministic
// iteration in validators and tests.
func TransferBasisCanonicalForms() []string {
	return []string{
		TransferBasisAdequacy,
		TransferBasisSafeguards,
		TransferBasisPasal56bDPA,
		TransferBasisConsent,
	}
}

// TransferBasisValid reports whether value is one of the recognized UU PDP
// Pasal 56 transfer-basis forms. Matching is case-sensitive: the canonical
// forms are lowercase, so "PASAL_56B_DPA" is rejected. Empty and unknown
// values return false.
func TransferBasisValid(value string) bool {
	for _, v := range TransferBasisCanonicalForms() {
		if value == v {
			return true
		}
	}
	return false
}

// OJKExportMetadata contains metadata about the export.
type OJKExportMetadata struct {
	ExportVersion string `json:"export_version"`
	GeneratedBy   string `json:"generated_by"`
	TenantID      string `json:"tenant_id,omitempty"`
	Checksum      string `json:"checksum,omitempty"`
}

// OJKRetentionStatusRequest is the request for retention status.
type OJKRetentionStatusRequest struct {
	DataTypes []OJKAuditDataType `json:"data_types,omitempty"`
}

// OJKRetentionStatusResponse contains retention compliance status.
type OJKRetentionStatusResponse struct {
	ComplianceStatus string                       `json:"compliance_status"`
	Framework        OJKComplianceFramework       `json:"framework"`
	RetentionDays    int                          `json:"retention_days"`
	MinRetentionDays int                          `json:"min_retention_days"`
	DataTypes        []OJKDataTypeRetentionStatus `json:"data_types"`
	NextCleanup      *time.Time                   `json:"next_cleanup,omitempty"`
}

// OJKDataTypeRetentionStatus contains retention status per data type.
type OJKDataTypeRetentionStatus struct {
	DataType      OJKAuditDataType `json:"data_type"`
	Status        string           `json:"status"`
	OldestRecord  *time.Time       `json:"oldest_record,omitempty"`
	NewestRecord  *time.Time       `json:"newest_record,omitempty"`
	TotalRecords  int64            `json:"total_records"`
}

// OJKComplianceReadinessResponse contains compliance readiness assessment.
type OJKComplianceReadinessResponse struct {
	Ready           bool                   `json:"ready"`
	Score           int                    `json:"score"` // 0-100
	Framework       OJKComplianceFramework `json:"framework"`
	Checks          []OJKComplianceCheck   `json:"checks"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// OJKComplianceCheck is a single compliance readiness check.
type OJKComplianceCheck struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"` // pass | fail | warning
	Details     string `json:"details,omitempty"`
}

// OJKBreachNotification represents a UU PDP Art. 46 breach notification.
type OJKBreachNotification struct {
	ID                string    `json:"id,omitempty"`
	IncidentTimestamp time.Time `json:"incident_timestamp"`
	DiscoveryTime     time.Time `json:"discovery_time"`
	NotificationDeadline time.Time `json:"notification_deadline,omitempty"`
	DataSubjectsAffected int     `json:"data_subjects_affected"`
	DataTypesInvolved    []string `json:"data_types_involved"`
	Description          string  `json:"description"`
	RemediationSteps     []string `json:"remediation_steps"`
	NotifiedAuthority    string  `json:"notified_authority,omitempty"` // MOCDA (until DPA constituted)
	Status               string  `json:"status,omitempty"`
	CreatedAt            time.Time `json:"created_at,omitempty"`
}

// OJKDashboardResponse contains the OJK compliance dashboard data.
type OJKDashboardResponse struct {
	Framework        OJKComplianceFramework `json:"framework"`
	ComplianceScore  int                    `json:"compliance_score"`
	TotalAuditRecords int64                 `json:"total_audit_records"`
	ActivePolicies   int                    `json:"active_policies"`
	RecentViolations int                    `json:"recent_violations"`
	RetentionStatus  string                 `json:"retention_status"`
	BreachNotifications int                 `json:"breach_notifications"`
	LastUpdated      time.Time              `json:"last_updated"`
}

// OJKAuditExportService is the interface for OJK audit export operations.
type OJKAuditExportService interface {
	ExportAuditData(ctx context.Context, tenantID string, req *OJKAuditExportRequest) (*OJKAuditExportResponse, error)
	GetRetentionStatus(ctx context.Context, tenantID string, req *OJKRetentionStatusRequest) (*OJKRetentionStatusResponse, error)
	GetExportStatus(ctx context.Context, tenantID string, exportID string) (*OJKAuditExportResponse, error)
	ValidateComplianceReadiness(ctx context.Context, tenantID string) (*OJKComplianceReadinessResponse, error)
	SubmitBreachNotification(ctx context.Context, tenantID string, req *OJKBreachNotification) (*OJKBreachNotification, error)
	GetDashboard(ctx context.Context, tenantID string) (*OJKDashboardResponse, error)
}

// OJKAPIError is a structured error response.
type OJKAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// IndonesiaRetentionDays is the minimum retention period for OJK/UU PDP compliance.
const IndonesiaRetentionDays = 1825

// context key type for avoiding collisions
type contextKey string
