// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Request size and pagination limits.
const (
	// MaxRequestBodySize is the maximum size of a request body (1MB).
	MaxRequestBodySize = 1 << 20 // 1MB

	// DefaultListLimit is the default limit for list operations.
	DefaultListLimit = 50

	// MaxListLimit is the maximum limit for list operations.
	MaxListLimit = 1000

	// DefaultMetricsListLimit is the default limit for metrics list operations.
	DefaultMetricsListLimit = 100

	// DefaultAlertCooldownMinutes is the default cooldown period for alerts.
	DefaultAlertCooldownMinutes = 15

	// DefaultAccuracyMinThreshold is the default minimum accuracy threshold.
	DefaultAccuracyMinThreshold = 0.80

	// DefaultBiasMaxThreshold is the default maximum bias threshold.
	DefaultBiasMaxThreshold = 0.10

	// DefaultValidityYears is the default validity period for conformity assessments.
	DefaultValidityYears = 1
)

// ExportType represents the type of compliance export.
type ExportType string

const (
	ExportTypeFullAudit         ExportType = "full_audit"
	ExportTypeConformityEvidence ExportType = "conformity_evidence"
	ExportTypeHITLSummary       ExportType = "hitl_summary"
	ExportTypeDecisionChain     ExportType = "decision_chain"
	ExportTypePolicyViolations  ExportType = "policy_violations"
	ExportTypeAccuracyMetrics   ExportType = "accuracy_metrics"
)

// Valid returns true if the export type is valid.
func (t ExportType) Valid() bool {
	switch t {
	case ExportTypeFullAudit, ExportTypeConformityEvidence, ExportTypeHITLSummary,
		ExportTypeDecisionChain, ExportTypePolicyViolations, ExportTypeAccuracyMetrics:
		return true
	}
	return false
}

// ExportFormat represents the output format for exports.
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatXML  ExportFormat = "xml"
	ExportFormatPDF  ExportFormat = "pdf"
)

// Valid returns true if the export format is valid.
func (f ExportFormat) Valid() bool {
	switch f {
	case ExportFormatJSON, ExportFormatCSV, ExportFormatXML, ExportFormatPDF:
		return true
	}
	return false
}

// ExportStatus represents the status of an export job.
type ExportStatus string

const (
	ExportStatusPending    ExportStatus = "pending"
	ExportStatusProcessing ExportStatus = "processing"
	ExportStatusCompleted  ExportStatus = "completed"
	ExportStatusFailed     ExportStatus = "failed"
)

// AssessmentStatus represents the status of a conformity assessment.
type AssessmentStatus string

const (
	AssessmentStatusDraft      AssessmentStatus = "draft"
	AssessmentStatusInProgress AssessmentStatus = "in_progress"
	AssessmentStatusSubmitted  AssessmentStatus = "submitted"
	AssessmentStatusApproved   AssessmentStatus = "approved"
	AssessmentStatusRejected   AssessmentStatus = "rejected"
)

// Valid returns true if the assessment status is valid.
func (s AssessmentStatus) Valid() bool {
	switch s {
	case AssessmentStatusDraft, AssessmentStatusInProgress, AssessmentStatusSubmitted,
		AssessmentStatusApproved, AssessmentStatusRejected:
		return true
	}
	return false
}

// RiskCategory represents the EU AI Act risk classification.
type RiskCategory string

const (
	RiskCategoryMinimal      RiskCategory = "minimal"
	RiskCategoryLimited      RiskCategory = "limited"
	RiskCategoryHighRisk     RiskCategory = "high-risk"
	RiskCategoryUnacceptable RiskCategory = "unacceptable"
)

// Valid returns true if the risk category is valid.
func (c RiskCategory) Valid() bool {
	switch c {
	case RiskCategoryMinimal, RiskCategoryLimited, RiskCategoryHighRisk, RiskCategoryUnacceptable:
		return true
	}
	return false
}

// MetricType represents the type of accuracy metric.
type MetricType string

const (
	MetricTypeAccuracy  MetricType = "accuracy"
	MetricTypePrecision MetricType = "precision"
	MetricTypeRecall    MetricType = "recall"
	MetricTypeF1Score   MetricType = "f1_score"
	MetricTypeAUCROC    MetricType = "auc_roc"
	MetricTypeAUCPR     MetricType = "auc_pr"
	MetricTypeMSE       MetricType = "mse"
	MetricTypeMAE       MetricType = "mae"
	MetricTypeCustom    MetricType = "custom"
)

// Valid returns true if the metric type is valid.
func (t MetricType) Valid() bool {
	switch t {
	case MetricTypeAccuracy, MetricTypePrecision, MetricTypeRecall, MetricTypeF1Score,
		MetricTypeAUCROC, MetricTypeAUCPR, MetricTypeMSE, MetricTypeMAE, MetricTypeCustom:
		return true
	}
	return false
}

// BiasCategory represents the category of bias being measured.
type BiasCategory string

const (
	BiasCategoryGender    BiasCategory = "gender"
	BiasCategoryAge       BiasCategory = "age"
	BiasCategoryEthnicity BiasCategory = "ethnicity"
	BiasCategoryDisability BiasCategory = "disability"
	BiasCategoryReligion  BiasCategory = "religion"
	BiasCategoryNationality BiasCategory = "nationality"
	BiasCategorySocioeconomic BiasCategory = "socioeconomic"
	BiasCategoryCustom    BiasCategory = "custom"
)

// Valid returns true if the bias category is valid.
func (c BiasCategory) Valid() bool {
	switch c {
	case BiasCategoryGender, BiasCategoryAge, BiasCategoryEthnicity, BiasCategoryDisability,
		BiasCategoryReligion, BiasCategoryNationality, BiasCategorySocioeconomic, BiasCategoryCustom:
		return true
	}
	return false
}

// AlertSeverity represents the severity of an accuracy alert.
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityCritical AlertSeverity = "critical"
)

// Export represents an EU AI Act compliance export job.
type Export struct {
	ID           string                 `json:"id"`
	OrgID        string                 `json:"org_id"`
	ExportType   ExportType             `json:"export_type"`
	Format       ExportFormat           `json:"format"`
	Status       ExportStatus           `json:"status"`
	Progress     int                    `json:"progress"` // 0-100
	FilePath     string                 `json:"file_path,omitempty"`
	FileSize     int64                  `json:"file_size,omitempty"`
	RecordCount  int                    `json:"record_count,omitempty"`
	DateFrom     time.Time              `json:"date_from,omitempty"`
	DateTo       time.Time              `json:"date_to,omitempty"`
	ModelIDs     []string               `json:"model_ids,omitempty"`
	Filters      map[string]interface{} `json:"filters,omitempty"`
	DownloadURL  string                 `json:"download_url,omitempty"`
	StorageType  string                 `json:"storage_type,omitempty"`
	StorageKey   string                 `json:"storage_key,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RequestedBy  string                 `json:"requested_by"`
	CreatedAt    time.Time              `json:"created_at"`
	StartedAt    *time.Time             `json:"started_at,omitempty"`
	CompletedAt  *time.Time             `json:"completed_at,omitempty"`
}

// DecisionChainRecord is a single governance decision exported for EU AI Act
// Article 12 record-keeping. It is derived from the canonical audit_logs
// decision rows (rows carrying policy_details->>'decision_id', written by the
// Decision Mode PEP and the MCP check planes) rather than the legacy
// decision_chain table, which has no production writer (#2588). Records are
// returned in chronological order, one per decision. Rows sharing a
// correlation_id (the W3C trace_id a PEP propagates across its llm/tool/agent
// hops, #2598) are reconstructed into a DecisionChainGroup; rows without one are
// singletons. See ExportRepository.GetDecisionChain and the #2585 audit-log
// northstar.
type DecisionChainRecord struct {
	ID                string    `json:"id"`
	RequestID         string    `json:"request_id"`
	Timestamp         time.Time `json:"timestamp"`
	DecisionType      string    `json:"decision_type"`
	DecisionOutcome   string    `json:"decision_outcome"`
	ModelID           string    `json:"model_id,omitempty"`
	RequiresReview    bool      `json:"requires_human_review"`
	PoliciesEvaluated string    `json:"policies_evaluated,omitempty"`
	PolicyTriggered   string    `json:"policy_triggered,omitempty"`
	ProcessingTimeMs  *int      `json:"processing_time_ms,omitempty"`
	// CorrelationID is the shared key tying this decision to the other stages of
	// the SAME logical request; empty for legacy/single-shot rows. The grouping
	// key for DecisionChainGroup (#2598).
	CorrelationID string `json:"correlation_id,omitempty"`
}

// DecisionChainGroup is one logical request's decision chain for EU AI Act
// Article 12 record-keeping: the decision rows sharing a correlation_id (the
// W3C trace_id a PEP propagates across its llm/tool/agent hops), in chronological
// step order. Rows with no correlation_id (legacy + single-shot callers) each
// form a singleton chain. #2598 / #2585.
type DecisionChainGroup struct {
	CorrelationID string                `json:"correlation_id,omitempty"`
	StepCount     int                   `json:"step_count"`
	StartedAt     time.Time             `json:"started_at"`
	EndedAt       time.Time             `json:"ended_at"`
	Steps         []DecisionChainRecord `json:"steps"`
}

// AuditLogRecord is one row of the canonical audit_logs decision/request record
// set, exported for EU AI Act Article 12 record-keeping (the full_audit export).
// Unlike DecisionChainRecord — which is the decision-only subset (rows carrying
// a decision_id) — the full audit export covers every governed request/response
// for the org in the window. The raw prompt text (audit_logs.query) is
// deliberately NOT exported (it may carry PII); query_hash is the tamper-evident
// fingerprint instead. #2610.
type AuditLogRecord struct {
	ID             string    `json:"id"`
	RequestID      string    `json:"request_id"`
	Timestamp      time.Time `json:"timestamp"`
	UserEmail      string    `json:"user_email,omitempty"`
	UserRole       string    `json:"user_role,omitempty"`
	ClientID       string    `json:"client_id,omitempty"`
	TenantID       string    `json:"tenant_id,omitempty"`
	OrgID          string    `json:"org_id,omitempty"`
	RequestType    string    `json:"request_type"`
	QueryHash      string    `json:"query_hash,omitempty"`
	PolicyDecision string    `json:"policy_decision"`
	DecisionID     string    `json:"decision_id,omitempty"`
	Plane          string    `json:"plane,omitempty"`
	Provider       string    `json:"provider,omitempty"`
	Model          string    `json:"model,omitempty"`
	ResponseTimeMs *int64    `json:"response_time_ms,omitempty"`
	TokensUsed     *int      `json:"tokens_used,omitempty"`
	ErrorMessage   string    `json:"error_message,omitempty"`
}

// PolicyViolationRecord is one policy_violations row exported for the EU AI Act
// policy_violations export (Article 12 record-keeping / Article 9 risk
// management evidence). #2610.
type PolicyViolationRecord struct {
	ID            int64                  `json:"id"`
	OrgID         string                 `json:"org_id,omitempty"`
	ViolationType string                 `json:"violation_type,omitempty"`
	Severity      string                 `json:"severity,omitempty"`
	ClientID      string                 `json:"client_id,omitempty"`
	UserID        string                 `json:"user_id,omitempty"`
	Description   string                 `json:"description,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
}

// HITLApprovalRecord is one hitl_approval_history row — the immutable
// human-oversight audit trail (EU AI Act Article 14 oversight / Article 12
// record-keeping) exported by the hitl_summary export. #2610.
type HITLApprovalRecord struct {
	ID             int64     `json:"id"`
	RequestID      string    `json:"request_id"`
	OrgID          string    `json:"org_id,omitempty"`
	TenantID       string    `json:"tenant_id,omitempty"`
	Action         string    `json:"action"`
	ActorID        string    `json:"actor_id,omitempty"`
	ActorEmail     string    `json:"actor_email,omitempty"`
	ActorRole      string    `json:"actor_role,omitempty"`
	Comment        string    `json:"comment,omitempty"`
	Justification  string    `json:"justification,omitempty"`
	PreviousStatus string    `json:"previous_status,omitempty"`
	NewStatus      string    `json:"new_status,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// ConformityAssessment represents an EU AI Act conformity assessment.
type ConformityAssessment struct {
	ID              string                 `json:"id"`
	OrgID           string                 `json:"org_id"`
	SystemID        string                 `json:"system_id"`
	SystemName      string                 `json:"system_name"`
	RiskCategory    RiskCategory           `json:"risk_category"`
	Status          AssessmentStatus       `json:"status"`
	Version         int                    `json:"version"`
	AssessmentDate  time.Time              `json:"assessment_date"`
	ValidUntil      *time.Time             `json:"valid_until,omitempty"`
	Assessors       []string               `json:"assessors"`
	Requirements    []RequirementStatus    `json:"requirements"`
	Evidence        []EvidenceItem         `json:"evidence"`
	Findings        []Finding              `json:"findings"`
	RiskMitigation  map[string]interface{} `json:"risk_mitigation,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
	CreatedBy       string                 `json:"created_by"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	SubmittedAt     *time.Time             `json:"submitted_at,omitempty"`
	SubmittedBy     string                 `json:"submitted_by,omitempty"`
	ApprovedAt      *time.Time             `json:"approved_at,omitempty"`
	ApprovedBy      string                 `json:"approved_by,omitempty"`
	RejectedAt      *time.Time             `json:"rejected_at,omitempty"`
	RejectedBy      string                 `json:"rejected_by,omitempty"`
	RejectionReason string                 `json:"rejection_reason,omitempty"`
}

// RequirementStatus tracks compliance with a specific EU AI Act requirement.
type RequirementStatus struct {
	RequirementID string `json:"requirement_id"`
	Article       string `json:"article"`
	Description   string `json:"description"`
	Status        string `json:"status"` // compliant, non_compliant, partial, not_applicable
	Notes         string `json:"notes,omitempty"`
	EvidenceIDs   []string `json:"evidence_ids,omitempty"`
}

// EvidenceItem represents evidence supporting conformity claims.
type EvidenceItem struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // document, test_result, audit_log, certification
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	URL         string    `json:"url,omitempty"`
	UploadedAt  time.Time `json:"uploaded_at"`
	UploadedBy  string    `json:"uploaded_by"`
}

// Finding represents a conformity assessment finding.
type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // critical, major, minor, observation
	Category    string `json:"category"`
	Description string `json:"description"`
	Article     string `json:"article,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Status      string `json:"status"` // open, resolved, accepted
}

// AccuracyMetric represents a recorded accuracy metric.
type AccuracyMetric struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	ModelID     string                 `json:"model_id"`
	MetricType  MetricType             `json:"metric_type"`
	Value       float64                `json:"value"`
	SampleSize  int                    `json:"sample_size"`
	Timestamp   time.Time              `json:"timestamp"`
	WindowStart time.Time              `json:"window_start,omitempty"`
	WindowEnd   time.Time              `json:"window_end,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// BiasRecord represents a bias detection measurement.
type BiasRecord struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	ModelID     string                 `json:"model_id"`
	Category    BiasCategory           `json:"category"`
	Score       float64                `json:"score"`
	Threshold   float64                `json:"threshold"`
	IsViolation bool                   `json:"is_violation"`
	SampleSize  int                    `json:"sample_size"`
	GroupA      string                 `json:"group_a"`
	GroupB      string                 `json:"group_b"`
	GroupARate  float64                `json:"group_a_rate"`
	GroupBRate  float64                `json:"group_b_rate"`
	Timestamp   time.Time              `json:"timestamp"`
	WindowStart time.Time              `json:"window_start,omitempty"`
	WindowEnd   time.Time              `json:"window_end,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AccuracyAlert represents an alert for accuracy threshold violations.
type AccuracyAlert struct {
	ID           string        `json:"id"`
	OrgID        string        `json:"org_id"`
	ModelID      string        `json:"model_id"`
	AlertType    string        `json:"alert_type"` // accuracy_degradation, bias_detected
	Severity     AlertSeverity `json:"severity"`
	Title        string        `json:"title"`
	Description  string        `json:"description"`
	MetricType   MetricType    `json:"metric_type,omitempty"`
	BiasCategory BiasCategory  `json:"bias_category,omitempty"`
	CurrentValue float64       `json:"current_value"`
	Threshold    float64       `json:"threshold"`
	TriggeredAt  time.Time     `json:"triggered_at"`
	AckedAt      *time.Time    `json:"acked_at,omitempty"`
	AckedBy      string        `json:"acked_by,omitempty"`
	ResolvedAt   *time.Time    `json:"resolved_at,omitempty"`
	ResolvedBy   string        `json:"resolved_by,omitempty"`
}

// AccuracySummary provides a summary of accuracy status for an organization.
type AccuracySummary struct {
	OrgID             string                 `json:"org_id"`
	TotalModels       int                    `json:"total_models"`
	ModelsAboveTarget int                    `json:"models_above_target"`
	ModelsBelowTarget int                    `json:"models_below_target"`
	AverageAccuracy   float64                `json:"average_accuracy"`
	ActiveAlerts      int                    `json:"active_alerts"`
	LastUpdated       time.Time              `json:"last_updated"`
	MetricsByModel    map[string]interface{} `json:"metrics_by_model,omitempty"`
}

// AggregatedMetric represents aggregated metrics over a time period.
type AggregatedMetric struct {
	MetricType MetricType `json:"metric_type"`
	Count      int64      `json:"count"`
	Min        float64    `json:"min"`
	Max        float64    `json:"max"`
	Avg        float64    `json:"avg"`
	StdDev     float64    `json:"std_dev"`
	P50        float64    `json:"p50"`
	P95        float64    `json:"p95"`
	P99        float64    `json:"p99"`
}

// Request/Response types

// CreateExportRequest is the request body for creating an export.
type CreateExportRequest struct {
	ExportType ExportType             `json:"export_type"`
	Format     ExportFormat           `json:"format"`
	DateFrom   string                 `json:"date_from,omitempty"`
	DateTo     string                 `json:"date_to,omitempty"`
	ModelIDs   []string               `json:"model_ids,omitempty"`
	Filters    map[string]interface{} `json:"filters,omitempty"`
}

// CreateAssessmentRequest is the request body for creating a conformity assessment.
type CreateAssessmentRequest struct {
	SystemID     string       `json:"system_id"`
	SystemName   string       `json:"system_name"`
	RiskCategory RiskCategory `json:"risk_category"`
	Assessors    []string     `json:"assessors,omitempty"`
}

// UpdateAssessmentRequest is the request body for updating a conformity assessment.
type UpdateAssessmentRequest struct {
	SystemName      string                 `json:"system_name,omitempty"`
	RiskCategory    RiskCategory           `json:"risk_category,omitempty"`
	Assessors       []string               `json:"assessors,omitempty"`
	Requirements    []RequirementStatus    `json:"requirements,omitempty"`
	Evidence        []EvidenceItem         `json:"evidence,omitempty"`
	Findings        []Finding              `json:"findings,omitempty"`
	RiskMitigation  map[string]interface{} `json:"risk_mitigation,omitempty"`
	Recommendations []string               `json:"recommendations,omitempty"`
}

// RecordAccuracyRequest is the request body for recording an accuracy metric.
type RecordAccuracyRequest struct {
	ModelID     string                 `json:"model_id"`
	MetricType  string                 `json:"metric_type"`
	Value       float64                `json:"value"`
	SampleSize  int                    `json:"sample_size"`
	WindowStart string                 `json:"window_start,omitempty"`
	WindowEnd   string                 `json:"window_end,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// RecordBiasRequest is the request body for recording a bias measurement.
type RecordBiasRequest struct {
	ModelID     string                 `json:"model_id"`
	Category    string                 `json:"category"`
	GroupA      string                 `json:"group_a"`
	GroupB      string                 `json:"group_b"`
	GroupARate  float64                `json:"group_a_rate"`
	GroupBRate  float64                `json:"group_b_rate"`
	SampleSize  int                    `json:"sample_size"`
	WindowStart string                 `json:"window_start,omitempty"`
	WindowEnd   string                 `json:"window_end,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// AccuracyMetricsParams contains parameters for querying accuracy metrics.
type AccuracyMetricsParams struct {
	ModelID    string `json:"model_id,omitempty"`
	MetricType string `json:"metric_type,omitempty"`
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// Helper functions for HTTP responses

// getOrgIDFromRequest extracts the organization ID from request headers.
func getOrgIDFromRequest(r *http.Request) string {
	orgID := r.Header.Get("X-Org-ID")
	if orgID == "" {
		orgID = r.Header.Get("X-Tenant-ID")
	}
	return orgID
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	jsonData, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"Failed to marshal response"}`))
		return
	}
	w.WriteHeader(status)
	w.Write(jsonData)
}

// writeError writes an error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// decodeJSONBody decodes a JSON request body with size limiting.
// It limits the request body to MaxRequestBodySize to prevent DoS attacks.
func decodeJSONBody(r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, MaxRequestBodySize)
	decoder := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBodySize))
	return decoder.Decode(v)
}
