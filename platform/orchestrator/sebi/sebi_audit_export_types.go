// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package orchestrator provides enterprise-only SEBI compliance audit export
// functionality for regulatory submissions.
//
// SEBI AI/ML Guidelines (June 2025 Consultation Paper) - Auditability Pillar:
// "All AI/ML-related decisions, including input data, model outputs, and actions
// taken, must be retained for a minimum period of 5 years for regulatory audit."
//
// This package implements the audit export API required for SEBI regulatory
// submissions, including:
//   - Comprehensive audit log exports in JSON/CSV/XML formats
//   - Policy violation summaries
//   - Human-in-the-loop oversight records
//   - Model decision chain tracing
//   - PII redaction activity logs
//go:build enterprise

package sebi

import (
	"context"
	"time"
)

// =============================================================================
// SEBI Audit Export Types
// =============================================================================

// SEBIComplianceFramework defines the regulatory framework for exports
type SEBIComplianceFramework string

const (
	// SEBIFrameworkAIML is the SEBI AI/ML Guidelines (June 2025)
	SEBIFrameworkAIML SEBIComplianceFramework = "SEBI_AI_ML"
	// SEBIFrameworkDPDP is the Digital Personal Data Protection Act 2023
	SEBIFrameworkDPDP SEBIComplianceFramework = "DPDP_ACT_2023"
	// SEBIFrameworkCombined is both SEBI AI/ML and DPDP combined
	SEBIFrameworkCombined SEBIComplianceFramework = "SEBI_DPDP_COMBINED"
)

// SEBIExportFormat defines the output format for audit exports
type SEBIExportFormat string

const (
	// SEBIFormatJSON is JSON format (default, recommended for programmatic access)
	SEBIFormatJSON SEBIExportFormat = "json"
	// SEBIFormatCSV is CSV format (for spreadsheet analysis)
	SEBIFormatCSV SEBIExportFormat = "csv"
	// SEBIFormatXML is XML format (for legacy system compatibility)
	SEBIFormatXML SEBIExportFormat = "xml"
)

// SEBIAuditDataType defines the type of audit data to export
type SEBIAuditDataType string

const (
	// SEBIDataTypePolicyViolations includes all policy violations
	SEBIDataTypePolicyViolations SEBIAuditDataType = "policy_violations"
	// SEBIDataTypeLLMCalls includes all LLM call audit records
	SEBIDataTypeLLMCalls SEBIAuditDataType = "llm_calls"
	// SEBIDataTypeDecisionChain includes decision chain tracing
	SEBIDataTypeDecisionChain SEBIAuditDataType = "decision_chain"
	// SEBIDataTypeHITLOversight includes human-in-the-loop oversight records
	SEBIDataTypeHITLOversight SEBIAuditDataType = "hitl_oversight"
	// SEBIDataTypePIIRedactions includes PII redaction activity
	SEBIDataTypePIIRedactions SEBIAuditDataType = "pii_redactions"
	// SEBIDataTypeAll includes all audit data types
	SEBIDataTypeAll SEBIAuditDataType = "all"
)

// =============================================================================
// Request Types
// =============================================================================

// SEBIAuditExportRequest defines the request for exporting SEBI compliance audits
type SEBIAuditExportRequest struct {
	// StartDate is the start of the export period (inclusive)
	StartDate time.Time `json:"start_date"`

	// EndDate is the end of the export period (inclusive)
	EndDate time.Time `json:"end_date"`

	// DataTypes specifies which types of audit data to export
	// If empty, defaults to all data types
	DataTypes []SEBIAuditDataType `json:"data_types,omitempty"`

	// Format specifies the output format (json, csv, xml)
	// Defaults to json if not specified
	Format SEBIExportFormat `json:"format,omitempty"`

	// Framework specifies the compliance framework for the export
	// Defaults to SEBI_AI_ML if not specified
	Framework SEBIComplianceFramework `json:"framework,omitempty"`

	// IncludeArchived specifies whether to include archived records
	// Records older than retention period may be in cold storage
	IncludeArchived bool `json:"include_archived,omitempty"`

	// RedactPII specifies whether to redact PII in the export
	// Useful for sharing with external auditors
	RedactPII bool `json:"redact_pii,omitempty"`

	// Filters allows filtering by specific criteria
	Filters *SEBIAuditExportFilters `json:"filters,omitempty"`
}

// SEBIAuditExportFilters defines optional filters for audit exports
type SEBIAuditExportFilters struct {
	// AgentIDs filters by specific agent IDs
	AgentIDs []string `json:"agent_ids,omitempty"`

	// UserIDs filters by specific user IDs
	UserIDs []int `json:"user_ids,omitempty"`

	// Severity filters by minimum severity level
	Severity string `json:"severity,omitempty"`

	// PolicyTypes filters by policy types
	PolicyTypes []string `json:"policy_types,omitempty"`

	// ViolationTypes filters by specific violation types
	ViolationTypes []string `json:"violation_types,omitempty"`

	// IncludeModelInfo includes detailed model information
	IncludeModelInfo bool `json:"include_model_info,omitempty"`
}

// =============================================================================
// Response Types
// =============================================================================

// SEBIAuditExportResponse is the response for audit export requests
type SEBIAuditExportResponse struct {
	// ExportID is the unique identifier for this export
	ExportID string `json:"export_id"`

	// Status is the export status (pending, processing, completed, failed)
	Status string `json:"status"`

	// ExportedAt is when the export was completed
	ExportedAt time.Time `json:"exported_at,omitempty"`

	// Framework is the compliance framework used
	Framework SEBIComplianceFramework `json:"framework"`

	// Summary contains export statistics
	Summary *SEBIAuditExportSummary `json:"summary,omitempty"`

	// Data contains the actual export data (for synchronous exports)
	Data *SEBIAuditExportData `json:"data,omitempty"`

	// DownloadURL is the URL to download large exports (for async exports)
	DownloadURL string `json:"download_url,omitempty"`

	// ExpiresAt is when the download URL expires
	ExpiresAt time.Time `json:"expires_at,omitempty"`

	// Metadata contains additional export metadata
	Metadata *SEBIExportMetadata `json:"metadata"`
}

// SEBIAuditExportSummary contains statistics about the export
type SEBIAuditExportSummary struct {
	// TotalRecords is the total number of records exported
	TotalRecords int `json:"total_records"`

	// RecordsByType breaks down records by data type
	RecordsByType map[SEBIAuditDataType]int `json:"records_by_type"`

	// DateRange is the actual date range of exported data
	DateRange *DateRange `json:"date_range"`

	// ViolationsSummary summarizes policy violations
	ViolationsSummary *ViolationsSummary `json:"violations_summary,omitempty"`

	// ComplianceScore is the overall compliance score for the period
	ComplianceScore float64 `json:"compliance_score,omitempty"`
}

// DateRange represents a date range
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ViolationsSummary summarizes policy violations
type ViolationsSummary struct {
	// Total is the total number of violations
	Total int `json:"total"`

	// BySeverity breaks down violations by severity
	BySeverity map[string]int `json:"by_severity"`

	// ByType breaks down violations by type
	ByType map[string]int `json:"by_type"`

	// TopViolations lists the most common violations
	TopViolations []ViolationCount `json:"top_violations,omitempty"`
}

// ViolationCount represents a violation type and its count
type ViolationCount struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Count       int    `json:"count"`
	Severity    string `json:"severity"`
}

// SEBIExportMetadata contains metadata about the export
type SEBIExportMetadata struct {
	// ExportVersion is the version of the export schema
	ExportVersion string `json:"export_version"`

	// GeneratedBy is the system that generated the export
	GeneratedBy string `json:"generated_by"`

	// GeneratedAt is when the export was generated
	GeneratedAt time.Time `json:"generated_at"`

	// TenantID is the tenant identifier
	TenantID string `json:"tenant_id"`

	// OrgName is the organization name
	OrgName string `json:"org_name"`

	// RequestedBy is the user who requested the export
	RequestedBy string `json:"requested_by"`

	// ComplianceFramework is the framework used for the export
	ComplianceFramework SEBIComplianceFramework `json:"compliance_framework"`

	// RetentionDays is the retention period for this data type
	RetentionDays int `json:"retention_days"`

	// Checksum is the SHA-256 checksum of the export data
	Checksum string `json:"checksum,omitempty"`

	// SignedBy is the signing authority (for signed exports)
	SignedBy string `json:"signed_by,omitempty"`
}

// =============================================================================
// Audit Data Types
// =============================================================================

// SEBIAuditExportData contains the actual audit data
type SEBIAuditExportData struct {
	// PolicyViolations contains policy violation records
	PolicyViolations []SEBIPolicyViolationRecord `json:"policy_violations,omitempty"`

	// LLMCalls contains LLM call audit records
	LLMCalls []SEBILLMCallRecord `json:"llm_calls,omitempty"`

	// DecisionChain contains the flat per-decision audit rows in chronological
	// order (one row per governance decision). Retained for chronological
	// consumers; each row now also carries its correlation_id.
	DecisionChain []SEBIDecisionChainRecord `json:"decision_chain,omitempty"`

	// DecisionChains contains the SAME decision rows reconstructed into logical
	// chains: every row sharing a correlation_id grouped into one chain in step
	// order, rows without one as singletons (#2598). This is the regulator-facing
	// "decision chain" view — the chronological DecisionChain above is the
	// flattened source.
	DecisionChains []SEBIDecisionChain `json:"decision_chains,omitempty"`

	// HITLOversight contains human-in-the-loop records
	HITLOversight []SEBIHITLRecord `json:"hitl_oversight,omitempty"`

	// PIIRedactions contains PII redaction records
	PIIRedactions []SEBIPIIRedactionRecord `json:"pii_redactions,omitempty"`
}

// SEBIPolicyViolationRecord represents a policy violation for SEBI export
type SEBIPolicyViolationRecord struct {
	// ID is the unique violation ID
	ID string `json:"id"`

	// Timestamp is when the violation occurred
	Timestamp time.Time `json:"timestamp"`

	// ViolationType is the type of violation
	ViolationType string `json:"violation_type"`

	// Severity is the severity level (critical, high, medium, low)
	Severity string `json:"severity"`

	// Description is a human-readable description
	Description string `json:"description"`

	// PolicyID is the ID of the violated policy
	PolicyID string `json:"policy_id"`

	// PolicyName is the name of the violated policy
	PolicyName string `json:"policy_name"`

	// AgentID is the agent that triggered the violation
	AgentID string `json:"agent_id,omitempty"`

	// UserID is the user associated with the request
	UserID int `json:"user_id,omitempty"`

	// RequestID is the associated request ID
	RequestID string `json:"request_id,omitempty"`

	// Action is the action taken in response
	Action string `json:"action"`

	// Details contains additional violation details
	Details map[string]interface{} `json:"details,omitempty"`

	// Remediation is the remediation action taken
	Remediation string `json:"remediation,omitempty"`
}

// SEBILLMCallRecord represents an LLM call for SEBI export
type SEBILLMCallRecord struct {
	// ID is the unique call ID
	ID string `json:"id"`

	// Timestamp is when the call was made
	Timestamp time.Time `json:"timestamp"`

	// RequestID is the associated request ID
	RequestID string `json:"request_id"`

	// Provider is the LLM provider (e.g., openai, anthropic, bedrock)
	Provider string `json:"provider"`

	// Model is the model used
	Model string `json:"model"`

	// InputTokens is the number of input tokens
	InputTokens int `json:"input_tokens"`

	// OutputTokens is the number of output tokens
	OutputTokens int `json:"output_tokens"`

	// LatencyMs is the response latency in milliseconds
	LatencyMs int64 `json:"latency_ms"`

	// Cost is the estimated cost in USD
	Cost float64 `json:"cost"`

	// PolicyDecision is the policy decision (allowed, blocked, redacted)
	PolicyDecision string `json:"policy_decision"`

	// UserID is the user who made the request
	UserID int `json:"user_id,omitempty"`

	// AgentID is the agent that processed the request
	AgentID string `json:"agent_id,omitempty"`

	// InputHash is the SHA-256 hash of the input (for audit without exposing content)
	InputHash string `json:"input_hash,omitempty"`

	// OutputHash is the SHA-256 hash of the output
	OutputHash string `json:"output_hash,omitempty"`

	// RedactedFields lists fields that were redacted
	RedactedFields []string `json:"redacted_fields,omitempty"`

	// ComplianceFlags lists applicable compliance flags
	ComplianceFlags []string `json:"compliance_flags,omitempty"`
}

// SEBIDecisionChainRecord represents a decision chain for SEBI export.
// Column mapping matches migrations/core/025_decision_chain.sql.
type SEBIDecisionChainRecord struct {
	ID               string    `json:"id"`
	RequestID        string    `json:"request_id"`
	Timestamp        time.Time `json:"timestamp"`
	DecisionType     string    `json:"decision_type"`
	DecisionOutcome  string    `json:"decision_outcome"`
	RiskLevel        string    `json:"risk_level"`
	ModelID          string    `json:"model_id,omitempty"`
	RequiresReview   bool      `json:"requires_human_review"`
	PoliciesEvaluated string  `json:"policies_evaluated,omitempty"`
	PolicyTriggered  string    `json:"policy_triggered,omitempty"`
	ProcessingTimeMs *int      `json:"processing_time_ms,omitempty"`
	InputFactors     []DecisionFactor `json:"input_factors,omitempty"`
	// CorrelationID is the shared key (the W3C trace_id a PEP propagates across
	// its hops) that ties this decision to the other stages of the SAME logical
	// request; empty for legacy/single-shot rows. The grouping key for
	// SEBIDecisionChain (#2598).
	CorrelationID string `json:"correlation_id,omitempty"`
}

// SEBIDecisionChain is one logical request's decision chain: the decision rows
// sharing a correlation_id (the W3C trace_id a PEP propagates across its
// llm/tool/agent hops), in chronological step order. Rows with no correlation_id
// (legacy + single-shot callers) each form a singleton chain. #2598 / #2585.
type SEBIDecisionChain struct {
	CorrelationID string                    `json:"correlation_id,omitempty"`
	StepCount     int                       `json:"step_count"`
	StartedAt     time.Time                 `json:"started_at"`
	EndedAt       time.Time                 `json:"ended_at"`
	Steps         []SEBIDecisionChainRecord `json:"steps"`
}

// DecisionFactor represents a factor in a decision
type DecisionFactor struct {
	Name   string  `json:"name"`
	Value  string  `json:"value"`
	Weight float64 `json:"weight"`
}

// SEBIHITLRecord represents a human-in-the-loop record for SEBI export
type SEBIHITLRecord struct {
	// ID is the unique HITL record ID
	ID string `json:"id"`

	// RequestID is the associated request ID
	RequestID string `json:"request_id"`

	// Timestamp is when the HITL action occurred
	Timestamp time.Time `json:"timestamp"`

	// TriggerReason is why HITL was triggered
	TriggerReason string `json:"trigger_reason"`

	// ReviewerID is the human reviewer
	ReviewerID int `json:"reviewer_id"`

	// ReviewerEmail is the reviewer's email
	ReviewerEmail string `json:"reviewer_email,omitempty"`

	// Decision is the human decision (approved, rejected, modified)
	Decision string `json:"decision"`

	// Notes are the reviewer's notes
	Notes string `json:"notes,omitempty"`

	// ReviewTimeMs is how long the review took
	ReviewTimeMs int64 `json:"review_time_ms"`

	// OriginalResponse is the original AI response (hash)
	OriginalResponseHash string `json:"original_response_hash,omitempty"`

	// ModifiedResponse is the modified response (hash)
	ModifiedResponseHash string `json:"modified_response_hash,omitempty"`

	// ComplianceFlags lists applicable compliance flags
	ComplianceFlags []string `json:"compliance_flags,omitempty"`
}

// SEBIPIIRedactionRecord represents a PII redaction for SEBI export
type SEBIPIIRedactionRecord struct {
	// ID is the unique redaction record ID
	ID string `json:"id"`

	// RequestID is the associated request ID
	RequestID string `json:"request_id"`

	// Timestamp is when the redaction occurred
	Timestamp time.Time `json:"timestamp"`

	// PIIType is the type of PII redacted (pan, aadhaar, email, phone, etc.)
	PIIType string `json:"pii_type"`

	// RedactionMethod is how the PII was redacted (mask, hash, remove)
	RedactionMethod string `json:"redaction_method"`

	// Location is where in the content the PII was found
	Location string `json:"location"`

	// DetectionConfidence is the confidence of PII detection (0-1)
	DetectionConfidence float64 `json:"detection_confidence"`

	// UserID is the user associated with the request
	UserID int `json:"user_id,omitempty"`

	// ComplianceFramework is the applicable compliance framework
	ComplianceFramework string `json:"compliance_framework"`
}

// =============================================================================
// Retention Status Types
// =============================================================================

// SEBIRetentionStatusRequest is the request for checking retention status
type SEBIRetentionStatusRequest struct {
	// DataTypes specifies which data types to check
	DataTypes []SEBIAuditDataType `json:"data_types,omitempty"`
}

// SEBIRetentionStatusResponse is the response for retention status
type SEBIRetentionStatusResponse struct {
	// TenantID is the tenant identifier
	TenantID string `json:"tenant_id"`

	// Framework is the compliance framework
	Framework SEBIComplianceFramework `json:"framework"`

	// Status contains status for each data type
	Status []SEBIDataTypeRetentionStatus `json:"status"`

	// ComplianceStatus is the overall compliance status
	ComplianceStatus string `json:"compliance_status"`

	// NextCleanup is when the next cleanup is scheduled
	NextCleanup time.Time `json:"next_cleanup,omitempty"`
}

// SEBIDataTypeRetentionStatus contains retention status for a data type
type SEBIDataTypeRetentionStatus struct {
	// DataType is the data type
	DataType SEBIAuditDataType `json:"data_type"`

	// RetentionDays is the configured retention period
	RetentionDays int `json:"retention_days"`

	// OldestRecord is the timestamp of the oldest record
	OldestRecord time.Time `json:"oldest_record,omitempty"`

	// NewestRecord is the timestamp of the newest record
	NewestRecord time.Time `json:"newest_record,omitempty"`

	// TotalRecords is the total number of records
	TotalRecords int64 `json:"total_records"`

	// ArchivedRecords is the number of archived records
	ArchivedRecords int64 `json:"archived_records"`

	// StorageBytes is the estimated storage used
	StorageBytes int64 `json:"storage_bytes,omitempty"`

	// ComplianceStatus indicates if retention meets compliance requirements
	ComplianceStatus string `json:"compliance_status"`

	// LastCleanup is when cleanup last ran
	LastCleanup time.Time `json:"last_cleanup,omitempty"`
}

// =============================================================================
// Service Interface
// =============================================================================

// SEBIAuditExportService defines the interface for SEBI audit export operations
type SEBIAuditExportService interface {
	// ExportAuditData exports audit data for SEBI compliance
	ExportAuditData(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error)

	// GetRetentionStatus returns the retention status for audit data
	GetRetentionStatus(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error)


	// ValidateComplianceReadiness checks if the org is ready for SEBI audit
	ValidateComplianceReadiness(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error)
}

// SEBIComplianceReadinessResponse indicates readiness for SEBI audit
type SEBIComplianceReadinessResponse struct {
	// Ready indicates if the org is ready for audit
	Ready bool `json:"ready"`

	// Score is the compliance readiness score (0-100)
	Score int `json:"score"`

	// Checks contains individual compliance checks
	Checks []SEBIComplianceCheck `json:"checks"`

	// Recommendations contains improvement recommendations
	Recommendations []string `json:"recommendations,omitempty"`
}

// SEBIComplianceCheck represents a single compliance check
type SEBIComplianceCheck struct {
	// Name is the check name
	Name string `json:"name"`

	// Description is what the check verifies
	Description string `json:"description"`

	// Status is the check status (pass, fail, warning)
	Status string `json:"status"`

	// Details provides additional information
	Details string `json:"details,omitempty"`
}
