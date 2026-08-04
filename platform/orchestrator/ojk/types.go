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
	OJKFrameworkUUPDP        OJKComplianceFramework = "UU_PDP"
	OJKFrameworkBIPJP        OJKComplianceFramework = "BI_PJP"
	OJKFrameworkCombined     OJKComplianceFramework = "OJK_BI_COMBINED"
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
	OJKDataTypePolicyViolations OJKAuditDataType = "policy_violations"
	OJKDataTypeLLMCalls         OJKAuditDataType = "llm_calls"
	OJKDataTypeDecisionChain    OJKAuditDataType = "decision_chain"
	OJKDataTypeHITLOversight    OJKAuditDataType = "hitl_oversight"
	OJKDataTypePIIRedactions    OJKAuditDataType = "pii_redactions"
	OJKDataTypeCrossBorder      OJKAuditDataType = "cross_border_transfers"
	OJKDataTypeBreachNotify     OJKAuditDataType = "breach_notifications"
	OJKDataTypeAll              OJKAuditDataType = "all"
)

// OJKAuditExportRequest is the request body for audit export.
type OJKAuditExportRequest struct {
	StartDate  string                 `json:"start_date"`
	EndDate    string                 `json:"end_date"`
	Format     OJKExportFormat        `json:"format,omitempty"`
	Framework  OJKComplianceFramework `json:"framework,omitempty"`
	DataTypes  []OJKAuditDataType     `json:"data_types,omitempty"`
	Filters    *OJKAuditExportFilters `json:"filters,omitempty"`
	IncludePII bool                   `json:"include_pii,omitempty"`
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
	ExportID  string                 `json:"export_id"`
	Status    string                 `json:"status"`
	Framework OJKComplianceFramework `json:"framework"`
	// Format is the format this response BODY is actually in, not the one that
	// was asked for. On this endpoint it is always json: the body is written
	// with Content-Type: application/json and the data is inline JSON.
	//
	// It used to echo req.Format, so a request for csv came back labelled
	// `"format": "csv"` with a JSON body -- the same content-mislabel class the
	// epic #2892 design record calls out for SEBI (D5). A regulator artifact
	// that misstates its own encoding is worse than one that refuses.
	Format OJKExportFormat `json:"format"`
	// RequestedFormat is set ONLY when the caller asked for something this
	// endpoint does not produce. Its presence is the signal that the body is
	// not what was requested.
	RequestedFormat OJKExportFormat `json:"requested_format,omitempty"`
	// FormatNote explains the discrepancy in words, so a human reading the
	// artifact does not have to infer it from two fields disagreeing.
	FormatNote  string                 `json:"format_note,omitempty"`
	Summary     *OJKAuditExportSummary `json:"summary,omitempty"`
	Data        *OJKAuditExportData    `json:"data,omitempty"`
	DownloadURL string                 `json:"download_url,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty"`
	Metadata    *OJKExportMetadata     `json:"metadata,omitempty"`
}

// OJKAuditExportSummary contains statistics about the exported data.
type OJKAuditExportSummary struct {
	TotalRecords    int            `json:"total_records"`
	RecordsByType   map[string]int `json:"records_by_type"`
	DateRange       DateRange      `json:"date_range"`
	ComplianceScore float64        `json:"compliance_score"`
	// ComplianceScoreUnknownChecks is how many readiness dimensions could not be
	// measured when ComplianceScore was computed. Non-zero means the score is
	// over a partially-observable deployment; an unmeasurable dimension scores
	// zero, so the number falls rather than inflating, but a reader still needs
	// to know the difference between a low score and a blind one.
	ComplianceScoreUnknownChecks int `json:"compliance_score_unknown_checks"`
	// ReportState is the roll-up of the per-section states below (#2892 design
	// record). populated iff at least one section is populated; not_available
	// iff EVERY requested section is not_available; enabled_empty otherwise.
	// It exists so a consumer never has to infer "module not enabled" from an
	// empty body -- a state the backend cannot actually produce.
	ReportState OJKReportState `json:"report_state"`
	// Sections carries one honest status per REQUESTED data type, in request
	// order (or framework order when the caller named none). A requested type
	// that could not be served appears here with an Error -- it is never
	// silently dropped, which is the defect this replaces.
	Sections []OJKSectionStatus `json:"sections"`
	// FrameworkSummary explains what the selected framework label scoped the
	// report to, and why. Present on every export.
	FrameworkSummary *OJKFrameworkSummary `json:"framework_summary,omitempty"`
}

// OJKReportState is the three-state report contract from the epic #2892 design
// record. It is carried per section AND rolled up on the summary.
//
//   - not_available: this deployment cannot serve the section at all (the
//     backing table is absent, e.g. the enterprise migration has not been
//     applied, or the requested data type is not implemented).
//   - enabled_empty: the section IS served and the honest answer is zero rows
//     for this org and window.
//   - populated: at least one row.
//
// The distinction is the whole point: an empty section must render as empty,
// never as "module not enabled", and a missing capability must never render as
// a clean zero.
type OJKReportState string

// Section error kinds. See OJKSectionStatus.ErrorKind.
const (
	OJKSectionErrorNotImplemented = "section_not_implemented"
	OJKSectionErrorStoreAbsent    = "store_absent"
	OJKSectionErrorQueryFailed    = "query_failed"
)

const (
	OJKReportStateNotAvailable OJKReportState = "not_available"
	OJKReportStateEnabledEmpty OJKReportState = "enabled_empty"
	OJKReportStatePopulated    OJKReportState = "populated"
)

// OJKSectionStatus is the per-data-type outcome of one export.
type OJKSectionStatus struct {
	DataType    OJKAuditDataType `json:"data_type"`
	ReportState OJKReportState   `json:"report_state"`
	RecordCount int              `json:"record_count"`
	// Error is set when the section could not be served: an unknown data type,
	// a missing backing store, or a query failure. Non-empty Error always pairs
	// with ReportState=not_available.
	Error string `json:"error,omitempty"`
	// ErrorKind CLASSIFIES that failure, because report_state alone cannot.
	// "the deployment structurally cannot produce human-oversight evidence" and
	// "that query timed out once" are very different things to tell a regulator,
	// and both previously rendered as a bare not_available.
	//   section_not_implemented - the requested data type has no handler
	//   store_absent            - the backing table does not exist here
	//   query_failed            - the store exists and the read failed
	// Empty when the section was served.
	ErrorKind string `json:"error_kind,omitempty"`
	// InFrameworkScope is false when the caller explicitly asked for a section
	// that the selected framework does not consider in scope. The section is
	// still served (an explicit request wins) but is flagged so a regulator
	// reading a BI PJP pack knows which parts are supplementary.
	InFrameworkScope bool `json:"in_framework_scope"`
	// Note carries the framework-specific relevance of this section, or the
	// reason it is out of scope.
	Note string `json:"note,omitempty"`
}

// OJKFrameworkSummary is the framework-specific block that makes the four
// framework labels produce four DIFFERENT reports rather than four labels on
// one report.
type OJKFrameworkSummary struct {
	Framework OJKComplianceFramework `json:"framework"`
	Title     string                 `json:"title"`
	// Citation is the instrument the section selection is derived from.
	Citation string `json:"citation"`
	// Sections is the framework's in-scope data types, in report order.
	Sections []OJKAuditDataType   `json:"sections"`
	Pillars  []OJKFrameworkPillar `json:"pillars"`
	Notes    string               `json:"notes,omitempty"`
}

// OJKFrameworkPillar maps one regulatory pillar to the report sections that
// evidence it.
type OJKFrameworkPillar struct {
	Name        string             `json:"name"`
	Citation    string             `json:"citation,omitempty"`
	Description string             `json:"description"`
	Sections    []OJKAuditDataType `json:"sections"`
}

// DateRange represents a time range.
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// OJKAuditExportData contains the exported audit data.
//
// Every slice is `omitempty`, so ABSENCE here is ambiguous by construction --
// which is exactly why OJKAuditExportSummary.Sections carries an explicit
// per-section report_state. Read the section status, not the presence of a key.
type OJKAuditExportData struct {
	PolicyViolations []OJKPolicyViolationRecord `json:"policy_violations,omitempty"`
	LLMCalls         []OJKLLMCallRecord         `json:"llm_calls,omitempty"`
	DecisionChains   []OJKDecisionChainRecord   `json:"decision_chains,omitempty"`
	// DecisionChainGroups is the same steps grouped by correlation_id (one
	// entry per logical request), mirroring SEBI's #2598 lineage shape.
	DecisionChainGroups []OJKDecisionChain            `json:"decision_chain_groups,omitempty"`
	HITLRecords         []OJKHITLRecord               `json:"hitl_records,omitempty"`
	PIIRedactions       []OJKPIIRedactionRecord       `json:"pii_redactions,omitempty"`
	CrossBorder         []CrossBorderTransferRecord   `json:"cross_border_transfers,omitempty"`
	BreachNotifications []OJKBreachNotificationRecord `json:"breach_notifications,omitempty"`
}

// OJKPolicyViolationRecord is a single policy-violation entry.
//
// Sourced from the canonical audit_logs decision rows whose verdict refused or
// modified the request (blocked / redacted / needs_approval) -- NOT from the
// legacy policy_violations table, which the Indonesia enforcement paths do not
// write. PolicyID/PolicyName come from policy_details->'policy_ids'; the
// Indonesia PII block path stamps "indonesia_pii_protection" there.
type OJKPolicyViolationRecord struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	PolicyID   string    `json:"policy_id"`
	PolicyName string    `json:"policy_name"`
	Severity   string    `json:"severity"`
	// Action is the canonical audit verdict (blocked | redacted |
	// needs_approval) -- what the platform DID.
	Action string `json:"action"`
	// Description is the recorded reason. It is the platform's own reason text
	// (policy_details->>'reason'), never the caller's query.
	Description string `json:"description"`
	// Plane is the enforcement surface (gateway | decision | mcp | llm | ...).
	Plane string `json:"plane,omitempty"`
	// TenantID is the tenant the refused request belonged to, recorded so an
	// org-wide pack is still attributable per tenant.
	TenantID string `json:"tenant_id,omitempty"`
}

// OJKLLMCallRecord is a single LLM-plane call, METADATA ONLY.
//
// Sourced from audit_logs rows with plane='llm' (the orchestrator's LLM-forward
// writer). Prompt and response bodies are deliberately NOT exported: OJK AI
// governance asks which model was invoked under which verdict, not what was
// said. audit_logs.query / response_sample exist on the row and are not read.
type OJKLLMCallRecord struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	ModelID     string    `json:"model_id"`
	Provider    string    `json:"provider"`
	TotalTokens int       `json:"total_tokens"`
	Cost        float64   `json:"cost"`
	LatencyMS   int64     `json:"latency_ms"`
	// PolicyDecision is the canonical audit verdict for the call.
	PolicyDecision string `json:"policy_decision"`
	// TransferBasis / DataResidency are the UU PDP Pasal 56 attributes stamped
	// on the forward when the operator declared a basis. Empty when this call
	// was not a declared cross-border transfer.
	TransferBasis string `json:"transfer_basis,omitempty"`
	DataResidency string `json:"data_residency,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// OJKDecisionChainRecord is one step of a governance decision chain.
//
// Mirrors SEBI's exportDecisionChain lineage (#2596/#2598): the steps of one
// logical request share a correlation_id, so OJKDecisionChain groups them.
type OJKDecisionChainRecord struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	DecisionID string    `json:"decision_id"`
	// CorrelationID is the shared key across the steps of one logical request.
	// Empty for single-shot callers, which become singleton chains.
	CorrelationID string `json:"correlation_id,omitempty"`
	// Stage is the decision stage (llm | tool | agent), Plane the surface.
	Stage string `json:"stage,omitempty"`
	Plane string `json:"plane,omitempty"`
	// Outcome is the canonical audit verdict for this step.
	Outcome string `json:"outcome"`
	// RiskLevel is NOT captured on canonical decision rows. It is left empty
	// rather than fabricated -- a regulator export must not invent a rating.
	RiskLevel      string `json:"risk_level,omitempty"`
	ModelID        string `json:"model_id,omitempty"`
	RequiresReview bool   `json:"requires_review"`
	TenantID       string `json:"tenant_id,omitempty"`
}

// OJKDecisionChain is one logical request's ordered decision steps.
type OJKDecisionChain struct {
	CorrelationID string                   `json:"correlation_id"`
	StepCount     int                      `json:"step_count"`
	StartedAt     time.Time                `json:"started_at"`
	EndedAt       time.Time                `json:"ended_at"`
	Steps         []OJKDecisionChainRecord `json:"steps"`
}

// OJKHITLRecord is a single human-in-the-loop oversight entry.
//
// Sourced from hitl_approval_queue (the store the evidence exporter reads),
// org-scoped. Only REVIEWED rows are exported: a still-pending request is not
// evidence of oversight having occurred.
type OJKHITLRecord struct {
	ID        string    `json:"id"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`
	// TriggerReason is why human oversight was required.
	TriggerReason string `json:"trigger_reason"`
	// TriggeredPolicyID / Name identify the gate that fired.
	TriggeredPolicyID   string `json:"triggered_policy_id,omitempty"`
	TriggeredPolicyName string `json:"triggered_policy_name,omitempty"`
	Severity            string `json:"severity,omitempty"`
	ReviewerID          string `json:"reviewer_id,omitempty"`
	ReviewerRole        string `json:"reviewer_role,omitempty"`
	// Decision is the queue status at review time (approved | rejected |
	// expired | overridden).
	Decision   string     `json:"decision"`
	ReviewedAt *time.Time `json:"reviewed_at,omitempty"`
	// ReviewTimeMS is reviewed_at - created_at. Zero when never reviewed.
	ReviewTimeMS int64  `json:"review_time_ms"`
	TenantID     string `json:"tenant_id,omitempty"`
}

// OJKPIIRedactionRecord is a single Indonesia PII detection event.
//
// Sourced from indonesia_pii_detection_events (enterprise migration 137),
// written by the Indonesia detector on the gateway / decision / MCP planes.
// MaskedValue is the detector's masked form; the raw detected value is never
// stored and therefore can never be exported.
type OJKPIIRedactionRecord struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	// PIIType is the detector type (nik, npwp_legacy, npwp_new,
	// phone_indonesia, bank_bca, bank_mandiri, bank_bri, bank_bni).
	PIIType string `json:"pii_type"`
	// OJKCategory is the regulator-facing grouping (national_identity |
	// tax_identifier | contact_information | financial_account).
	OJKCategory string `json:"ojk_category"`
	Severity    string `json:"severity"`
	// MaskedValue is the masked form only.
	MaskedValue string `json:"masked_value"`
	// RedactionMethod names how the value was masked. Constant for this
	// detector; recorded so the column means something to an auditor.
	RedactionMethod string  `json:"redaction_method"`
	Confidence      float64 `json:"confidence"`
	// Action is what the platform did:
	//   blocked            - the request/response was refused
	//   redacted           - THIS plane masked the value before forwarding
	//   redaction_required - a policy decision point determined redaction was
	//                        required and told the PEP; it masked nothing itself
	//                        (the gateway pre-check and /api/v1/decide are PDPs)
	//   detected           - forwarded UNMODIFIED under a warn/log posture, the
	//                        case an auditor most needs to see
	Action string `json:"action"`
	// Plane is the enforcement surface that observed it.
	Plane string `json:"plane"`
	// DecisionID / CorrelationID join back to the audit_logs decision row.
	DecisionID    string `json:"decision_id,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	TenantID      string `json:"tenant_id,omitempty"`
}

// CrossBorderTransferRecord tracks data transfers for UU PDP Art. 56.
type CrossBorderTransferRecord struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	DataResidency string    `json:"data_residency"`
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
	TransferBasis      string   `json:"transfer_basis"`
	DestinationCountry string   `json:"destination_country"`
	DataCategories     []string `json:"data_categories,omitempty"`
	ApprovalStatus     string   `json:"approval_status,omitempty"`
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
	DataType     OJKAuditDataType `json:"data_type"`
	Status       string           `json:"status"`
	OldestRecord *time.Time       `json:"oldest_record,omitempty"`
	NewestRecord *time.Time       `json:"newest_record,omitempty"`
	TotalRecords int64            `json:"total_records"`
}

// OJKComplianceReadinessResponse contains compliance readiness assessment.
type OJKComplianceReadinessResponse struct {
	// Ready requires: every check MEASURED (no unknowns), no failures, and a
	// score at or above OJKReadinessReadyScore. An unknown dimension blocks
	// readiness rather than being scored as a pass -- claiming readiness on a
	// dimension the platform could not observe is the defect this replaces.
	Ready bool `json:"ready"`
	// Score is over the MEASURABLE checks only: pass counts 1, warning 0.5,
	// fail 0, unknown is excluded from both numerator and denominator. Zero
	// when nothing could be measured.
	Score           int                    `json:"score"` // 0-100
	Framework       OJKComplianceFramework `json:"framework"`
	Checks          []OJKComplianceCheck   `json:"checks"`
	Recommendations []string               `json:"recommendations,omitempty"`
	// MeasuredChecks / UnknownChecks make the score's denominator visible, so a
	// consumer can tell "80% of everything" from "80% of the half we could see".
	MeasuredChecks int `json:"measured_checks"`
	UnknownChecks  int `json:"unknown_checks"`
}

// Readiness check statuses. "unknown" is first-class: a dimension the platform
// cannot observe from this deployment reports unknown, never a pass.
const (
	OJKCheckPass    = "pass"
	OJKCheckWarning = "warning"
	OJKCheckFail    = "fail"
	OJKCheckUnknown = "unknown"
)

// OJKReadinessReadyScore is the score threshold for Ready (in addition to the
// no-failures and no-unknowns conditions).
const OJKReadinessReadyScore = 80

// OJKComplianceCheck is a single compliance readiness check.
type OJKComplianceCheck struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Status is one of OJKCheckPass / OJKCheckWarning / OJKCheckFail /
	// OJKCheckUnknown.
	Status string `json:"status"`
	// Details states WHAT WAS OBSERVED, including the query that produced it.
	// A check must never assert a fact it did not measure.
	Details string `json:"details,omitempty"`
	// Observed is the raw measurement behind Status, when there is one (a row
	// count, a policy count). Nil for unknown.
	Observed *int64 `json:"observed,omitempty"`
}

// OJKBreachNotification represents a UU PDP Art. 46 breach notification.
type OJKBreachNotification struct {
	ID                   string    `json:"id,omitempty"`
	IncidentTimestamp    time.Time `json:"incident_timestamp"`
	DiscoveryTime        time.Time `json:"discovery_time"`
	NotificationDeadline time.Time `json:"notification_deadline,omitempty"`
	DataSubjectsAffected int       `json:"data_subjects_affected"`
	DataTypesInvolved    []string  `json:"data_types_involved"`
	Description          string    `json:"description"`
	RemediationSteps     []string  `json:"remediation_steps"`
	NotifiedAuthority    string    `json:"notified_authority,omitempty"` // MOCDA (until DPA constituted)
	Status               string    `json:"status,omitempty"`
	// SubmittedAt is set when the notification is transmitted to the authority
	// (the draft→submitted transition). Timely iff <= NotificationDeadline.
	SubmittedAt *time.Time `json:"submitted_at,omitempty"`
	// AcknowledgedAt is set when the authority confirms receipt
	// (the submitted→acknowledged transition).
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at,omitempty"`
}

// OJKBreachNotificationRecord is a single breach-notification audit entry as
// surfaced by ExportAuditData for OJKDataTypeBreachNotify. Status is the
// EFFECTIVE lifecycle status (the deadline evaluator is applied at export time),
// while StoredStatus is the durable operator-driven value persisted in the row.
type OJKBreachNotificationRecord struct {
	ID                   string    `json:"id"`
	IncidentTimestamp    time.Time `json:"incident_timestamp"`
	DiscoveryTime        time.Time `json:"discovery_time"`
	NotificationDeadline time.Time `json:"notification_deadline"`
	DataSubjectsAffected int       `json:"data_subjects_affected"`
	DataTypesInvolved    []string  `json:"data_types_involved,omitempty"`
	NotifiedAuthority    string    `json:"notified_authority,omitempty"`
	// Status is the effective status at export time — an un-acknowledged breach
	// past its 72h window reads "overdue" even if never explicitly flipped.
	Status string `json:"status"`
	// StoredStatus is the durable lifecycle value persisted in the row.
	StoredStatus   string     `json:"stored_status,omitempty"`
	SubmittedAt    *time.Time `json:"submitted_at,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	// WithinDeadline is the UU PDP Art. 46 timeliness verdict: false once the
	// breach is overdue (never transmitted in time / submitted late) or failed.
	WithinDeadline bool      `json:"within_deadline"`
	CreatedAt      time.Time `json:"created_at"`
}

// OJKDashboardResponse contains the OJK compliance dashboard data.
//
// Every count is an org-scoped aggregate derived from a query. None of them is
// a literal. Where a count could not be derived it is reported as -1 and named
// in Unavailable, rather than presented as a confident zero.
type OJKDashboardResponse struct {
	Framework       OJKComplianceFramework `json:"framework"`
	ComplianceScore int                    `json:"compliance_score"`
	// TotalAuditRecords is audit_logs rows for the org (all time).
	TotalAuditRecords int64 `json:"total_audit_records"`
	// ActivePolicies is the count of ENABLED Indonesia-relevant policy rows
	// visible to this org: the global/system tier plus the org's own.
	ActivePolicies int `json:"active_policies"`
	// RecentViolations is refusing/modifying decisions (blocked, redacted,
	// needs_approval) recorded for the org over the last
	// OJKDashboardRecentDays days.
	RecentViolations int    `json:"recent_violations"`
	RetentionStatus  string `json:"retention_status"`
	// ReadinessUnknownChecks is how many readiness dimensions could not be
	// measured. A non-zero value means compliance_score is a score over a
	// partially-observable deployment, and "compliance_score:partial" appears in
	// Unavailable.
	ReadinessUnknownChecks int `json:"readiness_unknown_checks"`
	// IndonesiaPIIEvents is Indonesia PII detection events for the org over the
	// same recent window.
	IndonesiaPIIEvents  int `json:"indonesia_pii_events"`
	BreachNotifications int `json:"breach_notifications"`
	// OverdueBreachNotifications is the count of breaches whose effective status
	// is overdue (past the 72h window without a timely submission, not yet
	// acknowledged/failed) — the UU PDP Art. 46 compliance-risk signal.
	OverdueBreachNotifications int `json:"overdue_breach_notifications"`
	// Unavailable names the counts that could not be derived on this
	// deployment (missing table, permission denied). EVERY name here carries -1
	// in its field. Empty on a healthy deployment.
	//
	// compliance_score is deliberately NOT listed here even when it is computed
	// over a partially-observable deployment: it is a real number, not -1, and
	// mixing "could not measure" with "measured over less than everything" in
	// one list would leave a consumer unable to trust either. Read
	// ReadinessUnknownChecks for that.
	Unavailable []string  `json:"unavailable,omitempty"`
	LastUpdated time.Time `json:"last_updated"`
}

// OJKDashboardRecentDays is the trailing window for the dashboard's "recent"
// counts. Named so the number a customer sees is traceable to one constant.
const OJKDashboardRecentDays = 30

// OJKCountUnavailable is the sentinel a dashboard count carries when it could
// not be derived. It is deliberately not 0: "we could not measure" and "there
// were none" are different answers to a regulator.
const OJKCountUnavailable = -1

// OJKAuditExportService is the interface for OJK audit export operations.
type OJKAuditExportService interface {
	ExportAuditData(ctx context.Context, tenantID string, req *OJKAuditExportRequest) (*OJKAuditExportResponse, error)
	GetRetentionStatus(ctx context.Context, tenantID string, req *OJKRetentionStatusRequest) (*OJKRetentionStatusResponse, error)
	GetExportStatus(ctx context.Context, tenantID string, exportID string) (*OJKAuditExportResponse, error)
	ValidateComplianceReadiness(ctx context.Context, tenantID string) (*OJKComplianceReadinessResponse, error)
	SubmitBreachNotification(ctx context.Context, tenantID string, req *OJKBreachNotification) (*OJKBreachNotification, error)
	// AcknowledgeBreachNotification records authority receipt for a previously
	// submitted breach (gated submitted→acknowledged transition; sets
	// acknowledged_at). Returns ErrBreachNotFound / ErrInvalidBreachTransition.
	AcknowledgeBreachNotification(ctx context.Context, tenantID string, id string) (*OJKBreachNotification, error)
	// EvaluateBreachDeadlines flips never-submitted drafts whose 72h window has
	// lapsed to overdue, durably. Returns the number of rows flipped.
	EvaluateBreachDeadlines(ctx context.Context, tenantID string) (int, error)
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
