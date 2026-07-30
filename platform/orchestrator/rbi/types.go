// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

// Package rbi provides types and services for RBI FREE-AI Framework compliance.
//
// This package implements the Reserve Bank of India's Framework for Responsible
// and Ethical Enablement of Artificial Intelligence (FREE-AI) as outlined in
// the August 2025 committee report.
//
// Key features:
//   - AI System Registry with board approval workflow
//   - Model Validation tracking (development, independent, post-deployment)
//   - Incident Management with board/RBI notification
//   - Kill Switch for emergency stop capability
//   - Board Reporting for quarterly compliance reports
//
// Reference: https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx?prid=59377
//go:build enterprise

package rbi

import (
	"time"
)

// =============================================================================
// Enums and Constants
// =============================================================================

// RiskCategory represents the risk classification per RBI guidelines.
type RiskCategory string

const (
	RiskCategoryLow    RiskCategory = "low"    // Chatbots, FAQ systems
	RiskCategoryMedium RiskCategory = "medium" // Credit scoring, fraud detection
	RiskCategoryHigh   RiskCategory = "high"   // Algorithmic trading, loan approval
)

// Valid returns true if the risk category is valid.
func (r RiskCategory) Valid() bool {
	switch r {
	case RiskCategoryLow, RiskCategoryMedium, RiskCategoryHigh:
		return true
	}
	return false
}

// DeploymentStatus represents the deployment lifecycle status.
type DeploymentStatus string

const (
	DeploymentStatusDevelopment DeploymentStatus = "development"
	DeploymentStatusSandbox     DeploymentStatus = "sandbox"
	DeploymentStatusCanary      DeploymentStatus = "canary"
	DeploymentStatusProduction  DeploymentStatus = "production"
	DeploymentStatusDeprecated  DeploymentStatus = "deprecated"
)

// Valid returns true if the deployment status is valid.
func (d DeploymentStatus) Valid() bool {
	switch d {
	case DeploymentStatusDevelopment, DeploymentStatusSandbox,
		DeploymentStatusCanary, DeploymentStatusProduction, DeploymentStatusDeprecated:
		return true
	}
	return false
}

// BoardApprovalStatus represents the board approval workflow status.
type BoardApprovalStatus string

const (
	BoardApprovalNotRequired BoardApprovalStatus = "not_required"
	BoardApprovalPending     BoardApprovalStatus = "pending"
	BoardApprovalApproved    BoardApprovalStatus = "approved"
	BoardApprovalRejected    BoardApprovalStatus = "rejected"
	BoardApprovalRevoked     BoardApprovalStatus = "revoked"
)

// Valid returns true if the board approval status is valid.
func (b BoardApprovalStatus) Valid() bool {
	switch b {
	case BoardApprovalNotRequired, BoardApprovalPending,
		BoardApprovalApproved, BoardApprovalRejected, BoardApprovalRevoked:
		return true
	}
	return false
}

// ValidationType represents the type of model validation.
type ValidationType string

const (
	ValidationTypeDevelopment   ValidationType = "development"
	ValidationTypeIndependent   ValidationType = "independent"
	ValidationTypePostDeployment ValidationType = "post_deployment"
	ValidationTypeStressTest    ValidationType = "stress_test"
	ValidationTypeBiasAudit     ValidationType = "bias_audit"
)

// Valid returns true if the validation type is valid.
func (v ValidationType) Valid() bool {
	switch v {
	case ValidationTypeDevelopment, ValidationTypeIndependent,
		ValidationTypePostDeployment, ValidationTypeStressTest, ValidationTypeBiasAudit:
		return true
	}
	return false
}

// ValidatorType represents who performed the validation.
type ValidatorType string

const (
	ValidatorTypeInternal       ValidatorType = "internal"
	ValidatorTypeExternalAuditor ValidatorType = "external_auditor"
	ValidatorTypeRegulator      ValidatorType = "regulator"
)

// Valid returns true if the validator type is valid.
func (v ValidatorType) Valid() bool {
	switch v {
	case ValidatorTypeInternal, ValidatorTypeExternalAuditor, ValidatorTypeRegulator:
		return true
	}
	return false
}

// ValidationRecommendation represents the validation outcome.
type ValidationRecommendation string

const (
	ValidationRecommendationApprove     ValidationRecommendation = "approve"
	ValidationRecommendationConditional ValidationRecommendation = "conditional"
	ValidationRecommendationReject      ValidationRecommendation = "reject"
	ValidationRecommendationRetest      ValidationRecommendation = "retest"
)

// Valid returns true if the validation recommendation is valid.
func (v ValidationRecommendation) Valid() bool {
	switch v {
	case ValidationRecommendationApprove, ValidationRecommendationConditional,
		ValidationRecommendationReject, ValidationRecommendationRetest:
		return true
	}
	return false
}

// IncidentType represents the type of AI incident.
type IncidentType string

const (
	IncidentTypeModelFailure           IncidentType = "model_failure"
	IncidentTypeBiasDetected           IncidentType = "bias_detected"
	IncidentTypeSecurityBreach         IncidentType = "security_breach"
	IncidentTypeDataLeak               IncidentType = "data_leak"
	IncidentTypePerformanceDegradation IncidentType = "performance_degradation"
	IncidentTypeRegulatoryViolation    IncidentType = "regulatory_violation"
	IncidentTypeCustomerHarm           IncidentType = "customer_harm"
	IncidentTypeFinancialLoss          IncidentType = "financial_loss"
	IncidentTypeOther                  IncidentType = "other"
)

// Valid returns true if the incident type is valid.
func (i IncidentType) Valid() bool {
	switch i {
	case IncidentTypeModelFailure, IncidentTypeBiasDetected, IncidentTypeSecurityBreach,
		IncidentTypeDataLeak, IncidentTypePerformanceDegradation, IncidentTypeRegulatoryViolation,
		IncidentTypeCustomerHarm, IncidentTypeFinancialLoss, IncidentTypeOther:
		return true
	}
	return false
}

// IncidentSeverity represents the severity of an incident.
type IncidentSeverity string

const (
	IncidentSeverityLow      IncidentSeverity = "low"
	IncidentSeverityMedium   IncidentSeverity = "medium"
	IncidentSeverityHigh     IncidentSeverity = "high"
	IncidentSeverityCritical IncidentSeverity = "critical"
)

// Valid returns true if the incident severity is valid.
func (s IncidentSeverity) Valid() bool {
	switch s {
	case IncidentSeverityLow, IncidentSeverityMedium, IncidentSeverityHigh, IncidentSeverityCritical:
		return true
	}
	return false
}

// RequiresBoardNotification returns true if the severity requires board notification.
func (s IncidentSeverity) RequiresBoardNotification() bool {
	return s == IncidentSeverityHigh || s == IncidentSeverityCritical
}

// IncidentStatus represents the status of an incident.
type IncidentStatus string

const (
	IncidentStatusOpen          IncidentStatus = "open"
	IncidentStatusInvestigating IncidentStatus = "investigating"
	IncidentStatusMitigated     IncidentStatus = "mitigated"
	IncidentStatusResolved      IncidentStatus = "resolved"
	IncidentStatusClosed        IncidentStatus = "closed"
	IncidentStatusReopened      IncidentStatus = "reopened"
)

// Valid returns true if the incident status is valid.
func (s IncidentStatus) Valid() bool {
	switch s {
	case IncidentStatusOpen, IncidentStatusInvestigating, IncidentStatusMitigated,
		IncidentStatusResolved, IncidentStatusClosed, IncidentStatusReopened:
		return true
	}
	return false
}

// DetectionMethod represents how an incident was detected.
type DetectionMethod string

const (
	DetectionMethodAutomated        DetectionMethod = "automated_monitoring"
	DetectionMethodHumanReview      DetectionMethod = "human_review"
	DetectionMethodCustomerComplaint DetectionMethod = "customer_complaint"
	DetectionMethodInternalAudit    DetectionMethod = "internal_audit"
	DetectionMethodExternalAudit    DetectionMethod = "external_audit"
	DetectionMethodRegulator        DetectionMethod = "regulator"
	DetectionMethodOther            DetectionMethod = "other"
)

// Valid returns true if the detection method is valid.
func (d DetectionMethod) Valid() bool {
	switch d {
	case DetectionMethodAutomated, DetectionMethodHumanReview, DetectionMethodCustomerComplaint,
		DetectionMethodInternalAudit, DetectionMethodExternalAudit, DetectionMethodRegulator, DetectionMethodOther:
		return true
	}
	return false
}

// KillSwitchScope represents the scope of a kill switch.
type KillSwitchScope string

const (
	KillSwitchScopeGlobal  KillSwitchScope = "global"
	KillSwitchScopeSystem  KillSwitchScope = "system"
	KillSwitchScopeModel   KillSwitchScope = "model"
	KillSwitchScopeFeature KillSwitchScope = "feature"
	KillSwitchScopeUseCase KillSwitchScope = "use_case"
)

// Valid returns true if the kill switch scope is valid.
func (k KillSwitchScope) Valid() bool {
	switch k {
	case KillSwitchScopeGlobal, KillSwitchScopeSystem, KillSwitchScopeModel,
		KillSwitchScopeFeature, KillSwitchScopeUseCase:
		return true
	}
	return false
}

// FallbackBehavior represents the fallback when kill switch is active.
type FallbackBehavior string

const (
	FallbackBehaviorBlockAll        FallbackBehavior = "block_all"
	FallbackBehaviorHumanReview     FallbackBehavior = "human_review"
	FallbackBehaviorPreviousVersion FallbackBehavior = "previous_version"
	FallbackBehaviorManualOnly      FallbackBehavior = "manual_only"
	FallbackBehaviorGracefulDegrade FallbackBehavior = "graceful_degrade"
)

// Valid returns true if the fallback behavior is valid.
func (f FallbackBehavior) Valid() bool {
	switch f {
	case FallbackBehaviorBlockAll, FallbackBehaviorHumanReview, FallbackBehaviorPreviousVersion,
		FallbackBehaviorManualOnly, FallbackBehaviorGracefulDegrade:
		return true
	}
	return false
}

// KillSwitchAction represents an action on a kill switch.
type KillSwitchAction string

const (
	KillSwitchActionCreated       KillSwitchAction = "created"
	KillSwitchActionActivated     KillSwitchAction = "activated"
	KillSwitchActionDeactivated   KillSwitchAction = "deactivated"
	KillSwitchActionAutoTriggered KillSwitchAction = "auto_triggered"
	KillSwitchActionConfigUpdated KillSwitchAction = "config_updated"
	KillSwitchActionDeleted       KillSwitchAction = "deleted"
)

// Valid returns true if the kill switch action is valid.
func (a KillSwitchAction) Valid() bool {
	switch a {
	case KillSwitchActionCreated, KillSwitchActionActivated, KillSwitchActionDeactivated,
		KillSwitchActionAutoTriggered, KillSwitchActionConfigUpdated, KillSwitchActionDeleted:
		return true
	}
	return false
}

// ReportType represents the type of board report.
type ReportType string

const (
	ReportTypeQuarterly  ReportType = "quarterly"
	ReportTypeAnnual     ReportType = "annual"
	ReportTypeIncident   ReportType = "incident"
	ReportTypeAdhoc      ReportType = "adhoc"
	ReportTypeRegulatory ReportType = "regulatory"
)

// Valid returns true if the report type is valid.
func (r ReportType) Valid() bool {
	switch r {
	case ReportTypeQuarterly, ReportTypeAnnual, ReportTypeIncident, ReportTypeAdhoc, ReportTypeRegulatory:
		return true
	}
	return false
}

// ReportApprovalStatus represents the approval status of a board report.
type ReportApprovalStatus string

const (
	ReportApprovalDraft        ReportApprovalStatus = "draft"
	ReportApprovalPendingReview ReportApprovalStatus = "pending_review"
	ReportApprovalApproved     ReportApprovalStatus = "approved"
	ReportApprovalRejected     ReportApprovalStatus = "rejected"
	ReportApprovalSuperseded   ReportApprovalStatus = "superseded"
)

// Valid returns true if the report approval status is valid.
func (r ReportApprovalStatus) Valid() bool {
	switch r {
	case ReportApprovalDraft, ReportApprovalPendingReview,
		ReportApprovalApproved, ReportApprovalRejected, ReportApprovalSuperseded:
		return true
	}
	return false
}

// =============================================================================
// Domain Types
// =============================================================================

// AISystem represents an AI system in the registry.
type AISystem struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id"`
	SystemID    string `json:"system_id"`
	SystemName  string `json:"system_name"`
	Version     string `json:"system_version,omitempty"`
	Description string `json:"description,omitempty"`

	// Risk classification
	RiskCategory     RiskCategory     `json:"risk_category"`
	DeploymentStatus DeploymentStatus `json:"deployment_status"`

	// Model characteristics
	ModelType     string `json:"model_type,omitempty"`
	ModelProvider string `json:"model_provider,omitempty"`

	// Use case
	UseCase            string `json:"use_case,omitempty"`
	UseCaseDescription string `json:"use_case_description,omitempty"`

	// Data governance
	DataSources             []string `json:"data_sources,omitempty"`
	SensitiveDataCategories []string `json:"sensitive_data_categories,omitempty"`
	DataResidency           string   `json:"data_residency,omitempty"`

	// Ownership
	OwnerID         string `json:"owner_id,omitempty"`
	OwnerName       string `json:"owner_name,omitempty"`
	OwnerDepartment string `json:"owner_department,omitempty"`
	OwnerEmail      string `json:"owner_email,omitempty"`

	// Board approval
	BoardApprovalRequired  bool                `json:"board_approval_required"`
	BoardApprovalStatus    BoardApprovalStatus `json:"board_approval_status"`
	BoardApprovalDate      *time.Time          `json:"board_approval_date,omitempty"`
	BoardApprovalReference string              `json:"board_approval_reference,omitempty"`
	BoardApproverName      string              `json:"board_approver_name,omitempty"`
	BoardApprovalNotes     string              `json:"board_approval_notes,omitempty"`

	// Validation tracking
	LastValidationDate      *time.Time `json:"last_validation_date,omitempty"`
	NextValidationDue       *time.Time `json:"next_validation_due,omitempty"`
	ValidationFrequencyDays int        `json:"validation_frequency_days,omitempty"`

	// Metadata
	Tags     []string               `json:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Timestamps
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeprecatedAt *time.Time `json:"deprecated_at,omitempty"`
}

// ModelValidation represents a validation record for an AI system.
type ModelValidation struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`

	// Link to AI system
	SystemID string `json:"system_id"`

	// Validation type
	ValidationType ValidationType `json:"validation_type"`

	// Validator information
	ValidatorType         ValidatorType `json:"validator_type"`
	ValidatorName         string        `json:"validator_name"`
	ValidatorOrganization string        `json:"validator_organization,omitempty"`
	ValidatorCredentials  string        `json:"validator_credentials,omitempty"`

	// Validation details
	ValidationDate        time.Time  `json:"validation_date"`
	ValidationPeriodStart *time.Time `json:"validation_period_start,omitempty"`
	ValidationPeriodEnd   *time.Time `json:"validation_period_end,omitempty"`

	// Dataset information
	DatasetDescription     string                 `json:"dataset_description,omitempty"`
	DatasetSize            int                    `json:"dataset_size,omitempty"`
	DatasetCharacteristics map[string]interface{} `json:"dataset_characteristics,omitempty"`

	// Methodology
	Methodology   string   `json:"methodology,omitempty"`
	TestScenarios []string `json:"test_scenarios,omitempty"`

	// Results
	Findings []ValidationFinding `json:"findings,omitempty"`

	// Accuracy metrics
	AccuracyMetrics map[string]float64 `json:"accuracy_metrics,omitempty"`

	// Bias assessment
	BiasAssessment       map[string]float64 `json:"bias_assessment,omitempty"`
	BiasCategoriesTested []string           `json:"bias_categories_tested,omitempty"`

	// Stress test results
	StressTestResults map[string]interface{} `json:"stress_test_results,omitempty"`
	StressTestPassed  *bool                  `json:"stress_test_passed,omitempty"`

	// Recommendation
	Recommendation ValidationRecommendation `json:"recommendation"`
	Conditions     string                   `json:"conditions,omitempty"`

	// Follow-up
	NextReviewDate       *time.Time `json:"next_review_date,omitempty"`
	RemediationRequired  bool       `json:"remediation_required"`
	RemediationDeadline  *time.Time `json:"remediation_deadline,omitempty"`

	// Attachments
	ReportFilePath     string `json:"report_file_path,omitempty"`
	ReportFileChecksum string `json:"report_file_checksum,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ValidationFinding represents a finding from a validation.
type ValidationFinding struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Impact      string `json:"impact,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Status      string `json:"status,omitempty"`
}

// AIIncident represents an AI-related incident.
type AIIncident struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`

	// Identification
	IncidentID string `json:"incident_id"`
	SystemID   string `json:"system_id,omitempty"`

	// Classification
	IncidentType IncidentType     `json:"incident_type"`
	Severity     IncidentSeverity `json:"severity"`

	// Detection
	DetectedAt       time.Time       `json:"detected_at"`
	DetectedBy       DetectionMethod `json:"detected_by"`
	DetectionDetails string          `json:"detection_details,omitempty"`

	// Description
	Title       string `json:"title"`
	Description string `json:"description"`
	RootCause   string `json:"root_cause,omitempty"`

	// Impact assessment
	AffectedCustomersCount    *int     `json:"affected_customers_count,omitempty"`
	AffectedTransactionsCount *int     `json:"affected_transactions_count,omitempty"`
	FinancialImpactINR        *float64 `json:"financial_impact_inr,omitempty"`
	ReputationalImpact        string   `json:"reputational_impact,omitempty"`

	// Remediation
	RemediationActions    []RemediationAction `json:"remediation_actions,omitempty"`
	ImmediateActionTaken  string              `json:"immediate_action_taken,omitempty"`
	LongTermFix           string              `json:"long_term_fix,omitempty"`

	// Status
	Status            IncidentStatus `json:"status"`
	ResolvedAt        *time.Time     `json:"resolved_at,omitempty"`
	ResolutionSummary string         `json:"resolution_summary,omitempty"`
	LessonsLearned    string         `json:"lessons_learned,omitempty"`

	// Board notification
	BoardNotificationRequired  bool       `json:"board_notification_required"`
	BoardNotified              bool       `json:"board_notified"`
	BoardNotificationDate      *time.Time `json:"board_notification_date,omitempty"`
	BoardNotificationReference string     `json:"board_notification_reference,omitempty"`

	// RBI notification
	RBINotificationRequired  bool       `json:"rbi_notification_required"`
	RBINotified              bool       `json:"rbi_notified"`
	RBINotificationDate      *time.Time `json:"rbi_notification_date,omitempty"`
	RBINotificationReference string     `json:"rbi_notification_reference,omitempty"`
	RBIResponse              string     `json:"rbi_response,omitempty"`

	// Attachments
	EvidenceFiles []string `json:"evidence_files,omitempty"`

	// Metadata
	Tags     []string               `json:"tags,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RemediationAction represents an action taken to remediate an incident.
type RemediationAction struct {
	ID          string     `json:"id"`
	Action      string     `json:"action"`
	AssignedTo  string     `json:"assigned_to,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Status      string     `json:"status"` // pending, in_progress, completed
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Notes       string     `json:"notes,omitempty"`
}

// KillSwitch represents a kill switch configuration.
type KillSwitch struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`

	// Scope
	Scope            KillSwitchScope `json:"scope"`
	SystemID         string          `json:"system_id,omitempty"`
	TargetIdentifier string          `json:"target_identifier,omitempty"`

	// State
	IsActive bool `json:"is_active"`

	// Activation details
	ActivatedBy      string     `json:"activated_by,omitempty"`
	ActivatedByEmail string     `json:"activated_by_email,omitempty"`
	ActivatedAt      *time.Time `json:"activated_at,omitempty"`
	ActivationReason string     `json:"activation_reason,omitempty"`

	// Auto-trigger
	AutoTriggered    bool                   `json:"auto_triggered"`
	TriggerCondition string                 `json:"trigger_condition,omitempty"`
	TriggerThreshold map[string]interface{} `json:"trigger_threshold,omitempty"`

	// Fallback behavior
	FallbackBehavior FallbackBehavior       `json:"fallback_behavior"`
	FallbackConfig   map[string]interface{} `json:"fallback_config,omitempty"`

	// Deactivation details
	DeactivatedBy      string     `json:"deactivated_by,omitempty"`
	DeactivatedByEmail string     `json:"deactivated_by_email,omitempty"`
	DeactivatedAt      *time.Time `json:"deactivated_at,omitempty"`
	DeactivationReason string     `json:"deactivation_reason,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// KillSwitchHistoryEntry represents an entry in the kill switch audit trail.
type KillSwitchHistoryEntry struct {
	ID           int64                  `json:"id"`
	OrgID        string                 `json:"org_id"`
	KillSwitchID string                 `json:"kill_switch_id"`
	Action       KillSwitchAction       `json:"action"`
	ActorID      string                 `json:"actor_id"`
	ActorEmail   string                 `json:"actor_email,omitempty"`
	ActorRole    string                 `json:"actor_role,omitempty"`
	ActorIP      string                 `json:"actor_ip,omitempty"`
	Reason       string                 `json:"reason,omitempty"`
	PreviousState map[string]interface{} `json:"previous_state,omitempty"`
	NewState     map[string]interface{} `json:"new_state,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt    time.Time              `json:"created_at"`
}

// BoardReport represents a board compliance report.
type BoardReport struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`

	// Report type
	ReportType ReportType `json:"report_type"`

	// Reporting period
	ReportPeriodStart *time.Time `json:"report_period_start,omitempty"`
	ReportPeriodEnd   *time.Time `json:"report_period_end,omitempty"`
	ReportQuarter     string     `json:"report_quarter,omitempty"`

	// AI Systems Summary
	TotalAISystems       int            `json:"total_ai_systems"`
	SystemsByRisk        map[string]int `json:"systems_by_risk,omitempty"`
	SystemsByStatus      map[string]int `json:"systems_by_status,omitempty"`
	NewSystemsDeployed   int            `json:"new_systems_deployed"`
	SystemsDeprecated    int            `json:"systems_deprecated"`

	// Validation Summary
	TotalValidations              int            `json:"total_validations"`
	ValidationsByType             map[string]int `json:"validations_by_type,omitempty"`
	ValidationsByRecommendation   map[string]int `json:"validations_by_recommendation,omitempty"`
	OverdueValidations            int            `json:"overdue_validations"`

	// Incident Summary
	TotalIncidents             int            `json:"total_incidents"`
	IncidentsBySeverity        map[string]int `json:"incidents_by_severity,omitempty"`
	IncidentsByType            map[string]int `json:"incidents_by_type,omitempty"`
	IncidentsResolved          int            `json:"incidents_resolved"`
	IncidentsOpen              int            `json:"incidents_open"`
	AverageResolutionTimeHours float64        `json:"average_resolution_time_hours,omitempty"`

	// Incidents that LEGALLY REQUIRE a board / RBI notification which has not
	// been sent yet (the GENERATED *_notification_required column is true but
	// the corresponding *_notified flag is still false). Derived at generation
	// time from GetPendingNotifications — not a stored board_reports column —
	// so the board sees an unsent-but-required notification distinctly from a
	// generic open-critical incident.
	PendingBoardNotifications int `json:"pending_board_notifications"`
	PendingRBINotifications   int `json:"pending_rbi_notifications"`

	// Key Metrics
	KeyMetrics map[string]interface{} `json:"key_metrics,omitempty"`

	// Compliance Status
	ComplianceScore  float64           `json:"compliance_score"`
	ComplianceIssues []ComplianceIssue `json:"compliance_issues,omitempty"`

	// Corrective Actions
	CorrectiveActions []CorrectiveAction `json:"corrective_actions,omitempty"`

	// Kill Switch Activity
	KillSwitchActivations int                    `json:"kill_switch_activations"`
	KillSwitchDetails     map[string]interface{} `json:"kill_switch_details,omitempty"`

	// Report Generation
	GeneratedBy       string    `json:"generated_by,omitempty"`
	GeneratedByEmail  string    `json:"generated_by_email,omitempty"`
	GeneratedAt       time.Time `json:"generated_at"`
	GenerationMethod  string    `json:"generation_method,omitempty"`

	// Board Approval
	ApprovalStatus    ReportApprovalStatus `json:"approval_status"`
	ApprovedBy        string               `json:"approved_by,omitempty"`
	ApprovedByEmail   string               `json:"approved_by_email,omitempty"`
	ApprovedAt        *time.Time           `json:"approved_at,omitempty"`
	ApprovalNotes     string               `json:"approval_notes,omitempty"`

	// File storage
	FilePath       string `json:"file_path,omitempty"`
	FileFormat     string `json:"file_format,omitempty"`
	FileSizeBytes  int64  `json:"file_size_bytes,omitempty"`
	FileChecksum   string `json:"file_checksum,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ComplianceIssue represents a compliance issue found during reporting.
type ComplianceIssue struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	SystemID    string `json:"system_id,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// CorrectiveAction represents a corrective action from a board report.
type CorrectiveAction struct {
	ID          string     `json:"id"`
	Action      string     `json:"action"`
	Priority    string     `json:"priority"`
	AssignedTo  string     `json:"assigned_to,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Status      string     `json:"status"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// =============================================================================
// RBI Audit Export Types
// =============================================================================

// AuditExportFormat represents the format for audit exports.
type AuditExportFormat string

const (
	AuditExportFormatJSON AuditExportFormat = "json"
	AuditExportFormatCSV  AuditExportFormat = "csv"
	AuditExportFormatPDF  AuditExportFormat = "pdf"
	AuditExportFormatXLSX AuditExportFormat = "xlsx"
)

// Valid returns true if the audit export format is valid.
func (f AuditExportFormat) Valid() bool {
	switch f {
	case AuditExportFormatJSON, AuditExportFormatCSV, AuditExportFormatPDF, AuditExportFormatXLSX:
		return true
	}
	return false
}

// AuditExportStatus represents the status of an audit export job.
type AuditExportStatus string

const (
	AuditExportStatusPending    AuditExportStatus = "pending"
	AuditExportStatusProcessing AuditExportStatus = "processing"
	AuditExportStatusCompleted  AuditExportStatus = "completed"
	AuditExportStatusFailed     AuditExportStatus = "failed"
	AuditExportStatusExpired    AuditExportStatus = "expired"
)

// Valid returns true if the audit export status is valid.
func (s AuditExportStatus) Valid() bool {
	switch s {
	case AuditExportStatusPending, AuditExportStatusProcessing,
		AuditExportStatusCompleted, AuditExportStatusFailed, AuditExportStatusExpired:
		return true
	}
	return false
}

// AuditExportType represents what data is included in the export.
type AuditExportType string

const (
	AuditExportTypeFull           AuditExportType = "full"
	AuditExportTypeSystems        AuditExportType = "systems"
	AuditExportTypeValidations    AuditExportType = "validations"
	AuditExportTypeIncidents      AuditExportType = "incidents"
	AuditExportTypeKillSwitches   AuditExportType = "kill_switches"
	AuditExportTypeReports        AuditExportType = "reports"
	AuditExportTypeComprehensive  AuditExportType = "comprehensive"
)

// Valid returns true if the audit export type is valid.
func (t AuditExportType) Valid() bool {
	switch t {
	case AuditExportTypeFull, AuditExportTypeSystems, AuditExportTypeValidations,
		AuditExportTypeIncidents, AuditExportTypeKillSwitches, AuditExportTypeReports,
		AuditExportTypeComprehensive:
		return true
	}
	return false
}

// AuditExport represents an audit export job and its results.
type AuditExport struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`

	// Export configuration
	ExportType AuditExportType   `json:"export_type"`
	Format     AuditExportFormat `json:"format"`

	// Date range for the export
	StartDate *time.Time `json:"start_date,omitempty"`
	EndDate   *time.Time `json:"end_date,omitempty"`

	// Filter options
	SystemIDs     []string `json:"system_ids,omitempty"`
	RiskCategories []string `json:"risk_categories,omitempty"`
	IncludeArchived bool    `json:"include_archived"`

	// Status
	Status      AuditExportStatus `json:"status"`
	ErrorMessage string           `json:"error_message,omitempty"`

	// Request info
	RequestedBy      string `json:"requested_by,omitempty"`
	RequestedByEmail string `json:"requested_by_email,omitempty"`
	Purpose          string `json:"purpose,omitempty"`

	// Processing info
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Result info
	FilePath     string `json:"file_path,omitempty"`
	FileSizeBytes int64  `json:"file_size_bytes,omitempty"`
	FileChecksum string `json:"file_checksum,omitempty"`
	RecordCount  int    `json:"record_count,omitempty"`

	// Cloud storage info
	DownloadURL string `json:"download_url,omitempty"` // presigned URL for cloud exports
	StorageType string `json:"storage_type,omitempty"` // "local" or "s3", "azure", "gcs"
	StorageKey  string `json:"storage_key,omitempty"`  // cloud object key

	// Export summary
	Summary *AuditExportSummary `json:"summary,omitempty"`

	// Expiration (for compliance with data retention)
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditExportSummary provides a summary of what was exported.
type AuditExportSummary struct {
	TotalSystems     int `json:"total_systems,omitempty"`
	TotalValidations int `json:"total_validations,omitempty"`
	TotalIncidents   int `json:"total_incidents,omitempty"`
	TotalKillSwitches int `json:"total_kill_switches,omitempty"`
	TotalReports     int `json:"total_reports,omitempty"`
	DateRangeStart   *time.Time `json:"date_range_start,omitempty"`
	DateRangeEnd     *time.Time `json:"date_range_end,omitempty"`
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateAISystemRequest is the request to create an AI system.
type CreateAISystemRequest struct {
	SystemID               string   `json:"system_id" validate:"required,max=100"`
	SystemName             string   `json:"system_name" validate:"required,max=255"`
	Version                string   `json:"system_version,omitempty" validate:"max=50"`
	Description            string   `json:"description,omitempty"`
	RiskCategory           string   `json:"risk_category" validate:"required,oneof=low medium high"`
	ModelType              string   `json:"model_type,omitempty" validate:"max=100"`
	ModelProvider          string   `json:"model_provider,omitempty" validate:"max=100"`
	UseCase                string   `json:"use_case,omitempty" validate:"max=255"`
	UseCaseDescription     string   `json:"use_case_description,omitempty"`
	DataSources            []string `json:"data_sources,omitempty"`
	SensitiveDataCategories []string `json:"sensitive_data_categories,omitempty"`
	DataResidency          string   `json:"data_residency,omitempty" validate:"max=50"`
	OwnerID                string   `json:"owner_id,omitempty" validate:"max=100"`
	OwnerName              string   `json:"owner_name,omitempty" validate:"max=255"`
	OwnerDepartment        string   `json:"owner_department,omitempty" validate:"max=100"`
	OwnerEmail             string   `json:"owner_email,omitempty" validate:"omitempty,email"`
	ValidationFrequencyDays int     `json:"validation_frequency_days,omitempty" validate:"min=0,max=3650"`
	Tags                   []string `json:"tags,omitempty"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateAISystemRequest is the request to update an AI system.
type UpdateAISystemRequest struct {
	SystemName              *string  `json:"system_name,omitempty" validate:"omitempty,max=255"`
	Version                 *string  `json:"system_version,omitempty" validate:"omitempty,max=50"`
	Description             *string  `json:"description,omitempty"`
	RiskCategory            *string  `json:"risk_category,omitempty" validate:"omitempty,oneof=low medium high"`
	DeploymentStatus        *string  `json:"deployment_status,omitempty" validate:"omitempty,oneof=development sandbox canary production deprecated"`
	ModelType               *string  `json:"model_type,omitempty" validate:"omitempty,max=100"`
	ModelProvider           *string  `json:"model_provider,omitempty" validate:"omitempty,max=100"`
	UseCase                 *string  `json:"use_case,omitempty" validate:"omitempty,max=255"`
	UseCaseDescription      *string  `json:"use_case_description,omitempty"`
	DataSources             []string `json:"data_sources,omitempty"`
	SensitiveDataCategories []string `json:"sensitive_data_categories,omitempty"`
	DataResidency           *string  `json:"data_residency,omitempty" validate:"omitempty,max=50"`
	OwnerID                 *string  `json:"owner_id,omitempty" validate:"omitempty,max=100"`
	OwnerName               *string  `json:"owner_name,omitempty" validate:"omitempty,max=255"`
	OwnerDepartment         *string  `json:"owner_department,omitempty" validate:"omitempty,max=100"`
	OwnerEmail              *string  `json:"owner_email,omitempty" validate:"omitempty,email"`
	ValidationFrequencyDays *int     `json:"validation_frequency_days,omitempty" validate:"omitempty,min=0,max=3650"`
	Tags                    []string `json:"tags,omitempty"`
	Metadata                map[string]interface{} `json:"metadata,omitempty"`
}

// BoardApprovalRequest is the request to approve an AI system for board.
type BoardApprovalRequest struct {
	Action    string `json:"action" validate:"required,oneof=approve reject revoke"`
	Reference string `json:"reference,omitempty" validate:"max=100"`
	Notes     string `json:"notes,omitempty"`

	// The acting principal is NOT accepted from the wire (#3150): these fields
	// carry `json:"-"` so a caller-typed identity cannot be decoded into them,
	// and the handler fills them from resolveActor(r). Deleting the field from
	// the wire rather than merely ignoring it is deliberate — an identity a
	// caller can type is an identity a future reader can wire back up.
	Approver string `json:"-"`
}

// ListAISystemsParams are the parameters for listing AI systems.
type ListAISystemsParams struct {
	RiskCategory        string `form:"risk_category" validate:"omitempty,oneof=low medium high"`
	DeploymentStatus    string `form:"deployment_status" validate:"omitempty,oneof=development sandbox canary production deprecated"`
	BoardApprovalStatus string `form:"board_approval_status" validate:"omitempty,oneof=not_required pending approved rejected revoked"`
	OwnerDepartment     string `form:"owner_department" validate:"max=100"`
	ValidationOverdue   *bool  `form:"validation_overdue"`
	Limit               int    `form:"limit" validate:"min=1,max=100"`
	Offset              int    `form:"offset" validate:"min=0"`
}

// AISystemSummary is a summary of AI systems for dashboard.
type AISystemSummary struct {
	TotalSystems            int            `json:"total_systems"`
	SystemsByRisk           map[string]int `json:"systems_by_risk"`
	SystemsByStatus         map[string]int `json:"systems_by_status"`
	SystemsPendingApproval  int            `json:"systems_pending_approval"`
	SystemsOverdueValidation int           `json:"systems_overdue_validation"`
}
