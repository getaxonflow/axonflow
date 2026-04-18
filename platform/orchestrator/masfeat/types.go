// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

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

	// DefaultAuditRetentionYears is the MAS-required audit retention period.
	DefaultAuditRetentionYears = 7

	// DefaultBiasMaxThreshold is the default maximum bias threshold for FEAT Fairness.
	DefaultBiasMaxThreshold = 0.10
)

// MaterialityClassification represents the MAS materiality classification.
type MaterialityClassification string

const (
	MaterialityHigh   MaterialityClassification = "high"
	MaterialityMedium MaterialityClassification = "medium"
	MaterialityLow    MaterialityClassification = "low"
)

// Valid returns true if the materiality classification is valid.
func (m MaterialityClassification) Valid() bool {
	switch m {
	case MaterialityHigh, MaterialityMedium, MaterialityLow:
		return true
	}
	return false
}

// SystemStatus represents the status of an AI system in the registry.
type SystemStatus string

const (
	SystemStatusDraft      SystemStatus = "draft"
	SystemStatusActive     SystemStatus = "active"
	SystemStatusSuspended  SystemStatus = "suspended"
	SystemStatusRetired    SystemStatus = "retired"
)

// Valid returns true if the system status is valid.
func (s SystemStatus) Valid() bool {
	switch s {
	case SystemStatusDraft, SystemStatusActive, SystemStatusSuspended, SystemStatusRetired:
		return true
	}
	return false
}

// FEATAssessmentStatus represents the status of a FEAT assessment.
type FEATAssessmentStatus string

const (
	FEATStatusPending    FEATAssessmentStatus = "pending"
	FEATStatusInProgress FEATAssessmentStatus = "in_progress"
	FEATStatusCompleted  FEATAssessmentStatus = "completed"
	FEATStatusApproved   FEATAssessmentStatus = "approved"
	FEATStatusRejected   FEATAssessmentStatus = "rejected"
)

// Valid returns true if the FEAT assessment status is valid.
func (s FEATAssessmentStatus) Valid() bool {
	switch s {
	case FEATStatusPending, FEATStatusInProgress, FEATStatusCompleted, FEATStatusApproved, FEATStatusRejected:
		return true
	}
	return false
}

// KillSwitchStatus represents the status of a kill switch.
type KillSwitchStatus string

const (
	KillSwitchEnabled  KillSwitchStatus = "enabled"
	KillSwitchDisabled KillSwitchStatus = "disabled"
	KillSwitchTriggered KillSwitchStatus = "triggered"
)

// Valid returns true if the kill switch status is valid.
func (s KillSwitchStatus) Valid() bool {
	switch s {
	case KillSwitchEnabled, KillSwitchDisabled, KillSwitchTriggered:
		return true
	}
	return false
}

// FEATPillar represents the four pillars of MAS FEAT.
type FEATPillar string

const (
	PillarFairness       FEATPillar = "fairness"
	PillarEthics         FEATPillar = "ethics"
	PillarAccountability FEATPillar = "accountability"
	PillarTransparency   FEATPillar = "transparency"
)

// Valid returns true if the FEAT pillar is valid.
func (p FEATPillar) Valid() bool {
	switch p {
	case PillarFairness, PillarEthics, PillarAccountability, PillarTransparency:
		return true
	}
	return false
}

// AISystemUseCase represents the AI system use case type.
type AISystemUseCase string

const (
	UseCaseCreditScoring       AISystemUseCase = "credit_scoring"
	UseCaseRoboAdvisory        AISystemUseCase = "robo_advisory"
	UseCaseInsuranceUnderwriting AISystemUseCase = "insurance_underwriting"
	UseCaseTradingAlgorithm    AISystemUseCase = "trading_algorithm"
	UseCaseAMLCFT              AISystemUseCase = "aml_cft"
	UseCaseCustomerService     AISystemUseCase = "customer_service"
	UseCaseFraudDetection      AISystemUseCase = "fraud_detection"
	UseCaseOther               AISystemUseCase = "other"
)

// Valid returns true if the use case is valid.
func (u AISystemUseCase) Valid() bool {
	switch u {
	case UseCaseCreditScoring, UseCaseRoboAdvisory, UseCaseInsuranceUnderwriting,
		UseCaseTradingAlgorithm, UseCaseAMLCFT, UseCaseCustomerService,
		UseCaseFraudDetection, UseCaseOther:
		return true
	}
	return false
}

// ExportFormat represents the output format for MAS compliance exports.
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

// AISystemRegistry represents an AI system registered with MAS FEAT.
type AISystemRegistry struct {
	ID                       string                    `json:"id"`
	OrgID                    string                    `json:"org_id"`
	SystemID                 string                    `json:"system_id"`
	SystemName               string                    `json:"system_name"`
	Description              string                    `json:"description,omitempty"`
	UseCase                  AISystemUseCase           `json:"use_case"`
	Status                   SystemStatus              `json:"status"`
	// 3-dimensional risk rating per MAS AI Risk Management Guidelines 2025
	RiskRatingImpact         int                       `json:"risk_rating_impact"`     // 1-5
	RiskRatingComplexity     int                       `json:"risk_rating_complexity"` // 1-5
	RiskRatingReliance       int                       `json:"risk_rating_reliance"`   // 1-5
	MaterialityClassification MaterialityClassification `json:"materiality_classification"`
	OwnerTeam                string                    `json:"owner_team"`
	OwnerEmail               string                    `json:"owner_email"`
	DataSources              []string                  `json:"data_sources,omitempty"`
	ModelType                string                    `json:"model_type,omitempty"`
	Version                  string                    `json:"version,omitempty"`
	DeploymentDate           *time.Time                `json:"deployment_date,omitempty"`
	LastAssessmentDate       *time.Time                `json:"last_assessment_date,omitempty"`
	NextAssessmentDue        *time.Time                `json:"next_assessment_due,omitempty"`
	Metadata                 map[string]interface{}    `json:"metadata,omitempty"`
	CreatedAt                time.Time                 `json:"created_at"`
	UpdatedAt                time.Time                 `json:"updated_at"`
	CreatedBy                string                    `json:"created_by"`
	UpdatedBy                string                    `json:"updated_by,omitempty"`
}

// FEATAssessment represents a FEAT assessment for an AI system.
type FEATAssessment struct {
	ID                  string                 `json:"id"`
	OrgID               string                 `json:"org_id"`
	SystemID            string                 `json:"system_id"`
	AssessmentType      string                 `json:"assessment_type"` // initial, periodic, ad_hoc
	Status              FEATAssessmentStatus   `json:"status"`
	Version             int                    `json:"version"`
	AssessmentDate      time.Time              `json:"assessment_date"`
	ValidUntil          *time.Time             `json:"valid_until,omitempty"`
	// FEAT Pillar Scores (0-100)
	FairnessScore       *float64               `json:"fairness_score,omitempty"`
	EthicsScore         *float64               `json:"ethics_score,omitempty"`
	AccountabilityScore *float64               `json:"accountability_score,omitempty"`
	TransparencyScore   *float64               `json:"transparency_score,omitempty"`
	OverallScore        *float64               `json:"overall_score,omitempty"`
	// Pillar details
	FairnessDetails     *PillarAssessment      `json:"fairness_details,omitempty"`
	EthicsDetails       *PillarAssessment      `json:"ethics_details,omitempty"`
	AccountabilityDetails *PillarAssessment    `json:"accountability_details,omitempty"`
	TransparencyDetails *PillarAssessment      `json:"transparency_details,omitempty"`
	// Findings and recommendations
	Findings            []Finding              `json:"findings,omitempty"`
	Recommendations     []string               `json:"recommendations,omitempty"`
	Assessors           []string               `json:"assessors"`
	// Audit trail
	CreatedBy           string                 `json:"created_by"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	SubmittedAt         *time.Time             `json:"submitted_at,omitempty"`
	SubmittedBy         string                 `json:"submitted_by,omitempty"`
	ApprovedAt          *time.Time             `json:"approved_at,omitempty"`
	ApprovedBy          string                 `json:"approved_by,omitempty"`
	RejectedAt          *time.Time             `json:"rejected_at,omitempty"`
	RejectedBy          string                 `json:"rejected_by,omitempty"`
	RejectionReason     string                 `json:"rejection_reason,omitempty"`
}

// PillarAssessment contains detailed assessment for a FEAT pillar.
type PillarAssessment struct {
	Score          float64                `json:"score"`
	Status         string                 `json:"status"` // compliant, partial, non_compliant
	Criteria       []CriterionAssessment  `json:"criteria,omitempty"`
	Evidence       []EvidenceItem         `json:"evidence,omitempty"`
	Notes          string                 `json:"notes,omitempty"`
}

// CriterionAssessment represents assessment of a specific FEAT criterion.
type CriterionAssessment struct {
	CriterionID string `json:"criterion_id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Score       int    `json:"score"` // 0-100
	Status      string `json:"status"` // met, partial, not_met, not_applicable
	Evidence    string `json:"evidence,omitempty"`
	Notes       string `json:"notes,omitempty"`
}

// EvidenceItem represents evidence supporting FEAT assessment claims.
type EvidenceItem struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // document, test_result, audit_log, model_card
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	URL         string    `json:"url,omitempty"`
	UploadedAt  time.Time `json:"uploaded_at"`
	UploadedBy  string    `json:"uploaded_by"`
}

// Finding represents a FEAT assessment finding.
type Finding struct {
	ID          string     `json:"id"`
	Pillar      FEATPillar `json:"pillar"`
	Severity    string     `json:"severity"` // critical, major, minor, observation
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Remediation string     `json:"remediation,omitempty"`
	Status      string     `json:"status"` // open, resolved, accepted
	DueDate     *time.Time `json:"due_date,omitempty"`
}

// KillSwitch represents a kill switch for an AI system.
type KillSwitch struct {
	ID                 string           `json:"id"`
	OrgID              string           `json:"org_id"`
	SystemID           string           `json:"system_id"`
	Status             KillSwitchStatus `json:"status"`
	TriggerReason      string           `json:"trigger_reason,omitempty"`
	TriggerConditions  map[string]interface{} `json:"trigger_conditions,omitempty"`
	AutoTriggerEnabled bool             `json:"auto_trigger_enabled"`
	// Thresholds for auto-trigger
	AccuracyThreshold  *float64         `json:"accuracy_threshold,omitempty"`
	BiasThreshold      *float64         `json:"bias_threshold,omitempty"`
	ErrorRateThreshold *float64         `json:"error_rate_threshold,omitempty"`
	// Audit trail
	TriggeredAt        *time.Time       `json:"triggered_at,omitempty"`
	TriggeredBy        string           `json:"triggered_by,omitempty"`
	RestoredAt         *time.Time       `json:"restored_at,omitempty"`
	RestoredBy         string           `json:"restored_by,omitempty"`
	RestoreReason      string           `json:"restore_reason,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	UpdatedAt          time.Time        `json:"updated_at"`
}

// KillSwitchHistory represents a kill switch state change event.
type KillSwitchHistory struct {
	ID           string    `json:"id"`
	KillSwitchID string    `json:"kill_switch_id"`
	Action       string    `json:"action"` // triggered, restored, enabled, disabled
	PreviousStatus string  `json:"previous_status"`
	NewStatus    string    `json:"new_status"`
	Reason       string    `json:"reason,omitempty"`
	PerformedBy  string    `json:"performed_by"`
	PerformedAt  time.Time `json:"performed_at"`
}

// BiasMetric represents a bias measurement for FEAT Fairness pillar.
type BiasMetric struct {
	ID          string                 `json:"id"`
	OrgID       string                 `json:"org_id"`
	SystemID    string                 `json:"system_id"`
	Category    string                 `json:"category"` // demographic, socioeconomic, geographic
	GroupA      string                 `json:"group_a"`
	GroupB      string                 `json:"group_b"`
	GroupARate  float64                `json:"group_a_rate"`
	GroupBRate  float64                `json:"group_b_rate"`
	DisparityScore float64             `json:"disparity_score"`
	Threshold   float64                `json:"threshold"`
	IsViolation bool                   `json:"is_violation"`
	SampleSize  int                    `json:"sample_size"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// Request/Response types

// CreateRegistryRequest is the request body for registering an AI system.
type CreateRegistryRequest struct {
	SystemID             string          `json:"system_id"`
	SystemName           string          `json:"system_name"`
	Description          string          `json:"description,omitempty"`
	UseCase              AISystemUseCase `json:"use_case"`
	RiskRatingImpact     int             `json:"risk_rating_impact"`     // 1-5
	RiskRatingComplexity int             `json:"risk_rating_complexity"` // 1-5
	RiskRatingReliance   int             `json:"risk_rating_reliance"`   // 1-5
	OwnerTeam            string          `json:"owner_team"`
	OwnerEmail           string          `json:"owner_email"`
	DataSources          []string        `json:"data_sources,omitempty"`
	ModelType            string          `json:"model_type,omitempty"`
	Version              string          `json:"version,omitempty"`
}

// UpdateRegistryRequest is the request body for updating an AI system.
type UpdateRegistryRequest struct {
	SystemName           string          `json:"system_name,omitempty"`
	Description          string          `json:"description,omitempty"`
	UseCase              AISystemUseCase `json:"use_case,omitempty"`
	Status               SystemStatus    `json:"status,omitempty"`
	RiskRatingImpact     *int            `json:"risk_rating_impact,omitempty"`
	RiskRatingComplexity *int            `json:"risk_rating_complexity,omitempty"`
	RiskRatingReliance   *int            `json:"risk_rating_reliance,omitempty"`
	OwnerTeam            string          `json:"owner_team,omitempty"`
	OwnerEmail           string          `json:"owner_email,omitempty"`
	DataSources          []string        `json:"data_sources,omitempty"`
	ModelType            string          `json:"model_type,omitempty"`
	Version              string          `json:"version,omitempty"`
}

// CreateAssessmentRequest is the request body for creating a FEAT assessment.
type CreateAssessmentRequest struct {
	SystemID       string   `json:"system_id"`
	AssessmentType string   `json:"assessment_type"` // initial, periodic, ad_hoc
	Assessors      []string `json:"assessors,omitempty"`
}

// UpdateAssessmentRequest is the request body for updating a FEAT assessment.
type UpdateAssessmentRequest struct {
	FairnessScore       *float64          `json:"fairness_score,omitempty"`
	EthicsScore         *float64          `json:"ethics_score,omitempty"`
	AccountabilityScore *float64          `json:"accountability_score,omitempty"`
	TransparencyScore   *float64          `json:"transparency_score,omitempty"`
	FairnessDetails     *PillarAssessment `json:"fairness_details,omitempty"`
	EthicsDetails       *PillarAssessment `json:"ethics_details,omitempty"`
	AccountabilityDetails *PillarAssessment `json:"accountability_details,omitempty"`
	TransparencyDetails *PillarAssessment `json:"transparency_details,omitempty"`
	Findings            []Finding         `json:"findings,omitempty"`
	Recommendations     []string          `json:"recommendations,omitempty"`
	Assessors           []string          `json:"assessors,omitempty"`
}

// TriggerKillSwitchRequest is the request body for triggering a kill switch.
type TriggerKillSwitchRequest struct {
	Reason string `json:"reason"`
}

// RestoreKillSwitchRequest is the request body for restoring a kill switch.
type RestoreKillSwitchRequest struct {
	Reason string `json:"reason"`
}

// ConfigureKillSwitchRequest is the request body for configuring a kill switch.
type ConfigureKillSwitchRequest struct {
	AutoTriggerEnabled bool                   `json:"auto_trigger_enabled"`
	AccuracyThreshold  *float64               `json:"accuracy_threshold,omitempty"`
	BiasThreshold      *float64               `json:"bias_threshold,omitempty"`
	ErrorRateThreshold *float64               `json:"error_rate_threshold,omitempty"`
	TriggerConditions  map[string]interface{} `json:"trigger_conditions,omitempty"`
}

// RecordBiasRequest is the request body for recording a bias measurement.
type RecordBiasRequest struct {
	SystemID   string                 `json:"system_id"`
	Category   string                 `json:"category"`
	GroupA     string                 `json:"group_a"`
	GroupB     string                 `json:"group_b"`
	GroupARate float64                `json:"group_a_rate"`
	GroupBRate float64                `json:"group_b_rate"`
	SampleSize int                    `json:"sample_size"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ListParams contains common pagination parameters.
type ListParams struct {
	Limit    int    `json:"limit,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Status   string `json:"status,omitempty"`
	SystemID string `json:"system_id,omitempty"`
}

// RegistrySummary provides a summary of registered AI systems.
type RegistrySummary struct {
	OrgID            string `json:"org_id"`
	TotalSystems     int    `json:"total_systems"`
	ActiveSystems    int    `json:"active_systems"`
	HighMateriality  int    `json:"high_materiality"`
	MediumMateriality int   `json:"medium_materiality"`
	LowMateriality   int    `json:"low_materiality"`
	AssessmentsDue   int    `json:"assessments_due"`
	KillSwitchesTriggered int `json:"kill_switches_triggered"`
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

// getUserFromRequest extracts the user identifier from request headers.
func getUserFromRequest(r *http.Request) string {
	user := r.Header.Get("X-User-ID")
	if user == "" {
		user = r.Header.Get("X-User-Email")
	}
	return user
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
func decodeJSONBody(r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(nil, r.Body, MaxRequestBodySize)
	decoder := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBodySize))
	return decoder.Decode(v)
}

// calculateMateriality calculates the materiality classification from risk ratings.
func calculateMateriality(impact, complexity, reliance int) MaterialityClassification {
	sum := impact + complexity + reliance
	if sum >= 12 {
		return MaterialityHigh
	}
	if sum >= 8 {
		return MaterialityMedium
	}
	return MaterialityLow
}
