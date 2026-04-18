// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"time"
)

// RBIPolicyType represents the type of RBI compliance policy
type RBIPolicyType string

const (
	RBIPolicyTypeDataProtection    RBIPolicyType = "data_protection"
	RBIPolicyTypeModelGovernance   RBIPolicyType = "model_governance"
	RBIPolicyTypeRiskManagement    RBIPolicyType = "risk_management"
	RBIPolicyTypeAuditCompliance   RBIPolicyType = "audit_compliance"
	RBIPolicyTypeIncidentResponse  RBIPolicyType = "incident_response"
	RBIPolicyTypeKillSwitch        RBIPolicyType = "kill_switch"
	RBIPolicyTypeBoardReporting    RBIPolicyType = "board_reporting"
	RBIPolicyTypeCustomerProtection RBIPolicyType = "customer_protection"
)

// RBIPolicySeverity indicates the severity level of policy violations
type RBIPolicySeverity string

const (
	RBIPolicySeverityLow      RBIPolicySeverity = "low"
	RBIPolicySeverityMedium   RBIPolicySeverity = "medium"
	RBIPolicySeverityHigh     RBIPolicySeverity = "high"
	RBIPolicySeverityCritical RBIPolicySeverity = "critical"
)

// RBIPolicyCondition represents a condition for policy evaluation
type RBIPolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// RBIPolicyAction represents an action to take when a policy is triggered
type RBIPolicyAction struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// RBIPolicyTemplate represents a pre-defined RBI compliance policy template
type RBIPolicyTemplate struct {
	ID                    string               `json:"id"`
	Name                  string               `json:"name"`
	Description           string               `json:"description"`
	Type                  RBIPolicyType        `json:"type"`
	Severity              RBIPolicySeverity    `json:"severity"`
	Priority              int                  `json:"priority"` // Higher = evaluated first
	Enabled               bool                 `json:"enabled"`
	Conditions            []RBIPolicyCondition `json:"conditions"`
	Actions               []RBIPolicyAction    `json:"actions"`
	RegulatoryReference   string               `json:"regulatory_reference"`   // RBI circular reference
	ApplicableRiskLevels  []string             `json:"applicable_risk_levels"` // low, medium, high, critical
	RequiresBoardApproval bool                 `json:"requires_board_approval"`
	CreatedAt             time.Time            `json:"created_at"`
	UpdatedAt             time.Time            `json:"updated_at"`
}

// RBIPolicyTemplateCategory groups related policy templates
type RBIPolicyTemplateCategory struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Templates   []*RBIPolicyTemplate `json:"templates"`
}

// GetRBIPolicyTemplates returns all RBI FREE-AI compliance policy templates
func GetRBIPolicyTemplates() []*RBIPolicyTemplate {
	now := time.Now()

	return []*RBIPolicyTemplate{
		// =============================================================================
		// Data Protection Policies
		// =============================================================================

		// UPI ID Protection
		{
			ID:          "rbi_pol_upi_protection",
			Name:        "UPI ID Data Protection",
			Description: "Detect and protect UPI ID information in AI interactions per RBI data protection guidelines",
			Type:        RBIPolicyTypeDataProtection,
			Severity:    RBIPolicySeverityCritical,
			Priority:    100,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "content",
					Operator: "contains_pattern",
					Value:    "upi_id",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "mask",
					Config: map[string]interface{}{
						"pattern_type": "upi_id",
						"mask_format":  "partial",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category":   "pii_detection",
						"rbi_report": true,
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "high",
						"channel":  "compliance",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 4.2 - Data Protection",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Aadhaar Number Protection
		{
			ID:          "rbi_pol_aadhaar_protection",
			Name:        "Aadhaar Number Protection",
			Description: "Detect and protect Aadhaar numbers in AI interactions per UIDAI and RBI guidelines",
			Type:        RBIPolicyTypeDataProtection,
			Severity:    RBIPolicySeverityCritical,
			Priority:    100,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "content",
					Operator: "contains_pattern",
					Value:    "aadhaar",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "mask",
					Config: map[string]interface{}{
						"pattern_type":   "aadhaar",
						"mask_format":    "last_4_visible",
						"storage_policy": "never_store",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category":   "aadhaar_access",
						"retention":  "7_years",
						"rbi_report": true,
					},
				},
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason":         "Aadhaar data storage not permitted",
						"exception_role": "kyc_officer",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 4.2 + UIDAI Guidelines",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// PAN Card Protection
		{
			ID:          "rbi_pol_pan_protection",
			Name:        "PAN Card Number Protection",
			Description: "Protect PAN card information in AI interactions per Income Tax and RBI requirements",
			Type:        RBIPolicyTypeDataProtection,
			Severity:    RBIPolicySeverityHigh,
			Priority:    95,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "content",
					Operator: "contains_pattern",
					Value:    "pan",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "mask",
					Config: map[string]interface{}{
						"pattern_type": "pan",
						"mask_format":  "first_2_last_2_visible",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category":   "tax_identifier_access",
						"rbi_report": true,
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 4.2 - Financial Identifiers",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Bank Account Protection
		{
			ID:          "rbi_pol_bank_account_protection",
			Name:        "Bank Account Number Protection",
			Description: "Protect bank account numbers and IFSC codes in AI interactions",
			Type:        RBIPolicyTypeDataProtection,
			Severity:    RBIPolicySeverityCritical,
			Priority:    98,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "content",
					Operator: "contains_pattern",
					Value:    "bank_account",
				},
				{
					Field:    "content",
					Operator: "contains_pattern",
					Value:    "ifsc",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "mask",
					Config: map[string]interface{}{
						"pattern_type": "bank_account",
						"mask_format":  "last_4_visible",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category":   "financial_data_access",
						"rbi_report": true,
					},
				},
				{
					Type: "rate_limit",
					Config: map[string]interface{}{
						"max_queries_per_hour": 50,
						"scope":                "user",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 4.2 - Banking Data",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Model Governance Policies
		// =============================================================================

		// High-Risk AI Model Deployment
		{
			ID:          "rbi_pol_high_risk_deployment",
			Name:        "High-Risk AI Model Deployment Control",
			Description: "Require board approval and additional validation for high-risk AI model deployments",
			Type:        RBIPolicyTypeModelGovernance,
			Severity:    RBIPolicySeverityCritical,
			Priority:    100,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "ai_system.risk_category",
					Operator: "in",
					Value:    []string{"high", "critical"},
				},
				{
					Field:    "deployment_status",
					Operator: "equals",
					Value:    "production",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "require_approval",
					Config: map[string]interface{}{
						"approver_role":  "board_member",
						"min_approvers":  2,
						"approval_window": "72_hours",
					},
				},
				{
					Type: "require_validation",
					Config: map[string]interface{}{
						"validation_types": []string{"independent", "development"},
						"max_age_days":     90,
					},
				},
				{
					Type: "notify",
					Config: map[string]interface{}{
						"recipients": []string{"cro", "cto", "compliance_head"},
						"template":   "high_risk_deployment",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 3.1 - Model Risk Management",
			ApplicableRiskLevels:  []string{"high", "critical"},
			RequiresBoardApproval: true,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Model Validation Expiry
		{
			ID:          "rbi_pol_validation_expiry",
			Name:        "Model Validation Expiry Check",
			Description: "Ensure AI models have current validation before processing requests",
			Type:        RBIPolicyTypeModelGovernance,
			Severity:    RBIPolicySeverityHigh,
			Priority:    95,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "ai_system.validation_status",
					Operator: "equals",
					Value:    "expired",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason":    "Model validation expired, re-validation required",
						"exception": "emergency_override",
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity":   "high",
						"recipients": []string{"model_owner", "compliance"},
					},
				},
				{
					Type: "create_incident",
					Config: map[string]interface{}{
						"type":     "compliance_gap",
						"severity": "high",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 3.2 - Validation Requirements",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Model Drift Detection
		{
			ID:          "rbi_pol_model_drift",
			Name:        "Model Drift Detection and Response",
			Description: "Detect and respond to model drift in production AI systems",
			Type:        RBIPolicyTypeModelGovernance,
			Severity:    RBIPolicySeverityMedium,
			Priority:    80,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "metrics.accuracy_degradation",
					Operator: "greater_than",
					Value:    0.1, // 10% degradation
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity":   "medium",
						"recipients": []string{"model_owner", "data_science_lead"},
					},
				},
				{
					Type: "create_incident",
					Config: map[string]interface{}{
						"type":     "model_drift",
						"severity": "medium",
					},
				},
				{
					Type: "schedule_validation",
					Config: map[string]interface{}{
						"validation_type": "performance_review",
						"priority":        "high",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 3.3 - Ongoing Monitoring",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Risk Management Policies
		// =============================================================================

		// Bias Detection Response
		{
			ID:          "rbi_pol_bias_detection",
			Name:        "AI Bias Detection and Mitigation",
			Description: "Detect and respond to bias in AI decision-making",
			Type:        RBIPolicyTypeRiskManagement,
			Severity:    RBIPolicySeverityHigh,
			Priority:    90,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "metrics.fairness_score",
					Operator: "less_than",
					Value:    0.8,
				},
				{
					Field:    "ai_system.decision_type",
					Operator: "in",
					Value:    []string{"credit", "loan", "insurance", "employment"},
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "create_incident",
					Config: map[string]interface{}{
						"type":          "bias_detected",
						"severity":      "high",
						"auto_escalate": true,
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity":   "high",
						"recipients": []string{"cro", "ethics_officer", "compliance"},
					},
				},
				{
					Type: "enable_human_review",
					Config: map[string]interface{}{
						"scope":    "all_decisions",
						"duration": "until_resolved",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 2.3 - Fairness and Non-discrimination",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Risk Score Threshold
		{
			ID:          "rbi_pol_risk_threshold",
			Name:        "AI Decision Risk Score Threshold",
			Description: "Require human review for AI decisions above risk threshold",
			Type:        RBIPolicyTypeRiskManagement,
			Severity:    RBIPolicySeverityMedium,
			Priority:    85,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "decision.risk_score",
					Operator: "greater_than",
					Value:    0.7,
				},
				{
					Field:    "decision.impact",
					Operator: "equals",
					Value:    "financial",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "require_human_review",
					Config: map[string]interface{}{
						"reviewer_role": "senior_underwriter",
						"sla_hours":     4,
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category":   "high_risk_decision",
						"rbi_report": true,
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 2.4 - Human Oversight",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Incident Response Policies
		// =============================================================================

		// Critical Incident Kill Switch
		{
			ID:          "rbi_pol_critical_kill_switch",
			Name:        "Critical Incident Auto Kill Switch",
			Description: "Automatically trigger kill switch for critical incidents",
			Type:        RBIPolicyTypeKillSwitch,
			Severity:    RBIPolicySeverityCritical,
			Priority:    100,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "incident.severity",
					Operator: "equals",
					Value:    "critical",
				},
				{
					Field:    "incident.type",
					Operator: "in",
					Value:    []string{"model_failure", "security_breach", "data_breach"},
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "activate_kill_switch",
					Config: map[string]interface{}{
						"scope":          "system",
						"require_manual_reset": true,
					},
				},
				{
					Type: "notify_board",
					Config: map[string]interface{}{
						"urgency":  "immediate",
						"template": "critical_incident",
					},
				},
				{
					Type: "prepare_rbi_notification",
					Config: map[string]interface{}{
						"notification_type": "major_incident",
						"deadline_hours":    24,
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 5.1 - Incident Response",
			ApplicableRiskLevels:  []string{"high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Customer Impact Incident
		{
			ID:          "rbi_pol_customer_impact",
			Name:        "Customer Impact Incident Response",
			Description: "Respond to incidents affecting customers",
			Type:        RBIPolicyTypeIncidentResponse,
			Severity:    RBIPolicySeverityHigh,
			Priority:    95,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "incident.customer_impact",
					Operator: "greater_than",
					Value:    100, // Number of affected customers
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "escalate",
					Config: map[string]interface{}{
						"to":       []string{"customer_service_head", "cro"},
						"priority": "urgent",
					},
				},
				{
					Type: "initiate_customer_communication",
					Config: map[string]interface{}{
						"template":   "service_disruption",
						"channels":   []string{"email", "sms"},
						"sla_hours":  2,
					},
				},
				{
					Type: "create_remediation_plan",
					Config: map[string]interface{}{
						"template": "customer_impact",
						"owner":    "customer_service_head",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 5.2 - Customer Communication",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Board Reporting Policies
		// =============================================================================

		// Quarterly Board Report Compliance
		{
			ID:          "rbi_pol_quarterly_report",
			Name:        "Quarterly AI Board Report Compliance",
			Description: "Ensure quarterly AI governance reports are submitted to the board",
			Type:        RBIPolicyTypeBoardReporting,
			Severity:    RBIPolicySeverityHigh,
			Priority:    90,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "report.type",
					Operator: "equals",
					Value:    "quarterly",
				},
				{
					Field:    "report.status",
					Operator: "equals",
					Value:    "due",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "generate_report",
					Config: map[string]interface{}{
						"template":       "quarterly_ai_governance",
						"include_sections": []string{
							"system_inventory",
							"validation_status",
							"incidents",
							"risk_metrics",
							"compliance_gaps",
						},
					},
				},
				{
					Type: "notify",
					Config: map[string]interface{}{
						"recipients": []string{"compliance_head", "cro", "board_secretary"},
						"template":   "report_due",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 6.1 - Board Reporting",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Critical Incident Board Notification
		{
			ID:          "rbi_pol_board_incident_notification",
			Name:        "Critical Incident Board Notification",
			Description: "Notify board of critical AI incidents within required timeframe",
			Type:        RBIPolicyTypeBoardReporting,
			Severity:    RBIPolicySeverityCritical,
			Priority:    100,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "incident.severity",
					Operator: "in",
					Value:    []string{"high", "critical"},
				},
				{
					Field:    "incident.board_notified",
					Operator: "equals",
					Value:    false,
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "notify_board",
					Config: map[string]interface{}{
						"urgency":       "immediate",
						"notification_method": "email_and_call",
						"template":      "critical_ai_incident",
					},
				},
				{
					Type: "schedule_board_meeting",
					Config: map[string]interface{}{
						"meeting_type": "emergency",
						"within_hours": 48,
					},
				},
				{
					Type: "prepare_rbi_notification",
					Config: map[string]interface{}{
						"notification_type": "critical_incident",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 6.2 - Incident Escalation",
			ApplicableRiskLevels:  []string{"high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Customer Protection Policies
		// =============================================================================

		// Explainability Requirement
		{
			ID:          "rbi_pol_explainability",
			Name:        "AI Decision Explainability Requirement",
			Description: "Ensure AI decisions can be explained to customers",
			Type:        RBIPolicyTypeCustomerProtection,
			Severity:    RBIPolicySeverityMedium,
			Priority:    80,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "decision.type",
					Operator: "in",
					Value:    []string{"credit_decision", "loan_decision", "insurance_decision"},
				},
				{
					Field:    "decision.outcome",
					Operator: "equals",
					Value:    "adverse",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "generate_explanation",
					Config: map[string]interface{}{
						"format":          "customer_friendly",
						"include_factors": true,
						"language":        "localized",
					},
				},
				{
					Type: "provide_appeal_info",
					Config: map[string]interface{}{
						"include_contact": true,
						"appeal_window":   "30_days",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category": "adverse_decision",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 2.5 - Transparency",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Customer Consent Management
		{
			ID:          "rbi_pol_consent_management",
			Name:        "Customer Consent for AI Processing",
			Description: "Ensure valid customer consent before AI-based processing of their data",
			Type:        RBIPolicyTypeCustomerProtection,
			Severity:    RBIPolicySeverityHigh,
			Priority:    85,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "processing.type",
					Operator: "equals",
					Value:    "ai_decision",
				},
				{
					Field:    "customer.consent_status",
					Operator: "not_equals",
					Value:    "active",
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Valid customer consent not found",
					},
				},
				{
					Type: "request_consent",
					Config: map[string]interface{}{
						"consent_type": "ai_processing",
						"template":     "ai_consent_request",
					},
				},
				{
					Type: "audit_log",
					Config: map[string]interface{}{
						"category": "consent_check",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 4.1 - Consent Requirements",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// =============================================================================
		// Audit Compliance Policies
		// =============================================================================

		// Audit Trail Completeness
		{
			ID:          "rbi_pol_audit_trail",
			Name:        "AI Decision Audit Trail Completeness",
			Description: "Ensure complete audit trails for all AI decisions",
			Type:        RBIPolicyTypeAuditCompliance,
			Severity:    RBIPolicySeverityHigh,
			Priority:    95,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "decision.audit_complete",
					Operator: "equals",
					Value:    false,
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Incomplete audit trail",
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity":   "high",
						"recipients": []string{"compliance", "audit"},
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 7.1 - Audit Requirements",
			ApplicableRiskLevels:  []string{"medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},

		// Data Retention Compliance
		{
			ID:          "rbi_pol_data_retention",
			Name:        "AI Data Retention Compliance",
			Description: "Ensure AI-related data is retained per RBI requirements",
			Type:        RBIPolicyTypeAuditCompliance,
			Severity:    RBIPolicySeverityMedium,
			Priority:    75,
			Enabled:     true,
			Conditions: []RBIPolicyCondition{
				{
					Field:    "data.type",
					Operator: "in",
					Value:    []string{"model_input", "model_output", "decision", "audit_log"},
				},
			},
			Actions: []RBIPolicyAction{
				{
					Type: "set_retention",
					Config: map[string]interface{}{
						"duration_years": 10,
						"immutable":      true,
					},
				},
				{
					Type: "encrypt",
					Config: map[string]interface{}{
						"algorithm":    "AES-256-GCM",
						"key_rotation": "annual",
					},
				},
			},
			RegulatoryReference:   "RBI FREE-AI Framework Section 7.2 - Data Retention",
			ApplicableRiskLevels:  []string{"low", "medium", "high", "critical"},
			RequiresBoardApproval: false,
			CreatedAt:             now,
			UpdatedAt:             now,
		},
	}
}

// GetRBIPolicyTemplatesByType returns policy templates filtered by type
func GetRBIPolicyTemplatesByType(policyType RBIPolicyType) []*RBIPolicyTemplate {
	allTemplates := GetRBIPolicyTemplates()
	var filtered []*RBIPolicyTemplate

	for _, t := range allTemplates {
		if t.Type == policyType {
			filtered = append(filtered, t)
		}
	}

	return filtered
}

// GetRBIPolicyTemplatesByRiskLevel returns policy templates applicable to a risk level
func GetRBIPolicyTemplatesByRiskLevel(riskLevel string) []*RBIPolicyTemplate {
	allTemplates := GetRBIPolicyTemplates()
	var filtered []*RBIPolicyTemplate

	for _, t := range allTemplates {
		for _, level := range t.ApplicableRiskLevels {
			if level == riskLevel {
				filtered = append(filtered, t)
				break
			}
		}
	}

	return filtered
}

// GetRBIPolicyTemplateByID returns a specific policy template by ID
func GetRBIPolicyTemplateByID(id string) *RBIPolicyTemplate {
	allTemplates := GetRBIPolicyTemplates()

	for _, t := range allTemplates {
		if t.ID == id {
			return t
		}
	}

	return nil
}

// GetRBIPolicyTemplateCategories returns policy templates organized by category
func GetRBIPolicyTemplateCategories() []*RBIPolicyTemplateCategory {
	categories := []*RBIPolicyTemplateCategory{
		{
			ID:          "data_protection",
			Name:        "Data Protection",
			Description: "Policies for protecting sensitive customer data including UPI, Aadhaar, PAN, and bank accounts",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeDataProtection),
		},
		{
			ID:          "model_governance",
			Name:        "Model Governance",
			Description: "Policies for AI model lifecycle management, validation, and deployment",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeModelGovernance),
		},
		{
			ID:          "risk_management",
			Name:        "Risk Management",
			Description: "Policies for managing AI-related risks including bias and decision oversight",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeRiskManagement),
		},
		{
			ID:          "incident_response",
			Name:        "Incident Response",
			Description: "Policies for responding to AI-related incidents",
			Templates:   append(GetRBIPolicyTemplatesByType(RBIPolicyTypeIncidentResponse), GetRBIPolicyTemplatesByType(RBIPolicyTypeKillSwitch)...),
		},
		{
			ID:          "board_reporting",
			Name:        "Board Reporting",
			Description: "Policies for board reporting and governance oversight",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeBoardReporting),
		},
		{
			ID:          "customer_protection",
			Name:        "Customer Protection",
			Description: "Policies for customer rights, explainability, and consent",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeCustomerProtection),
		},
		{
			ID:          "audit_compliance",
			Name:        "Audit & Compliance",
			Description: "Policies for audit trails, data retention, and compliance tracking",
			Templates:   GetRBIPolicyTemplatesByType(RBIPolicyTypeAuditCompliance),
		},
	}

	return categories
}

// ValidateRBIPolicyTemplate validates a policy template structure
func ValidateRBIPolicyTemplate(template *RBIPolicyTemplate) error {
	if template.ID == "" {
		return ErrInvalidInput
	}
	if template.Name == "" {
		return ErrInvalidInput
	}
	if len(template.Conditions) == 0 {
		return ErrInvalidInput
	}
	if len(template.Actions) == 0 {
		return ErrInvalidInput
	}
	if template.Priority < 0 || template.Priority > 100 {
		return ErrInvalidInput
	}
	return nil
}
