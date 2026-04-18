// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"encoding/json"
	"testing"
	"time"
)

// =============================================================================
// Enum Validation Tests
// =============================================================================

func TestRiskCategory_Valid(t *testing.T) {
	tests := []struct {
		name     string
		category RiskCategory
		want     bool
	}{
		{"low is valid", RiskCategoryLow, true},
		{"medium is valid", RiskCategoryMedium, true},
		{"high is valid", RiskCategoryHigh, true},
		{"empty is invalid", RiskCategory(""), false},
		{"unknown is invalid", RiskCategory("unknown"), false},
		{"critical is invalid", RiskCategory("critical"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.category.Valid(); got != tt.want {
				t.Errorf("RiskCategory.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeploymentStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status DeploymentStatus
		want   bool
	}{
		{"development is valid", DeploymentStatusDevelopment, true},
		{"sandbox is valid", DeploymentStatusSandbox, true},
		{"canary is valid", DeploymentStatusCanary, true},
		{"production is valid", DeploymentStatusProduction, true},
		{"deprecated is valid", DeploymentStatusDeprecated, true},
		{"empty is invalid", DeploymentStatus(""), false},
		{"staging is invalid", DeploymentStatus("staging"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("DeploymentStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBoardApprovalStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status BoardApprovalStatus
		want   bool
	}{
		{"not_required is valid", BoardApprovalNotRequired, true},
		{"pending is valid", BoardApprovalPending, true},
		{"approved is valid", BoardApprovalApproved, true},
		{"rejected is valid", BoardApprovalRejected, true},
		{"revoked is valid", BoardApprovalRevoked, true},
		{"empty is invalid", BoardApprovalStatus(""), false},
		{"unknown is invalid", BoardApprovalStatus("unknown"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("BoardApprovalStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidationType_Valid(t *testing.T) {
	tests := []struct {
		name  string
		vtype ValidationType
		want  bool
	}{
		{"development is valid", ValidationTypeDevelopment, true},
		{"independent is valid", ValidationTypeIndependent, true},
		{"post_deployment is valid", ValidationTypePostDeployment, true},
		{"stress_test is valid", ValidationTypeStressTest, true},
		{"bias_audit is valid", ValidationTypeBiasAudit, true},
		{"empty is invalid", ValidationType(""), false},
		{"qa is invalid", ValidationType("qa"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vtype.Valid(); got != tt.want {
				t.Errorf("ValidationType.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatorType_Valid(t *testing.T) {
	tests := []struct {
		name  string
		vtype ValidatorType
		want  bool
	}{
		{"internal is valid", ValidatorTypeInternal, true},
		{"external_auditor is valid", ValidatorTypeExternalAuditor, true},
		{"regulator is valid", ValidatorTypeRegulator, true},
		{"empty is invalid", ValidatorType(""), false},
		{"third_party is invalid", ValidatorType("third_party"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.vtype.Valid(); got != tt.want {
				t.Errorf("ValidatorType.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidationRecommendation_Valid(t *testing.T) {
	tests := []struct {
		name string
		rec  ValidationRecommendation
		want bool
	}{
		{"approve is valid", ValidationRecommendationApprove, true},
		{"conditional is valid", ValidationRecommendationConditional, true},
		{"reject is valid", ValidationRecommendationReject, true},
		{"retest is valid", ValidationRecommendationRetest, true},
		{"empty is invalid", ValidationRecommendation(""), false},
		{"pass is invalid", ValidationRecommendation("pass"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rec.Valid(); got != tt.want {
				t.Errorf("ValidationRecommendation.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIncidentType_Valid(t *testing.T) {
	tests := []struct {
		name  string
		itype IncidentType
		want  bool
	}{
		{"model_failure is valid", IncidentTypeModelFailure, true},
		{"bias_detected is valid", IncidentTypeBiasDetected, true},
		{"security_breach is valid", IncidentTypeSecurityBreach, true},
		{"data_leak is valid", IncidentTypeDataLeak, true},
		{"performance_degradation is valid", IncidentTypePerformanceDegradation, true},
		{"regulatory_violation is valid", IncidentTypeRegulatoryViolation, true},
		{"customer_harm is valid", IncidentTypeCustomerHarm, true},
		{"financial_loss is valid", IncidentTypeFinancialLoss, true},
		{"other is valid", IncidentTypeOther, true},
		{"empty is invalid", IncidentType(""), false},
		{"bug is invalid", IncidentType("bug"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.itype.Valid(); got != tt.want {
				t.Errorf("IncidentType.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIncidentSeverity_Valid(t *testing.T) {
	tests := []struct {
		name     string
		severity IncidentSeverity
		want     bool
	}{
		{"low is valid", IncidentSeverityLow, true},
		{"medium is valid", IncidentSeverityMedium, true},
		{"high is valid", IncidentSeverityHigh, true},
		{"critical is valid", IncidentSeverityCritical, true},
		{"empty is invalid", IncidentSeverity(""), false},
		{"minor is invalid", IncidentSeverity("minor"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.Valid(); got != tt.want {
				t.Errorf("IncidentSeverity.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIncidentSeverity_RequiresBoardNotification(t *testing.T) {
	tests := []struct {
		name     string
		severity IncidentSeverity
		want     bool
	}{
		{"low does not require notification", IncidentSeverityLow, false},
		{"medium does not require notification", IncidentSeverityMedium, false},
		{"high requires notification", IncidentSeverityHigh, true},
		{"critical requires notification", IncidentSeverityCritical, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.severity.RequiresBoardNotification(); got != tt.want {
				t.Errorf("IncidentSeverity.RequiresBoardNotification() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIncidentStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status IncidentStatus
		want   bool
	}{
		{"open is valid", IncidentStatusOpen, true},
		{"investigating is valid", IncidentStatusInvestigating, true},
		{"mitigated is valid", IncidentStatusMitigated, true},
		{"resolved is valid", IncidentStatusResolved, true},
		{"closed is valid", IncidentStatusClosed, true},
		{"reopened is valid", IncidentStatusReopened, true},
		{"empty is invalid", IncidentStatus(""), false},
		{"pending is invalid", IncidentStatus("pending"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("IncidentStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectionMethod_Valid(t *testing.T) {
	tests := []struct {
		name   string
		method DetectionMethod
		want   bool
	}{
		{"automated_monitoring is valid", DetectionMethodAutomated, true},
		{"human_review is valid", DetectionMethodHumanReview, true},
		{"customer_complaint is valid", DetectionMethodCustomerComplaint, true},
		{"internal_audit is valid", DetectionMethodInternalAudit, true},
		{"external_audit is valid", DetectionMethodExternalAudit, true},
		{"regulator is valid", DetectionMethodRegulator, true},
		{"other is valid", DetectionMethodOther, true},
		{"empty is invalid", DetectionMethod(""), false},
		{"manual is invalid", DetectionMethod("manual"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.method.Valid(); got != tt.want {
				t.Errorf("DetectionMethod.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKillSwitchScope_Valid(t *testing.T) {
	tests := []struct {
		name  string
		scope KillSwitchScope
		want  bool
	}{
		{"global is valid", KillSwitchScopeGlobal, true},
		{"system is valid", KillSwitchScopeSystem, true},
		{"model is valid", KillSwitchScopeModel, true},
		{"feature is valid", KillSwitchScopeFeature, true},
		{"use_case is valid", KillSwitchScopeUseCase, true},
		{"empty is invalid", KillSwitchScope(""), false},
		{"org is invalid", KillSwitchScope("org"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.Valid(); got != tt.want {
				t.Errorf("KillSwitchScope.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFallbackBehavior_Valid(t *testing.T) {
	tests := []struct {
		name     string
		behavior FallbackBehavior
		want     bool
	}{
		{"block_all is valid", FallbackBehaviorBlockAll, true},
		{"human_review is valid", FallbackBehaviorHumanReview, true},
		{"previous_version is valid", FallbackBehaviorPreviousVersion, true},
		{"manual_only is valid", FallbackBehaviorManualOnly, true},
		{"graceful_degrade is valid", FallbackBehaviorGracefulDegrade, true},
		{"empty is invalid", FallbackBehavior(""), false},
		{"fail is invalid", FallbackBehavior("fail"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.behavior.Valid(); got != tt.want {
				t.Errorf("FallbackBehavior.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKillSwitchAction_Valid(t *testing.T) {
	tests := []struct {
		name   string
		action KillSwitchAction
		want   bool
	}{
		{"created is valid", KillSwitchActionCreated, true},
		{"activated is valid", KillSwitchActionActivated, true},
		{"deactivated is valid", KillSwitchActionDeactivated, true},
		{"auto_triggered is valid", KillSwitchActionAutoTriggered, true},
		{"config_updated is valid", KillSwitchActionConfigUpdated, true},
		{"deleted is valid", KillSwitchActionDeleted, true},
		{"empty is invalid", KillSwitchAction(""), false},
		{"modified is invalid", KillSwitchAction("modified"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.Valid(); got != tt.want {
				t.Errorf("KillSwitchAction.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportType_Valid(t *testing.T) {
	tests := []struct {
		name   string
		report ReportType
		want   bool
	}{
		{"quarterly is valid", ReportTypeQuarterly, true},
		{"annual is valid", ReportTypeAnnual, true},
		{"incident is valid", ReportTypeIncident, true},
		{"adhoc is valid", ReportTypeAdhoc, true},
		{"regulatory is valid", ReportTypeRegulatory, true},
		{"empty is invalid", ReportType(""), false},
		{"monthly is invalid", ReportType("monthly"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.report.Valid(); got != tt.want {
				t.Errorf("ReportType.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReportApprovalStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status ReportApprovalStatus
		want   bool
	}{
		{"draft is valid", ReportApprovalDraft, true},
		{"pending_review is valid", ReportApprovalPendingReview, true},
		{"approved is valid", ReportApprovalApproved, true},
		{"rejected is valid", ReportApprovalRejected, true},
		{"superseded is valid", ReportApprovalSuperseded, true},
		{"empty is invalid", ReportApprovalStatus(""), false},
		{"final is invalid", ReportApprovalStatus("final"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("ReportApprovalStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// JSON Serialization Tests
// =============================================================================

func TestAISystem_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	approvalDate := now.Add(-24 * time.Hour)

	system := AISystem{
		ID:                      "sys-123",
		OrgID:                   "org-456",
		SystemID:                "credit-scoring-v1",
		SystemName:              "Credit Scoring Model",
		Version:                 "1.0.0",
		Description:             "AI model for credit scoring",
		RiskCategory:            RiskCategoryHigh,
		DeploymentStatus:        DeploymentStatusProduction,
		ModelType:               "xgboost",
		ModelProvider:           "internal",
		UseCase:                 "credit_scoring",
		UseCaseDescription:      "Automated credit scoring for loan applications",
		DataSources:             []string{"credit_bureau", "bank_statements"},
		SensitiveDataCategories: []string{"financial", "personal"},
		DataResidency:           "india",
		OwnerID:                 "user-789",
		OwnerName:               "John Doe",
		OwnerDepartment:         "Risk Management",
		OwnerEmail:              "john.doe@example.com",
		BoardApprovalRequired:   true,
		BoardApprovalStatus:     BoardApprovalApproved,
		BoardApprovalDate:       &approvalDate,
		BoardApprovalReference:  "BOARD-2025-001",
		BoardApproverName:       "CRO",
		ValidationFrequencyDays: 90,
		Tags:                    []string{"critical", "customer-facing"},
		CreatedAt:               now,
		UpdatedAt:               now,
	}

	data, err := json.Marshal(system)
	if err != nil {
		t.Fatalf("Failed to marshal AISystem: %v", err)
	}

	var decoded AISystem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AISystem: %v", err)
	}

	if decoded.ID != system.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, system.ID)
	}
	if decoded.SystemID != system.SystemID {
		t.Errorf("SystemID mismatch: got %v, want %v", decoded.SystemID, system.SystemID)
	}
	if decoded.RiskCategory != system.RiskCategory {
		t.Errorf("RiskCategory mismatch: got %v, want %v", decoded.RiskCategory, system.RiskCategory)
	}
	if decoded.DeploymentStatus != system.DeploymentStatus {
		t.Errorf("DeploymentStatus mismatch: got %v, want %v", decoded.DeploymentStatus, system.DeploymentStatus)
	}
	if decoded.BoardApprovalRequired != system.BoardApprovalRequired {
		t.Errorf("BoardApprovalRequired mismatch: got %v, want %v", decoded.BoardApprovalRequired, system.BoardApprovalRequired)
	}
	if len(decoded.DataSources) != len(system.DataSources) {
		t.Errorf("DataSources length mismatch: got %v, want %v", len(decoded.DataSources), len(system.DataSources))
	}
	if len(decoded.Tags) != len(system.Tags) {
		t.Errorf("Tags length mismatch: got %v, want %v", len(decoded.Tags), len(system.Tags))
	}
}

func TestModelValidation_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nextReview := now.Add(90 * 24 * time.Hour)

	validation := ModelValidation{
		ID:                    "val-123",
		OrgID:                 "org-456",
		SystemID:              "sys-789",
		ValidationType:        ValidationTypeIndependent,
		ValidatorType:         ValidatorTypeExternalAuditor,
		ValidatorName:         "KPMG India",
		ValidatorOrganization: "KPMG",
		ValidatorCredentials:  "RBI Approved Auditor",
		ValidationDate:        now,
		DatasetDescription:    "12 months historical data",
		DatasetSize:           1000000,
		Methodology:           "Cross-validation with holdout set",
		TestScenarios:         []string{"accuracy", "bias", "stress"},
		Findings: []ValidationFinding{
			{
				ID:          "f-1",
				Category:    "bias",
				Severity:    "medium",
				Title:       "Age bias detected",
				Description: "Model shows slight bias against applicants over 60",
				Impact:      "May affect 5% of applications",
				Remediation: "Add age-based fairness constraints",
				Status:      "open",
			},
		},
		AccuracyMetrics: map[string]float64{
			"accuracy":  0.92,
			"precision": 0.89,
			"recall":    0.94,
			"f1_score":  0.915,
		},
		BiasAssessment: map[string]float64{
			"gender_disparity": 0.02,
			"age_disparity":    0.08,
		},
		BiasCategoriesTested: []string{"gender", "age", "region"},
		Recommendation:       ValidationRecommendationConditional,
		Conditions:           "Address age bias within 30 days",
		NextReviewDate:       &nextReview,
		RemediationRequired:  true,
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	data, err := json.Marshal(validation)
	if err != nil {
		t.Fatalf("Failed to marshal ModelValidation: %v", err)
	}

	var decoded ModelValidation
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal ModelValidation: %v", err)
	}

	if decoded.ID != validation.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, validation.ID)
	}
	if decoded.ValidationType != validation.ValidationType {
		t.Errorf("ValidationType mismatch: got %v, want %v", decoded.ValidationType, validation.ValidationType)
	}
	if decoded.ValidatorType != validation.ValidatorType {
		t.Errorf("ValidatorType mismatch: got %v, want %v", decoded.ValidatorType, validation.ValidatorType)
	}
	if decoded.Recommendation != validation.Recommendation {
		t.Errorf("Recommendation mismatch: got %v, want %v", decoded.Recommendation, validation.Recommendation)
	}
	if len(decoded.Findings) != len(validation.Findings) {
		t.Errorf("Findings length mismatch: got %v, want %v", len(decoded.Findings), len(validation.Findings))
	}
	if decoded.AccuracyMetrics["accuracy"] != validation.AccuracyMetrics["accuracy"] {
		t.Errorf("AccuracyMetrics mismatch")
	}
}

func TestAIIncident_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	resolvedAt := now.Add(2 * time.Hour)
	notificationDate := now.Add(1 * time.Hour)

	affectedCustomers := 150
	affectedTransactions := 500
	financialImpact := 250000.50

	incident := AIIncident{
		ID:                        "inc-123",
		OrgID:                     "org-456",
		IncidentID:                "INC-2025-001",
		SystemID:                  "sys-789",
		IncidentType:              IncidentTypeBiasDetected,
		Severity:                  IncidentSeverityHigh,
		DetectedAt:                now,
		DetectedBy:                DetectionMethodAutomated,
		DetectionDetails:          "Automated bias monitoring detected anomaly",
		Title:                     "Gender bias in loan approvals",
		Description:               "Model showing 15% higher rejection rate for female applicants",
		RootCause:                 "Training data imbalance",
		AffectedCustomersCount:    &affectedCustomers,
		AffectedTransactionsCount: &affectedTransactions,
		FinancialImpactINR:        &financialImpact,
		ReputationalImpact:        "medium",
		RemediationActions: []RemediationAction{
			{
				ID:         "ra-1",
				Action:     "Retrain model with balanced dataset",
				AssignedTo: "ML Team",
				Status:     "in_progress",
			},
		},
		ImmediateActionTaken:       "Switched to manual review for affected segment",
		LongTermFix:                "Implement fairness constraints in model",
		Status:                     IncidentStatusMitigated,
		ResolvedAt:                 &resolvedAt,
		ResolutionSummary:          "Model retrained and bias reduced to acceptable levels",
		LessonsLearned:             "Need continuous bias monitoring",
		BoardNotificationRequired:  true,
		BoardNotified:              true,
		BoardNotificationDate:      &notificationDate,
		BoardNotificationReference: "BOARD-2025-INC-001",
		RBINotificationRequired:    false,
		Tags:                       []string{"bias", "lending"},
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}

	data, err := json.Marshal(incident)
	if err != nil {
		t.Fatalf("Failed to marshal AIIncident: %v", err)
	}

	var decoded AIIncident
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AIIncident: %v", err)
	}

	if decoded.ID != incident.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, incident.ID)
	}
	if decoded.IncidentType != incident.IncidentType {
		t.Errorf("IncidentType mismatch: got %v, want %v", decoded.IncidentType, incident.IncidentType)
	}
	if decoded.Severity != incident.Severity {
		t.Errorf("Severity mismatch: got %v, want %v", decoded.Severity, incident.Severity)
	}
	if decoded.Status != incident.Status {
		t.Errorf("Status mismatch: got %v, want %v", decoded.Status, incident.Status)
	}
	if *decoded.AffectedCustomersCount != *incident.AffectedCustomersCount {
		t.Errorf("AffectedCustomersCount mismatch")
	}
	if *decoded.FinancialImpactINR != *incident.FinancialImpactINR {
		t.Errorf("FinancialImpactINR mismatch")
	}
	if len(decoded.RemediationActions) != len(incident.RemediationActions) {
		t.Errorf("RemediationActions length mismatch")
	}
}

func TestKillSwitch_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	activatedAt := now.Add(-1 * time.Hour)

	killSwitch := KillSwitch{
		ID:               "ks-123",
		OrgID:            "org-456",
		Scope:            KillSwitchScopeSystem,
		SystemID:         "sys-789",
		TargetIdentifier: "credit-scoring",
		IsActive:         true,
		ActivatedBy:      "user-001",
		ActivatedByEmail: "admin@example.com",
		ActivatedAt:      &activatedAt,
		ActivationReason: "Bias detected in production",
		AutoTriggered:    false,
		TriggerCondition: "bias_score > 0.1",
		TriggerThreshold: map[string]interface{}{
			"bias_score": 0.1,
			"error_rate": 0.05,
		},
		FallbackBehavior: FallbackBehaviorHumanReview,
		FallbackConfig: map[string]interface{}{
			"queue_name": "urgent_review",
			"timeout_ms": 30000,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.Marshal(killSwitch)
	if err != nil {
		t.Fatalf("Failed to marshal KillSwitch: %v", err)
	}

	var decoded KillSwitch
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KillSwitch: %v", err)
	}

	if decoded.ID != killSwitch.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, killSwitch.ID)
	}
	if decoded.Scope != killSwitch.Scope {
		t.Errorf("Scope mismatch: got %v, want %v", decoded.Scope, killSwitch.Scope)
	}
	if decoded.IsActive != killSwitch.IsActive {
		t.Errorf("IsActive mismatch: got %v, want %v", decoded.IsActive, killSwitch.IsActive)
	}
	if decoded.FallbackBehavior != killSwitch.FallbackBehavior {
		t.Errorf("FallbackBehavior mismatch: got %v, want %v", decoded.FallbackBehavior, killSwitch.FallbackBehavior)
	}
}

func TestKillSwitchHistoryEntry_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	entry := KillSwitchHistoryEntry{
		ID:           1,
		OrgID:        "org-456",
		KillSwitchID: "ks-123",
		Action:       KillSwitchActionActivated,
		ActorID:      "user-001",
		ActorEmail:   "admin@example.com",
		ActorRole:    "admin",
		ActorIP:      "192.168.1.100",
		Reason:       "Emergency stop due to bias detection",
		PreviousState: map[string]interface{}{
			"is_active": false,
		},
		NewState: map[string]interface{}{
			"is_active": true,
		},
		CreatedAt: now,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("Failed to marshal KillSwitchHistoryEntry: %v", err)
	}

	var decoded KillSwitchHistoryEntry
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal KillSwitchHistoryEntry: %v", err)
	}

	if decoded.ID != entry.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, entry.ID)
	}
	if decoded.Action != entry.Action {
		t.Errorf("Action mismatch: got %v, want %v", decoded.Action, entry.Action)
	}
	if decoded.ActorID != entry.ActorID {
		t.Errorf("ActorID mismatch: got %v, want %v", decoded.ActorID, entry.ActorID)
	}
}

func TestBoardReport_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	periodStart := now.Add(-90 * 24 * time.Hour)
	periodEnd := now
	approvedAt := now.Add(-1 * time.Hour)

	report := BoardReport{
		ID:                "br-123",
		OrgID:             "org-456",
		ReportType:        ReportTypeQuarterly,
		ReportPeriodStart: &periodStart,
		ReportPeriodEnd:   &periodEnd,
		ReportQuarter:     "Q4-2025",
		TotalAISystems:    15,
		SystemsByRisk: map[string]int{
			"low":    5,
			"medium": 7,
			"high":   3,
		},
		SystemsByStatus: map[string]int{
			"development": 2,
			"production":  10,
			"deprecated":  3,
		},
		NewSystemsDeployed: 2,
		SystemsDeprecated:  1,
		TotalValidations:   25,
		ValidationsByType: map[string]int{
			"development":     10,
			"independent":     8,
			"post_deployment": 7,
		},
		ValidationsByRecommendation: map[string]int{
			"approve":     20,
			"conditional": 3,
			"reject":      2,
		},
		OverdueValidations: 2,
		TotalIncidents:     5,
		IncidentsBySeverity: map[string]int{
			"low":      2,
			"medium":   2,
			"high":     1,
			"critical": 0,
		},
		IncidentsByType: map[string]int{
			"bias_detected":           2,
			"performance_degradation": 2,
			"model_failure":           1,
		},
		IncidentsResolved:          4,
		IncidentsOpen:              1,
		AverageResolutionTimeHours: 4.5,
		ComplianceScore:            92.5,
		ComplianceIssues: []ComplianceIssue{
			{
				Category:    "validation",
				Description: "2 systems overdue for validation",
				Severity:    "medium",
				Remediation: "Schedule validation within 30 days",
			},
		},
		KillSwitchActivations: 1,
		GeneratedBy:           "system",
		GeneratedAt:           now,
		GenerationMethod:      "automated",
		ApprovalStatus:        ReportApprovalApproved,
		ApprovedBy:            "CRO",
		ApprovedByEmail:       "cro@example.com",
		ApprovedAt:            &approvedAt,
		FilePath:              "/reports/q4-2025-board-report.pdf",
		FileFormat:            "pdf",
		FileSizeBytes:         1024000,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Failed to marshal BoardReport: %v", err)
	}

	var decoded BoardReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal BoardReport: %v", err)
	}

	if decoded.ID != report.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, report.ID)
	}
	if decoded.ReportType != report.ReportType {
		t.Errorf("ReportType mismatch: got %v, want %v", decoded.ReportType, report.ReportType)
	}
	if decoded.TotalAISystems != report.TotalAISystems {
		t.Errorf("TotalAISystems mismatch: got %v, want %v", decoded.TotalAISystems, report.TotalAISystems)
	}
	if decoded.ComplianceScore != report.ComplianceScore {
		t.Errorf("ComplianceScore mismatch: got %v, want %v", decoded.ComplianceScore, report.ComplianceScore)
	}
	if decoded.ApprovalStatus != report.ApprovalStatus {
		t.Errorf("ApprovalStatus mismatch: got %v, want %v", decoded.ApprovalStatus, report.ApprovalStatus)
	}
	if len(decoded.SystemsByRisk) != len(report.SystemsByRisk) {
		t.Errorf("SystemsByRisk length mismatch")
	}
	if len(decoded.ComplianceIssues) != len(report.ComplianceIssues) {
		t.Errorf("ComplianceIssues length mismatch")
	}
}

// =============================================================================
// Request Type Tests
// =============================================================================

func TestCreateAISystemRequest_JSONSerialization(t *testing.T) {
	req := CreateAISystemRequest{
		SystemID:                "credit-scoring-v1",
		SystemName:              "Credit Scoring Model",
		Version:                 "1.0.0",
		Description:             "AI model for credit scoring",
		RiskCategory:            "high",
		ModelType:               "xgboost",
		ModelProvider:           "internal",
		UseCase:                 "credit_scoring",
		UseCaseDescription:      "Automated credit scoring for loan applications",
		DataSources:             []string{"credit_bureau", "bank_statements"},
		SensitiveDataCategories: []string{"financial", "personal"},
		DataResidency:           "india",
		OwnerID:                 "user-789",
		OwnerName:               "John Doe",
		OwnerDepartment:         "Risk Management",
		OwnerEmail:              "john.doe@example.com",
		ValidationFrequencyDays: 90,
		Tags:                    []string{"critical", "customer-facing"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal CreateAISystemRequest: %v", err)
	}

	var decoded CreateAISystemRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal CreateAISystemRequest: %v", err)
	}

	if decoded.SystemID != req.SystemID {
		t.Errorf("SystemID mismatch: got %v, want %v", decoded.SystemID, req.SystemID)
	}
	if decoded.RiskCategory != req.RiskCategory {
		t.Errorf("RiskCategory mismatch: got %v, want %v", decoded.RiskCategory, req.RiskCategory)
	}
	if decoded.OwnerEmail != req.OwnerEmail {
		t.Errorf("OwnerEmail mismatch: got %v, want %v", decoded.OwnerEmail, req.OwnerEmail)
	}
}

func TestUpdateAISystemRequest_JSONSerialization(t *testing.T) {
	name := "Updated Credit Scoring Model"
	riskCategory := "medium"
	status := "production"

	req := UpdateAISystemRequest{
		SystemName:       &name,
		RiskCategory:     &riskCategory,
		DeploymentStatus: &status,
		Tags:             []string{"updated", "v2"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal UpdateAISystemRequest: %v", err)
	}

	var decoded UpdateAISystemRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal UpdateAISystemRequest: %v", err)
	}

	if *decoded.SystemName != *req.SystemName {
		t.Errorf("SystemName mismatch: got %v, want %v", *decoded.SystemName, *req.SystemName)
	}
	if *decoded.RiskCategory != *req.RiskCategory {
		t.Errorf("RiskCategory mismatch: got %v, want %v", *decoded.RiskCategory, *req.RiskCategory)
	}
}

func TestBoardApprovalRequest_JSONSerialization(t *testing.T) {
	req := BoardApprovalRequest{
		Action:    "approve",
		Reference: "BOARD-2025-001",
		Approver:  "CRO",
		Notes:     "Approved after risk review",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal BoardApprovalRequest: %v", err)
	}

	var decoded BoardApprovalRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal BoardApprovalRequest: %v", err)
	}

	if decoded.Action != req.Action {
		t.Errorf("Action mismatch: got %v, want %v", decoded.Action, req.Action)
	}
	if decoded.Approver != req.Approver {
		t.Errorf("Approver mismatch: got %v, want %v", decoded.Approver, req.Approver)
	}
}

func TestListAISystemsParams_Defaults(t *testing.T) {
	params := ListAISystemsParams{}

	if params.Limit != 0 {
		t.Errorf("Expected default Limit to be 0, got %v", params.Limit)
	}
	if params.Offset != 0 {
		t.Errorf("Expected default Offset to be 0, got %v", params.Offset)
	}
	if params.ValidationOverdue != nil {
		t.Errorf("Expected default ValidationOverdue to be nil")
	}
}

func TestAISystemSummary_JSONSerialization(t *testing.T) {
	summary := AISystemSummary{
		TotalSystems: 15,
		SystemsByRisk: map[string]int{
			"low":    5,
			"medium": 7,
			"high":   3,
		},
		SystemsByStatus: map[string]int{
			"development": 2,
			"production":  10,
			"deprecated":  3,
		},
		SystemsPendingApproval:   2,
		SystemsOverdueValidation: 1,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal AISystemSummary: %v", err)
	}

	var decoded AISystemSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AISystemSummary: %v", err)
	}

	if decoded.TotalSystems != summary.TotalSystems {
		t.Errorf("TotalSystems mismatch: got %v, want %v", decoded.TotalSystems, summary.TotalSystems)
	}
	if decoded.SystemsPendingApproval != summary.SystemsPendingApproval {
		t.Errorf("SystemsPendingApproval mismatch: got %v, want %v", decoded.SystemsPendingApproval, summary.SystemsPendingApproval)
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestEmptyStructsSerialization(t *testing.T) {
	// Test empty structs serialize without error
	tests := []struct {
		name string
		val  interface{}
	}{
		{"AISystem", AISystem{}},
		{"ModelValidation", ModelValidation{}},
		{"AIIncident", AIIncident{}},
		{"KillSwitch", KillSwitch{}},
		{"BoardReport", BoardReport{}},
		{"ValidationFinding", ValidationFinding{}},
		{"RemediationAction", RemediationAction{}},
		{"ComplianceIssue", ComplianceIssue{}},
		{"CorrectiveAction", CorrectiveAction{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := json.Marshal(tt.val)
			if err != nil {
				t.Errorf("Failed to marshal empty %s: %v", tt.name, err)
			}
		})
	}
}

func TestNilPointerHandling(t *testing.T) {
	system := AISystem{
		ID:                    "sys-123",
		OrgID:                 "org-456",
		SystemID:              "test-system",
		RiskCategory:          RiskCategoryLow,
		DeploymentStatus:      DeploymentStatusDevelopment,
		BoardApprovalRequired: false,
		// All pointer fields are nil
	}

	data, err := json.Marshal(system)
	if err != nil {
		t.Fatalf("Failed to marshal AISystem with nil pointers: %v", err)
	}

	var decoded AISystem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AISystem: %v", err)
	}

	if decoded.BoardApprovalDate != nil {
		t.Errorf("Expected BoardApprovalDate to be nil")
	}
	if decoded.LastValidationDate != nil {
		t.Errorf("Expected LastValidationDate to be nil")
	}
	if decoded.NextValidationDue != nil {
		t.Errorf("Expected NextValidationDue to be nil")
	}
}

func TestEnumStringValues(t *testing.T) {
	// Ensure enum string values match database constraints
	tests := []struct {
		name     string
		enum     interface{}
		expected string
	}{
		{"RiskCategoryLow", RiskCategoryLow, "low"},
		{"RiskCategoryMedium", RiskCategoryMedium, "medium"},
		{"RiskCategoryHigh", RiskCategoryHigh, "high"},
		{"DeploymentStatusProduction", DeploymentStatusProduction, "production"},
		{"BoardApprovalPending", BoardApprovalPending, "pending"},
		{"IncidentSeverityCritical", IncidentSeverityCritical, "critical"},
		{"KillSwitchScopeGlobal", KillSwitchScopeGlobal, "global"},
		{"FallbackBehaviorBlockAll", FallbackBehaviorBlockAll, "block_all"},
		{"ReportTypeQuarterly", ReportTypeQuarterly, "quarterly"},
		{"AuditExportFormatJSON", AuditExportFormatJSON, "json"},
		{"AuditExportStatusPending", AuditExportStatusPending, "pending"},
		{"AuditExportTypeFull", AuditExportTypeFull, "full"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ""
			switch v := tt.enum.(type) {
			case RiskCategory:
				got = string(v)
			case DeploymentStatus:
				got = string(v)
			case BoardApprovalStatus:
				got = string(v)
			case IncidentSeverity:
				got = string(v)
			case KillSwitchScope:
				got = string(v)
			case FallbackBehavior:
				got = string(v)
			case ReportType:
				got = string(v)
			case AuditExportFormat:
				got = string(v)
			case AuditExportStatus:
				got = string(v)
			case AuditExportType:
				got = string(v)
			}
			if got != tt.expected {
				t.Errorf("Enum string value mismatch: got %v, want %v", got, tt.expected)
			}
		})
	}
}

// =============================================================================
// Audit Export Enum Tests
// =============================================================================

func TestAuditExportType_Valid(t *testing.T) {
	tests := []struct {
		name       string
		exportType AuditExportType
		want       bool
	}{
		{"full is valid", AuditExportTypeFull, true},
		{"systems is valid", AuditExportTypeSystems, true},
		{"validations is valid", AuditExportTypeValidations, true},
		{"incidents is valid", AuditExportTypeIncidents, true},
		{"kill_switches is valid", AuditExportTypeKillSwitches, true},
		{"reports is valid", AuditExportTypeReports, true},
		{"comprehensive is valid", AuditExportTypeComprehensive, true},
		{"empty is invalid", AuditExportType(""), false},
		{"partial is invalid", AuditExportType("partial"), false},
		{"summary is invalid", AuditExportType("summary"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.exportType.Valid(); got != tt.want {
				t.Errorf("AuditExportType.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditExportFormat_Valid(t *testing.T) {
	tests := []struct {
		name   string
		format AuditExportFormat
		want   bool
	}{
		{"json is valid", AuditExportFormatJSON, true},
		{"csv is valid", AuditExportFormatCSV, true},
		{"pdf is valid", AuditExportFormatPDF, true},
		{"xlsx is valid", AuditExportFormatXLSX, true},
		{"empty is invalid", AuditExportFormat(""), false},
		{"xml is invalid", AuditExportFormat("xml"), false},
		{"html is invalid", AuditExportFormat("html"), false},
		{"doc is invalid", AuditExportFormat("doc"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.format.Valid(); got != tt.want {
				t.Errorf("AuditExportFormat.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuditExportStatus_Valid(t *testing.T) {
	tests := []struct {
		name   string
		status AuditExportStatus
		want   bool
	}{
		{"pending is valid", AuditExportStatusPending, true},
		{"processing is valid", AuditExportStatusProcessing, true},
		{"completed is valid", AuditExportStatusCompleted, true},
		{"failed is valid", AuditExportStatusFailed, true},
		{"expired is valid", AuditExportStatusExpired, true},
		{"empty is invalid", AuditExportStatus(""), false},
		{"cancelled is invalid", AuditExportStatus("cancelled"), false},
		{"queued is invalid", AuditExportStatus("queued"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.Valid(); got != tt.want {
				t.Errorf("AuditExportStatus.Valid() = %v, want %v", got, tt.want)
			}
		})
	}
}

// =============================================================================
// AuditExport Struct Tests
// =============================================================================

func TestAuditExport_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	startDate := now.Add(-30 * 24 * time.Hour)
	endDate := now
	completedAt := now.Add(-1 * time.Hour)
	expiresAt := now.Add(7 * 24 * time.Hour)

	export := AuditExport{
		ID:               "ae-123",
		OrgID:            "org-456",
		ExportType:       AuditExportTypeFull,
		Format:           AuditExportFormatJSON,
		StartDate:        &startDate,
		EndDate:          &endDate,
		SystemIDs:        []string{"sys-1", "sys-2"},
		RiskCategories:   []string{"high", "medium"},
		IncludeArchived:  true,
		Status:           AuditExportStatusCompleted,
		RequestedBy:      "user-789",
		RequestedByEmail: "auditor@example.com",
		Purpose:          "Quarterly RBI compliance audit",
		CompletedAt:      &completedAt,
		FilePath:         "/exports/ae-123.json",
		FileSizeBytes:    2048000,
		FileChecksum:     "sha256:abc123",
		RecordCount:      500,
		DownloadURL:      "https://s3.example.com/exports/ae-123.json",
		StorageType:      "s3",
		StorageKey:       "exports/ae-123.json",
		Summary: &AuditExportSummary{
			TotalSystems:      15,
			TotalValidations:  25,
			TotalIncidents:    5,
			TotalKillSwitches: 3,
			TotalReports:      4,
			DateRangeStart:    &startDate,
			DateRangeEnd:      &endDate,
		},
		ExpiresAt: &expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("Failed to marshal AuditExport: %v", err)
	}

	var decoded AuditExport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AuditExport: %v", err)
	}

	if decoded.ID != export.ID {
		t.Errorf("ID mismatch: got %v, want %v", decoded.ID, export.ID)
	}
	if decoded.ExportType != export.ExportType {
		t.Errorf("ExportType mismatch: got %v, want %v", decoded.ExportType, export.ExportType)
	}
	if decoded.Format != export.Format {
		t.Errorf("Format mismatch: got %v, want %v", decoded.Format, export.Format)
	}
	if decoded.Status != export.Status {
		t.Errorf("Status mismatch: got %v, want %v", decoded.Status, export.Status)
	}
	if decoded.RecordCount != export.RecordCount {
		t.Errorf("RecordCount mismatch: got %v, want %v", decoded.RecordCount, export.RecordCount)
	}
	if decoded.Summary == nil {
		t.Fatal("Expected Summary to be non-nil")
	}
	if decoded.Summary.TotalSystems != export.Summary.TotalSystems {
		t.Errorf("Summary.TotalSystems mismatch: got %v, want %v", decoded.Summary.TotalSystems, export.Summary.TotalSystems)
	}
	if len(decoded.SystemIDs) != len(export.SystemIDs) {
		t.Errorf("SystemIDs length mismatch: got %v, want %v", len(decoded.SystemIDs), len(export.SystemIDs))
	}
	if decoded.IncludeArchived != export.IncludeArchived {
		t.Errorf("IncludeArchived mismatch: got %v, want %v", decoded.IncludeArchived, export.IncludeArchived)
	}
}

func TestAuditExportSummary_JSONSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Add(-30 * 24 * time.Hour)

	summary := AuditExportSummary{
		TotalSystems:      10,
		TotalValidations:  20,
		TotalIncidents:    3,
		TotalKillSwitches: 1,
		TotalReports:      5,
		DateRangeStart:    &start,
		DateRangeEnd:      &now,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal AuditExportSummary: %v", err)
	}

	var decoded AuditExportSummary
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal AuditExportSummary: %v", err)
	}

	if decoded.TotalSystems != summary.TotalSystems {
		t.Errorf("TotalSystems mismatch: got %v, want %v", decoded.TotalSystems, summary.TotalSystems)
	}
	if decoded.TotalValidations != summary.TotalValidations {
		t.Errorf("TotalValidations mismatch: got %v, want %v", decoded.TotalValidations, summary.TotalValidations)
	}
	if decoded.TotalIncidents != summary.TotalIncidents {
		t.Errorf("TotalIncidents mismatch: got %v, want %v", decoded.TotalIncidents, summary.TotalIncidents)
	}
}
