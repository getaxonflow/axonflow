// Copyright 2025 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"testing"
)

func TestGetRBIPolicyTemplates(t *testing.T) {
	templates := GetRBIPolicyTemplates()

	// Should return 17 templates
	if len(templates) != 17 {
		t.Errorf("Expected 17 templates, got %d", len(templates))
	}

	// Verify all templates have required fields
	for _, tmpl := range templates {
		if tmpl.ID == "" {
			t.Error("Template has empty ID")
		}
		if tmpl.Name == "" {
			t.Errorf("Template %s has empty Name", tmpl.ID)
		}
		if tmpl.Description == "" {
			t.Errorf("Template %s has empty Description", tmpl.ID)
		}
		if tmpl.Type == "" {
			t.Errorf("Template %s has empty Type", tmpl.ID)
		}
		if tmpl.Severity == "" {
			t.Errorf("Template %s has empty Severity", tmpl.ID)
		}
		if len(tmpl.Conditions) == 0 {
			t.Errorf("Template %s has no Conditions", tmpl.ID)
		}
		if len(tmpl.Actions) == 0 {
			t.Errorf("Template %s has no Actions", tmpl.ID)
		}
		if tmpl.RegulatoryReference == "" {
			t.Errorf("Template %s has empty RegulatoryReference", tmpl.ID)
		}
		if len(tmpl.ApplicableRiskLevels) == 0 {
			t.Errorf("Template %s has no ApplicableRiskLevels", tmpl.ID)
		}
	}

	// Verify unique IDs
	idMap := make(map[string]bool)
	for _, tmpl := range templates {
		if idMap[tmpl.ID] {
			t.Errorf("Duplicate template ID: %s", tmpl.ID)
		}
		idMap[tmpl.ID] = true
	}
}

func TestGetRBIPolicyTemplatesByType(t *testing.T) {
	tests := []struct {
		name         string
		policyType   RBIPolicyType
		expectedMin  int
		expectedMax  int
	}{
		{
			name:        "Data Protection",
			policyType:  RBIPolicyTypeDataProtection,
			expectedMin: 4,
			expectedMax: 4,
		},
		{
			name:        "Model Governance",
			policyType:  RBIPolicyTypeModelGovernance,
			expectedMin: 3,
			expectedMax: 3,
		},
		{
			name:        "Risk Management",
			policyType:  RBIPolicyTypeRiskManagement,
			expectedMin: 2,
			expectedMax: 2,
		},
		{
			name:        "Incident Response",
			policyType:  RBIPolicyTypeIncidentResponse,
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "Kill Switch",
			policyType:  RBIPolicyTypeKillSwitch,
			expectedMin: 1,
			expectedMax: 1,
		},
		{
			name:        "Board Reporting",
			policyType:  RBIPolicyTypeBoardReporting,
			expectedMin: 2,
			expectedMax: 2,
		},
		{
			name:        "Customer Protection",
			policyType:  RBIPolicyTypeCustomerProtection,
			expectedMin: 2,
			expectedMax: 2,
		},
		{
			name:        "Audit Compliance",
			policyType:  RBIPolicyTypeAuditCompliance,
			expectedMin: 2,
			expectedMax: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templates := GetRBIPolicyTemplatesByType(tt.policyType)
			if len(templates) < tt.expectedMin || len(templates) > tt.expectedMax {
				t.Errorf("GetRBIPolicyTemplatesByType(%s) returned %d templates, expected %d-%d",
					tt.policyType, len(templates), tt.expectedMin, tt.expectedMax)
			}

			// Verify all returned templates have the correct type
			for _, tmpl := range templates {
				if tmpl.Type != tt.policyType {
					t.Errorf("Template %s has type %s, expected %s", tmpl.ID, tmpl.Type, tt.policyType)
				}
			}
		})
	}
}

func TestGetRBIPolicyTemplatesByRiskLevel(t *testing.T) {
	tests := []struct {
		name        string
		riskLevel   string
		expectedMin int
	}{
		{
			name:        "Low Risk",
			riskLevel:   "low",
			expectedMin: 5, // Data protection + some audit policies
		},
		{
			name:        "Medium Risk",
			riskLevel:   "medium",
			expectedMin: 12,
		},
		{
			name:        "High Risk",
			riskLevel:   "high",
			expectedMin: 14,
		},
		{
			name:        "Critical Risk",
			riskLevel:   "critical",
			expectedMin: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templates := GetRBIPolicyTemplatesByRiskLevel(tt.riskLevel)
			if len(templates) < tt.expectedMin {
				t.Errorf("GetRBIPolicyTemplatesByRiskLevel(%s) returned %d templates, expected at least %d",
					tt.riskLevel, len(templates), tt.expectedMin)
			}

			// Verify all returned templates have the risk level in their applicable levels
			for _, tmpl := range templates {
				found := false
				for _, level := range tmpl.ApplicableRiskLevels {
					if level == tt.riskLevel {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Template %s doesn't have risk level %s in ApplicableRiskLevels",
						tmpl.ID, tt.riskLevel)
				}
			}
		})
	}

	// Test non-existent risk level
	t.Run("Non-existent Risk Level", func(t *testing.T) {
		templates := GetRBIPolicyTemplatesByRiskLevel("nonexistent")
		if len(templates) != 0 {
			t.Errorf("Expected 0 templates for non-existent risk level, got %d", len(templates))
		}
	})
}

func TestGetRBIPolicyTemplateByID(t *testing.T) {
	tests := []struct {
		name         string
		templateID   string
		expectNil    bool
		expectedName string
	}{
		{
			name:         "UPI Protection",
			templateID:   "rbi_pol_upi_protection",
			expectNil:    false,
			expectedName: "UPI ID Data Protection",
		},
		{
			name:         "Aadhaar Protection",
			templateID:   "rbi_pol_aadhaar_protection",
			expectNil:    false,
			expectedName: "Aadhaar Number Protection",
		},
		{
			name:         "High Risk Deployment",
			templateID:   "rbi_pol_high_risk_deployment",
			expectNil:    false,
			expectedName: "High-Risk AI Model Deployment Control",
		},
		{
			name:         "Kill Switch",
			templateID:   "rbi_pol_critical_kill_switch",
			expectNil:    false,
			expectedName: "Critical Incident Auto Kill Switch",
		},
		{
			name:         "Board Report",
			templateID:   "rbi_pol_quarterly_report",
			expectNil:    false,
			expectedName: "Quarterly AI Board Report Compliance",
		},
		{
			name:         "Non-existent ID",
			templateID:   "rbi_pol_nonexistent",
			expectNil:    true,
			expectedName: "",
		},
		{
			name:         "Empty ID",
			templateID:   "",
			expectNil:    true,
			expectedName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := GetRBIPolicyTemplateByID(tt.templateID)

			if tt.expectNil {
				if tmpl != nil {
					t.Errorf("Expected nil for ID %s, got template %s", tt.templateID, tmpl.Name)
				}
			} else {
				if tmpl == nil {
					t.Errorf("Expected template for ID %s, got nil", tt.templateID)
				} else if tmpl.Name != tt.expectedName {
					t.Errorf("Expected name %s for ID %s, got %s", tt.expectedName, tt.templateID, tmpl.Name)
				}
			}
		})
	}
}

func TestGetRBIPolicyTemplateCategories(t *testing.T) {
	categories := GetRBIPolicyTemplateCategories()

	// Should have 7 categories
	if len(categories) != 7 {
		t.Errorf("Expected 7 categories, got %d", len(categories))
	}

	expectedCategories := []struct {
		id           string
		name         string
		minTemplates int
	}{
		{"data_protection", "Data Protection", 4},
		{"model_governance", "Model Governance", 3},
		{"risk_management", "Risk Management", 2},
		{"incident_response", "Incident Response", 2}, // Includes kill switch
		{"board_reporting", "Board Reporting", 2},
		{"customer_protection", "Customer Protection", 2},
		{"audit_compliance", "Audit & Compliance", 2},
	}

	for i, expected := range expectedCategories {
		if i >= len(categories) {
			t.Errorf("Missing category: %s", expected.id)
			continue
		}

		cat := categories[i]
		if cat.ID != expected.id {
			t.Errorf("Category %d: expected ID %s, got %s", i, expected.id, cat.ID)
		}
		if cat.Name != expected.name {
			t.Errorf("Category %d: expected Name %s, got %s", i, expected.name, cat.Name)
		}
		if len(cat.Templates) < expected.minTemplates {
			t.Errorf("Category %s: expected at least %d templates, got %d",
				expected.id, expected.minTemplates, len(cat.Templates))
		}
		if cat.Description == "" {
			t.Errorf("Category %s has empty Description", cat.ID)
		}
	}
}

func TestValidateRBIPolicyTemplate(t *testing.T) {
	tests := []struct {
		name      string
		template  *RBIPolicyTemplate
		expectErr bool
	}{
		{
			name: "Valid Template",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: 50,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: false,
		},
		{
			name: "Empty ID",
			template: &RBIPolicyTemplate{
				ID:       "",
				Name:     "Test Policy",
				Priority: 50,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: true,
		},
		{
			name: "Empty Name",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "",
				Priority: 50,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: true,
		},
		{
			name: "No Conditions",
			template: &RBIPolicyTemplate{
				ID:         "test_policy",
				Name:       "Test Policy",
				Priority:   50,
				Conditions: []RBIPolicyCondition{},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: true,
		},
		{
			name: "No Actions",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: 50,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{},
			},
			expectErr: true,
		},
		{
			name: "Priority Too Low",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: -1,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: true,
		},
		{
			name: "Priority Too High",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: 101,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: true,
		},
		{
			name: "Priority at Boundary 0",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: 0,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: false,
		},
		{
			name: "Priority at Boundary 100",
			template: &RBIPolicyTemplate{
				ID:       "test_policy",
				Name:     "Test Policy",
				Priority: 100,
				Conditions: []RBIPolicyCondition{
					{Field: "test", Operator: "equals", Value: "value"},
				},
				Actions: []RBIPolicyAction{
					{Type: "alert"},
				},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRBIPolicyTemplate(tt.template)
			if tt.expectErr && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
		})
	}
}

func TestAllTemplatesAreValid(t *testing.T) {
	templates := GetRBIPolicyTemplates()

	for _, tmpl := range templates {
		err := ValidateRBIPolicyTemplate(tmpl)
		if err != nil {
			t.Errorf("Built-in template %s failed validation: %v", tmpl.ID, err)
		}
	}
}

func TestPolicyTemplatePriorities(t *testing.T) {
	// Critical policies should have priority >= 95
	criticalPolicies := []string{
		"rbi_pol_upi_protection",
		"rbi_pol_aadhaar_protection",
		"rbi_pol_bank_account_protection",
		"rbi_pol_high_risk_deployment",
		"rbi_pol_critical_kill_switch",
		"rbi_pol_board_incident_notification",
	}

	for _, id := range criticalPolicies {
		tmpl := GetRBIPolicyTemplateByID(id)
		if tmpl == nil {
			t.Errorf("Critical policy %s not found", id)
			continue
		}
		if tmpl.Priority < 95 {
			t.Errorf("Critical policy %s has priority %d, expected >= 95", id, tmpl.Priority)
		}
	}
}

func TestPolicyTypeCoverage(t *testing.T) {
	// Ensure we have at least one policy for each type
	types := []RBIPolicyType{
		RBIPolicyTypeDataProtection,
		RBIPolicyTypeModelGovernance,
		RBIPolicyTypeRiskManagement,
		RBIPolicyTypeAuditCompliance,
		RBIPolicyTypeIncidentResponse,
		RBIPolicyTypeKillSwitch,
		RBIPolicyTypeBoardReporting,
		RBIPolicyTypeCustomerProtection,
	}

	for _, policyType := range types {
		templates := GetRBIPolicyTemplatesByType(policyType)
		if len(templates) == 0 {
			t.Errorf("No templates found for policy type: %s", policyType)
		}
	}
}

func TestRegulatoryReferences(t *testing.T) {
	for _, tmpl := range GetRBIPolicyTemplates() {
		// All templates should reference RBI FREE-AI Framework
		if tmpl.RegulatoryReference == "" {
			t.Errorf("Template %s has no regulatory reference", tmpl.ID)
		}
		// Most should contain "RBI FREE-AI Framework"
		// (Some might reference other regulations like UIDAI)
	}
}

func TestDataProtectionPolicies(t *testing.T) {
	// Verify specific data protection policies exist and are configured correctly
	tests := []struct {
		id             string
		name           string
		severity       RBIPolicySeverity
		hasAuditAction bool
		hasMaskAction  bool
	}{
		{
			id:             "rbi_pol_upi_protection",
			name:           "UPI ID Data Protection",
			severity:       RBIPolicySeverityCritical,
			hasAuditAction: true,
			hasMaskAction:  true,
		},
		{
			id:             "rbi_pol_aadhaar_protection",
			name:           "Aadhaar Number Protection",
			severity:       RBIPolicySeverityCritical,
			hasAuditAction: true,
			hasMaskAction:  true,
		},
		{
			id:             "rbi_pol_pan_protection",
			name:           "PAN Card Number Protection",
			severity:       RBIPolicySeverityHigh,
			hasAuditAction: true,
			hasMaskAction:  true,
		},
		{
			id:             "rbi_pol_bank_account_protection",
			name:           "Bank Account Number Protection",
			severity:       RBIPolicySeverityCritical,
			hasAuditAction: true,
			hasMaskAction:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := GetRBIPolicyTemplateByID(tt.id)
			if tmpl == nil {
				t.Fatalf("Template %s not found", tt.id)
			}

			if tmpl.Name != tt.name {
				t.Errorf("Expected name %s, got %s", tt.name, tmpl.Name)
			}

			if tmpl.Severity != tt.severity {
				t.Errorf("Expected severity %s, got %s", tt.severity, tmpl.Severity)
			}

			// Check for required action types
			hasAudit := false
			hasMask := false
			for _, action := range tmpl.Actions {
				if action.Type == "audit_log" {
					hasAudit = true
				}
				if action.Type == "mask" {
					hasMask = true
				}
			}

			if tt.hasAuditAction && !hasAudit {
				t.Errorf("Template %s missing audit_log action", tt.id)
			}
			if tt.hasMaskAction && !hasMask {
				t.Errorf("Template %s missing mask action", tt.id)
			}
		})
	}
}

func TestKillSwitchPolicy(t *testing.T) {
	tmpl := GetRBIPolicyTemplateByID("rbi_pol_critical_kill_switch")
	if tmpl == nil {
		t.Fatal("Kill switch policy not found")
	}

	// Kill switch should be critical severity
	if tmpl.Severity != RBIPolicySeverityCritical {
		t.Errorf("Kill switch should be critical severity, got %s", tmpl.Severity)
	}

	// Should have highest priority
	if tmpl.Priority != 100 {
		t.Errorf("Kill switch should have priority 100, got %d", tmpl.Priority)
	}

	// Should have activate_kill_switch action
	hasKillSwitch := false
	hasNotifyBoard := false
	for _, action := range tmpl.Actions {
		if action.Type == "activate_kill_switch" {
			hasKillSwitch = true
		}
		if action.Type == "notify_board" {
			hasNotifyBoard = true
		}
	}

	if !hasKillSwitch {
		t.Error("Kill switch policy missing activate_kill_switch action")
	}
	if !hasNotifyBoard {
		t.Error("Kill switch policy missing notify_board action")
	}
}

func TestBoardApprovalRequirements(t *testing.T) {
	templates := GetRBIPolicyTemplates()

	boardApprovalRequired := 0
	for _, tmpl := range templates {
		if tmpl.RequiresBoardApproval {
			boardApprovalRequired++
			// High-risk deployment should require board approval
			if tmpl.ID == "rbi_pol_high_risk_deployment" {
				// This is expected
			}
		}
	}

	// At least the high-risk deployment policy should require board approval
	if boardApprovalRequired < 1 {
		t.Error("Expected at least one policy to require board approval")
	}
}

func TestPolicyConditionStructure(t *testing.T) {
	templates := GetRBIPolicyTemplates()

	for _, tmpl := range templates {
		for i, condition := range tmpl.Conditions {
			if condition.Field == "" {
				t.Errorf("Template %s condition %d has empty Field", tmpl.ID, i)
			}
			if condition.Operator == "" {
				t.Errorf("Template %s condition %d has empty Operator", tmpl.ID, i)
			}
			// Value can be various types, but should not be nil for most conditions
		}
	}
}

func TestPolicyActionStructure(t *testing.T) {
	templates := GetRBIPolicyTemplates()

	validActionTypes := map[string]bool{
		"mask":                          true,
		"audit_log":                     true,
		"alert":                         true,
		"block":                         true,
		"rate_limit":                    true,
		"require_approval":              true,
		"require_validation":            true,
		"notify":                        true,
		"create_incident":               true,
		"schedule_validation":           true,
		"enable_human_review":           true,
		"require_human_review":          true,
		"activate_kill_switch":          true,
		"notify_board":                  true,
		"prepare_rbi_notification":      true,
		"escalate":                      true,
		"initiate_customer_communication": true,
		"create_remediation_plan":       true,
		"generate_report":               true,
		"schedule_board_meeting":        true,
		"generate_explanation":          true,
		"provide_appeal_info":           true,
		"request_consent":               true,
		"set_retention":                 true,
		"encrypt":                       true,
	}

	for _, tmpl := range templates {
		for i, action := range tmpl.Actions {
			if action.Type == "" {
				t.Errorf("Template %s action %d has empty Type", tmpl.ID, i)
			}
			if !validActionTypes[action.Type] {
				t.Errorf("Template %s has unknown action type: %s", tmpl.ID, action.Type)
			}
		}
	}
}
