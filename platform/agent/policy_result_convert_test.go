// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

func TestConvertSharedResultToStatic_Nil(t *testing.T) {
	result := convertSharedResultToStatic(nil)
	if result == nil {
		t.Fatal("Expected non-nil result for nil input")
	}
	if result.Blocked {
		t.Error("Expected Blocked=false for nil input")
	}
	if len(result.TriggeredPolicies) != 0 {
		t.Error("Expected empty TriggeredPolicies for nil input")
	}
	if len(result.ChecksPerformed) == 0 || result.ChecksPerformed[0] != "shared_policy_engine" {
		t.Error("Expected ChecksPerformed to contain 'shared_policy_engine'")
	}
}

func TestConvertSharedResultToStatic_Blocked(t *testing.T) {
	blockedPolicy := &sharedpolicy.CompiledPolicy{
		PolicyID: "sqli_001",
		Severity: sharedpolicy.SeverityCritical,
	}

	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           true,
		BlockedBy:         blockedPolicy,
		BlockReason:       "SQL injection detected",
		PoliciesEvaluated: 150,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "sqli_001",
				Action:   sharedpolicy.ActionBlock,
				Category: sharedpolicy.CategorySecuritySQLi,
				Severity: sharedpolicy.SeverityCritical,
			},
		},
		ProcessingTimeMs: 2,
	})

	if !result.Blocked {
		t.Error("Expected Blocked=true")
	}
	if result.Reason != "SQL injection detected" {
		t.Errorf("Expected reason 'SQL injection detected', got '%s'", result.Reason)
	}
	if result.Severity != string(sharedpolicy.SeverityCritical) {
		t.Errorf("Expected severity 'critical', got '%s'", result.Severity)
	}
	if len(result.TriggeredPolicies) != 1 || result.TriggeredPolicies[0] != "sqli_001" {
		t.Errorf("Expected triggered policy 'sqli_001', got %v", result.TriggeredPolicies)
	}
	if result.ProcessingTimeMs != 2 {
		t.Errorf("Expected ProcessingTimeMs=2, got %d", result.ProcessingTimeMs)
	}
	if result.RequiresRedaction {
		t.Error("Blocked result should not require redaction")
	}
}

func TestConvertSharedResultToStatic_PIIRedaction(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 50,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "pii_ssn",
				Action:   sharedpolicy.ActionRedact,
				Category: sharedpolicy.CategoryPIIUS,
				Severity: sharedpolicy.SeverityCritical,
			},
			{
				PolicyID: "pii_email",
				Action:   sharedpolicy.ActionRedact,
				Category: sharedpolicy.CategoryPIIGlobal,
				Severity: sharedpolicy.SeverityMedium,
			},
		},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false for PII redaction")
	}
	if !result.RequiresRedaction {
		t.Error("Expected RequiresRedaction=true for PII matches")
	}
	if len(result.TriggeredPolicies) != 2 {
		t.Errorf("Expected 2 triggered policies, got %d", len(result.TriggeredPolicies))
	}
}

func TestConvertSharedResultToStatic_RequiresApproval(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 1,
		MatchedPolicies: []sharedpolicy.PolicyMatch{
			{
				PolicyID: "hitl_credit_scoring",
				Action:   sharedpolicy.ActionRequireApproval,
				Category: sharedpolicy.CategorySensitiveData,
				Severity: sharedpolicy.SeverityCritical,
			},
		},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false for require_approval")
	}
	if !result.RequiresApproval {
		t.Error("Expected RequiresApproval=true for ActionRequireApproval")
	}
}

func TestConvertSharedResultToStatic_EmptyResult(t *testing.T) {
	result := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:           false,
		PoliciesEvaluated: 150,
		MatchedPolicies:   []sharedpolicy.PolicyMatch{},
	})

	if result.Blocked {
		t.Error("Expected Blocked=false")
	}
	if result.RequiresRedaction {
		t.Error("Expected RequiresRedaction=false for no matches")
	}
	if result.RequiresApproval {
		t.Error("Expected RequiresApproval=false for no matches")
	}
}

func TestIsPIICategory_True(t *testing.T) {
	piiCategories := []sharedpolicy.PolicyCategory{
		sharedpolicy.CategoryPIIGlobal,
		sharedpolicy.CategoryPIIUS,
		sharedpolicy.CategoryPIIIndia,
		sharedpolicy.CategoryPIIEU,
		sharedpolicy.CategoryPIISingapore,
	}

	for _, cat := range piiCategories {
		if !isPIICategory(cat) {
			t.Errorf("isPIICategory(%s) = false, want true", cat)
		}
	}
}

func TestIsPIICategory_False(t *testing.T) {
	nonPIICategories := []sharedpolicy.PolicyCategory{
		sharedpolicy.CategorySecuritySQLi,
		sharedpolicy.CategorySecurityDangerous,
		sharedpolicy.CategoryAdminAccess,
		sharedpolicy.CategoryDataExfiltration,
		sharedpolicy.CategoryComplianceGDPR,
		sharedpolicy.CategoryComplianceHIPAA,
		sharedpolicy.CategorySensitiveData,
	}

	for _, cat := range nonPIICategories {
		if isPIICategory(cat) {
			t.Errorf("isPIICategory(%s) = true, want false", cat)
		}
	}
}
