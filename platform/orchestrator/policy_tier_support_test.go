// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"

	"axonflow/platform/agent/license"
)

func TestDefaultLicenseChecker(t *testing.T) {
	checker := &DefaultLicenseChecker{}

	if checker.IsEnterprise() {
		t.Error("DefaultLicenseChecker.IsEnterprise() should be false")
	}
	if tier := checker.Tier(); tier != license.TierCommunity {
		t.Errorf("DefaultLicenseChecker.Tier() = %q, want %q", tier, license.TierCommunity)
	}
	if limit := checker.PolicyLimit(); limit != license.CommunityLimits.TenantPolicies {
		t.Errorf("DefaultLicenseChecker.PolicyLimit() = %d, want %d", limit, license.CommunityLimits.TenantPolicies)
	}
	if limit := checker.OrgPolicyLimit(); limit != 0 {
		t.Errorf("DefaultLicenseChecker.OrgPolicyLimit() = %d, want 0", limit)
	}
	if limit := checker.CustomPolicyConnectorLimit(); limit != license.CommunityLimits.CustomPolicyConnectors {
		t.Errorf("DefaultLicenseChecker.CustomPolicyConnectorLimit() = %d, want %d", limit, license.CommunityLimits.CustomPolicyConnectors)
	}
	if days := checker.AuditRetentionDays(); days != 3 {
		t.Errorf("DefaultLicenseChecker.AuditRetentionDays() = %d, want 3", days)
	}
	if v := checker.MaxLLMProviders(); v != 2 {
		t.Errorf("DefaultLicenseChecker.MaxLLMProviders() = %d, want 2", v)
	}
	if v := checker.MaxExecutionHistory(); v != 50 {
		t.Errorf("DefaultLicenseChecker.MaxExecutionHistory() = %d, want 50", v)
	}
	if v := checker.MaxConcurrentExecutions(); v != 5 {
		t.Errorf("DefaultLicenseChecker.MaxConcurrentExecutions() = %d, want 5", v)
	}
	if v := checker.MaxPlans(); v != 25 {
		t.Errorf("DefaultLicenseChecker.MaxPlans() = %d, want 25", v)
	}
	if v := checker.MaxVersionsPerPlan(); v != 10 {
		t.Errorf("DefaultLicenseChecker.MaxVersionsPerPlan() = %d, want 10", v)
	}
	if v := checker.MaxSSEConnections(); v != 5 {
		t.Errorf("DefaultLicenseChecker.MaxSSEConnections() = %d, want 5", v)
	}
}

func TestEnvLicenseChecker_Community(t *testing.T) {
	// Without AXONFLOW_LICENSE_KEY, should default to Community tier
	t.Setenv("AXONFLOW_LICENSE_KEY", "")

	checker := NewEnvLicenseChecker()

	if checker.IsEnterprise() {
		t.Error("EnvLicenseChecker.IsEnterprise() should be false without license")
	}
	if tier := checker.Tier(); tier != license.TierCommunity {
		t.Errorf("EnvLicenseChecker.Tier() = %q, want %q", tier, license.TierCommunity)
	}
	if limit := checker.PolicyLimit(); limit != 20 {
		t.Errorf("EnvLicenseChecker.PolicyLimit() = %d, want 20", limit)
	}
	if limit := checker.OrgPolicyLimit(); limit != 0 {
		t.Errorf("EnvLicenseChecker.OrgPolicyLimit() = %d, want 0", limit)
	}
	if limit := checker.CustomPolicyConnectorLimit(); limit != 2 {
		t.Errorf("EnvLicenseChecker.CustomPolicyConnectorLimit() = %d, want 2", limit)
	}
	if days := checker.AuditRetentionDays(); days != 3 {
		t.Errorf("EnvLicenseChecker.AuditRetentionDays() = %d, want 3", days)
	}
	if v := checker.MaxLLMProviders(); v != 2 {
		t.Errorf("EnvLicenseChecker.MaxLLMProviders() = %d, want 2", v)
	}
	if v := checker.MaxExecutionHistory(); v != 50 {
		t.Errorf("EnvLicenseChecker.MaxExecutionHistory() = %d, want 50", v)
	}
	if v := checker.MaxConcurrentExecutions(); v != 5 {
		t.Errorf("EnvLicenseChecker.MaxConcurrentExecutions() = %d, want 5", v)
	}
	if v := checker.MaxPlans(); v != 25 {
		t.Errorf("EnvLicenseChecker.MaxPlans() = %d, want 25", v)
	}
	if v := checker.MaxVersionsPerPlan(); v != 10 {
		t.Errorf("EnvLicenseChecker.MaxVersionsPerPlan() = %d, want 10", v)
	}
	if v := checker.MaxSSEConnections(); v != 5 {
		t.Errorf("EnvLicenseChecker.MaxSSEConnections() = %d, want 5", v)
	}
}

func TestTierValidationError(t *testing.T) {
	err := NewTierValidationError("test message", "TEST_CODE")
	if err.Error() != "test message (TEST_CODE)" {
		t.Errorf("TierValidationError.Error() = %q, want %q", err.Error(), "test message (TEST_CODE)")
	}

	if !IsTierValidationError(err) {
		t.Error("IsTierValidationError should return true for TierValidationError")
	}

	if IsTierValidationError(nil) {
		t.Error("IsTierValidationError should return false for nil")
	}
}

func TestLicenseCheckerInterface(t *testing.T) {
	// Verify both implementations satisfy the interface
	var _ LicenseChecker = &DefaultLicenseChecker{}
	var _ LicenseChecker = &EnvLicenseChecker{}
}
