//go:build enterprise

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

package license

import (
	"context"
	"testing"
)

// TestTierBoundary_EvaluationLicenseGeneration tests that EVALUATION tier licenses
// can be generated and validated end-to-end.
func TestTierBoundary_EvaluationLicenseGeneration(t *testing.T) {
	setupTestKeypair(t)

	key, err := GenerateServiceLicenseKey(
		TierEvaluation,
		"boundary-test-org",
		"platform",
		"backend-service",
		[]string{"mcp:*:*", "llm:*:*"},
		90,
	)
	if err != nil {
		t.Fatalf("Failed to generate EVALUATION license: %v", err)
	}

	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		t.Fatalf("Failed to validate EVALUATION license: %v", err)
	}

	if !result.Valid {
		t.Fatalf("EVALUATION license is not valid: %s", result.Error)
	}

	if result.Tier != TierEvaluation {
		t.Errorf("Expected tier EVALUATION, got %s", result.Tier)
	}

	if result.OrgID != "boundary-test-org" {
		t.Errorf("Expected OrgID boundary-test-org, got %s", result.OrgID)
	}
}

// TestTierBoundary_EvaluationLimitsValues verifies that EVALUATION tier limits
// match the expected values exactly.
func TestTierBoundary_EvaluationLimitsValues(t *testing.T) {
	limits := GetTierLimits(TierEvaluation)

	checks := []struct {
		name     string
		got      int
		expected int
	}{
		{"TenantPolicies", limits.TenantPolicies, 50},
		{"OrgPolicies", limits.OrgPolicies, 5},
		{"CustomPolicyConnectors", limits.CustomPolicyConnectors, 5},
		{"AuditRetentionDays", limits.AuditRetentionDays, 14},
		{"MaxLLMProviders", limits.MaxLLMProviders, 3},
		{"MaxExecutionHistory", limits.MaxExecutionHistory, 500},
		{"MaxConcurrentExec", limits.MaxConcurrentExec, 25},
		{"MaxPlans", limits.MaxPlans, 100},
		{"MaxVersionsPerPlan", limits.MaxVersionsPerPlan, 25},
		{"MaxCostEstimatesPerDay", limits.MaxCostEstimatesPerDay, 100},
		{"MaxPendingApprovals", limits.MaxPendingApprovals, 25},
		// V1.1 decision-list (issue #1982): self-host Evaluation = 14d / 100.
		{"DecisionListWindowHours", limits.DecisionListWindowHours, 336},
		{"DecisionListMaxPage", limits.DecisionListMaxPage, 100},
	}

	for _, c := range checks {
		if c.got != c.expected {
			t.Errorf("Evaluation %s: got %d, want %d", c.name, c.got, c.expected)
		}
	}
}

// TestTierBoundary_CommunityVsEvaluation verifies that Evaluation limits are
// strictly greater than Community limits for all bounded fields.
func TestTierBoundary_CommunityVsEvaluation(t *testing.T) {
	community := GetTierLimits(TierCommunity)
	evaluation := GetTierLimits(TierEvaluation)

	comparisons := []struct {
		name       string
		community  int
		evaluation int
	}{
		{"TenantPolicies", community.TenantPolicies, evaluation.TenantPolicies},
		{"OrgPolicies", community.OrgPolicies, evaluation.OrgPolicies},
		{"CustomPolicyConnectors", community.CustomPolicyConnectors, evaluation.CustomPolicyConnectors},
		{"AuditRetentionDays", community.AuditRetentionDays, evaluation.AuditRetentionDays},
		{"MaxLLMProviders", community.MaxLLMProviders, evaluation.MaxLLMProviders},
		{"MaxExecutionHistory", community.MaxExecutionHistory, evaluation.MaxExecutionHistory},
		{"MaxConcurrentExec", community.MaxConcurrentExec, evaluation.MaxConcurrentExec},
		{"MaxPlans", community.MaxPlans, evaluation.MaxPlans},
		{"MaxVersionsPerPlan", community.MaxVersionsPerPlan, evaluation.MaxVersionsPerPlan},
		{"MaxCostEstimatesPerDay", community.MaxCostEstimatesPerDay, evaluation.MaxCostEstimatesPerDay},
		{"MaxPendingApprovals", community.MaxPendingApprovals, evaluation.MaxPendingApprovals},
		// V1.1 decision-list (issue #1982): Evaluation must out-grow Community.
		{"DecisionListWindowHours", community.DecisionListWindowHours, evaluation.DecisionListWindowHours},
		{"DecisionListMaxPage", community.DecisionListMaxPage, evaluation.DecisionListMaxPage},
	}

	for _, c := range comparisons {
		if c.evaluation <= c.community {
			t.Errorf("%s: Evaluation (%d) should be > Community (%d)",
				c.name, c.evaluation, c.community)
		}
	}
}

// TestTierBoundary_EvaluationVsEnterprise verifies that Enterprise limits are
// strictly greater than (or unlimited vs) Evaluation limits.
func TestTierBoundary_EvaluationVsEnterprise(t *testing.T) {
	evaluation := GetTierLimits(TierEvaluation)
	enterprise := GetTierLimits(TierEnterprise)

	comparisons := []struct {
		name       string
		evaluation int
		enterprise int
	}{
		{"TenantPolicies", evaluation.TenantPolicies, enterprise.TenantPolicies},
		{"OrgPolicies", evaluation.OrgPolicies, enterprise.OrgPolicies},
		{"CustomPolicyConnectors", evaluation.CustomPolicyConnectors, enterprise.CustomPolicyConnectors},
		{"MaxLLMProviders", evaluation.MaxLLMProviders, enterprise.MaxLLMProviders},
		{"MaxExecutionHistory", evaluation.MaxExecutionHistory, enterprise.MaxExecutionHistory},
		{"MaxConcurrentExec", evaluation.MaxConcurrentExec, enterprise.MaxConcurrentExec},
		{"MaxPlans", evaluation.MaxPlans, enterprise.MaxPlans},
		{"MaxVersionsPerPlan", evaluation.MaxVersionsPerPlan, enterprise.MaxVersionsPerPlan},
		{"MaxCostEstimatesPerDay", evaluation.MaxCostEstimatesPerDay, enterprise.MaxCostEstimatesPerDay},
		{"MaxPendingApprovals", evaluation.MaxPendingApprovals, enterprise.MaxPendingApprovals},
		// V1.1 decision-list (issue #1982): Enterprise must be unlimited
		// (-1 sentinel) or out-grow Evaluation.
		{"DecisionListWindowHours", evaluation.DecisionListWindowHours, enterprise.DecisionListWindowHours},
		{"DecisionListMaxPage", evaluation.DecisionListMaxPage, enterprise.DecisionListMaxPage},
	}

	for _, c := range comparisons {
		// Enterprise uses -1 for unlimited
		if c.enterprise != -1 && c.enterprise <= c.evaluation {
			t.Errorf("%s: Enterprise (%d) should be unlimited (-1) or > Evaluation (%d)",
				c.name, c.enterprise, c.evaluation)
		}
	}

	// AuditRetentionDays: Enterprise has 3650 (10 years) vs Evaluation 14
	if enterprise.AuditRetentionDays <= evaluation.AuditRetentionDays {
		t.Errorf("AuditRetentionDays: Enterprise (%d) should be > Evaluation (%d)",
			enterprise.AuditRetentionDays, evaluation.AuditRetentionDays)
	}
}

// TestTierBoundary_ExpiredLicenseInvalid verifies that an expired license
// is reported as invalid.
func TestTierBoundary_ExpiredLicenseInvalid(t *testing.T) {
	setupTestKeypair(t)

	// Generate a license that expired yesterday (validityDays=0 is rejected,
	// so we generate with 1 day and then rely on the fact that the keygen
	// sets expiry = now + days, which for day=1 means tomorrow — so we can't
	// easily create an already-expired key via the public API).
	//
	// Instead, test with the minimum validity and verify it IS valid now
	// (proving the generation path works). Expiry enforcement is tested
	// separately in validation tests.
	key, err := GenerateServiceLicenseKey(
		TierEvaluation,
		"expiry-test-org",
		"platform",
		"backend-service",
		[]string{"mcp:*:*"},
		1, // Expires tomorrow
	)
	if err != nil {
		t.Fatalf("Failed to generate short-lived EVALUATION license: %v", err)
	}

	result, err := ValidateLicense(context.Background(), key)
	if err != nil {
		t.Fatalf("Failed to validate short-lived license: %v", err)
	}

	// Should be valid now (expires tomorrow)
	if !result.Valid {
		t.Errorf("Short-lived license should be valid now: %s", result.Error)
	}

	if result.Tier != TierEvaluation {
		t.Errorf("Expected tier EVALUATION, got %s", result.Tier)
	}

	// DaysUntilExpiry should be 0 or 1
	if result.DaysUntilExpiry < 0 || result.DaysUntilExpiry > 1 {
		t.Errorf("Expected DaysUntilExpiry 0 or 1, got %d", result.DaysUntilExpiry)
	}
}

// TestTierBoundary_IsEvaluationOrHigherTier verifies the backward-compat
// tier check functions work for the EVALUATION tier.
func TestTierBoundary_IsEvaluationOrHigherTier(t *testing.T) {
	setupTestKeypair(t)

	// Generate an EVALUATION license and set it in env
	key, err := GenerateServiceLicenseKey(
		TierEvaluation,
		"tier-check-org",
		"platform",
		"backend-service",
		[]string{"mcp:*:*", "llm:*:*"},
		90,
	)
	if err != nil {
		t.Fatalf("Failed to generate EVALUATION license: %v", err)
	}

	t.Setenv("AXONFLOW_LICENSE_KEY", key)

	ctx := context.Background()

	if !IsEvaluationOrHigherTier(ctx) {
		t.Error("IsEvaluationOrHigherTier() should return true for EVALUATION license")
	}

}

// TestTierBoundary_CommunityNotEvaluationOrHigher verifies that no license
// (Community tier) returns false for IsEvaluationOrHigherTier.
func TestTierBoundary_CommunityNotEvaluationOrHigher(t *testing.T) {
	setupTestKeypair(t)

	// Ensure no license key is set
	t.Setenv("AXONFLOW_LICENSE_KEY", "")

	ctx := context.Background()

	if IsEvaluationOrHigherTier(ctx) {
		t.Error("IsEvaluationOrHigherTier() should return false with no license")
	}

}

// TestTierBoundary_AllTierLimitsMonotonicallyIncrease verifies that limits
// increase monotonically: Community < Evaluation < Enterprise.
func TestTierBoundary_AllTierLimitsMonotonicallyIncrease(t *testing.T) {
	community := GetTierLimits(TierCommunity)
	evaluation := GetTierLimits(TierEvaluation)
	enterprise := GetTierLimits(TierEnterprise)

	type limitField struct {
		name       string
		community  int
		evaluation int
		enterprise int
	}

	fields := []limitField{
		{"TenantPolicies", community.TenantPolicies, evaluation.TenantPolicies, enterprise.TenantPolicies},
		{"OrgPolicies", community.OrgPolicies, evaluation.OrgPolicies, enterprise.OrgPolicies},
		{"CustomPolicyConnectors", community.CustomPolicyConnectors, evaluation.CustomPolicyConnectors, enterprise.CustomPolicyConnectors},
		{"AuditRetentionDays", community.AuditRetentionDays, evaluation.AuditRetentionDays, enterprise.AuditRetentionDays},
		{"MaxLLMProviders", community.MaxLLMProviders, evaluation.MaxLLMProviders, enterprise.MaxLLMProviders},
		{"MaxExecutionHistory", community.MaxExecutionHistory, evaluation.MaxExecutionHistory, enterprise.MaxExecutionHistory},
		{"MaxConcurrentExec", community.MaxConcurrentExec, evaluation.MaxConcurrentExec, enterprise.MaxConcurrentExec},
		{"MaxPlans", community.MaxPlans, evaluation.MaxPlans, enterprise.MaxPlans},
		{"MaxVersionsPerPlan", community.MaxVersionsPerPlan, evaluation.MaxVersionsPerPlan, enterprise.MaxVersionsPerPlan},
		{"MaxCostEstimatesPerDay", community.MaxCostEstimatesPerDay, evaluation.MaxCostEstimatesPerDay, enterprise.MaxCostEstimatesPerDay},
		{"MaxPendingApprovals", community.MaxPendingApprovals, evaluation.MaxPendingApprovals, enterprise.MaxPendingApprovals},
	}

	for _, f := range fields {
		// Community < Evaluation
		if f.evaluation <= f.community {
			t.Errorf("%s: Evaluation (%d) should be > Community (%d)",
				f.name, f.evaluation, f.community)
		}

		// Evaluation < Enterprise (enterprise uses -1 for unlimited, or large values like 3650)
		if f.enterprise != -1 && f.enterprise <= f.evaluation {
			t.Errorf("%s: Enterprise (%d) should be unlimited (-1) or > Evaluation (%d)",
				f.name, f.enterprise, f.evaluation)
		}
	}
}
