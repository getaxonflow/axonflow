// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

func TestValidPolicyTypes_NotEmpty(t *testing.T) {
	if len(ValidPolicyTypes) == 0 {
		t.Fatal("ValidPolicyTypes should not be empty")
	}
}

func TestValidPolicyTypes_ContainsStandardTypes(t *testing.T) {
	expected := []string{"content", "user", "risk", "cost"}
	for _, exp := range expected {
		found := false
		for _, vt := range ValidPolicyTypes {
			if vt == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidPolicyTypes should contain %q", exp)
		}
	}
}

func TestValidPolicyTypes_ContainsMCPTypes(t *testing.T) {
	expected := []string{"rate-limit", "budget", "time-access", "role-access", "mcp", "connector"}
	for _, exp := range expected {
		found := false
		for _, vt := range ValidPolicyTypes {
			if vt == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidPolicyTypes should contain MCP type %q", exp)
		}
	}
}

func TestValidPolicyTypes_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, vt := range ValidPolicyTypes {
		if seen[vt] {
			t.Errorf("Duplicate policy type: %q", vt)
		}
		seen[vt] = true
	}
}

func TestValidPolicyTypes_NoEmptyStrings(t *testing.T) {
	for i, vt := range ValidPolicyTypes {
		if vt == "" {
			t.Errorf("ValidPolicyTypes[%d] is an empty string", i)
		}
	}
}

func TestValidPolicyOperators_NotEmpty(t *testing.T) {
	if len(ValidPolicyOperators) == 0 {
		t.Fatal("ValidPolicyOperators should not be empty")
	}
}

func TestValidPolicyOperators_ContainsExpected(t *testing.T) {
	expected := []string{
		"equals", "not_equals",
		"contains", "not_contains", "contains_any",
		"regex",
		"greater_than", "less_than",
		"in", "not_in",
	}
	for _, exp := range expected {
		found := false
		for _, op := range ValidPolicyOperators {
			if op == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidPolicyOperators should contain %q", exp)
		}
	}
}

func TestValidPolicyOperators_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, op := range ValidPolicyOperators {
		if seen[op] {
			t.Errorf("Duplicate operator: %q", op)
		}
		seen[op] = true
	}
}

func TestValidPolicyFields_NotEmpty(t *testing.T) {
	if len(ValidPolicyFields) == 0 {
		t.Fatal("ValidPolicyFields should not be empty")
	}
}

func TestValidPolicyFields_ContainsExpected(t *testing.T) {
	expected := []string{
		"query", "response",
		"user.email", "user.role", "user.department", "user.tenant_id",
		"risk_score", "request_type",
		"connector", "cost_estimate",
	}
	for _, exp := range expected {
		found := false
		for _, field := range ValidPolicyFields {
			if field == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidPolicyFields should contain %q", exp)
		}
	}
}

func TestValidPolicyFields_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, field := range ValidPolicyFields {
		if seen[field] {
			t.Errorf("Duplicate field: %q", field)
		}
		seen[field] = true
	}
}

func TestValidActionTypes_NotEmpty(t *testing.T) {
	if len(ValidActionTypes) == 0 {
		t.Fatal("ValidActionTypes should not be empty")
	}
}

func TestValidActionTypes_ContainsExpected(t *testing.T) {
	// Includes "warn" since the policy engine emits it (shared/policy/types.go),
	// and the customer-portal override validator now mirrors this list.
	expected := []string{"block", "redact", "alert", "log", "route", "modify_risk", "require_approval", "warn"}
	for _, exp := range expected {
		found := false
		for _, at := range ValidActionTypes {
			if at == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidActionTypes should contain %q", exp)
		}
	}
}

func TestValidActionTypes_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, at := range ValidActionTypes {
		if seen[at] {
			t.Errorf("Duplicate action type: %q", at)
		}
		seen[at] = true
	}
}

func TestValidActionTypes_IncludesRequireApproval(t *testing.T) {
	// Issue #1082: require_approval must be present for WCP HITL integration
	found := false
	for _, at := range ValidActionTypes {
		if at == "require_approval" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidActionTypes must include 'require_approval' for WCP HITL integration (Issue #1082)")
	}
}

func TestPolicyTierConstants(t *testing.T) {
	tests := []struct {
		name     string
		tier     PolicyTier
		expected string
	}{
		{"system tier", TierSystem, "system"},
		{"organization tier", TierOrganization, "organization"},
		{"tenant tier", TierTenant, "tenant"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.tier) != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, string(tt.tier))
			}
		})
	}
}

func TestDynamicPolicyCategoryConstants(t *testing.T) {
	tests := []struct {
		name     string
		category DynamicPolicyCategory
		expected string
	}{
		{"risk", CategoryDynamicRisk, "dynamic-risk"},
		{"compliance", CategoryDynamicCompliance, "dynamic-compliance"},
		{"security", CategoryDynamicSecurity, "dynamic-security"},
		{"cost", CategoryDynamicCost, "dynamic-cost"},
		{"access", CategoryDynamicAccess, "dynamic-access"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.category) != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, string(tt.category))
			}
		})
	}
}

func TestDynamicPolicyCategoryConstants_AllHavePrefix(t *testing.T) {
	categories := []DynamicPolicyCategory{
		CategoryDynamicRisk,
		CategoryDynamicCompliance,
		CategoryDynamicSecurity,
		CategoryDynamicCost,
		CategoryDynamicAccess,
	}

	for _, cat := range categories {
		if len(cat) < 8 || cat[:8] != "dynamic-" {
			t.Errorf("Category %q should have 'dynamic-' prefix", cat)
		}
	}
}

func TestPolicyResourceStruct_JSONTags(t *testing.T) {
	// Verify PolicyResource can be instantiated with required fields
	pr := PolicyResource{
		ID:       "test-id",
		Name:     "test-policy",
		Type:     "content",
		Tier:     TierTenant,
		Priority: 100,
		Enabled:  true,
		Version:  1,
		TenantID: "tenant-1",
	}

	if pr.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got %q", pr.ID)
	}
	if pr.Name != "test-policy" {
		t.Errorf("Expected Name 'test-policy', got %q", pr.Name)
	}
	if pr.Tier != TierTenant {
		t.Errorf("Expected Tier TierTenant, got %q", pr.Tier)
	}
}

func TestCreatePolicyRequest_Struct(t *testing.T) {
	req := CreatePolicyRequest{
		Name:        "New Policy",
		Description: "A new policy",
		Type:        "content",
		Tier:        TierTenant,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "test"},
		},
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{"level": "info"}},
		},
		Priority: 50,
		Enabled:  true,
		Tags:     []string{"test"},
	}

	if req.Name != "New Policy" {
		t.Errorf("Expected Name 'New Policy', got %q", req.Name)
	}
	if len(req.Conditions) != 1 {
		t.Errorf("Expected 1 condition, got %d", len(req.Conditions))
	}
	if len(req.Actions) != 1 {
		t.Errorf("Expected 1 action, got %d", len(req.Actions))
	}
}

func TestPaginationMeta_Struct(t *testing.T) {
	pm := PaginationMeta{
		Page:       1,
		PageSize:   20,
		TotalItems: 100,
		TotalPages: 5,
	}

	if pm.Page != 1 {
		t.Errorf("Expected Page 1, got %d", pm.Page)
	}
	if pm.TotalPages != 5 {
		t.Errorf("Expected TotalPages 5, got %d", pm.TotalPages)
	}
}

func TestListPoliciesParams_Defaults(t *testing.T) {
	// Zero-value should be usable
	params := ListPoliciesParams{}
	if params.Page != 0 {
		t.Errorf("Expected zero-value Page 0, got %d", params.Page)
	}
	if params.Tier != nil {
		t.Errorf("Expected nil Tier, got %v", params.Tier)
	}
	if params.Enabled != nil {
		t.Errorf("Expected nil Enabled, got %v", params.Enabled)
	}
	if params.IncludeDeleted {
		t.Error("Expected IncludeDeleted to be false by default")
	}
}

func TestImportPoliciesRequest_Struct(t *testing.T) {
	req := ImportPoliciesRequest{
		Policies: []CreatePolicyRequest{
			{Name: "Policy 1", Type: "content"},
			{Name: "Policy 2", Type: "risk"},
		},
		OverwriteMode: "skip",
	}

	if len(req.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(req.Policies))
	}
	if req.OverwriteMode != "skip" {
		t.Errorf("Expected OverwriteMode 'skip', got %q", req.OverwriteMode)
	}
}
