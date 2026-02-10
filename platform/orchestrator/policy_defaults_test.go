// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
	"time"
)

func TestLoadDefaultDynamicPolicies_ReturnsNonEmpty(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	if len(policies) == 0 {
		t.Fatal("loadDefaultDynamicPolicies() returned empty slice")
	}
}

func TestLoadDefaultDynamicPolicies_ExpectedCount(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	if len(policies) < 10 {
		t.Errorf("Expected at least 10 default policies, got %d", len(policies))
	}
}

func TestLoadDefaultDynamicPolicies_UniqueIDs(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	seen := make(map[string]bool)
	for _, p := range policies {
		if seen[p.ID] {
			t.Errorf("Duplicate policy ID: %s", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestLoadDefaultDynamicPolicies_UniqueNames(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	seen := make(map[string]bool)
	for _, p := range policies {
		if seen[p.Name] {
			t.Errorf("Duplicate policy name: %s", p.Name)
		}
		seen[p.Name] = true
	}
}

func TestLoadDefaultDynamicPolicies_AllEnabled(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if !p.Enabled {
			t.Errorf("Default policy %q (ID: %s) is not enabled", p.Name, p.ID)
		}
	}
}

func TestLoadDefaultDynamicPolicies_AllHaveConditions(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if len(p.Conditions) == 0 {
			t.Errorf("Default policy %q (ID: %s) has no conditions", p.Name, p.ID)
		}
	}
}

func TestLoadDefaultDynamicPolicies_AllHaveActions(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if len(p.Actions) == 0 {
			t.Errorf("Default policy %q (ID: %s) has no actions", p.Name, p.ID)
		}
	}
}

func TestLoadDefaultDynamicPolicies_ValidTypes(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	validTypes := map[string]bool{
		"content": true,
		"user":    true,
		"risk":    true,
		"cost":    true,
	}

	for _, p := range policies {
		if !validTypes[p.Type] {
			t.Errorf("Default policy %q (ID: %s) has invalid type %q", p.Name, p.ID, p.Type)
		}
	}
}

func TestLoadDefaultDynamicPolicies_PositivePriorities(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if p.Priority <= 0 {
			t.Errorf("Default policy %q (ID: %s) has non-positive priority %d", p.Name, p.ID, p.Priority)
		}
	}
}

func TestLoadDefaultDynamicPolicies_TimestampsSet(t *testing.T) {
	before := time.Now().Add(-1 * time.Second)
	policies := loadDefaultDynamicPolicies()
	after := time.Now().Add(1 * time.Second)

	for _, p := range policies {
		if p.CreatedAt.Before(before) || p.CreatedAt.After(after) {
			t.Errorf("Default policy %q CreatedAt %v is not within expected range", p.Name, p.CreatedAt)
		}
		if p.UpdatedAt.Before(before) || p.UpdatedAt.After(after) {
			t.Errorf("Default policy %q UpdatedAt %v is not within expected range", p.Name, p.UpdatedAt)
		}
	}
}

func TestLoadDefaultDynamicPolicies_IDsHavePrefix(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if p.ID == "" {
			t.Errorf("Default policy %q has empty ID", p.Name)
			continue
		}
		if len(p.ID) < 4 || p.ID[:4] != "pol_" {
			t.Errorf("Default policy %q ID %q does not start with 'pol_' prefix", p.Name, p.ID)
		}
	}
}

func TestLoadDefaultDynamicPolicies_ValidActionTypes(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	validActionTypes := map[string]bool{
		"block":       true,
		"redact":      true,
		"alert":       true,
		"log":         true,
		"route":       true,
		"modify_risk": true,
	}

	for _, p := range policies {
		for _, action := range p.Actions {
			if !validActionTypes[action.Type] {
				t.Errorf("Default policy %q action type %q is not valid", p.Name, action.Type)
			}
		}
	}
}

func TestLoadDefaultDynamicPolicies_ValidConditionOperators(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	validOperators := map[string]bool{
		"equals":       true,
		"not_equals":   true,
		"contains":     true,
		"not_contains": true,
		"contains_any": true,
		"regex":        true,
		"greater_than": true,
		"less_than":    true,
		"in":           true,
		"not_in":       true,
	}

	for _, p := range policies {
		for _, cond := range p.Conditions {
			if !validOperators[cond.Operator] {
				t.Errorf("Default policy %q condition operator %q is not valid", p.Name, cond.Operator)
			}
		}
	}
}

func TestLoadDefaultDynamicPolicies_ConditionsHaveFields(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		for i, cond := range p.Conditions {
			if cond.Field == "" {
				t.Errorf("Default policy %q condition[%d] has empty field", p.Name, i)
			}
		}
	}
}

func TestLoadDefaultDynamicPolicies_ConditionsHaveValues(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		for i, cond := range p.Conditions {
			if cond.Value == nil {
				t.Errorf("Default policy %q condition[%d] has nil value", p.Name, i)
			}
		}
	}
}

func TestLoadDefaultDynamicPolicies_SpecificPoliciesExist(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	policyIDs := make(map[string]bool)
	for _, p := range policies {
		policyIDs[p.ID] = true
	}

	expectedIDs := []string{
		"pol_high_risk_block",
		"pol_sensitive_data_control",
		"pol_hipaa_compliance",
		"pol_financial_data_protection",
		"pol_expensive_query_limit",
		"pol_gdpr_compliance",
		"pol_anomaly_detection",
		"pol_tenant_isolation",
		"pol_llm_cost_optimization",
		"pol_debug_mode_restriction",
	}

	for _, id := range expectedIDs {
		if !policyIDs[id] {
			t.Errorf("Expected default policy with ID %q not found", id)
		}
	}
}

func TestLoadDefaultDynamicPolicies_HighRiskBlock(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	var found *DynamicPolicy
	for i := range policies {
		if policies[i].ID == "pol_high_risk_block" {
			found = &policies[i]
			break
		}
	}

	if found == nil {
		t.Fatal("pol_high_risk_block not found")
	}

	if found.Type != "risk" {
		t.Errorf("Expected type 'risk', got %q", found.Type)
	}
	if found.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", found.Priority)
	}

	// Should have block and alert actions
	actionTypes := make(map[string]bool)
	for _, a := range found.Actions {
		actionTypes[a.Type] = true
	}
	if !actionTypes["block"] {
		t.Error("Expected 'block' action")
	}
	if !actionTypes["alert"] {
		t.Error("Expected 'alert' action")
	}
}

func TestLoadDefaultDynamicPolicies_TenantIsolation(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	var found *DynamicPolicy
	for i := range policies {
		if policies[i].ID == "pol_tenant_isolation" {
			found = &policies[i]
			break
		}
	}

	if found == nil {
		t.Fatal("pol_tenant_isolation not found")
	}

	if found.Type != "user" {
		t.Errorf("Expected type 'user', got %q", found.Type)
	}
	if found.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", found.Priority)
	}

	// Should have block action (security-critical)
	hasBlock := false
	for _, a := range found.Actions {
		if a.Type == "block" {
			hasBlock = true
			break
		}
	}
	if !hasBlock {
		t.Error("Tenant isolation policy should have 'block' action")
	}
}

func TestLoadDefaultDynamicPolicies_NoEmptyDescriptions(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if p.Description == "" {
			t.Errorf("Default policy %q (ID: %s) has empty description", p.Name, p.ID)
		}
	}
}

func TestLoadDefaultDynamicPolicies_NoEmptyNames(t *testing.T) {
	policies := loadDefaultDynamicPolicies()
	for _, p := range policies {
		if p.Name == "" {
			t.Errorf("Default policy with ID %q has empty name", p.ID)
		}
	}
}
