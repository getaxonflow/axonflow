// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

func TestStaticPolicyCategories(t *testing.T) {
	categories := StaticPolicyCategories()

	expected := []PolicyCategory{
		CategorySecuritySQLi,
		CategorySecurityAdmin,
		CategoryPIIGlobal,
		CategoryPIIUS,
		CategoryPIIEU,
		CategoryPIIIndia,
		CategoryCodeSecrets,
		CategoryCodeUnsafe,
		CategoryCodeCompliance,
	}

	if len(categories) != len(expected) {
		t.Errorf("StaticPolicyCategories() returned %d categories, expected %d", len(categories), len(expected))
	}

	for i, cat := range expected {
		if categories[i] != cat {
			t.Errorf("StaticPolicyCategories()[%d] = %s, expected %s", i, categories[i], cat)
		}
	}
}

func TestDynamicPolicyCategories(t *testing.T) {
	categories := DynamicPolicyCategories()

	expected := []PolicyCategory{
		CategoryDynamicRisk,
		CategoryDynamicCompliance,
		CategoryDynamicSecurity,
		CategoryDynamicCost,
		CategoryDynamicAccess,
	}

	if len(categories) != len(expected) {
		t.Errorf("DynamicPolicyCategories() returned %d categories, expected %d", len(categories), len(expected))
	}

	for i, cat := range expected {
		if categories[i] != cat {
			t.Errorf("DynamicPolicyCategories()[%d] = %s, expected %s", i, categories[i], cat)
		}
	}
}

func TestAllPolicyCategories(t *testing.T) {
	all := AllPolicyCategories()
	static := StaticPolicyCategories()
	dynamic := DynamicPolicyCategories()

	expectedLen := len(static) + len(dynamic)
	if len(all) != expectedLen {
		t.Errorf("AllPolicyCategories() returned %d categories, expected %d", len(all), expectedLen)
	}
}

func TestIsValidStaticCategory(t *testing.T) {
	tests := []struct {
		name     string
		category PolicyCategory
		want     bool
	}{
		{"security-sqli is valid", CategorySecuritySQLi, true},
		{"security-admin is valid", CategorySecurityAdmin, true},
		{"pii-global is valid", CategoryPIIGlobal, true},
		{"pii-us is valid", CategoryPIIUS, true},
		{"pii-eu is valid", CategoryPIIEU, true},
		{"pii-india is valid", CategoryPIIIndia, true},
		{"code-secrets is valid", CategoryCodeSecrets, true},
		{"code-unsafe is valid", CategoryCodeUnsafe, true},
		{"code-compliance is valid", CategoryCodeCompliance, true},
		{"dynamic-risk is invalid for static", CategoryDynamicRisk, false},
		{"empty is invalid", PolicyCategory(""), false},
		{"unknown is invalid", PolicyCategory("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidStaticCategory(tt.category); got != tt.want {
				t.Errorf("IsValidStaticCategory(%s) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestIsValidDynamicCategory(t *testing.T) {
	tests := []struct {
		name     string
		category PolicyCategory
		want     bool
	}{
		{"dynamic-risk is valid", CategoryDynamicRisk, true},
		{"dynamic-compliance is valid", CategoryDynamicCompliance, true},
		{"dynamic-security is valid", CategoryDynamicSecurity, true},
		{"dynamic-cost is valid", CategoryDynamicCost, true},
		{"dynamic-access is valid", CategoryDynamicAccess, true},
		{"security-sqli is invalid for dynamic", CategorySecuritySQLi, false},
		{"empty is invalid", PolicyCategory(""), false},
		{"unknown is invalid", PolicyCategory("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidDynamicCategory(tt.category); got != tt.want {
				t.Errorf("IsValidDynamicCategory(%s) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestAllPolicyTiers(t *testing.T) {
	tiers := AllPolicyTiers()

	expected := []PolicyTier{TierSystem, TierOrganization, TierTenant}

	if len(tiers) != len(expected) {
		t.Errorf("AllPolicyTiers() returned %d tiers, expected %d", len(tiers), len(expected))
	}

	for i, tier := range expected {
		if tiers[i] != tier {
			t.Errorf("AllPolicyTiers()[%d] = %s, expected %s", i, tiers[i], tier)
		}
	}
}

func TestIsValidTier(t *testing.T) {
	tests := []struct {
		name string
		tier PolicyTier
		want bool
	}{
		{"system is valid", TierSystem, true},
		{"organization is valid", TierOrganization, true},
		{"tenant is valid", TierTenant, true},
		{"empty is invalid", PolicyTier(""), false},
		{"unknown is invalid", PolicyTier("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidTier(tt.tier); got != tt.want {
				t.Errorf("IsValidTier(%s) = %v, want %v", tt.tier, got, tt.want)
			}
		})
	}
}

func TestAllOverrideActions(t *testing.T) {
	actions := AllOverrideActions()

	expected := []OverrideAction{ActionBlock, ActionRequireApproval, ActionRedact, ActionWarn, ActionLog}

	if len(actions) != len(expected) {
		t.Errorf("AllOverrideActions() returned %d actions, expected %d", len(actions), len(expected))
	}

	for i, action := range expected {
		if actions[i] != action {
			t.Errorf("AllOverrideActions()[%d] = %s, expected %s", i, actions[i], action)
		}
	}
}

func TestIsValidOverrideAction(t *testing.T) {
	tests := []struct {
		name   string
		action OverrideAction
		want   bool
	}{
		{"block is valid", ActionBlock, true},
		{"require_approval is valid", ActionRequireApproval, true},
		{"redact is valid", ActionRedact, true},
		{"warn is valid", ActionWarn, true},
		{"log is valid", ActionLog, true},
		{"empty is invalid", OverrideAction(""), false},
		{"unknown is invalid", OverrideAction("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidOverrideAction(tt.action); got != tt.want {
				t.Errorf("IsValidOverrideAction(%s) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestActionRestrictiveness(t *testing.T) {
	tests := []struct {
		name   string
		action OverrideAction
		want   int
	}{
		{"block has highest restrictiveness", ActionBlock, 5},
		{"require_approval has high restrictiveness", ActionRequireApproval, 4},
		{"redact has medium-high restrictiveness", ActionRedact, 3},
		{"warn has medium restrictiveness", ActionWarn, 2},
		{"log has lowest restrictiveness", ActionLog, 1},
		{"unknown has zero restrictiveness", OverrideAction("unknown"), 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ActionRestrictiveness(tt.action); got != tt.want {
				t.Errorf("ActionRestrictiveness(%s) = %d, want %d", tt.action, got, tt.want)
			}
		})
	}
}

func TestIsMoreRestrictive(t *testing.T) {
	tests := []struct {
		name       string
		newAction  OverrideAction
		baseAction OverrideAction
		want       bool
	}{
		{"block is more restrictive than require_approval", ActionBlock, ActionRequireApproval, true},
		{"block is more restrictive than warn", ActionBlock, ActionWarn, true},
		{"block is more restrictive than redact", ActionBlock, ActionRedact, true},
		{"block is more restrictive than require_approval", ActionBlock, ActionRequireApproval, true},
		{"block is more restrictive than log", ActionBlock, ActionLog, true},
		{"require_approval is more restrictive than redact", ActionRequireApproval, ActionRedact, true},
		{"require_approval is more restrictive than warn", ActionRequireApproval, ActionWarn, true},
		{"require_approval is more restrictive than log", ActionRequireApproval, ActionLog, true},
		{"redact is more restrictive than warn", ActionRedact, ActionWarn, true},
		{"redact is more restrictive than log", ActionRedact, ActionLog, true},
		{"warn is more restrictive than log", ActionWarn, ActionLog, true},
		{"block is equally restrictive as block", ActionBlock, ActionBlock, true},
		{"require_approval is equally restrictive as require_approval", ActionRequireApproval, ActionRequireApproval, true},
		{"redact is equally restrictive as redact", ActionRedact, ActionRedact, true},
		{"require_approval is not more restrictive than block", ActionRequireApproval, ActionBlock, false},
		{"warn is not more restrictive than block", ActionWarn, ActionBlock, false},
		{"require_approval is not more restrictive than block", ActionRequireApproval, ActionBlock, false},
		{"redact is not more restrictive than block", ActionRedact, ActionBlock, false},
		{"warn is not more restrictive than require_approval", ActionWarn, ActionRequireApproval, false},
		{"redact is not more restrictive than require_approval", ActionRedact, ActionRequireApproval, false},
		{"warn is not more restrictive than redact", ActionWarn, ActionRedact, false},
		{"log is not more restrictive than block", ActionLog, ActionBlock, false},
		{"log is not more restrictive than require_approval", ActionLog, ActionRequireApproval, false},
		{"log is not more restrictive than warn", ActionLog, ActionWarn, false},
		{"log is not more restrictive than redact", ActionLog, ActionRedact, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsMoreRestrictive(tt.newAction, tt.baseAction); got != tt.want {
				t.Errorf("IsMoreRestrictive(%s, %s) = %v, want %v", tt.newAction, tt.baseAction, got, tt.want)
			}
		})
	}
}

func TestAllSeverities(t *testing.T) {
	severities := AllSeverities()

	expected := []PolicySeverity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

	if len(severities) != len(expected) {
		t.Errorf("AllSeverities() returned %d severities, expected %d", len(severities), len(expected))
	}

	for i, sev := range expected {
		if severities[i] != sev {
			t.Errorf("AllSeverities()[%d] = %s, expected %s", i, severities[i], sev)
		}
	}
}

func TestIsValidSeverity(t *testing.T) {
	tests := []struct {
		name     string
		severity PolicySeverity
		want     bool
	}{
		{"critical is valid", SeverityCritical, true},
		{"high is valid", SeverityHigh, true},
		{"medium is valid", SeverityMedium, true},
		{"low is valid", SeverityLow, true},
		{"empty is invalid", PolicySeverity(""), false},
		{"unknown is invalid", PolicySeverity("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidSeverity(tt.severity); got != tt.want {
				t.Errorf("IsValidSeverity(%s) = %v, want %v", tt.severity, got, tt.want)
			}
		})
	}
}

func TestCategoryConstants(t *testing.T) {
	// Verify category string values match expected format
	tests := []struct {
		category PolicyCategory
		expected string
	}{
		{CategorySecuritySQLi, "security-sqli"},
		{CategorySecurityAdmin, "security-admin"},
		{CategoryPIIGlobal, "pii-global"},
		{CategoryPIIUS, "pii-us"},
		{CategoryPIIEU, "pii-eu"},
		{CategoryPIIIndia, "pii-india"},
		{CategoryCodeSecrets, "code-secrets"},
		{CategoryCodeUnsafe, "code-unsafe"},
		{CategoryCodeCompliance, "code-compliance"},
		{CategoryDynamicRisk, "dynamic-risk"},
		{CategoryDynamicCompliance, "dynamic-compliance"},
		{CategoryDynamicSecurity, "dynamic-security"},
		{CategoryDynamicCost, "dynamic-cost"},
		{CategoryDynamicAccess, "dynamic-access"},
	}

	for _, tt := range tests {
		if string(tt.category) != tt.expected {
			t.Errorf("Category %s has value %s, expected %s", tt.expected, string(tt.category), tt.expected)
		}
	}
}

func TestTierConstants(t *testing.T) {
	// Verify tier string values match expected format
	tests := []struct {
		tier     PolicyTier
		expected string
	}{
		{TierSystem, "system"},
		{TierOrganization, "organization"},
		{TierTenant, "tenant"},
	}

	for _, tt := range tests {
		if string(tt.tier) != tt.expected {
			t.Errorf("Tier %s has value %s, expected %s", tt.expected, string(tt.tier), tt.expected)
		}
	}
}

func TestOverrideActionConstants(t *testing.T) {
	// Verify action string values match expected format
	tests := []struct {
		action   OverrideAction
		expected string
	}{
		{ActionBlock, "block"},
		{ActionRequireApproval, "require_approval"},
		{ActionRedact, "redact"},
		{ActionWarn, "warn"},
		{ActionLog, "log"},
	}

	for _, tt := range tests {
		if string(tt.action) != tt.expected {
			t.Errorf("Action %s has value %s, expected %s", tt.expected, string(tt.action), tt.expected)
		}
	}
}

func TestPolicyTypeConstants(t *testing.T) {
	// Verify policy type string values
	if TypeStatic != "static" {
		t.Errorf("TypeStatic = %s, expected static", TypeStatic)
	}
	if TypeDynamic != "dynamic" {
		t.Errorf("TypeDynamic = %s, expected dynamic", TypeDynamic)
	}
}
