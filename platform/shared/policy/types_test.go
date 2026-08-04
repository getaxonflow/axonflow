// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"testing"
)

func TestIsComplianceCategory(t *testing.T) {
	tests := []struct {
		name     string
		category PolicyCategory
		want     bool
	}{
		// Compliance categories - should return true
		{"RBI compliance", CategoryComplianceRBI, true},
		{"SEBI compliance", CategoryComplianceSEBI, true},
		{"EU AI Act compliance", CategoryComplianceEUAIAct, true},
		{"MAS FEAT compliance", CategoryComplianceMASFEAT, true},
		{"GDPR compliance", CategoryComplianceGDPR, true},
		{"HIPAA compliance", CategoryComplianceHIPAA, true},

		// Non-compliance categories - should return false
		{"PII Global", CategoryPIIGlobal, false},
		{"PII US", CategoryPIIUS, false},
		{"PII India", CategoryPIIIndia, false},
		{"PII EU", CategoryPIIEU, false},
		{"PII Singapore", CategoryPIISingapore, false},
		{"Security SQLi", CategorySecuritySQLi, false},
		{"Security Dangerous", CategorySecurityDangerous, false},
		{"Data Exfiltration", CategoryDataExfiltration, false},
		{"Dynamic Rate Limit", CategoryDynamicRateLimit, false},
		{"Unknown category", PolicyCategory("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsComplianceCategory(tt.category)
			if got != tt.want {
				t.Errorf("IsComplianceCategory(%q) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestAllComplianceCategories(t *testing.T) {
	categories := AllComplianceCategories()

	// Should return exactly 6 compliance categories
	expectedCount := 6
	if len(categories) != expectedCount {
		t.Errorf("AllComplianceCategories() returned %d categories, want %d", len(categories), expectedCount)
	}

	// Verify expected categories are present
	expected := map[PolicyCategory]bool{
		CategoryComplianceGDPR:    true,
		CategoryComplianceHIPAA:   true,
		CategoryComplianceRBI:     true,
		CategoryComplianceSEBI:    true,
		CategoryComplianceEUAIAct: true,
		CategoryComplianceMASFEAT: true,
	}

	for _, cat := range categories {
		if !expected[cat] {
			t.Errorf("AllComplianceCategories() contains unexpected category: %q", cat)
		}
		delete(expected, cat)
	}

	// Check no expected categories are missing
	for cat := range expected {
		t.Errorf("AllComplianceCategories() missing expected category: %q", cat)
	}
}

func TestAllComplianceCategoriesAreValidComplianceCategories(t *testing.T) {
	// Every category returned by AllComplianceCategories should pass IsComplianceCategory
	for _, cat := range AllComplianceCategories() {
		if !IsComplianceCategory(cat) {
			t.Errorf("Category %q from AllComplianceCategories() failed IsComplianceCategory check", cat)
		}
	}
}

func TestIsPIIPolicyCategory(t *testing.T) {
	tests := []struct {
		name     string
		category PolicyCategory
		want     bool
	}{
		// PII categories - should return true
		{"PII Global", CategoryPIIGlobal, true},
		{"PII US", CategoryPIIUS, true},
		{"PII India", CategoryPIIIndia, true},
		{"PII EU", CategoryPIIEU, true},
		{"PII Singapore", CategoryPIISingapore, true},
		{"PII Indonesia", CategoryPIIIndonesia, true},

		// Non-PII categories - should return false
		{"Security SQLi", CategorySecuritySQLi, false},
		{"Compliance RBI", CategoryComplianceRBI, false},
		{"Unknown", PolicyCategory("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPIIPolicyCategory(tt.category)
			if got != tt.want {
				t.Errorf("IsPIIPolicyCategory(%q) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

// TestAllTextPIICategories_MatchesConvention keeps the canonical PII list
// (spread into the proxy + openai-compat category whitelists) in lockstep with
// the pii-* convention: every entry must satisfy IsPIIPolicyCategory, the set
// must be distinct, and it must include the jurisdictions that must never drop
// off a whitelist (Singapore + Indonesia — the #2965 omission). If a new pii-*
// category is added to IsPIIPolicyCategory's world but not here, the plane
// whitelists silently stop evaluating it; this test is the drift guard.
func TestAllTextPIICategories_MatchesConvention(t *testing.T) {
	got := AllTextPIICategories()
	seen := make(map[PolicyCategory]bool)
	for _, c := range got {
		if !IsPIIPolicyCategory(c) {
			t.Errorf("AllTextPIICategories contains %q which is not a pii-* category", c)
		}
		if seen[c] {
			t.Errorf("AllTextPIICategories contains duplicate %q", c)
		}
		seen[c] = true
	}
	// The must-be-present set — categories whose omission from a plane whitelist
	// is a silent-allow bug (#2965 was pii-indonesia).
	for _, must := range []PolicyCategory{
		CategoryPIIGlobal, CategoryPIIUS, CategoryPIIIndia,
		CategoryPIIEU, CategoryPIISingapore, CategoryPIIIndonesia,
	} {
		if !seen[must] {
			t.Errorf("AllTextPIICategories is missing %q", must)
		}
	}
}

func TestIsSecurityPolicyCategory(t *testing.T) {
	tests := []struct {
		name     string
		category PolicyCategory
		want     bool
	}{
		// Security categories - should return true
		{"Security SQLi", CategorySecuritySQLi, true},
		{"Security Dangerous", CategorySecurityDangerous, true},

		// Non-security categories - should return false
		// Note: Admin Access is NOT a security category (has its own handling in GetActionForPhase)
		{"Admin Access", CategoryAdminAccess, false},
		{"PII Global", CategoryPIIGlobal, false},
		{"Compliance RBI", CategoryComplianceRBI, false},
		{"Unknown", PolicyCategory("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSecurityPolicyCategory(tt.category)
			if got != tt.want {
				t.Errorf("isSecurityPolicyCategory(%q) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestGetActionForPhase(t *testing.T) {
	tests := []struct {
		name           string
		requestAction  Action
		responseAction Action
		category       PolicyCategory
		severity       Severity
		phase          Phase
		want           Action
	}{
		// Explicit actions take precedence
		{"Request phase with explicit block", ActionBlock, ActionRedact, "", "", PhaseRequest, ActionBlock},
		{"Response phase with explicit redact", ActionBlock, ActionRedact, "", "", PhaseResponse, ActionRedact},

		// Empty actions fall back to category-based logic
		{"PII category defaults to redact", "", "", CategoryPIIGlobal, "", PhaseRequest, ActionRedact},
		{"Security SQLi critical defaults to block", "", "", CategorySecuritySQLi, SeverityCritical, PhaseRequest, ActionBlock},
		{"Security SQLi non-critical defaults to log", "", "", CategorySecuritySQLi, SeverityHigh, PhaseRequest, ActionLog},
		{"Admin access defaults to warn", "", "", CategoryAdminAccess, "", PhaseRequest, ActionWarn},
		{"Compliance category defaults to log", "", "", CategoryComplianceRBI, "", PhaseRequest, ActionLog},
		{"Unknown category defaults to log", "", "", PolicyCategory("unknown"), "", PhaseBoth, ActionLog},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &CompiledPolicy{
				ActionRequest:  tt.requestAction,
				ActionResponse: tt.responseAction,
				Category:       tt.category,
				Severity:       tt.severity,
			}
			got := policy.GetActionForPhase(tt.phase)
			if got != tt.want {
				t.Errorf("GetActionForPhase(%q) = %v, want %v", tt.phase, got, tt.want)
			}
		})
	}
}

func TestValidActionTypes(t *testing.T) {
	if len(ValidActionTypes) == 0 {
		t.Fatal("ValidActionTypes must not be empty")
	}

	mustHave := []string{
		"block", "redact", "log", "warn",
		"alert", "route", "modify_risk", "require_approval",
	}
	for _, want := range mustHave {
		if !IsValidActionType(want) {
			t.Errorf("ValidActionTypes is missing %q", want)
		}
	}

	if IsValidActionType("allow") {
		t.Error("ValidActionTypes must not include 'allow' — it is an implicit default, not a policy action type")
	}
	if IsValidActionType("nonsense") {
		t.Error("IsValidActionType returned true for 'nonsense'")
	}
	if IsValidActionType("") {
		t.Error("IsValidActionType returned true for empty string")
	}

	seen := make(map[string]bool, len(ValidActionTypes))
	for _, a := range ValidActionTypes {
		if seen[a] {
			t.Errorf("duplicate entry in ValidActionTypes: %q", a)
		}
		seen[a] = true
	}
}

func TestValidOverrideActions(t *testing.T) {
	if len(ValidOverrideActions) == 0 {
		t.Fatal("ValidOverrideActions must not be empty")
	}

	mustHave := []string{"block", "require_approval", "redact", "warn", "log"}
	for _, want := range mustHave {
		if !IsValidOverrideAction(want) {
			t.Errorf("ValidOverrideActions is missing %q", want)
		}
	}

	// Authoring-only actions must NOT be in the override list — they have no
	// terminal-action meaning. Adding them would silently widen what overrides
	// can do at the customer-portal boundary while the agent's override
	// repository would still reject them downstream.
	for _, mustReject := range []string{"alert", "route", "modify_risk", "allow"} {
		if IsValidOverrideAction(mustReject) {
			t.Errorf("ValidOverrideActions must NOT include authoring-only action %q", mustReject)
		}
	}

	if IsValidOverrideAction("Block") {
		t.Error("IsValidOverrideAction must be case-sensitive: 'Block' rejected")
	}
	if IsValidOverrideAction(" block") {
		t.Error("IsValidOverrideAction must reject leading whitespace")
	}
	if IsValidOverrideAction("") {
		t.Error("IsValidOverrideAction must reject empty string")
	}

	seen := make(map[string]bool, len(ValidOverrideActions))
	for _, a := range ValidOverrideActions {
		if seen[a] {
			t.Errorf("duplicate entry in ValidOverrideActions: %q", a)
		}
		seen[a] = true
	}
}
