// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
)

func TestValidTemplateCategories_NotEmpty(t *testing.T) {
	if len(ValidTemplateCategories) == 0 {
		t.Fatal("ValidTemplateCategories should not be empty")
	}
}

func TestValidTemplateCategories_ContainsExpected(t *testing.T) {
	expected := []string{
		"general",
		"security",
		"compliance",
		"content_safety",
		"rate_limiting",
		"access_control",
		"data_protection",
		"custom",
	}

	for _, exp := range expected {
		found := false
		for _, cat := range ValidTemplateCategories {
			if cat == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ValidTemplateCategories should contain %q", exp)
		}
	}
}

func TestValidTemplateCategories_NoDuplicates(t *testing.T) {
	seen := make(map[string]bool)
	for _, cat := range ValidTemplateCategories {
		if seen[cat] {
			t.Errorf("Duplicate template category: %q", cat)
		}
		seen[cat] = true
	}
}

func TestValidTemplateCategories_NoEmptyStrings(t *testing.T) {
	for i, cat := range ValidTemplateCategories {
		if cat == "" {
			t.Errorf("ValidTemplateCategories[%d] is an empty string", i)
		}
	}
}

func TestValidTemplateCategories_IncludesCustom(t *testing.T) {
	// "custom" must always be present to allow user-defined categories
	found := false
	for _, cat := range ValidTemplateCategories {
		if cat == "custom" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ValidTemplateCategories must include 'custom' for user-defined categories")
	}
}

func TestPolicyTemplate_Struct(t *testing.T) {
	tmpl := PolicyTemplate{
		ID:          "tmpl-1",
		Name:        "test-template",
		DisplayName: "Test Template",
		Description: "A test template",
		Category:    "security",
		IsBuiltin:   true,
		IsActive:    true,
		Version:     "1.0.0",
		Tags:        []string{"security", "pii"},
	}

	if tmpl.ID != "tmpl-1" {
		t.Errorf("Expected ID 'tmpl-1', got %q", tmpl.ID)
	}
	if tmpl.Category != "security" {
		t.Errorf("Expected Category 'security', got %q", tmpl.Category)
	}
	if !tmpl.IsBuiltin {
		t.Error("Expected IsBuiltin to be true")
	}
	if !tmpl.IsActive {
		t.Error("Expected IsActive to be true")
	}
}

func TestTemplateVariable_Struct(t *testing.T) {
	v := TemplateVariable{
		Name:        "threshold",
		Type:        "number",
		Default:     0.8,
		Description: "Risk threshold",
		Required:    true,
		Validation:  `^\d+\.?\d*$`,
	}

	if v.Name != "threshold" {
		t.Errorf("Expected Name 'threshold', got %q", v.Name)
	}
	if v.Type != "number" {
		t.Errorf("Expected Type 'number', got %q", v.Type)
	}
	if !v.Required {
		t.Error("Expected Required to be true")
	}
}

func TestApplyTemplateRequest_Struct(t *testing.T) {
	priority := 50
	req := ApplyTemplateRequest{
		Variables: map[string]interface{}{
			"threshold": 0.9,
			"fields":    []string{"ssn", "email"},
		},
		PolicyName:  "Custom PII Policy",
		Description: "Generated from template",
		Enabled:     true,
		Priority:    &priority,
	}

	if req.PolicyName != "Custom PII Policy" {
		t.Errorf("Expected PolicyName 'Custom PII Policy', got %q", req.PolicyName)
	}
	if len(req.Variables) != 2 {
		t.Errorf("Expected 2 variables, got %d", len(req.Variables))
	}
	if req.Priority == nil || *req.Priority != 50 {
		t.Errorf("Expected Priority 50, got %v", req.Priority)
	}
}

func TestApplyTemplateResponse_Struct(t *testing.T) {
	resp := ApplyTemplateResponse{
		Success: true,
		Policy: &PolicyResource{
			ID:   "pol-123",
			Name: "Generated Policy",
		},
		UsageID: "usage-1",
		Message: "Policy created successfully",
	}

	if !resp.Success {
		t.Error("Expected Success to be true")
	}
	if resp.Policy == nil {
		t.Fatal("Expected Policy to be non-nil")
	}
	if resp.Policy.ID != "pol-123" {
		t.Errorf("Expected Policy ID 'pol-123', got %q", resp.Policy.ID)
	}
}

func TestTemplatePaginationMeta_Struct(t *testing.T) {
	pm := TemplatePaginationMeta{
		Page:       2,
		PageSize:   10,
		TotalItems: 45,
		TotalPages: 5,
	}

	if pm.Page != 2 {
		t.Errorf("Expected Page 2, got %d", pm.Page)
	}
	if pm.TotalPages != 5 {
		t.Errorf("Expected TotalPages 5, got %d", pm.TotalPages)
	}
}

func TestListTemplatesParams_ZeroValues(t *testing.T) {
	params := ListTemplatesParams{}
	if params.Category != "" {
		t.Errorf("Expected empty Category, got %q", params.Category)
	}
	if params.Active != nil {
		t.Errorf("Expected nil Active, got %v", params.Active)
	}
	if params.Builtin != nil {
		t.Errorf("Expected nil Builtin, got %v", params.Builtin)
	}
}
