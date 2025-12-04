// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// TemplateService handles business logic for template operations
type TemplateService struct {
	templateRepo *TemplateRepository
	policyRepo   *PolicyRepository
}

// NewTemplateService creates a new template service
func NewTemplateService(templateRepo *TemplateRepository, policyRepo *PolicyRepository) *TemplateService {
	return &TemplateService{
		templateRepo: templateRepo,
		policyRepo:   policyRepo,
	}
}

// GetTemplate retrieves a template by ID
func (s *TemplateService) GetTemplate(ctx context.Context, templateID string) (*PolicyTemplate, error) {
	return s.templateRepo.GetByID(ctx, templateID)
}

// ListTemplates retrieves templates with filtering
func (s *TemplateService) ListTemplates(ctx context.Context, params ListTemplatesParams) (*TemplatesListResponse, error) {
	templates, total, err := s.templateRepo.List(ctx, params)
	if err != nil {
		return nil, err
	}

	if params.PageSize < 1 {
		params.PageSize = 20
	}
	if params.Page < 1 {
		params.Page = 1
	}

	totalPages := (total + params.PageSize - 1) / params.PageSize

	return &TemplatesListResponse{
		Templates: templates,
		Pagination: TemplatePaginationMeta{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: total,
			TotalPages: totalPages,
		},
	}, nil
}

// ApplyTemplate creates a new policy from a template with variable substitution
func (s *TemplateService) ApplyTemplate(ctx context.Context, tenantID, templateID string, req *ApplyTemplateRequest, appliedBy string) (*ApplyTemplateResponse, error) {
	// Get the template
	template, err := s.templateRepo.GetByID(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}
	if template == nil {
		return nil, fmt.Errorf("template not found")
	}

	// Validate request
	if err := s.validateApplyRequest(template, req); err != nil {
		return nil, err
	}

	// Substitute variables in the template
	processedTemplate, err := s.substituteVariables(template.Template, template.Variables, req.Variables)
	if err != nil {
		return nil, fmt.Errorf("failed to substitute variables: %w", err)
	}

	// Extract policy fields from the processed template
	policyType, conditions, actions, priority, err := s.extractPolicyFields(processedTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to extract policy fields: %w", err)
	}

	// Use priority from request if provided, otherwise from template
	if req.Priority != nil {
		priority = *req.Priority
	}

	// Create the policy
	policyReq := &CreatePolicyRequest{
		Name:        req.PolicyName,
		Description: req.Description,
		Type:        policyType,
		Conditions:  conditions,
		Actions:     actions,
		Priority:    priority,
		Enabled:     req.Enabled,
	}

	policy := &PolicyResource{
		Name:        policyReq.Name,
		Description: policyReq.Description,
		Type:        policyReq.Type,
		Conditions:  policyReq.Conditions,
		Actions:     policyReq.Actions,
		Priority:    policyReq.Priority,
		Enabled:     policyReq.Enabled,
		TenantID:    tenantID,
		CreatedBy:   appliedBy,
		UpdatedBy:   appliedBy,
	}

	if err := s.policyRepo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create policy from template: %w", err)
	}

	// Record template usage
	usage := &PolicyTemplateUsage{
		TemplateID: templateID,
		TenantID:   tenantID,
		PolicyID:   policy.ID,
	}
	if err := s.templateRepo.RecordUsage(ctx, usage); err != nil {
		// Log but don't fail - usage tracking is not critical
		fmt.Printf("Warning: failed to record template usage: %v\n", err)
	}

	return &ApplyTemplateResponse{
		Success: true,
		Policy:  policy,
		UsageID: usage.ID,
		Message: fmt.Sprintf("Successfully created policy '%s' from template '%s'", policy.Name, template.Name),
	}, nil
}

// validateApplyRequest validates the apply template request
func (s *TemplateService) validateApplyRequest(template *PolicyTemplate, req *ApplyTemplateRequest) error {
	var errors []TemplateFieldError

	if req.PolicyName == "" || len(req.PolicyName) < 3 || len(req.PolicyName) > 100 {
		errors = append(errors, TemplateFieldError{
			Field:   "policy_name",
			Message: "Policy name must be between 3 and 100 characters",
		})
	}

	if len(req.Description) > 500 {
		errors = append(errors, TemplateFieldError{
			Field:   "description",
			Message: "Description must not exceed 500 characters",
		})
	}

	// Validate required variables
	for _, v := range template.Variables {
		if v.Required {
			if _, exists := req.Variables[v.Name]; !exists {
				errors = append(errors, TemplateFieldError{
					Field:   fmt.Sprintf("variables.%s", v.Name),
					Message: fmt.Sprintf("Required variable '%s' is missing", v.Name),
				})
			}
		}
	}

	// Validate variable types and patterns
	for _, v := range template.Variables {
		if value, exists := req.Variables[v.Name]; exists {
			if v.Validation != "" {
				// Validate against regex pattern
				if strValue, ok := value.(string); ok {
					re, err := regexp.Compile(v.Validation)
					if err == nil && !re.MatchString(strValue) {
						errors = append(errors, TemplateFieldError{
							Field:   fmt.Sprintf("variables.%s", v.Name),
							Message: fmt.Sprintf("Variable '%s' does not match required pattern", v.Name),
						})
					}
				}
			}
		}
	}

	if len(errors) > 0 {
		return &TemplateValidationError{Errors: errors}
	}

	return nil
}

// substituteVariables replaces variable placeholders with actual values
func (s *TemplateService) substituteVariables(template map[string]interface{}, varDefs []TemplateVariable, values map[string]interface{}) (map[string]interface{}, error) {
	// Build a map of variable defaults
	defaults := make(map[string]interface{})
	for _, v := range varDefs {
		if v.Default != nil {
			defaults[v.Name] = v.Default
		}
	}

	// Merge defaults with provided values (provided values take precedence)
	finalValues := make(map[string]interface{})
	for k, v := range defaults {
		finalValues[k] = v
	}
	for k, v := range values {
		finalValues[k] = v
	}

	// Deep copy and substitute
	result, err := s.deepSubstitute(template, finalValues)
	if err != nil {
		return nil, err
	}

	return result.(map[string]interface{}), nil
}

// deepSubstitute recursively substitutes variables in the structure
func (s *TemplateService) deepSubstitute(value interface{}, variables map[string]interface{}) (interface{}, error) {
	switch v := value.(type) {
	case string:
		return s.substituteString(v, variables), nil
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, val := range v {
			substituted, err := s.deepSubstitute(val, variables)
			if err != nil {
				return nil, err
			}
			result[key] = substituted
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, val := range v {
			substituted, err := s.deepSubstitute(val, variables)
			if err != nil {
				return nil, err
			}
			result[i] = substituted
		}
		return result, nil
	default:
		return value, nil
	}
}

// substituteString replaces {{variable}} placeholders in a string
func (s *TemplateService) substituteString(str string, variables map[string]interface{}) interface{} {
	// Pattern for {{variable_name}}
	re := regexp.MustCompile(`\{\{(\w+)\}\}`)

	// Check if the entire string is a single variable reference
	matches := re.FindAllStringSubmatchIndex(str, -1)
	if len(matches) == 1 && matches[0][0] == 0 && matches[0][1] == len(str) {
		// Entire string is a single variable - return the value directly (preserving type)
		varName := str[2 : len(str)-2]
		if value, exists := variables[varName]; exists {
			return value
		}
		return str
	}

	// Multiple variables or partial matches - do string substitution
	result := re.ReplaceAllStringFunc(str, func(match string) string {
		varName := match[2 : len(match)-2]
		if value, exists := variables[varName]; exists {
			return fmt.Sprintf("%v", value)
		}
		return match
	})

	return result
}

// extractPolicyFields extracts policy-specific fields from the processed template
func (s *TemplateService) extractPolicyFields(template map[string]interface{}) (string, []PolicyCondition, []PolicyAction, int, error) {
	var policyType string
	var conditions []PolicyCondition
	var actions []PolicyAction
	var priority int

	// Extract type
	if t, ok := template["type"].(string); ok {
		policyType = t
	} else {
		policyType = "content" // Default
	}

	// Extract priority
	switch p := template["priority"].(type) {
	case float64:
		priority = int(p)
	case int:
		priority = p
	default:
		priority = 50 // Default priority
	}

	// Extract conditions
	if conds, ok := template["conditions"].([]interface{}); ok {
		for _, c := range conds {
			if condMap, ok := c.(map[string]interface{}); ok {
				condition := PolicyCondition{
					Field:    getStringFromMap(condMap, "field"),
					Operator: getStringFromMap(condMap, "operator"),
					Value:    condMap["value"],
				}
				conditions = append(conditions, condition)
			}
		}
	}

	// Extract actions
	if acts, ok := template["actions"].([]interface{}); ok {
		for _, a := range acts {
			if actMap, ok := a.(map[string]interface{}); ok {
				action := PolicyAction{
					Type: getStringFromMap(actMap, "type"),
				}
				if config, ok := actMap["config"].(map[string]interface{}); ok {
					action.Config = config
				}
				actions = append(actions, action)
			}
		}
	}

	if len(conditions) == 0 {
		return "", nil, nil, 0, fmt.Errorf("template must define at least one condition")
	}

	if len(actions) == 0 {
		return "", nil, nil, 0, fmt.Errorf("template must define at least one action")
	}

	return policyType, conditions, actions, priority, nil
}

// GetCategories retrieves all unique template categories
func (s *TemplateService) GetCategories(ctx context.Context) ([]string, error) {
	return s.templateRepo.GetCategories(ctx)
}

// GetUsageStats retrieves usage statistics for templates
func (s *TemplateService) GetUsageStats(ctx context.Context, tenantID string) ([]TemplateUsageStatsResponse, error) {
	return s.templateRepo.GetUsageStats(ctx, tenantID)
}

// getStringFromMap safely gets a string from a map[string]interface{}
func getStringFromMap(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// TemplateValidationError represents validation failures
type TemplateValidationError struct {
	Errors []TemplateFieldError
}

func (e *TemplateValidationError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(msgs, "; ")
}
