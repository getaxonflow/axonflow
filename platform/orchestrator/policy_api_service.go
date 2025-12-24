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

package orchestrator

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PolicyService handles business logic for policy operations
type PolicyService struct {
	repo           *PolicyRepository
	policyEngine   *DynamicPolicyEngine
	licenseChecker LicenseChecker
}

// NewPolicyService creates a new policy service with environment-based license checker.
func NewPolicyService(repo *PolicyRepository, engine *DynamicPolicyEngine) *PolicyService {
	return &PolicyService{
		repo:           repo,
		policyEngine:   engine,
		licenseChecker: NewEnvLicenseChecker(),
	}
}

// NewPolicyServiceWithLicense creates a policy service with a custom license checker.
func NewPolicyServiceWithLicense(repo *PolicyRepository, engine *DynamicPolicyEngine, lc LicenseChecker) *PolicyService {
	return &PolicyService{
		repo:           repo,
		policyEngine:   engine,
		licenseChecker: lc,
	}
}

// CreatePolicy validates and creates a new policy
func (s *PolicyService) CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error) {
	// Validate request
	if err := s.validateCreateRequest(req); err != nil {
		return nil, err
	}

	// Tier validation
	if err := s.validateTierForCreate(ctx, tenantID, req); err != nil {
		return nil, err
	}

	// Default to tenant tier if not specified
	tier := req.Tier
	if tier == "" {
		tier = TierTenant
	}

	policy := &PolicyResource{
		Name:        req.Name,
		Description: req.Description,
		Type:        string(req.Type),
		Category:    req.Category,
		Tier:        tier,
		Conditions:  req.Conditions,
		Actions:     req.Actions,
		Priority:    req.Priority,
		Enabled:     req.Enabled,
		TenantID:    tenantID,
		Tags:        req.Tags,
		CreatedBy:   createdBy,
		UpdatedBy:   createdBy,
	}

	if err := s.repo.Create(ctx, policy); err != nil {
		return nil, fmt.Errorf("failed to create policy: %w", err)
	}

	return policy, nil
}

// GetPolicy retrieves a policy by ID
func (s *PolicyService) GetPolicy(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
	return s.repo.GetByID(ctx, tenantID, policyID)
}

// ListPolicies retrieves policies with filtering
func (s *PolicyService) ListPolicies(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
	policies, total, err := s.repo.List(ctx, tenantID, params)
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

	return &PoliciesListResponse{
		Policies: policies,
		Pagination: PaginationMeta{
			Page:       params.Page,
			PageSize:   params.PageSize,
			TotalItems: total,
			TotalPages: totalPages,
		},
	}, nil
}

// UpdatePolicy validates and updates an existing policy
func (s *PolicyService) UpdatePolicy(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
	// Validate request
	if err := s.validateUpdateRequest(req); err != nil {
		return nil, err
	}

	// Tier validation: system tier policies cannot be modified
	if err := s.validateTierForModify(ctx, tenantID, policyID); err != nil {
		return nil, err
	}

	return s.repo.Update(ctx, tenantID, policyID, req, updatedBy)
}

// DeletePolicy removes a policy
func (s *PolicyService) DeletePolicy(ctx context.Context, tenantID, policyID string, deletedBy string) error {
	// Tier validation: system tier policies cannot be deleted
	if err := s.validateTierForModify(ctx, tenantID, policyID); err != nil {
		return err
	}

	return s.repo.Delete(ctx, tenantID, policyID, deletedBy)
}

// TestPolicy evaluates a policy against test input
func (s *PolicyService) TestPolicy(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
	// Get the policy
	policy, err := s.repo.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("policy not found")
	}

	start := time.Now()

	// Evaluate conditions
	matched := s.evaluateConditions(policy.Conditions, req)

	response := &TestPolicyResponse{
		Matched:    matched,
		EvalTimeMs: float64(time.Since(start).Microseconds()) / 1000,
	}

	if matched {
		// Determine which actions would trigger
		for _, action := range policy.Actions {
			triggered := TriggeredAction{
				Type:   action.Type,
				Config: action.Config,
			}

			if action.Type == "block" {
				response.Blocked = true
				if msg, ok := action.Config["message"].(string); ok {
					triggered.Message = msg
				}
			}

			response.Actions = append(response.Actions, triggered)
		}

		response.Explanation = fmt.Sprintf("Policy '%s' matched: all %d conditions evaluated to true",
			policy.Name, len(policy.Conditions))
	} else {
		response.Explanation = fmt.Sprintf("Policy '%s' did not match: one or more conditions evaluated to false",
			policy.Name)
	}

	return response, nil
}

// GetPolicyVersions retrieves version history
func (s *PolicyService) GetPolicyVersions(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
	versions, err := s.repo.GetVersions(ctx, tenantID, policyID)
	if err != nil {
		return nil, err
	}

	return &PolicyVersionResponse{Versions: versions}, nil
}

// ExportPolicies exports all policies for a tenant
func (s *PolicyService) ExportPolicies(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
	policies, err := s.repo.ExportAll(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &ExportPoliciesResponse{
		Policies:   policies,
		ExportedAt: time.Now(),
		TenantID:   tenantID,
	}, nil
}

// ImportPolicies imports multiple policies
func (s *PolicyService) ImportPolicies(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error) {
	// Validate all policies first
	for i, p := range req.Policies {
		if err := s.validateCreateRequest(&p); err != nil {
			return nil, fmt.Errorf("policy %d validation failed: %w", i, err)
		}
	}

	mode := req.OverwriteMode
	if mode == "" {
		mode = "skip"
	}

	return s.repo.ImportBulk(ctx, tenantID, req.Policies, mode, importedBy)
}

// validateCreateRequest validates a create policy request
func (s *PolicyService) validateCreateRequest(req *CreatePolicyRequest) error {
	var errors []PolicyFieldError

	if req.Name == "" || len(req.Name) < 3 || len(req.Name) > 100 {
		errors = append(errors, PolicyFieldError{
			Field:   "name",
			Message: "Name must be between 3 and 100 characters",
		})
	}

	if len(req.Description) > 500 {
		errors = append(errors, PolicyFieldError{
			Field:   "description",
			Message: "Description must not exceed 500 characters",
		})
	}

	if req.Type == "" {
		errors = append(errors, PolicyFieldError{
			Field:   "type",
			Message: "Type is required",
		})
	} else if !s.isValidPolicyType(string(req.Type)) {
		errors = append(errors, PolicyFieldError{
			Field:   "type",
			Message: "Type must be one of: content, user, risk, cost",
		})
	}

	if len(req.Conditions) == 0 {
		errors = append(errors, PolicyFieldError{
			Field:   "conditions",
			Message: "At least one condition is required",
		})
	} else {
		for i, cond := range req.Conditions {
			if condErr := s.validateCondition(cond); condErr != nil {
				errors = append(errors, PolicyFieldError{
					Field:   fmt.Sprintf("conditions[%d]", i),
					Message: condErr.Error(),
				})
			}
		}
	}

	if len(req.Actions) == 0 {
		errors = append(errors, PolicyFieldError{
			Field:   "actions",
			Message: "At least one action is required",
		})
	} else {
		for i, action := range req.Actions {
			if actionErr := s.validateAction(action); actionErr != nil {
				errors = append(errors, PolicyFieldError{
					Field:   fmt.Sprintf("actions[%d]", i),
					Message: actionErr.Error(),
				})
			}
		}
	}

	if req.Priority < 0 || req.Priority > 1000 {
		errors = append(errors, PolicyFieldError{
			Field:   "priority",
			Message: "Priority must be between 0 and 1000",
		})
	}

	if len(errors) > 0 {
		return &ValidationError{Errors: errors}
	}

	return nil
}

// validateUpdateRequest validates an update policy request
func (s *PolicyService) validateUpdateRequest(req *UpdatePolicyRequest) error {
	var errors []PolicyFieldError

	if req.Name != nil && (len(*req.Name) < 3 || len(*req.Name) > 100) {
		errors = append(errors, PolicyFieldError{
			Field:   "name",
			Message: "Name must be between 3 and 100 characters",
		})
	}

	if req.Description != nil && len(*req.Description) > 500 {
		errors = append(errors, PolicyFieldError{
			Field:   "description",
			Message: "Description must not exceed 500 characters",
		})
	}

	if req.Type != nil && !s.isValidPolicyType(string(*req.Type)) {
		errors = append(errors, PolicyFieldError{
			Field:   "type",
			Message: "Type must be one of: content, user, risk, cost",
		})
	}

	if req.Conditions != nil {
		for i, cond := range req.Conditions {
			if condErr := s.validateCondition(cond); condErr != nil {
				errors = append(errors, PolicyFieldError{
					Field:   fmt.Sprintf("conditions[%d]", i),
					Message: condErr.Error(),
				})
			}
		}
	}

	if req.Actions != nil {
		for i, action := range req.Actions {
			if actionErr := s.validateAction(action); actionErr != nil {
				errors = append(errors, PolicyFieldError{
					Field:   fmt.Sprintf("actions[%d]", i),
					Message: actionErr.Error(),
				})
			}
		}
	}

	if req.Priority != nil && (*req.Priority < 0 || *req.Priority > 1000) {
		errors = append(errors, PolicyFieldError{
			Field:   "priority",
			Message: "Priority must be between 0 and 1000",
		})
	}

	if len(errors) > 0 {
		return &ValidationError{Errors: errors}
	}

	return nil
}

// isValidPolicyType checks if the policy type is valid
func (s *PolicyService) isValidPolicyType(t string) bool {
	for _, valid := range ValidPolicyTypes {
		if t == valid {
			return true
		}
	}
	return false
}

// validateCondition validates a single condition
func (s *PolicyService) validateCondition(cond PolicyCondition) error {
	if cond.Field == "" {
		return fmt.Errorf("field is required")
	}

	if cond.Operator == "" {
		return fmt.Errorf("operator is required")
	}

	// Validate operator
	validOp := false
	for _, op := range ValidPolicyOperators {
		if cond.Operator == op {
			validOp = true
			break
		}
	}
	if !validOp {
		return fmt.Errorf("invalid operator: %s", cond.Operator)
	}

	// Validate regex if operator is regex
	if cond.Operator == "regex" {
		if str, ok := cond.Value.(string); ok {
			if _, err := regexp.Compile(str); err != nil {
				return fmt.Errorf("invalid regex pattern: %v", err)
			}
		}
	}

	return nil
}

// validateAction validates a single action
func (s *PolicyService) validateAction(action PolicyAction) error {
	valid := false
	for _, validType := range ValidActionTypes {
		if action.Type == validType {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("invalid action type: %s", action.Type)
	}

	return nil
}

// evaluateConditions evaluates all conditions against the test request
func (s *PolicyService) evaluateConditions(conditions []PolicyCondition, req *TestPolicyRequest) bool {
	for _, cond := range conditions {
		if !s.evaluateCondition(cond, req) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (s *PolicyService) evaluateCondition(cond PolicyCondition, req *TestPolicyRequest) bool {
	var fieldValue interface{}

	// Get the field value from the request
	switch {
	case cond.Field == "query":
		fieldValue = req.Query
	case cond.Field == "request_type":
		fieldValue = req.RequestType
	case strings.HasPrefix(cond.Field, "user."):
		userField := strings.TrimPrefix(cond.Field, "user.")
		if req.User != nil {
			fieldValue = req.User[userField]
		}
	case strings.HasPrefix(cond.Field, "context."):
		contextField := strings.TrimPrefix(cond.Field, "context.")
		if req.Context != nil {
			fieldValue = req.Context[contextField]
		}
	default:
		return false
	}

	// Evaluate the condition
	return s.evaluateOperator(cond.Operator, fieldValue, cond.Value)
}

// evaluateOperator applies the operator to compare values
func (s *PolicyService) evaluateOperator(operator string, fieldValue, conditionValue interface{}) bool {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	condStr := fmt.Sprintf("%v", conditionValue)

	switch operator {
	case "equals":
		return fieldStr == condStr
	case "not_equals":
		return fieldStr != condStr
	case "contains":
		return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(condStr))
	case "not_contains":
		return !strings.Contains(strings.ToLower(fieldStr), strings.ToLower(condStr))
	case "contains_any":
		if values, ok := conditionValue.([]interface{}); ok {
			for _, v := range values {
				if strings.Contains(strings.ToLower(fieldStr), strings.ToLower(fmt.Sprintf("%v", v))) {
					return true
				}
			}
		}
		return false
	case "regex":
		if pattern, ok := conditionValue.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(fieldStr)
		}
		return false
	case "in":
		if values, ok := conditionValue.([]interface{}); ok {
			for _, v := range values {
				if fieldStr == fmt.Sprintf("%v", v) {
					return true
				}
			}
		}
		return false
	case "not_in":
		if values, ok := conditionValue.([]interface{}); ok {
			for _, v := range values {
				if fieldStr == fmt.Sprintf("%v", v) {
					return false
				}
			}
		}
		return true
	default:
		return false
	}
}

// ValidationError represents validation failures
type ValidationError struct {
	Errors []PolicyFieldError
}

func (e *ValidationError) Error() string {
	var msgs []string
	for _, err := range e.Errors {
		msgs = append(msgs, fmt.Sprintf("%s: %s", err.Field, err.Message))
	}
	return strings.Join(msgs, "; ")
}

// validateTierForCreate validates tier constraints for policy creation.
func (s *PolicyService) validateTierForCreate(ctx context.Context, tenantID string, req *CreatePolicyRequest) error {
	tier := req.Tier
	if tier == "" {
		tier = TierTenant
	}

	// System tier cannot be created via API
	if tier == TierSystem {
		return NewTierValidationError("System policies cannot be created via API", ErrCodeSystemTierImmutable)
	}

	// Organization tier requires Enterprise license
	if tier == TierOrganization && !s.licenseChecker.IsEnterprise() {
		return NewTierValidationError("Organization-tier policies require Enterprise license", ErrCodeOrgTierEnterprise)
	}

	// Tenant tier: check policy limit for Community edition
	if tier == TierTenant && !s.licenseChecker.IsEnterprise() {
		count, err := s.repo.CountByTenant(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to count policies: %w", err)
		}
		if count >= CommunityPolicyLimit {
			return NewTierValidationError(
				fmt.Sprintf("Policy limit of %d reached for Community edition", CommunityPolicyLimit),
				ErrCodePolicyLimitExceeded,
			)
		}
	}

	return nil
}

// validateTierForModify validates that a policy can be modified (updated or deleted).
// System tier policies are immutable and cannot be modified via API.
func (s *PolicyService) validateTierForModify(ctx context.Context, tenantID, policyID string) error {
	policy, err := s.repo.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil // Let the actual operation handle not found
	}

	if policy.Tier == TierSystem {
		return NewTierValidationError("System policies cannot be modified via API", ErrCodeSystemTierImmutable)
	}

	return nil
}
