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
	"log"
	"regexp"
	"strings"
	"time"

	"axonflow/platform/agent/license"
)

// PolicyEngineRefresher is an interface for policy engines that can refresh their cache.
// This allows the PolicyService to trigger an immediate refresh after policy changes
// without waiting for the background refresh cycle (default 30 seconds).
// Issue #1082: Used by WCP HITL integration for immediate policy availability.
type PolicyEngineRefresher interface {
	RefreshPolicies() error
}

// PolicyService handles business logic for policy operations
type PolicyService struct {
	repo            *PolicyRepository
	policyEngine    *DynamicPolicyEngine
	policyRefresher PolicyEngineRefresher // Interface for triggering policy refresh
	licenseChecker  LicenseChecker
}

// NewPolicyService creates a new policy service with environment-based license checker.
func NewPolicyService(repo *PolicyRepository, engine *DynamicPolicyEngine) *PolicyService {
	return &PolicyService{
		repo:           repo,
		policyEngine:   engine,
		licenseChecker: NewEnvLicenseChecker(),
	}
}

// NewPolicyServiceWithRefresher creates a new policy service with a policy refresher.
// The refresher allows triggering immediate policy cache refresh after changes.
// Issue #1082: Used for WCP HITL integration.
func NewPolicyServiceWithRefresher(repo *PolicyRepository, refresher PolicyEngineRefresher) *PolicyService {
	return &PolicyService{
		repo:            repo,
		policyRefresher: refresher,
		licenseChecker:  NewEnvLicenseChecker(),
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

// refreshPolicyCache triggers an immediate policy cache refresh if a refresher is configured.
// This ensures newly created/updated/deleted policies are available immediately.
func (s *PolicyService) refreshPolicyCache() {
	if s.policyRefresher != nil {
		if err := s.policyRefresher.RefreshPolicies(); err != nil {
			log.Printf("[PolicyService] Failed to refresh policy cache: %v", err)
		} else {
			log.Println("[PolicyService] Policy cache refreshed successfully")
		}
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

	// Trigger immediate policy cache refresh so the new policy is available
	// Issue #1082: Required for WCP HITL integration
	s.refreshPolicyCache()

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

	// Issue #1673: retry-aware step.* conditions require Evaluation tier on
	// every mutation path, not just create. Without this check a Community
	// tenant could create a benign policy, then PATCH its conditions to
	// retry-aware fields. UpdatePolicyRequest.Conditions is optional — if
	// nil the caller isn't changing conditions and there's nothing to
	// re-gate. Runs BEFORE validateTierForModify so a quick reject path
	// doesn't roundtrip to the DB just to return a tier error.
	if len(req.Conditions) > 0 {
		if err := s.validateRetryAwareTier(req.Conditions); err != nil {
			return nil, err
		}
	}

	// Tier validation: system tier policies cannot be modified (except system media policies)
	if err := s.validateTierForModify(ctx, tenantID, policyID); err != nil {
		return nil, err
	}

	// Additional field-level validation for system media policies
	existing, err := s.repo.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy for validation: %w", err)
	}
	if existing != nil && existing.Tier == TierSystem && isMediaPolicyCategory(existing.Category) {
		if err := s.validateSystemMediaPolicyUpdate(existing, req); err != nil {
			return nil, err
		}
	}

	policy, err := s.repo.Update(ctx, tenantID, policyID, req, updatedBy)
	if err != nil {
		return nil, err
	}

	// Trigger immediate policy cache refresh so the updated policy is available
	// Issue #1082: Required for WCP HITL integration
	s.refreshPolicyCache()

	return policy, nil
}

// DeletePolicy removes a policy
func (s *PolicyService) DeletePolicy(ctx context.Context, tenantID, policyID string, deletedBy string) error {
	// System policies (including system media policies) cannot be deleted
	existing, err := s.repo.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if existing != nil && existing.Tier == TierSystem {
		return NewTierValidationError("System policies cannot be deleted", ErrCodeSystemTierImmutable)
	}

	if err := s.repo.Delete(ctx, tenantID, policyID, deletedBy); err != nil {
		return err
	}

	// Trigger immediate policy cache refresh so the deleted policy is removed
	// Issue #1082: Required for WCP HITL integration
	s.refreshPolicyCache()

	return nil
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
		// Issue #1673: retry-aware step.* conditions require Evaluation tier
		// on the import path too, not just direct create. Reject the whole
		// import if any policy in the batch has retry-aware fields on a
		// non-Evaluation-or-higher license.
		if err := s.validateRetryAwareTier(p.Conditions); err != nil {
			return nil, fmt.Errorf("policy %d: %w", i, err)
		}
	}

	// Check tier limits before import to prevent bulk import from bypassing limits
	if len(req.Policies) > 0 {
		licenseTier := s.licenseChecker.Tier()

		// Count how many new org-tier and tenant-tier policies are being imported
		var newOrgCount, newTenantCount int
		for _, p := range req.Policies {
			if p.Tier == TierSystem {
				return nil, NewTierValidationError("System policies cannot be created via API", ErrCodeSystemTierImmutable)
			}
			if p.Tier == TierOrganization {
				newOrgCount++
			} else {
				newTenantCount++
			}
		}

		// Organization tier requires Evaluation or higher license
		if newOrgCount > 0 && !license.IsEvaluationOrHigher(licenseTier) {
			return nil, NewTierValidationError(
				"Organization-tier policies require Evaluation or Enterprise license. "+
					"Get a free Evaluation license at https://getaxonflow.com/evaluation-license",
				ErrCodeOrgTierEvaluationOrHigher,
			)
		}

		// For Evaluation tier, enforce org policy limit
		if newOrgCount > 0 && licenseTier == license.TierEvaluation {
			existingOrgCount, err := s.repo.CountOrgPolicies(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to count organization policies: %w", err)
			}
			limit := s.licenseChecker.OrgPolicyLimit()
			if existingOrgCount+newOrgCount > limit {
				return nil, NewTierValidationError(
					fmt.Sprintf("Import would exceed organization policy limit of %d for Evaluation tier (current: %d, importing: %d). "+
						"Upgrade to Enterprise for unlimited policies at https://getaxonflow.com/enterprise", limit, existingOrgCount, newOrgCount),
					ErrCodeOrgPolicyLimitExceeded,
				)
			}
		}

		// Tenant tier: check policy limit for non-paid tiers
		if newTenantCount > 0 && !license.IsPaidTier(licenseTier) {
			existingTenantCount, err := s.repo.CountByTenant(ctx, tenantID)
			if err != nil {
				return nil, fmt.Errorf("failed to count policies: %w", err)
			}
			limit := s.licenseChecker.PolicyLimit()
			if existingTenantCount+newTenantCount > limit {
				var upgradeMsg string
				if licenseTier == license.TierCommunity {
					upgradeMsg = "Get a free Evaluation license for 50 policies at https://getaxonflow.com/evaluation-license"
				} else {
					upgradeMsg = "Upgrade to Enterprise for unlimited policies at https://getaxonflow.com/enterprise"
				}
				return nil, NewTierValidationError(
					fmt.Sprintf("Import would exceed policy limit of %d for %s tier (current: %d, importing: %d). %s",
						limit, licenseTier, existingTenantCount, newTenantCount, upgradeMsg),
					ErrCodePolicyLimitExceeded,
				)
			}
		}
	}

	mode := req.OverwriteMode
	if mode == "" {
		mode = "skip"
	}

	result, err := s.repo.ImportBulk(ctx, tenantID, req.Policies, mode, importedBy)
	if err != nil {
		return nil, err
	}

	// Trigger immediate policy cache refresh so imported policies are available
	// Issue #1082: Required for WCP HITL integration
	s.refreshPolicyCache()

	return result, nil
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
			Message: "Type must be one of: content, user, risk, cost, context_aware, media, rate-limit, budget, time-access, role-access, mcp, connector",
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
			Message: "Type must be one of: content, user, risk, cost, context_aware, media, rate-limit, budget, time-access, role-access, mcp, connector",
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
		// For fields like "step_input.recipient_count" or "tool_input.query",
		// look them up directly in the context map (WCPPolicyAdapter stores them
		// with dotted keys like "step_input.recipient_count" in OrchestratorRequest.Context).
		if req.Context != nil {
			fieldValue = req.Context[cond.Field]
		}
		if fieldValue == nil {
			return false
		}
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

	licenseTier := s.licenseChecker.Tier()

	// System tier cannot be created via API
	if tier == TierSystem {
		return NewTierValidationError("System policies cannot be created via API", ErrCodeSystemTierImmutable)
	}

	// Organization tier requires Evaluation or Enterprise license
	if tier == TierOrganization {
		if !license.IsEvaluationOrHigher(licenseTier) {
			return NewTierValidationError(
				"Organization-tier policies require Evaluation or Enterprise license. "+
					"Get a free Evaluation license at https://getaxonflow.com/evaluation-license",
				ErrCodeOrgTierEvaluationOrHigher,
			)
		}

		// For Evaluation tier, enforce org policy limit
		if licenseTier == license.TierEvaluation {
			count, err := s.repo.CountOrgPolicies(ctx)
			if err != nil {
				return fmt.Errorf("failed to count organization policies: %w", err)
			}
			limit := s.licenseChecker.OrgPolicyLimit()
			if count >= limit {
				return NewTierValidationError(
					fmt.Sprintf("Organization policy limit of %d reached for Evaluation tier. "+
						"Upgrade to Enterprise for unlimited policies at https://getaxonflow.com/enterprise", limit),
					ErrCodeOrgPolicyLimitExceeded,
				)
			}
		}
	}

	// Issue #1673: retry-aware step.* condition fields are an Evaluation-tier
	// capability per the edition split. Reject at create time so the edition
	// table maps to enforceable code, not just documentation. Checked BEFORE
	// the tenant policy-count query so Community users attempting a retry-aware
	// policy see the right error immediately without the count roundtrip.
	if err := s.validateRetryAwareTier(req.Conditions); err != nil {
		return err
	}

	// Tenant tier: check policy limit for non-paid tiers
	if tier == TierTenant && !license.IsPaidTier(licenseTier) {
		count, err := s.repo.CountByTenant(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("failed to count policies: %w", err)
		}
		limit := s.licenseChecker.PolicyLimit()
		if count >= limit {
			var upgradeMsg string
			if licenseTier == license.TierCommunity {
				upgradeMsg = "Get a free Evaluation license for 50 policies at https://getaxonflow.com/evaluation-license"
			} else {
				upgradeMsg = "Upgrade to Enterprise for unlimited policies at https://getaxonflow.com/enterprise"
			}
			return NewTierValidationError(
				fmt.Sprintf("Policy limit of %d reached for %s tier. %s", limit, licenseTier, upgradeMsg),
				ErrCodePolicyLimitExceeded,
			)
		}
	}

	return nil
}

// firstRetryAwareField returns the first step.* condition field in the
// given slice, or "" if none. Retry-aware fields (step.gate_count,
// step.completion_count, step.prior_completion_status, etc.) are the
// Phase 1 + Phase 2 additions from Issue #1673; policies using any of
// them require Evaluation tier or higher. Shared by create, update,
// and import paths so the edition boundary cannot be bypassed via a
// different entry point.
func firstRetryAwareField(conditions []PolicyCondition) string {
	for _, c := range conditions {
		if strings.HasPrefix(c.Field, "step.") {
			return c.Field
		}
	}
	return ""
}

// retryAwareTierError returns the standard TierValidationError for a
// retry-aware policy condition on a non-Evaluation-or-higher license.
// Used by every code path that accepts policy conditions (create,
// update, import) so the error message stays consistent.
func retryAwareTierError(field string) error {
	return NewTierValidationError(
		fmt.Sprintf("Retry-aware policy condition %q requires Evaluation or Enterprise license. "+
			"Get a free Evaluation license at https://getaxonflow.com/evaluation-license", field),
		ErrCodeFeatureRequiresEvaluation,
	)
}

// validateRetryAwareTier enforces the Evaluation-tier gate for retry-aware
// step.* condition fields across every policy-mutation entry point. Call
// this before writing any policy with caller-supplied conditions.
func (s *PolicyService) validateRetryAwareTier(conditions []PolicyCondition) error {
	if license.IsEvaluationOrHigher(s.licenseChecker.Tier()) {
		return nil
	}
	if field := firstRetryAwareField(conditions); field != "" {
		return retryAwareTierError(field)
	}
	return nil
}

// isMediaPolicyCategory returns true if the category is a media governance category.
func isMediaPolicyCategory(category string) bool {
	switch DynamicPolicyCategory(category) {
	case CategoryMediaSafety, CategoryMediaBiometric, CategoryMediaDocument, CategoryMediaPII:
		return true
	}
	return false
}

// validateTierForModify validates that a policy can be modified (updated or deleted).
// System tier policies are generally immutable, except for system media policies
// which support tiered modification per issue #1222.
func (s *PolicyService) validateTierForModify(ctx context.Context, tenantID, policyID string) error {
	policy, err := s.repo.GetByID(ctx, tenantID, policyID)
	if err != nil {
		return fmt.Errorf("failed to get policy: %w", err)
	}
	if policy == nil {
		return nil // Let the actual operation handle not found
	}

	if policy.Tier == TierSystem {
		// System media policies allow tiered modification (toggle enabled, Enterprise: actions/priority)
		if isMediaPolicyCategory(policy.Category) {
			return nil // Allowed — field-level restrictions enforced in UpdatePolicy
		}
		return NewTierValidationError("System policies cannot be modified via API", ErrCodeSystemTierImmutable)
	}

	return nil
}

// validateSystemMediaPolicyUpdate enforces field-level restrictions on system media policy updates.
// All tiers: toggle enabled only. Enterprise: also modify actions and priority.
// No tier can modify conditions, name, description, or type on system media policies.
func (s *PolicyService) validateSystemMediaPolicyUpdate(policy *PolicyResource, req *UpdatePolicyRequest) error {
	isEnterprise := license.IsPaidTier(s.licenseChecker.Tier())

	if req.Conditions != nil {
		return NewTierValidationError("Conditions on system media policies cannot be modified", ErrCodeSystemTierImmutable)
	}
	if req.Name != nil {
		return NewTierValidationError("Name on system media policies cannot be modified", ErrCodeSystemTierImmutable)
	}
	if req.Description != nil {
		return NewTierValidationError("Description on system media policies cannot be modified", ErrCodeSystemTierImmutable)
	}
	if req.Type != nil {
		return NewTierValidationError("Type on system media policies cannot be modified", ErrCodeSystemTierImmutable)
	}
	if req.Category != nil {
		return NewTierValidationError("Category on system media policies cannot be modified", ErrCodeSystemTierImmutable)
	}
	if req.Actions != nil && !isEnterprise {
		return NewTierValidationError(
			"Modifying system media policy actions requires Enterprise license. "+
				"Upgrade at https://getaxonflow.com/enterprise",
			"ENTERPRISE_REQUIRED",
		)
	}
	if req.Priority != nil && !isEnterprise {
		return NewTierValidationError(
			"Modifying system media policy priority requires Enterprise license. "+
				"Upgrade at https://getaxonflow.com/enterprise",
			"ENTERPRISE_REQUIRED",
		)
	}

	return nil
}
