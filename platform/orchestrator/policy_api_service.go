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
	sharedpolicy "axonflow/platform/shared/policy"
)

// policyTestEvaluator is the shared substrate (#3296,
// platform/shared/policy/condition_evaluator.go). This evaluator's legacy
// operator set (PolicyService.evaluateOperator) excluded greater_than/
// less_than entirely; the #3296 convergence pass added them, along with the
// other four convergences (case-insensitive contains, contains_any
// stringifies every item, string-required regex, unparseable-numeric-never-
// coerces-to-zero) — see the shared type's doc comment for the full
// convergence record. This evaluator's own unknown-operator behavior was
// always silent (previously a nil hook; now the same silence — no logging
// hook exists to configure at all). Slice 2 gave this evaluator's
// unevaluable conditions (unknown operator, non-numeric operand, non-string
// regex pattern) a real signal despite that silence: they report through
// policyTestUnevaluableRecorder (condition_unevaluable_metrics.go), passed
// into Match per call. A zero-condition policy vacuously matches — see
// evaluateConditions below and the shared type's "Withdrawn" doc section for
// why a brief attempt at making that a non-match was reverted. A
// package-level value — not a struct field — because it holds no per-service
// state and every PolicyService constructor (NewPolicyService,
// NewPolicyServiceWithRefresher, NewPolicyServiceWithLicense, and the bare
// `&PolicyService{}` literals used throughout this package's tests) must get
// the exact same configured evaluator; constructed once, never per-request —
// TestPolicy runs this on every policy-test request, so a per-request
// allocation here would be a needless cost.
var policyTestEvaluator = sharedpolicy.ConditionEvaluator{}

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

// TestPolicy evaluates a policy against test input.
//
// # Segment-awareness (#3296, ADR-060 #2989/#3266)
//
// Before this change, TestPolicy did raw condition evaluation with zero
// segment semantics: a segment-scoped policy (dynamic_policies.segment_id,
// migration 159) would report Matched=true for a caller who is not a member
// of that segment, exactly the enforcement/preview drift #3266 tracks.
//
// Two pieces of information this method would need to fully mirror
// enforcement are not available through the types it is handed:
//
//   - A verified caller identity. TestPolicyRequest has no email/org field,
//     and today's HTTP entry points that call TestPolicy never bind one onto
//     ctx before calling it. verifiedTestIdentity below looks for the SAME
//     ctxKeyUser value the /process governed-request path binds (run.go's
//     applyAuthoritativePrincipal): today this is ALWAYS a miss in
//     production, but the lookup costs nothing, lets a future caller that
//     does thread a verified identity get real segment enforcement for
//     free, and lets this be tested directly via context.WithValue.
//   - The policy's own SegmentID. PolicyResource has no SegmentID field, and
//     PolicyRepository.GetByID's SELECT does not fetch
//     dynamic_policies.segment_id — a structural gap in those types, not
//     something fixable from inside this method. The best-effort fallback is
//     s.policyEngine.LookupSegmentID (dynamic_policy_engine.go), which reads
//     the SAME dynamic_policies table via the in-memory engine's
//     already-loaded cache. When policyEngine is nil or the cache does not
//     have this policy, segment-scope status is UNKNOWN — never assumed
//     absent.
//
// # Fail-closed / degrade-observably contract
//
//   - Verified identity present, segment resolution FAILS: fail closed like
//     enforcement — Matched forced false, never silently treated as
//     tenant-wide.
//   - Verified identity present, resolution succeeds, policy IS
//     segment-scoped, caller is NOT a member: Matched forced false
//     regardless of condition evaluation — mirrors
//     CompiledPolicy.AppliesToSegments / memPolicyAppliesToTenant's
//     restriction-only rule. The Explanation note for this case never spells
//     out the segment's identifier. It does NOT achieve full non-disclosure,
//     though: the note's mere presence ("This policy does not apply to the
//     caller.") versus its absence is itself a one-bit oracle — it tells a
//     non-member that SOME scope excluded them, which a member (or a
//     non-segment-scoped policy) never sees. #3320 review: this claim was
//     previously overstated as "the caller learns nothing"; that is false as
//     written. It is not fixed here because it is inert in production today
//     (ctxKeyUser, which identityAvailable depends on, is bound only on the
//     /process governed-request path — TestPolicy's HTTP entry points never
//     bind it), so there is no live caller who can observe the bit; treat
//     this as a documented weakness to hold in mind if TestPolicy ever gains
//     a verified-identity entry point, not as something already closed.
//   - Verified identity present and (caller IS a member, or policy is not
//     segment-scoped, or scope status could not be determined): normal
//     condition-only evaluation stands.
//   - No verified identity at all (today's universal case on this path):
//     condition-only evaluation proceeds UNCHANGED — this is the
//     pre-existing, already-tested behavior — but Explanation is appended
//     with an explicit note that segment scoping was NOT evaluated,
//     degrading OBSERVABLY rather than silently presenting a possibly
//     segment-restricted policy as an unqualified tenant-wide match (#3283's
//     "silent misleading output" failure mode).
//
// testPolicyVerdictForStoredRow returns the #3384 exclusion verdict for a
// stored row whose conditions list is EXPLICITLY empty, or nil when the row
// evaluates normally. A stored `[]` is excluded from evaluation on every
// engine plane (released-update-gap residue; see db_dynamic_policies.go's
// cachedPolicyToDynamicPolicy), and this preview MUST agree with the
// engines. TestPolicy reads the row via repo.GetByID rather than the cache
// converter, so the exclusion has to be applied here too — without it the
// R3 of this fix found the exact contradiction the #3266 lineage warns
// about: the test endpoint told an operator a legacy row "matches
// everything, would block" while no engine would ever enforce it. GetByID
// unmarshals `[]` into a non-nil empty slice and JSON `null` into a nil
// one, preserving the same distinction the engines key on; a condition-LESS
// (nil) row returns nil here and vacuously matches, matching the engines'
// restored semantics.
func (s *PolicyService) testPolicyVerdictForStoredRow(policy *PolicyResource) *TestPolicyResponse {
	if policy.Conditions == nil || len(policy.Conditions) != 0 {
		return nil
	}
	policyTestUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonEmptyConditions)
	return &TestPolicyResponse{
		Matched: false,
		Blocked: false,
		Explanation: fmt.Sprintf("Policy '%s' is EXCLUDED from evaluation: its conditions list is explicitly empty, a legacy state no current API can author (pre-9.19 update-API residue, #3384). No engine plane enforces this policy. Give it real conditions via update, or delete it.",
			policy.Name),
	}
}

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

	if v := s.testPolicyVerdictForStoredRow(policy); v != nil {
		v.EvalTimeMs = float64(time.Since(start).Microseconds()) / 1000
		return v, nil
	}

	// Evaluate conditions
	matched := s.evaluateConditions(policy.Conditions, req)
	matched, segNote := s.applySegmentScopeToTestVerdict(ctx, policyID, matched)

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

		response.Explanation = fmt.Sprintf("Policy '%s' matched: all %d conditions evaluated to true.%s",
			policy.Name, len(policy.Conditions), segNote)
	} else {
		response.Explanation = fmt.Sprintf("Policy '%s' did not match: one or more conditions evaluated to false.%s",
			policy.Name, segNote)
	}

	return response, nil
}

// verifiedTestIdentity looks for a verified caller identity on ctx, keyed
// under the SAME ctxKeyUser the /process governed-request path binds
// (run.go's applyAuthoritativePrincipal + ctx construction). See TestPolicy's
// doc for why today's TestPolicy entry points never set it, and why the
// lookup exists anyway.
func verifiedTestIdentity(ctx context.Context) (UserContext, bool) {
	u, ok := ctx.Value(ctxKeyUser).(UserContext)
	if !ok {
		return UserContext{}, false
	}
	return u, true
}

// applySegmentScopeToTestVerdict layers ADR-060 segment scoping onto a
// condition-only TestPolicy verdict, per the fail-closed / degrade-observably
// contract documented on TestPolicy. Returns the (possibly overridden)
// matched verdict and a human-readable note to append to Explanation.
func (s *PolicyService) applySegmentScopeToTestVerdict(ctx context.Context, policyID string, matched bool) (bool, string) {
	user, identityAvailable := verifiedTestIdentity(ctx)
	if !identityAvailable {
		// This disclaimer is uniform across every policy tested on this
		// path (identity is never available here in production) — it is
		// never informed by, and never reveals, whether THIS policy is
		// actually segment-scoped.
		return matched, " Segment scoping NOT evaluated: no verified caller identity is available on this path (ADR-060 #2989/#3266) — this result does not reflect any segment restriction the policy may carry."
	}

	segIDs, segOK := resolveSegmentsForPolicy(ctx, user.OrgID, user.Email)
	if !segOK {
		return false, " Segment resolution failed (fail-closed, ADR-060 #2989/#3266): treated as no match."
	}

	segID, found := s.lookupPolicySegmentID(policyID)
	if !found || segID == "" {
		// Not segment-scoped, or scope status could not be determined for
		// this policy — condition-only evaluation stands. A lookup miss must
		// never be treated as proof of "not segment-scoped" (that would risk
		// exactly the #3266 over-disclosure this method exists to prevent);
		// it is simply silent here because there is nothing more to say.
		return matched, ""
	}

	if !segmentSetContains(segIDs, segID) {
		// #3266: a caller who is not a member of segID must not learn the
		// segment's identifier — the note below says nothing segment-
		// specific, unlike a policy ID leaking into triggered_policies for a
		// non-member. This is narrower than full non-disclosure, though:
		// the note is appended only on this branch, so its presence is
		// itself a one-bit signal that the caller was excluded by SOME
		// scope, distinguishable from a member's or a non-segment-scoped
		// policy's silent "" note. See TestPolicy's doc comment (Fail-closed
		// / degrade-observably contract) for why this is left as-is: it is
		// inert in production (identityAvailable is never true on today's
		// call paths), not a claim that the bit is actually hidden.
		return false, " This policy does not apply to the caller."
	}
	// Caller is a member: the condition-only verdict stands unmodified. No
	// note — the segment identifier is internal bookkeeping, and there is no
	// operational need to echo it back even to a member.
	return matched, ""
}

// lookupPolicySegmentID returns the SegmentID of a policy from the in-memory
// DynamicPolicyEngine's cache, and whether it was found there. See
// TestPolicy's doc for why this indirection exists: PolicyResource itself
// carries no SegmentID, and the policy-API repository does not fetch
// dynamic_policies.segment_id.
func (s *PolicyService) lookupPolicySegmentID(policyID string) (string, bool) {
	if s.policyEngine == nil {
		return "", false
	}
	return s.policyEngine.LookupSegmentID(policyID)
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

// validateCreateRequest validates a create policy request.
//
// Zero conditions is rejected here even though the evaluators now treat it
// as a legitimate "applies to everything" match (see
// platform/shared/policy/condition_evaluator.go's "Withdrawn" doc section).
// This is a deliberate asymmetry, not an oversight: the platform may seed a
// condition-less policy meaning "applies to everything" (loadDefaultPolicies'
// fallback, insertSamplePolicies' three sample rows), but a customer may not
// author one through this API. Revisitable later if there is demand for a
// customer-authored unconditional policy — today, rejecting it here is what
// keeps a zero-condition row a platform-controlled, deliberate construct
// instead of something any tenant can create by accident.
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

// validateUpdateRequest validates an update policy request. Mirrors
// validateCreateRequest's rejection of zero conditions (see that function's
// doc for the platform-may-seed / customer-may-not-author asymmetry) — this
// stays rejected on update too.
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

	// An explicitly-provided empty conditions array must be rejected here the
	// same way validateCreateRequest rejects one on create — mirroring that
	// error message. `nil` (the field omitted from the request body
	// entirely) stays the "leave conditions unchanged" signal and must NOT
	// be rejected; only a present-but-empty JSON `[]` reaches the branch
	// below. Without this guard, `req.Conditions != nil` lets `[]` straight
	// through the loop (which runs zero times) with no error, so a caller
	// could PUT a block-action policy down to zero conditions — and because
	// zero/absent conditions now vacuously matches everything (see
	// condition_evaluator.go's "Withdrawn" doc section), that row would
	// deny every request for the tenant. This validation is the load-bearing
	// guard against that shape now that the evaluators no longer neutralize
	// it themselves; it stays in place regardless of authoring-restriction
	// changes elsewhere.
	if req.Conditions != nil {
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

	// Validate regex if operator is regex. #3296 convergence 4: the shared
	// ConditionEvaluator now requires a regex condition's Value to be a Go
	// string at evaluation time (matching the majority legacy behavior) —
	// a non-string Value used to compile-check successfully skipped here
	// (`if str, ok := ...; ok` silently passed a non-string through) and
	// then, on the in-memory engine (1a) only, matched via a
	// fmt.Sprint-and-compile fallback that no longer exists. Rejecting it
	// here closes that authoring gap: this shape can no longer be created
	// going forward, on any engine.
	if cond.Operator == "regex" {
		str, ok := cond.Value.(string)
		if !ok {
			return fmt.Errorf("regex pattern must be a string")
		}
		if _, err := regexp.Compile(str); err != nil {
			return fmt.Errorf("invalid regex pattern: %v", err)
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

// evaluateConditions evaluates all conditions against the test request. No
// conditions means the policy applies to everything — vacuous truth, the
// same as an empty `WHERE` clause matching every row; see the shared
// evaluator's "Withdrawn" doc section (condition_evaluator.go) for why a
// stricter "zero conditions never matches" guard briefly lived here and was
// reverted. Creation and update both reject an empty/cleared conditions
// array, so a zero-condition policy reaching TestPolicy at all means a
// platform-seeded, deliberately-unconditional row.
func (s *PolicyService) evaluateConditions(conditions []PolicyCondition, req *TestPolicyRequest) bool {
	for _, cond := range conditions {
		if !s.evaluateCondition(cond, req) {
			return false
		}
	}
	return true
}

// policyTestFieldValue resolves cond.Field against req for evaluateCondition.
// ok=false reproduces the legacy default-arm short-circuit EXACTLY: a field
// that is not "query"/"request_type"/"user.*"/"context.*" fell to the
// default arm, which only proceeded to evaluateOperator when
// req.Context[field] produced a genuinely non-nil value — a nil Context, a
// missing key, OR a key whose stored value is itself nil all made the
// legacy function return false immediately, BEFORE ever looking at the
// operator. That is a real, reachable divergence from "resolve to nil and
// let the operator switch run": not_equals and regex, in particular, would
// otherwise be able to spuriously MATCH an unresolvable field. evaluateCondition
// below preserves the short-circuit by checking ok itself, never inside
// ConditionEvaluator.Match.
//
// The "user."/"context." prefixed branches, by contrast, NEVER short-circuit
// even when the underlying map is nil or the key is absent — ok=true always
// there (value nil), exactly matching legacy's unconditional fall-through to
// evaluateOperator(cond.Operator, nil, cond.Value) in those two cases.
func policyTestFieldValue(field string, req *TestPolicyRequest) (value any, ok bool) {
	switch {
	case field == "query":
		return req.Query, true
	case field == "request_type":
		return req.RequestType, true
	case strings.HasPrefix(field, "user."):
		userField := strings.TrimPrefix(field, "user.")
		if req.User != nil {
			return req.User[userField], true
		}
		return nil, true
	case strings.HasPrefix(field, "context."):
		contextField := strings.TrimPrefix(field, "context.")
		if req.Context != nil {
			return req.Context[contextField], true
		}
		return nil, true
	default:
		// For fields like "step_input.recipient_count" or "tool_input.query",
		// look them up directly in the context map (WCPPolicyAdapter stores them
		// with dotted keys like "step_input.recipient_count" in OrchestratorRequest.Context).
		if req.Context != nil {
			if v := req.Context[field]; v != nil {
				return v, true
			}
		}
		return nil, false
	}
}

// evaluateCondition evaluates a single condition.
//
// #3296: delegates the operator logic to policyTestEvaluator (the
// shared substrate — case-insensitive contains, contains_any stringifies
// non-string items, the full ten-operator union. This plane's legacy switch
// covered eight of the ten; convergence 5 in condition_evaluator.go's
// package doc added the missing greater_than/less_than). The
// unresolvable-field short-circuit (see policyTestFieldValue) runs BEFORE
// the evaluator is consulted, exactly reproducing the legacy function's
// early-return shape rather than letting a nil field value flow into the
// operator switch.
func (s *PolicyService) evaluateCondition(cond PolicyCondition, req *TestPolicyRequest) bool {
	fieldValue, ok := policyTestFieldValue(cond.Field, req)
	if !ok {
		policyTestUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonFieldUnresolved)
		return false
	}
	return policyTestEvaluator.Match(
		sharedpolicy.MatchCondition{Field: cond.Field, Operator: cond.Operator, Value: cond.Value},
		func(string) (any, bool) { return fieldValue, true },
		policyTestUnevaluableRecorder,
	)
}

// #3296: evaluateOperator was deleted here — its operator-comparison
// logic now lives in platform/shared/policy/condition_evaluator.go
// (policyTestEvaluator above). Grep confirmed its only callers were the old
// evaluateCondition (policy_api_service.go, deleted above) and its own
// tests (TestPolicyService_EvaluateOperator_Additional, relocated to
// policy_api_service_test.go as TestPolicyTestEvaluator_Operators, which
// exercises the exact preconfigured shared evaluator this service uses).

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
