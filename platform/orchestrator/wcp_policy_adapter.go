// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"

	"axonflow/platform/decision/legacycompile"
	"github.com/google/uuid"
)

// HITLApprovalCreator is the interface for creating HITL approval requests (Issue #1082)
type HITLApprovalCreator interface {
	CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error)
}

// WCPPolicyAdapter adapts the dynamic policy engine to the workflow_control.PolicyEvaluator interface
// This bridges the gap between the main orchestrator's policy engine and the WCP service (Issue #1021)
type WCPPolicyAdapter struct {
	engine interface {
		EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
		ListActivePolicies() []DynamicPolicy
		IsHealthy() bool
	}
	hitlApproval HITLApprovalCreator // HITL approval service for require_approval action (Issue #1082)
}

// NewWCPPolicyAdapter creates a new adapter wrapping the dynamic policy engine
func NewWCPPolicyAdapter(engine interface {
	EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
	ListActivePolicies() []DynamicPolicy
	IsHealthy() bool
}) *WCPPolicyAdapter {
	return &WCPPolicyAdapter{engine: engine}
}

// SetHITLApproval sets the HITL approval service for require_approval action (Issue #1082)
func (a *WCPPolicyAdapter) SetHITLApproval(approval HITLApprovalCreator) {
	a.hitlApproval = approval
}

// EvaluateStepGate implements workflow_control.PolicyEvaluator
// Converts WCP step gate context to orchestrator request, evaluates policies, and converts result back
func (a *WCPPolicyAdapter) EvaluateStepGate(ctx context.Context, step *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	if a.engine == nil {
		// No policy engine configured - allow all steps
		return &workflow_control.StepGateEvaluation{
			Decision: workflow_control.GateDecisionAllow,
			Reason:   "No policy engine configured",
		}
	}

	// Convert StepGateContext to OrchestratorRequest
	req := a.convertToOrchestratorRequest(step)

	// Evaluate policies
	startTime := time.Now()
	req.ShadowPlane = legacycompile.PlaneWCP // ADR-065 decision shadow (#3564)
	result := a.engine.EvaluateDynamicPolicies(ctx, req)
	durationMs := time.Since(startTime).Milliseconds()

	// ADR-044: if the result is a deny, check for an active session override
	// BEFORE converting to a step gate evaluation. Overrides only apply to
	// denies on non-critical policies with allow_override=true.
	if !result.Allowed {
		toolSig := ""
		if step.ToolContext != nil {
			toolSig = step.ToolContext.ToolName
		}
		// #3281: prefer the trust-gated verified email over step.UserID for the
		// ADR-044 override lookup's userEmail parameter. UserID is attribution
		// only and its fallback chain can hold a non-email X-User-ID, so an
		// override keyed on a real address never matched on this plane unless
		// the caller's UserID happened to BE that address. step.Email is a
		// verified address by construction. Falling back to step.UserID when no
		// email is present preserves the existing ADR-043/044 plugin-flow
		// behaviour for callers whose UserID already holds one, so this is
		// strictly a widening and cannot regress an override that matches today.
		overrideEmail := step.Email
		if overrideEmail == "" {
			overrideEmail = step.UserID
		}
		_, _ = ApplyOverrideToResult(ctx, usageDB, auditLogger, result,
			step.TenantID, step.OrgID, overrideEmail, toolSig)
	}

	// Convert PolicyEvaluationResult to StepGateEvaluation
	evaluation := a.convertToStepGateEvaluation(result, durationMs)

	// Issue #1082: If require_approval, create HITL approval request.
	//
	// #3408 sibling: the enqueue result is now RECORDED, not just logged. It
	// used to be that a failed enqueue produced the identical response to a
	// successful one minus the approval_id, so "held with a reviewer surface"
	// and "held with nothing to approve" were indistinguishable to the client,
	// to the audit row and to every dashboard. The step is still HELD in both
	// cases - admitting it because the review queue is full would turn a
	// capacity limit into a governance bypass - but which one happened is now
	// on the wire (StepGateResponse.approval_enqueue), on the audit row
	// (policy_details.approval_enqueue) and on
	// axonflow_hitl_enqueue_total{plane,outcome}.
	if evaluation.Decision == workflow_control.GateDecisionRequireApproval && a.hitlApproval != nil {
		approvalID, outcome, err := a.createHITLApproval(ctx, step, result)
		evaluation.ApprovalEnqueue = outcome
		if err != nil {
			var reason string
			evaluation.ApprovalEnqueue, reason = classifyEnqueueFailure(err)
			// APPENDED, not assigned. Overwriting Reason discarded the
			// POLICY's own reason - the record of why the step was gated at
			// all - from both the wire and the audit row, on exactly the
			// requests an operator most needs to reconstruct. The two facts
			// are independent and both belong.
			//
			// The empty guard is not dead code by accident: on THIS branch
			// convertToStepGateEvaluation has always set Reason to "Step
			// requires human approval", so the else arm is unreachable today.
			// It is kept because the invariant it protects ("never produce a
			// leading separator") should not depend on a value set 300 lines
			// away, and asserted by
			// TestEnqueueRefusalKeepsThePolicyReason.
			if evaluation.Reason != "" {
				evaluation.Reason = evaluation.Reason + "; " + reason
			} else {
				evaluation.Reason = reason
			}
			log.Printf("[WCP] HITL enqueue %s for step %s (workflow %s): %v",
				evaluation.ApprovalEnqueue, logutil.Sanitize(step.StepName),
				logutil.Sanitize(step.WorkflowID), err)
		} else if approvalID != uuid.Nil {
			evaluation.ApprovalID = approvalID.String()
			log.Printf("[WCP] HITL approval %s for step %s: %s",
				evaluation.ApprovalEnqueue, logutil.Sanitize(step.StepName), approvalID)
		}
	}

	return evaluation
}

// createHITLApproval creates an HITL approval request for require_approval
// actions (Issue #1082).
//
// Returns the approval id, the enqueue classification, and the error. It used
// to return only the id and to log the error internally, which is what made a
// cap refusal or a licence refusal invisible to every caller (#3408 sibling).
// The error is now the caller's to classify and disclose.
func (a *WCPPolicyAdapter) createHITLApproval(ctx context.Context, step *workflow_control.StepGateContext, result *PolicyEvaluationResult) (uuid.UUID, string, error) {
	if a.hitlApproval == nil {
		return uuid.Nil, "", nil
	}

	// Determine the triggering policy for the HITL queue entry.
	// Prefer the policy that contributed the highest severity (SeverityPolicyID),
	// since that's the policy driving the routing behavior. Fall back to the first
	// applied policy if no severity attribution is available.
	policyID := ""
	policyName := "unknown"
	if result.SeverityPolicyID != "" {
		policyName = result.SeverityPolicyID
		policyID = policyName
	} else if len(result.AppliedPolicies) > 0 {
		policyName = result.AppliedPolicies[0]
		policyID = policyName
	}

	req := &HITLApprovalRequest{
		OrgID:         step.OrgID,
		TenantID:      step.TenantID,
		ClientID:      step.ClientID,
		UserID:        step.UserID,
		ExecutionID:   step.WorkflowID,
		StepName:      step.StepName,
		StepType:      string(step.StepType),
		PolicyID:      policyID,
		PolicyName:    policyName,
		TriggerReason: "Step requires human approval per policy",
		Severity:      deriveSeverityFromResult(result),
		RequestContext: map[string]interface{}{
			"workflow_id":   step.WorkflowID,
			"step_id":       step.StepID,
			"workflow_name": step.WorkflowName,
			"step_index":    step.StepIndex,
			"model":         step.Model,
			"provider":      step.Provider,
			"tool_name":     toolNameForContext(step),
			"tool_type":     toolTypeForContext(step),
		},
	}

	resp, err := a.hitlApproval.CreateApproval(ctx, req)
	if err != nil {
		return uuid.Nil, "", err
	}
	if resp == nil {
		// A nil response with a nil error is a broken HITLApprovalCreator.
		// Report it as an enqueue error rather than returning uuid.Nil with
		// no classification, which is the shape this change exists to remove.
		return uuid.Nil, "", fmt.Errorf("HITL approval creator returned no response and no error")
	}

	return resp.ApprovalID, resp.Enqueue, nil
}

// convertToOrchestratorRequest converts WCP step context to orchestrator request format.
//
// SEGMENT ENFORCEMENT (ADR-060 #2989 P3b, #3281): the UserContext built below
// carries TenantID, OrgID, AND Email - step.Email is the trust-gated
// X-User-Email the WCP handler read off the HTTP request (see
// StepGateRequest.Email's doc), threaded through StepGateContext.Email. A
// step-gate's EvaluateDynamicPolicies call therefore resolves the caller's
// governance-segment set the SAME way /api/v1/process and MAP do
// (resolveUserSegments, segment_policy_gate.go), and a segment-scoped
// dynamic policy is enforced identically on a WCP workflow step-gate. This
// holds on EVERY route that reaches Service.StepGate: the gate handler and
// both checkpoint-resume routes read the same trust-gated header (#3281), and
// the two GateOverride callers (MAP confirm/step, run.go's plan resume) never
// reach policy evaluation at all. Where no verified identity is available
// (an identity-absent caller), this degrades to the SAME org-only path
// /api/v1/process takes with no identity: non-segment-
// scoped policies still enforce, segment-scoped ones do not apply, and
// resolveUserSegments's ok=true / nil-set contract means this is never
// treated as a resolution FAILURE. A genuine resolver error is handled
// inside EvaluateDynamicPolicies itself (db_dynamic_policies.go), which
// returns EvaluationError=true / Allowed=false - surfaced as a fail-closed
// GateDecisionBlock by convertToStepGateEvaluation below, never a
// no-match-allow. See ADR-060's enforcement-surface coverage matrix.
func (a *WCPPolicyAdapter) convertToOrchestratorRequest(step *workflow_control.StepGateContext) OrchestratorRequest {
	// Build context map with step information for policy matching
	contextData := make(map[string]interface{})
	contextData["workflow_id"] = step.WorkflowID
	contextData["workflow_name"] = step.WorkflowName
	contextData["source"] = string(step.Source)
	contextData["step_id"] = step.StepID
	contextData["step_name"] = step.StepName
	contextData["step_type"] = string(step.StepType)
	contextData["step_index"] = step.StepIndex
	contextData["model"] = step.Model
	contextData["provider"] = step.Provider

	// Merge step input into context
	for k, v := range step.StepInput {
		contextData["step_input."+k] = v
	}

	// Propagate tool-level context for per-tool governance (#1243)
	if step.ToolContext != nil {
		contextData["tool_name"] = step.ToolContext.ToolName
		if step.ToolContext.ToolType != "" {
			contextData["tool_type"] = step.ToolContext.ToolType
		}
		// Limit tool_input to 50 keys to prevent context bloat.
		// Sort keys first for deterministic inclusion across identical requests.
		toolInputKeys := make([]string, 0, len(step.ToolContext.ToolInput))
		for k := range step.ToolContext.ToolInput {
			toolInputKeys = append(toolInputKeys, k)
		}
		sort.Strings(toolInputKeys)
		for i, k := range toolInputKeys {
			if i >= 50 {
				break
			}
			contextData["tool_input."+k] = step.ToolContext.ToolInput[k]
		}
	}

	// Issue #1673 Phase 1: retry-aware condition fields. Policies can match
	// on `step.gate_count`, `step.completion_count`,
	// `step.prior_completion_status`, `step.prior_output_available`,
	// `step.last_decision`, `step.first_attempt_age_seconds`, and
	// `step.idempotency_key`. Values reflect the projected post-bump state
	// at evaluation time (so `gate_count > 1` matches on the second call,
	// not the third). Populated by service.applyRetryContextToGate.
	contextData["step.gate_count"] = step.GateCount
	contextData["step.completion_count"] = step.CompletionCount
	contextData["step.prior_completion_status"] = string(step.PriorCompletionStatus)
	contextData["step.prior_output_available"] = step.PriorOutputAvailable
	contextData["step.last_decision"] = string(step.LastDecision)
	contextData["step.first_attempt_age_seconds"] = step.FirstAttemptAgeSeconds
	// Phase 2: business-level key for policy-authored equals/regex matching.
	// Always populate — empty string signals "no key supplied" so policy
	// authors can govern both the presence and absence of keys:
	//   step.idempotency_key == ""       → no key supplied
	//   step.idempotency_key regex "..."  → pattern match against key
	// Matches the wire contract which surfaces the same empty string on
	// retry_context.idempotency_key when unset.
	contextData["step.idempotency_key"] = step.IdempotencyKey

	return OrchestratorRequest{
		RequestID:   step.WorkflowID + "_" + step.StepID,
		RequestType: "workflow_step_gate",
		User: UserContext{
			TenantID: step.TenantID,
			// #3281 (ADR-060 #2989 P3b): OrgID and Email are required for
			// resolveUserSegments to resolve a verified per-user
			// identity - previously only Client.OrgID below was populated,
			// leaving User.OrgID zero and forcing every step-gate onto the
			// org-only / no-identity path regardless of the caller's actual
			// segment memberships.
			OrgID: step.OrgID,
			Email: step.Email,
		},
		Client: ClientContext{
			ID:       step.ClientID,
			TenantID: step.TenantID,
			OrgID:    step.OrgID,
		},
		Context: contextData,
	}
}

// toolNameForContext extracts tool name from step context for HITL approval requests.
func toolNameForContext(step *workflow_control.StepGateContext) string {
	if step.ToolContext != nil {
		return step.ToolContext.ToolName
	}
	return ""
}

// toolTypeForContext extracts tool type from step context for HITL approval requests.
func toolTypeForContext(step *workflow_control.StepGateContext) string {
	if step.ToolContext != nil {
		return step.ToolContext.ToolType
	}
	return ""
}

// deriveSeverityFromResult determines the severity for an HITL approval request.
// If the policy explicitly set a severity via the require_approval action config, use it.
// Otherwise, derive severity from the risk score:
//   - ≥0.8 → critical
//   - ≥0.5 → high
//   - ≥0.3 → medium
//   - <0.3 → low
func deriveSeverityFromResult(result *PolicyEvaluationResult) string {
	// Explicit severity from policy action config takes precedence
	if result.Severity != "" {
		return result.Severity
	}

	// Derive from risk score
	switch {
	case result.RiskScore >= 0.8:
		return "critical"
	case result.RiskScore >= 0.5:
		return "high"
	case result.RiskScore >= 0.3:
		return "medium"
	default:
		return "low"
	}
}

// convertToStepGateEvaluation converts policy evaluation result to WCP step gate evaluation
func (a *WCPPolicyAdapter) convertToStepGateEvaluation(result *PolicyEvaluationResult, durationMs int64) *workflow_control.StepGateEvaluation {
	evaluation := &workflow_control.StepGateEvaluation{
		Decision:          workflow_control.GateDecisionAllow,
		Reason:            "No matching policies",
		PolicyIDs:         result.AppliedPolicies,
		PoliciesEvaluated: []workflow_control.PolicyMatch{},
		PoliciesMatched:   []workflow_control.PolicyMatch{},
	}

	// #3281 (ADR-060 #2989 P3b): a genuine segment-resolution FAILURE inside
	// EvaluateDynamicPolicies is signaled via EvaluationError=true (S1,
	// #3239 round 2), always paired with Allowed=false - see
	// PolicyEvaluationResult.EvaluationError's doc (run.go). Without this
	// branch the generic "!result.Allowed" handling below still produces
	// GateDecisionBlock (safe - fail-closed is preserved either way, since
	// AppliedPolicies is empty and RequiredActions never contains
	// "require_approval"/"human_review" on this path), but the Reason/
	// PolicyIDs would read as an indistinguishable, unnamed "Step blocked by
	// policy" instead of naming the availability failure - the same
	// disclosure convention run.go's proxy handler and policy_api_service.go
	// use for this exact condition (triggeredPolicies :=
	// []string{"segment_resolution_failed"}). Named explicitly here so the
	// audit row, the API response, and the runtime-e2e fail-closed assertion
	// can all key off it instead of string-matching a human-readable reason.
	//
	// DELIBERATE DIVERGENCE from #3312: the gateway pre-check also calls
	// circuitBreakerInstance.RecordPolicyViolation on this deny, feeding the
	// #1176 auto-trip threshold. This plane cannot: circuitBreakerInstance is
	// a package-level singleton owned by platform/agent and wired in the AGENT
	// process. The orchestrator binary neither imports agent/circuitbreaker nor
	// holds an instance (grep: zero references under platform/orchestrator), so
	// there is nothing here to record into. Matching #3312 would mean giving
	// the orchestrator its own circuit-breaker wiring -- a real change with its
	// own tripping semantics and blast radius, not a parity tidy-up. Left
	// diverged on purpose; the deny itself is fail-closed either way, and the
	// named PolicyIDs above keep it attributable.
	if result.EvaluationError {
		evaluation.Decision = workflow_control.GateDecisionBlock
		// Wording aligned with the #3312 gateway pre-check's literal at
		// gateway_handlers.go:698, which reads "segment resolution
		// unavailable", then a dash, then "request denied (fail-closed,
		// ADR-060 #2989)" -- so the two human-readable halves of one
		// condition do not read as two different conditions. NOT quoted
		// verbatim here: that literal separates its two clauses with an em
		// dash and this plane's string below uses a hyphen, so a verbatim
		// quote would be a misquote AND would put an em dash in this file.
		// Nothing byte-compares the two strings across planes, and nothing
		// should: the machine-readable half is what consumers key off.
		// The machine-readable half is PolicyIDs below, which is what the
		// audit row and the runtime-e2e assertion key off -- deliberately NOT
		// this string, which no consumer should be matching on.
		evaluation.Reason = "segment resolution unavailable - request denied (fail-closed, ADR-060 #2989 P3b)"
		evaluation.PolicyIDs = []string{"segment_resolution_failed"}
		return evaluation
	}

	// If not allowed, determine the appropriate decision
	if !result.Allowed {
		// Check if any policy requires approval (has "require_approval" action)
		requiresApproval := false
		for _, action := range result.RequiredActions {
			if action == "require_approval" || action == "human_review" {
				requiresApproval = true
				break
			}
		}

		if requiresApproval {
			evaluation.Decision = workflow_control.GateDecisionRequireApproval
			evaluation.Reason = "Step requires human approval"
		} else {
			evaluation.Decision = workflow_control.GateDecisionBlock
			evaluation.Reason = "Step blocked by policy"
		}
	}

	// Build policy match details. Prefer the structured AppliedPoliciesDetail
	// (ADR-044/ADR-043) when populated — falls back to the name-only path for
	// engines that haven't been upgraded.
	if len(result.AppliedPoliciesDetail) > 0 {
		for _, p := range result.AppliedPoliciesDetail {
			match := workflow_control.PolicyMatch{
				PolicyID:          p.PolicyID,
				PolicyName:        p.PolicyName,
				Action:            string(evaluation.Decision),
				RiskLevel:         p.RiskLevel,
				AllowOverride:     p.AllowOverride,
				MatchedRule:       p.MatchedRule,
				PolicyDescription: p.Description,
			}
			evaluation.PoliciesEvaluated = append(evaluation.PoliciesEvaluated, match)
			if !result.Allowed {
				evaluation.PoliciesMatched = append(evaluation.PoliciesMatched, match)
			}
		}
	} else {
		for _, policyName := range result.AppliedPolicies {
			match := workflow_control.PolicyMatch{
				PolicyID:   policyName, // Use name as ID if no separate ID
				PolicyName: policyName,
				Action:     string(evaluation.Decision),
			}
			evaluation.PoliciesEvaluated = append(evaluation.PoliciesEvaluated, match)
			if !result.Allowed {
				evaluation.PoliciesMatched = append(evaluation.PoliciesMatched, match)
			}
		}
	}

	// ADR-044: if a session override was applied, surface it in the reason.
	if result.OverrideApplied && result.OverrideID != "" {
		evaluation.Reason = "Allowed by session override " + result.OverrideID
	}

	return evaluation
}

// WCPAuditAdapter adapts the orchestrator's AuditLogger to the workflow_control.WorkflowAuditLogger interface
// This bridges the gap between the main orchestrator's audit logger and the WCP service (Issue #1019)
type WCPAuditAdapter struct {
	auditLogger *AuditLogger
}

// NewWCPAuditAdapter creates a new adapter wrapping the audit logger
func NewWCPAuditAdapter(auditLogger *AuditLogger) *WCPAuditAdapter {
	return &WCPAuditAdapter{auditLogger: auditLogger}
}

// LogWorkflowOperation implements workflow_control.WorkflowAuditLogger
// Converts WCP audit entry to orchestrator format and logs it
func (a *WCPAuditAdapter) LogWorkflowOperation(ctx context.Context, entry *workflow_control.WorkflowAuditEntry) {
	if a.auditLogger == nil || entry == nil {
		return
	}

	// Convert workflow_control.WorkflowAuditEntry to orchestrator.WorkflowAuditEntry
	orchestratorEntry := &WorkflowAuditEntry{
		WorkflowID:   entry.WorkflowID,
		WorkflowName: entry.WorkflowName,
		StepID:       entry.StepID,
		StepName:     entry.StepName,
		Operation:    entry.Operation,
		Decision:     entry.Decision,
		Reason:       entry.Reason,
		TenantID:     entry.TenantID,
		OrgID:        entry.OrgID,
		ClientID:     entry.ClientID,
		UserID:       entry.UserID,
		UserEmail:    entry.UserEmail,
		UserRole:     entry.UserRole,
		Metadata:     entry.Metadata,
	}

	a.auditLogger.LogWorkflowOperation(ctx, orchestratorEntry)
}

// MAPAuditAdapter adapts the orchestrator's AuditLogger to the planning.PlanAuditLogger interface
// This bridges the gap between the main orchestrator's audit logger and the MAP service (Issue #1019, #1020)
type MAPAuditAdapter struct {
	auditLogger *AuditLogger
}

// NewMAPAuditAdapter creates a new adapter wrapping the audit logger
func NewMAPAuditAdapter(auditLogger *AuditLogger) *MAPAuditAdapter {
	return &MAPAuditAdapter{auditLogger: auditLogger}
}

// LogPlanOperation implements planning.PlanAuditLogger
// Converts planning audit entry to orchestrator format and logs it
func (a *MAPAuditAdapter) LogPlanOperation(ctx context.Context, entry *planning.PlanAuditEntry) {
	if a.auditLogger == nil || entry == nil {
		return
	}

	// Convert planning.PlanAuditEntry to orchestrator.PlanAuditEntry
	orchestratorEntry := &PlanAuditEntry{
		PlanID:    entry.PlanID,
		Query:     entry.Query,
		Domain:    entry.Domain,
		Operation: entry.Operation,
		Status:    entry.Status,
		StepCount: entry.StepCount,
		ErrorMsg:  entry.ErrorMsg,
		TenantID:  entry.TenantID,
		OrgID:     entry.OrgID,
		ClientID:  entry.ClientID,
		UserID:    entry.UserID,
		Metadata:  entry.Metadata,
	}

	a.auditLogger.LogPlanOperation(ctx, orchestratorEntry)
}
