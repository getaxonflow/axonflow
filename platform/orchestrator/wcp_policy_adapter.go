// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"log"
	"sort"
	"time"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"

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
		_, _ = ApplyOverrideToResult(ctx, usageDB, auditLogger, result,
			step.TenantID, step.OrgID, step.UserID, toolSig)
	}

	// Convert PolicyEvaluationResult to StepGateEvaluation
	evaluation := a.convertToStepGateEvaluation(result, durationMs)

	// Issue #1082: If require_approval, create HITL approval request
	if evaluation.Decision == workflow_control.GateDecisionRequireApproval && a.hitlApproval != nil {
		approvalID := a.createHITLApproval(ctx, step, result)
		if approvalID != uuid.Nil {
			evaluation.ApprovalID = approvalID.String()
			log.Printf("[WCP] HITL approval created for step %s: %s", step.StepName, approvalID)
		}
	}

	return evaluation
}

// createHITLApproval creates an HITL approval request for require_approval actions (Issue #1082)
func (a *WCPPolicyAdapter) createHITLApproval(ctx context.Context, step *workflow_control.StepGateContext, result *PolicyEvaluationResult) uuid.UUID {
	if a.hitlApproval == nil {
		return uuid.Nil
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
		log.Printf("[WCP] Failed to create HITL approval: %v", err)
		return uuid.Nil
	}

	return resp.ApprovalID
}

// convertToOrchestratorRequest converts WCP step context to orchestrator request format
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
