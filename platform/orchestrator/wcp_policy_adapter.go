// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"

	"github.com/google/uuid"
)

// HITLApprovalCreator is the interface for creating HITL approval requests (Issue #1082)
type HITLApprovalCreator interface {
	CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error)
}

// WCPPolicyAdapter is the workflow_control.PolicyEvaluator the step gate decides
// through (Issue #1021): it presents each step to the anchored engine
// (wcp_enforcing_seam.go) and queues a held step's approval. It holds no policy
// engine of its own since #4254.
type WCPPolicyAdapter struct {
	hitlApproval HITLApprovalCreator // HITL approval service for require_approval action (Issue #1082)
}

// NewWCPPolicyAdapter creates the step gate's adapter.
func NewWCPPolicyAdapter() *WCPPolicyAdapter {
	return &WCPPolicyAdapter{}
}

// SetHITLApproval sets the HITL approval service for require_approval action (Issue #1082)
func (a *WCPPolicyAdapter) SetHITLApproval(approval HITLApprovalCreator) {
	a.hitlApproval = approval
}

// EvaluateStepGate implements workflow_control.PolicyEvaluator
// Converts WCP step gate context to orchestrator request, evaluates policies, and converts result back
func (a *WCPPolicyAdapter) EvaluateStepGate(ctx context.Context, step *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	// #4254: the anchored engine authors this plane's verdict. There is no
	// "no engine configured" arm any more: a step gate that cannot reach a
	// verdict FAILS CLOSED (stepGateEvaluationFor), because admitting a step
	// because nothing was wired is an outage answering as a governance
	// decision. The request is still built the same way, because the fact
	// producer reads exactly the fields the dynamic matcher read.
	req := a.convertToOrchestratorRequest(step)
	evaluation, result := stepGateEvaluationFor(ctx, step, req)

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
		if errors.Is(err, errApprovalExpiredBeforeQueue) && result.hold != nil && result.hold.approval != nil {
			// #4254: the approval timed out between the decision and the
			// enqueue. A timed-out approval is a deny: the step is withheld as
			// approval_expired, as the seam withholds one that had already
			// expired when it was decided, and there is no queue row to approve.
			// The engine counted this decision once, when it held the step.
			return withholdLapsedApproval(evaluation, result.hold)
		}
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
			// the seam has always set Reason to "Step requires human
			// approval", so the else arm is unreachable today.
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

// withholdLapsedApproval is the approval_expired refusal for a hold whose
// approval timed out before it could be queued: the answer
// stepGateApprovalExpired gives, keeping the anchored decision the evaluation
// was stamped with (PRD v11 §5.7).
func withholdLapsedApproval(held *workflow_control.StepGateEvaluation, hold *stepGateHold) *workflow_control.StepGateEvaluation {
	withheld := stepGateBlocked(approvalExpiredReason(hold.decisionID, hold.approval.ExpiresAt), []string{string(contract.ReasonApprovalExpired)})
	withheld.Plane, withheld.Engine, withheld.SubjectType, withheld.PolicyBundle, withheld.EngineDecisionID =
		held.Plane, held.Engine, held.SubjectType, held.PolicyBundle, held.EngineDecisionID
	return withheld
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
	// #4254: a typed challenge holds the step with an approval requirement.
	// The queue row carries it, and lives no longer than it: timeout is deny.
	if result.hold != nil {
		for k, v := range result.hold.requestContext(wcpSeamScope.String()) {
			req.RequestContext[k] = v
		}
		if result.hold.approval != nil {
			req.ExpiresAt = result.hold.approval.ExpiresAt
		}
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
// treated as a resolution FAILURE. A genuine resolver error now fails the
// request CLOSED at the seam rather than inside a legacy evaluation: the fact
// producer answers errDynamicFactsUnavailable, and stepGateEvaluationFor
// withholds the step naming the cause, never a no-match-allow (#4254). See
// ADR-060's enforcement-surface coverage matrix.
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
		// The step gate's anchored decision (PRD v11 §5.7).
		Plane:            entry.Plane,
		Engine:           entry.Engine,
		SubjectType:      entry.SubjectType,
		PolicyBundle:     entry.PolicyBundle,
		EngineDecisionID: entry.EngineDecisionID,
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
