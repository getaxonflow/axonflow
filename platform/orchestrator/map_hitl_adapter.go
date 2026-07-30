// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// MAP-HITL Adapter — Bridges MAP execution with HITL approval queue (#1076)

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"axonflow/platform/orchestrator/workflow_control"
	logutil "axonflow/platform/shared/logger"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// MAPHITLPolicyChecker evaluates dynamic policies for MAP plan steps
// and returns require_approval when applicable.
type MAPHITLPolicyChecker struct{}

// CheckPolicy evaluates pre-step policies using the dynamic policy engine.
func (c *MAPHITLPolicyChecker) CheckPolicy(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, error) {
	if dynamicPolicyEngine == nil {
		return nil, nil
	}

	req := OrchestratorRequest{
		RequestID:   execution.ID,
		Query:       fmt.Sprintf("MAP step: %s (%s)", step.Name, step.Type),
		RequestType: "map_step",
		User:        execution.UserContext,
		Context: map[string]interface{}{
			"step_name":     step.Name,
			"step_type":     step.Type,
			"step_provider": step.Provider,
			"step_model":    step.Model,
		},
	}

	result := dynamicPolicyEngine.EvaluateDynamicPolicies(ctx, req)
	if result == nil {
		return nil, nil
	}

	if !result.Allowed {
		action := "block"
		reason := "Blocked by policy"
		policyName := ""
		if len(result.AppliedPolicies) > 0 {
			policyName = result.AppliedPolicies[0]
		}

		// Check if require_approval is in the required actions
		for _, ra := range result.RequiredActions {
			if ra == "require_approval" {
				action = "require_approval"
				reason = "Policy requires human approval"
				break
			}
		}

		// Map risk score to severity
		severity := "low"
		if result.RiskScore >= 0.8 {
			severity = "critical"
		} else if result.RiskScore >= 0.6 {
			severity = "high"
		} else if result.RiskScore >= 0.3 {
			severity = "medium"
		}

		return &PolicyCheckResult{
			Allowed:    false,
			Action:     action,
			PolicyName: policyName,
			Reason:     reason,
			Severity:   severity,
		}, nil
	}

	return nil, nil
}

// MAPHITLApprovalAdapter provides in-memory approval tracking for MAP steps.
// In production enterprise deployments, this delegates to the HITL queue service.
type MAPHITLApprovalAdapter struct{}

// CreateApproval creates a new HITL approval request for a MAP step.
func (a *MAPHITLApprovalAdapter) CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error) {
	approvalID := uuid.New()

	log.Printf("[MAP-HITL] Created approval request %s for step %s (policy: %s)",
		approvalID, logutil.Sanitize(req.StepName), logutil.Sanitize(req.PolicyName))

	return &HITLApprovalResponse{
		ApprovalID: approvalID,
		Status:     "pending",
	}, nil
}

// GetApproval retrieves the status of an HITL approval request.
//
// #3067 (S-4): the scan is bound to the caller's org scope, carried on the
// context by WithHITLScope. The HITLApprovalService interface signature is
// shared with the WCP-backed implementations, so the scope travels on ctx
// rather than as a parameter. A context with no scope asserted matches
// nothing — fail-closed, same shape as the store accessors.
func (a *MAPHITLApprovalAdapter) GetApproval(ctx context.Context, approvalID uuid.UUID) (*HITLApprovalResponse, error) {
	executionStoreMutex.RLock()
	defer executionStoreMutex.RUnlock()

	if exec := findHITLExecutionByApproval(hitlScopeFromContext(ctx), approvalID); exec != nil {
		return &HITLApprovalResponse{
			ApprovalID: approvalID,
			Status:     exec.ApprovalStatus,
		}, nil
	}

	return nil, fmt.Errorf("approval %s not found", approvalID)
}

// mapHITLCallerScope resolves the org scope of a MAP plan approve/reject
// request from the identity headers the agent's auth chain stamps
// authoritatively (apiAuthMiddleware does `r.Header.Set` on X-Tenant-ID and
// X-Org-ID, overwriting anything the client sent) — the same source
// tryApproveViaWCP has always used for its tenantID/orgID arguments. An empty
// result is refused by every consumer rather than matching everything.
func mapHITLCallerScope(r *http.Request) string {
	return normalizeHITLScope(r.Header.Get("X-Org-ID"), r.Header.Get("X-Tenant-ID"))
}

// mapHITLActorIdentity resolves WHO is approving or rejecting a MAP plan step.
//
// #3135: this used to prefer a body field (`approved_by` / `rejected_by`) and
// fall back to the header, which is the exact inverse of
// applyAuthoritativeIdentity ("the actor EMAIL is authoritative from the
// trust-gated header, NEVER the request body"). The value lands in
// workflow_steps.approved_by and, via WorkflowAuditEntry.UserEmail, in
// audit_logs.user_email — so a caller who was already authenticated could name
// any approver they liked and that name is what the HITL audit trail recorded.
// That defeats attribution and non-repudiation on an approval, which is the
// entire point of the trail (ADR-044). It is not a tenancy hole: the caller
// still cannot reach another tenant's step (#3067 S-4 binds the in-memory scan,
// workflowBelongsTo binds the WCP path).
//
// The body is no longer consulted at all — not even as a fallback, because a
// fallback is still a channel the caller controls. The header set and the
// precedence deliberately mirror workflow_control.Handler.getUserID, the
// guarded WCP sibling of this operation, so the same human approving on either
// plane is stamped with the same identity string. getUserID's third source (a
// "user_id" context value) has no writer on this route, so it is omitted rather
// than copied as dead code.
//
// Returns "" when the request carries no identity; callers substitute "system",
// which is the honest record of an unattributable approval — and is what the
// portal's own proxy comment already assumes happens when it forwards no
// X-User-ID (orchestrator_proxy.go). Note the identity headers are trust-gated
// at the agent (AXONFLOW_TRUST_IDENTITY_HEADERS, #2896 WS1): when the gate is
// off they are stripped before the orchestrator sees them, so approvals record
// "system" rather than an unverified name. Failing to "system" rather than to a
// forgeable value is the fail-safe direction for an audit column.
func mapHITLActorIdentity(r *http.Request) string {
	if userID := strings.TrimSpace(r.Header.Get("X-User-ID")); userID != "" {
		return userID
	}
	if email := strings.TrimSpace(r.Header.Get("X-User-Email")); email != "" {
		return email
	}
	return ""
}

// mapStepApproveHandler handles POST /api/v1/plans/{id}/steps/{step_id}/approve
//
// Two code paths, same response shape (Issue #1677):
//
//  1. WCP-backed flow (MAP confirm / step modes): the plan has an underlying
//     WCP workflow that was created by MAPWCPExecutor and written to
//     workflow_steps. We delegate to workflowControlService.ApproveStep then
//     fetch the step + project via workflow_control.ProjectStepGateToHTTP —
//     identical to what the WCP /approve endpoint returns, with plan_id added.
//
//  2. Legacy in-memory flow (policy-driven pause/resume): the plan has no WCP
//     workflow; approval state lives in executionStore. We project a minimal
//     StepGateHTTPResponse with workflow_id empty, retry_context zero-valued,
//     and approval metadata sourced from the in-memory execution record.
//
// Both paths return StepGateHTTPResponse so clients don't have to branch on
// which mode the plan ran in.
func mapStepApproveHandler(w http.ResponseWriter, r *http.Request) {
	// #3135: the approver identity this handler stamps is only as good as the
	// hop that set the header, so require the same agent proxy-auth gate the
	// WCP siblings run (workflow_control.Handler.requireProxyAuth on
	// ApproveStep/RejectStep). Placed first, matching those siblings.
	//
	// Scope note, so nobody reads more into this than it does: since #3068 the
	// whole orchestrator mux is already behind requireInternalProxyAuth, which
	// is strictly stronger (it has no Community carve-out). So on a running
	// server this gate refuses nothing that would otherwise be served, and adding
	// it cannot break a caller — it is defense in depth and plane parity, and it
	// makes the handler's trust assumption checkable where the handler is used
	// directly. The load-bearing part of #3135 is mapHITLActorIdentity.
	if ok, msg := verifyAgentProxyAuth(r, "MAP-HITL-Approve"); !ok {
		sendErrorResponse(w, msg, http.StatusForbidden)
		return
	}

	// Tier gating matches WCP /approve (Evaluation+ via tier checker, Enterprise via
	// DEPLOYMENT_MODE). Prior to v7.4.0 this was blanket-blocked in community mode
	// even when an Evaluation license was present — a pre-existing inconsistency
	// with WCP that the parity work surfaced. Now both planes accept Evaluation+.
	if isCommunityMode() && (tierChecker == nil || !tierChecker.IsHITLApprovalEnabled()) {
		sendErrorResponse(w, "MAP step approval requires Evaluation or Enterprise license", http.StatusForbidden)
		return
	}

	if !hitlEnabled || hitlWorkflowEngine == nil {
		sendErrorResponse(w, "HITL not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	stepID := vars["step_id"]

	if planID == "" || stepID == "" {
		sendErrorResponse(w, "Plan ID and Step ID are required", http.StatusBadRequest)
		return
	}

	// Parse the optional body for the approval comment. Comment validation
	// mirrors WCP /approve (min 10 chars) only when WCP-backed path is taken;
	// legacy in-memory path accepts empty body for back-compat.
	//
	// #3135: `approved_by` is deliberately NOT a field here. The struct is the
	// enforcement — an identity the caller can type cannot be read back out by
	// accident. Clients that still send it (the field was accepted before
	// v9.13.0) are unaffected: encoding/json ignores unknown keys, so the
	// request still succeeds, it is just no longer the caller who decides whose
	// name goes in the audit trail.
	var body struct {
		Comment string `json:"comment"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	body.Comment = strings.TrimSpace(body.Comment)

	// #3135: header-authoritative, body ignored — see mapHITLActorIdentity.
	approvedBy := mapHITLActorIdentity(r)
	if approvedBy == "" {
		approvedBy = "system"
	}

	log.Printf("[MAP-HITL] Step approval for plan %s, step %s", logutil.Sanitize(planID), logutil.Sanitize(stepID))

	// Path 1 — try WCP-backed flow. If a WCP workflow is registered for this
	// plan_id (MAP confirm/step mode), delegate so the response matches the
	// WCP approve response byte-for-byte. Returns (resp, true, nil) on success,
	// (_, false, nil) when no WCP workflow matches (fall through to legacy),
	// or (_, false, err) when the WCP-backed path hit a real error (surface it).
	if workflowControlService != nil {
		resp, wcpBacked, wcpErr := tryApproveViaWCP(r.Context(), planID, stepID, r, approvedBy, body.Comment)
		if wcpErr != nil {
			sendErrorResponse(w, wcpErr.Error(), http.StatusConflict)
			return
		}
		if wcpBacked {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// Path 2 — legacy in-memory flow. Locate the paused execution, mark it
	// approved, and project a best-effort StepGateHTTPResponse. No WCP step
	// row exists, so retry_context stays zero-valued; ApprovalID is surfaced
	// from the execution record when available.
	//
	// #3067 (S-4, CRITICAL): this scan matched on plan id ALONE across a
	// process-global store and then flipped ApprovalStatus to approved and
	// Status to running — so any tenant could release another tenant's
	// paused, human-gated workflow. A foreign plan reliably reached this path
	// because path 1 (GetWorkflowByPlanID) returns not-found under the
	// caller's own tenancy. The lookup is now bound to the caller's org
	// scope; a caller that asserts no scope matches nothing.
	callerScope := mapHITLCallerScope(r)

	executionStoreMutex.Lock()
	targetExec := findPausedHITLExecutionForPlan(callerScope, planID)
	if targetExec != nil {
		targetExec.ApprovalStatus = StatusApproved
		targetExec.Status = "running"
	}
	executionStoreMutex.Unlock()

	if targetExec == nil {
		sendErrorResponse(w, "No paused execution found for this plan", http.StatusNotFound)
		return
	}

	log.Printf("[MAP-HITL] Execution %s approved and resumed for plan %s, step %s",
		targetExec.ID, logutil.Sanitize(planID), logutil.Sanitize(stepID))

	resp := workflow_control.ProjectStepGateToHTTP(
		"", // no WCP workflow_id in legacy path
		planID,
		nil, // no WCP step row
		workflow_control.ApproverMeta{ApprovalID: targetExec.ApprovalID.String()},
		"Step approved",
		false,
	)
	resp.StepID = stepID
	approved := workflow_control.ApprovalStatusApproved
	resp.ApprovalStatus = &approved
	resp.Status = string(approved) // legacy `status` mirror
	resp.ApprovedBy = approvedBy

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("[MAP-HITL] Error encoding response: %v", err)
	}
}

// tryApproveViaWCP delegates to the WCP service for plans backed by a WCP
// workflow (MAP confirm / step modes). Returns (response, true) on success,
// (_, false) when no WCP workflow exists for this plan (caller should fall
// back to the legacy flow). Errors other than not-found short-circuit the
// HTTP response via the caller's ResponseWriter.
// tryApproveViaWCP delegates to the WCP service for plans backed by a WCP
// workflow (MAP confirm / step modes).
//
// Return semantics:
//   - (resp, true,  nil)  — WCP path succeeded, resp is the rich projection
//   - (_,    false, nil)  — no WCP workflow exists for this plan (caller must
//     fall back to the legacy in-memory flow)
//   - (_,    false, err)  — plan IS WCP-backed but the subsequent operation
//     failed; caller should surface the error rather than silently falling
//     through to legacy (which would mask "step not pending approval" type
//     errors as generic "No paused execution found")
func tryApproveViaWCP(
	ctx context.Context,
	planID, stepID string,
	r *http.Request,
	approvedBy, comment string,
) (workflow_control.StepGateHTTPResponse, bool, error) {
	// WCP uses X-Tenant-ID for the tenantID argument on its service methods
	// (see Handler.getClientID — `clientID` is a WCP-internal alias for the
	// same header). The MAP handler mirrors that convention so a plan-scoped
	// caller authenticates identically to a workflow-scoped one.
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Org-ID")

	wf, err := workflowControlService.GetWorkflowByPlanID(ctx, planID, tenantID, orgID)
	if err != nil {
		if errors.Is(err, workflow_control.ErrWorkflowNotFound) {
			return workflow_control.StepGateHTTPResponse{}, false, nil
		}
		log.Printf("[MAP-HITL] GetWorkflowByPlanID error for plan %s: %v", logutil.Sanitize(planID), err)
		return workflow_control.StepGateHTTPResponse{}, false, nil
	}

	effectiveComment := comment
	if len(effectiveComment) < 10 {
		// WCP service layer enforces min-10 on the comment; MAP's legacy API
		// didn't require it, so synthesize a default to keep the confirm/step
		// mode usable via the plan endpoint without breaking the audit trail.
		effectiveComment = fmt.Sprintf("MAP plan %s step approved via /plans endpoint", planID)
	}

	if err := workflowControlService.ApproveStep(ctx, wf.WorkflowID, stepID, tenantID, orgID, approvedBy, effectiveComment); err != nil {
		log.Printf("[MAP-HITL] WCP ApproveStep error for plan %s step %s: %v",
			logutil.Sanitize(planID), logutil.Sanitize(stepID), err)
		return workflow_control.StepGateHTTPResponse{}, false, err
	}

	step, err := workflowControlService.GetStep(ctx, wf.WorkflowID, stepID, tenantID, orgID)
	if err != nil {
		log.Printf("[MAP-HITL] GetStep error post-approve for %s/%s: %v", wf.WorkflowID, stepID, err)
		return workflow_control.ProjectStepGateToHTTP(
			wf.WorkflowID, planID, nil,
			workflow_control.ApproverMeta{},
			"Step approved", false,
		), true, nil
	}

	approver := workflow_control.ApproverMeta{
		ApprovalID: workflow_control.DeriveHITLApprovalID(wf.WorkflowID, stepID),
	}
	return workflow_control.ProjectStepGateToHTTP(
		wf.WorkflowID, planID, step, approver, "Step approved", false,
	), true, nil
}

// mapStepRejectHandler handles POST /api/v1/plans/{id}/steps/{step_id}/reject.
// Symmetric to mapStepApproveHandler — two paths (WCP-backed, legacy in-memory)
// that share the same StepGateHTTPResponse shape (Issue #1677).
func mapStepRejectHandler(w http.ResponseWriter, r *http.Request) {
	// #3135: same agent proxy-auth gate as the approve path — see
	// mapStepApproveHandler for why it is here and what it is (and is not)
	// load-bearing for.
	if ok, msg := verifyAgentProxyAuth(r, "MAP-HITL-Reject"); !ok {
		sendErrorResponse(w, msg, http.StatusForbidden)
		return
	}

	// Tier gating matches WCP /reject — see mapStepApproveHandler for the context.
	if isCommunityMode() && (tierChecker == nil || !tierChecker.IsHITLApprovalEnabled()) {
		sendErrorResponse(w, "MAP step rejection requires Evaluation or Enterprise license", http.StatusForbidden)
		return
	}

	if !hitlEnabled || hitlWorkflowEngine == nil {
		sendErrorResponse(w, "HITL not enabled", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	planID := vars["id"]
	stepID := vars["step_id"]

	if planID == "" || stepID == "" {
		sendErrorResponse(w, "Plan ID and Step ID are required", http.StatusBadRequest)
		return
	}

	// #3135: `rejected_by` is deliberately NOT a field here — see the approve
	// handler's body struct for why, and mapHITLActorIdentity for the contract.
	var body struct {
		Reason string `json:"reason"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	body.Reason = strings.TrimSpace(body.Reason)

	// #3135: header-authoritative, body ignored — see mapHITLActorIdentity.
	rejectedBy := mapHITLActorIdentity(r)
	if rejectedBy == "" {
		rejectedBy = "system"
	}

	log.Printf("[MAP-HITL] Step rejection for plan %s, step %s: %s",
		logutil.Sanitize(planID), logutil.Sanitize(stepID), logutil.Sanitize(body.Reason))

	// Path 1 — WCP-backed reject (confirm / step mode). See tryApproveViaWCP
	// comment for the tri-valued return contract.
	if workflowControlService != nil {
		resp, wcpBacked, wcpErr := tryRejectViaWCP(r.Context(), planID, stepID, r, rejectedBy, body.Reason)
		if wcpErr != nil {
			sendErrorResponse(w, wcpErr.Error(), http.StatusConflict)
			return
		}
		if wcpBacked {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
	}

	// Path 2 — legacy in-memory flow. Bound to the caller's org scope for the
	// same reason as the approve path (#3067 S-4): rejecting another tenant's
	// paused execution aborts their workflow.
	callerScope := mapHITLCallerScope(r)

	executionStoreMutex.Lock()
	targetExec := findPausedHITLExecutionForPlan(callerScope, planID)
	executionStoreMutex.Unlock()

	if targetExec == nil {
		sendErrorResponse(w, "No paused execution found for this plan", http.StatusNotFound)
		return
	}

	reason := body.Reason
	if reason == "" {
		reason = "Step rejected"
	}
	// Carry the caller's scope so the approval-status lookup AbortExecution
	// performs is bound too.
	_, _ = hitlWorkflowEngine.AbortExecution(WithHITLScope(r.Context(), callerScope), targetExec, reason)

	resp := workflow_control.ProjectStepGateToHTTP(
		"", planID, nil,
		workflow_control.ApproverMeta{ApprovalID: targetExec.ApprovalID.String()},
		"Step rejected, workflow aborted",
		false,
	)
	resp.StepID = stepID
	rejected := workflow_control.ApprovalStatusRejected
	resp.ApprovalStatus = &rejected
	resp.Status = string(rejected) // legacy `status` mirror
	resp.RejectedBy = rejectedBy
	resp.Reason = reason

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// mapPendingApprovalsHandler handles GET /api/v1/plans/approvals/pending.
//
// The MAP-plane counterpart to WCP's GET /api/v1/workflows/approvals/pending
// (Issue #1680). Lists steps currently awaiting approval across MAP-backed
// workflows for the caller's tenant — i.e. workflows whose metadata carries a
// plan_id (MAP confirm/step mode creates them; native WCP workflows don't).
//
// Every returned entry has plan_id populated — the intentional asymmetry
// with the WCP endpoint, mirroring the approve/reject asymmetry established
// in #1677/ADR-046. Reviewer tooling that needs to branch on plane can read
// plan_id without a second lookup.
//
// Query parameters:
//   - plan_id=<id> — optional filter to a single plan
//   - limit=<n>   — optional result cap (default 20, same as WCP)
//
// Tier gate matches the MAP approve/reject handlers: Evaluation+ via
// IsHITLApprovalEnabled(), Enterprise via !isCommunityMode().
func mapPendingApprovalsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Tier gating — matches mapStepApproveHandler. Evaluation+ via IsHITLApprovalEnabled,
	// Enterprise via !isCommunityMode. Community-without-eval blocked with 403.
	if isCommunityMode() && (tierChecker == nil || !tierChecker.IsHITLApprovalEnabled()) {
		sendErrorResponse(w, "Listing plan-scoped pending approvals requires Evaluation or Enterprise license", http.StatusForbidden)
		return
	}

	if workflowControlService == nil {
		sendErrorResponse(w, "Workflow control plane unavailable", http.StatusServiceUnavailable)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		sendErrorResponse(w, "X-Tenant-ID header is required", http.StatusBadRequest)
		return
	}

	planIDFilter := strings.TrimSpace(r.URL.Query().Get("plan_id"))

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	approvals, err := workflowControlService.GetPendingPlanApprovals(r.Context(), tenantID, planIDFilter, limit)
	if err != nil {
		log.Printf("[MAP-HITL] GetPendingPlanApprovals error: %v", err)
		sendErrorResponse(w, "Failed to get pending plan approvals", http.StatusInternalServerError)
		return
	}

	total, countErr := workflowControlService.CountPendingPlanApprovals(r.Context(), tenantID, planIDFilter)
	if countErr != nil {
		log.Printf("[MAP-HITL] CountPendingPlanApprovals error: %v", countErr)
		total = len(approvals)
	}

	// Emit an empty list instead of nil so JSON stays `[]` not `null` — mirrors
	// the WCP pending-list contract that reviewer UIs rely on.
	if approvals == nil {
		approvals = []workflow_control.PendingApprovalResponse{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_approvals": approvals,
		"count":             total,
	})
}

// tryRejectViaWCP mirrors tryApproveViaWCP for the reject path. Same tri-valued
// return contract — see that function for the semantics.
func tryRejectViaWCP(
	ctx context.Context,
	planID, stepID string,
	r *http.Request,
	rejectedBy, reason string,
) (workflow_control.StepGateHTTPResponse, bool, error) {
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Org-ID")

	wf, err := workflowControlService.GetWorkflowByPlanID(ctx, planID, tenantID, orgID)
	if err != nil {
		if errors.Is(err, workflow_control.ErrWorkflowNotFound) {
			return workflow_control.StepGateHTTPResponse{}, false, nil
		}
		log.Printf("[MAP-HITL] GetWorkflowByPlanID error for plan %s: %v", logutil.Sanitize(planID), err)
		return workflow_control.StepGateHTTPResponse{}, false, nil
	}

	effectiveReason := reason
	if len(effectiveReason) < 10 {
		effectiveReason = fmt.Sprintf("MAP plan %s step rejected via /plans endpoint", planID)
	}

	if err := workflowControlService.RejectStep(ctx, wf.WorkflowID, stepID, tenantID, orgID, rejectedBy, effectiveReason); err != nil {
		log.Printf("[MAP-HITL] WCP RejectStep error for plan %s step %s: %v",
			logutil.Sanitize(planID), logutil.Sanitize(stepID), err)
		return workflow_control.StepGateHTTPResponse{}, false, err
	}

	step, err := workflowControlService.GetStep(ctx, wf.WorkflowID, stepID, tenantID, orgID)
	if err != nil {
		log.Printf("[MAP-HITL] GetStep error post-reject for %s/%s: %v", wf.WorkflowID, stepID, err)
		return workflow_control.ProjectStepGateToHTTP(
			wf.WorkflowID, planID, nil,
			workflow_control.ApproverMeta{},
			"Step rejected, workflow aborted", false,
		), true, nil
	}

	approver := workflow_control.ApproverMeta{
		ApprovalID: workflow_control.DeriveHITLApprovalID(wf.WorkflowID, stepID),
	}
	return workflow_control.ProjectStepGateToHTTP(
		wf.WorkflowID, planID, step, approver,
		"Step rejected, workflow aborted", false,
	), true, nil
}
