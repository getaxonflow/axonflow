// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// HITL-Aware Workflow Execution
// Enables pause/resume for require_approval policy action

package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	logutil "axonflow/platform/shared/logger"
)

// ErrExecutionNotFound is returned when an execution ID is not found in storage.
var ErrExecutionNotFound = errors.New("execution not found")

// executionStore provides thread-safe in-memory storage for HITL executions.
// For production, replace with database-backed storage.
//
// #3067 (S-4): entries are keyed by `orgScope + NUL + executionID`, not by
// execution id alone. The MAP approve/reject handlers used to SCAN this flat
// map matching on plan id only and then flip ApprovalStatus to approved —
// letting any tenant release another tenant's paused, human-gated workflow.
// That is the in-memory twin of the #3049 R3 blocker (HITL approve forgery
// via a BYPASSRLS lookup); it was invisible to that census because this
// store issues no SQL. Keying by the owning org means a scan cannot reach
// outside the caller's scope even when the caller knows the plan id.
var (
	executionStore      = make(map[string]*HITLWorkflowExecution)
	executionStoreMutex sync.RWMutex
)

// hitlScopeSep separates the org scope from the execution id in the store's
// composite keys. NUL appears in neither component.
const hitlScopeSep = "\x00"

// normalizeHITLScope reduces an (orgID, tenantID) pair to the single canonical
// scope used as the store's key prefix.
//
// Both sides of every comparison are produced by this one function from the
// same pair of headers: executeWorkflowHandler re-derives
// User.OrgID/User.TenantID from X-Org-ID/X-Tenant-ID and executePlanHandler
// calls applyAuthoritativeIdentity, while the approve/reject handlers read
// those headers directly. OrgID wins because org_id is the canonical tenancy
// identifier post-Phase-6; TenantID is the pre-org fallback still used in
// community mode.
//
// Both writer-side overlays are CONDITIONAL on the header being non-empty —
// run.go guards each with `if header != ""`, and applyAuthoritativeIdentity
// returns early when both are empty — and `req.User` is itself a JSON body
// field. So the headers are authoritative only for a caller that carries them;
// a caller reaching the orchestrator directly with none still picks its own
// scope out of the body. That is not a regression (pre-#3066-C3-1 the body was
// preferred OVER the header, so the agent-proxied path is now strictly
// closed), and it is not closed here: the router-level gate in #3073
// (#3064/#3068) is what guarantees a caller cannot reach the orchestrator
// without an authenticated identity. Read this comment as "the store keys
// consistently off whatever scope was resolved", not as proof that the scope
// is always agent-authenticated.
func normalizeHITLScope(orgID, tenantID string) string {
	if orgID != "" {
		return orgID
	}
	return tenantID
}

// executionScope returns the canonical scope that owns an execution.
// It reads UserContext only — never execution.Input, which is the
// client-supplied request body.
func executionScope(exec *HITLWorkflowExecution) string {
	if exec == nil || exec.WorkflowExecution == nil {
		return ""
	}
	return normalizeHITLScope(exec.UserContext.OrgID, exec.UserContext.TenantID)
}

// hitlStoreKey builds the composite store key.
func hitlStoreKey(scope, executionID string) string {
	return scope + hitlScopeSep + executionID
}

// saveHITLExecution stores an execution under its owning scope. An execution
// with no resolvable scope is stored under the empty scope, which no
// authenticated caller can ever match (every accessor refuses an empty
// caller scope) — fail-closed rather than globally visible.
func saveHITLExecution(exec *HITLWorkflowExecution) {
	if exec == nil || exec.WorkflowExecution == nil {
		return
	}
	executionStoreMutex.Lock()
	defer executionStoreMutex.Unlock()
	executionStore[hitlStoreKey(executionScope(exec), exec.ID)] = exec
}

// lookupHITLExecution returns the execution with this id IF it belongs to the
// caller's scope. An empty scope never matches.
func lookupHITLExecution(scope, executionID string) (*HITLWorkflowExecution, bool) {
	if scope == "" {
		return nil, false
	}
	executionStoreMutex.RLock()
	defer executionStoreMutex.RUnlock()
	exec, ok := executionStore[hitlStoreKey(scope, executionID)]
	return exec, ok
}

// findPausedHITLExecutionForPlan returns the paused execution belonging to
// scope that corresponds to planID, or nil. The plan-id predicate is
// unchanged from the legacy handler; what changed is that the iteration only
// ever considers entries whose key carries the caller's own scope.
//
// The caller must hold executionStoreMutex (read or write) — the approve path
// needs the write lock across find-and-mutate, so the locking cannot live in
// here.
func findPausedHITLExecutionForPlan(scope, planID string) *HITLWorkflowExecution {
	if scope == "" || planID == "" {
		return nil
	}
	prefix := scope + hitlScopeSep
	for key, exec := range executionStore {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if exec == nil || exec.WorkflowExecution == nil || exec.Status != StatusPaused {
			continue
		}
		if exec.WorkflowName == "plan-"+planID ||
			exec.ID == planID ||
			(exec.Input != nil && exec.Input["plan_id"] == planID) {
			return exec
		}
	}
	return nil
}

// findHITLExecutionByApproval returns the execution in scope carrying this
// approval id, or nil.
//
// The caller must hold executionStoreMutex (read or write).
func findHITLExecutionByApproval(scope string, approvalID uuid.UUID) *HITLWorkflowExecution {
	if scope == "" || approvalID == uuid.Nil {
		return nil
	}
	prefix := scope + hitlScopeSep
	for key, exec := range executionStore {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if exec != nil && exec.ApprovalID == approvalID {
			return exec
		}
	}
	return nil
}

// hitlScopeCtxKey carries the caller's HITL scope through a context so the
// HITLApprovalService implementations (whose interface signature is fixed by
// HITLApprovalService and shared with the WCP-backed path) can bind their
// store scans without a signature change.
type hitlScopeCtxKey struct{}

// WithHITLScope returns a context carrying the caller's HITL org scope.
func WithHITLScope(ctx context.Context, scope string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, hitlScopeCtxKey{}, scope)
}

// hitlScopeFromContext reads the caller's HITL org scope. The empty string
// means "not asserted", and every consumer treats that as no-match.
func hitlScopeFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if scope, ok := ctx.Value(hitlScopeCtxKey{}).(string); ok {
		return scope
	}
	return ""
}

// HITL execution status constants
const (
	// StatusPaused indicates execution is waiting for human approval.
	StatusPaused = "paused"
	// StatusApproved indicates human approval was granted.
	StatusApproved = "approved"
	// StatusRejected indicates human rejection.
	StatusRejected = "rejected"
	// StatusExpired indicates approval request expired.
	StatusExpired = "expired"
)

// HITLWorkflowExecution extends WorkflowExecution with HITL support.
type HITLWorkflowExecution struct {
	*WorkflowExecution

	// ApprovalID is the UUID of the pending HITL approval request.
	ApprovalID uuid.UUID `json:"approval_id,omitempty"`

	// ApprovalStatus is the current status of the approval.
	ApprovalStatus string `json:"approval_status,omitempty"`

	// PausedAtStep is the index of the step where execution was paused.
	PausedAtStep int `json:"paused_at_step,omitempty"`

	// PausedReason explains why execution was paused.
	PausedReason string `json:"paused_reason,omitempty"`

	// ResumedAt is when execution was resumed after approval.
	ResumedAt *time.Time `json:"resumed_at,omitempty"`
}

// HITLStepExecution extends StepExecution with HITL support.
type HITLStepExecution struct {
	StepExecution

	// RequiredApproval indicates this step triggered require_approval.
	RequiredApproval bool `json:"required_approval,omitempty"`

	// ApprovalID is the UUID of the approval request for this step.
	ApprovalID uuid.UUID `json:"approval_id,omitempty"`
}

// PolicyCheckResult represents the result of a pre-step policy check.
type PolicyCheckResult struct {
	Allowed    bool
	Action     string // block, require_approval, warn, log
	PolicyID   string
	PolicyName string
	Reason     string
	Severity   string
}

// HITLPolicyChecker is the interface for checking policies before step execution.
type HITLPolicyChecker interface {
	CheckPolicy(ctx context.Context, step WorkflowStep, execution *WorkflowExecution) (*PolicyCheckResult, error)
}

// HITLApprovalService is the interface for creating and managing HITL approvals.
type HITLApprovalService interface {
	CreateApproval(ctx context.Context, req *HITLApprovalRequest) (*HITLApprovalResponse, error)
	GetApproval(ctx context.Context, approvalID uuid.UUID) (*HITLApprovalResponse, error)
}

// HITLApprovalRequest contains data for creating an HITL approval.
type HITLApprovalRequest struct {
	OrgID          string
	TenantID       string
	ClientID       string
	UserID         string
	ExecutionID    string
	StepName       string
	StepType       string
	PolicyID       string
	PolicyName     string
	TriggerReason  string
	Severity       string
	RequestContext map[string]interface{}
}

// HITLApprovalResponse contains the approval details.
type HITLApprovalResponse struct {
	ApprovalID uuid.UUID
	Status     string // pending, approved, rejected, expired
	ReviewerID string
	Comment    string
	CreatedAt  time.Time
	ReviewedAt *time.Time
	ExpiresAt  time.Time
	// Enqueue is the classification the shared HITL chokepoint returned for
	// a CreateApproval call: "created" or "reused" (see
	// platform/agent/hitl/queue.Outcome). Empty on the read path
	// (GetApproval) and on implementations that do not enqueue, such as
	// MAPHITLApprovalAdapter's in-memory tracking. Callers surface it as
	// StepGateResponse.approval_enqueue so a re-gate is distinguishable from
	// a first gate without a second query.
	Enqueue string
}

// hitlAuditLogger is the audit dependency of the HITL engine: just the canonical
// workflow-operation writer. Narrowing to an interface (rather than holding the
// concrete *AuditLogger) lets a test inject a recording fake and assert the
// step_gate row deterministically, with no async worker or database. *AuditLogger
// satisfies it.
type hitlAuditLogger interface {
	LogWorkflowOperation(ctx context.Context, entry *WorkflowAuditEntry)
}

// HITLWorkflowEngine wraps WorkflowEngine with HITL support.
type HITLWorkflowEngine struct {
	engine          *WorkflowEngine
	policyChecker   HITLPolicyChecker
	approvalService HITLApprovalService

	// auditLogger records the policy GATE decision (block / require_approval) for
	// each step to the canonical audit_logs feed (#2693). Optional: a nil logger
	// (engine constructed without one) makes the audit a no-op. Wired via
	// SetAuditLogger so the existing 3-arg constructor and all its callers are
	// unchanged.
	auditLogger hitlAuditLogger
}

// NewHITLWorkflowEngine creates a new HITL-aware workflow engine.
func NewHITLWorkflowEngine(engine *WorkflowEngine, checker HITLPolicyChecker, approval HITLApprovalService) *HITLWorkflowEngine {
	return &HITLWorkflowEngine{
		engine:          engine,
		policyChecker:   checker,
		approvalService: approval,
	}
}

// SetAuditLogger wires the canonical audit writer onto the engine so the
// block / require_approval gate decisions are recorded to audit_logs (#2693).
// Mirrors the SetAuditLogger pattern used for the MAP/WCP services in run.go. A
// nil logger leaves the engine in its (audit-silent) default state.
func (e *HITLWorkflowEngine) SetAuditLogger(l hitlAuditLogger) {
	e.auditLogger = l
}

// auditStepGate records a policy GATE decision (block or require_approval) for a
// workflow step to the canonical audit_logs feed via the established
// LogWorkflowOperation writer (#2693). The legacy in-memory HITL engine
// (AXONFLOW_HITL_ENABLED, default-OFF) previously ENFORCED these terminal
// verdicts — failing the workflow on block, pausing on require_approval — with no
// audit row, asymmetric with the WCP path. No new writer or table:
// WorkflowAuditEntry.Decision ("block" | "require_approval") is mapped onto the
// canonical policy_decision vocabulary by workflowAuditDecision. A nil
// auditLogger is a no-op.
func (e *HITLWorkflowEngine) auditStepGate(ctx context.Context, exec *HITLWorkflowExecution, workflowName string, step WorkflowStep, pr *PolicyCheckResult, user UserContext) {
	if e.auditLogger == nil || pr == nil {
		return
	}
	e.auditLogger.LogWorkflowOperation(ctx, &WorkflowAuditEntry{
		WorkflowID:   exec.ID,
		WorkflowName: workflowName,
		StepName:     step.Name,
		Operation:    "step_gate",
		Decision:     pr.Action, // "block" | "require_approval" → canonical via workflowAuditDecision
		Reason:       pr.Reason,
		TenantID:     user.TenantID,
		OrgID:        user.OrgID,
		UserEmail:    user.Email,
		UserRole:     user.Role,
		Metadata: map[string]interface{}{
			"policy_id":   pr.PolicyID,
			"policy_name": pr.PolicyName,
			"severity":    pr.Severity,
			"step_type":   step.Type,
		},
	})
}

// auditStepGateError records the FAIL-OPEN-on-policy-ERROR path (#2698) to the
// canonical audit_logs feed. The legacy in-memory HITL engine fails OPEN when the
// policy checker returns an error — it proceeds with execution for availability,
// a deliberate design choice — but the errored governance verdict was previously
// LOST (only a log.Printf). This records a canonical `error` step_gate row via the
// same LogWorkflowOperation seam #2693 used; the engine STILL proceeds (fail-open
// behavior unchanged), the verdict is just no longer silently unrecorded. The
// reason is the policy-check failure text (an engine/eval error string, no
// request content). A nil auditLogger is a no-op.
func (e *HITLWorkflowEngine) auditStepGateError(ctx context.Context, exec *HITLWorkflowExecution, workflowName string, step WorkflowStep, checkErr error, user UserContext) {
	if e.auditLogger == nil || checkErr == nil {
		return
	}
	e.auditLogger.LogWorkflowOperation(ctx, &WorkflowAuditEntry{
		WorkflowID:   exec.ID,
		WorkflowName: workflowName,
		StepName:     step.Name,
		Operation:    "step_gate",
		Decision:     "error", // → canonical DecisionError via workflowAuditDecision (#2698)
		Reason:       fmt.Sprintf("policy check error (fail-open): %v", checkErr),
		TenantID:     user.TenantID,
		OrgID:        user.OrgID,
		UserEmail:    user.Email,
		UserRole:     user.Role,
		Metadata: map[string]interface{}{
			"fail_open": true,
			"step_type": step.Type,
		},
	})
}

// ExecuteWithHITL executes a workflow with HITL pause/resume support.
func (e *HITLWorkflowEngine) ExecuteWithHITL(ctx context.Context, workflow Workflow, input map[string]interface{}, user UserContext) (*HITLWorkflowExecution, error) {
	baseExec, err := e.createExecution(workflow, input, user)
	if err != nil {
		return nil, err
	}

	hitlExec := &HITLWorkflowExecution{
		WorkflowExecution: baseExec,
	}

	for i, step := range workflow.Spec.Steps {
		if e.policyChecker != nil {
			policyResult, err := e.policyChecker.CheckPolicy(ctx, step, baseExec)
			if err != nil {
				// DESIGN DECISION: Fail-open for availability.
				// Policy check errors should not block workflow execution.
				// This prioritizes availability over strict enforcement.
				// For fail-closed behavior, configure the policy checker to return
				// a blocking PolicyCheckResult on error instead of returning an error.
				log.Printf("[HITL] WARNING: Policy check error for step %s: %v - proceeding with execution (fail-open)", step.Name, err)
				// #2698: record the errored governance verdict before proceeding.
				// The engine still fails OPEN (availability), but the error is no
				// longer lost from the audit trail.
				e.auditStepGateError(ctx, hitlExec, workflow.Metadata.Name, step, err, user)
			} else if policyResult != nil {
				switch policyResult.Action {
				case "block":
					// Audit the terminal block BEFORE returning — this verdict
					// withholds the step and must leave a trail (#2693).
					e.auditStepGate(ctx, hitlExec, workflow.Metadata.Name, step, policyResult, user)
					hitlExec.Status = "failed"
					hitlExec.Error = fmt.Sprintf("Blocked by policy %s: %s", policyResult.PolicyName, policyResult.Reason)
					return hitlExec, fmt.Errorf("execution blocked by policy: %s", policyResult.PolicyName)

				case "require_approval":
					// Audit the gate decision before pausing for approval (#2693).
					e.auditStepGate(ctx, hitlExec, workflow.Metadata.Name, step, policyResult, user)
					return e.pauseForApproval(ctx, hitlExec, i, step, policyResult, user)

				case "warn":
					log.Printf("[HITL] Warning for step %s: Policy %s triggered - %s",
						step.Name, policyResult.PolicyName, policyResult.Reason)

				case "log":
					log.Printf("[HITL] Audit: Step %s triggered policy %s",
						step.Name, policyResult.PolicyName)
				}
			}
		}

		stepExec, err := e.executeStep(ctx, step, input, hitlExec)
		if err != nil {
			hitlExec.Status = "failed"
			hitlExec.Error = err.Error()
			return hitlExec, err
		}

		if stepExec.Output != nil {
			for key, value := range stepExec.Output {
				input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
			}
		}
	}

	hitlExec.Status = "completed"
	now := time.Now()
	hitlExec.EndTime = &now

	return hitlExec, nil
}

// pauseForApproval pauses execution and creates an HITL approval request.
func (e *HITLWorkflowEngine) pauseForApproval(
	ctx context.Context,
	exec *HITLWorkflowExecution,
	stepIndex int,
	step WorkflowStep,
	policyResult *PolicyCheckResult,
	user UserContext,
) (*HITLWorkflowExecution, error) {
	exec.Status = StatusPaused
	exec.PausedAtStep = stepIndex
	exec.PausedReason = fmt.Sprintf("Policy %s requires human approval: %s",
		policyResult.PolicyName, policyResult.Reason)

	if e.approvalService != nil {
		req := &HITLApprovalRequest{
			TenantID:      user.TenantID,
			UserID:        fmt.Sprintf("%d", user.ID),
			ExecutionID:   exec.ID,
			StepName:      step.Name,
			StepType:      step.Type,
			PolicyID:      policyResult.PolicyID,
			PolicyName:    policyResult.PolicyName,
			TriggerReason: policyResult.Reason,
			Severity:      policyResult.Severity,
		}

		resp, err := e.approvalService.CreateApproval(ctx, req)
		if err != nil {
			log.Printf("[HITL] Failed to create approval request: %v", err)
			exec.Error = fmt.Sprintf("Failed to create approval: %v", err)
			return exec, err
		}

		exec.ApprovalID = resp.ApprovalID
		exec.ApprovalStatus = resp.Status
	}

	log.Printf("[HITL] Execution %s paused at step %d (%s) - awaiting approval %s",
		exec.ID, stepIndex, step.Name, exec.ApprovalID)

	return exec, nil
}

// ResumeExecution resumes a paused execution after approval.
func (e *HITLWorkflowEngine) ResumeExecution(ctx context.Context, exec *HITLWorkflowExecution, workflow Workflow, input map[string]interface{}) (*HITLWorkflowExecution, error) {
	if exec.Status != StatusPaused {
		return nil, fmt.Errorf("execution is not paused, status: %s", exec.Status)
	}

	if e.approvalService != nil && exec.ApprovalID != uuid.Nil {
		approval, err := e.approvalService.GetApproval(ctx, exec.ApprovalID)
		if err != nil {
			return nil, fmt.Errorf("failed to get approval status: %w", err)
		}

		if approval.Status != "approved" && approval.Status != "overridden" {
			return nil, fmt.Errorf("cannot resume: approval status is %s", approval.Status)
		}

		exec.ApprovalStatus = approval.Status
	}

	now := time.Now()
	exec.ResumedAt = &now
	exec.Status = "running"

	log.Printf("[HITL] Resuming execution %s from step %d", exec.ID, exec.PausedAtStep)

	for i := exec.PausedAtStep; i < len(workflow.Spec.Steps); i++ {
		step := workflow.Spec.Steps[i]

		stepExec, err := e.executeStep(ctx, step, input, exec)
		if err != nil {
			exec.Status = "failed"
			exec.Error = err.Error()
			return exec, err
		}

		if stepExec.Output != nil {
			for key, value := range stepExec.Output {
				input[fmt.Sprintf("step_%s_%s", step.Name, key)] = value
			}
		}
	}

	exec.Status = "completed"
	endTime := time.Now()
	exec.EndTime = &endTime

	return exec, nil
}

// AbortExecution aborts a paused execution after rejection.
func (e *HITLWorkflowEngine) AbortExecution(ctx context.Context, exec *HITLWorkflowExecution, reason string) (*HITLWorkflowExecution, error) {
	if exec.Status != StatusPaused {
		return nil, fmt.Errorf("execution is not paused, status: %s", exec.Status)
	}

	exec.Status = "aborted"
	now := time.Now()
	exec.EndTime = &now
	exec.Error = fmt.Sprintf("Execution aborted: %s", reason)

	if e.approvalService != nil && exec.ApprovalID != uuid.Nil {
		approval, _ := e.approvalService.GetApproval(ctx, exec.ApprovalID)
		if approval != nil {
			exec.ApprovalStatus = approval.Status
		}
	}

	log.Printf("[HITL] Execution %s aborted: %s", exec.ID, logutil.Sanitize(reason))

	return exec, nil
}

// createExecution creates a new workflow execution.
func (e *HITLWorkflowEngine) createExecution(workflow Workflow, input map[string]interface{}, user UserContext) (*WorkflowExecution, error) {
	return &WorkflowExecution{
		ID:           newEngineExecutionID(),
		WorkflowName: workflow.Metadata.Name,
		Status:       "running",
		Input:        input,
		Output:       make(map[string]interface{}),
		Steps:        make([]StepExecution, 0),
		StartTime:    time.Now(),
		UserContext:  user,
	}, nil
}

// executeStep executes a single workflow step.
func (e *HITLWorkflowEngine) executeStep(ctx context.Context, step WorkflowStep, input map[string]interface{}, exec *HITLWorkflowExecution) (*StepExecution, error) {
	stepExec := StepExecution{
		Name:      step.Name,
		Status:    "running",
		StartTime: time.Now(),
		Input:     input,
	}

	exec.Steps = append(exec.Steps, stepExec)

	processor, exists := e.engine.stepProcessors[step.Type]
	if !exists {
		stepExec.Status = "failed"
		stepExec.Error = fmt.Sprintf("unknown step type: %s", step.Type)
		exec.Steps[len(exec.Steps)-1] = stepExec
		return &stepExec, fmt.Errorf("unknown step type: %s", step.Type)
	}

	output, err := processor.ExecuteStep(ctx, step, input, exec.WorkflowExecution)
	now := time.Now()
	stepExec.EndTime = &now
	stepExec.ProcessTime = now.Sub(stepExec.StartTime).String()

	if err != nil {
		stepExec.Status = "failed"
		stepExec.Error = err.Error()
		exec.Steps[len(exec.Steps)-1] = stepExec
		return &stepExec, err
	}

	stepExec.Status = "completed"
	stepExec.Output = output
	exec.Steps[len(exec.Steps)-1] = stepExec

	log.Printf("[HITL] Completed step: %s in %s", step.Name, stepExec.ProcessTime)

	return &stepExec, nil
}

// SaveExecution stores an execution in the execution store under the org that
// owns it (#3067).
// For production, replace with database-backed storage.
func (e *HITLWorkflowEngine) SaveExecution(exec *HITLWorkflowExecution) {
	saveHITLExecution(exec)
}

// GetExecutionStatusForScope returns the current status of an execution
// including HITL state, bound to the caller's org scope. An execution owned by
// another org is ErrExecutionNotFound, indistinguishable from one that does
// not exist.
//
// #3067: this is the ONLY status accessor. The by-id-across-all-scopes variant
// it replaced let a caller who knew an execution id read another org's status,
// approval id and paused reason; it was removed rather than deprecated so no
// new caller can reach for it.
func (e *HITLWorkflowEngine) GetExecutionStatusForScope(ctx context.Context, scope, executionID string) (*HITLExecutionStatus, error) {
	exec, exists := lookupHITLExecution(scope, executionID)
	if !exists {
		return nil, ErrExecutionNotFound
	}
	return projectHITLExecutionStatus(executionID, exec), nil
}

// projectHITLExecutionStatus builds the wire status for an execution.
func projectHITLExecutionStatus(executionID string, exec *HITLWorkflowExecution) *HITLExecutionStatus {
	return &HITLExecutionStatus{
		ExecutionID:    executionID,
		Status:         exec.Status,
		ApprovalID:     exec.ApprovalID,
		ApprovalStatus: exec.ApprovalStatus,
		PausedAtStep:   exec.PausedAtStep,
		PausedReason:   exec.PausedReason,
	}
}

// HITLExecutionStatus represents the current status of an HITL execution.
type HITLExecutionStatus struct {
	ExecutionID    string    `json:"execution_id"`
	Status         string    `json:"status"`
	ApprovalID     uuid.UUID `json:"approval_id,omitempty"`
	ApprovalStatus string    `json:"approval_status,omitempty"`
	PausedAtStep   int       `json:"paused_at_step,omitempty"`
	PausedReason   string    `json:"paused_reason,omitempty"`
}
