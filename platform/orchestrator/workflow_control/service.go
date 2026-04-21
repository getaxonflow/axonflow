// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	logutil "axonflow/platform/shared/logger"
)

// PolicyEvaluator interface for evaluating step policies
// This is implemented by the dynamic policy engine
type PolicyEvaluator interface {
	// EvaluateStepGate checks if a workflow step should be allowed, blocked, or require approval
	EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation
}

// StepGateContext provides context for policy evaluation
type StepGateContext struct {
	WorkflowID   string
	WorkflowName string
	Source       WorkflowSource
	StepID       string
	StepName     string
	StepType     StepType
	StepInput    map[string]interface{}
	Model        string
	Provider     string
	StepIndex    int
	TenantID     string
	OrgID        string
	UserID       string
	ClientID     string
	ToolContext  *ToolContext
}

// StepGateEvaluation is the result of policy evaluation
type StepGateEvaluation struct {
	Decision          GateDecision
	Reason            string
	PolicyIDs         []string
	PoliciesEvaluated []PolicyMatch
	PoliciesMatched   []PolicyMatch
	ApprovalID        string // HITL approval ID when Decision is GateDecisionRequireApproval (Issue #1082)
}

// DefaultPolicyEvaluator is a no-op evaluator that allows all steps
// Used when no policy engine is configured (community default behavior)
type DefaultPolicyEvaluator struct{}

// EvaluateStepGate allows all steps by default
func (d *DefaultPolicyEvaluator) EvaluateStepGate(ctx context.Context, step *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:          GateDecisionAllow,
		Reason:            "No policies configured",
		PolicyIDs:         []string{},
		PoliciesEvaluated: []PolicyMatch{},
		PoliciesMatched:   []PolicyMatch{},
	}
}

// WorkflowAuditLogger interface for audit logging workflow operations
// This avoids a circular dependency with the orchestrator package
type WorkflowAuditLogger interface {
	LogWorkflowOperation(ctx context.Context, entry *WorkflowAuditEntry)
}

// WorkflowExecutionTracker interface for unified execution tracking
// This allows the orchestrator package to inject unified tracking without circular dependencies
type WorkflowExecutionTracker interface {
	// OnWorkflowCreated is called when a new workflow is registered
	OnWorkflowCreated(ctx context.Context, workflow *Workflow) error
	// OnStepGate is called when a step gate check is performed
	OnStepGate(ctx context.Context, workflowID string, step *WorkflowStep) error
	// OnStepCompleted is called when a step execution completes
	OnStepCompleted(ctx context.Context, workflowID string, stepID string, metrics *StepCompleteRequest) error
	// OnWorkflowCompleted is called when a workflow completes successfully
	OnWorkflowCompleted(ctx context.Context, workflowID string) error
	// OnWorkflowFailed is called when a workflow fails
	OnWorkflowFailed(ctx context.Context, workflowID string, reason string) error
	// OnWorkflowAborted is called when a workflow is aborted
	OnWorkflowAborted(ctx context.Context, workflowID string, reason string) error
}

// WorkflowAuditEntry represents an audit entry for workflow operations
type WorkflowAuditEntry struct {
	WorkflowID   string
	WorkflowName string
	StepID       string
	StepName     string
	Operation    string // created, step_gate, step_completed, completed, aborted
	Decision     string // allow, block, require_approval (for step_gate)
	Reason       string
	TenantID     string
	ClientID     string
	UserID       string
	Metadata     map[string]interface{}
}

// WebhookNotifier fires webhook notifications for WCP events.
type WebhookNotifier interface {
	// Fire sends a webhook event to all matching subscriptions (best-effort, async).
	Fire(ctx context.Context, eventType string, data map[string]interface{}, tenantID, orgID string)
}

// Service handles workflow control plane business logic
type Service struct {
	repo             Repository
	policyEvaluator  PolicyEvaluator
	auditLogger      WorkflowAuditLogger
	executionTracker WorkflowExecutionTracker
	webhookNotifier  WebhookNotifier
	logger           *log.Logger
	baseURL          string // Base URL for approval URLs
}

// ServiceConfig configures the workflow control service
type ServiceConfig struct {
	BaseURL string // Base URL for generating approval URLs (e.g., https://portal.getaxonflow.com)
}

// NewService creates a new workflow control service
func NewService(repo Repository, policyEvaluator PolicyEvaluator, config *ServiceConfig) *Service {
	if policyEvaluator == nil {
		policyEvaluator = &DefaultPolicyEvaluator{}
	}
	baseURL := ""
	if config != nil {
		baseURL = config.BaseURL
	}
	return &Service{
		repo:            repo,
		policyEvaluator: policyEvaluator,
		logger:          log.Default(),
		baseURL:         baseURL,
	}
}

// NewServiceWithLogger creates a new workflow control service with a custom logger
func NewServiceWithLogger(repo Repository, policyEvaluator PolicyEvaluator, config *ServiceConfig, logger *log.Logger) *Service {
	svc := NewService(repo, policyEvaluator, config)
	if logger != nil {
		svc.logger = logger
	}
	return svc
}

// SetAuditLogger sets the audit logger for the service
func (s *Service) SetAuditLogger(auditLogger WorkflowAuditLogger) {
	s.auditLogger = auditLogger
}

// SetExecutionTracker sets the unified execution tracker for the service
func (s *Service) SetExecutionTracker(tracker WorkflowExecutionTracker) {
	s.executionTracker = tracker
}

// SetWebhookNotifier sets the webhook notifier for the service
func (s *Service) SetWebhookNotifier(notifier WebhookNotifier) {
	s.webhookNotifier = notifier
}

// fireWebhook sends a webhook notification if a notifier is configured (best-effort)
func (s *Service) fireWebhook(ctx context.Context, eventType string, data map[string]interface{}, tenantID, orgID string) {
	if s.webhookNotifier == nil {
		return
	}
	s.webhookNotifier.Fire(ctx, eventType, data, tenantID, orgID)
}

// logAudit logs a workflow audit entry if an audit logger is configured
func (s *Service) logAudit(ctx context.Context, entry *WorkflowAuditEntry) {
	if s.auditLogger != nil {
		s.auditLogger.LogWorkflowOperation(ctx, entry)
	}
}

// trackExecution calls the unified execution tracker if configured
// Errors are logged but don't fail the operation (best-effort tracking)
func (s *Service) trackExecution(ctx context.Context, op string, fn func() error) {
	if s.executionTracker == nil {
		return
	}
	if err := fn(); err != nil {
		s.logger.Printf("[WorkflowControl] Execution tracking error (%s): %v", logutil.Sanitize(op), err)
	}
}

// CreateWorkflow registers a new workflow from an external orchestrator
func (s *Service) CreateWorkflow(ctx context.Context, req *CreateWorkflowRequest, tenantID, orgID, userID, clientID string) (*Workflow, error) {
	if req.WorkflowName == "" {
		return nil, fmt.Errorf("workflow_name is required")
	}

	// Validate trace_id length (character count, not bytes, to match VARCHAR(255))
	if utf8.RuneCountInString(req.TraceID) > 255 {
		return nil, fmt.Errorf("trace_id exceeds maximum length of 255 characters")
	}

	// Determine source
	source := req.Source
	if source == "" {
		source = WorkflowSourceExternal
	}

	// Convert metadata to JSON
	var metadataJSON json.RawMessage
	if req.Metadata != nil {
		data, err := json.Marshal(req.Metadata)
		if err != nil {
			return nil, fmt.Errorf("invalid metadata: %w", err)
		}
		metadataJSON = data
	} else {
		metadataJSON = json.RawMessage("{}")
	}

	workflow := &Workflow{
		WorkflowID:       fmt.Sprintf("wf_%s", uuid.New().String()[:8]),
		WorkflowName:     req.WorkflowName,
		Source:           source,
		Status:           WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		TotalSteps:       req.TotalSteps,
		TenantID:         tenantID,
		OrgID:            orgID,
		UserID:           userID,
		ClientID:         clientID,
		TraceID:          req.TraceID,
		Metadata:         metadataJSON,
	}

	if err := s.repo.Create(ctx, workflow); err != nil {
		return nil, fmt.Errorf("failed to create workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Created workflow %s (%s) source=%s",
		logutil.Sanitize(workflow.WorkflowID), logutil.Sanitize(workflow.WorkflowName), logutil.Sanitize(string(workflow.Source)))

	// Audit log: workflow created
	auditMeta := map[string]interface{}{
		"source": workflow.Source,
	}
	if workflow.TraceID != "" {
		auditMeta["trace_id"] = workflow.TraceID
	}
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflow.WorkflowID,
		WorkflowName: workflow.WorkflowName,
		Operation:    "created",
		TenantID:     tenantID,
		ClientID:     clientID,
		UserID:       userID,
		Metadata:     auditMeta,
	})

	// Unified execution tracking — propagate concurrent limit errors
	if s.executionTracker != nil {
		if err := s.executionTracker.OnWorkflowCreated(ctx, workflow); err != nil {
			if isConcurrentLimitError(err) {
				// Roll back the workflow creation
				_ = s.repo.Delete(ctx, workflow.WorkflowID)
				return nil, fmt.Errorf("concurrent execution limit reached: %w", err)
			}
			s.logger.Printf("[WorkflowControl] Execution tracking error (workflow_created): %v", err)
		}
	}

	return workflow, nil
}

// isConcurrentLimitError checks if the error is a concurrent execution limit error.
func isConcurrentLimitError(err error) bool {
	return err != nil && err.Error() == "concurrent execution limit reached"
}

// GetWorkflow retrieves a workflow by ID, scoped to the caller's tenant and org.
// Returns ErrWorkflowNotFound if the workflow exists but belongs to a different
// tenant or org — 404-style response prevents tenant-existence side-channel leaks.
func (s *Service) GetWorkflow(ctx context.Context, workflowID, tenantID, orgID string) (*Workflow, error) {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}
	return workflow, nil
}

// workflowBelongsTo returns true if the workflow is owned by the given tenant+org.
// Multi-tenant isolation: a workflow created under (tenant_id=A, org_id=X) must
// not be returned to a caller authenticated as any other (tenant_id, org_id) pair.
// Community mode and internal-service callers pass empty strings to bypass the
// check — but the handler layer must only do that for trusted code paths.
func workflowBelongsTo(workflow *Workflow, tenantID, orgID string) bool {
	if tenantID == "" && orgID == "" {
		// Bypass — trusted caller (community, internal service, migration)
		return true
	}
	if tenantID != "" && workflow.TenantID != tenantID {
		return false
	}
	if orgID != "" && workflow.OrgID != orgID {
		return false
	}
	return true
}

// buildCachedResponse constructs a StepGateResponse from a previously persisted step decision.
// This supports idempotent retry semantics (#1414): same (workflow_id, step_id) returns the
// same decision without re-running the policy evaluator.
//
// Special case: if the original decision was require_approval but the step has since been
// approved, we return "allow" — the approval resolved the gate and the step can proceed.
// If rejected, we return "block" since the workflow was aborted.
func buildCachedResponse(step *WorkflowStep, workflowID, baseURL string) *StepGateResponse {
	decision := step.Decision
	reason := step.DecisionReason

	// Resolve approval state: approved require_approval → allow, rejected → block
	if step.Decision == GateDecisionRequireApproval && step.ApprovalStatus != nil {
		switch *step.ApprovalStatus {
		case ApprovalStatusApproved:
			decision = GateDecisionAllow
			reason = "Previously approved: " + step.DecisionReason
		case ApprovalStatusRejected:
			decision = GateDecisionBlock
			reason = "Previously rejected: " + step.DecisionReason
		}
	}

	// Reconstruct policy match details from stored JSON
	var policiesEvaluated, policiesMatched []PolicyMatch
	if step.PoliciesEvaluated != nil {
		_ = json.Unmarshal(step.PoliciesEvaluated, &policiesEvaluated)
	}
	if step.PoliciesMatched != nil {
		_ = json.Unmarshal(step.PoliciesMatched, &policiesMatched)
	}

	// Extract policy IDs from matched policies
	var policyIDs []string
	for _, pm := range policiesMatched {
		policyIDs = append(policyIDs, pm.PolicyID)
	}

	resp := &StepGateResponse{
		Decision:          decision,
		StepID:            step.StepID,
		DecisionID:        fmt.Sprintf("dec_%s_%s", workflowID, step.StepID),
		PolicyIDs:         policyIDs,
		Reason:            reason,
		PoliciesEvaluated: policiesEvaluated,
		PoliciesMatched:   policiesMatched,
		Cached:            true,
		DecisionSource:    "cached",
	}

	// Include approval URL for pending require_approval decisions
	if step.Decision == GateDecisionRequireApproval &&
		step.ApprovalStatus != nil &&
		*step.ApprovalStatus == ApprovalStatusPending &&
		baseURL != "" {
		resp.ApprovalURL = fmt.Sprintf("%s/workflows/%s/steps/%s/approve",
			baseURL, workflowID, step.StepID)
	}

	return resp
}

// StepGate checks if a workflow step is allowed to proceed
// This is the core governance function - called before each step in an external workflow
func (s *Service) StepGate(ctx context.Context, workflowID string, stepID string, req *StepGateRequest, tenantID, orgID, userID, clientID string) (*StepGateResponse, error) {
	// Get the workflow
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}

	// Multi-tenant isolation: reject gate calls for workflows that don't
	// belong to the caller's tenant/org. Return 404-style error to avoid
	// leaking existence of other tenants' workflows.
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	// Check if workflow is in a terminal state
	if workflow.IsTerminal() {
		return nil, fmt.Errorf("workflow is in terminal state: %s", workflow.Status)
	}

	// Execution boundary semantics (#1414): default to idempotent retry behavior.
	// Same (workflow_id, step_id) returns the same decision unless the caller
	// explicitly requests a fresh evaluation via retry_policy=reevaluate.
	retryPolicy := req.RetryPolicy
	if retryPolicy == "" {
		retryPolicy = RetryPolicyIdempotent
	}

	// Idempotent cache lookup: return prior decision if step was already evaluated.
	// This MUST run before the pending-approval guard so that retrying the same
	// step that has a pending approval returns the cached require_approval decision
	// instead of an error. GateOverride (MAP confirm/step modes) bypasses the cache
	// because those modes have their own evaluator-level caching via sync.Map.
	if retryPolicy == RetryPolicyIdempotent && req.GateOverride == nil {
		cached, err := s.repo.GetStepDecision(ctx, workflowID, stepID)
		if err != nil {
			return nil, fmt.Errorf("failed to check cached decision: %w", err)
		}
		if cached != nil {
			return buildCachedResponse(cached, workflowID, s.baseURL), nil
		}
	}

	// Check for pending approval on a DIFFERENT step.
	// If the last step has a pending approval and the caller is requesting a
	// gate for a new (different) step, block it — the workflow can't advance
	// past a pending approval boundary. Same-step retries were already handled
	// above via the cache lookup.
	if len(workflow.Steps) > 0 {
		lastStep := workflow.Steps[len(workflow.Steps)-1]
		if lastStep.Decision == GateDecisionRequireApproval &&
			lastStep.ApprovalStatus != nil &&
			*lastStep.ApprovalStatus == ApprovalStatusPending &&
			lastStep.StepID != stepID {
			return nil, fmt.Errorf("workflow has pending approval for step %s", lastStep.StepID)
		}
	}

	// Build policy evaluation context
	stepInput := make(map[string]interface{})
	if req.StepInput != nil {
		stepInput = req.StepInput
	}

	gateCtx := &StepGateContext{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		Source:       workflow.Source,
		StepID:       stepID,
		StepName:     req.StepName,
		StepType:     req.StepType,
		StepInput:    stepInput,
		Model:        req.Model,
		Provider:     req.Provider,
		StepIndex:    workflow.CurrentStepIndex + 1,
		TenantID:     tenantID,
		OrgID:        orgID,
		UserID:       userID,
		ClientID:     clientID,
		ToolContext:  req.ToolContext,
	}

	// Evaluate policies (or use override for MAP confirm/step modes)
	var evaluation *StepGateEvaluation
	if req.GateOverride != nil {
		evaluation = &StepGateEvaluation{
			Decision:  *req.GateOverride,
			Reason:    "Gate override: execution mode requires " + string(*req.GateOverride),
			PolicyIDs: []string{"execution-mode-override"},
		}
	} else {
		evaluation = s.policyEvaluator.EvaluateStepGate(ctx, gateCtx)
	}

	// Convert step input to JSON for storage
	stepInputJSON, _ := json.Marshal(stepInput)
	policiesEvaluatedJSON, _ := json.Marshal(evaluation.PoliciesEvaluated)
	policiesMatchedJSON, _ := json.Marshal(evaluation.PoliciesMatched)

	// Determine approval status for require_approval decisions
	var approvalStatus *ApprovalStatus
	if evaluation.Decision == GateDecisionRequireApproval {
		pending := ApprovalStatusPending
		approvalStatus = &pending
	}

	// Record the step decision
	step := &WorkflowStep{
		WorkflowID:        workflowID,
		StepID:            stepID,
		StepIndex:         gateCtx.StepIndex,
		StepName:          req.StepName,
		StepType:          req.StepType,
		Decision:          evaluation.Decision,
		DecisionReason:    evaluation.Reason,
		PoliciesEvaluated: policiesEvaluatedJSON,
		PoliciesMatched:   policiesMatchedJSON,
		ApprovalStatus:    approvalStatus,
		StepInput:         stepInputJSON,
		Model:             req.Model,
		Provider:          req.Provider,
		TokensIn:          req.TokensIn,
		TokensOut:         req.TokensOut,
		CostUSD:           req.CostUSD,
	}

	if err := s.repo.AddStep(ctx, step); err != nil {
		return nil, fmt.Errorf("failed to record step decision: %w", err)
	}

	// Concurrent safety (#1414 P3): after upserting, read back the persisted step
	// to return what actually landed in the DB. If two concurrent first-time calls
	// race past the cache check, the upsert deduplicates at the storage layer, but
	// one caller's evaluation may have been overwritten. Reading back ensures both
	// callers return the same decision — the one that persisted.
	persisted, err := s.repo.GetStepDecision(ctx, workflowID, stepID)
	if err != nil {
		return nil, fmt.Errorf("failed to read back step decision: %w", err)
	}
	if persisted != nil && persisted.Decision != evaluation.Decision {
		s.logger.Printf("[WorkflowControl] Concurrent race detected: workflow=%s step=%s evaluated=%s persisted=%s (returning persisted)",
			logutil.Sanitize(workflowID), logutil.Sanitize(stepID),
			logutil.Sanitize(string(evaluation.Decision)), logutil.Sanitize(string(persisted.Decision)))
		return buildCachedResponse(persisted, workflowID, s.baseURL), nil
	}

	// Create step-gate checkpoint for safe resume.
	// Best-effort: checkpoint creation failure must not fail the step gate itself.
	cpType := CheckpointStepGate
	if evaluation.Decision == GateDecisionRequireApproval {
		cpType = CheckpointApprovalBoundary
	}
	// Serialize tool context for checkpoint storage
	var toolContextJSON json.RawMessage
	if req.ToolContext != nil {
		toolContextJSON, _ = json.Marshal(req.ToolContext)
	}
	cp := &Checkpoint{
		WorkflowID:        workflowID,
		StepID:            stepID,
		StepIndex:         gateCtx.StepIndex,
		StepType:          req.StepType,
		StepName:          req.StepName,
		CheckpointType:    cpType,
		GateDecision:      string(evaluation.Decision),
		GateReason:        evaluation.Reason,
		PoliciesEvaluated: policiesEvaluatedJSON,
		PoliciesMatched:   policiesMatchedJSON,
		StepInput:         stepInputJSON,
		ToolContext:       toolContextJSON,
		Model:             req.Model,
		Provider:          req.Provider,
		IsResumable:       evaluation.Decision != GateDecisionBlock,
		OrgID:             orgID,
		TenantID:          tenantID,
		UserID:            userID,
		ClientID:          clientID,
	}
	if cpErr := s.repo.CreateCheckpoint(ctx, cp); cpErr != nil {
		s.logger.Printf("[WorkflowControl] Warning: checkpoint creation failed for %s/%s: %v",
			workflowID, stepID, cpErr)
	}

	// Build response (Issue #1021: Include policy info in response)
	response := &StepGateResponse{
		Decision:          evaluation.Decision,
		StepID:            stepID,
		DecisionID:        fmt.Sprintf("dec_%s_%s", workflowID, stepID),
		PolicyIDs:         evaluation.PolicyIDs,
		Reason:            evaluation.Reason,
		ApprovalID:        evaluation.ApprovalID,
		PoliciesEvaluated: evaluation.PoliciesEvaluated,
		PoliciesMatched:   evaluation.PoliciesMatched,
		Cached:            false,
		DecisionSource:    "fresh",
	}

	// Add approval URL for require_approval decisions
	if evaluation.Decision == GateDecisionRequireApproval && s.baseURL != "" {
		response.ApprovalURL = fmt.Sprintf("%s/workflows/%s/steps/%s/approve",
			s.baseURL, workflowID, stepID)
	}

	s.logger.Printf("[WorkflowControl] Step gate: workflow=%s step=%s decision=%s reason=%s",
		logutil.Sanitize(workflowID), logutil.Sanitize(stepID), logutil.Sanitize(string(evaluation.Decision)), logutil.Sanitize(evaluation.Reason))

	// Audit log: step gate decision
	auditMeta := map[string]interface{}{
		"step_type":          req.StepType,
		"model":              req.Model,
		"provider":           req.Provider,
		"policies_evaluated": len(evaluation.PoliciesEvaluated),
		"policies_matched":   len(evaluation.PoliciesMatched),
	}
	if req.ToolContext != nil {
		auditMeta["tool_name"] = req.ToolContext.ToolName
		auditMeta["tool_type"] = req.ToolContext.ToolType
	}
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		StepID:       stepID,
		StepName:     req.StepName,
		Operation:    "step_gate",
		Decision:     string(evaluation.Decision),
		Reason:       evaluation.Reason,
		TenantID:     tenantID,
		ClientID:     clientID,
		UserID:       userID,
		Metadata:     auditMeta,
	})

	// Unified execution tracking
	s.trackExecution(ctx, "step_gate", func() error {
		return s.executionTracker.OnStepGate(ctx, workflowID, step)
	})

	// Webhook notification for require_approval decisions
	if evaluation.Decision == GateDecisionRequireApproval {
		s.fireWebhook(ctx, "step.approval_required", map[string]interface{}{
			"workflow_id":   workflowID,
			"workflow_name": workflow.WorkflowName,
			"step_id":       stepID,
			"step_name":     req.StepName,
			"step_type":     string(req.StepType),
			"approval_url":  response.ApprovalURL,
		}, tenantID, orgID)
	}

	return response, nil
}

// ApproveStep approves a step that requires approval (Enterprise feature)
func (s *Service) ApproveStep(ctx context.Context, workflowID, stepID, tenantID, orgID, approvedBy, comment string) error {
	// Multi-tenant isolation: verify the workflow belongs to the caller
	// before allowing approval. Without this check, any authenticated
	// client could approve any other tenant's pending step.
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	step, err := s.repo.GetStep(ctx, workflowID, stepID)
	if err != nil {
		return err
	}

	if step.Decision != GateDecisionRequireApproval {
		return fmt.Errorf("step does not require approval")
	}

	if step.ApprovalStatus == nil || *step.ApprovalStatus != ApprovalStatusPending {
		return fmt.Errorf("step is not pending approval")
	}

	if err := s.repo.UpdateStepApproval(ctx, workflowID, stepID, ApprovalStatusApproved, approvedBy, comment); err != nil {
		return fmt.Errorf("failed to approve step: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Step approved: workflow=%s step=%s by=%s",
		logutil.Sanitize(workflowID), logutil.Sanitize(stepID), logutil.Sanitize(approvedBy))

	// Webhook notification (best-effort — get workflow for tenant context)
	if wf, wfErr := s.repo.GetByID(ctx, workflowID); wfErr == nil {
		s.fireWebhook(ctx, "step.approved", map[string]interface{}{
			"workflow_id": workflowID,
			"step_id":     stepID,
			"step_name":   step.StepName,
			"approved_by": approvedBy,
		}, wf.TenantID, wf.OrgID)
	}

	return nil
}

// RejectStep rejects a step that requires approval (Enterprise feature)
func (s *Service) RejectStep(ctx context.Context, workflowID, stepID, tenantID, orgID, rejectedBy, reason string) error {
	// Multi-tenant isolation: verify ownership before allowing rejection.
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	step, err := s.repo.GetStep(ctx, workflowID, stepID)
	if err != nil {
		return err
	}

	if step.Decision != GateDecisionRequireApproval {
		return fmt.Errorf("step does not require approval")
	}

	if step.ApprovalStatus == nil || *step.ApprovalStatus != ApprovalStatusPending {
		return fmt.Errorf("step is not pending approval")
	}

	if err := s.repo.UpdateStepApproval(ctx, workflowID, stepID, ApprovalStatusRejected, rejectedBy, reason); err != nil {
		return fmt.Errorf("failed to reject step: %w", err)
	}

	// When a step is rejected, abort the workflow
	if err := s.repo.Abort(ctx, workflowID, fmt.Sprintf("Step %s rejected by %s", stepID, rejectedBy)); err != nil {
		s.logger.Printf("[WorkflowControl] Warning: failed to abort workflow after rejection: %v", err)
	}

	s.logger.Printf("[WorkflowControl] Step rejected: workflow=%s step=%s by=%s",
		logutil.Sanitize(workflowID), logutil.Sanitize(stepID), logutil.Sanitize(rejectedBy))

	// Webhook notification (best-effort)
	if wf, wfErr := s.repo.GetByID(ctx, workflowID); wfErr == nil {
		s.fireWebhook(ctx, "step.rejected", map[string]interface{}{
			"workflow_id": workflowID,
			"step_id":     stepID,
			"step_name":   step.StepName,
			"rejected_by": rejectedBy,
		}, wf.TenantID, wf.OrgID)
	}

	return nil
}

// ResumeWorkflow attempts to resume a workflow that was waiting for approval
func (s *Service) ResumeWorkflow(ctx context.Context, workflowID, tenantID, orgID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	// Multi-tenant isolation: reject resume on workflows owned by another tenant.
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("cannot resume workflow in terminal state: %s", workflow.Status)
	}

	// Check if there's a pending approval blocking the workflow
	if len(workflow.Steps) > 0 {
		lastStep := workflow.Steps[len(workflow.Steps)-1]
		if lastStep.Decision == GateDecisionRequireApproval {
			if lastStep.ApprovalStatus == nil || *lastStep.ApprovalStatus == ApprovalStatusPending {
				return fmt.Errorf("workflow has pending approval for step %s", lastStep.StepID)
			}
			if *lastStep.ApprovalStatus == ApprovalStatusRejected {
				return fmt.Errorf("workflow step %s was rejected", lastStep.StepID)
			}
		}
	}

	s.logger.Printf("[WorkflowControl] Workflow resumed: %s", logutil.Sanitize(workflowID))
	return nil
}

// AbortWorkflow aborts a workflow, scoped to the caller's tenant and org.
func (s *Service) AbortWorkflow(ctx context.Context, workflowID, reason, tenantID, orgID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	// Multi-tenant isolation: reject abort on workflows owned by another tenant.
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("workflow is already in terminal state: %s", workflow.Status)
	}

	if err := s.repo.Abort(ctx, workflowID, reason); err != nil {
		return fmt.Errorf("failed to abort workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Workflow aborted: %s reason=%s", logutil.Sanitize(workflowID), logutil.Sanitize(reason))

	// Audit log: workflow aborted
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		Operation:    "aborted",
		Reason:       reason,
		TenantID:     workflow.TenantID,
		ClientID:     workflow.ClientID,
		UserID:       workflow.UserID,
	})

	// Unified execution tracking
	s.trackExecution(ctx, "workflow_aborted", func() error {
		return s.executionTracker.OnWorkflowAborted(ctx, workflowID, reason)
	})

	// Webhook notification
	s.fireWebhook(ctx, "workflow.aborted", map[string]interface{}{
		"workflow_id":   workflowID,
		"workflow_name": workflow.WorkflowName,
		"reason":        reason,
	}, workflow.TenantID, workflow.OrgID)

	return nil
}

// CompleteWorkflow marks a workflow as completed, scoped to the caller's tenant and org.
func (s *Service) CompleteWorkflow(ctx context.Context, workflowID, tenantID, orgID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	// Multi-tenant isolation: reject complete on workflows owned by another tenant.
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("workflow is already in terminal state: %s", workflow.Status)
	}

	// Check for pending approvals
	for _, step := range workflow.Steps {
		if step.Decision == GateDecisionRequireApproval &&
			step.ApprovalStatus != nil &&
			*step.ApprovalStatus == ApprovalStatusPending {
			return fmt.Errorf("cannot complete workflow with pending approval for step %s", step.StepID)
		}
	}

	if err := s.repo.Complete(ctx, workflowID); err != nil {
		return fmt.Errorf("failed to complete workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Workflow completed: %s", logutil.Sanitize(workflowID))

	// Audit log: workflow completed
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		Operation:    "completed",
		TenantID:     workflow.TenantID,
		ClientID:     workflow.ClientID,
		UserID:       workflow.UserID,
		Metadata: map[string]interface{}{
			"steps_executed": len(workflow.Steps),
		},
	})

	// Unified execution tracking
	s.trackExecution(ctx, "workflow_completed", func() error {
		return s.executionTracker.OnWorkflowCompleted(ctx, workflowID)
	})

	// Webhook notification
	s.fireWebhook(ctx, "workflow.completed", map[string]interface{}{
		"workflow_id":    workflowID,
		"workflow_name":  workflow.WorkflowName,
		"steps_executed": len(workflow.Steps),
	}, workflow.TenantID, workflow.OrgID)

	return nil
}

// FailWorkflow marks a workflow as failed
func (s *Service) FailWorkflow(ctx context.Context, workflowID, reason, tenantID, orgID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	// Multi-tenant isolation: reject fail on workflows owned by another tenant.
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("workflow is already in terminal state: %s", workflow.Status)
	}

	if err := s.repo.Fail(ctx, workflowID, reason); err != nil {
		return fmt.Errorf("failed to fail workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Workflow failed: %s reason=%s", logutil.Sanitize(workflowID), logutil.Sanitize(reason))

	// Audit log: workflow failed
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		Operation:    "failed",
		Reason:       reason,
		TenantID:     workflow.TenantID,
		ClientID:     workflow.ClientID,
		UserID:       workflow.UserID,
	})

	// Unified execution tracking
	s.trackExecution(ctx, "workflow_failed", func() error {
		return s.executionTracker.OnWorkflowFailed(ctx, workflowID, reason)
	})

	// Webhook notification
	s.fireWebhook(ctx, "workflow.failed", map[string]interface{}{
		"workflow_id":   workflowID,
		"workflow_name": workflow.WorkflowName,
		"reason":        reason,
	}, workflow.TenantID, workflow.OrgID)

	return nil
}

// ListWorkflows lists workflows with optional filters
func (s *Service) ListWorkflows(ctx context.Context, opts ListWorkflowsOptions) (*ListWorkflowsResponse, error) {
	workflows, total, err := s.repo.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows: %w", err)
	}

	limit := opts.Limit
	if limit <= 0 {
		limit = 20
	}

	// Convert to response format
	responses := make([]WorkflowStatusResponse, len(workflows))
	for i, w := range workflows {
		responses[i] = w.ToStatusResponse()
	}

	hasMore := opts.Offset+len(workflows) < total

	return &ListWorkflowsResponse{
		Workflows: responses,
		Total:     total,
		Limit:     limit,
		Offset:    opts.Offset,
		HasMore:   hasMore,
	}, nil
}

// GetPendingApprovals returns steps awaiting approval for a tenant
func (s *Service) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]PendingApprovalResponse, error) {
	return s.repo.GetPendingApprovals(ctx, tenantID, limit)
}

// CountPendingApprovals returns the total number of pending approvals for a tenant
func (s *Service) CountPendingApprovals(ctx context.Context, tenantID string) (int, error) {
	return s.repo.CountPendingApprovals(ctx, tenantID)
}

// MarkStepCompleted marks a step as completed after the external orchestrator executes it.
// The optional req carries post-execution metrics (tokens, cost, output) from the SDK.
func (s *Service) MarkStepCompleted(ctx context.Context, workflowID, stepID string, req *StepCompleteRequest, tenantID, orgID string) error {
	// Get workflow for audit logging and ownership check
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	// Multi-tenant isolation: reject step completion on workflows owned
	// by another tenant. Without this check, any authenticated client
	// could mark any other tenant's steps as completed (including injecting
	// fake cost/token metrics into audit logs).
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	if err := s.repo.MarkStepCompleted(ctx, workflowID, stepID, req); err != nil {
		return fmt.Errorf("failed to mark step completed: %w", err)
	}

	// Find step name for audit log
	stepName := ""
	for _, step := range workflow.Steps {
		if step.StepID == stepID {
			stepName = step.StepName
			break
		}
	}

	// Audit log: step completed
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflow.WorkflowName,
		StepID:       stepID,
		StepName:     stepName,
		Operation:    "step_completed",
		TenantID:     workflow.TenantID,
		ClientID:     workflow.ClientID,
		UserID:       workflow.UserID,
	})

	// Unified execution tracking
	s.trackExecution(ctx, "step_completed", func() error {
		return s.executionTracker.OnStepCompleted(ctx, workflowID, stepID, req)
	})

	return nil
}

// CleanupStaleWorkflows marks workflows as failed if they've been inactive too long
func (s *Service) CleanupStaleWorkflows(ctx context.Context, inactiveDuration time.Duration) (int, error) {
	// This is a placeholder for future implementation
	// Would query for workflows where updated_at < now - inactiveDuration
	// and status = in_progress, then mark them as failed
	return 0, nil
}

// --- Checkpoint operations ---

// GetCheckpoints returns all checkpoints for a workflow, ordered by step_index.
// Available to all tiers (Community can see checkpoints but not resume from them).
func (s *Service) GetCheckpoints(ctx context.Context, workflowID, tenantID, orgID string) (*CheckpointListResponse, error) {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	checkpoints, err := s.repo.ListCheckpoints(ctx, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to list checkpoints: %w", err)
	}

	return &CheckpointListResponse{
		Checkpoints: checkpoints,
		WorkflowID:  workflowID,
	}, nil
}

// ResumeFromLastCheckpoint re-evaluates the workflow from its last resumable checkpoint.
// The step gate is called with retry_policy=reevaluate to get a fresh policy decision,
// reflecting any policy changes since the checkpoint was created.
// Available to Evaluation+ tiers.
func (s *Service) ResumeFromLastCheckpoint(ctx context.Context, workflowID, tenantID, orgID string) (*ResumeFromCheckpointResponse, error) {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	cp, err := s.repo.GetLastResumableCheckpoint(ctx, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to get last checkpoint: %w", err)
	}
	if cp == nil {
		return nil, fmt.Errorf("no resumable checkpoint found for workflow %s", workflowID)
	}

	return s.resumeFromCheckpointInternal(ctx, workflow, cp, tenantID, orgID)
}

// ResumeFromCheckpoint re-evaluates a workflow from a specific checkpoint.
// Available to Enterprise tier only.
func (s *Service) ResumeFromCheckpoint(ctx context.Context, workflowID string, checkpointID int64, tenantID, orgID string) (*ResumeFromCheckpointResponse, error) {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	if !workflowBelongsTo(workflow, tenantID, orgID) {
		return nil, fmt.Errorf("%s: %w", workflowID, ErrWorkflowNotFound)
	}

	cp, err := s.repo.GetCheckpointByID(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkpoint: %w", err)
	}
	if cp == nil {
		return nil, fmt.Errorf("checkpoint %d not found", checkpointID)
	}
	if cp.WorkflowID != workflowID {
		return nil, fmt.Errorf("checkpoint %d does not belong to workflow %s", checkpointID, workflowID)
	}
	if !cp.IsResumable {
		return nil, fmt.Errorf("checkpoint %d is not resumable (step was blocked)", checkpointID)
	}

	return s.resumeFromCheckpointInternal(ctx, workflow, cp, tenantID, orgID)
}

// resumeFromCheckpointInternal handles the shared logic for resuming from any checkpoint.
func (s *Service) resumeFromCheckpointInternal(ctx context.Context, workflow *Workflow, cp *Checkpoint, tenantID, orgID string) (*ResumeFromCheckpointResponse, error) {
	// If workflow is in a terminal state that's not aborted, we can't resume
	if workflow.Status == WorkflowStatusCompleted || workflow.Status == WorkflowStatusFailed {
		return nil, fmt.Errorf("cannot resume workflow in %s state", workflow.Status)
	}

	// If workflow was aborted (e.g. after rejection), reset to in_progress for resume
	if workflow.Status == WorkflowStatusAborted {
		if err := s.repo.UpdateStatus(ctx, workflow.WorkflowID, WorkflowStatusInProgress); err != nil {
			return nil, fmt.Errorf("failed to reset workflow status: %w", err)
		}
	}

	// Reconstruct the full gate request from checkpoint context.
	// All fields must be restored because policies may match on any of them
	// (model, provider, tool_context, step_name, etc.).
	var stepInput map[string]interface{}
	if cp.StepInput != nil {
		_ = json.Unmarshal(cp.StepInput, &stepInput)
	}
	var toolContext *ToolContext
	if cp.ToolContext != nil {
		toolContext = &ToolContext{}
		_ = json.Unmarshal(cp.ToolContext, toolContext)
	}
	stepType := cp.StepType
	if stepType == "" {
		stepType = StepTypeToolCall // Fallback for checkpoints created before step_type was added
	}

	// Use the checkpoint's original user_id and client_id for actor attribution,
	// falling back to empty strings if the checkpoint predates those fields.
	resumeUserID := cp.UserID
	resumeClientID := cp.ClientID

	gateResp, err := s.StepGate(ctx, workflow.WorkflowID, cp.StepID, &StepGateRequest{
		StepName:    cp.StepName,
		StepType:    stepType,
		StepInput:   stepInput,
		Model:       cp.Model,
		Provider:    cp.Provider,
		ToolContext: toolContext,
		RetryPolicy: RetryPolicyReevaluate,
	}, tenantID, cp.OrgID, resumeUserID, resumeClientID)
	if err != nil {
		return nil, fmt.Errorf("failed to re-evaluate step gate at checkpoint: %w", err)
	}

	// Increment resume count
	if err := s.repo.IncrementResumeCount(ctx, cp.ID); err != nil {
		s.logger.Printf("[WorkflowControl] Warning: failed to increment resume count for checkpoint %d: %v", cp.ID, err)
	}

	s.logger.Printf("[WorkflowControl] Resumed workflow %s from checkpoint step=%s (index=%d), new decision=%s",
		workflow.WorkflowID, cp.StepID, cp.StepIndex, gateResp.Decision)

	return &ResumeFromCheckpointResponse{
		WorkflowID:            workflow.WorkflowID,
		ResumedFromCheckpoint: cp.StepID,
		ResumedFromIndex:      cp.StepIndex,
		NewDecision:           string(gateResp.Decision),
		DecisionSource:        "fresh",
		ResumeCount:           cp.ResumeCount + 1,
		Message:               fmt.Sprintf("Workflow resumed from checkpoint at step %s (index %d)", cp.StepID, cp.StepIndex),
	}, nil
}
