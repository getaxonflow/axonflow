// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

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
	OnStepCompleted(ctx context.Context, workflowID string, stepID string) error
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
		s.logger.Printf("[WorkflowControl] Execution tracking error (%s): %v", op, err)
	}
}

// CreateWorkflow registers a new workflow from an external orchestrator
func (s *Service) CreateWorkflow(ctx context.Context, req *CreateWorkflowRequest, tenantID, orgID, userID, clientID string) (*Workflow, error) {
	if req.WorkflowName == "" {
		return nil, fmt.Errorf("workflow_name is required")
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
		Metadata:         metadataJSON,
	}

	if err := s.repo.Create(ctx, workflow); err != nil {
		return nil, fmt.Errorf("failed to create workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Created workflow %s (%s) source=%s",
		workflow.WorkflowID, workflow.WorkflowName, workflow.Source)

	// Audit log: workflow created
	s.logAudit(ctx, &WorkflowAuditEntry{
		WorkflowID:   workflow.WorkflowID,
		WorkflowName: workflow.WorkflowName,
		Operation:    "created",
		TenantID:     tenantID,
		ClientID:     clientID,
		UserID:       userID,
		Metadata: map[string]interface{}{
			"source":      workflow.Source,
			"total_steps": req.TotalSteps,
		},
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

// GetWorkflow retrieves a workflow by ID
func (s *Service) GetWorkflow(ctx context.Context, workflowID string) (*Workflow, error) {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}
	return workflow, nil
}

// StepGate checks if a workflow step is allowed to proceed
// This is the core governance function - called before each step in an external workflow
func (s *Service) StepGate(ctx context.Context, workflowID string, stepID string, req *StepGateRequest, tenantID, orgID, userID, clientID string) (*StepGateResponse, error) {
	// Get the workflow
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return nil, err
	}

	// Check if workflow is in a terminal state
	if workflow.IsTerminal() {
		return nil, fmt.Errorf("workflow is in terminal state: %s", workflow.Status)
	}

	// Check for pending approval on previous step
	if len(workflow.Steps) > 0 {
		lastStep := workflow.Steps[len(workflow.Steps)-1]
		if lastStep.Decision == GateDecisionRequireApproval &&
			lastStep.ApprovalStatus != nil &&
			*lastStep.ApprovalStatus == ApprovalStatusPending {
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
	}

	if err := s.repo.AddStep(ctx, step); err != nil {
		return nil, fmt.Errorf("failed to record step decision: %w", err)
	}

	// Build response (Issue #1021: Include policy info in response)
	response := &StepGateResponse{
		Decision:          evaluation.Decision,
		StepID:            stepID,
		DecisionID:        fmt.Sprintf("dec_%s_%s", workflowID, stepID),
		PolicyIDs:         evaluation.PolicyIDs,
		Reason:            evaluation.Reason,
		PoliciesEvaluated: evaluation.PoliciesEvaluated,
		PoliciesMatched:   evaluation.PoliciesMatched,
	}

	// Add approval URL for require_approval decisions
	if evaluation.Decision == GateDecisionRequireApproval && s.baseURL != "" {
		response.ApprovalURL = fmt.Sprintf("%s/workflows/%s/steps/%s/approve",
			s.baseURL, workflowID, stepID)
	}

	s.logger.Printf("[WorkflowControl] Step gate: workflow=%s step=%s decision=%s reason=%s",
		workflowID, stepID, evaluation.Decision, logutil.Sanitize(evaluation.Reason))

	// Audit log: step gate decision
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
		Metadata: map[string]interface{}{
			"step_type":          req.StepType,
			"model":              req.Model,
			"provider":           req.Provider,
			"policies_evaluated": len(evaluation.PoliciesEvaluated),
			"policies_matched":   len(evaluation.PoliciesMatched),
		},
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
func (s *Service) ApproveStep(ctx context.Context, workflowID, stepID string, approvedBy string) error {
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

	if err := s.repo.UpdateStepApproval(ctx, workflowID, stepID, ApprovalStatusApproved, approvedBy); err != nil {
		return fmt.Errorf("failed to approve step: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Step approved: workflow=%s step=%s by=%s",
		workflowID, stepID, logutil.Sanitize(approvedBy))

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
func (s *Service) RejectStep(ctx context.Context, workflowID, stepID string, rejectedBy string) error {
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

	if err := s.repo.UpdateStepApproval(ctx, workflowID, stepID, ApprovalStatusRejected, rejectedBy); err != nil {
		return fmt.Errorf("failed to reject step: %w", err)
	}

	// When a step is rejected, abort the workflow
	if err := s.repo.Abort(ctx, workflowID, fmt.Sprintf("Step %s rejected by %s", stepID, rejectedBy)); err != nil {
		s.logger.Printf("[WorkflowControl] Warning: failed to abort workflow after rejection: %v", err)
	}

	s.logger.Printf("[WorkflowControl] Step rejected: workflow=%s step=%s by=%s",
		workflowID, stepID, logutil.Sanitize(rejectedBy))

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
func (s *Service) ResumeWorkflow(ctx context.Context, workflowID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
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

	s.logger.Printf("[WorkflowControl] Workflow resumed: %s", workflowID)
	return nil
}

// AbortWorkflow aborts a workflow
func (s *Service) AbortWorkflow(ctx context.Context, workflowID string, reason string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("workflow is already in terminal state: %s", workflow.Status)
	}

	if err := s.repo.Abort(ctx, workflowID, reason); err != nil {
		return fmt.Errorf("failed to abort workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Workflow aborted: %s reason=%s", workflowID, reason)

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

// CompleteWorkflow marks a workflow as completed
func (s *Service) CompleteWorkflow(ctx context.Context, workflowID string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
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

	s.logger.Printf("[WorkflowControl] Workflow completed: %s", workflowID)

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
		"workflow_id":     workflowID,
		"workflow_name":   workflow.WorkflowName,
		"steps_executed":  len(workflow.Steps),
	}, workflow.TenantID, workflow.OrgID)

	return nil
}

// FailWorkflow marks a workflow as failed
func (s *Service) FailWorkflow(ctx context.Context, workflowID string, reason string) error {
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return err
	}

	if workflow.IsTerminal() {
		return fmt.Errorf("workflow is already in terminal state: %s", workflow.Status)
	}

	if err := s.repo.Fail(ctx, workflowID, reason); err != nil {
		return fmt.Errorf("failed to fail workflow: %w", err)
	}

	s.logger.Printf("[WorkflowControl] Workflow failed: %s reason=%s", workflowID, logutil.Sanitize(reason))

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
func (s *Service) GetPendingApprovals(ctx context.Context, tenantID string, limit int) ([]WorkflowStep, error) {
	return s.repo.GetPendingApprovals(ctx, tenantID, limit)
}

// MarkStepCompleted marks a step as completed after the external orchestrator executes it
func (s *Service) MarkStepCompleted(ctx context.Context, workflowID, stepID string) error {
	// Get workflow for audit logging
	workflow, err := s.repo.GetByID(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	if err := s.repo.MarkStepCompleted(ctx, workflowID, stepID); err != nil {
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
		return s.executionTracker.OnStepCompleted(ctx, workflowID, stepID)
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
