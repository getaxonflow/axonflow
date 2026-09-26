// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// The multi-agent step gate's shared types and audit entries. The legacy
// in-memory HITL engine that paused a workflow for approval (#1082) ran no
// route's execution since #4382 and is retired (#4249 row 5774060413); a
// multi-agent plan is held in confirm or step mode, through the workflow
// control plane.

package orchestrator

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PolicyCheckResult represents the result of a pre-step policy check.
type PolicyCheckResult struct {
	Allowed    bool
	Action     string // block, require_approval, warn, log
	PolicyID   string
	PolicyName string
	Reason     string
	Severity   string
	// hold is the typed approval a challenge carried (#4254); the step gate
	// names its decision in the withholding reason. Unexported, so it is never
	// marshalled.
	hold *stepGateHold
	// decided is the anchored decision the step's audit row records (PRD v11
	// §5.7). Unexported, so it is never marshalled.
	decided *anchoredDecision
}

// HITLPolicyChecker is the interface for checking policies before step execution.
type HITLPolicyChecker interface {
	// content is what the step presents beside its definition: the input the
	// engine passes it and the processor that will run it (#4249).
	CheckPolicy(ctx context.Context, step WorkflowStep, content StepContent, execution *WorkflowExecution) (*PolicyCheckResult, error)
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
	// ExpiresAt is when the approval this request queues stops being grantable,
	// from the typed approval requirement (#4254). Zero means none was declared,
	// and the queue's default expiry applies.
	ExpiresAt time.Time
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
	// (GetApproval) and on implementations that do not enqueue. Callers surface it as
	// StepGateResponse.approval_enqueue so a re-gate is distinguishable from
	// a first gate without a second query.
	Enqueue string
}

// hitlAuditLogger is the audit dependency of the multi-agent step gate: just the canonical
// workflow-operation writer. Narrowing to an interface (rather than holding the
// concrete *AuditLogger) lets a test inject a recording fake and assert the
// step_gate row deterministically, with no async worker or database. *AuditLogger
// satisfies it.
type hitlAuditLogger interface {
	LogWorkflowOperation(ctx context.Context, entry *WorkflowAuditEntry)
}

// stepGateEntry is the step_gate row for a step at branchPath. An empty path is
// a top-level step's row; a branch step's row adds its path as StepID and
// Metadata["branch_path"] (#4249 row 5665091860), so two branch steps with one
// name are recorded apart. It is the one step-gate row builder of the map
// plane: the step gate's rows and a confirm or step mode step's row
// (auditStepModeDecision) are built here.
func stepGateEntry(workflowID, workflowName string, step WorkflowStep, pr *PolicyCheckResult, user UserContext, branchPath string) *WorkflowAuditEntry {
	var decided anchoredDecision
	if pr.decided != nil {
		decided = *pr.decided
	}
	entry := &WorkflowAuditEntry{
		WorkflowID:   workflowID,
		WorkflowName: workflowName,
		StepName:     step.Name,
		Operation:    "step_gate",
		Decision:     pr.Action, // "allow" | "block" | "require_approval" → canonical via workflowAuditDecision
		// The anchored decision, under plane "map" (PRD v11 §5.7).
		Plane:            decided.Plane,
		Engine:           decided.Engine,
		SubjectType:      decided.SubjectType,
		PolicyBundle:     decided.PolicyBundle,
		EngineDecisionID: decided.DecisionID,
		Reason:           pr.Reason,
		TenantID:         user.TenantID,
		OrgID:            user.OrgID,
		UserEmail:        user.Email,
		UserRole:         user.Role,
		Metadata: map[string]interface{}{
			"policy_id":   pr.PolicyID,
			"policy_name": pr.PolicyName,
			"severity":    pr.Severity,
			"step_type":   step.Type,
		},
	}
	if branchPath != "" {
		entry.StepID = branchPath
		entry.Metadata["branch_path"] = branchPath
	}
	return entry
}

// stepGateErrorEntry is the step_gate row of a fail-open policy-check error
// (#2698).
func stepGateErrorEntry(executionID, workflowName string, step WorkflowStep, checkErr error, user UserContext) *WorkflowAuditEntry {
	return &WorkflowAuditEntry{
		WorkflowID:   executionID,
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
	}
}
