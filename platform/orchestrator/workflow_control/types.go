// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Package workflow_control implements the Workflow Control Plane V1.
// It provides governance gates for external orchestrators (LangChain, LangGraph, CrewAI).
//
// The 30-second pitch:
// "LangChain runs the workflow. AxonFlow decides when it's allowed to move forward."

package workflow_control

import (
	"encoding/json"
	"time"
)

// WorkflowStatus represents the state of a workflow
type WorkflowStatus string

const (
	WorkflowStatusInProgress WorkflowStatus = "in_progress"
	WorkflowStatusCompleted  WorkflowStatus = "completed"
	WorkflowStatusAborted    WorkflowStatus = "aborted"
	WorkflowStatusFailed     WorkflowStatus = "failed"
)

// WorkflowSource represents the external orchestrator type
type WorkflowSource string

const (
	WorkflowSourceLangGraph WorkflowSource = "langgraph"
	WorkflowSourceLangChain WorkflowSource = "langchain"
	WorkflowSourceCrewAI    WorkflowSource = "crewai"
	WorkflowSourceExternal  WorkflowSource = "external"
)

// GateDecision represents the decision for a step gate
type GateDecision string

const (
	GateDecisionAllow           GateDecision = "allow"
	GateDecisionBlock           GateDecision = "block"
	GateDecisionRequireApproval GateDecision = "require_approval"
)

// ApprovalStatus represents the approval state for require_approval decisions
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
)

// StepType represents the type of workflow step
type StepType string

const (
	StepTypeLLMCall       StepType = "llm_call"
	StepTypeToolCall      StepType = "tool_call"
	StepTypeConnectorCall StepType = "connector_call"
	StepTypeHumanTask     StepType = "human_task"
)

// Workflow represents a registered workflow from an external orchestrator
type Workflow struct {
	WorkflowID       string          `json:"workflow_id" db:"workflow_id"`
	WorkflowName     string          `json:"workflow_name" db:"workflow_name"`
	Source           WorkflowSource  `json:"source" db:"source"`
	Status           WorkflowStatus  `json:"status" db:"status"`
	CurrentStepIndex int             `json:"current_step_index" db:"current_step_index"`
	TotalSteps       *int            `json:"total_steps,omitempty" db:"total_steps"`
	OrgID            string          `json:"org_id,omitempty" db:"org_id"`
	TenantID         string          `json:"tenant_id,omitempty" db:"tenant_id"`
	UserID           string          `json:"user_id,omitempty" db:"user_id"`
	ClientID         string          `json:"client_id,omitempty" db:"client_id"`
	Metadata         json.RawMessage `json:"metadata,omitempty" db:"metadata"`
	StartedAt        time.Time       `json:"started_at" db:"started_at"`
	CompletedAt      *time.Time      `json:"completed_at,omitempty" db:"completed_at"`
	CreatedAt        time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at" db:"updated_at"`
	Steps            []WorkflowStep  `json:"steps,omitempty"`
}

// WorkflowStep represents a step gate decision in a workflow
type WorkflowStep struct {
	ID                int             `json:"id" db:"id"`
	WorkflowID        string          `json:"workflow_id" db:"workflow_id"`
	StepID            string          `json:"step_id" db:"step_id"`
	StepIndex         int             `json:"step_index" db:"step_index"`
	StepName          string          `json:"step_name,omitempty" db:"step_name"`
	StepType          StepType        `json:"step_type,omitempty" db:"step_type"`
	Decision          GateDecision    `json:"decision" db:"decision"`
	DecisionReason    string          `json:"decision_reason,omitempty" db:"decision_reason"`
	PoliciesEvaluated json.RawMessage `json:"policies_evaluated,omitempty" db:"policies_evaluated"`
	PoliciesMatched   json.RawMessage `json:"policies_matched,omitempty" db:"policies_matched"`
	ApprovalStatus    *ApprovalStatus `json:"approval_status,omitempty" db:"approval_status"`
	ApprovedBy        string          `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt        *time.Time      `json:"approved_at,omitempty" db:"approved_at"`
	StepInput         json.RawMessage `json:"step_input,omitempty" db:"step_input"`
	Model             string          `json:"model,omitempty" db:"model"`
	Provider          string          `json:"provider,omitempty" db:"provider"`
	TokensIn          *int            `json:"tokens_in,omitempty" db:"tokens_in"`
	TokensOut         *int            `json:"tokens_out,omitempty" db:"tokens_out"`
	CostUSD           *float64        `json:"cost_usd,omitempty" db:"cost_usd"`
	GateCheckedAt     time.Time       `json:"gate_checked_at" db:"gate_checked_at"`
	StepCompletedAt   *time.Time      `json:"step_completed_at,omitempty" db:"step_completed_at"`
}

// --- API Request/Response Types ---

// CreateWorkflowRequest is the request to register a new workflow
type CreateWorkflowRequest struct {
	WorkflowName string                 `json:"workflow_name" validate:"required"`
	Source       WorkflowSource         `json:"source,omitempty"`
	TotalSteps   *int                   `json:"total_steps,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// CreateWorkflowResponse is the response when a workflow is created
type CreateWorkflowResponse struct {
	WorkflowID   string         `json:"workflow_id"`
	WorkflowName string         `json:"workflow_name"`
	Source       WorkflowSource `json:"source"`
	Status       WorkflowStatus `json:"status"`
	CreatedAt    time.Time      `json:"created_at"`
}

// StepGateRequest is the request to check if a step is allowed to proceed
type StepGateRequest struct {
	StepName  string                 `json:"step_name,omitempty"`
	StepType  StepType               `json:"step_type" validate:"required"`
	StepInput map[string]interface{} `json:"step_input,omitempty"`
	Model     string                 `json:"model,omitempty"`
	Provider  string                 `json:"provider,omitempty"`
	TokensIn  *int                   `json:"tokens_in,omitempty"`
	TokensOut *int                   `json:"tokens_out,omitempty"`
	CostUSD   *float64              `json:"cost_usd,omitempty"`
	// GateOverride bypasses the policy evaluator and forces a specific decision.
	// Used by MAP confirm/step modes to enforce require_approval regardless of policies.
	GateOverride *GateDecision `json:"-"`
}

// StepGateResponse is the response for a step gate check
type StepGateResponse struct {
	Decision          GateDecision  `json:"decision"`
	StepID            string        `json:"step_id"`
	DecisionID        string        `json:"decision_id,omitempty"`
	PolicyIDs         []string      `json:"policy_ids,omitempty"`
	Reason            string        `json:"reason,omitempty"`
	ApprovalURL       string        `json:"approval_url,omitempty"`
	PoliciesEvaluated []PolicyMatch `json:"policies_evaluated,omitempty"` // All policies checked (Issue #1021)
	PoliciesMatched   []PolicyMatch `json:"policies_matched,omitempty"`   // Policies that matched and contributed to decision (Issue #1021)
}

// WorkflowStatusResponse is the response for workflow status
type WorkflowStatusResponse struct {
	WorkflowID       string         `json:"workflow_id"`
	WorkflowName     string         `json:"workflow_name"`
	Source           WorkflowSource `json:"source"`
	Status           WorkflowStatus `json:"status"`
	CurrentStepIndex int            `json:"current_step_index"`
	TotalSteps       *int           `json:"total_steps,omitempty"`
	StartedAt        time.Time      `json:"started_at"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	Steps            []StepInfo     `json:"steps,omitempty"`
}

// StepInfo provides summary info about a step
type StepInfo struct {
	StepID         string          `json:"step_id"`
	StepIndex      int             `json:"step_index"`
	StepName       string          `json:"step_name,omitempty"`
	StepType       StepType        `json:"step_type,omitempty"`
	Decision       GateDecision    `json:"decision"`
	ApprovalStatus *ApprovalStatus `json:"approval_status,omitempty"`
	GateCheckedAt  time.Time       `json:"gate_checked_at"`
}

// AbortWorkflowRequest is the request to abort a workflow
type AbortWorkflowRequest struct {
	Reason string `json:"reason,omitempty"`
}

// FailWorkflowRequest is the request to mark a workflow as failed
type FailWorkflowRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ListWorkflowsOptions contains filters for listing workflows
type ListWorkflowsOptions struct {
	Status   *WorkflowStatus `json:"status,omitempty"`
	Source   *WorkflowSource `json:"source,omitempty"`
	TenantID string          `json:"tenant_id,omitempty"`
	OrgID    string          `json:"org_id,omitempty"`
	Limit    int             `json:"limit,omitempty"`
	Offset   int             `json:"offset,omitempty"`
}

// ListWorkflowsResponse is the response for listing workflows
type ListWorkflowsResponse struct {
	Workflows  []WorkflowStatusResponse `json:"workflows"`
	Total      int                      `json:"total"`
	Limit      int                      `json:"limit"`
	Offset     int                      `json:"offset"`
	HasMore    bool                     `json:"has_more"`
}

// PolicyMatch represents a matched policy for a step
type PolicyMatch struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
}

// --- Helper Functions ---

// ToStatusResponse converts a Workflow to WorkflowStatusResponse
func (w *Workflow) ToStatusResponse() WorkflowStatusResponse {
	resp := WorkflowStatusResponse{
		WorkflowID:       w.WorkflowID,
		WorkflowName:     w.WorkflowName,
		Source:           w.Source,
		Status:           w.Status,
		CurrentStepIndex: w.CurrentStepIndex,
		TotalSteps:       w.TotalSteps,
		StartedAt:        w.StartedAt,
		CompletedAt:      w.CompletedAt,
	}

	if len(w.Steps) > 0 {
		resp.Steps = make([]StepInfo, len(w.Steps))
		for i, step := range w.Steps {
			resp.Steps[i] = StepInfo{
				StepID:         step.StepID,
				StepIndex:      step.StepIndex,
				StepName:       step.StepName,
				StepType:       step.StepType,
				Decision:       step.Decision,
				ApprovalStatus: step.ApprovalStatus,
				GateCheckedAt:  step.GateCheckedAt,
			}
		}
	}

	return resp
}

// ToCreateResponse converts a Workflow to CreateWorkflowResponse
func (w *Workflow) ToCreateResponse() CreateWorkflowResponse {
	return CreateWorkflowResponse{
		WorkflowID:   w.WorkflowID,
		WorkflowName: w.WorkflowName,
		Source:       w.Source,
		Status:       w.Status,
		CreatedAt:    w.CreatedAt,
	}
}

// IsTerminal returns true if the workflow is in a terminal state
func (w *Workflow) IsTerminal() bool {
	return w.Status == WorkflowStatusCompleted ||
		w.Status == WorkflowStatusAborted ||
		w.Status == WorkflowStatusFailed
}

// IsBlockingDecision returns true if the decision blocks step execution
func (d GateDecision) IsBlockingDecision() bool {
	return d == GateDecisionBlock || d == GateDecisionRequireApproval
}
