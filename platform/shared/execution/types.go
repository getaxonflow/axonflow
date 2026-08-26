// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package execution provides unified execution tracking for MAP and WCP.
//
// This package implements the shared infrastructure described in ADR-030,
// enabling consistent status tracking, step-level progress, and cost tracking
// across both Multi-Agent Planning (MAP) and Workflow Control Plane (WCP).
package execution

import (
	"encoding/json"
	"time"
)

// ExecutionType distinguishes between MAP plans and WCP workflows.
type ExecutionType string

const (
	// ExecutionTypeMAP represents a Multi-Agent Planning execution.
	ExecutionTypeMAP ExecutionType = "map_plan"
	// ExecutionTypeWCP represents a Workflow Control Plane execution.
	ExecutionTypeWCP ExecutionType = "wcp_workflow"
)

// ExecutionStatusValue represents the status of an execution.
type ExecutionStatusValue string

const (
	StatusPending    ExecutionStatusValue = "pending"
	StatusRunning    ExecutionStatusValue = "running"
	StatusCompleted  ExecutionStatusValue = "completed"
	StatusFailed     ExecutionStatusValue = "failed"
	StatusCancelled  ExecutionStatusValue = "cancelled"
	StatusAborted    ExecutionStatusValue = "aborted" // WCP-specific: workflow aborted
	StatusExpired    ExecutionStatusValue = "expired" // MAP-specific: plan expired before execution
)

// StepStatusValue represents the status of an individual step.
type StepStatusValue string

const (
	StepStatusPending   StepStatusValue = "pending"
	StepStatusRunning   StepStatusValue = "running"
	StepStatusCompleted StepStatusValue = "completed"
	StepStatusFailed    StepStatusValue = "failed"
	StepStatusSkipped   StepStatusValue = "skipped"
	StepStatusBlocked   StepStatusValue = "blocked" // WCP: blocked by policy
	StepStatusApproval  StepStatusValue = "approval" // WCP: waiting for approval
)

// StepType represents the type of workflow step.
type StepType string

const (
	StepTypeLLMCall       StepType = "llm_call"
	StepTypeToolCall      StepType = "tool_call"
	StepTypeConnectorCall StepType = "connector_call"
	StepTypeHumanTask     StepType = "human_task"
	StepTypeSynthesis     StepType = "synthesis" // MAP: result synthesis step
	StepTypeAction        StepType = "action"    // Generic action step
	StepTypeGate          StepType = "gate"      // WCP: policy gate evaluation
)

// GateDecision represents the policy decision for a step (WCP).
type GateDecision string

const (
	GateDecisionAllow           GateDecision = "allow"
	GateDecisionBlock           GateDecision = "block"
	GateDecisionRequireApproval GateDecision = "require_approval"
)

// ApprovalStatus represents the approval state for require_approval decisions.
type ApprovalStatus string

const (
	ApprovalStatusPending  ApprovalStatus = "pending"
	ApprovalStatusApproved ApprovalStatus = "approved"
	ApprovalStatusRejected ApprovalStatus = "rejected"
	// ApprovalStatusExpired is a terminal "not approved" state produced when a
	// require_approval step times out (auto-expiry) rather than being explicitly
	// reviewed. It is surfaced distinctly from a human reject so a timeout is
	// never reported as a rejection (#2654).
	ApprovalStatusExpired ApprovalStatus = "expired"
)

// ExecutionStatus is the unified status response for both MAP and WCP.
// This type is used in API responses and SDK methods.
type ExecutionStatus struct {
	// Identity
	ExecutionID   string        `json:"execution_id"`
	ExecutionType ExecutionType `json:"execution_type"`
	Name          string        `json:"name"`

	// ExternalID is the source system's identifier for this run (#3442). It is
	// WRITE-SIDE ONLY: Create persists it to execution_history.external_id, and
	// no SELECT in this package reads the column back, so a value read from the
	// database always arrives empty. It is therefore not serialized - a field
	// that is present on a write and absent on the matching read is exactly the
	// kind of half-truth an API should not publish. A future reader must add
	// the column to the SELECT lists in repository.go before removing `json:"-"`.
	ExternalID string `json:"-"`

	// Source (WCP-specific: langchain, crewai, etc.)
	Source string `json:"source,omitempty"`

	// Progress
	Status           ExecutionStatusValue `json:"status"`
	CurrentStepIndex int                  `json:"current_step_index"`
	TotalSteps       int                  `json:"total_steps"`
	ProgressPercent  float64              `json:"progress_percent"`

	// Timing
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Duration    string     `json:"duration,omitempty"`

	// Cost tracking
	EstimatedCostUSD *float64 `json:"estimated_cost_usd,omitempty"`
	ActualCostUSD    *float64 `json:"actual_cost_usd,omitempty"`

	// Steps with full details
	Steps []StepStatus `json:"steps,omitempty"`

	// Error information
	Error string `json:"error,omitempty"`

	// Multi-tenancy context
	TenantID string `json:"tenant_id,omitempty"`
	OrgID    string `json:"org_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// StepStatus provides detailed information about an individual step.
type StepStatus struct {
	// Identity
	StepID    string   `json:"step_id"`
	StepIndex int      `json:"step_index"`
	StepName  string   `json:"step_name"`
	StepType  StepType `json:"step_type"`

	// Status
	Status    StepStatusValue `json:"status"`
	StartedAt *time.Time      `json:"started_at,omitempty"`
	EndedAt   *time.Time      `json:"ended_at,omitempty"`
	Duration  string          `json:"duration,omitempty"`

	// Policy evaluation (applicable to both MAP and WCP)
	Decision        GateDecision `json:"decision,omitempty"`
	DecisionReason  string       `json:"decision_reason,omitempty"`
	PoliciesMatched []string     `json:"policies_matched,omitempty"`

	// Approval (WCP-specific, but included for unified schema).
	// approved_by / approved_at are populated on the approval path; rejected_by
	// / rejected_at on the rejection path. The two pairs are mutually exclusive
	// at projection time even though the underlying workflow_steps row stores
	// the reviewer identity in a single shared column — the split mirrors
	// workflow_control.ProjectStepGateToHTTP so UIs can key off approval_status.
	ApprovalStatus *ApprovalStatus `json:"approval_status,omitempty"`
	ApprovedBy     string          `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time      `json:"approved_at,omitempty"`
	RejectedBy     string          `json:"rejected_by,omitempty"`
	RejectedAt     *time.Time      `json:"rejected_at,omitempty"`

	// LLM/Provider info
	Model    string `json:"model,omitempty"`
	Provider string `json:"provider,omitempty"`

	// Cost tracking per step
	CostUSD *float64 `json:"cost_usd,omitempty"`

	// Token tracking per step
	TokensIn  *int `json:"tokens_in,omitempty"`
	TokensOut *int `json:"tokens_out,omitempty"`

	// Input/Output (optional, can be large)
	Input  json.RawMessage `json:"input,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`

	// Result summary (human-readable)
	ResultSummary string `json:"result_summary,omitempty"`

	// Error information
	Error string `json:"error,omitempty"`
}

// PolicyMatch represents a policy that was evaluated/matched during execution.
type PolicyMatch struct {
	PolicyID          string `json:"policy_id"`
	PolicyName        string `json:"policy_name"`
	Action            string `json:"action"`
	Reason            string `json:"reason,omitempty"`
	RiskLevel         string `json:"risk_level,omitempty"`         // low|medium|high|critical (ADR-044)
	AllowOverride     bool   `json:"allow_override,omitempty"`     // false forbids session override (ADR-044)
	MatchedRule       string `json:"matched_rule,omitempty"`       // human-readable description of what matched (ADR-043)
	PolicyDescription string `json:"policy_description,omitempty"` // policy description for end-user display (ADR-043)
}

// --- Helper Methods ---

// IsTerminal returns true if the execution is in a terminal state.
func (e *ExecutionStatus) IsTerminal() bool {
	return e.Status == StatusCompleted ||
		e.Status == StatusFailed ||
		e.Status == StatusCancelled ||
		e.Status == StatusAborted ||
		e.Status == StatusExpired
}

// CalculateProgress computes the progress percentage based on completed steps.
func (e *ExecutionStatus) CalculateProgress() float64 {
	if e.TotalSteps == 0 {
		return 0
	}

	completedSteps := 0
	for _, step := range e.Steps {
		if step.Status == StepStatusCompleted {
			completedSteps++
		}
	}

	return float64(completedSteps) / float64(e.TotalSteps) * 100
}

// CalculateDuration computes the duration string from start to end/now.
func (e *ExecutionStatus) CalculateDuration() string {
	if e.StartedAt.IsZero() {
		return ""
	}

	endTime := time.Now()
	if e.CompletedAt != nil {
		endTime = *e.CompletedAt
	}

	duration := endTime.Sub(e.StartedAt)
	return formatDuration(duration)
}

// TotalCost returns the sum of all step costs.
func (e *ExecutionStatus) TotalCost() float64 {
	var total float64
	for _, step := range e.Steps {
		if step.CostUSD != nil {
			total += *step.CostUSD
		}
	}
	return total
}

// GetCurrentStep returns the currently executing step, if any.
func (e *ExecutionStatus) GetCurrentStep() *StepStatus {
	for i := range e.Steps {
		if e.Steps[i].Status == StepStatusRunning {
			return &e.Steps[i]
		}
	}
	return nil
}

// --- Step Helper Methods ---

// IsTerminal returns true if the step is in a terminal state.
func (s *StepStatus) IsTerminal() bool {
	return s.Status == StepStatusCompleted ||
		s.Status == StepStatusFailed ||
		s.Status == StepStatusSkipped
}

// IsBlocking returns true if the step is blocked (policy or approval).
func (s *StepStatus) IsBlocking() bool {
	return s.Status == StepStatusBlocked || s.Status == StepStatusApproval
}

// CalculateDuration computes the step duration.
func (s *StepStatus) CalculateDuration() string {
	if s.StartedAt == nil {
		return ""
	}

	endTime := time.Now()
	if s.EndedAt != nil {
		endTime = *s.EndedAt
	}

	duration := endTime.Sub(*s.StartedAt)
	return formatDuration(duration)
}

// --- Utility Functions ---

// formatDuration formats a duration as a human-readable string.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}

// --- Request/Response Types for API ---

// CreateExecutionRequest is the request to start tracking a new execution.
type CreateExecutionRequest struct {
	ExecutionType ExecutionType          `json:"execution_type" validate:"required"`
	Name          string                 `json:"name" validate:"required"`
	Source        string                 `json:"source,omitempty"`
	TotalSteps    int                    `json:"total_steps,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`

	// ExecutionID lets a caller whose subsystem ALREADY has the run's identity
	// hand it in rather than have a second one minted here. Empty means "mint
	// one" (generateExecutionID), which is the MAP path and the default.
	//
	// #3442: the WCP path supplies the control-plane workflow_id. A
	// `workflows` row is itself the run - it carries status,
	// current_step_index, started_at and completed_at - and its
	// execution_history row is a 1:1 projection created synchronously from it
	// (WCPExecutionTracker.OnWorkflowCreated) and resolved by
	// metadata->>'workflow_id' on every subsequent read. Minting a second
	// `wf_`-prefixed id for it put two different strings, indistinguishable by
	// prefix, on two operator screens for one run.
	//
	// Deliberately NOT serialized from any wire format: this is an
	// in-process seam between a subsystem and its projection, not something a
	// client may choose. Letting a caller name the primary key of
	// execution_history would let it address, and collide with, another
	// tenant's row.
	ExecutionID string `json:"-"`

	// ExternalID is the source system's own identifier for this run: the
	// workflow_id for WCP, the plan_id for MAP. It lands in
	// execution_history.external_id, which migration core/042 documents as
	// exactly that ("Original ID from source system (plan_id or workflow_id)")
	// and which the writer had been filling with a copy of the execution id
	// instead - an indexed correlation column that correlated a row only with
	// itself. Empty falls back to the execution id, preserving the old value
	// for any caller that does not set it.
	ExternalID string `json:"-"`

	// Tenancy
	TenantID string `json:"tenant_id,omitempty"`
	OrgID    string `json:"org_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// ListExecutionsRequest contains filters for listing executions.
type ListExecutionsRequest struct {
	ExecutionType *ExecutionType        `json:"execution_type,omitempty"`
	Status        *ExecutionStatusValue `json:"status,omitempty"`
	TenantID      string                `json:"tenant_id,omitempty"`
	OrgID         string                `json:"org_id,omitempty"`
	// OrgWide asks for an ORG-SCOPED read: every execution in OrgID, whatever
	// credential wrote it (#3367). It is an explicit statement of INTENT by a
	// caller that has established org-wide tenancy authority, and the
	// repository will not serve that read without it.
	//
	// It is a field rather than an inference from "OrgID set, TenantID empty",
	// because that shape is reachable by simply OMITTING a header, while the
	// authority behind it is not. Keying the BYPASSRLS read on the shape would
	// hand it to any caller who left X-Tenant-ID off, which is the
	// guard-by-shape mistake rather than guard-by-capability. Deliberately not
	// serialized: no wire format may set it, only server-side code that has
	// resolved the caller's authority.
	OrgWide bool `json:"-"`
	Limit   int  `json:"limit,omitempty"`
	Offset  int  `json:"offset,omitempty"`
}

// CancelExecutionRequest is the request to cancel an execution.
type CancelExecutionRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ListExecutionsResponse is the paginated response for listing executions.
type ListExecutionsResponse struct {
	Executions []ExecutionStatus `json:"executions"`
	Total      int               `json:"total"`
	Limit      int               `json:"limit"`
	Offset     int               `json:"offset"`
	HasMore    bool              `json:"has_more"`
}
