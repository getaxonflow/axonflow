// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package replay provides execution replay and debugging capabilities for MAP workflows.
// It captures every step of workflow execution for debugging, auditing, and compliance purposes.
package replay

import (
	"encoding/json"
	"time"
)

// StepStatus represents the status of an execution step
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusPaused    StepStatus = "paused"
)

// ExecutionStatus represents the status of an execution
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
)

// ExecutionSnapshot represents a snapshot of a single step in a workflow execution.
// It captures all relevant information for replay and debugging.
type ExecutionSnapshot struct {
	ID          int             `json:"id,omitempty"`
	RequestID   string          `json:"request_id"`
	StepIndex   int             `json:"step_index"`
	StepName    string          `json:"step_name"`
	Status      StepStatus      `json:"status"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	DurationMs  *int            `json:"duration_ms,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	Output      json.RawMessage `json:"output,omitempty"`

	// LLM Details
	Provider  string  `json:"provider,omitempty"`
	Model     string  `json:"model,omitempty"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`

	// Policy Events
	PoliciesChecked   []string      `json:"policies_checked"`
	PoliciesTriggered []PolicyEvent `json:"policies_triggered"`

	// Error info
	ErrorMessage string `json:"error_message,omitempty"`
	RetryCount   int    `json:"retry_count"`

	CreatedAt time.Time `json:"created_at,omitempty"`
}

// PolicyEvent represents a policy that was triggered during step execution
type PolicyEvent struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name,omitempty"`
	Action     string `json:"action"`     // block, warn, require_approval
	Matched    string `json:"matched"`    // What triggered it
	Resolution string `json:"resolution"` // How it was resolved
}

// ExecutionSummary provides an overview of a workflow execution
type ExecutionSummary struct {
	RequestID      string          `json:"request_id"`
	WorkflowName   string          `json:"workflow_name,omitempty"`
	Status         ExecutionStatus `json:"status"`
	TotalSteps     int             `json:"total_steps"`
	CompletedSteps int             `json:"completed_steps"`
	StartedAt      time.Time       `json:"started_at"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	DurationMs     *int            `json:"duration_ms,omitempty"`
	TotalTokens    int             `json:"total_tokens"`
	TotalCostUSD   float64         `json:"total_cost_usd"`

	// Context
	OrgID    string `json:"org_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`

	// Metadata
	InputSummary  json.RawMessage `json:"input_summary,omitempty"`
	OutputSummary json.RawMessage `json:"output_summary,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Execution combines summary and steps for full execution details
type Execution struct {
	Summary *ExecutionSummary   `json:"summary"`
	Steps   []ExecutionSnapshot `json:"steps"`
}

// ListOptions provides filtering and pagination for listing executions
type ListOptions struct {
	OrgID      string     `json:"org_id,omitempty"`
	TenantID   string     `json:"tenant_id,omitempty"`
	Status     string     `json:"status,omitempty"`
	Limit      int        `json:"limit,omitempty"`
	Offset     int        `json:"offset,omitempty"`
	StartTime  *time.Time `json:"start_time,omitempty"`
	EndTime    *time.Time `json:"end_time,omitempty"`
	WorkflowID string     `json:"workflow_id,omitempty"`
}

// ExportFormat defines the format for exported execution data
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	// Future: ExportFormatPDF ExportFormat = "pdf" (Phase 2)
)

// ExportOptions provides options for exporting execution data
type ExportOptions struct {
	Format         ExportFormat `json:"format"`
	IncludeInput   bool         `json:"include_input"`
	IncludeOutput  bool         `json:"include_output"`
	IncludePolicies bool        `json:"include_policies"`
}

// TimelineEntry represents a single entry in the execution timeline
type TimelineEntry struct {
	StepIndex   int        `json:"step_index"`
	StepName    string     `json:"step_name"`
	Status      StepStatus `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	DurationMs  *int       `json:"duration_ms,omitempty"`
	HasError    bool       `json:"has_error"`
	HasApproval bool       `json:"has_approval"`
}

// NewExecutionSnapshot creates a new snapshot with defaults
func NewExecutionSnapshot(requestID, stepName string, stepIndex int) *ExecutionSnapshot {
	return &ExecutionSnapshot{
		RequestID:         requestID,
		StepIndex:         stepIndex,
		StepName:          stepName,
		Status:            StepStatusPending,
		StartedAt:         time.Now().UTC(),
		PoliciesChecked:   make([]string, 0),
		PoliciesTriggered: make([]PolicyEvent, 0),
	}
}

// NewExecutionSummary creates a new summary with defaults
func NewExecutionSummary(requestID string, totalSteps int) *ExecutionSummary {
	return &ExecutionSummary{
		RequestID:  requestID,
		Status:     ExecutionStatusPending,
		TotalSteps: totalSteps,
		StartedAt:  time.Now().UTC(),
	}
}

// MarkCompleted updates the snapshot status to completed
func (s *ExecutionSnapshot) MarkCompleted(output json.RawMessage) {
	now := time.Now().UTC()
	s.Status = StepStatusCompleted
	s.CompletedAt = &now
	duration := int(now.Sub(s.StartedAt).Milliseconds())
	s.DurationMs = &duration
	s.Output = output
}

// MarkFailed updates the snapshot status to failed
func (s *ExecutionSnapshot) MarkFailed(errMsg string) {
	now := time.Now().UTC()
	s.Status = StepStatusFailed
	s.CompletedAt = &now
	duration := int(now.Sub(s.StartedAt).Milliseconds())
	s.DurationMs = &duration
	s.ErrorMessage = errMsg
}

// MarkRunning updates the snapshot status to running
func (s *ExecutionSnapshot) MarkRunning() {
	s.Status = StepStatusRunning
	s.StartedAt = time.Now().UTC()
}

// SetLLMDetails sets the LLM-related fields
func (s *ExecutionSnapshot) SetLLMDetails(provider, model string, tokensIn, tokensOut int, cost float64) {
	s.Provider = provider
	s.Model = model
	s.TokensIn = tokensIn
	s.TokensOut = tokensOut
	s.CostUSD = cost
}

// AddPolicyEvent adds a policy event to the snapshot
func (s *ExecutionSnapshot) AddPolicyEvent(event PolicyEvent) {
	s.PoliciesTriggered = append(s.PoliciesTriggered, event)
}

// AddPolicyChecked adds a policy ID to the checked list
func (s *ExecutionSnapshot) AddPolicyChecked(policyID string) {
	s.PoliciesChecked = append(s.PoliciesChecked, policyID)
}
