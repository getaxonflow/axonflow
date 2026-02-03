// Package axonflow provides an HTTP client for the AxonFlow API.
package axonflow

import (
	"encoding/json"
	"time"
)

// StepStatus represents the status of an execution step.
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusPaused    StepStatus = "paused"
)

// ExecutionStatus represents the status of an execution.
type ExecutionStatus string

const (
	ExecutionStatusPending   ExecutionStatus = "pending"
	ExecutionStatusRunning   ExecutionStatus = "running"
	ExecutionStatusCompleted ExecutionStatus = "completed"
	ExecutionStatusFailed    ExecutionStatus = "failed"
)

// ExecutionSnapshot represents a single step in a workflow execution.
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

	Provider  string  `json:"provider,omitempty"`
	Model     string  `json:"model,omitempty"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	CostUSD   float64 `json:"cost_usd"`

	PoliciesChecked   []string      `json:"policies_checked"`
	PoliciesTriggered []PolicyEvent `json:"policies_triggered"`

	ErrorMessage string `json:"error_message,omitempty"`
	RetryCount   int    `json:"retry_count"`

	CreatedAt time.Time `json:"created_at,omitempty"`
}

// PolicyEvent represents a policy that was triggered during step execution.
type PolicyEvent struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name,omitempty"`
	Action     string `json:"action"`
	Matched    string `json:"matched"`
	Resolution string `json:"resolution"`
}

// ExecutionSummary provides an overview of a workflow execution.
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

	OrgID    string `json:"org_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`

	InputSummary  json.RawMessage `json:"input_summary,omitempty"`
	OutputSummary json.RawMessage `json:"output_summary,omitempty"`
	ErrorMessage  string          `json:"error_message,omitempty"`

	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Execution combines summary and steps for full execution details.
type Execution struct {
	Summary *ExecutionSummary   `json:"summary"`
	Steps   []ExecutionSnapshot `json:"steps"`
}

// TimelineEntry represents a single entry in the execution timeline.
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

// ListExecutionsResponse is the API response for listing executions.
type ListExecutionsResponse struct {
	Executions []ExecutionSummary `json:"executions"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
}

// ListOptions provides filtering and pagination for listing executions.
type ListOptions struct {
	Status     string `json:"status,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
	WorkflowID string `json:"workflow_id,omitempty"`
}

// ErrorResponse represents an API error response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
