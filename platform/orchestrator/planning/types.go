// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package planning provides types and repository for Multi-Agent Planning (MAP)
// two-step execution flow: GeneratePlan stores plans, ExecutePlan executes them.
package planning

import (
	"encoding/json"
	"errors"
	"time"
)

// Plan status constants
type PlanStatus string

const (
	PlanStatusPending   PlanStatus = "pending"
	PlanStatusExecuting PlanStatus = "executing"
	PlanStatusCompleted PlanStatus = "completed"
	PlanStatusFailed    PlanStatus = "failed"
	PlanStatusExpired   PlanStatus = "expired"
)

// DefaultPlanTTL is the default time-to-live for plans (1 hour)
const DefaultPlanTTL = 1 * time.Hour

// Common errors
var (
	ErrPlanNotFound    = errors.New("plan not found")
	ErrPlanExpired     = errors.New("plan has expired")
	ErrPlanAlreadyRun  = errors.New("plan has already been executed")
	ErrInvalidPlanID   = errors.New("invalid plan ID")
	ErrInvalidWorkflow = errors.New("invalid workflow definition")
)

// Plan represents a stored multi-agent plan
type Plan struct {
	PlanID        string `json:"plan_id"`
	Query         string `json:"query"`
	Domain        string `json:"domain"`
	ExecutionMode string `json:"execution_mode"`

	// Workflow definition (stored as JSON)
	WorkflowDefinition json.RawMessage `json:"workflow_definition"`

	// Plan metadata
	Complexity        int    `json:"complexity"`
	Parallel          bool   `json:"parallel"`
	EstimatedDuration string `json:"estimated_duration"`
	StepCount         int    `json:"step_count"`

	// Execution state
	Status          PlanStatus      `json:"status"`
	ExecutedAt      *time.Time      `json:"executed_at,omitempty"`
	ExecutionResult json.RawMessage `json:"execution_result,omitempty"`
	ErrorMessage    string          `json:"error_message,omitempty"`

	// Multi-tenancy
	OrgID    string `json:"org_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`

	// TTL
	ExpiresAt time.Time `json:"expires_at"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// IsExpired returns true if the plan has passed its expiration time
func (p *Plan) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// CanExecute returns true if the plan can be executed
func (p *Plan) CanExecute() bool {
	return p.Status == PlanStatusPending && !p.IsExpired()
}

// PlanStep represents a step in the plan (for API response)
type PlanStep struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Type         string                 `json:"type"`
	Description  string                 `json:"description,omitempty"`
	Dependencies []string               `json:"dependencies,omitempty"`
	Agent        string                 `json:"agent,omitempty"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
}

// CreatePlanRequest contains the data needed to create a plan
type CreatePlanRequest struct {
	PlanID             string
	Query              string
	Domain             string
	ExecutionMode      string
	WorkflowDefinition json.RawMessage
	Complexity         int
	Parallel           bool
	EstimatedDuration  string
	StepCount          int
	OrgID              string
	TenantID           string
	UserID             string
	ClientID           string
	TTL                time.Duration // Optional, defaults to DefaultPlanTTL
}

// ExecutePlanResult contains the result of plan execution
type ExecutePlanResult struct {
	PlanID         string                 `json:"plan_id"`
	Status         string                 `json:"status"`
	Result         interface{}            `json:"result,omitempty"`
	StepResults    []StepResult           `json:"step_results,omitempty"`
	Error          string                 `json:"error,omitempty"`
	Duration       string                 `json:"duration,omitempty"`
	CompletedSteps int                    `json:"completed_steps"`
	TotalSteps     int                    `json:"total_steps"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// StepResult represents the result of a single step execution
type StepResult struct {
	StepID   string      `json:"step_id"`
	StepName string      `json:"step_name"`
	Status   string      `json:"status"`
	Result   interface{} `json:"result,omitempty"`
	Error    string      `json:"error,omitempty"`
	Duration string      `json:"duration,omitempty"`
}
