// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import "errors"

// Standard errors for the Workflow Control Plane
var (
	// ErrWorkflowNotFound indicates the workflow was not found
	ErrWorkflowNotFound = errors.New("workflow not found")

	// ErrStepNotFound indicates the workflow step was not found
	ErrStepNotFound = errors.New("step not found")

	// ErrWorkflowTerminal indicates the workflow is in a terminal state
	ErrWorkflowTerminal = errors.New("workflow is in terminal state")

	// ErrApprovalPending indicates the workflow has a pending approval
	ErrApprovalPending = errors.New("workflow has pending approval")

	// ErrNoApprovalNeeded indicates the step does not require approval
	ErrNoApprovalNeeded = errors.New("step does not require approval")

	// ErrNotPendingApproval indicates the step is not in pending approval state
	ErrNotPendingApproval = errors.New("step is not pending approval")

	// ErrInvalidWorkflowName indicates an invalid workflow name
	ErrInvalidWorkflowName = errors.New("workflow_name is required")

	// ErrInvalidStepType indicates an invalid step type
	ErrInvalidStepType = errors.New("step_type is required")

	// ErrStepRejected indicates the step was rejected
	ErrStepRejected = errors.New("step was rejected")
)

// IsNotFoundError checks if the error is a not found error
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrWorkflowNotFound) || errors.Is(err, ErrStepNotFound)
}

// IsConflictError checks if the error is a conflict error
func IsConflictError(err error) bool {
	return errors.Is(err, ErrWorkflowTerminal) ||
		errors.Is(err, ErrApprovalPending) ||
		errors.Is(err, ErrNoApprovalNeeded) ||
		errors.Is(err, ErrNotPendingApproval) ||
		errors.Is(err, ErrStepRejected)
}

// IsValidationError checks if the error is a validation error
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidWorkflowName) || errors.Is(err, ErrInvalidStepType)
}
