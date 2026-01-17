// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"errors"
	"testing"
)

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "workflow not found",
			err:  ErrWorkflowNotFound,
			want: true,
		},
		{
			name: "step not found",
			err:  ErrStepNotFound,
			want: true,
		},
		{
			name: "other error",
			err:  ErrWorkflowTerminal,
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("something went wrong"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsNotFoundError(tt.err); got != tt.want {
				t.Errorf("IsNotFoundError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsConflictError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "workflow terminal",
			err:  ErrWorkflowTerminal,
			want: true,
		},
		{
			name: "approval pending",
			err:  ErrApprovalPending,
			want: true,
		},
		{
			name: "no approval needed",
			err:  ErrNoApprovalNeeded,
			want: true,
		},
		{
			name: "not pending approval",
			err:  ErrNotPendingApproval,
			want: true,
		},
		{
			name: "step rejected",
			err:  ErrStepRejected,
			want: true,
		},
		{
			name: "not found error",
			err:  ErrWorkflowNotFound,
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("something went wrong"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConflictError(tt.err); got != tt.want {
				t.Errorf("IsConflictError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "invalid workflow name",
			err:  ErrInvalidWorkflowName,
			want: true,
		},
		{
			name: "invalid step type",
			err:  ErrInvalidStepType,
			want: true,
		},
		{
			name: "not found error",
			err:  ErrWorkflowNotFound,
			want: false,
		},
		{
			name: "conflict error",
			err:  ErrWorkflowTerminal,
			want: false,
		},
		{
			name: "generic error",
			err:  errors.New("something went wrong"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidationError(tt.err); got != tt.want {
				t.Errorf("IsValidationError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorMessages(t *testing.T) {
	tests := []struct {
		err     error
		wantMsg string
	}{
		{ErrWorkflowNotFound, "workflow not found"},
		{ErrStepNotFound, "step not found"},
		{ErrWorkflowTerminal, "workflow is in terminal state"},
		{ErrApprovalPending, "workflow has pending approval"},
		{ErrNoApprovalNeeded, "step does not require approval"},
		{ErrNotPendingApproval, "step is not pending approval"},
		{ErrInvalidWorkflowName, "workflow_name is required"},
		{ErrInvalidStepType, "step_type is required"},
		{ErrStepRejected, "step was rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.wantMsg, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("error message = %s, want %s", got, tt.wantMsg)
			}
		})
	}
}
