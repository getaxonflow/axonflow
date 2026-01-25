// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package execution

import (
	"testing"
	"time"
)

func TestExecutionStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		status   ExecutionStatusValue
		expected bool
	}{
		{"pending is not terminal", StatusPending, false},
		{"running is not terminal", StatusRunning, false},
		{"completed is terminal", StatusCompleted, true},
		{"failed is terminal", StatusFailed, true},
		{"cancelled is terminal", StatusCancelled, true},
		{"aborted is terminal", StatusAborted, true},
		{"expired is terminal", StatusExpired, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &ExecutionStatus{Status: tt.status}
			if got := exec.IsTerminal(); got != tt.expected {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_CalculateProgress(t *testing.T) {
	tests := []struct {
		name       string
		totalSteps int
		steps      []StepStatus
		expected   float64
	}{
		{
			name:       "no steps",
			totalSteps: 0,
			steps:      []StepStatus{},
			expected:   0,
		},
		{
			name:       "no completed steps",
			totalSteps: 3,
			steps: []StepStatus{
				{Status: StepStatusPending},
				{Status: StepStatusPending},
				{Status: StepStatusPending},
			},
			expected: 0,
		},
		{
			name:       "one completed step",
			totalSteps: 3,
			steps: []StepStatus{
				{Status: StepStatusCompleted},
				{Status: StepStatusRunning},
				{Status: StepStatusPending},
			},
			expected: 33.33333333333333,
		},
		{
			name:       "all completed",
			totalSteps: 3,
			steps: []StepStatus{
				{Status: StepStatusCompleted},
				{Status: StepStatusCompleted},
				{Status: StepStatusCompleted},
			},
			expected: 100,
		},
		{
			name:       "half completed",
			totalSteps: 4,
			steps: []StepStatus{
				{Status: StepStatusCompleted},
				{Status: StepStatusCompleted},
				{Status: StepStatusRunning},
				{Status: StepStatusPending},
			},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &ExecutionStatus{
				TotalSteps: tt.totalSteps,
				Steps:      tt.steps,
			}
			got := exec.CalculateProgress()
			if got != tt.expected {
				t.Errorf("CalculateProgress() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_TotalCost(t *testing.T) {
	cost1 := 0.01
	cost2 := 0.02
	cost3 := 0.005

	tests := []struct {
		name     string
		steps    []StepStatus
		expected float64
	}{
		{
			name:     "no steps",
			steps:    []StepStatus{},
			expected: 0,
		},
		{
			name: "steps without cost",
			steps: []StepStatus{
				{StepID: "1"},
				{StepID: "2"},
			},
			expected: 0,
		},
		{
			name: "steps with cost",
			steps: []StepStatus{
				{StepID: "1", CostUSD: &cost1},
				{StepID: "2", CostUSD: &cost2},
				{StepID: "3", CostUSD: &cost3},
			},
			expected: 0.035,
		},
		{
			name: "mixed steps",
			steps: []StepStatus{
				{StepID: "1", CostUSD: &cost1},
				{StepID: "2"},
				{StepID: "3", CostUSD: &cost3},
			},
			expected: 0.015,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &ExecutionStatus{Steps: tt.steps}
			got := exec.TotalCost()
			// Use approximate comparison for floating point
			diff := got - tt.expected
			if diff < 0 {
				diff = -diff
			}
			if diff > 0.0001 {
				t.Errorf("TotalCost() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecutionStatus_GetCurrentStep(t *testing.T) {
	tests := []struct {
		name          string
		steps         []StepStatus
		expectedID    string
		expectedFound bool
	}{
		{
			name:          "no steps",
			steps:         []StepStatus{},
			expectedID:    "",
			expectedFound: false,
		},
		{
			name: "no running step",
			steps: []StepStatus{
				{StepID: "1", Status: StepStatusCompleted},
				{StepID: "2", Status: StepStatusPending},
			},
			expectedID:    "",
			expectedFound: false,
		},
		{
			name: "has running step",
			steps: []StepStatus{
				{StepID: "1", Status: StepStatusCompleted},
				{StepID: "2", Status: StepStatusRunning},
				{StepID: "3", Status: StepStatusPending},
			},
			expectedID:    "2",
			expectedFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &ExecutionStatus{Steps: tt.steps}
			got := exec.GetCurrentStep()

			if tt.expectedFound {
				if got == nil {
					t.Errorf("GetCurrentStep() = nil, want step with ID %s", tt.expectedID)
				} else if got.StepID != tt.expectedID {
					t.Errorf("GetCurrentStep().StepID = %s, want %s", got.StepID, tt.expectedID)
				}
			} else {
				if got != nil {
					t.Errorf("GetCurrentStep() = %v, want nil", got)
				}
			}
		})
	}
}

func TestExecutionStatus_CalculateDuration(t *testing.T) {
	now := time.Now()
	completedAt := now.Add(-30 * time.Second)

	tests := []struct {
		name        string
		startedAt   time.Time
		completedAt *time.Time
		expectEmpty bool
	}{
		{
			name:        "zero start time",
			startedAt:   time.Time{},
			completedAt: nil,
			expectEmpty: true,
		},
		{
			name:        "ongoing execution",
			startedAt:   now.Add(-10 * time.Second),
			completedAt: nil,
			expectEmpty: false,
		},
		{
			name:        "completed execution",
			startedAt:   now.Add(-60 * time.Second),
			completedAt: &completedAt,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &ExecutionStatus{
				StartedAt:   tt.startedAt,
				CompletedAt: tt.completedAt,
			}
			got := exec.CalculateDuration()

			if tt.expectEmpty && got != "" {
				t.Errorf("CalculateDuration() = %s, want empty", got)
			}
			if !tt.expectEmpty && got == "" {
				t.Errorf("CalculateDuration() = empty, want non-empty")
			}
		})
	}
}

func TestStepStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		name     string
		status   StepStatusValue
		expected bool
	}{
		{"pending is not terminal", StepStatusPending, false},
		{"running is not terminal", StepStatusRunning, false},
		{"approval is not terminal", StepStatusApproval, false},
		{"blocked is not terminal", StepStatusBlocked, false},
		{"completed is terminal", StepStatusCompleted, true},
		{"failed is terminal", StepStatusFailed, true},
		{"skipped is terminal", StepStatusSkipped, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &StepStatus{Status: tt.status}
			if got := step.IsTerminal(); got != tt.expected {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStepStatus_IsBlocking(t *testing.T) {
	tests := []struct {
		name     string
		status   StepStatusValue
		expected bool
	}{
		{"pending is not blocking", StepStatusPending, false},
		{"running is not blocking", StepStatusRunning, false},
		{"completed is not blocking", StepStatusCompleted, false},
		{"blocked is blocking", StepStatusBlocked, true},
		{"approval is blocking", StepStatusApproval, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &StepStatus{Status: tt.status}
			if got := step.IsBlocking(); got != tt.expected {
				t.Errorf("IsBlocking() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestStepStatus_CalculateDuration(t *testing.T) {
	now := time.Now()
	endedAt := now.Add(5 * time.Second)

	tests := []struct {
		name        string
		startedAt   *time.Time
		endedAt     *time.Time
		expectEmpty bool
	}{
		{
			name:        "nil start time",
			startedAt:   nil,
			endedAt:     nil,
			expectEmpty: true,
		},
		{
			name:        "ongoing step",
			startedAt:   &now,
			endedAt:     nil,
			expectEmpty: false,
		},
		{
			name:        "completed step",
			startedAt:   &now,
			endedAt:     &endedAt,
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &StepStatus{
				StartedAt: tt.startedAt,
				EndedAt:   tt.endedAt,
			}
			got := step.CalculateDuration()

			if tt.expectEmpty && got != "" {
				t.Errorf("CalculateDuration() = %s, want empty", got)
			}
			if !tt.expectEmpty && got == "" {
				t.Errorf("CalculateDuration() = empty, want non-empty")
			}
		})
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{"milliseconds", 500 * time.Millisecond, "500ms"},
		{"seconds", 5 * time.Second, "5s"},
		{"minutes and seconds", 2*time.Minute + 30*time.Second, "2m30s"},
		{"hours", 2*time.Hour + 15*time.Minute, "2h15m0s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatDuration(tt.duration)
			if got != tt.want {
				t.Errorf("formatDuration(%v) = %s, want %s", tt.duration, got, tt.want)
			}
		})
	}
}

func TestGenerateExecutionID(t *testing.T) {
	tests := []struct {
		name       string
		execType   ExecutionType
		wantPrefix string
	}{
		{"MAP generates plan_ prefix", ExecutionTypeMAP, "plan_"},
		{"WCP generates wf_ prefix", ExecutionTypeWCP, "wf_"},
		{"unknown generates exec_ prefix", ExecutionType("unknown"), "exec_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateExecutionID(tt.execType)
			if len(got) < len(tt.wantPrefix)+10 {
				t.Errorf("generateExecutionID() = %s, want longer ID", got)
			}
			if got[:len(tt.wantPrefix)] != tt.wantPrefix {
				t.Errorf("generateExecutionID() = %s, want prefix %s", got, tt.wantPrefix)
			}
		})
	}

	// Test uniqueness
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateExecutionID(ExecutionTypeMAP)
		if ids[id] {
			t.Errorf("generateExecutionID() produced duplicate ID: %s", id)
		}
		ids[id] = true
	}
}
