// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWorkflowStatus(t *testing.T) {
	tests := []struct {
		status     WorkflowStatus
		wantString string
	}{
		{WorkflowStatusInProgress, "in_progress"},
		{WorkflowStatusCompleted, "completed"},
		{WorkflowStatusAborted, "aborted"},
		{WorkflowStatusFailed, "failed"},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			if string(tt.status) != tt.wantString {
				t.Errorf("status = %s, want %s", tt.status, tt.wantString)
			}
		})
	}
}

func TestWorkflowSource(t *testing.T) {
	tests := []struct {
		source     WorkflowSource
		wantString string
	}{
		{WorkflowSourceLangGraph, "langgraph"},
		{WorkflowSourceLangChain, "langchain"},
		{WorkflowSourceCrewAI, "crewai"},
		{WorkflowSourceExternal, "external"},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			if string(tt.source) != tt.wantString {
				t.Errorf("source = %s, want %s", tt.source, tt.wantString)
			}
		})
	}
}

func TestGateDecision(t *testing.T) {
	tests := []struct {
		decision   GateDecision
		wantString string
	}{
		{GateDecisionAllow, "allow"},
		{GateDecisionBlock, "block"},
		{GateDecisionRequireApproval, "require_approval"},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			if string(tt.decision) != tt.wantString {
				t.Errorf("decision = %s, want %s", tt.decision, tt.wantString)
			}
		})
	}
}

func TestApprovalStatus(t *testing.T) {
	tests := []struct {
		status     ApprovalStatus
		wantString string
	}{
		{ApprovalStatusPending, "pending"},
		{ApprovalStatusApproved, "approved"},
		{ApprovalStatusRejected, "rejected"},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			if string(tt.status) != tt.wantString {
				t.Errorf("status = %s, want %s", tt.status, tt.wantString)
			}
		})
	}
}

func TestStepType(t *testing.T) {
	tests := []struct {
		stepType   StepType
		wantString string
	}{
		{StepTypeLLMCall, "llm_call"},
		{StepTypeToolCall, "tool_call"},
		{StepTypeConnectorCall, "connector_call"},
		{StepTypeHumanTask, "human_task"},
	}

	for _, tt := range tests {
		t.Run(tt.wantString, func(t *testing.T) {
			if string(tt.stepType) != tt.wantString {
				t.Errorf("step_type = %s, want %s", tt.stepType, tt.wantString)
			}
		})
	}
}

func TestWorkflowIsTerminal(t *testing.T) {
	tests := []struct {
		name         string
		status       WorkflowStatus
		wantTerminal bool
	}{
		{"in_progress is not terminal", WorkflowStatusInProgress, false},
		{"completed is terminal", WorkflowStatusCompleted, true},
		{"aborted is terminal", WorkflowStatusAborted, true},
		{"failed is terminal", WorkflowStatusFailed, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &Workflow{Status: tt.status}
			if got := w.IsTerminal(); got != tt.wantTerminal {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.wantTerminal)
			}
		})
	}
}

func TestGateDecisionIsBlockingDecision(t *testing.T) {
	tests := []struct {
		name        string
		decision    GateDecision
		wantBlocking bool
	}{
		{"allow is not blocking", GateDecisionAllow, false},
		{"block is blocking", GateDecisionBlock, true},
		{"require_approval is blocking", GateDecisionRequireApproval, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.decision.IsBlockingDecision(); got != tt.wantBlocking {
				t.Errorf("IsBlockingDecision() = %v, want %v", got, tt.wantBlocking)
			}
		})
	}
}

func TestWorkflowToStatusResponse(t *testing.T) {
	now := time.Now()
	totalSteps := 5
	completedAt := now.Add(time.Hour)
	pending := ApprovalStatusPending

	workflow := &Workflow{
		WorkflowID:       "wf_123",
		WorkflowName:     "test-workflow",
		Source:           WorkflowSourceLangGraph,
		Status:           WorkflowStatusCompleted,
		CurrentStepIndex: 3,
		TotalSteps:       &totalSteps,
		StartedAt:        now,
		CompletedAt:      &completedAt,
		Steps: []WorkflowStep{
			{
				StepID:         "step-1",
				StepIndex:      1,
				StepName:       "Generate Code",
				StepType:       StepTypeLLMCall,
				Decision:       GateDecisionAllow,
				ApprovalStatus: nil,
				GateCheckedAt:  now,
			},
			{
				StepID:         "step-2",
				StepIndex:      2,
				StepName:       "Review Code",
				StepType:       StepTypeHumanTask,
				Decision:       GateDecisionRequireApproval,
				ApprovalStatus: &pending,
				GateCheckedAt:  now.Add(time.Minute),
			},
		},
	}

	response := workflow.ToStatusResponse()

	if response.WorkflowID != "wf_123" {
		t.Errorf("workflow_id = %s, want wf_123", response.WorkflowID)
	}
	if response.WorkflowName != "test-workflow" {
		t.Errorf("workflow_name = %s, want test-workflow", response.WorkflowName)
	}
	if response.Source != WorkflowSourceLangGraph {
		t.Errorf("source = %s, want langgraph", response.Source)
	}
	if response.Status != WorkflowStatusCompleted {
		t.Errorf("status = %s, want completed", response.Status)
	}
	if response.CurrentStepIndex != 3 {
		t.Errorf("current_step_index = %d, want 3", response.CurrentStepIndex)
	}
	if response.TotalSteps == nil || *response.TotalSteps != 5 {
		t.Error("total_steps should be 5")
	}
	if response.CompletedAt == nil {
		t.Error("completed_at should not be nil")
	}
	if len(response.Steps) != 2 {
		t.Errorf("steps count = %d, want 2", len(response.Steps))
	}
	if response.Steps[0].StepID != "step-1" {
		t.Errorf("steps[0].step_id = %s, want step-1", response.Steps[0].StepID)
	}
}

func TestWorkflowToStatusResponseSurfacesApproverIdentity(t *testing.T) {
	// Regression: StepInfo previously dropped ApprovedBy / ApprovedAt on the way
	// from WorkflowStep to the response, so /api/v1/workflows/{id} always rendered
	// approved_by as null even after approval landed. Caught in banking-demo VC
	// demo verification 2026-04-21.
	now := time.Now()
	approvedAt := now.Add(2 * time.Minute)
	approved := ApprovalStatusApproved

	workflow := &Workflow{
		WorkflowID:   "wf_test",
		WorkflowName: "test",
		Source:       WorkflowSourceLangGraph,
		Status:       WorkflowStatusInProgress,
		StartedAt:    now,
		Steps: []WorkflowStep{
			{
				StepID:         "step-wire",
				StepIndex:      2,
				StepName:       "Initiate Wire Transfer",
				StepType:       StepTypeToolCall,
				Decision:       GateDecisionRequireApproval,
				ApprovalStatus: &approved,
				ApprovedBy:     "sarah.thompson@fraud.example.com",
				ApprovedAt:     &approvedAt,
				GateCheckedAt:  now,
			},
		},
	}

	response := workflow.ToStatusResponse()

	if len(response.Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(response.Steps))
	}
	if response.Steps[0].ApprovedBy != "sarah.thompson@fraud.example.com" {
		t.Errorf("approved_by = %q, want sarah.thompson@fraud.example.com", response.Steps[0].ApprovedBy)
	}
	if response.Steps[0].ApprovedAt == nil {
		t.Error("approved_at should not be nil when approval landed")
	} else if !response.Steps[0].ApprovedAt.Equal(approvedAt) {
		t.Errorf("approved_at = %v, want %v", response.Steps[0].ApprovedAt, approvedAt)
	}
}

func TestWorkflowToStatusResponseNoSteps(t *testing.T) {
	now := time.Now()

	workflow := &Workflow{
		WorkflowID:       "wf_123",
		WorkflowName:     "test-workflow",
		Source:           WorkflowSourceExternal,
		Status:           WorkflowStatusInProgress,
		CurrentStepIndex: 0,
		TotalSteps:       nil,
		StartedAt:        now,
		CompletedAt:      nil,
		Steps:            nil,
	}

	response := workflow.ToStatusResponse()

	if response.TotalSteps != nil {
		t.Error("total_steps should be nil")
	}
	if response.CompletedAt != nil {
		t.Error("completed_at should be nil")
	}
	if response.Steps != nil {
		t.Error("steps should be nil")
	}
}

func TestWorkflowToCreateResponse(t *testing.T) {
	now := time.Now()

	workflow := &Workflow{
		WorkflowID:   "wf_123",
		WorkflowName: "test-workflow",
		Source:       WorkflowSourceCrewAI,
		Status:       WorkflowStatusInProgress,
		CreatedAt:    now,
	}

	response := workflow.ToCreateResponse()

	if response.WorkflowID != "wf_123" {
		t.Errorf("workflow_id = %s, want wf_123", response.WorkflowID)
	}
	if response.WorkflowName != "test-workflow" {
		t.Errorf("workflow_name = %s, want test-workflow", response.WorkflowName)
	}
	if response.Source != WorkflowSourceCrewAI {
		t.Errorf("source = %s, want crewai", response.Source)
	}
	if response.Status != WorkflowStatusInProgress {
		t.Errorf("status = %s, want in_progress", response.Status)
	}
}

func TestWorkflowJSONSerialization(t *testing.T) {
	totalSteps := 3
	workflow := &Workflow{
		WorkflowID:       "wf_test",
		WorkflowName:     "JSON Test",
		Source:           WorkflowSourceLangChain,
		Status:           WorkflowStatusInProgress,
		CurrentStepIndex: 1,
		TotalSteps:       &totalSteps,
		TenantID:         "tenant-1",
		OrgID:            "org-1",
		Metadata:         json.RawMessage(`{"key":"value"}`),
		StartedAt:        time.Now(),
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Marshal to JSON
	data, err := json.Marshal(workflow)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Unmarshal back
	var parsed Workflow
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.WorkflowID != workflow.WorkflowID {
		t.Errorf("workflow_id = %s, want %s", parsed.WorkflowID, workflow.WorkflowID)
	}
	if parsed.WorkflowName != workflow.WorkflowName {
		t.Errorf("workflow_name = %s, want %s", parsed.WorkflowName, workflow.WorkflowName)
	}
}

func TestStepGateRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		req     StepGateRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: StepGateRequest{
				StepName: "generate",
				StepType: StepTypeLLMCall,
				Model:    "gpt-4",
				Provider: "openai",
			},
			wantErr: false,
		},
		{
			name: "minimal valid request",
			req: StepGateRequest{
				StepType: StepTypeLLMCall,
			},
			wantErr: false,
		},
		{
			name: "request with step input",
			req: StepGateRequest{
				StepName: "query",
				StepType: StepTypeToolCall,
				StepInput: map[string]interface{}{
					"query": "SELECT * FROM users",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON serialization roundtrip
			data, err := json.Marshal(tt.req)
			if err != nil {
				if !tt.wantErr {
					t.Errorf("unexpected marshal error: %v", err)
				}
				return
			}

			var parsed StepGateRequest
			if err := json.Unmarshal(data, &parsed); err != nil {
				if !tt.wantErr {
					t.Errorf("unexpected unmarshal error: %v", err)
				}
				return
			}

			if parsed.StepType != tt.req.StepType {
				t.Errorf("step_type = %s, want %s", parsed.StepType, tt.req.StepType)
			}
		})
	}
}

func TestPolicyMatch(t *testing.T) {
	pm := PolicyMatch{
		PolicyID:   "policy-1",
		PolicyName: "Block Sensitive Data",
		Action:     "block",
		Reason:     "Contains PII",
	}

	// Test JSON serialization
	data, err := json.Marshal(pm)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed PolicyMatch
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed.PolicyID != pm.PolicyID {
		t.Errorf("policy_id = %s, want %s", parsed.PolicyID, pm.PolicyID)
	}
	if parsed.Action != pm.Action {
		t.Errorf("action = %s, want %s", parsed.Action, pm.Action)
	}
}

func TestListWorkflowsOptions(t *testing.T) {
	status := WorkflowStatusInProgress
	source := WorkflowSourceLangGraph

	opts := ListWorkflowsOptions{
		Status:   &status,
		Source:   &source,
		TenantID: "tenant-1",
		OrgID:    "org-1",
		Limit:    50,
		Offset:   10,
	}

	if *opts.Status != WorkflowStatusInProgress {
		t.Errorf("status = %s, want in_progress", *opts.Status)
	}
	if *opts.Source != WorkflowSourceLangGraph {
		t.Errorf("source = %s, want langgraph", *opts.Source)
	}
	if opts.Limit != 50 {
		t.Errorf("limit = %d, want 50", opts.Limit)
	}
}
