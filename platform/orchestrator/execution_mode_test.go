// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"testing"
)

// =============================================================================
// IsValidExecutionMode tests
// =============================================================================

func TestIsValidExecutionMode(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		isEnterprise bool
		want         bool
	}{
		// Community valid modes
		{
			name:         "community sequential is valid",
			mode:         "sequential",
			isEnterprise: false,
			want:         true,
		},
		{
			name:         "community parallel is valid",
			mode:         "parallel",
			isEnterprise: false,
			want:         true,
		},
		{
			name:         "community auto is valid",
			mode:         "auto",
			isEnterprise: false,
			want:         true,
		},
		{
			name:         "community balanced is valid",
			mode:         "balanced",
			isEnterprise: false,
			want:         true,
		},

		// Community rejects enterprise modes
		{
			name:         "community rejects confirm",
			mode:         "confirm",
			isEnterprise: false,
			want:         false,
		},
		{
			name:         "community rejects step",
			mode:         "step",
			isEnterprise: false,
			want:         false,
		},

		// Enterprise allows all community modes
		{
			name:         "enterprise sequential is valid",
			mode:         "sequential",
			isEnterprise: true,
			want:         true,
		},
		{
			name:         "enterprise parallel is valid",
			mode:         "parallel",
			isEnterprise: true,
			want:         true,
		},
		{
			name:         "enterprise auto is valid",
			mode:         "auto",
			isEnterprise: true,
			want:         true,
		},
		{
			name:         "enterprise balanced is valid",
			mode:         "balanced",
			isEnterprise: true,
			want:         true,
		},

		// Enterprise allows enterprise-only modes
		{
			name:         "enterprise confirm is valid",
			mode:         "confirm",
			isEnterprise: true,
			want:         true,
		},
		{
			name:         "enterprise step is valid",
			mode:         "step",
			isEnterprise: true,
			want:         true,
		},

		// Invalid modes rejected in both tiers
		{
			name:         "community rejects empty string",
			mode:         "",
			isEnterprise: false,
			want:         false,
		},
		{
			name:         "enterprise rejects empty string",
			mode:         "",
			isEnterprise: true,
			want:         false,
		},
		{
			name:         "community rejects unknown mode",
			mode:         "turbo",
			isEnterprise: false,
			want:         false,
		},
		{
			name:         "enterprise rejects unknown mode",
			mode:         "turbo",
			isEnterprise: true,
			want:         false,
		},
		{
			name:         "rejects mode with wrong case",
			mode:         "Parallel",
			isEnterprise: false,
			want:         false,
		},
		{
			name:         "rejects mode with whitespace",
			mode:         " sequential ",
			isEnterprise: false,
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidExecutionMode(tt.mode, tt.isEnterprise)
			if got != tt.want {
				t.Errorf("IsValidExecutionMode(%q, %v) = %v, want %v",
					tt.mode, tt.isEnterprise, got, tt.want)
			}
		})
	}
}

// =============================================================================
// applyExecutionMode tests
// =============================================================================

func TestApplyExecutionMode_Sequential(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-data", Type: "connector-call", Timeout: "15s"},
				{Name: "analyze", Type: "llm-call", Timeout: "30s"},
				{Name: "synthesize-results", Type: "llm-call", Timeout: "30s"},
			},
		},
	}

	engine.applyExecutionMode(workflow, "sequential")

	// Sequential mode should not add or change timeouts -- the executor
	// simply runs steps one by one. Verify steps are unchanged.
	for _, step := range workflow.Spec.Steps {
		if step.Type == "connector-call" && step.Timeout != "15s" {
			t.Errorf("step %s: expected timeout 15s preserved, got %s",
				step.Name, step.Timeout)
		}
	}
}

func TestApplyExecutionMode_Parallel(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-flights", Type: "connector-call"},
				{Name: "fetch-hotels", Type: "connector-call"},
				{Name: "analyze", Type: "llm-call", Timeout: "60s"},
				{Name: "synthesize-results", Type: "llm-call"},
			},
		},
	}

	engine.applyExecutionMode(workflow, "parallel")

	// Parallel mode ensures all steps have timeouts set.
	for _, step := range workflow.Spec.Steps {
		if step.Timeout == "" {
			t.Errorf("step %s: expected timeout to be set in parallel mode, got empty",
				step.Name)
		}
	}

	// Steps with existing timeouts should keep them.
	if workflow.Spec.Steps[2].Timeout != "60s" {
		t.Errorf("step analyze: expected existing timeout 60s preserved, got %s",
			workflow.Spec.Steps[2].Timeout)
	}
}

func TestApplyExecutionMode_Balanced(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-flights", Type: "connector-call"},
				{Name: "fetch-hotels", Type: "connector-call"},
				{Name: "analyze", Type: "llm-call"},
				{Name: "synthesize-results", Type: "llm-call"},
			},
		},
	}

	engine.applyExecutionMode(workflow, "balanced")

	// Balanced mode: connector-call steps get a timeout set if empty.
	for _, step := range workflow.Spec.Steps {
		if step.Type == "connector-call" && step.Timeout == "" {
			t.Errorf("step %s: expected connector-call step to have timeout in balanced mode",
				step.Name)
		}
	}
}

func TestApplyExecutionMode_ConfirmAndStep(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	// confirm and step modes are stored as metadata for the WCP executor.
	// The function should not modify workflow steps.
	for _, mode := range []string{"confirm", "step"} {
		t.Run(mode, func(t *testing.T) {
			workflow := &Workflow{
				Spec: WorkflowSpec{
					Steps: []WorkflowStep{
						{Name: "task-1", Type: "llm-call"},
						{Name: "task-2", Type: "connector-call"},
					},
				},
			}

			engine.applyExecutionMode(workflow, mode)

			// Steps should remain unmodified.
			if workflow.Spec.Steps[0].Timeout != "" {
				t.Errorf("expected no timeout modification for mode %s on llm-call step", mode)
			}
			if workflow.Spec.Steps[1].Timeout != "" {
				t.Errorf("expected no timeout modification for mode %s on connector-call step", mode)
			}
		})
	}
}

func TestApplyExecutionMode_NilWorkflow(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	// Should not panic on nil workflow.
	engine.applyExecutionMode(nil, "parallel")
}

func TestApplyExecutionMode_EmptySteps(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{},
		},
	}

	// Should not panic on empty steps.
	engine.applyExecutionMode(workflow, "parallel")
}

func TestApplyExecutionMode_UnknownMode(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "task-1", Type: "llm-call"},
			},
		},
	}

	// Unknown mode should not panic; it falls through to the default case.
	engine.applyExecutionMode(workflow, "unknown-mode")
}

// =============================================================================
// applyBalancedMode tests
// =============================================================================

func TestApplyBalancedMode_ConnectorCallsGetTimeout(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-flights", Type: "connector-call"},
				{Name: "fetch-hotels", Type: "connector-call"},
				{Name: "analyze", Type: "llm-call"},
				{Name: "synthesize-results", Type: "llm-call"},
			},
		},
	}

	engine.applyBalancedMode(workflow)

	// connector-call steps should have a timeout set.
	for _, step := range workflow.Spec.Steps {
		if step.Type == "connector-call" {
			if step.Timeout == "" {
				t.Errorf("step %s: expected connector-call to have timeout in balanced mode",
					step.Name)
			}
		}
	}
}

func TestApplyBalancedMode_LLMCallsUnchanged(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "analyze", Type: "llm-call"},
				{Name: "summarize", Type: "llm-call"},
			},
		},
	}

	engine.applyBalancedMode(workflow)

	// llm-call steps should remain without timeout (not modified by balanced mode).
	for _, step := range workflow.Spec.Steps {
		if step.Type == "llm-call" && step.Timeout != "" {
			t.Errorf("step %s: expected llm-call to remain without timeout in balanced mode, got %s",
				step.Name, step.Timeout)
		}
	}
}

func TestApplyBalancedMode_PreservesExistingTimeout(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-data", Type: "connector-call", Timeout: "60s"},
			},
		},
	}

	engine.applyBalancedMode(workflow)

	// Existing timeout should be preserved.
	if workflow.Spec.Steps[0].Timeout != "60s" {
		t.Errorf("expected existing timeout 60s to be preserved, got %s",
			workflow.Spec.Steps[0].Timeout)
	}
}

func TestApplyBalancedMode_NilWorkflow(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	// Should not panic.
	engine.applyBalancedMode(nil)
}

func TestApplyBalancedMode_EmptySteps(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{},
		},
	}

	// Should not panic.
	engine.applyBalancedMode(workflow)
}

func TestApplyBalancedMode_MixedStepTypes(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "connector-1", Type: "connector-call"},
				{Name: "llm-1", Type: "llm-call"},
				{Name: "connector-2", Type: "connector-call"},
				{Name: "llm-2", Type: "llm-call"},
				{Name: "tool-1", Type: "tool-call"},
			},
		},
	}

	engine.applyBalancedMode(workflow)

	// Verify each step type is handled correctly.
	expectations := map[string]bool{
		"connector-1": true,  // should have timeout
		"llm-1":       false, // should NOT have timeout
		"connector-2": true,  // should have timeout
		"llm-2":       false, // should NOT have timeout
		"tool-1":      false, // not connector-call, should NOT have timeout
	}

	for _, step := range workflow.Spec.Steps {
		expectTimeout := expectations[step.Name]
		hasTimeout := step.Timeout != ""
		if expectTimeout && !hasTimeout {
			t.Errorf("step %s (type=%s): expected timeout to be set", step.Name, step.Type)
		}
		if !expectTimeout && hasTimeout {
			t.Errorf("step %s (type=%s): expected no timeout, got %s", step.Name, step.Type, step.Timeout)
		}
	}
}

// =============================================================================
// groupStepsForBalancedExecution tests
// =============================================================================

func TestGroupStepsForBalancedExecution_EmptySteps(t *testing.T) {
	groups := groupStepsForBalancedExecution(nil)
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for nil steps, got %d", len(groups))
	}
	if groups[0].IsParallel {
		t.Error("expected group to be sequential for nil steps")
	}
	if len(groups[0].Steps) != 0 {
		t.Errorf("expected 0 steps in group, got %d", len(groups[0].Steps))
	}

	groups = groupStepsForBalancedExecution([]WorkflowStep{})
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for empty steps, got %d", len(groups))
	}
}

func TestGroupStepsForBalancedExecution_SingleStep(t *testing.T) {
	tests := []struct {
		name     string
		step     WorkflowStep
		wantPar  bool
	}{
		{
			name:    "single connector-call",
			step:    WorkflowStep{Name: "fetch", Type: "connector-call"},
			wantPar: false, // single step is never marked parallel
		},
		{
			name:    "single llm-call",
			step:    WorkflowStep{Name: "analyze", Type: "llm-call"},
			wantPar: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups := groupStepsForBalancedExecution([]WorkflowStep{tt.step})
			if len(groups) != 1 {
				t.Fatalf("expected 1 group, got %d", len(groups))
			}
			if groups[0].IsParallel != tt.wantPar {
				t.Errorf("expected IsParallel=%v, got %v", tt.wantPar, groups[0].IsParallel)
			}
		})
	}
}

func TestGroupStepsForBalancedExecution_AllConnectorCalls(t *testing.T) {
	steps := []WorkflowStep{
		{Name: "fetch-flights", Type: "connector-call"},
		{Name: "fetch-hotels", Type: "connector-call"},
		{Name: "fetch-cars", Type: "connector-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Should have 1 group: all connector-calls in parallel.
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for all connector-calls, got %d", len(groups))
	}
	if !groups[0].IsParallel {
		t.Error("expected connector-call group to be parallel")
	}
	if len(groups[0].Steps) != 3 {
		t.Errorf("expected 3 steps in connector group, got %d", len(groups[0].Steps))
	}
}

func TestGroupStepsForBalancedExecution_AllLLMCalls(t *testing.T) {
	steps := []WorkflowStep{
		{Name: "analyze", Type: "llm-call"},
		{Name: "summarize", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Should have 1 group: all llm-calls sequential.
	if len(groups) != 1 {
		t.Fatalf("expected 1 group for all llm-calls, got %d", len(groups))
	}
	if groups[0].IsParallel {
		t.Error("expected llm-call group to be sequential")
	}
	if len(groups[0].Steps) != 2 {
		t.Errorf("expected 2 steps in llm group, got %d", len(groups[0].Steps))
	}
}

func TestGroupStepsForBalancedExecution_MixedTypes(t *testing.T) {
	steps := []WorkflowStep{
		{Name: "fetch-flights", Type: "connector-call"},
		{Name: "fetch-hotels", Type: "connector-call"},
		{Name: "analyze", Type: "llm-call"},
		{Name: "synthesize-results", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Expected groups:
	// 1. connector-calls (parallel)
	// 2. analyze (llm-call, sequential)
	// 3. synthesize-results (synthesis, sequential)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups (connectors, llm, synthesis), got %d", len(groups))
	}

	// First group: connector-calls, parallel
	if !groups[0].IsParallel {
		t.Error("expected first group (connector-calls) to be parallel")
	}
	if len(groups[0].Steps) != 2 {
		t.Errorf("expected 2 connector-call steps, got %d", len(groups[0].Steps))
	}

	// Second group: llm-call, sequential
	if groups[1].IsParallel {
		t.Error("expected second group (llm-calls) to be sequential")
	}

	// Third group: synthesis, sequential
	if groups[2].IsParallel {
		t.Error("expected third group (synthesis) to be sequential")
	}
	if len(groups[2].Steps) != 1 {
		t.Errorf("expected 1 synthesis step, got %d", len(groups[2].Steps))
	}
}

func TestGroupStepsForBalancedExecution_SynthesisDetection(t *testing.T) {
	// Verify that various synthesis step name patterns are detected correctly.
	synthesisNames := []string{
		"synthesize-results",
		"combine-data",
		"final-output",
		"summary-report",
	}

	for _, name := range synthesisNames {
		t.Run(name, func(t *testing.T) {
			steps := []WorkflowStep{
				{Name: "fetch", Type: "connector-call"},
				{Name: name, Type: "llm-call"},
			}

			groups := groupStepsForBalancedExecution(steps)

			// Should have connector group + synthesis group separately.
			if len(groups) < 2 {
				t.Fatalf("expected at least 2 groups, got %d", len(groups))
			}

			// Last group should contain the synthesis step.
			lastGroup := groups[len(groups)-1]
			if len(lastGroup.Steps) != 1 || lastGroup.Steps[0].Name != name {
				t.Errorf("expected last group to contain synthesis step %s", name)
			}
			if lastGroup.IsParallel {
				t.Error("expected synthesis group to be sequential")
			}
		})
	}
}

func TestGroupStepsForBalancedExecution_SingleConnectorNotParallel(t *testing.T) {
	// A single connector-call step should NOT be marked as parallel.
	steps := []WorkflowStep{
		{Name: "fetch-data", Type: "connector-call"},
		{Name: "synthesize-results", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// First group: single connector-call.
	connectorGroup := groups[0]
	if connectorGroup.IsParallel {
		t.Error("expected single connector-call group to NOT be parallel")
	}
}

func TestGroupStepsForBalancedExecution_ConnectorAndLLMWithSynthesis(t *testing.T) {
	steps := []WorkflowStep{
		{Name: "fetch-flights", Type: "connector-call"},
		{Name: "fetch-hotels", Type: "connector-call"},
		{Name: "analyze-budget", Type: "llm-call"},
		{Name: "check-weather", Type: "llm-call"},
		{Name: "synthesize-results", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Expected: connectors (parallel) + llm (sequential) + synthesis (sequential)
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// Connector group
	if len(groups[0].Steps) != 2 {
		t.Errorf("expected 2 connector steps, got %d", len(groups[0].Steps))
	}
	if !groups[0].IsParallel {
		t.Error("expected connector group to be parallel")
	}

	// LLM group
	if len(groups[1].Steps) != 2 {
		t.Errorf("expected 2 llm steps, got %d", len(groups[1].Steps))
	}
	if groups[1].IsParallel {
		t.Error("expected llm group to be sequential")
	}

	// Synthesis group
	if len(groups[2].Steps) != 1 {
		t.Errorf("expected 1 synthesis step, got %d", len(groups[2].Steps))
	}
	if groups[2].IsParallel {
		t.Error("expected synthesis group to be sequential")
	}
}

// =============================================================================
// Integration: applyExecutionMode + groupStepsForBalancedExecution
// =============================================================================

func TestBalancedMode_EndToEnd(t *testing.T) {
	engine := NewPlanningEngine(NewMockLLMRouter())

	workflow := &Workflow{
		Spec: WorkflowSpec{
			Steps: []WorkflowStep{
				{Name: "fetch-flights", Type: "connector-call"},
				{Name: "fetch-hotels", Type: "connector-call"},
				{Name: "analyze-reviews", Type: "llm-call"},
				{Name: "synthesize-results", Type: "llm-call"},
			},
		},
	}

	// Apply balanced mode (sets timeouts on connector-calls).
	engine.applyExecutionMode(workflow, "balanced")

	// Then group for balanced execution.
	groups := groupStepsForBalancedExecution(workflow.Spec.Steps)

	// Verify connector steps have timeouts.
	for _, step := range workflow.Spec.Steps {
		if step.Type == "connector-call" && step.Timeout == "" {
			t.Errorf("step %s: connector-call should have timeout after balanced mode", step.Name)
		}
	}

	// Verify grouping is correct.
	if len(groups) < 2 {
		t.Fatalf("expected at least 2 groups, got %d", len(groups))
	}

	// First group should be connector-calls in parallel.
	if !groups[0].IsParallel {
		t.Error("expected first group to be parallel (connector-calls)")
	}
}

// =============================================================================
// Edge cases and boundary tests
// =============================================================================

func TestIsValidExecutionMode_AllValidCommunityModes(t *testing.T) {
	// Verify exact set of valid community modes matches the exported map.
	expectedModes := []string{"sequential", "parallel", "auto", "balanced"}

	for _, mode := range expectedModes {
		if !ValidExecutionModes[mode] {
			t.Errorf("expected %s to be in ValidExecutionModes map", mode)
		}
		if !IsValidExecutionMode(mode, false) {
			t.Errorf("expected %s to be valid in community mode", mode)
		}
	}

	if len(ValidExecutionModes) != len(expectedModes) {
		t.Errorf("expected %d valid execution modes, got %d",
			len(expectedModes), len(ValidExecutionModes))
	}
}

func TestIsValidExecutionMode_AllValidEnterpriseModes(t *testing.T) {
	// Verify exact set of enterprise-only modes matches the exported map.
	expectedModes := []string{"confirm", "step"}

	for _, mode := range expectedModes {
		if !EnterpriseExecutionModes[mode] {
			t.Errorf("expected %s to be in EnterpriseExecutionModes map", mode)
		}
		if !IsValidExecutionMode(mode, true) {
			t.Errorf("expected %s to be valid in enterprise mode", mode)
		}
	}

	if len(EnterpriseExecutionModes) != len(expectedModes) {
		t.Errorf("expected %d enterprise execution modes, got %d",
			len(expectedModes), len(EnterpriseExecutionModes))
	}
}

func TestApplyExecutionMode_AllModes(t *testing.T) {
	// Verify that applyExecutionMode does not panic for any valid mode.
	engine := NewPlanningEngine(NewMockLLMRouter())

	allModes := []string{
		"sequential", "parallel", "auto", "balanced",
		"confirm", "step",
		"", "unknown",
	}

	for _, mode := range allModes {
		t.Run(mode, func(t *testing.T) {
			workflow := &Workflow{
				Spec: WorkflowSpec{
					Steps: []WorkflowStep{
						{Name: "task-1", Type: "llm-call"},
						{Name: "task-2", Type: "connector-call"},
					},
				},
			}
			// Should not panic.
			engine.applyExecutionMode(workflow, mode)
		})
	}
}

func TestGroupStepsForBalancedExecution_NoSynthesisStep(t *testing.T) {
	// When there is no synthesis step, groups should still be formed correctly.
	steps := []WorkflowStep{
		{Name: "fetch-data", Type: "connector-call"},
		{Name: "fetch-more", Type: "connector-call"},
		{Name: "analyze", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Expected: connectors (parallel) + llm (sequential), no synthesis group.
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (no synthesis), got %d", len(groups))
	}
	if !groups[0].IsParallel {
		t.Error("expected connector group to be parallel")
	}
	if groups[1].IsParallel {
		t.Error("expected llm group to be sequential")
	}
}

func TestGroupStepsForBalancedExecution_OnlySynthesis(t *testing.T) {
	// Edge case: workflow with only a synthesis step.
	steps := []WorkflowStep{
		{Name: "synthesize-results", Type: "llm-call"},
	}

	groups := groupStepsForBalancedExecution(steps)

	// Single step workflow should return single group.
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}
	if groups[0].IsParallel {
		t.Error("expected synthesis-only group to be sequential")
	}
}
