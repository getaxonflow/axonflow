// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/orchestrator/workflow_control"
)

func TestStepGateStatesTypedMoneyFromInputsItRuns(t *testing.T) {
	step := contentStep(workflow_control.StepTypeToolCall,
		map[string]interface{}{"amount_minor": float64(94900), "currency": "USD"},
		&workflow_control.ToolContext{ToolName: "support-ops.issue_refund",
			ToolInput: map[string]interface{}{"amount_minor": float64(94900), "currency": "USD"}})
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	facts, _, err := stepPlaneProducer(t).Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		"args.step_input.amount_minor": float64(94900), "args.step_input.currency": "USD",
		"args.tool_input.amount_minor": float64(94900), "args.tool_input.currency": "USD",
	} {
		got := facts[path]
		if got.State != contract.StateKnown || got.Value != want || got.Source != contract.ProvCaller {
			t.Errorf("%s = %+v, want known caller value %v", path, got, want)
		}
	}
	step.ToolContext.ToolInput["amount_minor"] = "94900"
	req = (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	facts, _, err = stepPlaneProducer(t).Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if facts["args.tool_input.amount_minor"].State != contract.StateUnknown {
		t.Fatalf("a string amount was accepted: %+v", facts["args.tool_input.amount_minor"])
	}
}
