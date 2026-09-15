// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"encoding/json"
	"testing"
)

// THE STEP GATE'S ANSWER NAMES HOW THE STEP WAS DECIDED (PRD v11 §5.7).
//
// A fresh answer carries the engine, the subject type and the policy bundle the
// evaluator recorded, and the step_gate row carries those with the plane and the
// engine's decision id. A cached replay reproduces a stored decision without
// deciding again, so it carries none of them.

// anchoredEvaluator answers every step with an anchored decision, every member set.
type anchoredEvaluator struct{}

func (anchoredEvaluator) EvaluateStepGate(context.Context, *StepGateContext) *StepGateEvaluation {
	return &StepGateEvaluation{
		Decision:         GateDecisionAllow,
		Reason:           "permitted",
		PolicyIDs:        []string{"test-policy"},
		Plane:            "wcp",
		Engine:           "anchored",
		SubjectType:      "Client",
		PolicyBundle:     "sha256:bundle",
		EngineDecisionID: "dec-engine-1",
	}
}

func stepGateRow(t *testing.T, capture *captureAuditLogger) *WorkflowAuditEntry {
	t.Helper()
	var rows []*WorkflowAuditEntry
	for _, e := range capture.entries {
		if e.Operation == "step_gate" {
			rows = append(rows, e)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("step_gate rows = %d, want exactly one", len(rows))
	}
	return rows[0]
}

func answerMembers(t *testing.T, resp *StepGateResponse) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var members map[string]interface{}
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return members
}

func TestTheStepGateAnswerCarriesTheEngineEnvelope(t *testing.T) {
	svc, _ := setupTestService(anchoredEvaluator{})
	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)
	workflowID := createTestWorkflow(t, svc)
	ctx := context.Background()

	fresh, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{StepType: StepTypeToolCall}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	if fresh.Cached {
		t.Fatal("PREMISE: the first gate of a step was served cached")
	}
	wire := answerMembers(t, fresh)
	for member, want := range map[string]string{"engine": "anchored", "subject_type": "Client", "policy_bundle": "sha256:bundle"} {
		if got, ok := wire[member]; !ok || got != want {
			t.Errorf("the fresh answer's %s = %v (present %v), want %q", member, got, ok, want)
		}
	}
	if fresh.DecisionID == "dec-engine-1" {
		t.Errorf("the answer's decision_id became the engine's id; it stays the gate's own identifier")
	}

	row := stepGateRow(t, capture)
	for member, got := range map[string]string{
		"plane": row.Plane, "engine": row.Engine, "subject_type": row.SubjectType,
		"policy_bundle": row.PolicyBundle, "engine decision id": row.EngineDecisionID,
	} {
		want := map[string]string{
			"plane": "wcp", "engine": "anchored", "subject_type": "Client",
			"policy_bundle": "sha256:bundle", "engine decision id": "dec-engine-1",
		}[member]
		if got != want {
			t.Errorf("the step_gate row's %s = %q, want %q", member, got, want)
		}
	}

	cached, err := svc.StepGate(ctx, workflowID, "step-1", &StepGateRequest{StepType: StepTypeToolCall}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate (replay): %v", err)
	}
	if !cached.Cached {
		t.Fatal("PREMISE: the second gate of a step was not served cached")
	}
	replay := answerMembers(t, cached)
	for _, member := range []string{"engine", "subject_type", "policy_bundle"} {
		if got, ok := replay[member]; ok {
			t.Errorf("the cached replay carries %s = %v; a replay decides nothing, so it is omitted", member, got)
		}
	}
}

// An evaluator that records no anchored decision adds nothing to the answer.
func TestAStepGateAnswerWithNoAnchoredDecisionOmitsTheEnvelope(t *testing.T) {
	svc, _ := setupTestService(&fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
	workflowID := createTestWorkflow(t, svc)
	resp, err := svc.StepGate(context.Background(), workflowID, "step-1", &StepGateRequest{StepType: StepTypeToolCall}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("StepGate: %v", err)
	}
	wire := answerMembers(t, resp)
	for _, member := range []string{"engine", "subject_type", "policy_bundle"} {
		if got, ok := wire[member]; ok {
			t.Errorf("an answer with no anchored decision carries %s = %v", member, got)
		}
	}
	if _, ok := wire["decision"]; !ok {
		t.Fatal("CONTROL: the answer carries no decision, so the omissions above prove nothing")
	}
}
