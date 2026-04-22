// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-plane HITL response parity contract (Issue #1677 Phase 3).
//
// This is the guardrail that prevents future drift between WCP's
// /api/v1/workflows/{id}/steps/{step_id}/approve|reject responses and MAP's
// /api/v1/plans/{id}/steps/{step_id}/approve|reject responses. Both planes
// must surface the same field set on the wire — the parity rule codified in
// ADR-046 (technical-docs/architecture-decisions/046-hitl-response-parity.md).
//
// If you add a field to workflow_control.StepGateHTTPResponse *and* update
// workflow_control.HITLResponseFieldSet, this test will pass automatically
// on both planes because both call ProjectStepGateToHTTP. If you forget one,
// the failure points at the missing plane — either MAP regressed or the WCP
// handler skipped the projection.

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"

	"github.com/gorilla/mux"
)

// hitlParityTestEnv wires up an in-memory WCP service + plan service so both
// planes' approve/reject handlers can be exercised against the same underlying
// step row. Returns the workflow_id the tests should use plus a cleanup hook.
type hitlParityTestEnv struct {
	wcpSvc     *workflow_control.Service
	wcpRepo    *workflow_control.MockRepository
	workflowID string
	planID     string
	stepID     string
	cleanup    func()
}

func setupHITLParityEnv(t *testing.T, caseName string) *hitlParityTestEnv {
	t.Helper()

	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")

	origWCP := workflowControlService
	origEngine := hitlWorkflowEngine
	origEnabled := hitlEnabled
	origExecutor := mapWCPExecutor
	origPlanSvc := planService

	wcpRepo := workflow_control.NewMockRepository()
	wcpSvc := workflow_control.NewService(wcpRepo, &wcpParityPolicyEvaluator{}, nil)
	workflowControlService = wcpSvc
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	planRepo := planning.NewMockRepository()
	planSvc := planning.NewService(planRepo)
	planService = planSvc
	mapWCPExecutor = NewMAPWCPExecutor(wcpSvc, planSvc)

	planID := "plan-" + caseName
	workflowID := "wf-" + caseName
	stepID := "step-" + caseName

	// Create the WCP workflow that MAP confirm/step would have created.
	metadataJSON, _ := json.Marshal(map[string]interface{}{
		"plan_id":        planID,
		"execution_mode": "confirm",
	})
	wf := &workflow_control.Workflow{
		WorkflowID:   workflowID,
		WorkflowName: "map-confirm-" + planID,
		Source:       workflow_control.WorkflowSource("map"),
		Status:       workflow_control.WorkflowStatusInProgress,
		TenantID:     "tenant-1",
		OrgID:        "org-1",
		UserID:       "user-1",
		ClientID:     "client-1",
		Metadata:     metadataJSON,
	}
	if err := wcpRepo.Create(context.Background(), wf); err != nil {
		t.Fatalf("wcpRepo.Create: %v", err)
	}

	// Gate the step through the service so retry_context counters / timestamps
	// populate properly — this matches what MAPWCPExecutor does on the live path.
	req := &workflow_control.StepGateRequest{
		StepName:       "step-name",
		StepType:       workflow_control.StepTypeToolCall,
		IdempotencyKey: "idem-" + caseName,
	}
	requireApproval := workflow_control.GateDecisionRequireApproval
	req.GateOverride = &requireApproval
	if _, err := wcpSvc.StepGate(context.Background(), workflowID, stepID, req,
		"tenant-1", "org-1", "user-1", "client-1",
	); err != nil {
		t.Fatalf("wcpSvc.StepGate: %v", err)
	}

	return &hitlParityTestEnv{
		wcpSvc:     wcpSvc,
		wcpRepo:    wcpRepo,
		workflowID: workflowID,
		planID:     planID,
		stepID:     stepID,
		cleanup: func() {
			workflowControlService = origWCP
			hitlEnabled = origEnabled
			hitlWorkflowEngine = origEngine
			mapWCPExecutor = origExecutor
			planService = origPlanSvc
			if origDeployment != "" {
				os.Setenv("DEPLOYMENT_MODE", origDeployment)
			} else {
				os.Unsetenv("DEPLOYMENT_MODE")
			}
		},
	}
}

// wcpParityPolicyEvaluator is a minimal PolicyEvaluator stub — the service
// requires a non-nil evaluator, but parity tests inject GateOverride so the
// evaluator's return value doesn't affect the test outcome.
type wcpParityPolicyEvaluator struct{}

func (wcpParityPolicyEvaluator) EvaluateStepGate(_ context.Context, _ *workflow_control.StepGateContext) *workflow_control.StepGateEvaluation {
	return &workflow_control.StepGateEvaluation{
		Decision:          workflow_control.GateDecisionRequireApproval,
		PoliciesEvaluated: []workflow_control.PolicyMatch{},
		PoliciesMatched:   []workflow_control.PolicyMatch{},
		PolicyIDs:         []string{},
	}
}

// TestHITLResponseParity asserts WCP /approve and MAP /plans/.../approve
// surface the same field set. Fails loudly when one plane drops a field that
// the other surfaces — the drift scenario Issue #1677 was filed to prevent.
func TestHITLResponseParity(t *testing.T) {
	tests := []struct {
		name   string
		verb   string // "approve" or "reject"
		body   string
		header string
	}{
		{"approve_parity", "approve", `{"comment":"Approved after full audit review"}`, "Step approved"},
		{"reject_parity", "reject", `{"reason":"Regulatory red-flag triggered full block"}`, "Step rejected, workflow aborted"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wcpKeys := callWCPHandler(t, tc.verb, tc.body, tc.name+"_wcp")
			mapKeys := callMAPHandler(t, tc.verb, tc.body, tc.name+"_map")

			// plan_id is the single intentional asymmetry — MAP populates it
			// from the URL, WCP has no plan concept so it stays empty and
			// omitempty suppresses it. Every other field must match exactly.
			allowedAsymmetry := map[string]bool{"plan_id": true}
			diff := []string{}
			for _, d := range symDiff(wcpKeys, mapKeys) {
				bare := d
				for _, prefix := range []string{"wcp-only:", "map-only:"} {
					if len(bare) > len(prefix) && bare[:len(prefix)] == prefix {
						bare = bare[len(prefix):]
					}
				}
				if !allowedAsymmetry[bare] {
					diff = append(diff, d)
				}
			}
			if len(diff) > 0 {
				t.Errorf("field-set drift between WCP and MAP %s response: %v\nWCP keys=%v\nMAP keys=%v",
					tc.verb, diff, sortedKeys(wcpKeys), sortedKeys(mapKeys))
			}

			// Every field emitted by either plane must appear in the declared
			// contract (HITLResponseFieldSet). A new field landed without
			// updating the contract → loud failure.
			for k := range wcpKeys {
				if !inSlice(workflow_control.HITLResponseFieldSet, k) {
					t.Errorf("WCP emitted field %q not declared in HITLResponseFieldSet — add it there", k)
				}
			}
			for k := range mapKeys {
				if !inSlice(workflow_control.HITLResponseFieldSet, k) {
					t.Errorf("MAP emitted field %q not declared in HITLResponseFieldSet — add it there", k)
				}
			}
		})
	}
}

// TestHITLResponseParity_EnrichmentFields asserts the fields Issue #1677
// specifically called out (retry_context, approval_id, approved_by/approved_at
// on approve, rejected_by/rejected_at on reject, policies_matched) are present
// on both planes. Guards against a future silent narrowing of the response.
func TestHITLResponseParity_EnrichmentFields(t *testing.T) {
	approveFields := []string{"retry_context", "approval_id", "approved_by", "approved_at"}
	rejectFields := []string{"retry_context", "approval_id", "rejected_by", "rejected_at"}

	wcpApprove := callWCPHandler(t, "approve", `{"comment":"Approved after full audit"}`, "enrich_wcp_appr")
	mapApprove := callMAPHandler(t, "approve", `{"comment":"Approved after full audit"}`, "enrich_map_appr")
	for _, f := range approveFields {
		if _, ok := wcpApprove[f]; !ok {
			t.Errorf("WCP approve response missing enrichment field %q", f)
		}
		if _, ok := mapApprove[f]; !ok {
			t.Errorf("MAP approve response missing enrichment field %q", f)
		}
	}

	wcpReject := callWCPHandler(t, "reject", `{"reason":"Reviewed and rejected for compliance"}`, "enrich_wcp_rej")
	mapReject := callMAPHandler(t, "reject", `{"reason":"Reviewed and rejected for compliance"}`, "enrich_map_rej")
	for _, f := range rejectFields {
		if _, ok := wcpReject[f]; !ok {
			t.Errorf("WCP reject response missing enrichment field %q", f)
		}
		if _, ok := mapReject[f]; !ok {
			t.Errorf("MAP reject response missing enrichment field %q", f)
		}
	}
}

// callWCPHandler drives the WCP approve/reject handler for a fresh test case
// and returns the emitted JSON key set.
func callWCPHandler(t *testing.T, verb, body, caseName string) map[string]json.RawMessage {
	t.Helper()
	env := setupHITLParityEnv(t, caseName)
	defer env.cleanup()

	handler := workflow_control.NewHandler(env.wcpSvc)
	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/workflows/%s/steps/%s/%s", env.workflowID, env.stepID, verb),
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": env.workflowID, "step_id": env.stepID})
	req.Header.Set("X-User-ID", "u@example.com")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	if verb == "approve" {
		handler.ApproveStep(rr, req)
	} else {
		handler.RejectStep(rr, req)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("WCP %s: status %d body=%s", verb, rr.Code, rr.Body.String())
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("WCP %s: unmarshal: %v body=%s", verb, err, rr.Body.String())
	}
	return m
}

// callMAPHandler drives the MAP plan-level approve/reject handler against the
// same WCP-backed step and returns the emitted JSON key set.
func callMAPHandler(t *testing.T, verb, body, caseName string) map[string]json.RawMessage {
	t.Helper()
	env := setupHITLParityEnv(t, caseName)
	defer env.cleanup()

	req := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/plans/%s/steps/%s/%s", env.planID, env.stepID, verb),
		bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": env.planID, "step_id": env.stepID})
	req.Header.Set("X-User-ID", "u@example.com")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")

	rr := httptest.NewRecorder()
	if verb == "approve" {
		mapStepApproveHandler(rr, req)
	} else {
		mapStepRejectHandler(rr, req)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("MAP %s: status %d body=%s", verb, rr.Code, rr.Body.String())
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("MAP %s: unmarshal: %v body=%s", verb, err, rr.Body.String())
	}
	return m
}

// symDiff returns the keys present in exactly one of the two maps.
func symDiff(a, b map[string]json.RawMessage) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, "wcp-only:"+k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, "map-only:"+k)
		}
	}
	return out
}

// TestMAPApprove_WCPBackedSurfacesRealErrors asserts that when a plan IS
// WCP-backed but the approval fails (e.g., step already approved, not pending),
// the MAP handler surfaces the real error rather than silently falling through
// to the legacy flow and returning a misleading 404 "No paused execution
// found". Guards the control-flow fix we landed in map_hitl_adapter.go.
func TestMAPApprove_WCPBackedSurfacesRealErrors(t *testing.T) {
	env := setupHITLParityEnv(t, "surface_errors")
	defer env.cleanup()

	// First approval lands successfully.
	first := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/"+env.planID+"/steps/"+env.stepID+"/approve",
		bytes.NewBufferString(`{"comment":"Approved first time around"}`))
	first = mux.SetURLVars(first, map[string]string{"id": env.planID, "step_id": env.stepID})
	first.Header.Set("X-User-ID", "approver@example.com")
	first.Header.Set("X-Tenant-ID", "tenant-1")
	first.Header.Set("X-Org-ID", "org-1")
	firstRR := httptest.NewRecorder()
	mapStepApproveHandler(firstRR, first)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("first approve should succeed, got %d: %s", firstRR.Code, firstRR.Body.String())
	}

	// Second attempt on the same (already-approved) step should fail with a
	// 409 Conflict from the WCP service, NOT a 404 legacy-fallback error.
	second := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/"+env.planID+"/steps/"+env.stepID+"/approve",
		bytes.NewBufferString(`{"comment":"Second attempt should fail"}`))
	second = mux.SetURLVars(second, map[string]string{"id": env.planID, "step_id": env.stepID})
	second.Header.Set("X-User-ID", "approver@example.com")
	second.Header.Set("X-Tenant-ID", "tenant-1")
	second.Header.Set("X-Org-ID", "org-1")
	secondRR := httptest.NewRecorder()
	mapStepApproveHandler(secondRR, second)

	if secondRR.Code == http.StatusNotFound {
		t.Fatalf("second approve returned 404 — WCP error was swallowed by legacy fallback; body=%s",
			secondRR.Body.String())
	}
	if secondRR.Code != http.StatusConflict {
		t.Fatalf("second approve expected 409 Conflict, got %d: %s",
			secondRR.Code, secondRR.Body.String())
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func inSlice(s []string, t string) bool {
	for _, v := range s {
		if v == t {
			return true
		}
	}
	return false
}
