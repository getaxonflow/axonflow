// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Covers the legacy in-memory MAP HITL path (Issue #1677). Tests assert that
// when no WCP workflow is registered for a plan, the handler falls back to
// the in-memory executionStore and still projects a StepGateHTTPResponse
// shape — just with empty retry_context (no step row exists).

package orchestrator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"axonflow/platform/orchestrator/workflow_control"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// legacyHITLOrgID is the org the legacy in-memory HITL executions in this
// suite belong to; every request below asserts it via X-Org-ID.
const legacyHITLOrgID = "org-legacy-hitl"

// withLegacyHITLEnv sets DEPLOYMENT_MODE=enterprise, enables HITL, and
// installs a paused HITL execution in the in-memory store.
func withLegacyHITLEnv(t *testing.T, planID string) (uuid.UUID, func()) {
	t.Helper()
	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")

	// #3135: the handlers now run verifyAgentProxyAuth; these are behavioural
	// tests of the legacy projection, so they arrive over an authenticated hop.
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	origWCP := workflowControlService
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}
	workflowControlService = nil // force legacy path

	approvalID := uuid.New()
	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:           "exec-" + planID,
			WorkflowName: "plan-" + planID,
			Status:       StatusPaused,
			Input:        map[string]interface{}{"plan_id": planID},
			// #3067: the legacy in-memory path is bound to the caller's org
			// scope, so the stored execution must carry the identity the
			// request asserts via X-Org-ID.
			UserContext: UserContext{OrgID: legacyHITLOrgID},
		},
		ApprovalID:     approvalID,
		ApprovalStatus: "pending",
		PausedAtStep:   0,
	}
	executionStoreMutex.Lock()
	executionStore[hitlStoreKey(legacyHITLOrgID, exec.ID)] = exec
	executionStoreMutex.Unlock()

	cleanup := func() {
		executionStoreMutex.Lock()
		delete(executionStore, hitlStoreKey(legacyHITLOrgID, exec.ID))
		executionStoreMutex.Unlock()

		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
		workflowControlService = origWCP
		if origDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}
	return approvalID, cleanup
}

func TestMapStepApproveHandler_LegacyInMemoryPath(t *testing.T) {
	approvalID, cleanup := withLegacyHITLEnv(t, "legacy-plan-1")
	defer cleanup()

	// #3135: this test used to source the expected approver from the BODY,
	// which pinned the defect as a requirement. Inverted: the body now carries a
	// DIFFERENT name from the header, and the header is what must be projected.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/legacy-plan-1/steps/step-x/approve",
		bytes.NewBufferString(`{"approved_by":"forged@attacker.example"}`))
	req = mux.SetURLVars(req, map[string]string{"id": "legacy-plan-1", "step_id": "step-x"})
	req.Header.Set("X-Org-ID", legacyHITLOrgID)
	req.Header.Set("X-User-ID", "ops@example.com")
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	rr := httptest.NewRecorder()

	mapStepApproveHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	var resp workflow_control.StepGateHTTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}

	if resp.PlanID != "legacy-plan-1" {
		t.Errorf("PlanID = %q, want legacy-plan-1", resp.PlanID)
	}
	if resp.StepID != "step-x" {
		t.Errorf("StepID = %q, want step-x", resp.StepID)
	}
	if resp.ApprovalID != approvalID.String() {
		t.Errorf("ApprovalID = %q, want %q", resp.ApprovalID, approvalID.String())
	}
	if resp.ApprovedBy != "ops@example.com" {
		t.Errorf("ApprovedBy = %q, want ops@example.com (#3135: X-User-ID, never the body)", resp.ApprovedBy)
	}
	if resp.ApprovalStatus == nil || *resp.ApprovalStatus != workflow_control.ApprovalStatusApproved {
		t.Errorf("ApprovalStatus = %v, want approved", resp.ApprovalStatus)
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q, want approved (legacy back-compat mirror)", resp.Status)
	}
	if resp.Message != "Step approved" {
		t.Errorf("Message = %q, want 'Step approved'", resp.Message)
	}
	// Legacy flow has no WCP step row → retry_context zero-valued.
	if resp.RetryContext.GateCount != 0 {
		t.Errorf("RetryContext.GateCount = %d, want 0 (legacy in-memory has no WCP state)", resp.RetryContext.GateCount)
	}
	if resp.WorkflowID != "" {
		t.Errorf("WorkflowID = %q, want empty (legacy path has no WCP workflow)", resp.WorkflowID)
	}
}

func TestMapStepRejectHandler_LegacyInMemoryPath(t *testing.T) {
	approvalID, cleanup := withLegacyHITLEnv(t, "legacy-plan-2")
	defer cleanup()

	// #3135: same inversion as the approve case above — body name differs from
	// the header, header must win.
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/legacy-plan-2/steps/step-y/reject",
		bytes.NewBufferString(`{"rejected_by":"forged@attacker.example","reason":"Flagged by eyes-on review"}`))
	req = mux.SetURLVars(req, map[string]string{"id": "legacy-plan-2", "step_id": "step-y"})
	req.Header.Set("X-Org-ID", legacyHITLOrgID)
	req.Header.Set("X-User-ID", "ops@example.com")
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	rr := httptest.NewRecorder()

	mapStepRejectHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	var resp workflow_control.StepGateHTTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v body=%s", err, rr.Body.String())
	}

	if resp.PlanID != "legacy-plan-2" {
		t.Errorf("PlanID = %q, want legacy-plan-2", resp.PlanID)
	}
	if resp.StepID != "step-y" {
		t.Errorf("StepID = %q, want step-y", resp.StepID)
	}
	if resp.ApprovalID != approvalID.String() {
		t.Errorf("ApprovalID = %q, want %q", resp.ApprovalID, approvalID.String())
	}
	if resp.RejectedBy != "ops@example.com" {
		t.Errorf("RejectedBy = %q, want ops@example.com (#3135: X-User-ID, never the body)", resp.RejectedBy)
	}
	if resp.Reason != "Flagged by eyes-on review" {
		t.Errorf("Reason = %q, want 'Flagged by eyes-on review'", resp.Reason)
	}
	if resp.Message != "Step rejected, workflow aborted" {
		t.Errorf("Message = %q, want 'Step rejected, workflow aborted'", resp.Message)
	}
	if resp.ApprovalStatus == nil || *resp.ApprovalStatus != workflow_control.ApprovalStatusRejected {
		t.Errorf("ApprovalStatus = %v, want rejected", resp.ApprovalStatus)
	}
	if resp.Status != "rejected" {
		t.Errorf("Status = %q, want rejected (legacy back-compat mirror)", resp.Status)
	}
}

func TestMapStepRejectHandler_DefaultReasonForEmptyBody(t *testing.T) {
	_, cleanup := withLegacyHITLEnv(t, "legacy-plan-default")
	defer cleanup()

	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/legacy-plan-default/steps/step/reject", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "legacy-plan-default", "step_id": "step"})
	req.Header.Set("X-Org-ID", legacyHITLOrgID)
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	rr := httptest.NewRecorder()

	mapStepRejectHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rr.Code, rr.Body.String())
	}

	var resp workflow_control.StepGateHTTPResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)

	if resp.Reason != "Step rejected" {
		t.Errorf("Reason = %q, want 'Step rejected' (empty-body default)", resp.Reason)
	}
}
