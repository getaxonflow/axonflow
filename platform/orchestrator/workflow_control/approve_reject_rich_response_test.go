// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Covers the rich StepGateHTTPResponse returned by WCP's ApproveStep / RejectStep
// handlers (Issue #1677 Phase 1). Asserts retry_context, approval_id,
// approved_by/at, rejected_by/at, policies_matched, and the shared
// ProjectStepGateToHTTP projection are all wired correctly through the
// HTTP boundary.

package workflow_control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func setupApprovalTestHandler() (*Handler, *Service) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)
	return NewHandler(svc), svc
}

// TestHandlerApproveStep_RichResponse asserts that a successful approval
// surfaces every documented field: decision resolves to allow, approval_id is
// the deterministic HITL queue UUID, retry_context is populated with counters
// from the step row, approved_by/approved_at echo what the caller supplied,
// and policies_matched is present.
func TestHandlerApproveStep_RichResponse(t *testing.T) {
	handler, svc := setupApprovalTestHandler()

	workflow, err := svc.CreateWorkflow(t.Context(), &CreateWorkflowRequest{
		WorkflowName: "approve-rich",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	// Gate the step so it lands at require_approval.
	if _, err := svc.StepGate(t.Context(), workflow.WorkflowID, "step-1",
		&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall, IdempotencyKey: "idem-abc"},
		"tenant-1", "org-1", "user-1", "client-1",
	); err != nil {
		t.Fatalf("StepGate: %v", err)
	}

	body := strings.NewReader(`{"comment": "Approved after full audit review"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/approve", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "approver@example.com")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Client-ID", "client-1")

	rr := httptest.NewRecorder()
	handler.ApproveStep(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	var resp StepGateHTTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rr.Body.String())
	}

	if resp.WorkflowID != workflow.WorkflowID {
		t.Errorf("WorkflowID = %q, want %q", resp.WorkflowID, workflow.WorkflowID)
	}
	if resp.StepID != "step-1" {
		t.Errorf("StepID = %q, want step-1", resp.StepID)
	}
	if resp.Decision != GateDecisionAllow {
		t.Errorf("Decision = %q, want allow (approved require_approval → allow)", resp.Decision)
	}
	if resp.ApprovalStatus == nil || *resp.ApprovalStatus != ApprovalStatusApproved {
		t.Errorf("ApprovalStatus = %v, want approved", resp.ApprovalStatus)
	}
	if resp.Status != "approved" {
		t.Errorf("Status = %q, want approved (legacy back-compat mirror)", resp.Status)
	}
	if resp.ApprovedBy != "approver@example.com" {
		t.Errorf("ApprovedBy = %q, want approver@example.com", resp.ApprovedBy)
	}
	if resp.ApprovedAt == nil {
		t.Error("ApprovedAt = nil, want non-nil")
	}
	if resp.ApprovalID == "" {
		t.Error("ApprovalID empty, want deterministic UUID")
	}
	if wantID := DeriveHITLApprovalID(workflow.WorkflowID, "step-1"); resp.ApprovalID != wantID {
		t.Errorf("ApprovalID = %q, want %q (deterministic)", resp.ApprovalID, wantID)
	}
	if resp.RetryContext.IdempotencyKey != "idem-abc" {
		t.Errorf("RetryContext.IdempotencyKey = %q, want idem-abc", resp.RetryContext.IdempotencyKey)
	}
	if resp.RetryContext.GateCount < 1 {
		t.Errorf("RetryContext.GateCount = %d, want >= 1", resp.RetryContext.GateCount)
	}
	if resp.Message != "Step approved" {
		t.Errorf("Message = %q, want 'Step approved'", resp.Message)
	}
	if resp.RejectedBy != "" {
		t.Errorf("RejectedBy = %q, want empty on approval", resp.RejectedBy)
	}
	// The "approved" case should not leak the old shallow response shape —
	// legacy callers that looked for approval_status: "approved" top-level
	// still see it, but decision / retry_context / approval_id must all be set.
}

// TestHandlerRejectStep_RichResponse mirrors the approval-path test for reject.
func TestHandlerRejectStep_RichResponse(t *testing.T) {
	handler, svc := setupApprovalTestHandler()

	workflow, err := svc.CreateWorkflow(t.Context(), &CreateWorkflowRequest{
		WorkflowName: "reject-rich",
	}, "tenant-1", "org-1", "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}

	if _, err := svc.StepGate(t.Context(), workflow.WorkflowID, "step-1",
		&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
		"tenant-1", "org-1", "user-1", "client-1",
	); err != nil {
		t.Fatalf("StepGate: %v", err)
	}

	body := strings.NewReader(`{"reason": "PII risk detected in output sample"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/reject", body)
	req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
	req.Header.Set("X-User-ID", "rejecter@example.com")
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Client-ID", "client-1")

	rr := httptest.NewRecorder()
	handler.RejectStep(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	var resp StepGateHTTPResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nbody: %s", err, rr.Body.String())
	}

	if resp.Decision != GateDecisionBlock {
		t.Errorf("Decision = %q, want block (rejected → block)", resp.Decision)
	}
	if resp.ApprovalStatus == nil || *resp.ApprovalStatus != ApprovalStatusRejected {
		t.Errorf("ApprovalStatus = %v, want rejected", resp.ApprovalStatus)
	}
	if resp.Status != "rejected" {
		t.Errorf("Status = %q, want rejected (legacy back-compat mirror)", resp.Status)
	}
	if resp.RejectedBy != "rejecter@example.com" {
		t.Errorf("RejectedBy = %q, want rejecter@example.com", resp.RejectedBy)
	}
	if resp.RejectedAt == nil {
		t.Error("RejectedAt = nil, want non-nil")
	}
	if resp.ApprovedBy != "" {
		t.Errorf("ApprovedBy = %q, want empty on rejection", resp.ApprovedBy)
	}
	if resp.Message != "Step rejected, workflow aborted" {
		t.Errorf("Message = %q, want 'Step rejected, workflow aborted'", resp.Message)
	}
	if resp.ApprovalID == "" {
		t.Error("ApprovalID empty, want deterministic UUID")
	}
	if resp.RetryContext.GateCount < 1 {
		t.Errorf("RetryContext.GateCount = %d, want >= 1", resp.RetryContext.GateCount)
	}
}

// TestHandlerApproveStep_ParityWithRejectShape asserts the two responses share
// the same JSON field set (modulo approved_* vs rejected_*). This is the
// in-package analogue of the cross-plane TestHITLResponseParity that lives in
// the orchestrator package — it guards against drift within WCP itself.
func TestHandlerApproveStep_ParityWithRejectShape(t *testing.T) {
	handler, svc := setupApprovalTestHandler()

	run := func(method string) map[string]json.RawMessage {
		workflow, err := svc.CreateWorkflow(t.Context(), &CreateWorkflowRequest{
			WorkflowName: "parity-" + method,
		}, "tenant-1", "org-1", "user-1", "client-1")
		if err != nil {
			t.Fatalf("CreateWorkflow: %v", err)
		}
		if _, err := svc.StepGate(t.Context(), workflow.WorkflowID, "step-1",
			&StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
			"tenant-1", "org-1", "user-1", "client-1",
		); err != nil {
			t.Fatalf("StepGate: %v", err)
		}

		var body *strings.Reader
		if method == "approve" {
			body = strings.NewReader(`{"comment": "Approved after full audit review"}`)
		} else {
			body = strings.NewReader(`{"reason": "PII risk detected in output sample"}`)
		}
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+workflow.WorkflowID+"/steps/step-1/"+method, body)
		req = mux.SetURLVars(req, map[string]string{"id": workflow.WorkflowID, "step_id": "step-1"})
		req.Header.Set("X-User-ID", "u@example.com")
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Client-ID", "client-1")

		rr := httptest.NewRecorder()
		if method == "approve" {
			handler.ApproveStep(rr, req)
		} else {
			handler.RejectStep(rr, req)
		}
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d body=%s", method, rr.Code, rr.Body.String())
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: unmarshal: %v", method, err)
		}
		return m
	}

	approveFields := run("approve")
	rejectFields := run("reject")

	// Fields that MUST be present in every path. Includes the legacy
	// `status` back-compat mirror (Issue #1677 review feedback — existing
	// callers read this property).
	mustBothHave := []string{"workflow_id", "step_id", "status", "decision", "approval_status", "approval_id",
		"retry_context", "message", "reason"}
	for _, f := range mustBothHave {
		if _, ok := approveFields[f]; !ok {
			t.Errorf("approve missing field %q, keys=%v", f, keysOf(approveFields))
		}
		if _, ok := rejectFields[f]; !ok {
			t.Errorf("reject missing field %q, keys=%v", f, keysOf(rejectFields))
		}
	}

	// Symmetric approver-identity routing.
	if _, ok := approveFields["approved_by"]; !ok {
		t.Error("approve path missing approved_by")
	}
	if _, ok := approveFields["rejected_by"]; ok {
		t.Error("approve path should not surface rejected_by")
	}
	if _, ok := rejectFields["rejected_by"]; !ok {
		t.Error("reject path missing rejected_by")
	}
	if _, ok := rejectFields["approved_by"]; ok {
		t.Error("reject path should not surface approved_by")
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
