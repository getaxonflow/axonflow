// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// HTTP-handler-level tests for Issue #1673 Phase 1 + Phase 2.
// Covers the pieces service-level tests can't reach:
//   - ?include_prior_output=true query param parsing
//   - max-length validation for idempotency_key (400)
//   - writeIdempotencyKeyMismatch envelope on 409
//   - typed error class surfacing expected/received keys

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestHandler_StepGate_IncludePriorOutputParam verifies the ?include_prior_output=true
// query param reaches the service and populates RetryContext.PriorOutput.
func TestHandler_StepGate_IncludePriorOutputParam(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "tc"},
		"tenant-1", "org-1", "user-1", "client-1")

	// Prime: gate + complete so there's a prior output.
	gateReq := &StepGateRequest{StepType: StepTypeToolCall, StepName: "s"}
	if _, err := svc.StepGate(ctx, wf.WorkflowID, "s1", gateReq, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("prime gate: %v", err)
	}
	out := map[string]interface{}{"transfer_id": "TXN-xyz"}
	if err := svc.MarkStepCompleted(ctx, wf.WorkflowID, "s1",
		&StepCompleteRequest{Output: out}, "tenant-1", "org-1"); err != nil {
		t.Fatalf("prime complete: %v", err)
	}

	t.Run("without include_prior_output → prior_output null", func(t *testing.T) {
		body, _ := json.Marshal(StepGateRequest{StepType: StepTypeToolCall})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/gate",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp StepGateResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.RetryContext.PriorOutput != nil {
			t.Errorf("PriorOutput: want nil without query param, got %v", resp.RetryContext.PriorOutput)
		}
		if !resp.RetryContext.PriorOutputAvailable {
			t.Error("PriorOutputAvailable: want true (prior completion exists)")
		}
	})

	t.Run("with include_prior_output=true → prior_output populated", func(t *testing.T) {
		body, _ := json.Marshal(StepGateRequest{StepType: StepTypeToolCall})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/gate?include_prior_output=true",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		var resp StepGateResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.RetryContext.PriorOutput == nil {
			t.Fatal("PriorOutput: want populated with include_prior_output=true")
		}
		if resp.RetryContext.PriorOutput["transfer_id"] != "TXN-xyz" {
			t.Errorf("PriorOutput[transfer_id]: want TXN-xyz, got %v", resp.RetryContext.PriorOutput["transfer_id"])
		}
	})
}

// TestHandler_IdempotencyKeyMismatch_409Envelope exercises the 409 response
// shape for both /gate and /complete endpoints — must match
// technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md §5.
func TestHandler_IdempotencyKeyMismatch_409Envelope(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()

	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "tc"}, "tenant-1", "org-1", "user-1", "client-1")
	if _, err := svc.StepGate(ctx, wf.WorkflowID, "s1", &StepGateRequest{
		StepType: StepTypeToolCall, IdempotencyKey: "K-initial",
	}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
		t.Fatalf("prime gate: %v", err)
	}

	t.Run("gate mismatch", func(t *testing.T) {
		body, _ := json.Marshal(StepGateRequest{StepType: StepTypeToolCall, IdempotencyKey: "K-different"})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/gate",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		assertMismatch409(t, rr, wf.WorkflowID, "s1", "K-initial", "K-different")
	})

	t.Run("complete mismatch", func(t *testing.T) {
		body, _ := json.Marshal(StepCompleteRequest{IdempotencyKey: "K-different"})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/complete",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.ContentLength = int64(len(body))
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
		rr := httptest.NewRecorder()
		handler.MarkStepCompleted(rr, req)
		assertMismatch409(t, rr, wf.WorkflowID, "s1", "K-initial", "K-different")
	})
}

func assertMismatch409(t *testing.T, rr *httptest.ResponseRecorder, wfID, stepID, expected, received string) {
	t.Helper()
	if rr.Code != http.StatusConflict {
		t.Fatalf("status=%d want=409 body=%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var env APIErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Error.Code != ErrorCodeIdempotencyKeyMismatch {
		t.Errorf("Error.Code: want %s, got %s", ErrorCodeIdempotencyKeyMismatch, env.Error.Code)
	}
	if env.Error.Details.WorkflowID != wfID {
		t.Errorf("WorkflowID: want %s, got %s", wfID, env.Error.Details.WorkflowID)
	}
	if env.Error.Details.StepID != stepID {
		t.Errorf("StepID: want %s, got %s", stepID, env.Error.Details.StepID)
	}
	if env.Error.Details.ExpectedIdempotencyKey != expected {
		t.Errorf("ExpectedKey: want %q, got %q", expected, env.Error.Details.ExpectedIdempotencyKey)
	}
	if env.Error.Details.ReceivedIdempotencyKey != received {
		t.Errorf("ReceivedKey: want %q, got %q", received, env.Error.Details.ReceivedIdempotencyKey)
	}
}

// TestHandler_IdempotencyKey_MaxLength covers the 400 response for oversized keys.
func TestHandler_IdempotencyKey_MaxLength(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	ctx := context.Background()
	wf, _ := svc.CreateWorkflow(ctx, &CreateWorkflowRequest{WorkflowName: "tc"}, "tenant-1", "org-1", "user-1", "client-1")

	tooLong := strings.Repeat("x", 256) // limit is 255

	t.Run("gate rejects oversized key", func(t *testing.T) {
		body, _ := json.Marshal(StepGateRequest{StepType: StepTypeToolCall, IdempotencyKey: tooLong})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s1/gate",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s1"})
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=400 body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("complete rejects oversized key", func(t *testing.T) {
		// Prime a step to complete
		if _, err := svc.StepGate(ctx, wf.WorkflowID, "s2",
			&StepGateRequest{StepType: StepTypeToolCall}, "tenant-1", "org-1", "user-1", "client-1"); err != nil {
			t.Fatalf("prime: %v", err)
		}
		body, _ := json.Marshal(StepCompleteRequest{IdempotencyKey: tooLong})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/s2/complete",
			bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.ContentLength = int64(len(body))
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "s2"})
		rr := httptest.NewRecorder()
		handler.MarkStepCompleted(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status=%d want=400 body=%s", rr.Code, rr.Body.String())
		}
	})
}
