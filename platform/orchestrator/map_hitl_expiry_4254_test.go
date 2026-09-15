// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// A TIMED-OUT APPROVAL IS A DENY ON THE MULTI-AGENT PLANE TOO (#4254). The
// production approval adapter carries the typed approval's expiry onto the
// paused execution, and the approve route refuses after it, leaving the
// execution paused. These tests drive MAPHITLApprovalAdapter, the adapter the
// orchestrator wires, and never a recording double.

// pausedUnderTheProductionAdapter pauses a one-step plan on a typed challenge
// expiring at expiresAt, through the production adapter, and saves it where the
// approve route finds it.
func pausedUnderTheProductionAdapter(t *testing.T, expiresAt time.Time) *HITLWorkflowExecution {
	t.Helper()
	withMAPEngine(t, typedHoldVerdict("dec-map-expiry", typedApproval(expiresAt)))
	hitl, processor := mapHITLEngine(&MAPHITLApprovalAdapter{})
	exec, err := hitl.ExecuteWithHITL(mapSubjectContext(), oneStepWorkflow(), map[string]interface{}{}, UserContext{OrgID: "org-map"})
	if err != nil || exec == nil || exec.Status != StatusPaused {
		t.Fatalf("PREMISE: execution = (%+v, %v), want paused on the typed challenge", exec, err)
	}
	if processor.ran != 0 {
		t.Fatalf("PREMISE: the held step ran %d times", processor.ran)
	}
	hitl.SaveExecution(exec)
	t.Cleanup(func() {
		executionStoreMutex.Lock()
		delete(executionStore, hitlStoreKey(executionScope(exec), exec.ID))
		executionStoreMutex.Unlock()
	})
	return exec
}

// approveThePlan drives the multi-agent approve route for planID over an
// authenticated hop, on the in-memory path.
func approveThePlan(t *testing.T, planID string) *httptest.ResponseRecorder {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	installProxyTokenValidator(t, proxyGuardTestSecret)
	prevEnabled, prevEngine, prevWCP := hitlEnabled, hitlWorkflowEngine, workflowControlService
	hitlEnabled, hitlWorkflowEngine, workflowControlService = true, &HITLWorkflowEngine{}, nil
	t.Cleanup(func() { hitlEnabled, hitlWorkflowEngine, workflowControlService = prevEnabled, prevEngine, prevWCP })

	req := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+planID+"/steps/step1/approve", bytes.NewBufferString(`{}`))
	req = mux.SetURLVars(req, map[string]string{"id": planID, "step_id": "step1"})
	req.Header.Set("X-Org-ID", "org-map")
	req.Header.Set("X-User-ID", "ops@example.com")
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, req)
	return rr
}

func TestTheProductionMAPAdapterCarriesTheApprovalExpiryOntoTheHold(t *testing.T) {
	expiresAt := time.Now().Add(time.Hour).Truncate(time.Second)
	exec := pausedUnderTheProductionAdapter(t, expiresAt)
	if !exec.approvalExpiresAt.Equal(expiresAt) {
		t.Errorf("the paused execution's approval expiry = %s, want %s", exec.approvalExpiresAt, expiresAt)
	}
}

func TestAMAPApprovalAfterItsExpiryIsRefusedAndTheExecutionStaysPaused(t *testing.T) {
	expiresAt := time.Now().Add(1500 * time.Millisecond)
	exec := pausedUnderTheProductionAdapter(t, expiresAt)
	time.Sleep(time.Until(expiresAt) + 50*time.Millisecond)

	rr := approveThePlan(t, exec.ID)

	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "approval_expired") {
		t.Fatalf("status = %d, body = %s; want 409 naming approval_expired", rr.Code, rr.Body.String())
	}
	executionStoreMutex.RLock()
	status, approval := exec.Status, exec.ApprovalStatus
	executionStoreMutex.RUnlock()
	if status != StatusPaused || approval == StatusApproved {
		t.Errorf("after the refused approval the execution is %q with approval %q, want it still paused", status, approval)
	}
}

// CONTROL: before the expiry the same route approves, so the refusal above is
// the expiry's.
func TestAMAPApprovalBeforeItsExpiryIsApproved(t *testing.T) {
	exec := pausedUnderTheProductionAdapter(t, time.Now().Add(time.Hour))

	rr := approveThePlan(t, exec.ID)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s; want 200", rr.Code, rr.Body.String())
	}
	executionStoreMutex.RLock()
	defer executionStoreMutex.RUnlock()
	if exec.ApprovalStatus != StatusApproved {
		t.Errorf("approval status = %q, want approved", exec.ApprovalStatus)
	}
}

// A typed approval that declares no expiry reaches the approve route with a zero
// expiry, and approving it releases the execution. The route builds its answer
// without reading the execution, so the release is asserted on the execution
// itself: a zero expiry counted as timed out would leave it paused behind a 200.
func TestAMAPApprovalThatDeclaresNoExpiryIsApprovedAndReleased(t *testing.T) {
	exec := pausedUnderTheProductionAdapter(t, time.Time{})
	if !exec.approvalExpiresAt.IsZero() {
		t.Fatalf("PREMISE: the paused execution's approval expiry = %s, want none declared", exec.approvalExpiresAt)
	}

	rr := approveThePlan(t, exec.ID)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s; want 200", rr.Code, rr.Body.String())
	}
	executionStoreMutex.RLock()
	status, approval := exec.Status, exec.ApprovalStatus
	executionStoreMutex.RUnlock()
	if approval != StatusApproved || status != "running" {
		t.Errorf("after approving a hold with no expiry the execution is %q with approval %q, want running and approved", status, approval)
	}
}
