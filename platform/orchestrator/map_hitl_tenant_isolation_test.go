// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-tenant isolation of the in-memory HITL execution store (#3067 S-4).
//
// The MAP legacy approve/reject path SCANNED a process-global map matching on
// plan id ALONE and then flipped ApprovalStatus to approved and Status to
// running. Any tenant could release another tenant's paused, human-gated
// workflow — the in-memory twin of the #3049 R3 blocker, invisible to that
// census because this store issues no SQL. A foreign plan reliably reached
// this path because path 1 (GetWorkflowByPlanID) returns not-found under the
// caller's own tenancy.
//
// Vacuity: against the pre-fix code the scan ignored the caller entirely, so
// the attacker request returned 200 and the victim execution came back
// approved+running. Both assertions below would fail.

package orchestrator

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

const (
	hitlVictimOrg   = "org-victim"
	hitlAttackerOrg = "org-attacker"
)

// pausedVictimExecution installs one paused execution owned by hitlVictimOrg
// and returns its approval id plus a cleanup func.
func pausedVictimExecution(t *testing.T, planID string) (*HITLWorkflowExecution, func()) {
	t.Helper()

	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	_ = os.Setenv("DEPLOYMENT_MODE", "enterprise")

	// #3135: the handlers now run verifyAgentProxyAuth. Every request in this
	// suite carries a VALID proxy token on purpose — the negative tests here
	// assert TENANT ISOLATION, not proxy auth, and a cross-tenant attacker in a
	// real deployment is a legitimate tenant whose traffic does arrive over an
	// authenticated agent hop. Letting them 403 at the proxy gate instead would
	// leave the org-scope binding (#3067 S-4) unexercised while the tests still
	// went green.
	installProxyTokenValidator(t, proxyGuardTestSecret)

	origEnabled := hitlEnabled
	origEngine := hitlWorkflowEngine
	origWCP := workflowControlService
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}
	workflowControlService = nil // force the legacy in-memory path

	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:           "exec-" + planID,
			WorkflowName: "plan-" + planID,
			Status:       StatusPaused,
			Input:        map[string]interface{}{"plan_id": planID},
			UserContext:  UserContext{OrgID: hitlVictimOrg, TenantID: hitlVictimOrg},
		},
		ApprovalID:     uuid.New(),
		ApprovalStatus: "pending",
	}
	saveHITLExecution(exec)

	cleanup := func() {
		executionStoreMutex.Lock()
		delete(executionStore, hitlStoreKey(hitlVictimOrg, exec.ID))
		executionStoreMutex.Unlock()

		hitlEnabled = origEnabled
		hitlWorkflowEngine = origEngine
		workflowControlService = origWCP
		if origDeployment != "" {
			_ = os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			_ = os.Unsetenv("DEPLOYMENT_MODE")
		}
	}
	return exec, cleanup
}

func approveRequest(planID, orgID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/"+planID+"/steps/step-1/approve",
		bytes.NewBufferString(`{"approved_by":"attacker@example.com"}`))
	req = mux.SetURLVars(req, map[string]string{"id": planID, "step_id": "step-1"})
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	if orgID != "" {
		req.Header.Set("X-Org-ID", orgID)
	}
	return req
}

func rejectRequest(planID, orgID string) *http.Request {
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/plans/"+planID+"/steps/step-1/reject",
		bytes.NewBufferString(`{"rejected_by":"attacker@example.com","reason":"denied"}`))
	req = mux.SetURLVars(req, map[string]string{"id": planID, "step_id": "step-1"})
	req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
	if orgID != "" {
		req.Header.Set("X-Org-ID", orgID)
	}
	return req
}

func TestMAPHITL_AnotherTenantCannotApproveAPausedExecution(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-1")
	defer cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, approveRequest("victim-plan-1", hitlAttackerOrg))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant approve must 404, got %d: %s", rr.Code, rr.Body.String())
	}
	// The load-bearing assertion: the governance gate is still closed.
	if exec.ApprovalStatus != "pending" {
		t.Fatalf("victim execution approval was forged: %q", exec.ApprovalStatus)
	}
	if exec.Status != StatusPaused {
		t.Fatalf("victim execution was released to %q by another tenant", exec.Status)
	}
}

func TestMAPHITL_OwnerCanStillApprove(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-2")
	defer cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, approveRequest("victim-plan-2", hitlVictimOrg))

	if rr.Code != http.StatusOK {
		t.Fatalf("positive control: the owning org must be able to approve, got %d: %s", rr.Code, rr.Body.String())
	}
	if exec.ApprovalStatus != StatusApproved {
		t.Fatalf("positive control: expected approved, got %q", exec.ApprovalStatus)
	}
	if exec.Status != "running" {
		t.Fatalf("positive control: expected running, got %q", exec.Status)
	}
}

func TestMAPHITL_AnotherTenantCannotRejectAPausedExecution(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-3")
	defer cleanup()

	rr := httptest.NewRecorder()
	mapStepRejectHandler(rr, rejectRequest("victim-plan-3", hitlAttackerOrg))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant reject must 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if exec.Status != StatusPaused {
		t.Fatalf("victim execution was aborted by another tenant (status %q)", exec.Status)
	}
}

func TestMAPHITL_UnidentifiedCallerCannotApprove(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-4")
	defer cleanup()

	rr := httptest.NewRecorder()
	mapStepApproveHandler(rr, approveRequest("victim-plan-4", "")) // no identity headers

	if rr.Code != http.StatusNotFound {
		t.Fatalf("an unidentified caller must 404, got %d: %s", rr.Code, rr.Body.String())
	}
	if exec.ApprovalStatus != "pending" {
		t.Fatalf("an unidentified caller forged an approval: %q", exec.ApprovalStatus)
	}
}

// TestMAPHITL_GetApprovalIsScoped covers the third defect in S-4: the adapter's
// approval lookup scanned the whole store.
func TestMAPHITL_GetApprovalIsScoped(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-5")
	defer cleanup()

	adapter := &MAPHITLApprovalAdapter{}

	if _, err := adapter.GetApproval(WithHITLScope(context.Background(), hitlAttackerOrg), exec.ApprovalID); err == nil {
		t.Fatal("another tenant resolved the victim's approval")
	}
	if _, err := adapter.GetApproval(context.Background(), exec.ApprovalID); err == nil {
		t.Fatal("a context with no asserted scope must resolve nothing")
	}

	got, err := adapter.GetApproval(WithHITLScope(context.Background(), hitlVictimOrg), exec.ApprovalID)
	if err != nil {
		t.Fatalf("positive control: the owning org must resolve its approval: %v", err)
	}
	if got.ApprovalID != exec.ApprovalID || got.Status != "pending" {
		t.Fatalf("positive control returned the wrong approval: %+v", got)
	}
}

// TestHITLStore_ScopedStatusLookup covers the bound status accessor.
func TestHITLStore_ScopedStatusLookup(t *testing.T) {
	exec, cleanup := pausedVictimExecution(t, "victim-plan-6")
	defer cleanup()

	engine := &HITLWorkflowEngine{}

	if _, err := engine.GetExecutionStatusForScope(context.Background(), hitlAttackerOrg, exec.ID); err != ErrExecutionNotFound {
		t.Fatalf("another tenant must get ErrExecutionNotFound, got %v", err)
	}
	if _, err := engine.GetExecutionStatusForScope(context.Background(), "", exec.ID); err != ErrExecutionNotFound {
		t.Fatalf("an unidentified caller must get ErrExecutionNotFound, got %v", err)
	}

	status, err := engine.GetExecutionStatusForScope(context.Background(), hitlVictimOrg, exec.ID)
	if err != nil {
		t.Fatalf("positive control: the owning org must read its own status: %v", err)
	}
	if status.ExecutionID != exec.ID || status.Status != StatusPaused {
		t.Fatalf("positive control returned the wrong status: %+v", status)
	}
}

// TestHITLStore_ScopeComesFromUserContextNotInput proves the owning scope is
// derived from the header-overlaid UserContext, never from the forgeable
// request body carried in execution.Input.
func TestHITLStore_ScopeComesFromUserContextNotInput(t *testing.T) {
	exec := &HITLWorkflowExecution{
		WorkflowExecution: &WorkflowExecution{
			ID:          "exec-scope",
			Input:       map[string]interface{}{"tenant_id": hitlVictimOrg, "org_id": hitlVictimOrg},
			UserContext: UserContext{OrgID: hitlAttackerOrg, TenantID: hitlAttackerOrg},
		},
	}
	if got := executionScope(exec); got != hitlAttackerOrg {
		t.Fatalf("scope must come from UserContext, got %q", got)
	}

	// OrgID wins over TenantID; TenantID is the community-mode fallback.
	both := &HITLWorkflowExecution{WorkflowExecution: &WorkflowExecution{
		UserContext: UserContext{OrgID: "org-1", TenantID: "tenant-1"},
	}}
	if got := executionScope(both); got != "org-1" {
		t.Fatalf("OrgID must win, got %q", got)
	}
	tenantOnly := &HITLWorkflowExecution{WorkflowExecution: &WorkflowExecution{
		UserContext: UserContext{TenantID: "tenant-1"},
	}}
	if got := executionScope(tenantOnly); got != "tenant-1" {
		t.Fatalf("TenantID must be the fallback, got %q", got)
	}
	if got := executionScope(nil); got != "" {
		t.Fatalf("nil execution must yield no scope, got %q", got)
	}
}
