// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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

	"axonflow/platform/shared/tenantscope"
)

// #3065 F1 — cross-tenant WORKFLOW STATE TRANSITIONS via header omission.
//
// Before this change, nine of the fourteen WCP routes had no proxy-auth gate
// and the sole tenancy check (workflowBelongsTo) returned TRUE when the
// caller's tenant and org were both empty. So a caller who knew a workflow id
// and simply sent no X-Tenant-ID / X-Org-ID could abort, complete, fail or
// resume another tenant's workflow, mark its steps completed, and approve or
// reject its pending human-approval steps — choosing the recorded approver
// identity while doing it.
//
// Every case below fails against the pre-fix code. The pre-fix behaviour is
// named per assertion so the inversion is auditable rather than asserted.

// seedScopedWorkflow creates a workflow owned by (tenant, org) with one pending
// approval step, and returns its id.
func seedScopedWorkflow(t *testing.T, svc *Service, tenant, org string) string {
	t.Helper()
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{
		WorkflowName: "victim-workflow",
	}, tenant, org, "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow(%s/%s): %v", tenant, org, err)
	}
	return wf.WorkflowID
}

// mutations enumerates every state transition the issue reports as reachable.
// Each returns the handler and the request it drives.
type wcpMutation struct {
	name     string
	method   string
	path     string
	body     string
	vars     map[string]string
	invoke   func(h *Handler, w http.ResponseWriter, r *http.Request)
	terminal bool // leaves the workflow in a terminal state on success
}

func wcpMutations(workflowID string) []wcpMutation {
	step := map[string]string{"id": workflowID, "step_id": "step-1"}
	only := map[string]string{"id": workflowID}
	return []wcpMutation{
		{"AbortWorkflow", http.MethodPost, "/abort", `{"reason":"attacker abort"}`, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.AbortWorkflow(w, r) }, true},
		{"CompleteWorkflow", http.MethodPost, "/complete", ``, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.CompleteWorkflow(w, r) }, true},
		{"FailWorkflow", http.MethodPost, "/fail", `{"reason":"attacker fail"}`, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.FailWorkflow(w, r) }, true},
		{"ResumeWorkflow", http.MethodPost, "/resume", ``, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ResumeWorkflow(w, r) }, false},
		{"MarkStepCompleted", http.MethodPost, "/steps/step-1/complete", ``, step,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.MarkStepCompleted(w, r) }, false},
		{"ApproveStep", http.MethodPost, "/steps/step-1/approve", `{"comment":"approved by attacker"}`, step,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.ApproveStep(w, r) }, false},
		{"RejectStep", http.MethodPost, "/steps/step-1/reject", `{"reason":"rejected by attacker"}`, step,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.RejectStep(w, r) }, false},
		{"GetWorkflow", http.MethodGet, "", ``, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetWorkflow(w, r) }, false},
		{"GetCheckpoints", http.MethodGet, "/checkpoints", ``, only,
			func(h *Handler, w http.ResponseWriter, r *http.Request) { h.GetCheckpoints(w, r) }, false},
	}
}

func driveWCP(t *testing.T, h *Handler, m wcpMutation, workflowID string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var body *bytes.Reader
	if m.body != "" {
		body = bytes.NewReader([]byte(m.body))
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(m.method, "/api/v1/workflows/"+workflowID+m.path, body)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req = mux.SetURLVars(req, m.vars)
	rr := httptest.NewRecorder()
	m.invoke(h, rr, req)
	return rr
}

// TestWCP_CallerOmitsTenancyHeaders_IsDenied is the headline case: omitting a
// header WAS the exploit.
func TestWCP_CallerOmitsTenancyHeaders_IsDenied(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	victim := seedScopedWorkflow(t, svc, "tenant-victim", "org-victim")

	for _, m := range wcpMutations(victim) {
		for _, hdrs := range []struct {
			name    string
			headers map[string]string
		}{
			{"no headers at all", map[string]string{}},
			{"org omitted", map[string]string{"X-Tenant-ID": "tenant-victim"}},
			{"tenant omitted", map[string]string{"X-Org-ID": "org-victim"}},
			{"whitespace-only headers", map[string]string{"X-Tenant-ID": "  ", "X-Org-ID": "\t"}},
		} {
			t.Run(m.name+"/"+hdrs.name, func(t *testing.T) {
				rr := driveWCP(t, handler, m, victim, hdrs.headers)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("pre-fix this returned 2xx and %s SUCCEEDED against another tenant's workflow; got %d: %s",
						m.name, rr.Code, rr.Body.String())
				}
			})
		}
	}

	// The victim's workflow is untouched — assert on its identity and state,
	// not on a count.
	after, err := svc.GetWorkflow(context.Background(), victim, "tenant-victim", "org-victim")
	if err != nil {
		t.Fatalf("victim workflow must still be readable by its owner: %v", err)
	}
	if after.WorkflowID != victim {
		t.Fatalf("unexpected workflow %q", after.WorkflowID)
	}
	if after.Status != WorkflowStatusInProgress {
		t.Fatalf("an unauthenticated caller changed the victim workflow's status to %s", after.Status)
	}
}

// TestWCP_CrossTenantCallerIsDenied covers the fully-authenticated attacker:
// real headers, someone else's workflow id.
func TestWCP_CrossTenantCallerIsDenied(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	victim := seedScopedWorkflow(t, svc, "tenant-victim", "org-victim")
	attacker := map[string]string{"X-Tenant-ID": "tenant-attacker", "X-Org-ID": "org-attacker"}

	for _, m := range wcpMutations(victim) {
		t.Run(m.name, func(t *testing.T) {
			rr := driveWCP(t, handler, m, victim, attacker)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("cross-tenant %s must be 404 (never 403 — no existence oracle), got %d: %s",
					m.name, rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), victim) {
				t.Errorf("the denial response echoes the victim's workflow id %q, confirming it exists", victim)
			}
		})
	}

	after, err := svc.GetWorkflow(context.Background(), victim, "tenant-victim", "org-victim")
	if err != nil {
		t.Fatalf("victim workflow must survive: %v", err)
	}
	if after.Status != WorkflowStatusInProgress {
		t.Fatalf("a cross-tenant caller changed the victim workflow's status to %s", after.Status)
	}
}

// TestWCP_SameTenantCallerSucceeds is the positive control. Without it the
// tests above pass trivially on a change that simply broke every route.
func TestWCP_SameTenantCallerSucceeds(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	owner := map[string]string{"X-Tenant-ID": "tenant-owner", "X-Org-ID": "org-owner"}

	t.Run("read by id", func(t *testing.T) {
		id := seedScopedWorkflow(t, svc, "tenant-owner", "org-owner")
		rr := driveWCP(t, handler, wcpMutations(id)[7], id, owner) // GetWorkflow
		if rr.Code != http.StatusOK {
			t.Fatalf("the owning tenant must still read its own workflow, got %d: %s", rr.Code, rr.Body.String())
		}
		var resp map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp["workflow_id"] != id {
			t.Errorf("workflow_id = %v, want %q", resp["workflow_id"], id)
		}
	})

	t.Run("abort", func(t *testing.T) {
		id := seedScopedWorkflow(t, svc, "tenant-owner", "org-owner")
		rr := driveWCP(t, handler, wcpMutations(id)[0], id, owner) // AbortWorkflow
		if rr.Code != http.StatusOK {
			t.Fatalf("the owning tenant must still abort its own workflow, got %d: %s", rr.Code, rr.Body.String())
		}
		after, err := svc.GetWorkflow(context.Background(), id, "tenant-owner", "org-owner")
		if err != nil {
			t.Fatalf("GetWorkflow: %v", err)
		}
		if after.Status != WorkflowStatusAborted {
			t.Errorf("status = %s, want aborted — the positive path must actually work", after.Status)
		}
	})

	t.Run("complete", func(t *testing.T) {
		id := seedScopedWorkflow(t, svc, "tenant-owner", "org-owner")
		rr := driveWCP(t, handler, wcpMutations(id)[1], id, owner) // CompleteWorkflow
		if rr.Code != http.StatusOK {
			t.Fatalf("the owning tenant must still complete its own workflow, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

// TestWCP_ProxyAuthGateCoversEveryByIDRoute pins the gate itself. The routes
// were not ungated by accident once — the three that DID carry the gate show
// the omission was a per-door census that missed nine doors.
func TestWCP_ProxyAuthGateCoversEveryByIDRoute(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	id := seedScopedWorkflow(t, svc, "tenant-owner", "org-owner")

	var gateCalls int
	handler.SetProxyAuthCheck(func(*http.Request) (bool, string) {
		gateCalls++
		return false, "Unauthorized: request must be routed through AxonFlow Agent"
	})

	owner := map[string]string{"X-Tenant-ID": "tenant-owner", "X-Org-ID": "org-owner"}
	for _, m := range wcpMutations(id) {
		t.Run(m.name, func(t *testing.T) {
			before := gateCalls
			rr := driveWCP(t, handler, m, id, owner)
			if gateCalls != before+1 {
				t.Fatalf("%s did not run the proxy-auth gate — a direct caller reaches it with self-asserted tenancy", m.name)
			}
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s must 403 when the gate refuses, got %d: %s", m.name, rr.Code, rr.Body.String())
			}
		})
	}

	t.Run("CreateWorkflow", func(t *testing.T) {
		before := gateCalls
		req := httptest.NewRequest(http.MethodPost, "/api/v1/workflows",
			bytes.NewReader([]byte(`{"workflow_name":"x"}`)))
		req.Header.Set("X-Tenant-ID", "tenant-owner")
		req.Header.Set("X-Org-ID", "org-owner")
		rr := httptest.NewRecorder()
		handler.CreateWorkflow(rr, req)
		if gateCalls != before+1 {
			t.Fatal("CreateWorkflow did not run the proxy-auth gate — a direct caller can seed rows under any org")
		}
		if rr.Code != http.StatusForbidden {
			t.Fatalf("CreateWorkflow must 403 when the gate refuses, got %d", rr.Code)
		}
	})
}

// TestWCP_UnownedWorkflowIsReachableByNobody covers the ROW side. A workflow
// with no tenancy key used to satisfy every caller's check; it now satisfies
// none. (The write path refuses to create such a row at all — see
// TestWCP_CreateWorkflowRefusesUnownedRow — so this can only be a legacy row,
// which migration core/156 stamps with the unowned sentinel.)
func TestWCP_UnownedWorkflowIsReachableByNobody(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)

	// Seed directly through the repository to bypass the service's write
	// guard — this is the shape a pre-upgrade row has.
	orphan := &Workflow{WorkflowID: "wf_orphan", WorkflowName: "legacy", Status: WorkflowStatusInProgress}
	if err := repo.Create(context.Background(), orphan); err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, caller := range []struct{ tenant, org string }{
		{"tenant-a", "org-a"},
		{"tenant-b", "org-b"},
		{"", ""},
	} {
		if _, err := svc.GetWorkflow(context.Background(), "wf_orphan", caller.tenant, caller.org); err == nil {
			t.Errorf("caller (%q,%q) reached an unowned workflow — an unowned row belongs to nobody, not to everybody",
				caller.tenant, caller.org)
		}
	}
}

// TestWCP_CreateWorkflowRefusesUnownedRow: make the empty state
// unrepresentable at the write path, so the class cannot be reintroduced by
// data.
func TestWCP_CreateWorkflowRefusesUnownedRow(t *testing.T) {
	repo := NewMockRepository()
	svc := NewService(repo, &MockApprovalPolicyEvaluator{}, nil)

	for _, tc := range []struct{ name, tenant, org string }{
		{"no tenancy at all", "", ""},
		{"org missing", "tenant-a", ""},
		{"tenant missing", "", "org-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "x"},
				tc.tenant, tc.org, "u", "c"); err == nil {
				t.Fatal("persisting a workflow with no tenancy key manufactures a row every tenant can reach")
			}
		})
	}

	// Positive control.
	if _, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "x"},
		"tenant-a", "org-a", "u", "c"); err != nil {
		t.Fatalf("a fully-scoped create must still succeed: %v", err)
	}
}

// TestWCP_ListIsNeverTenantWide: the by-id fail-open had a sibling one layer
// down — both the Postgres List and the mock omitted the tenancy predicate
// entirely when the value was empty.
func TestWCP_ListIsNeverTenantWide(t *testing.T) {
	_, svc, _ := setupTestHandler()
	a := seedScopedWorkflow(t, svc, "tenant-a", "org-a")
	b := seedScopedWorkflow(t, svc, "tenant-b", "org-b")

	if _, err := svc.ListWorkflows(context.Background(), ListWorkflowsOptions{Limit: 100}); err == nil {
		t.Error("an unscoped listing must be refused, not silently widened to every tenant")
	}

	resp, err := svc.ListWorkflows(context.Background(), ListWorkflowsOptions{
		TenantID: "tenant-a", OrgID: "org-a", Limit: 100,
	})
	if err != nil {
		t.Fatalf("scoped listing: %v", err)
	}
	// Assert on identifiers, never counts.
	seen := map[string]bool{}
	for _, wf := range resp.Workflows {
		seen[wf.WorkflowID] = true
	}
	if !seen[a] {
		t.Errorf("tenant-a's own workflow %q is missing from its listing", a)
	}
	if seen[b] {
		t.Errorf("tenant-b's workflow %q leaked into tenant-a's listing", b)
	}
}

// TestWCP_GuardEdgeCases pins the branches the route-level tests cannot reach.
func TestWCP_GuardEdgeCases(t *testing.T) {
	t.Run("nil workflow never belongs to anyone", func(t *testing.T) {
		if workflowBelongsTo(nil, "tenant-a", "org-a") {
			t.Fatal("a nil workflow must never authorize")
		}
	})

	t.Run("listing surfaces refuse the unowned sentinel as a tenant", func(t *testing.T) {
		if err := requireTenant(tenantscope.UnownedOrgSentinel); err == nil {
			t.Fatal("the unowned sentinel must never be accepted as a caller tenant")
		}
		if err := requireTenant("   "); err == nil {
			t.Fatal("a whitespace-only tenant must be refused")
		}
		if err := requireTenant("tenant-a"); err != nil {
			t.Fatalf("a real tenant must be accepted: %v", err)
		}
	})
}
