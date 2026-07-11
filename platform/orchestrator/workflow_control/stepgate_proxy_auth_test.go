// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// #2896 WS1b: the step-gate's per-user identity keys the ADR-044 override
// apply (a deny→allow flip). When a proxy-auth check is installed, a request
// that did not arrive through the trusted Agent gateway must be rejected
// before any evaluation — a direct caller cannot forge the override identity.
func TestStepGate_ProxyAuthRequired(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	// Simulate the orchestrator's wiring: block unless the request carries a
	// (stand-in) valid proxy token, mirroring verifyAgentProxyAuth.
	handler.SetProxyAuthCheck(func(r *http.Request) (bool, string) {
		if r.Header.Get("X-Axonflow-Proxy-Auth") != "valid-token" {
			return false, "Unauthorized: request must be routed through AxonFlow Agent"
		}
		return true, ""
	})

	wf, _ := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{
		WorkflowName: "wf",
	}, "tenant-1", "org-1", "user-1", "client-1")

	mk := func(proxyToken string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(StepGateRequest{StepName: "s", StepType: StepTypeLLMCall})
		req := httptest.NewRequest(http.MethodPost,
			"/api/v1/workflows/"+wf.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
		req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "step-1"})
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		// A direct attacker forges the override identity here:
		req.Header.Set("X-User-Email", "victim@corp.example")
		if proxyToken != "" {
			req.Header.Set("X-Axonflow-Proxy-Auth", proxyToken)
		}
		rr := httptest.NewRecorder()
		handler.StepGate(rr, req)
		return rr
	}

	t.Run("direct access (no proxy token) → 403 before evaluation", func(t *testing.T) {
		rr := mk("")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("direct step-gate access: status = %d, want 403; body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("forged proxy token → 403", func(t *testing.T) {
		rr := mk("forged")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("forged proxy token: status = %d, want 403", rr.Code)
		}
	})

	t.Run("valid proxy token → proceeds (200)", func(t *testing.T) {
		rr := mk("valid-token")
		if rr.Code != http.StatusOK {
			t.Fatalf("valid proxy token: status = %d, want 200; body=%s", rr.Code, rr.Body.String())
		}
	})
}

// A handler with no proxy-auth check installed (embedded / test use) must not
// change behavior — the gate is opt-in via SetProxyAuthCheck.
func TestStepGate_NoProxyAuthCheck_Unenforced(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	wf, _ := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "wf"},
		"tenant-1", "org-1", "user-1", "client-1")
	body, _ := json.Marshal(StepGateRequest{StepName: "s", StepType: StepTypeLLMCall})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/workflows/"+wf.WorkflowID+"/steps/step-1/gate", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"id": wf.WorkflowID, "step_id": "step-1"})
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	handler.StepGate(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("no proxy-auth check installed: status = %d, want 200 (unenforced)", rr.Code)
	}
}

// #2896 WS1c: resuming a checkpoint re-evaluates its step and applies any
// ADR-044 override keyed on the checkpoint's STORED actor identity (a
// deny→allow flip). Both checkpoint-resume handlers must reject a request
// that did not arrive through the trusted Agent gateway BEFORE reaching the
// service (where the re-evaluation + override apply happen). Mutation:
// removing the guard lets the request proceed to the service call.
func TestCheckpointResume_ProxyAuthRequired(t *testing.T) {
	handler, svc, _ := setupTestHandler()
	handler.SetProxyAuthCheck(func(r *http.Request) (bool, string) {
		if r.Header.Get("X-Axonflow-Proxy-Auth") != "valid-token" {
			return false, "Unauthorized: request must be routed through AxonFlow Agent"
		}
		return true, ""
	})
	wf, _ := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{WorkflowName: "wf"},
		"tenant-1", "org-1", "user-1", "client-1")

	// Each resume handler, with and without a valid proxy token. A blocked
	// request 403s at the gate; an authorized one gets PAST the gate (it then
	// 404/409s at the service because there's no resumable checkpoint — proof
	// the gate did not short-circuit, not a security assertion).
	cases := []struct {
		name string
		call func(w http.ResponseWriter, r *http.Request)
		path string
		vars map[string]string
	}{
		{
			name: "ResumeFromLastCheckpoint",
			call: handler.ResumeFromLastCheckpoint,
			path: "/api/v1/workflows/" + wf.WorkflowID + "/checkpoints/resume",
			vars: map[string]string{"id": wf.WorkflowID},
		},
		{
			name: "ResumeFromCheckpoint",
			call: handler.ResumeFromCheckpoint,
			path: "/api/v1/workflows/" + wf.WorkflowID + "/checkpoints/1/resume",
			vars: map[string]string{"id": wf.WorkflowID, "checkpoint_id": "1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name+" direct access (no token) → 403", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req = mux.SetURLVars(req, tc.vars)
			req.Header.Set("X-Tenant-ID", "tenant-1")
			req.Header.Set("X-User-Id", "victim@corp.example") // forged actor identity
			rr := httptest.NewRecorder()
			tc.call(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s direct access: status = %d, want 403; body=%s", tc.name, rr.Code, rr.Body.String())
			}
		})
		t.Run(tc.name+" forged token → 403", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req = mux.SetURLVars(req, tc.vars)
			req.Header.Set("X-Axonflow-Proxy-Auth", "forged")
			rr := httptest.NewRecorder()
			tc.call(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("%s forged token: status = %d, want 403", tc.name, rr.Code)
			}
		})
		t.Run(tc.name+" valid token → past the gate (not 403)", func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req = mux.SetURLVars(req, tc.vars)
			req.Header.Set("X-Axonflow-Proxy-Auth", "valid-token")
			req.Header.Set("X-Tenant-ID", "tenant-1")
			rr := httptest.NewRecorder()
			tc.call(rr, req)
			if rr.Code == http.StatusForbidden {
				t.Fatalf("%s valid token must pass the proxy-auth gate, got 403: %s", tc.name, rr.Body.String())
			}
		})
	}
}
