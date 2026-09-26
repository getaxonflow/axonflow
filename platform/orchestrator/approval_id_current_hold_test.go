// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/orchestrator/workflow_control"
)

// holdMirror is a mirror resolver whose CurrentHoldID answer is set by the
// test, and which records the scope every lookup was asked for.
type holdMirror struct {
	id    string
	found bool
	err   error

	mu      sync.Mutex
	lookups []string
}

func (m *holdMirror) ResolveStepMirror(context.Context, string, string, string, string, string, string, string) {
}

func (m *holdMirror) StepMirrorExpiry(context.Context, string, string, string, string) (time.Time, bool, bool, error) {
	return time.Time{}, false, false, nil
}

func (m *holdMirror) CurrentHoldID(_ context.Context, orgID, tenantID, workflowID, stepID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lookups = append(m.lookups, orgID+"/"+tenantID+"/"+workflowID+"/"+stepID)
	return m.id, m.found, m.err
}

// TestApproveAndRejectProjectTheCurrentHoldsApprovalID covers the four sites
// that project `approval_id` - WCP approve and reject, MAP approve and reject
// (#4249 row 5700138809). A step held again has one queue row per hold, and the
// decision resolves the CURRENT one, so the response must name that row, not
// the first hold's derived id:
//
//   - the lookup finds a row: its id, asked for under the workflow's org and
//     tenant;
//   - no row: the hold-1 id, as every response projected before;
//   - the lookup fails: no approval_id at all, rather than one that may name
//     the wrong hold.
func TestApproveAndRejectProjectTheCurrentHoldsApprovalID(t *testing.T) {
	const hold2 = "189eab2c-ad75-5b6e-b889-bd62adb01bf8"
	sites := []struct {
		plane, verb, body string
	}{
		{"wcp", "approve", `{"comment":"Approved after full audit"}`},
		{"wcp", "reject", `{"reason":"Reviewed and rejected for compliance"}`},
		{"map", "approve", `{"comment":"Approved after full audit"}`},
		{"map", "reject", `{"reason":"Reviewed and rejected for compliance"}`},
	}
	answers := []struct {
		name string
		m    *holdMirror
		want func(env *hitlParityTestEnv) string
	}{
		{"current hold found", &holdMirror{id: hold2, found: true},
			func(*hitlParityTestEnv) string { return hold2 }},
		{"no row", &holdMirror{},
			func(env *hitlParityTestEnv) string {
				return workflow_control.DeriveHITLApprovalID(env.workflowID, env.stepID)
			}},
		{"lookup fails", &holdMirror{err: errors.New("connection reset")},
			func(*hitlParityTestEnv) string { return "" }},
	}

	for _, site := range sites {
		for i, a := range answers {
			caseName := fmt.Sprintf("hold_%s_%s_%d", site.plane, site.verb, i)
			t.Run(site.plane+" "+site.verb+"/"+a.name, func(t *testing.T) {
				mirror := &holdMirror{id: a.m.id, found: a.m.found, err: a.m.err}
				env := setupHITLParityEnv(t, caseName)
				defer env.cleanup()
				env.wcpSvc.SetHITLMirrorResolver(mirror)

				body := callApprovalSite(t, env, site.plane, site.verb, site.body)
				raw, present := body["approval_id"]
				want := a.want(env)
				if want == "" {
					if present {
						t.Errorf("approval_id = %s, want it absent when the current hold cannot be read", raw)
					}
				} else {
					var got string
					_ = json.Unmarshal(raw, &got)
					if got != want {
						t.Errorf("approval_id = %q, want %q", got, want)
					}
				}

				mirror.mu.Lock()
				defer mirror.mu.Unlock()
				wantLookup := "org-1/tenant-1/" + env.workflowID + "/" + env.stepID
				if len(mirror.lookups) != 1 || mirror.lookups[0] != wantLookup {
					t.Errorf("CurrentHoldID lookups = %v, want exactly [%s]", mirror.lookups, wantLookup)
				}
			})
		}
	}
}

// callApprovalSite drives one approve/reject site and returns its JSON body.
func callApprovalSite(t *testing.T, env *hitlParityTestEnv, plane, verb, body string) map[string]json.RawMessage {
	t.Helper()
	rr := httptest.NewRecorder()
	switch plane {
	case "wcp":
		req := httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/v1/workflows/%s/steps/%s/%s", env.workflowID, env.stepID, verb),
			bytes.NewBufferString(body))
		req = mux.SetURLVars(req, map[string]string{"id": env.workflowID, "step_id": env.stepID})
		req.Header.Set("X-User-ID", "u@example.com")
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		handler := workflow_control.NewHandler(env.wcpSvc)
		if verb == "approve" {
			handler.ApproveStep(rr, req)
		} else {
			handler.RejectStep(rr, req)
		}
	case "map":
		req := httptest.NewRequest(http.MethodPost,
			fmt.Sprintf("/api/v1/plans/%s/steps/%s/%s", env.planID, env.stepID, verb),
			bytes.NewBufferString(body))
		req = mux.SetURLVars(req, map[string]string{"id": env.planID, "step_id": env.stepID})
		req.Header.Set("X-User-ID", "u@example.com")
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Axonflow-Proxy-Auth", mapHITLTestProxyToken())
		if verb == "approve" {
			mapStepApproveHandler(rr, req)
		} else {
			mapStepRejectHandler(rr, req)
		}
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d body=%s", plane, verb, rr.Code, rr.Body.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &m); err != nil {
		t.Fatalf("%s %s: unmarshal: %v body=%s", plane, verb, err, rr.Body.String())
	}
	return m
}
