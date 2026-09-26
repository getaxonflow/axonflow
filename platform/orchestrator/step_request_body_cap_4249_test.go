// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
)

// #4249 row 5666236540: every multi-agent route whose body carries a step's
// content is bounded as the step gate is, and refuses a body over the bound
// whole, before decoding it (workflow_control/request_body_cap.go).

type cappedStepRoute struct {
	name    string
	method  string
	path    string
	vars    map[string]string
	handler http.HandlerFunc
	scope   legacycompile.EnforcementScope
}

func cappedStepRoutes() []cappedStepRoute {
	return []cappedStepRoute{
		{"workflows/execute", http.MethodPost, "/api/v1/workflows/execute", nil, executeWorkflowHandler, mapSeamScope},
		{"plan", http.MethodPost, "/api/v1/plan", nil, planRequestHandler, mapSeamScope},
		{"plan/execute", http.MethodPost, "/api/v1/plan/execute", nil, executePlanHandler, orchestratorRequestSeamScope},
		{"plan/{id} PUT", http.MethodPut, "/api/v1/plan/plan_capped", map[string]string{"id": "plan_capped"}, updatePlanHandler, mapSeamScope},
		{"plan/{id}/resume", http.MethodPost, "/api/v1/plan/plan_capped/resume", map[string]string{"id": "plan_capped"}, resumePlanHandler, mapSeamScope},
	}
}

func bodyTooLargeCount(scope legacycompile.EnforcementScope) float64 {
	return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(scope.String(), anchoredenforcer.EngineAnchored, "deny", workflow_control.RequestTooLarge))
}

// withCappedRouteServices installs what every capped route checks before its
// body: a planning engine, a plan service, a recording workflow engine and the
// proxy-token validator.
func withCappedRouteServices(t *testing.T) *recordingStepProcessor {
	t.Helper()
	previousPlanning, previousPlans := planningEngine, planService
	t.Cleanup(func() { planningEngine, planService = previousPlanning, previousPlans })
	// The resume route serves Enterprise only.
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	planningEngine = &PlanningEngine{}
	planService = planning.NewService(planning.NewMockRepository())
	installProxyTokenValidator(t, proxyGuardTestSecret)
	return withRecordingWorkflowEngine(t)
}

// jsonBodyOfSize is a JSON object exactly size bytes long.
func jsonBodyOfSize(size int) string {
	const head, tail = `{"pad":"`, `"}`
	return head + strings.Repeat("p", size-len(head)-len(tail)) + tail
}

func serveCapped(t *testing.T, route cappedStepRoute, body string) *httptest.ResponseRecorder {
	t.Helper()
	// A chunked body: the bound is enforced on what is read, not only on a
	// declared length.
	req := httptest.NewRequest(route.method, route.path, io.MultiReader(strings.NewReader(body)))
	if route.vars != nil {
		req = mux.SetURLVars(req, route.vars)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org_1")
	req.Header.Set("X-Tenant-ID", "tenant_1")
	req.Header.Set("X-User-ID", "user_1")
	req.Header.Set("X-Axonflow-Proxy-Auth", validProxyToken(t))
	w := httptest.NewRecorder()
	route.handler(w, req)
	return w
}

func TestEveryMultiAgentStepRouteRefusesABodyOverTheBoundBeforeDecode(t *testing.T) {
	processor := withCappedRouteServices(t)
	over := jsonBodyOfSize(int(workflow_control.MaxStepRequestBody) + 1)
	for _, route := range cappedStepRoutes() {
		t.Run(route.name, func(t *testing.T) {
			before := bodyTooLargeCount(route.scope)
			w := serveCapped(t, route, over)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status %d one byte over the bound, want 413; body %.300s", w.Code, w.Body.String())
			}
			var body struct {
				Success *bool  `json:"success"`
				Error   string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body.Success == nil || *body.Success || !strings.HasPrefix(body.Error, workflow_control.RequestTooLarge+": ") {
				t.Errorf("413 body %.300s; want the flat {success: false, error: %q...} these routes answer in", w.Body.String(), workflow_control.RequestTooLarge)
			}
			if got := bodyTooLargeCount(route.scope) - before; got != 1 {
				t.Errorf("recorded %v refusal(s) under %s, want 1", got, route.scope)
			}
			if processor.ran != 0 {
				t.Errorf("%d step(s) ran for a refused body", processor.ran)
			}
		})
	}
}

func TestAMultiAgentStepRouteBodyAtTheBoundIsDecoded(t *testing.T) {
	withCappedRouteServices(t)
	at := jsonBodyOfSize(int(workflow_control.MaxStepRequestBody))
	for _, route := range cappedStepRoutes() {
		t.Run(route.name, func(t *testing.T) {
			before := bodyTooLargeCount(route.scope)
			w := serveCapped(t, route, at)
			if w.Code == http.StatusRequestEntityTooLarge {
				t.Fatalf("a body at the bound was refused 413")
			}
			if got := bodyTooLargeCount(route.scope) - before; got != 0 {
				t.Errorf("recorded %v refusal(s) for a body at the bound, want 0", got)
			}
			// A body cut anywhere is not valid JSON, and each of these routes
			// answers an undecodable body "Invalid request body". The resume
			// route ignores a decode error, so its answer cannot tell.
			if route.handler != nil && route.name != "plan/{id}/resume" && strings.Contains(w.Body.String(), "Invalid request body") {
				t.Errorf("the body at the bound did not decode whole: %.300s", w.Body.String())
			}
		})
	}
}
