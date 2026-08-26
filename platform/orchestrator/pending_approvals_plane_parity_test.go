// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Cross-plane contract test for the pending-approvals listings (Issue #1680).
//
// WCP exposes GET /api/v1/workflows/approvals/pending; MAP exposes GET
// /api/v1/plans/approvals/pending. Both list workflow_steps that are
// waiting on approval, scoped to the caller's tenant. The intentional
// asymmetry is `plan_id`: MAP populates it on every entry, WCP never does.
//
// This test guards against future drift the same way TestHITLResponseParity
// does for approve/reject — if someone adds an entry field to one plane but
// not the other, or flips the plan_id contract, the test fails loudly.

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"axonflow/platform/agent/license"
	"axonflow/platform/orchestrator/workflow_control"
)

// planeParityPendingTestEnv wires WCP service + MAP globals against the same
// in-memory repo. Seeds three pending-approval rows per tenant:
//   - wf-map-a (plan-a), wf-map-b (plan-b)  — MAP-backed, plan_id populated
//   - wf-wcp-c                              — native WCP, no plan_id
//
// Returns the tenantID used + a cleanup that restores globals.
type planeParityPendingTestEnv struct {
	wcpSvc   *workflow_control.Service
	wcpRepo  *workflow_control.MockRepository
	tenantID string
	cleanup  func()
}

func setupPlaneParityPendingEnv(t *testing.T, name string) *planeParityPendingTestEnv {
	t.Helper()

	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "enterprise")

	origWCP := workflowControlService
	origHitl := hitlEnabled
	origEngine := hitlWorkflowEngine

	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	workflowControlService = svc
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	tenantID := "tenant-" + name

	pending := workflow_control.ApprovalStatusPending
	seed := func(workflowID, workflowName, planID, stepID, tenant string) {
		var meta []byte
		if planID != "" {
			meta, _ = json.Marshal(map[string]interface{}{
				"plan_id":        planID,
				"execution_mode": "confirm",
			})
		}
		wf := &workflow_control.Workflow{
			WorkflowID:   workflowID,
			WorkflowName: workflowName,
			Source:       workflow_control.WorkflowSource("map"),
			Status:       workflow_control.WorkflowStatusInProgress,
			TenantID:     tenant,
			OrgID:        "org-1",
			UserID:       "user-1",
			ClientID:     "client-1",
			Metadata:     meta,
		}
		if err := repo.Create(context.Background(), wf); err != nil {
			t.Fatalf("seed workflow %s: %v", workflowID, err)
		}
		step := &workflow_control.WorkflowStep{
			WorkflowID:     workflowID,
			StepID:         stepID,
			StepIndex:      0,
			StepName:       "step-" + stepID,
			StepType:       workflow_control.StepTypeToolCall,
			Decision:       workflow_control.GateDecisionRequireApproval,
			ApprovalStatus: &pending,
		}
		if err := repo.AddStep(context.Background(), step); err != nil {
			t.Fatalf("seed step %s/%s: %v", workflowID, stepID, err)
		}
	}

	seed("wf-map-a-"+name, "map-confirm-plan-a-"+name, "plan-a-"+name, "step_0_analyze", tenantID)
	seed("wf-map-b-"+name, "map-confirm-plan-b-"+name, "plan-b-"+name, "step_0_prepare", tenantID)
	seed("wf-wcp-c-"+name, "wcp-native-"+name, "", "step_0", tenantID)

	return &planeParityPendingTestEnv{
		wcpSvc:   svc,
		wcpRepo:  repo,
		tenantID: tenantID,
		cleanup: func() {
			workflowControlService = origWCP
			hitlEnabled = origHitl
			hitlWorkflowEngine = origEngine
			if origDeployment != "" {
				os.Setenv("DEPLOYMENT_MODE", origDeployment)
			} else {
				os.Unsetenv("DEPLOYMENT_MODE")
			}
		},
	}
}

// TestPendingApprovalsPlaneParity asserts the MAP and WCP pending-approval
// listings share the same entry field set modulo the acknowledged plan_id
// asymmetry. Sibling of TestHITLResponseParity for approve/reject (#1677).
func TestPendingApprovalsPlaneParity(t *testing.T) {
	env := setupPlaneParityPendingEnv(t, "parity")
	defer env.cleanup()

	wcpBody, wcpCount := callWCPPendingHandler(t, env.tenantID, env.wcpSvc)
	mapBody, mapCount := callMAPPendingHandler(t, env.tenantID)

	// Both lists must contain entries
	if len(wcpBody) == 0 {
		t.Fatalf("WCP pending listing returned zero entries")
	}
	if len(mapBody) == 0 {
		t.Fatalf("MAP pending listing returned zero entries")
	}

	// Plane-specific expectations
	if mapCount != 2 {
		t.Errorf("MAP pending count: want 2, got %d", mapCount)
	}
	if wcpCount != 3 {
		t.Errorf("WCP pending count (all approvals, both planes): want 3, got %d", wcpCount)
	}

	// Collect field sets
	wcpKeys := unionFieldSet(wcpBody)
	mapKeys := unionFieldSet(mapBody)

	// plan_id is the one intentional asymmetry: omitempty on WCP, always populated on MAP
	allowedAsymmetry := map[string]bool{"plan_id": true}
	var drift []string
	for k := range wcpKeys {
		if !mapKeys[k] && !allowedAsymmetry[k] {
			drift = append(drift, "wcp-only:"+k)
		}
	}
	for k := range mapKeys {
		if !wcpKeys[k] && !allowedAsymmetry[k] {
			drift = append(drift, "map-only:"+k)
		}
	}
	if len(drift) > 0 {
		t.Errorf("field-set drift between WCP and MAP pending listings: %v\nWCP keys=%v\nMAP keys=%v",
			drift, sortedFieldKeys(wcpKeys), sortedFieldKeys(mapKeys))
	}

	// MAP entries MUST populate plan_id; WCP entries MUST NOT
	for i, entry := range mapBody {
		if _, ok := entry["plan_id"]; !ok {
			t.Errorf("MAP entry %d missing plan_id: %+v", i, entry)
		}
	}
	for i, entry := range wcpBody {
		if _, ok := entry["plan_id"]; ok {
			t.Errorf("WCP entry %d leaked plan_id — asymmetry violated: %+v", i, entry)
		}
	}
}

// TestMAPPendingApprovals_PlanIDFilter asserts ?plan_id= scopes the MAP
// listing to a single plan.
func TestMAPPendingApprovals_PlanIDFilter(t *testing.T) {
	env := setupPlaneParityPendingEnv(t, "filter")
	defer env.cleanup()

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/plans/approvals/pending?plan_id=plan-a-filter", nil)
	req.Header.Set("X-Tenant-ID", env.tenantID)
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	var resp struct {
		PendingApprovals []map[string]interface{} `json:"pending_approvals"`
		Count            int                      `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Count != 1 {
		t.Errorf("filter count: want 1, got %d", resp.Count)
	}
	if len(resp.PendingApprovals) != 1 {
		t.Fatalf("filter entries: want 1, got %d", len(resp.PendingApprovals))
	}
	if resp.PendingApprovals[0]["plan_id"] != "plan-a-filter" {
		t.Errorf("plan_id = %v, want plan-a-filter", resp.PendingApprovals[0]["plan_id"])
	}
}

// TestMAPPendingApprovals_TierGateMatrix covers the community / community+eval /
// enterprise paths. Community without eval must 403; community with eval
// license and enterprise must 200.
func TestMAPPendingApprovals_TierGateMatrix(t *testing.T) {
	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	origChecker := tierChecker
	origWCP := workflowControlService
	origHitl := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		tierChecker = origChecker
		workflowControlService = origWCP
		hitlEnabled = origHitl
		hitlWorkflowEngine = origEngine
		if origDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	repo := workflow_control.NewMockRepository()
	svc := workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	workflowControlService = svc
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	tests := []struct {
		name         string
		deployment   string
		licenseTier  license.Tier
		hitlEnabled  bool
		nilChecker   bool
		wantHTTPCode int
		wantBodyHint string
	}{
		{
			name:         "enterprise allowed",
			deployment:   "enterprise",
			licenseTier:  license.TierEnterprise,
			hitlEnabled:  true,
			wantHTTPCode: http.StatusOK,
		},
		{
			name: "community + evaluation license allowed",
			// #3096: was "" relying on unset==community. Named explicitly.
			deployment:   "community",
			licenseTier:  license.TierEvaluation,
			hitlEnabled:  true,
			wantHTTPCode: http.StatusOK,
		},
		{
			name:         "community without license blocked",
			deployment:   "community",
			licenseTier:  license.TierCommunity,
			hitlEnabled:  false,
			wantHTTPCode: http.StatusForbidden,
			wantBodyHint: "Professional, Enterprise or Enterprise Plus",
		},
		{
			name:         "community with nil tier checker blocked",
			deployment:   "community",
			nilChecker:   true,
			wantHTTPCode: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv (not os.Setenv) so the mode is restored after each case;
			// the old form leaked an unset DEPLOYMENT_MODE into whatever ran next.
			t.Setenv("DEPLOYMENT_MODE", tc.deployment)
			if tc.nilChecker {
				tierChecker = nil
			} else {
				tierChecker = &mockLicenseCheckerForSim{tier: tc.licenseTier, hitlEnabled: tc.hitlEnabled}
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
			req.Header.Set("X-Tenant-ID", "tenant-tier-test")
			rr := httptest.NewRecorder()
			mapPendingApprovalsHandler(rr, req)

			if rr.Code != tc.wantHTTPCode {
				t.Errorf("status = %d, want %d, body = %s", rr.Code, tc.wantHTTPCode, rr.Body.String())
			}
			if tc.wantBodyHint != "" && !strings.Contains(rr.Body.String(), tc.wantBodyHint) {
				t.Errorf("body %q missing expected hint %q", rr.Body.String(), tc.wantBodyHint)
			}
		})
	}
}

// TestMAPPendingApprovals_MissingTenant asserts the handler rejects requests
// without X-Tenant-ID. Enterprise mode so the tier gate doesn't short-circuit
// the check.
func TestMAPPendingApprovals_MissingTenant(t *testing.T) {
	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	origWCP := workflowControlService
	origHitl := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		workflowControlService = origWCP
		hitlEnabled = origHitl
		hitlWorkflowEngine = origEngine
		if origDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	repo := workflow_control.NewMockRepository()
	workflowControlService = workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing tenant: want 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMAPPendingApprovals_ServiceUnavailable asserts the handler returns 503
// when workflowControlService is unset.
func TestMAPPendingApprovals_ServiceUnavailable(t *testing.T) {
	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	origWCP := workflowControlService
	defer func() {
		workflowControlService = origWCP
		if origDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	workflowControlService = nil

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("service nil: want 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestMAPPendingApprovals_OptionsPreflight exercises the CORS preflight path.
func TestMAPPendingApprovals_OptionsPreflight(t *testing.T) {
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/plans/approvals/pending", nil)
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("OPTIONS: want 200, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Errorf("OPTIONS missing CORS Origin header")
	}
}

// TestMAPPendingApprovals_LimitQueryParam asserts the ?limit= cap works and
// invalid limits fall back to the default.
func TestMAPPendingApprovals_LimitQueryParam(t *testing.T) {
	env := setupPlaneParityPendingEnv(t, "limit")
	defer env.cleanup()

	tests := []struct {
		name     string
		query    string
		wantLen  int
		wantCode int
	}{
		{"limit=1 caps to 1", "?limit=1", 1, http.StatusOK},
		{"limit=5 returns all 2 MAP entries", "?limit=5", 2, http.StatusOK},
		{"limit=0 falls back to default and returns all", "?limit=0", 2, http.StatusOK},
		{"limit=garbage ignored", "?limit=not-a-number", 2, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending"+tc.query, nil)
			req.Header.Set("X-Tenant-ID", env.tenantID)
			rr := httptest.NewRecorder()
			mapPendingApprovalsHandler(rr, req)
			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, tc.wantCode, rr.Body.String())
			}
			entries, _ := decodePendingList(t, rr.Body.Bytes(), "MAP")
			if len(entries) != tc.wantLen {
				t.Errorf("entries = %d, want %d", len(entries), tc.wantLen)
			}
		})
	}
}

// TestMAPPendingApprovals_EmptyListSerialisedAsArray asserts the handler
// returns pending_approvals: [] rather than null when no entries match.
// Reviewer UIs rely on the array shape.
func TestMAPPendingApprovals_EmptyListSerialisedAsArray(t *testing.T) {
	origDeployment := os.Getenv("DEPLOYMENT_MODE")
	origWCP := workflowControlService
	origHitl := hitlEnabled
	origEngine := hitlWorkflowEngine
	defer func() {
		workflowControlService = origWCP
		hitlEnabled = origHitl
		hitlWorkflowEngine = origEngine
		if origDeployment != "" {
			os.Setenv("DEPLOYMENT_MODE", origDeployment)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	os.Setenv("DEPLOYMENT_MODE", "enterprise")
	repo := workflow_control.NewMockRepository()
	workflowControlService = workflow_control.NewService(repo, &wcpParityPolicyEvaluator{}, nil)
	hitlEnabled = true
	hitlWorkflowEngine = &HITLWorkflowEngine{}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
	req.Header.Set("X-Tenant-ID", "tenant-empty")
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"pending_approvals":[]`) {
		t.Errorf("empty result must serialise as [], not null; body=%s", body)
	}
}

// === helpers ===

// callWCPPendingHandler drives the WCP pending-list handler and returns the
// entries + count from the response.
func callWCPPendingHandler(t *testing.T, tenantID string, svc *workflow_control.Service) ([]map[string]interface{}, int) {
	t.Helper()
	handler := workflow_control.NewHandler(svc)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflows/approvals/pending", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	// #3065: the WCP listing binds on BOTH tenancy dimensions now — it was the
	// one listing route still reading a self-asserted header after the by-id
	// routes were converted.
	req.Header.Set("X-Org-ID", "org-"+tenantID)
	rr := httptest.NewRecorder()
	handler.GetPendingApprovals(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("WCP pending: status %d body=%s", rr.Code, rr.Body.String())
	}
	return decodePendingList(t, rr.Body.Bytes(), "WCP")
}

// callMAPPendingHandler drives the MAP pending-list handler and returns the
// entries + count from the response.
func callMAPPendingHandler(t *testing.T, tenantID string) ([]map[string]interface{}, int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plans/approvals/pending", nil)
	req.Header.Set("X-Tenant-ID", tenantID)
	rr := httptest.NewRecorder()
	mapPendingApprovalsHandler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("MAP pending: status %d body=%s", rr.Code, rr.Body.String())
	}
	return decodePendingList(t, rr.Body.Bytes(), "MAP")
}

func decodePendingList(t *testing.T, raw []byte, plane string) ([]map[string]interface{}, int) {
	t.Helper()
	var resp struct {
		PendingApprovals []map[string]interface{} `json:"pending_approvals"`
		Count            int                      `json:"count"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("%s unmarshal: %v", plane, err)
	}
	return resp.PendingApprovals, resp.Count
}

func unionFieldSet(entries []map[string]interface{}) map[string]bool {
	out := map[string]bool{}
	for _, e := range entries {
		for k := range e {
			out[k] = true
		}
	}
	return out
}

func sortedFieldKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
