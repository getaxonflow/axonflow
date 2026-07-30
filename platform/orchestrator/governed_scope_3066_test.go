// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/rs/cors"

	"axonflow/platform/shared/tenantscope"
)

// #3066 C3-5 and C3-6 — the governed request plane must take its tenancy from
// the authenticated identity and nothing else.
//
// Pre-fix, /api/v1/process, /api/v1/workflows/execute, /api/v1/plan and
// /api/v1/plan/execute all overlaid the gateway-stamped headers onto the
// decoded body with `if header != ""` and NO else branch. A caller that
// reached the orchestrator without them kept whatever tenancy the body named:
//
//   - C3-5: that tenancy keys the dynamic-policy set EvaluateDynamicPolicies
//     loads and the applied_policies_detail[] array echoed back on a block, so
//     varying the query while naming a victim tenant bisected the victim's
//     policy conditions — and each attempt wrote a policy_metrics row under
//     the victim's org.
//   - C3-6: that tenancy is what the workflow engine's replay recorder and the
//     plan store stamp onto rows, so the body chose the owner of the row — or,
//     when the body was silent too, produced the unstamped rows that #3065's
//     fail-open `a != "" && b != "" && a != b` predicates then exposed to
//     every tenant.
//
// The tests below drive the real handlers, and the request-plane ones drive
// them through buildOrchestratorHandler — the handler Run() actually serves —
// so the #3068 authentication gate is in the path exactly as in production.

const (
	gs3066AttackerOrg   = "gs3066-attacker-org"
	gs3066AttackerTenat = "gs3066-attacker-tenant"
	gs3066VictimOrg     = "gs3066-victim-org"
	gs3066VictimTenant  = "gs3066-victim-tenant"
)

// gs3066PolicyName is the marker each tenant's "policy set" is named after.
// Seeing another tenant's marker in a response IS the C3-5 disclosure.
func gs3066PolicyName(tenant string) string { return "policy-of-" + tenant }

// gs3066Engine is a policy engine whose answer DEPENDS ON THE TENANT it is
// asked about, which is what makes the disclosure assertions real rather than
// simulated: a response can only contain the victim's marker if the evaluation
// actually ran under the victim's tenancy.
type gs3066Engine struct {
	captured []OrchestratorRequest
}

func (m *gs3066Engine) EvaluateDynamicPolicies(_ context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	m.captured = append(m.captured, req)
	// Prefer the client tenancy — the surface C3-5's oracle ran on — and fall
	// back to the user's, mirroring how the real engine reads both.
	tenant := req.Client.TenantID
	if tenant == "" {
		tenant = req.User.TenantID
	}
	name := gs3066PolicyName(tenant)
	return &PolicyEvaluationResult{
		Allowed:         false, // block, so the handler returns without an LLM
		AppliedPolicies: []string{name},
		AppliedPoliciesDetail: []AppliedPolicyDetail{
			{PolicyID: name, PolicyName: name, Action: "block", RiskLevel: "high"},
		},
	}
}

func (m *gs3066Engine) ListActivePolicies() []DynamicPolicy { return []DynamicPolicy{} }
func (m *gs3066Engine) ListActivePoliciesForTenant(_ string) []DynamicPolicy {
	return []DynamicPolicy{}
}
func (m *gs3066Engine) IsHealthy() bool { return true }

// gs3066ServedHandler builds the handler Run() serves — the #3068 gate inside
// the CORS handler, wrapping a mux carrying the route under test.
func gs3066ServedHandler(t *testing.T, path string, h http.HandlerFunc) http.Handler {
	t.Helper()
	withAuthnValidator(t) // installs proxyTokenValidator, restores on cleanup

	r := mux.NewRouter()
	r.HandleFunc(path, h).Methods("POST")
	return buildOrchestratorHandler(cors.New(cors.Options{AllowedOrigins: []string{"*"}}), r)
}

// gs3066Post issues an authenticated (proxy-auth'd) POST with the given
// tenancy headers. Every request here carries the internal-service token: the
// property under test is TENANCY binding, not the #3068 gate, so a token-less
// probe would prove the wrong thing.
func gs3066Post(t *testing.T, h http.Handler, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Axonflow-Proxy-Auth", validAuthnToken())
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// ---------------------------------------------------------------------------
// The helpers, unit level
// ---------------------------------------------------------------------------

func TestGoverned3066_ResolveGovernedScope(t *testing.T) {
	cases := []struct {
		name       string
		headers    map[string]string
		wantStatus int
		wantOrg    string
		wantTenant string
	}{
		{
			name:       "no stamped tenancy at all",
			headers:    nil,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "org only — half stamped",
			headers:    map[string]string{"X-Org-ID": gs3066AttackerOrg},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "tenant only — half stamped",
			headers:    map[string]string{"X-Tenant-ID": gs3066AttackerTenat},
			wantStatus: http.StatusUnauthorized,
		},
		{
			// The reason presence, not emptiness, selects the branch: a hop
			// that stamped an empty tenancy must fail closed rather than look
			// like a caller that stamped nothing.
			name:       "present but empty",
			headers:    map[string]string{"X-Org-ID": "", "X-Tenant-ID": ""},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "whitespace only",
			headers:    map[string]string{"X-Org-ID": "   ", "X-Tenant-ID": "\t"},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "the unowned sentinel is not a tenancy",
			headers: map[string]string{
				"X-Org-ID":    tenantscope.UnownedOrgSentinel,
				"X-Tenant-ID": tenantscope.UnownedOrgSentinel,
			},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name: "fully stamped binds, trimmed",
			headers: map[string]string{
				"X-Org-ID":    " " + gs3066AttackerOrg + " ",
				"X-Tenant-ID": gs3066AttackerTenat,
			},
			wantStatus: 0,
			wantOrg:    gs3066AttackerOrg,
			wantTenant: gs3066AttackerTenat,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/process", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			scope, status, msg := resolveGovernedScope(req, "test")
			if status != tc.wantStatus {
				t.Fatalf("status = %d (%s), want %d", status, msg, tc.wantStatus)
			}
			if tc.wantStatus != 0 {
				if scope.OrgID != "" || scope.TenantID != "" {
					t.Errorf("a refused request must yield the zero scope, got %+v", scope)
				}
				return
			}
			if scope.OrgID != tc.wantOrg || scope.TenantID != tc.wantTenant {
				t.Errorf("scope = %+v, want org=%q tenant=%q", scope, tc.wantOrg, tc.wantTenant)
			}
		})
	}
}

func TestGoverned3066_AuthorizeBodyTenancy(t *testing.T) {
	scope := tenantscope.Scope{OrgID: gs3066AttackerOrg, TenantID: gs3066AttackerTenat}

	cases := []struct {
		name       string
		claim      bodyTenancyClaim
		wantStatus int
	}{
		{"absent claim asserts nothing", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, ""}, 0},
		{"whitespace claim asserts nothing", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, "  "}, 0},
		{"matching tenant", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, gs3066AttackerTenat}, 0},
		{"matching tenant, padded", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, " " + gs3066AttackerTenat + " "}, 0},
		{"matching org", bodyTenancyClaim{"client.org_id", tenancyDimOrg, gs3066AttackerOrg}, 0},
		{"foreign tenant", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, gs3066VictimTenant}, http.StatusForbidden},
		{"foreign org", bodyTenancyClaim{"client.org_id", tenancyDimOrg, gs3066VictimOrg}, http.StatusForbidden},
		// Org and tenant are independent keys. A value that is a perfectly good
		// TENANT must not authorize an ORG claim, or a deployment where the two
		// differ would accept a cross-dimension substitution.
		{"tenant value offered as an org claim", bodyTenancyClaim{"client.org_id", tenancyDimOrg, gs3066AttackerTenat}, http.StatusForbidden},
		{"org value offered as a tenant claim", bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, gs3066AttackerOrg}, http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := authorizeBodyTenancy(scope, "test", tc.claim)
			if status != tc.wantStatus {
				t.Fatalf("status = %d (%s), want %d", status, msg, tc.wantStatus)
			}
			if status == 0 {
				return
			}
			if !strings.Contains(msg, tc.claim.field) {
				t.Errorf("refusal should name the offending field %q, got %q", tc.claim.field, msg)
			}
			// The refusal must not disclose the authenticated tenancy, or it
			// becomes an enumeration oracle for a caller probing what it is.
			if strings.Contains(msg, gs3066AttackerOrg) || strings.Contains(msg, gs3066AttackerTenat) {
				t.Errorf("refusal discloses the authenticated tenancy: %q", msg)
			}
		})
	}

	t.Run("first failing claim wins and later claims cannot rescue it", func(t *testing.T) {
		status, _ := authorizeBodyTenancy(scope, "test",
			bodyTenancyClaim{"client.tenant_id", tenancyDimTenant, gs3066VictimTenant},
			bodyTenancyClaim{"user.tenant_id", tenancyDimTenant, gs3066AttackerTenat},
		)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 — one foreign claim must refuse the request", status)
		}
	})
}

// TestGoverned3066_RequireStampedRowKeys is what keeps the C3-6 write-side
// guard from being a branch nothing exercises.
func TestGoverned3066_RequireStampedRowKeys(t *testing.T) {
	cases := []struct {
		name       string
		org        string
		tenant     string
		wantStatus int
	}{
		{"both present", "o", "t", 0},
		{"empty org", "", "t", http.StatusUnauthorized},
		{"empty tenant", "o", "", http.StatusUnauthorized},
		{"both empty", "", "", http.StatusUnauthorized},
		{"whitespace org", "   ", "t", http.StatusUnauthorized},
		{"sentinel org", tenantscope.UnownedOrgSentinel, "t", http.StatusUnauthorized},
		{"sentinel tenant", "o", tenantscope.UnownedOrgSentinel, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if status, _ := requireStampedRowKeys("test", tc.org, tc.tenant); status != tc.wantStatus {
				t.Fatalf("status = %d, want %d", status, tc.wantStatus)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// C3-5 — POST /api/v1/process
// ---------------------------------------------------------------------------

func TestGoverned3066_ProcessBindsTenancyFromTheGatewayNotTheBody(t *testing.T) {
	oldEngine, oldAudit := dynamicPolicyEngine, auditLogger
	t.Cleanup(func() { dynamicPolicyEngine, auditLogger = oldEngine, oldAudit })
	auditLogger = NewAuditLogger("")

	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)

	stamped := map[string]string{
		"X-Org-ID":    gs3066AttackerOrg,
		"X-Tenant-ID": gs3066AttackerTenat,
	}

	// The exact request the C3-5 finding describes: a valid credential, no
	// gateway tenancy, and a body naming the victim.
	t.Run("no stamped tenancy: refused, victim never evaluated", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process", nil, map[string]any{
			"query":        "select 1",
			"request_type": "llm",
			"user":         map[string]any{"id": 1, "tenant_id": gs3066VictimTenant},
			"client":       map[string]any{"tenant_id": gs3066VictimTenant, "org_id": gs3066VictimOrg},
		})

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(engine.captured) != 0 {
			t.Errorf("policy evaluation ran for an unauthenticated request (%d call(s)) — "+
				"the refusal must precede the evaluator, the metrics row and the response",
				len(engine.captured))
		}
		if strings.Contains(rr.Body.String(), gs3066PolicyName(gs3066VictimTenant)) {
			t.Errorf("the victim's policy leaked into the response: %s", rr.Body.String())
		}
	})

	t.Run("half-stamped tenancy: refused", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process",
			map[string]string{"X-Tenant-ID": gs3066AttackerTenat}, // no X-Org-ID
			map[string]any{"query": "select 1", "request_type": "llm"})

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(engine.captured) != 0 {
			t.Errorf("policy evaluation ran on a half-stamped request")
		}
	})

	t.Run("body names a foreign tenant: 403, victim never evaluated", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process", stamped, map[string]any{
			"query":        "select 1",
			"request_type": "llm",
			"client":       map[string]any{"tenant_id": gs3066VictimTenant},
		})

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(engine.captured) != 0 {
			t.Errorf("policy evaluation ran for a refused cross-tenant request")
		}
		if strings.Contains(rr.Body.String(), gs3066PolicyName(gs3066VictimTenant)) {
			t.Errorf("the victim's policy leaked into the response: %s", rr.Body.String())
		}
	})

	t.Run("body names a foreign org: 403", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process", stamped, map[string]any{
			"query":        "select 1",
			"request_type": "llm",
			"client":       map[string]any{"org_id": gs3066VictimOrg},
		})

		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
		}
		if len(engine.captured) != 0 {
			t.Errorf("policy evaluation ran for a refused cross-tenant request")
		}
	})

	// The positive direction. Without this the whole file would be satisfied by
	// a handler that refuses everything.
	t.Run("stamped, body silent: evaluated under the STAMPED tenancy", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process", stamped, map[string]any{
			"query":        "select 1",
			"request_type": "llm",
			"user":         map[string]any{"id": 1},
		})

		if rr.Code != http.StatusForbidden {
			// 403 here is the POLICY block from the stub engine, not an
			// authorization refusal — distinguished by the body below.
			t.Fatalf("status = %d, want 403 from the blocking stub policy (body=%s)", rr.Code, rr.Body.String())
		}
		if len(engine.captured) != 1 {
			t.Fatalf("policy engine called %d time(s), want 1", len(engine.captured))
		}
		got := engine.captured[0]
		if got.Client.TenantID != gs3066AttackerTenat || got.User.TenantID != gs3066AttackerTenat {
			t.Errorf("evaluated tenancy = client %q / user %q, want %q on both",
				got.Client.TenantID, got.User.TenantID, gs3066AttackerTenat)
		}
		if got.Client.OrgID != gs3066AttackerOrg || got.User.OrgID != gs3066AttackerOrg {
			t.Errorf("evaluated org = client %q / user %q, want %q on both",
				got.Client.OrgID, got.User.OrgID, gs3066AttackerOrg)
		}
		if !strings.Contains(rr.Body.String(), gs3066PolicyName(gs3066AttackerTenat)) {
			t.Errorf("caller's OWN policy set was not evaluated — response=%s", rr.Body.String())
		}
	})

	// user.org_id is deliberately NOT authorized (it is JWT-derived on the
	// agent's governed forward and legitimately differs from the licensed org),
	// but it must still be OVERWRITTEN, so a divergent value cannot reach the
	// evaluator or a metrics row.
	t.Run("body user.org_id is bound, not authorized", func(t *testing.T) {
		engine := &gs3066Engine{}
		dynamicPolicyEngine = engine

		rr := gs3066Post(t, handler, "/api/v1/process", stamped, map[string]any{
			"query":        "select 1",
			"request_type": "llm",
			"user":         map[string]any{"id": 1, "org_id": gs3066VictimOrg},
		})

		if rr.Code == http.StatusUnauthorized {
			t.Fatalf("a divergent user.org_id must not be refused — the agent derives it from the JWT, not from a caller assertion (body=%s)", rr.Body.String())
		}
		if len(engine.captured) != 1 {
			t.Fatalf("policy engine called %d time(s), want 1", len(engine.captured))
		}
		if got := engine.captured[0].User.OrgID; got != gs3066AttackerOrg {
			t.Errorf("evaluated user.org_id = %q, want the authenticated %q — the body value must be overwritten",
				got, gs3066AttackerOrg)
		}
	})
}

// ---------------------------------------------------------------------------
// C3-6 — POST /api/v1/workflows/execute
// ---------------------------------------------------------------------------

func gs3066Workflow(extraUser map[string]any) map[string]any {
	user := map[string]any{"id": 1, "email": "gs3066@example.com"}
	for k, v := range extraUser {
		user[k] = v
	}
	return map[string]any{
		"workflow": map[string]any{
			"metadata": map[string]any{"name": "gs3066-workflow"},
			"spec": map[string]any{
				"steps": []map[string]any{
					{"name": "step1", "type": "function-call"},
				},
			},
		},
		"input": map[string]any{},
		"user":  user,
	}
}

func TestGoverned3066_ExecuteWorkflowBindsTenancyAndNeverPersistsAnUnstampedRow(t *testing.T) {
	oldEngine, oldHITL := workflowEngine, hitlEnabled
	t.Cleanup(func() { workflowEngine, hitlEnabled = oldEngine, oldHITL })
	workflowEngine = NewWorkflowEngine()
	hitlEnabled = false

	handler := gs3066ServedHandler(t, "/api/v1/workflows/execute", executeWorkflowHandler)

	stamped := map[string]string{
		"X-Org-ID":    gs3066AttackerOrg,
		"X-Tenant-ID": gs3066AttackerTenat,
	}

	// The C3-6 shape: no tenancy anywhere. Pre-fix this EXECUTED and recorded
	// an execution row with org_id="" — the unstamped row #3065 then exposed.
	t.Run("no stamped tenancy: refused, nothing executed", func(t *testing.T) {
		before := gs3066ExecutionCount(t)
		rr := gs3066Post(t, handler, "/api/v1/workflows/execute", nil, gs3066Workflow(nil))
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body=%s)", rr.Code, rr.Body.String())
		}
		if after := gs3066ExecutionCount(t); after != before {
			t.Errorf("an unauthenticated request created %d execution row(s)", after-before)
		}
	})

	t.Run("body names a foreign tenant: 403, nothing executed", func(t *testing.T) {
		before := gs3066ExecutionCount(t)
		rr := gs3066Post(t, handler, "/api/v1/workflows/execute", stamped,
			gs3066Workflow(map[string]any{"tenant_id": gs3066VictimTenant}))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%s)", rr.Code, rr.Body.String())
		}
		if after := gs3066ExecutionCount(t); after != before {
			t.Errorf("a refused cross-tenant request created %d execution row(s)", after-before)
		}
	})

	// The direct write assertion #3066 asks for: a row that IS created carries
	// a non-empty org_id and tenant_id, and they are the authenticated ones.
	t.Run("stamped: the row carries the authenticated tenancy, never an empty org_id", func(t *testing.T) {
		rr := gs3066Post(t, handler, "/api/v1/workflows/execute", stamped,
			gs3066Workflow(map[string]any{"tenant_id": gs3066AttackerTenat, "org_id": gs3066VictimOrg}))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}

		var exec WorkflowExecution
		if err := json.Unmarshal(rr.Body.Bytes(), &exec); err != nil {
			t.Fatalf("decode execution: %v (body=%s)", err, rr.Body.String())
		}
		if exec.UserContext.OrgID == "" || exec.UserContext.TenantID == "" {
			t.Fatalf("execution row persisted with an unstamped tenancy: org=%q tenant=%q",
				exec.UserContext.OrgID, exec.UserContext.TenantID)
		}
		if exec.UserContext.OrgID != gs3066AttackerOrg {
			t.Errorf("execution row org_id = %q, want the authenticated %q (the body claimed %q)",
				exec.UserContext.OrgID, gs3066AttackerOrg, gs3066VictimOrg)
		}
		if exec.UserContext.TenantID != gs3066AttackerTenat {
			t.Errorf("execution row tenant_id = %q, want the authenticated %q",
				exec.UserContext.TenantID, gs3066AttackerTenat)
		}
	})
}

func gs3066ExecutionCount(t *testing.T) int {
	t.Helper()
	execs, err := workflowEngine.ListRecentExecutions(1000)
	if err != nil {
		t.Fatalf("list executions: %v", err)
	}
	return len(execs)
}

// ---------------------------------------------------------------------------
// The assumption every branch above rests on
// ---------------------------------------------------------------------------

// TestGoverned3066_GovernedRoutesAreCoveredByTheInternalProxyAuthGate pins the
// #3068 gate over the four routes this change binds.
//
// resolveGovernedScope's 401 answers "which tenancy may this caller use". It
// says nothing about whether the caller should have reached the orchestrator
// at all — that is requireInternalProxyAuth's job. If one of these paths ever
// acquired an exemption, an anonymous caller would be back to naming a tenancy
// in a header, and header trust is the whole foundation of the fix.
func TestGoverned3066_GovernedRoutesAreCoveredByTheInternalProxyAuthGate(t *testing.T) {
	for _, spelling := range []string{
		"/api/v1/process", "/api/v1/process/",
		"/api/v1/workflows/execute", "/api/v1/workflows", "/api/v1/workflows/",
		"/api/v1/plan", "/api/v1/plan/", "/api/v1/plan/execute",
	} {
		if _, exempt := orchestratorAuthExemptPaths[spelling]; exempt {
			t.Errorf("%q is exempt from requireInternalProxyAuth — the governed request plane's "+
				"tenancy binding trusts headers that only an authenticated hop can stamp", spelling)
		}
	}

	// DELIBERATELY UNARMED: no X-Axonflow-Proxy-Auth. The property is that a
	// token-less caller is refused, so handing it a credential would invert it.
	handler := gs3066ServedHandler(t, "/api/v1/process", processRequestHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/process",
		strings.NewReader(`{"query":"x","client":{"tenant_id":"`+gs3066VictimTenant+`"}}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("token-less POST /api/v1/process: status = %d, want 403 from requireInternalProxyAuth (body=%s)",
			rr.Code, rr.Body.String())
	}
}
