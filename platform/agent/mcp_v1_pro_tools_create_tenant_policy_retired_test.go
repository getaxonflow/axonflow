// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
	"axonflow/platform/shared/retiredenv"
)

// AXONFLOW_CREATE_TENANT_POLICY IS RETIRED IN V11 (#4249 row 5667510887).
//
// The tool created a tenant dynamic policy, and in v11 a tenant dynamic policy
// decides nothing (PRD v11 §1.2). Until v11.1.0 it still wrote that row wherever
// the legacy table was writable (an owner-role deployment) and answered
// created:true, and refused only where the core/172 freeze reached it. These
// tests hold that it now refuses the same way on every posture, before any
// orchestrator call, and that the Free quota over the rows it no longer writes
// is gone.

// fakeOrchestrator answers every request with status and body, and records
// each request's method and path. Every path, not only the legacy create: the
// claim is that the tool makes NO orchestrator call.
type fakeOrchestrator struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeOrchestrator) serve(t *testing.T, status int, body interface{}) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	original := orchestratorURL
	orchestratorURL = srv.URL
	t.Cleanup(func() { orchestratorURL = original })
}

func (f *fakeOrchestrator) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// orchestratorPostures are the two answers the tool used to get for its create.
// The owner-role one is the posture where the old tool wrote an undecided row
// and said created:true; the app-role one is the core/172 freeze.
var orchestratorPostures = []struct {
	name   string
	status int
	body   map[string]interface{}
}{
	{"owner-role: the legacy create would succeed", http.StatusCreated, map[string]interface{}{
		"policy": map[string]interface{}{"id": "0d2a83cf-9b2e-4d3a-9f1a-7b9c2e1a4d56", "policy_id": "tenant-p", "enabled": true},
	}},
	{"app-role: the legacy create is frozen", http.StatusConflict, map[string]interface{}{
		"error": map[string]interface{}{"code": legacyfreeze.ErrCode, "message": legacyfreeze.Message},
	}},
}

// retiredToolArgs are what callers send: a well-formed create, every action the
// tool advertised, an invalid action, and nothing at all. A retired tool
// refuses whatever it is given, as mcpToolCreateOverride does.
func retiredToolArgs() map[string]map[string]interface{} {
	full := func(action string) map[string]interface{} {
		return map[string]interface{}{
			"name": "Block ssh-key writes", "connector_type": "claude_code.Bash",
			"pattern": ".*~/\\.ssh/.*", "action": action, "description": "Prevent the AI from writing ssh keys",
		}
	}
	return map[string]map[string]interface{}{
		"block":            full("block"),
		"warn":             full("warn"),
		"audit":            full("audit"),
		"require_approval": full("require_approval"),
		"invalid action":   full("invalid_action"),
		"blank name":       {"name": "  ", "connector_type": "x", "pattern": ".*", "action": "block"},
		"empty":            {},
		"nil":              nil,
	}
}

// assertTheRetiredAnswer holds the one refusal's content.
func assertTheRetiredAnswer(t *testing.T, msg string) {
	t.Helper()
	if !strings.HasPrefix(msg, legacyfreeze.ErrCode+": ") {
		t.Errorf("the refusal does not lead with the freeze code, so a caller cannot key on it: %s", msg)
	}
	for _, want := range []string{
		"axonflow_create_tenant_policy is retired in v11",
		"writes nothing on any deployment",
		"decides nothing in v11 (PRD v11 §1.2)",
		legacyfreeze.TypedAuthoringRoute,
		"#4249",
		"5667510887",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not contain %q: %s", want, msg)
		}
	}
	// The old answers, each of which said something false or conditional.
	for _, absent := range []string{"Created tenant-scoped policy", "STORED AND NOT ENFORCED", "could not create tenant policy", "license tier", "orchestrator detail:", "frozen on this deployment"} {
		if strings.Contains(msg, absent) {
			t.Errorf("the refusal carries %q from an answer that no longer exists: %s", absent, msg)
		}
	}
	for _, name := range retiredenv.MCPDynamicPolicies {
		if strings.Contains(msg, name) {
			t.Errorf("the refusal names the retired %s as a lever; setting it refuses boot: %s", name, msg)
		}
	}
}

// TestCreateTenantPolicyRetired_RefusesOnEveryPostureWithNoOrchestratorCall:
// for either orchestrator posture, the empty (self-hosted) tier, Free and Pro, and every argument shape, the
// tool answers the one retired refusal, returns no result, and the orchestrator
// receives zero requests.
func TestCreateTenantPolicyRetired_RefusesOnEveryPostureWithNoOrchestratorCall(t *testing.T) {
	for _, posture := range orchestratorPostures {
		for _, tier := range []string{"", "Free", "Pro"} {
			for argsName, args := range retiredToolArgs() {
				t.Run(posture.name+"/tier="+tier+"/"+argsName, func(t *testing.T) {
					orch := &fakeOrchestrator{}
					orch.serve(t, posture.status, posture.body)

					result, err := mcpToolCreateTenantPolicy(&mcpSession{tenantID: "cs_retired", clientID: "c1", tier: tier}, args)
					if err == nil {
						t.Fatalf("the retired tool answered success: %v", result)
					}
					if result != nil {
						t.Errorf("the retired tool returned a result beside its refusal: %v", result)
					}
					if !errors.Is(err, errTenantPolicyWriteRetired) {
						t.Errorf("the refusal is not errTenantPolicyWriteRetired: %v", err)
					}
					assertTheRetiredAnswer(t, err.Error())
					if got := orch.requests(); len(got) != 0 {
						t.Errorf("the orchestrator received %v, want no request: a retired tool writes nothing", got)
					}
				})
			}
		}
	}
}

// TestCreateTenantPolicyRetired_ToolsCallAnswersIsError drives the tool the way
// a plugin does, a JSON-RPC tools/call to /api/v1/mcp-server, against the
// owner-role posture: the answer is isError:true carrying the refusal, and the
// orchestrator receives nothing.
func TestCreateTenantPolicyRetired_ToolsCallAnswersIsError(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	orch := &fakeOrchestrator{}
	orch.serve(t, orchestratorPostures[0].status, orchestratorPostures[0].body)

	router := setupMCPServerRouter()
	sessionID := initMCPSession(t, router)
	w := mcpServerPost(t, router, "tools/call", "ctp-retired", map[string]interface{}{
		"name":      mcpToolNameCreateTenantPolicy,
		"arguments": retiredToolArgs()["block"],
	}, mcpSessionHeaderKey, sessionID)

	resp := parseJSONRPCResponse(t, w)
	result, _ := resp.Result.(map[string]interface{})
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("tools/call did not answer isError:true: %s", w.Body.String())
	}
	content, _ := result["content"].([]interface{})
	if len(content) == 0 {
		t.Fatalf("tools/call answered no content: %s", w.Body.String())
	}
	first, _ := content[0].(map[string]interface{})
	text, _ := first["text"].(string)
	assertTheRetiredAnswer(t, text)
	if got := orch.requests(); len(got) != 0 {
		t.Errorf("the orchestrator received %v across the tools/call, want no request", got)
	}
}

// TestCreateTenantPolicyRetired_NoFreeQuotaGate: the active_policies quota
// counted legacy rows this tool no longer writes. The tool carries no usage
// limit, which is the assertion that holds the line, and the gate lets Free and
// Pro callers through to the refusal. The gate call alone could not catch a
// restored count: that count failed open to 0 and would not have blocked.
func TestCreateTenantPolicyRetired_NoFreeQuotaGate(t *testing.T) {
	var tool *mcpTool
	for _, candidate := range v1ProMCPTools() {
		if candidate.Name == mcpToolNameCreateTenantPolicy {
			candidate := candidate
			tool = &candidate
		}
	}
	if tool == nil {
		t.Fatalf("%s is not registered: a retired tool stays listed, refusing", mcpToolNameCreateTenantPolicy)
	}
	if tool.FreeUsageLimit != nil {
		t.Errorf("%s carries a FreeUsageLimit %+v over rows it no longer writes", tool.Name, *tool.FreeUsageLimit)
	}

	for _, tier := range []string{"Free", "Pro"} {
		rr := httptest.NewRecorder()
		if blocked := enforceMCPToolGate(context.Background(), rr, &jsonRPCRequest{ID: 7}, &mcpSession{tenantID: "cs_free", tier: tier}, *tool, nil); blocked {
			t.Errorf("tier %s: the gate blocked the retired tool: %s", tier, rr.Body.String())
		}
	}
}

// TestCreateTenantPolicyRetired_DescriptionSaysRetired: tools/list tells an
// assistant before it calls that the tool is retired on every deployment and
// where a policy is authored instead. It does not describe a create.
func TestCreateTenantPolicyRetired_DescriptionSaysRetired(t *testing.T) {
	var desc string
	for _, tool := range v1ProMCPTools() {
		if tool.Name == mcpToolNameCreateTenantPolicy {
			desc = tool.Description
		}
	}
	if desc == "" {
		t.Fatalf("%s is not registered or has no description", mcpToolNameCreateTenantPolicy)
	}
	for _, want := range []string{"Retired in v11 (PRD v11 §1.2)", legacyfreeze.ErrCode, "writes nothing on any deployment", legacyfreeze.TypedAuthoringRoute} {
		if !strings.Contains(desc, want) {
			t.Errorf("the description does not contain %q: %s", want, desc)
		}
	}
	for _, absent := range []string{"Create a custom tenant-scoped governance policy", "Free tier supports", "delete one to make room", "On a deployment whose legacy policy tables are read-only"} {
		if strings.Contains(desc, absent) {
			t.Errorf("the description still carries %q: %s", absent, desc)
		}
	}
}
