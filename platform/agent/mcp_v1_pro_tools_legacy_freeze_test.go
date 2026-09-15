// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
)

// THE V11.0.0 LEGACY WRITE FREEZE, ANSWERED BY NAME (PRD v11 §5 item 5).
//
// axonflow_create_tenant_policy creates a legacy-shaped tenant policy through
// the orchestrator's legacy create route. On a deployment whose application
// role lost write access to the legacy policy tables (migrations/core/172) the
// orchestrator refuses that create with 409 LEGACY_POLICY_WRITE_FROZEN. These
// tests hold that the tool answers that refusal by name, names the typed
// authoring route, and does nothing else: no retry, no fallback write, and no
// mapping of any OTHER refusal onto the freeze.

// freezeEnvelope is the body the orchestrator writes for the freeze
// (legacyfreeze.Refuse through PolicyAPIHandler.writeError).
func freezeEnvelope() map[string]interface{} {
	return map[string]interface{}{
		"error": map[string]interface{}{
			"code":    legacyfreeze.ErrCode,
			"message": legacyfreeze.Message,
		},
	}
}

// fakeOrchestrator answers every request with status and body, and records
// each request's method and path.
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
		switch b := body.(type) {
		case string:
			_, _ = w.Write([]byte(b))
		default:
			_ = json.NewEncoder(w).Encode(b)
		}
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

func createTenantPolicyArgs() map[string]interface{} {
	return map[string]interface{}{
		"name":           "freeze-probe",
		"connector_type": "claude_code.Bash",
		"pattern":        ".*~/\\.ssh/.*",
		"action":         "block",
	}
}

func TestIsOrchestratorLegacyWriteFrozen_Cases(t *testing.T) {
	frozen409 := fmt.Errorf(`orchestrator returned 409: {"error":{"code":%q,"message":%q}}`, legacyfreeze.ErrCode, legacyfreeze.Message)
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"409 carrying the freeze code", frozen409, true},
		{"the freeze wrapped once more still matches", fmt.Errorf("proxy: %w", frozen409), true},
		{"409 without the code is another conflict", fmt.Errorf(`orchestrator returned 409: {"error":{"code":"CONFLICT","message":"a policy with that name already exists"}}`), false},
		{"409 with tier words and no code", fmt.Errorf(`orchestrator returned 409: {"error":{"code":"policy_limit_exceeded","message":"Policy limit reached"}}`), false},
		{"403 carrying the code is not the freeze", fmt.Errorf(`orchestrator returned 403: {"error":{"code":%q}}`, legacyfreeze.ErrCode), false},
		{"500 carrying the code is not the freeze", fmt.Errorf(`orchestrator returned 500: {"error":{"code":%q}}`, legacyfreeze.ErrCode), false},
		{"the code in text that is not an orchestrator answer", fmt.Errorf("unexpected 200 mentioning %s", legacyfreeze.ErrCode), false},
		{"a malformed 409 body without the code", fmt.Errorf("orchestrator returned 409: conflict"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrchestratorLegacyWriteFrozen(tc.err); got != tc.want {
				t.Errorf("isOrchestratorLegacyWriteFrozen(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestLegacyFreezeAndPaidTierMatchersDoNotOverlap: precedence is decided by
// each matcher's own keys. The freeze is never read as a tier refusal, and a
// 403 tier refusal that happens to carry the freeze code is still the tier
// refusal, so the paid-tier branch wins on its own key.
func TestLegacyFreezeAndPaidTierMatchersDoNotOverlap(t *testing.T) {
	frozen409 := fmt.Errorf(`orchestrator returned 409: {"error":{"code":%q,"message":%q}}`, legacyfreeze.ErrCode, legacyfreeze.Message)
	if isOrchestratorPaidTierReject(frozen409) {
		t.Error("the freeze was classified as a paid-tier refusal")
	}
	tier403WithCode := fmt.Errorf(`orchestrator returned 403: {"error":{"code":"policy_limit_exceeded","message":"Policy limit of 20 reached; %s"}}`, legacyfreeze.ErrCode)
	if !isOrchestratorPaidTierReject(tier403WithCode) {
		t.Fatal("PREMISE: a 403 policy-limit refusal is not classified as paid-tier")
	}
	if isOrchestratorLegacyWriteFrozen(tier403WithCode) {
		t.Error("a 403 tier refusal carrying the freeze code was classified as the freeze")
	}
}

// TestMCPToolCreateTenantPolicy_LegacyWriteFrozen: the orchestrator's freeze
// comes back as a refusal that names the cause, the typed authoring route and
// the tracking row, in that order, then carries the orchestrator's own answer.
// The create is sent exactly once: no retry and no fallback write. The mapping
// does not depend on the caller's tier.
func TestMCPToolCreateTenantPolicy_LegacyWriteFrozen(t *testing.T) {
	for _, tier := range []string{"", "Free", "Pro"} {
		t.Run("tier="+tier, func(t *testing.T) {
			orch := &fakeOrchestrator{}
			orch.serve(t, http.StatusConflict, freezeEnvelope())

			_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "cs_frozen", tier: tier}, createTenantPolicyArgs())
			if err == nil {
				t.Fatal("expected a refusal from the orchestrator's 409 freeze")
			}
			msg := err.Error()

			ordered := []string{"frozen on this deployment in v11.0.0", "because the legacy policy tables are read-only for the application role", legacyfreeze.TypedAuthoringRoute, "#4249", "orchestrator detail:", legacyfreeze.ErrCode}
			last := -1
			for _, part := range ordered {
				i := strings.Index(msg, part)
				if i < 0 {
					t.Fatalf("the refusal does not contain %q: %s", part, msg)
				}
				if i <= last {
					t.Fatalf("%q appears out of order in the refusal: %s", part, msg)
				}
				last = i
			}
			for _, absent := range []string{"license tier", "could not create tenant policy"} {
				if strings.Contains(msg, absent) {
					t.Errorf("the freeze refusal carries %q, which belongs to another branch: %s", absent, msg)
				}
			}
			if errors.Unwrap(err) == nil {
				t.Error("the refusal does not wrap the orchestrator's error")
			}
			// One request and it is a POST: no retry, no fallback write. The path is
			// TestMCPToolCreateTenantPolicy_HappyPath's to pin.
			if got := orch.requests(); len(got) != 1 || !strings.HasPrefix(got[0], "POST ") {
				t.Errorf("the orchestrator saw %v, want exactly one POST to the legacy create route (no retry, no fallback write)", got)
			}
		})
	}
}

// TestMCPToolCreateTenantPolicy_409WithoutFreezeCodeStaysGeneric: only the
// freeze is mapped. A 409 carrying another code, and a 409 whose body is not
// JSON at all, keep the generic wrap and never name the typed route.
func TestMCPToolCreateTenantPolicy_409WithoutFreezeCodeStaysGeneric(t *testing.T) {
	cases := map[string]interface{}{
		"another conflict code": map[string]interface{}{"error": map[string]interface{}{"code": "CONFLICT", "message": "a policy with that name already exists"}},
		"a malformed body":      "conflict",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			orch := &fakeOrchestrator{}
			orch.serve(t, http.StatusConflict, body)

			_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "cs_conflict", tier: ""}, createTenantPolicyArgs())
			if err == nil {
				t.Fatal("expected an error from the orchestrator's 409")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "could not create tenant policy: ") {
				t.Errorf("a non-freeze 409 did not keep the generic wrap: %s", msg)
			}
			if strings.Contains(msg, "frozen") || strings.Contains(msg, legacyfreeze.TypedAuthoringRoute) {
				t.Errorf("a non-freeze 409 was answered as the freeze: %s", msg)
			}
		})
	}
}

// TestCreateTenantPolicyDescriptionNamesTheFreeze: tools/list tells an
// assistant up front, before it calls, that a read-only deployment refuses and
// where to author instead. The sentence is conditional, so an owner-role
// deployment, where the create still succeeds, is not told it will be refused.
func TestCreateTenantPolicyDescriptionNamesTheFreeze(t *testing.T) {
	var found *mcpTool
	for _, tool := range v1ProMCPTools() {
		if tool.Name == mcpToolNameCreateTenantPolicy {
			tool := tool
			found = &tool
			break
		}
	}
	if found == nil {
		t.Fatalf("%s is not registered", mcpToolNameCreateTenantPolicy)
	}
	desc := found.Description
	if !strings.Contains(desc, "On a deployment whose legacy policy tables are read-only") {
		t.Errorf("the description does not state the condition under which the tool refuses: %s", desc)
	}
	if !strings.Contains(desc, legacyfreeze.TypedAuthoringRoute) {
		t.Errorf("the description does not name the typed authoring route: %s", desc)
	}
	if !strings.Contains(desc, "Create a custom tenant-scoped governance policy.") {
		t.Errorf("the description lost its original purpose sentence: %s", desc)
	}
}
