// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Regression tests for #3061 — the honesty half.
//
// axonflow_create_tenant_policy unconditionally reported "It will apply to
// subsequent governed calls." An operator who believes a block policy is live
// when it is not is worse off than one with no policy. In v11 the MCP
// tool-governance plane is decided by the anchored engine, and tenant dynamic
// policies no longer decide there (PRD v11 §1.2), so the tool reports the
// stored policy as not enforced on that plane, machine-readably and in prose,
// and names no retired variable as the lever.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/shared/retiredenv"
)

// createTenantPolicyAgainstStubOrchestrator runs the tool against a stub
// orchestrator that always accepts the create, so the assertions isolate the
// enforcement-reporting logic from the create path.
func createTenantPolicyAgainstStubOrchestrator(t *testing.T, args map[string]interface{}) map[string]interface{} {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"policy": map[string]interface{}{
				"id":        "11111111-2222-3333-4444-555555555555",
				"policy_id": "tenant-p-3061",
				"enabled":   true,
			},
		})
	}))
	t.Cleanup(srv.Close)

	original := orchestratorURL
	orchestratorURL = srv.URL
	t.Cleanup(func() { orchestratorURL = original })

	result, err := mcpToolCreateTenantPolicy(
		context.Background(),
		&mcpSession{tenantID: "cs_3061_tenant", tier: "Pro"},
		args,
	)
	if err != nil {
		t.Fatalf("create tenant policy: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not a map: %T", result)
	}
	return m
}

func blockPolicyArgs() map[string]interface{} {
	return map[string]interface{}{
		"name":           "Block AWS key exfiltration",
		"connector_type": "shell",
		"pattern":        "AKIA[0-9A-Z]{16}",
		"action":         "block",
		"description":    "Stop the agent leaking AWS keys",
	}
}

// The stored policy must carry EXACTLY the pattern condition and nothing else.
//
// Emitting {field:"connector", operator:"equals"} is the obvious fix for "the
// user's connector is discarded", and it is wrong: policy_type is 'content',
// and the orchestrator content engine governing the LLM/MAP/WCP planes cannot
// resolve `connector` (getFieldValue falls to its default arm and returns
// nil), so `equals` compares "<nil>" to the real connector name, yields false,
// and — because all conditions must match — the whole policy is skipped on the
// planes where these policies enforce TODAY. This test is the guard against
// that regression being reintroduced.
func TestCreateTenantPolicy3061_EmitsNoConnectorCondition(t *testing.T) {
	for _, connectorType := range []string{"claude_code.Bash", "shell", "*"} {
		t.Run(connectorType, func(t *testing.T) {
			var capturedBody map[string]interface{}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&capturedBody)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"policy": map[string]interface{}{"id": "c-1", "policy_id": "tenant-c"},
				})
			}))
			defer srv.Close()
			original := orchestratorURL
			orchestratorURL = srv.URL
			defer func() { orchestratorURL = original }()

			args := blockPolicyArgs()
			args["connector_type"] = connectorType
			if _, err := mcpToolCreateTenantPolicy(context.Background(),
				&mcpSession{tenantID: "cs_3061_tenant", tier: "Pro"}, args); err != nil {
				t.Fatalf("create: %v", err)
			}

			conds, _ := capturedBody["conditions"].([]interface{})
			if len(conds) != 1 {
				t.Fatalf("conditions len = %d, want 1 (pattern only); got %v", len(conds), conds)
			}
			c0, _ := conds[0].(map[string]interface{})
			if c0["field"] != "query" || c0["operator"] != "regex" {
				t.Errorf("the single condition must be the pattern, got %v", c0)
			}
			for _, c := range conds {
				if m, _ := c.(map[string]interface{}); m["field"] == "connector" {
					t.Errorf("connector condition would break LLM/MAP/WCP enforcement: %v", m)
				}
			}
		})
	}
}

// Unit-level guard on the condition builder.
func TestBuildTenantPolicyConditions3061(t *testing.T) {
	got := buildTenantPolicyConditions("AKIA[0-9A-Z]{16}")
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0]["field"] != "query" || got[0]["operator"] != "regex" || got[0]["value"] != "AKIA[0-9A-Z]{16}" {
		t.Errorf("condition shape drift: %v", got[0])
	}
}

// Because the connector is NOT enforced as a scope, the response must say so
// machine-readably. Silence here would let connector_type imply a
// narrowing the stored policy does not carry, which is the false-promise class
// #3061 exists to eliminate.
func TestCreateTenantPolicy3061_DisclosesConnectorScopeNotEnforced(t *testing.T) {
	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["connector_scope_enforced"] != false {
		t.Errorf("connector_scope_enforced = %v, want false", m["connector_scope_enforced"])
	}
	if m["applies_to_connectors"] != "all" {
		t.Errorf("applies_to_connectors = %v, want \"all\"", m["applies_to_connectors"])
	}
}

// In v11 the MCP tool-governance plane never enforces a tenant dynamic policy,
// so the tool must never promise it, must say so machine-readably and in
// prose, and must not point at a retired variable: setting one refuses boot.
func TestCreateTenantPolicy3061_IsNotEnforcedOnTheMCPPlane(t *testing.T) {
	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["success"] != true || m["created"] != true {
		t.Errorf("the policy WAS created — success/created must stay true: %v", m)
	}
	if m["enforced"] != false {
		t.Errorf("enforced = %v, want false: tenant dynamic policies do not decide the MCP plane", m["enforced"])
	}
	msg, _ := m["message"].(string)
	if strings.Contains(msg, "It will apply to subsequent governed calls") || !strings.Contains(msg, "NOT ENFORCED") {
		t.Errorf("message must state plainly that the policy is not enforced: %q", msg)
	}
	reason, _ := m["enforcement_blocked_reason"].(string)
	if !strings.Contains(reason, "PRD v11") {
		t.Errorf("enforcement_blocked_reason = %q, want the v11 cause", reason)
	}
	for _, text := range []string{msg, reason} {
		for _, name := range retiredenv.MCPDynamicPolicies {
			if strings.Contains(text, name) {
				t.Errorf("the response names the retired %s as a lever; setting it now refuses boot: %q", name, text)
			}
		}
	}
}
