// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Regression tests for #3061 — the honesty half.
//
// axonflow_create_tenant_policy unconditionally reported
// "It will apply to subsequent governed calls." That was false on every
// default install: both the community docker-compose default and the
// community-saas CloudFormation default ship MCP_DYNAMIC_POLICIES_ENABLED
// false, so the policy was stored and inert. An operator who believes a
// block policy is live when it is not is worse off than one with no policy.
//
// The tool now reports the deployment's ACTUAL posture: an `enforced` boolean
// (machine-readable, so an LLM consumer need not parse prose) plus a message
// that names the exact lever to flip.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// withGlobalEvaluator installs a dynamic-policy evaluator for the duration of
// one test and restores the previous one. Passing nil models a process that
// never initialized an evaluator at all.
func withGlobalEvaluator(t *testing.T, evaluator *sharedpolicy.DynamicPolicyEvaluator) {
	t.Helper()
	original := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalDynamicPolicyEvaluator(evaluator)
	t.Cleanup(func() { sharedpolicy.SetGlobalDynamicPolicyEvaluator(original) })
}

// evaluatorWith builds an evaluator with the given enabled flag + connector
// allowlist, bypassing the env-var constructor so the test states its intent
// directly.
func evaluatorWith(enabled bool, connectors []string) *sharedpolicy.DynamicPolicyEvaluator {
	cfg := sharedpolicy.DefaultDynamicPolicyConfig()
	cfg.Enabled = enabled
	cfg.EnabledConnectors = connectors
	return sharedpolicy.NewDynamicPolicyEvaluator(cfg)
}

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

// The default-install case, and the one from the issue: the plane is off, so
// the tool must NOT promise enforcement.
func TestCreateTenantPolicy3061_DisabledPlaneReportsNotEnforced(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(false, nil))

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["success"] != true || m["created"] != true {
		t.Errorf("the policy WAS created — success/created must stay true: %v", m)
	}
	if m["enforced"] != false {
		t.Errorf("enforced = %v, want false when the MCP dynamic plane is disabled", m["enforced"])
	}
	msg, _ := m["message"].(string)
	if strings.Contains(msg, "It will apply to subsequent governed calls") {
		t.Errorf("the false enforcement promise is still present: %q", msg)
	}
	if !strings.Contains(msg, "NOT ENFORCED") {
		t.Errorf("message must state plainly that the policy is not enforced: %q", msg)
	}
	// The message has to be actionable — name the lever, not just the symptom.
	if !strings.Contains(msg, "MCP_DYNAMIC_POLICIES_ENABLED") {
		t.Errorf("message must name the env var to set: %q", msg)
	}
	reason, _ := m["enforcement_blocked_reason"].(string)
	if !strings.Contains(reason, "MCP_DYNAMIC_POLICIES_ENABLED") {
		t.Errorf("enforcement_blocked_reason = %q, want the disabled-plane cause", reason)
	}
}

// Vacuity control for the test above: with the plane genuinely enabled the
// tool DOES promise enforcement. Without this, an implementation that always
// said "not enforced" would pass.
func TestCreateTenantPolicy3061_EnabledPlaneReportsEnforced(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, nil))

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["enforced"] != true {
		t.Errorf("enforced = %v, want true when the plane is enabled for all connectors", m["enforced"])
	}
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "It will apply to subsequent governed calls") {
		t.Errorf("message must confirm enforcement when it is real: %q", msg)
	}
	if _, present := m["enforcement_blocked_reason"]; present {
		t.Errorf("enforcement_blocked_reason must be absent when enforced: %v", m["enforcement_blocked_reason"])
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
	withGlobalEvaluator(t, evaluatorWith(true, nil))

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

// Because the connector is NOT enforced as a scope, the response must say so —
// in prose AND machine-readably. Silence here would let connector_type imply a
// narrowing the stored policy does not carry, which is the false-promise class
// #3061 exists to eliminate.
func TestCreateTenantPolicy3061_DisclosesConnectorScopeNotEnforced(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, nil))

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["connector_scope_enforced"] != false {
		t.Errorf("connector_scope_enforced = %v, want false", m["connector_scope_enforced"])
	}
	if m["applies_to_connectors"] != "all" {
		t.Errorf("applies_to_connectors = %v, want \"all\"", m["applies_to_connectors"])
	}
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "NOT yet enforced as a scope") {
		t.Errorf("message must disclose that connector_type is not a scope: %q", msg)
	}
	if !strings.Contains(msg, "EVERY governed connector") {
		t.Errorf("message must state the policy applies to every connector: %q", msg)
	}
}

// A restricted allowlist narrows where the plane runs at all, so the policy is
// still enforced — but only there, and the response must name the restriction
// rather than claim blanket coverage.
func TestCreateTenantPolicy3061_RestrictedAllowlistIsDisclosedNotDenied(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, []string{"postgres", "http"}))

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["enforced"] != true {
		t.Errorf("enforced = %v, want true — the plane is on, just narrowed", m["enforced"])
	}
	applies, _ := m["applies_to_connectors"].([]string)
	if len(applies) != 2 || applies[0] != "postgres" {
		t.Errorf("applies_to_connectors = %v, want the allowlist", m["applies_to_connectors"])
	}
	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "MCP_DYNAMIC_POLICIES_CONNECTORS") {
		t.Errorf("message must name the restricting lever: %q", msg)
	}
	if !strings.Contains(msg, "postgres, http") {
		t.Errorf("message must list the governed connectors: %q", msg)
	}
}

// A connector name the platform never emits (the wire form is the composite
// "<client>.<Tool>") must NOT flip enforcement reporting. Pre-review this went
// through IsEnabled(connectorType), which returns true for ANY string when the
// allowlist is empty and false when it is not — reporting a policy as scoped to
// a connector that will never appear on the wire.
func TestCreateTenantPolicy3061_BogusConnectorNameDoesNotSkewEnforcement(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, []string{"claude_code.Bash"}))

	args := blockPolicyArgs()
	args["connector_type"] = "shell" // not a wire connector name
	m := createTenantPolicyAgainstStubOrchestrator(t, args)

	// Enforcement is a plane-level fact and does not depend on this string.
	if m["enforced"] != true {
		t.Errorf("enforced = %v, want true (plane on); it must not depend on connector_type", m["enforced"])
	}
	if m["connector_scope_enforced"] != false {
		t.Errorf("connector_scope_enforced = %v, want false", m["connector_scope_enforced"])
	}
	msg, _ := m["message"].(string)
	if strings.Contains(msg, "on connector \"shell\".") {
		t.Errorf("message must not claim scoping to a connector that is not enforced: %q", msg)
	}
}

// No evaluator at all must be reported as not-enforced, and must not panic —
// IsEnabled/GetConfig take a lock, so a nil receiver would crash the tools/call.
func TestCreateTenantPolicy3061_NilEvaluatorIsNotEnforcedAndDoesNotPanic(t *testing.T) {
	withGlobalEvaluator(t, nil)

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	if m["enforced"] != false {
		t.Errorf("enforced = %v, want false when no evaluator is initialized", m["enforced"])
	}
	if m["success"] != true {
		t.Errorf("the create still succeeded; success must stay true: %v", m)
	}
}

// Only "block" denies on this plane — the MCP evaluation response has no
// approval or alert channel. An enforced non-block policy must say so.
func TestCreateTenantPolicy3061_NonBlockActionDisclosesNoGate(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, nil))

	args := blockPolicyArgs()
	args["action"] = "require_approval"
	m := createTenantPolicyAgainstStubOrchestrator(t, args)

	msg, _ := m["message"].(string)
	if !strings.Contains(msg, "does not stop the call") {
		t.Errorf("message must disclose that require_approval does not gate here: %q", msg)
	}
}

// A block action carries no such caveat.
func TestCreateTenantPolicy3061_BlockActionCarriesNoCaveat(t *testing.T) {
	withGlobalEvaluator(t, evaluatorWith(true, nil))

	m := createTenantPolicyAgainstStubOrchestrator(t, blockPolicyArgs())

	msg, _ := m["message"].(string)
	if strings.Contains(msg, "does not stop the call") {
		t.Errorf("a block policy must not carry the non-gating caveat: %q", msg)
	}
}

// Direct coverage of the status helper. It is deliberately plane-level: it
// takes no connector argument, so no connector string can skew it.
func TestTenantPolicyEnforcementStatus3061(t *testing.T) {
	cases := []struct {
		name           string
		evaluator      *sharedpolicy.DynamicPolicyEvaluator
		wantEnforced   bool
		wantReasonHas  string
		wantRestricted []string
	}{
		{"nil evaluator", nil, false, "no MCP dynamic-policy evaluator", nil},
		{"disabled", evaluatorWith(false, nil), false, "MCP_DYNAMIC_POLICIES_ENABLED", nil},
		{"enabled, all connectors", evaluatorWith(true, nil), true, "", nil},
		{"enabled, restricted", evaluatorWith(true, []string{"postgres"}), true, "", []string{"postgres"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withGlobalEvaluator(t, tc.evaluator)
			enforced, reason, restricted := tenantPolicyEnforcementStatus()
			if enforced != tc.wantEnforced {
				t.Fatalf("enforced = %v, want %v (reason %q)", enforced, tc.wantEnforced, reason)
			}
			if tc.wantEnforced && reason != "" {
				t.Errorf("enforced status must carry no blocked reason, got %q", reason)
			}
			if !tc.wantEnforced && !strings.Contains(reason, tc.wantReasonHas) {
				t.Errorf("reason = %q, want it to mention %q", reason, tc.wantReasonHas)
			}
			if len(restricted) != len(tc.wantRestricted) {
				t.Errorf("restrictedTo = %v, want %v", restricted, tc.wantRestricted)
			}
		})
	}
}
