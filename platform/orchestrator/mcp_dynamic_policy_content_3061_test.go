// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression tests for #3061 — tenant policies created through the Pro tool
// axonflow_create_tenant_policy could never enforce on the MCP tool-governance
// plane, in ANY deployment configuration, while the tool reported
// "It will apply to subsequent governed calls."
//
// Three independent blockers, all here in mcp_dynamic_policy_handler.go:
//
//  1. getPoliciesForMCP admitted mcp|connector|rate-limit|budget|time-access|
//     role-access|anomaly. The tool writes type=content (and POST
//     /api/v1/policies defaults policy_type to 'content'), so the policy was
//     dropped BEFORE evaluation.
//  2. evaluateCondition knew no `query`/`statement` field and no `regex`
//     operator, and the tool writes exactly {field:"query",operator:"regex"} —
//     a condition that could only ever evaluate FALSE.
//  3. getPoliciesForMCP carried its OWN tenant predicate, the exact inverse of
//     the canonical dbCachedPolicyAppliesToTenant (#3059) on every stored
//     shape: it skipped 'global' and NULL→"default" (which apply to every
//     tenant) and admitted '' (which applies to none, and which migration
//     core/155 forbids). It now calls ListActivePoliciesForTenant so each
//     engine applies its own enforcement predicate.
//
// The block tests fail against the pre-fix handler because the policy never
// reaches the evaluator at all.
//
// The allow-direction assertions are deliberate vacuity controls: "now
// blocks" alone would also pass if the handler simply started denying
// everything (feedback_absence_is_not_evidence_in_runtime_harness).
//
// NOTE ON THE FIXTURE. tenantPolicyAsStored emits exactly what
// buildTenantPolicyConditions writes — one {query regex} condition and NO
// connector condition. connector_type is descriptive only; the tests here, the
// agent-side assertion in mcp_v1_pro_tools_test.go and runtime-e2e assertion 5
// all agree on that, and all three break when real scoping lands (#3082).

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// awsKeyPattern is the pattern from the issue's reproduction.
const awsKeyPattern = "AKIA[0-9A-Z]{16}"

// tenantPolicyAsStored mirrors the exact row axonflow_create_tenant_policy
// writes: type=content and ONE condition — {field:"query", operator:"regex"}.
//
// There is deliberately NO connector condition, because the writer emits none:
// buildTenantPolicyConditions (agent/mcp_v1_pro_tools.go) returns the pattern
// and only the pattern, and the connector the caller named is recorded in the
// policy DESCRIPTION. Emitting {field:"connector"} would break the LLM/MAP/WCP
// planes where these policy_type='content' rows already enforce — the
// orchestrator content engine cannot resolve `connector`, so the condition
// yields false and (all conditions must match) the whole policy is skipped.
//
// Keeping this fixture identical to the real writer is the point. An earlier
// version added a connector condition the writer never emits, which made
// TestMCP3061_ContentPolicyScopedToNamedConnector pass while asserting a
// scoping the shipped code does not have — and put this file in direct
// contradiction with agent/mcp_v1_pro_tools_test.go and the runtime-e2e, both
// of which assert the opposite. A fixture that "fixes up" the shape tests
// nothing.
func tenantPolicyAsStored(id, tenantID, pattern string) DynamicPolicy {
	return DynamicPolicy{
		ID:       id,
		Name:     "Block AWS key exfiltration",
		Type:     "content",
		Enabled:  true,
		TenantID: tenantID,
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "regex", Value: pattern},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{
				"reason": `Tenant policy "Block AWS key exfiltration" matched`,
			}},
		},
	}
}

// evaluateMCP drives the REAL route through the REAL router, not the
// evaluator method directly — the type filter that caused this bug lives on
// the request path, so a direct evaluateConditions call would not exercise it.
func evaluateMCP(t *testing.T, policies []DynamicPolicy, req MCPPolicyEvaluationRequest) MCPPolicyEvaluationResponse {
	t.Helper()
	engine := newTestEngine(policies)
	defer engine.Close()

	router := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(router)

	jsonBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	httpReq := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	if rr.Code != 200 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp MCPPolicyEvaluationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// The issue's exact reproduction: connector=shell, the AKIA pattern, a
// statement carrying a real-shaped key. Pre-fix this returned allowed=true
// with the policy silently absent from evaluation.
func TestMCP3061_ContentPolicyBlocksMatchingStatement(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p1", "tenant-1", awsKeyPattern)}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Operation:     "bash",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})

	if resp.PoliciesEvaluated != 1 {
		t.Fatalf("policies_evaluated = %d, want 1 — a content policy must REACH the evaluator", resp.PoliciesEvaluated)
	}
	if resp.Allowed {
		t.Fatal("allowed = true; the tenant policy must block a statement matching its pattern")
	}
	if resp.BlockReason != `Tenant policy "Block AWS key exfiltration" matched` {
		t.Errorf("block_reason = %q, want the policy's configured reason", resp.BlockReason)
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != "p1" {
		t.Errorf("matched_policies = %+v, want the one policy that blocked", resp.MatchedPolicies)
	}
}

// Vacuity control for the test above: the SAME policy must NOT block a
// statement that does not match. Without this, a handler that denied
// unconditionally would pass the block test.
func TestMCP3061_ContentPolicyAllowsNonMatchingStatement(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p1", "tenant-1", awsKeyPattern)}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Operation:     "bash",
		Statement:     "echo hello world",
	})

	if resp.PoliciesEvaluated != 1 {
		t.Fatalf("policies_evaluated = %d, want 1", resp.PoliciesEvaluated)
	}
	if !resp.Allowed {
		t.Fatalf("allowed = false for a non-matching statement; block_reason = %q", resp.BlockReason)
	}
	if len(resp.MatchedPolicies) != 0 {
		t.Errorf("matched_policies = %+v, want none", resp.MatchedPolicies)
	}
}

// DOCUMENTED SEMANTICS, pinned deliberately: connector_type is NOT a scope.
//
// The stored row carries no connector condition (see tenantPolicyAsStored and
// buildTenantPolicyConditions), so the policy governs its PATTERN on every
// connector the plane evaluates — not only the one the caller named. That is
// over-broad rather than under-broad (it fails toward more governance), it
// matches the pre-#3061 stored shape so no existing row changes meaning, and
// the tool discloses it (`connector_scope_enforced: false`,
// `applies_to_connectors: "all"`).
//
// This replaces an earlier TestMCP3061_ContentPolicyScopedToNamedConnector,
// which asserted the opposite and only passed because the fixture invented a
// connector condition the writer never emits. This test, the agent-side
// assertion in mcp_v1_pro_tools_test.go and runtime-e2e assertion 5 now agree,
// and all three fail loudly when genuine connector scoping lands (#3082).
func TestMCP3061_PolicyGovernsEveryConnectorNotOnlyTheNamedOne(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p1", "tenant-1", awsKeyPattern)}

	// The tool call that created this policy named connector_type="shell";
	// a "postgres" call carrying the same pattern is governed all the same.
	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})

	if resp.Allowed {
		t.Fatal("connector_type is not a scope: the policy must govern a connector other than the one named")
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].PolicyID != "p1" {
		t.Errorf("matched_policies = %+v, want the one policy that blocked", resp.MatchedPolicies)
	}

	// Vacuity control: the block above is PATTERN-driven, not blanket. The same
	// policy on the same non-named connector must allow a non-matching
	// statement — otherwise "blocks on every connector" would also be satisfied
	// by an evaluator that simply denied everything.
	clean := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Statement:     "SELECT 1",
	})
	if !clean.Allowed {
		t.Fatalf("control failed: a non-matching statement must stay allowed; block_reason = %q", clean.BlockReason)
	}
}

// `statement` is accepted as an alias for `query` so a policy authored against
// the wire field's own name behaves identically.
func TestMCP3061_StatementFieldAlias(t *testing.T) {
	policies := []DynamicPolicy{{
		ID: "p-alias", Name: "alias", Type: "content", Enabled: true, TenantID: "tenant-1",
		Conditions: []PolicyCondition{{Field: "statement", Operator: "regex", Value: awsKeyPattern}},
		Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "alias matched"}}},
	}}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "AKIAIOSFODNN7EXAMPLE",
	})
	if resp.Allowed {
		t.Fatal("field \"statement\" must resolve to the governed statement")
	}
	if resp.BlockReason != "alias matched" {
		t.Errorf("block_reason = %q", resp.BlockReason)
	}
}

// A pattern that fails to COMPILE must fail SAFE — treated as "did not match",
// never as a match and never as an error that aborts the whole evaluation. The
// sibling policy in the same set must still block, proving one malformed
// tenant policy cannot disable governance for the rest.
func TestMCP3061_InvalidRegexFailsSafeWithoutDisablingSiblings(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID: "p-bad", Name: "malformed", Type: "content", Enabled: true, TenantID: "tenant-1",
			Conditions: []PolicyCondition{{Field: "query", Operator: "regex", Value: "AKIA[0-9A-Z{16}("}},
			Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "malformed matched"}}},
		},
		tenantPolicyAsStored("p-good", "tenant-1", awsKeyPattern),
	}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})

	if resp.PoliciesEvaluated != 2 {
		t.Fatalf("policies_evaluated = %d, want 2", resp.PoliciesEvaluated)
	}
	if resp.Allowed {
		t.Fatal("the well-formed sibling policy must still block")
	}
	if resp.BlockReason == "malformed matched" {
		t.Fatal("an uncompilable pattern must never be treated as a MATCH")
	}
	for _, m := range resp.MatchedPolicies {
		if m.PolicyID == "p-bad" {
			t.Errorf("malformed-regex policy reported as matched: %+v", m)
		}
	}
}

// A non-matching regex on an otherwise matching policy must not block —
// guards against a fail-safe implemented as "on error, match".
func TestMCP3061_RegexNonMatchDoesNotBlock(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p1", "tenant-1", "^ghp_[A-Za-z0-9]{36}$")}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if !resp.Allowed {
		t.Fatalf("non-matching pattern must not block; block_reason = %q", resp.BlockReason)
	}
}

// DoD: the tenant filter is unchanged and still correct. Admitting `content`
// widened the TYPE filter only — tenant B's content policy must not be
// evaluated for, and can never block, tenant A. Asserting policies_evaluated
// (not just allowed) proves the policy was excluded at the filter rather than
// merely failing to match.
func TestMCP3061_ContentPolicyTenantFilterStillIsolates(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p-tenant-b", "tenant-B", awsKeyPattern)}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-A",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})

	if resp.PoliciesEvaluated != 0 {
		t.Fatalf("policies_evaluated = %d, want 0 — tenant B's policy must not be evaluated for tenant A", resp.PoliciesEvaluated)
	}
	if !resp.Allowed {
		t.Fatalf("tenant B's policy blocked tenant A's call: %q", resp.BlockReason)
	}

	// Vacuity control: the identical policy DOES block its own tenant, so the
	// isolation above is real and not an artifact of a policy that never matches.
	own := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-B",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if own.Allowed {
		t.Fatal("control failed: the policy must block its OWN tenant, else the isolation assertion is vacuous")
	}
}

// A deployment-wide content policy applies to every tenant on THE IN-MEMORY
// engine, whose apply-to-all shape is an empty TenantID (memPolicyAppliesToTenant).
//
// This is the in-memory half only. The shapes PRODUCTION stores are 'global'
// and NULL→"default" under the database engine, and they are covered by
// TestMCP3061_DatabaseEngineSentinelTenantsGovernTheMCPPlane below — an earlier
// version of this test asserted TenantID:"" under a name claiming to prove
// "a global policy applies to every tenant", which was false assurance aimed
// precisely at the broken case: refreshPolicies maps NULL to "default" and
// never to "", and migration core/155 forbids the empty string outright, so
// that shape cannot exist under the engine production runs.
func TestMCP3061_DeploymentWidePolicyAppliesOnInMemoryEngine(t *testing.T) {
	policies := []DynamicPolicy{tenantPolicyAsStored("p-global", "", awsKeyPattern)}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "any-tenant",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if resp.Allowed {
		t.Fatal("a deployment-wide content policy must apply to every tenant on the in-memory engine")
	}

	// Vacuity control: a non-matching statement stays allowed, so the block
	// above is the policy matching rather than the evaluator denying blanket.
	clean := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "any-tenant",
		ConnectorName: "shell",
		Statement:     "echo benign",
	})
	if !clean.Allowed {
		t.Fatalf("control failed: non-matching statement blocked; block_reason = %q", clean.BlockReason)
	}
}

// dbEngineWithCachedPolicy builds a DatabaseDynamicPolicyEngine whose cache
// holds one entry in the EXACT shape refreshPolicies writes for a stored row —
// including the _metadata block dbCachedPolicyAppliesToTenant reads. No
// database is involved: the tenant decision is made entirely from the cached
// shape, which is the thing under test.
//
// tenantIDStr is the value refreshPolicies computes from the column: the real
// tenant id, "global", or "default" (its NULL sentinel).
func dbEngineWithCachedPolicy(policyID, tenantIDStr, pattern string) *DatabaseDynamicPolicyEngine {
	conditions, _ := json.Marshal([]PolicyCondition{
		{Field: "query", Operator: "regex", Value: pattern},
	})
	actions, _ := json.Marshal([]PolicyAction{
		{Type: "block", Config: map[string]interface{}{"reason": "deployment-wide baseline matched"}},
	})
	return &DatabaseDynamicPolicyEngine{
		policies: map[string]interface{}{
			policyID: map[string]interface{}{
				"policy_id":  policyID,
				"name":       "deployment-wide baseline",
				"type":       "content",
				"conditions": json.RawMessage(conditions),
				"actions":    json.RawMessage(actions),
				"tenant_id":  tenantIDStr,
				"priority":   100,
				"_metadata": map[string]interface{}{
					"id":        policyID,
					"name":      "deployment-wide baseline",
					"tenant_id": tenantIDStr,
					"priority":  100,
				},
			},
		},
	}
}

func evaluateMCPWithEngine(t *testing.T, engine MCPPolicyEngine, req MCPPolicyEvaluationRequest) MCPPolicyEvaluationResponse {
	t.Helper()
	router := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(router)

	jsonBody, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	httpReq := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	httpReq.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httpReq)

	if rr.Code != 200 {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var resp MCPPolicyEvaluationResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// #3061 R3 BLOCKER 2 — the MCP plane must agree with dbCachedPolicyAppliesToTenant
// on every stored shape, because that is the function deciding ENFORCEMENT on
// the LLM/MAP/WCP planes for the very same row.
//
// The handler used to carry its own predicate:
//
//	if p.TenantID != "" && p.TenantID != req.TenantID { continue }
//
// which was the exact INVERSE of the canonical one on all three shapes —
// 'global' skipped, 'default' (NULL) skipped, empty-string admitted. Concretely: an
// operator's deployment-wide `content` baseline stored as tenant_id='global'
// blocked on LLM/MAP/WCP and was silently skipped on every MCP tool call.
//
// This test drives the DATABASE engine — the one production runs — through the
// real HTTP route, so it measures the shipped path end to end rather than a
// look-alike predicate. It is the direct regression pin for that gap: reinstate
// the old predicate and the 'global' and 'default' cases go allowed=true.
func TestMCP3061_DatabaseEngineSentinelTenantsGovernTheMCPPlane(t *testing.T) {
	const matching = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"

	cases := []struct {
		name string
		// storedTenant is what refreshPolicies puts in _metadata.tenant_id.
		storedTenant string
		callerTenant string
		wantBlock    bool
		why          string
	}{
		{
			name: "global baseline governs an unrelated tenant", storedTenant: "global",
			callerTenant: "tenant-1", wantBlock: true,
			why: "'global' is the shared-baseline sentinel; dbCachedPolicyAppliesToTenant returns true for every tenant",
		},
		{
			name: "NULL tenant_id (loaded as \"default\") governs an unrelated tenant", storedTenant: "default",
			callerTenant: "tenant-1", wantBlock: true,
			why: "refreshPolicies maps a NULL tenant_id to the \"default\" sentinel, which applies to all tenants",
		},
		{
			name: "an exact tenant match still governs", storedTenant: "tenant-1",
			callerTenant: "tenant-1", wantBlock: true,
			why: "the ordinary single-tenant case must keep working",
		},
		{
			name: "another tenant's policy still does not govern", storedTenant: "tenant-B",
			callerTenant: "tenant-1", wantBlock: false,
			why: "ISOLATION CONTROL: widening to the sentinels must not widen to real foreign tenants",
		},
		{
			name: "an empty tenant_id applies to NOBODY", storedTenant: "",
			callerTenant: "tenant-1", wantBlock: false,
			why: "the accidental fourth shape core/155 now forbids; the canonical predicate returns false for it",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			engine := dbEngineWithCachedPolicy("p-sentinel", tc.storedTenant, awsKeyPattern)

			// Pin the MCP plane against the canonical predicate on the SAME raw
			// cache entry, so this test cannot drift from #3059's choke point:
			// if dbCachedPolicyAppliesToTenant ever changes, the expectation
			// table must change with it or this fails.
			raw := engine.policies["p-sentinel"].(map[string]interface{})
			if canonical := dbCachedPolicyAppliesToTenant(raw, tc.callerTenant, nil, "p-sentinel"); canonical != tc.wantBlock {
				t.Fatalf("expectation drift: dbCachedPolicyAppliesToTenant = %v but this case wants block = %v (%s)",
					canonical, tc.wantBlock, tc.why)
			}

			resp := evaluateMCPWithEngine(t, engine, MCPPolicyEvaluationRequest{
				TenantID:      tc.callerTenant,
				ConnectorName: "shell",
				Statement:     matching,
			})

			if gotBlock := !resp.Allowed; gotBlock != tc.wantBlock {
				t.Errorf("MCP plane blocked = %v, want %v (stored tenant_id=%q, caller=%q) — %s; policies_evaluated=%d",
					gotBlock, tc.wantBlock, tc.storedTenant, tc.callerTenant, tc.why, resp.PoliciesEvaluated)
			}
			if tc.wantBlock && resp.PoliciesEvaluated != 1 {
				t.Errorf("policies_evaluated = %d, want 1 — the policy must REACH the evaluator", resp.PoliciesEvaluated)
			}
			if !tc.wantBlock && resp.PoliciesEvaluated != 0 {
				t.Errorf("policies_evaluated = %d, want 0 — a non-applicable policy must be filtered out, not merely fail to match",
					resp.PoliciesEvaluated)
			}
		})
	}

	// Vacuity control for the whole table: the sentinel shape that DOES govern
	// still only blocks its pattern, so "blocks everywhere" is not the evaluator
	// denying blanket.
	clean := evaluateMCPWithEngine(t, dbEngineWithCachedPolicy("p-sentinel", "global", awsKeyPattern),
		MCPPolicyEvaluationRequest{
			TenantID:      "tenant-1",
			ConnectorName: "shell",
			Statement:     "echo benign",
		})
	if !clean.Allowed {
		t.Fatalf("control failed: a global policy must not block a non-matching statement; block_reason = %q", clean.BlockReason)
	}
}

// A disabled content policy must stay inert — admitting the type must not
// bypass the enabled check.
func TestMCP3061_DisabledContentPolicyStaysInert(t *testing.T) {
	p := tenantPolicyAsStored("p-off", "tenant-1", awsKeyPattern)
	p.Enabled = false

	resp := evaluateMCP(t, []DynamicPolicy{p}, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if resp.PoliciesEvaluated != 0 {
		t.Fatalf("policies_evaluated = %d, want 0 for a disabled policy", resp.PoliciesEvaluated)
	}
	if !resp.Allowed {
		t.Fatal("a disabled policy must never block")
	}
}

// Non-block actions surface as matched but do not stop the call — the MCP
// evaluation response has no approval/alert channel. This pins the behavior
// the agent tool's message now states honestly.
func TestMCP3061_NonBlockActionMatchesWithoutDenying(t *testing.T) {
	p := tenantPolicyAsStored("p-alert", "tenant-1", awsKeyPattern)
	p.Actions = []PolicyAction{{Type: "alert", Config: map[string]interface{}{"reason": "noisy"}}}

	resp := evaluateMCP(t, []DynamicPolicy{p}, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if !resp.Allowed {
		t.Fatal("an alert-action policy must not deny on this plane")
	}
	if len(resp.MatchedPolicies) != 1 || resp.MatchedPolicies[0].Action != "alert" {
		t.Errorf("matched_policies = %+v, want one match carrying action=alert", resp.MatchedPolicies)
	}
}

// A condition-less policy matches everything, INCLUDING a benign call — this
// is the restored, honest semantics (see condition_evaluator.go's
// "Withdrawn" doc section) and a deliberate reversal of this test's own
// former assertion. Admitting `content` widened this evaluation path to the
// type the policy API defaults to, and the safety concern that originally
// motivated a "never match" guard here — a row whose conditions JSON failed
// to unmarshal reaching this handler with Conditions silently nil'd out,
// indistinguishable from a genuinely condition-less policy — is now closed
// one layer up: cachedPolicyToDynamicPolicy (db_dynamic_policies.go)
// excludes a policy whose conditions fail to unmarshal from the cache
// entirely, so it can never reach this handler as a bare `Conditions: nil`
// DynamicPolicy in the first place. By the time a DynamicPolicy with nil
// Conditions reaches evaluateConditions, it can only mean one thing: a
// deliberately condition-less, platform-seeded policy. Blocking is therefore
// the correct outcome for the fixture below, not a bug.
func TestMCP3061_ConditionlessPolicyMatchesEverything(t *testing.T) {
	policies := []DynamicPolicy{{
		ID: "p-unconditional", Name: "unconditional policy", Type: "content", Enabled: true, TenantID: "tenant-1",
		Conditions: nil,
		Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "applies to everything"}}},
	}}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "echo entirely benign",
	})

	if resp.Allowed {
		t.Fatalf("a condition-less block policy must deny (it applies to everything), got Allowed=true")
	}
	if len(resp.MatchedPolicies) != 1 {
		t.Errorf("condition-less policy not reported as matched: %+v", resp.MatchedPolicies)
	}
}

// BLAST-RADIUS PIN (#3061 R3 HIGH-1). Admitting `content` means existing
// LLM-plane policies also evaluate here, and it is NOT true that an unfamiliar
// condition always fails to no-match. That holds for unknown FIELDS (the
// default arm yields nil → false), but a KNOWN field with a NEGATED operator
// matches on the empty value: `user.role` is frequently empty on the MCP plane
// (the internal-service path leaves it unset), and `not_equals "admin"` on ""
// is TRUE.
//
// So an existing policy {query regex …} AND {user.role not_equals "admin"} →
// block, authored for the LLM plane, DOES deny MCP tool calls wherever the
// plane is enabled. That is a real behavior change on upgrade, deliberately
// pinned here rather than left as a surprise. The semantics themselves are
// correct — an empty role genuinely is "not admin" — so this test documents
// the consequence rather than asserting a guard.
func TestMCP3061_NegatedOperatorOnEmptyFieldMatches(t *testing.T) {
	policies := []DynamicPolicy{{
		ID: "p-llm", Name: "llm-plane policy", Type: "content", Enabled: true, TenantID: "tenant-1",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "regex", Value: awsKeyPattern},
			{Field: "user.role", Operator: "not_equals", Value: "admin"},
		},
		Actions: []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "non-admin denied"}}},
	}}

	// UserRole deliberately unset — the shape the MCP plane commonly presents.
	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if resp.Allowed {
		t.Fatal("documented blast radius: not_equals on an empty user.role MATCHES, so this policy denies")
	}
	if resp.BlockReason != "non-admin denied" {
		t.Errorf("block_reason = %q", resp.BlockReason)
	}

	// Control: with the role populated to the excluded value, it does not match.
	allowed := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		UserRole:      "admin",
		Statement:     "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
	})
	if !allowed.Allowed {
		t.Fatalf("admin must not be denied by a not_equals-admin condition: %q", allowed.BlockReason)
	}
}

// The unknown-FIELD half of the claim, which does hold: a condition naming a
// field this evaluator cannot resolve fails to no-match rather than matching.
func TestMCP3061_UnknownFieldFailsToNoMatch(t *testing.T) {
	policies := []DynamicPolicy{{
		ID: "p-unknown", Name: "unknown field", Type: "content", Enabled: true, TenantID: "tenant-1",
		Conditions: []PolicyCondition{
			{Field: "risk_score", Operator: "greater_than", Value: 0},
		},
		Actions: []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "should not fire"}}},
	}}

	resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "shell",
		Statement:     "echo benign",
	})
	if !resp.Allowed {
		t.Fatalf("a field this evaluator cannot resolve must not block: %q", resp.BlockReason)
	}
}

// Regex semantics must be identical to the orchestrator content engine's arm
// (db_dynamic_policies.go): unanchored search, case-sensitive.
func TestMCP3061_RegexSemanticsMatchOrchestratorEngine(t *testing.T) {
	cases := []struct {
		name      string
		pattern   string
		statement string
		wantBlock bool
	}{
		{"unanchored search matches mid-string", "AKIA[0-9A-Z]{16}", "prefix AKIAIOSFODNN7EXAMPLE suffix", true},
		{"case sensitive by default", "akia[0-9a-z]{16}", "AKIAIOSFODNN7EXAMPLE", false},
		{"explicit case-insensitive flag honored", "(?i)akia[0-9a-z]{16}", "AKIAIOSFODNN7EXAMPLE", true},
		{"anchored pattern respects anchors", "^AKIA[0-9A-Z]{16}$", "prefix AKIAIOSFODNN7EXAMPLE", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := []DynamicPolicy{tenantPolicyAsStored("p", "tenant-1", tc.pattern)}
			resp := evaluateMCP(t, policies, MCPPolicyEvaluationRequest{
				TenantID:      "tenant-1",
				ConnectorName: "shell",
				Statement:     tc.statement,
			})
			if gotBlock := !resp.Allowed; gotBlock != tc.wantBlock {
				t.Errorf("blocked = %v, want %v (pattern %q vs %q)", gotBlock, tc.wantBlock, tc.pattern, tc.statement)
			}
		})
	}
}
