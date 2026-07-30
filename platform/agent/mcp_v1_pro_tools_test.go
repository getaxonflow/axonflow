// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestV1ProMCPTools_AllFiveListed asserts the V1 Plugin Pro tool list
// returns exactly 5 entries with the locked names + correct tier gates.
// Plugin SKILL.md / README files (S3 lane of umbrella #1958) reference
// these names verbatim — drift here breaks plugin auto-discovery.
func TestV1ProMCPTools_AllFiveListed(t *testing.T) {
	tools := v1ProMCPTools()
	if len(tools) != 5 {
		t.Fatalf("v1ProMCPTools() returned %d tools, want 5", len(tools))
	}

	expected := map[string]struct {
		requiredTier string
		hasLimit     bool
		limitType    string
	}{
		mcpToolNameGetTenantID:       {"", false, ""},
		mcpToolNameRequestApproval:   {"", true, LimitTypeHITLApprovalsWindow},
		mcpToolNameCreateTenantPolicy: {"", true, LimitTypeActivePolicies},
		mcpToolNameGetCostEstimate:   {"Pro", false, ""},
		mcpToolNameListProFeatures:   {"", false, ""},
	}

	got := make(map[string]bool)
	for _, tool := range tools {
		exp, ok := expected[tool.Name]
		if !ok {
			t.Errorf("unexpected V1 tool name: %q", tool.Name)
			continue
		}
		got[tool.Name] = true
		if tool.RequiredTier != exp.requiredTier {
			t.Errorf("tool %s: RequiredTier = %q, want %q", tool.Name, tool.RequiredTier, exp.requiredTier)
		}
		if exp.hasLimit && tool.FreeUsageLimit == nil {
			t.Errorf("tool %s: FreeUsageLimit is nil, want non-nil", tool.Name)
		}
		if !exp.hasLimit && tool.FreeUsageLimit != nil {
			t.Errorf("tool %s: FreeUsageLimit is non-nil, want nil", tool.Name)
		}
		if tool.FreeUsageLimit != nil && tool.FreeUsageLimit.LimitType != exp.limitType {
			t.Errorf("tool %s: LimitType = %q, want %q", tool.Name, tool.FreeUsageLimit.LimitType, exp.limitType)
		}
		if tool.Description == "" {
			t.Errorf("tool %s: Description is empty", tool.Name)
		}
	}
	for name := range expected {
		if !got[name] {
			t.Errorf("missing V1 tool: %q", name)
		}
	}
}

// TestFilterMCPToolsByTier covers the three tier scenarios that drive
// tools/list filter visibility:
//
//   - Empty tier (self-hosted enterprise / internal-service) → all tools
//   - Free tier → all except Pro-only (axonflow_get_cost_estimate hidden)
//   - Pro tier → all
func TestFilterMCPToolsByTier(t *testing.T) {
	allTools := append(getMCPTools(), v1ProMCPTools()...)
	totalCount := len(allTools)

	cases := []struct {
		name      string
		tier      string
		wantCount int
		mustHide  []string
		mustShow  []string
	}{
		{
			name:      "empty_tier_sees_all",
			tier:      "",
			wantCount: totalCount,
			mustHide:  []string{},
			mustShow:  []string{mcpToolNameGetTenantID, mcpToolNameGetCostEstimate, mcpToolNameListProFeatures},
		},
		{
			name:      "free_hides_cost_estimate",
			tier:      "Free",
			wantCount: totalCount - 1, // axonflow_get_cost_estimate (Pro-only) hidden
			mustHide:  []string{mcpToolNameGetCostEstimate},
			mustShow:  []string{mcpToolNameGetTenantID, mcpToolNameRequestApproval, mcpToolNameCreateTenantPolicy, mcpToolNameListProFeatures},
		},
		{
			name:      "pro_sees_all",
			tier:      "Pro",
			wantCount: totalCount,
			mustHide:  []string{},
			mustShow:  []string{mcpToolNameGetTenantID, mcpToolNameGetCostEstimate, mcpToolNameListProFeatures},
		},
		{
			name:      "premium_sees_all",
			tier:      "Premium",
			wantCount: totalCount,
			mustHide:  []string{},
			mustShow:  []string{mcpToolNameGetCostEstimate},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filtered := filterMCPToolsByTier(allTools, tc.tier)
			if len(filtered) != tc.wantCount {
				t.Errorf("filterMCPToolsByTier(%q) returned %d tools, want %d", tc.tier, len(filtered), tc.wantCount)
			}
			names := make(map[string]bool, len(filtered))
			for _, t := range filtered {
				names[t.Name] = true
			}
			for _, hidden := range tc.mustHide {
				if names[hidden] {
					t.Errorf("tool %q should be hidden for tier=%q but is visible", hidden, tc.tier)
				}
			}
			for _, shown := range tc.mustShow {
				if !names[shown] {
					t.Errorf("tool %q should be visible for tier=%q but is hidden", shown, tc.tier)
				}
			}
		})
	}
}

// TestSaasPluginTierRank covers the rank function used by both filter
// and gate enforcement. Free=0 / Pro=1 / Premium=2; unknown returns 0
// (most-restrictive — fail closed).
func TestSaasPluginTierRank(t *testing.T) {
	cases := []struct {
		tier string
		want int
	}{
		{"Free", 0},
		{"Pro", 1},
		{"Premium", 2},
		{"", 0},
		{"unknown_tier", 0},
		{"free", 0}, // case-sensitive — lowercase doesn't match TierFree
	}
	for _, tc := range cases {
		t.Run(tc.tier, func(t *testing.T) {
			got := saasPluginTierRank(tc.tier)
			if got != tc.want {
				t.Errorf("saasPluginTierRank(%q) = %d, want %d", tc.tier, got, tc.want)
			}
		})
	}
}

// TestEnforceMCPToolGate_EmptyTierBypass asserts self-hosted /
// internal-service callers (empty tier) are never gated. The gating
// framework only applies to SaaS Plugin tiers.
func TestEnforceMCPToolGate_EmptyTierBypass(t *testing.T) {
	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: 1}
	session := &mcpSession{tier: ""} // self-hosted
	tool := mcpTool{
		Name:         mcpToolNameGetCostEstimate,
		RequiredTier: "Pro", // would normally block Free
	}

	if blocked := enforceMCPToolGate(context.Background(), rr, req, session, tool, nil); blocked {
		t.Error("empty-tier caller was gate-blocked — should always pass")
	}
}

// TestEnforceMCPToolGate_RequiredTierBlock asserts a Free caller hitting
// a Pro-only tool gets the feature_pro_only envelope.
func TestEnforceMCPToolGate_RequiredTierBlock(t *testing.T) {
	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: 1}
	session := &mcpSession{tier: "Free", tenantID: "cs_test"}
	tool := mcpTool{
		Name:         mcpToolNameGetCostEstimate,
		RequiredTier: "Pro",
	}

	if blocked := enforceMCPToolGate(context.Background(), rr, req, session, tool, nil); !blocked {
		t.Fatal("Free caller hitting Pro-only tool was NOT blocked")
	}

	// Verify the rejection envelope landed in the JSON-RPC result.
	var envelope rateLimitEnvelope
	if err := extractEnvelopeFromMCPResult(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("could not extract envelope: %v\nbody: %s", err, rr.Body.String())
	}
	if envelope.LimitType != LimitTypeFeatureProOnly {
		t.Errorf("envelope.limit_type = %q, want %q", envelope.LimitType, LimitTypeFeatureProOnly)
	}
	if envelope.Tier != "Free" {
		t.Errorf("envelope.tier = %q, want Free", envelope.Tier)
	}
	if envelope.Upgrade.CompareURL != v1ProUpgradeCompareURL {
		t.Errorf("envelope.upgrade.compare_url = %q, want %q", envelope.Upgrade.CompareURL, v1ProUpgradeCompareURL)
	}
	if envelope.Upgrade.BuyURL != v1ProUpgradeBuyURL {
		t.Errorf("envelope.upgrade.buy_url = %q, want %q", envelope.Upgrade.BuyURL, v1ProUpgradeBuyURL)
	}
	if !strings.Contains(envelope.Upgrade.Wording, "Pro feature") {
		t.Errorf("wording missing locked phrase: %q", envelope.Upgrade.Wording)
	}
}

// TestEnforceMCPToolGate_ProTierPasses asserts a Pro caller hitting a
// Pro-only tool is NOT blocked.
func TestEnforceMCPToolGate_ProTierPasses(t *testing.T) {
	rr := httptest.NewRecorder()
	req := &jsonRPCRequest{ID: 1}
	session := &mcpSession{tier: "Pro", tenantID: "cs_test"}
	tool := mcpTool{
		Name:         mcpToolNameGetCostEstimate,
		RequiredTier: "Pro",
	}
	if blocked := enforceMCPToolGate(context.Background(), rr, req, session, tool, nil); blocked {
		t.Error("Pro caller was gate-blocked on Pro-only tool — should pass")
	}
}

// extractEnvelopeFromMCPResult unwraps the JSON-RPC mcpToolCallResult
// (with isError=true) to extract the V1 Plugin Pro envelope from the
// content[0].text field. Plugins do this same parse — our tests
// exercise the actual wire shape they'll see.
func extractEnvelopeFromMCPResult(body []byte, env *rateLimitEnvelope) error {
	// Wire shape:
	//   {"jsonrpc":"2.0","id":N,"result":{"content":[{"type":"text","text":"<envelope JSON>"}],"isError":true}}
	var rpcResp struct {
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return err
	}
	if !rpcResp.Result.IsError {
		return nil // No error — caller can decide if that's wrong
	}
	if len(rpcResp.Result.Content) == 0 {
		return nil
	}
	return json.Unmarshal([]byte(rpcResp.Result.Content[0].Text), env)
}

// TestMCPToolGetTenantID covers the simplest tool — pure session
// passthrough. Free, Pro, and self-hosted callers all see correct
// tier in the response.
func TestMCPToolGetTenantID(t *testing.T) {
	cases := []struct {
		name        string
		sessionTier string
		wantTier    string
	}{
		{"free", "Free", "Free"},
		{"pro", "Pro", "Pro"},
		{"premium", "Premium", "Premium"},
		{"self_hosted", "", "self-hosted"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := &mcpSession{tenantID: "cs_test_tenant", tier: tc.sessionTier}
			result, err := mcpToolGetTenantID(session)
			if err != nil {
				t.Fatalf("mcpToolGetTenantID returned error: %v", err)
			}
			m, ok := result.(map[string]interface{})
			if !ok {
				t.Fatalf("result is not map: %T", result)
			}
			// Explicit success flag for LLM consumers (#1986)
			if m["success"] != true {
				t.Errorf("success = %v, want true", m["success"])
			}
			if m["tenant_id"] != "cs_test_tenant" {
				t.Errorf("tenant_id = %v, want cs_test_tenant", m["tenant_id"])
			}
			if m["tier"] != tc.wantTier {
				t.Errorf("tier = %v, want %s", m["tier"], tc.wantTier)
			}
			if m["upgrade_url"] != v1ProUpgradeCompareURL {
				t.Errorf("upgrade_url = %v, want %s", m["upgrade_url"], v1ProUpgradeCompareURL)
			}
			if m["buy_url"] != v1ProUpgradeBuyURL {
				t.Errorf("buy_url = %v, want %s", m["buy_url"], v1ProUpgradeBuyURL)
			}
		})
	}
}

// TestMCPToolListProFeatures asserts the data-only Pro feature list
// returns the locked 5-differentiator shape with verbatim values from
// PRD_TENANT_DURABILITY_AND_CLAIM §"Customer-facing copy".
func TestMCPToolListProFeatures(t *testing.T) {
	session := &mcpSession{tenantID: "cs_test", tier: "Free"}
	result, err := mcpToolListProFeatures(session)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not map: %T", result)
	}

	// Explicit success flag for LLM consumers (#1986)
	if m["success"] != true {
		t.Errorf("success = %v, want true", m["success"])
	}

	// Locked pricing
	pricing, _ := m["pricing"].(map[string]interface{})
	if pricing["price_usd"] != 9.99 {
		t.Errorf("pricing.price_usd = %v, want 9.99", pricing["price_usd"])
	}
	if pricing["duration_days"] != 90 {
		t.Errorf("pricing.duration_days = %v, want 90", pricing["duration_days"])
	}

	// 5 differentiators present
	diffs, _ := m["differentiators"].([]map[string]interface{})
	if len(diffs) != 5 {
		t.Errorf("differentiators count = %d, want 5", len(diffs))
	}
	expectedIDs := map[string]bool{
		"daily_quota": false, "audit_retention": false,
		"active_policies": false, "hitl_approvals": false, "cost_preflight": false,
	}
	for _, d := range diffs {
		id, _ := d["id"].(string)
		if _, ok := expectedIDs[id]; ok {
			expectedIDs[id] = true
		}
	}
	for id, found := range expectedIDs {
		if !found {
			t.Errorf("missing differentiator: %s", id)
		}
	}

	// Locked URLs
	if m["upgrade_url"] != v1ProUpgradeCompareURL {
		t.Errorf("upgrade_url = %v, want %s", m["upgrade_url"], v1ProUpgradeCompareURL)
	}
	if m["buy_url"] != v1ProUpgradeBuyURL {
		t.Errorf("buy_url = %v, want %s", m["buy_url"], v1ProUpgradeBuyURL)
	}

	// Tone direction quote present (locked verbatim per umbrella #1958)
	tone, _ := m["tone"].(string)
	if !strings.Contains(tone, "Pro raises the caps") {
		t.Errorf("tone missing locked phrase 'Pro raises the caps': %q", tone)
	}
}

// TestMCPToolGetCostEstimate_HappyPath stands up an httptest server in
// place of the orchestrator and asserts the tool builds the expected
// request body shape, calls /api/v1/plans/estimate, and returns the
// orchestrator's CostEstimateResponse passed through with `model` +
// `plan` injected for plugin convenience.
func TestMCPToolGetCostEstimate_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	var capturedPath string
	var capturedTenantHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedTenantHeader = r.Header.Get("X-Tenant-ID")
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"estimated_cost_usd": 0.0456,
			"currency":           "USD",
			"breakdown": []map[string]interface{}{
				{
					"step_name":            "plan",
					"provider":             "anthropic",
					"model":                "claude-opus-4-7",
					"estimated_tokens_in":  60,
					"estimated_tokens_out": 4096,
					"estimated_cost_usd":   0.0456,
				},
			},
		})
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	session := &mcpSession{tenantID: "cs_pro_tenant", tier: "Pro", clientID: "client-x"}
	result, err := mcpToolGetCostEstimate(session, map[string]interface{}{
		"plan":  "Refactor 10 files in this repo to use the new logger.",
		"model": "claude-opus-4-7",
	})
	if err != nil {
		t.Fatalf("happy path error: %v", err)
	}

	if capturedPath != "/api/v1/plans/estimate" {
		t.Errorf("orchestrator path = %q, want /api/v1/plans/estimate", capturedPath)
	}
	if capturedTenantHeader != "cs_pro_tenant" {
		t.Errorf("X-Tenant-ID = %q, want cs_pro_tenant", capturedTenantHeader)
	}

	if capturedBody["provider"] != "anthropic" {
		t.Errorf("provider = %v, want anthropic (derived from claude-opus)", capturedBody["provider"])
	}
	if capturedBody["model"] != "claude-opus-4-7" {
		t.Errorf("model = %v, want claude-opus-4-7", capturedBody["model"])
	}
	steps, _ := capturedBody["steps"].([]interface{})
	if len(steps) != 1 {
		t.Fatalf("steps len = %d, want 1", len(steps))
	}
	step0, _ := steps[0].(map[string]interface{})
	if step0["type"] != "llm-call" {
		t.Errorf("step.type = %v, want llm-call", step0["type"])
	}
	if step0["prompt"] != "Refactor 10 files in this repo to use the new logger." {
		t.Errorf("step.prompt drift: %v", step0["prompt"])
	}
	if step0["max_tokens"] != float64(4096) {
		t.Errorf("step.max_tokens = %v, want 4096", step0["max_tokens"])
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not map: %T", result)
	}
	if m["estimated_cost_usd"] != 0.0456 {
		t.Errorf("estimated_cost_usd = %v, want 0.0456", m["estimated_cost_usd"])
	}
	if m["currency"] != "USD" {
		t.Errorf("currency = %v, want USD", m["currency"])
	}
	if m["model"] != "claude-opus-4-7" {
		t.Errorf("model passthrough = %v, want claude-opus-4-7", m["model"])
	}
	if _, hasPlan := m["plan"]; !hasPlan {
		t.Error("plan passthrough missing")
	}
	breakdown, _ := m["breakdown"].([]interface{})
	if len(breakdown) != 1 {
		t.Errorf("breakdown len = %d, want 1", len(breakdown))
	}
}

// TestMCPToolGetCostEstimate_OrchestratorError asserts orchestrator
// failures propagate as a clean wrapped error rather than panicking
// or returning malformed data.
func TestMCPToolGetCostEstimate_OrchestratorError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal failure"}`))
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	session := &mcpSession{tenantID: "cs_t", tier: "Pro"}
	_, err := mcpToolGetCostEstimate(session, map[string]interface{}{"plan": "test plan"})
	if err == nil {
		t.Fatal("expected error from 500 orchestrator response, got none")
	}
	if !strings.Contains(err.Error(), "cost estimate failed") {
		t.Errorf("error = %q, want it to contain 'cost estimate failed'", err.Error())
	}
}

// TestMCPToolGetCostEstimate_NonObjectResponse asserts the tool rejects
// orchestrator responses that aren't a JSON object (e.g. raw strings
// or arrays) rather than panicking on a type assertion.
func TestMCPToolGetCostEstimate_NonObjectResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`["not", "a", "map"]`))
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	session := &mcpSession{tenantID: "cs_t", tier: "Pro"}
	_, err := mcpToolGetCostEstimate(session, map[string]interface{}{"plan": "test plan"})
	if err == nil {
		t.Fatal("expected error from non-object response, got none")
	}
	if !strings.Contains(err.Error(), "unexpected response shape") {
		t.Errorf("error = %q, want it to contain 'unexpected response shape'", err.Error())
	}
}

// TestMCPToolGetCostEstimate_RequiredArgs asserts the tool rejects
// missing/empty plan input BEFORE making any network call to the
// orchestrator. (Validation happens in the tool body, not via proxy.)
func TestMCPToolGetCostEstimate_RequiredArgs(t *testing.T) {
	originalURL := orchestratorURL
	orchestratorURL = "http://127.0.0.1:1" // would fail if dialed
	defer func() { orchestratorURL = originalURL }()

	session := &mcpSession{tier: "Pro"}
	for _, args := range []map[string]interface{}{
		{},
		{"plan": ""},
		{"plan": "   "},
	} {
		_, err := mcpToolGetCostEstimate(session, args)
		if err == nil {
			t.Errorf("expected error for args=%v, got none", args)
		}
		if err != nil && !strings.Contains(err.Error(), "plan is required") {
			t.Errorf("error = %q, want it to contain 'plan is required' (proves no network call)", err.Error())
		}
	}
}

// TestDeriveProviderFromModel covers the model→provider mapping used
// to populate the orchestrator request's `provider` field. The
// orchestrator's pricingConfig keys by (provider, model) so getting
// the provider right is load-bearing for accurate estimates.
func TestDeriveProviderFromModel(t *testing.T) {
	cases := []struct {
		model string
		want  string
	}{
		{"claude-opus-4-7", "anthropic"},
		{"claude-sonnet-4-6", "anthropic"},
		{"claude-haiku-4-5", "anthropic"},
		{"opus", "anthropic"},
		{"sonnet-vision", "anthropic"},
		{"gpt-4", "openai"},
		{"gpt-4-turbo", "openai"},
		{"openai/gpt-3.5", "openai"},
		{"gemini-1.5-pro", "google"},
		{"mistral-large", "mistral"},
		{"some-unknown-model", "anthropic"}, // platform default
		{"GPT-4", "openai"},                  // case-insensitive
		{"CLAUDE-SONNET", "anthropic"},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			got := deriveProviderFromModel(tc.model)
			if got != tc.want {
				t.Errorf("deriveProviderFromModel(%q) = %q, want %q", tc.model, got, tc.want)
			}
		})
	}
}

// TestMCPToolRequestApproval_RequiredArgs asserts the tool rejects
// missing/empty required input.
func TestMCPToolRequestApproval_RequiredArgs(t *testing.T) {
	session := &mcpSession{tenantID: "cs_test", tier: "Pro"}
	cases := []map[string]interface{}{
		{},
		{"original_query": "rm -rf"}, // missing request_type
		{"request_type": "shell_command"}, // missing original_query
		{"original_query": "  ", "request_type": "shell_command"},
		{"original_query": "rm -rf", "request_type": "  "},
	}
	for i, args := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			_, err := mcpToolRequestApproval(context.Background(), nil, session, args)
			if err == nil {
				t.Errorf("expected error for args=%v, got none", args)
			}
		})
	}
}

// TestMCPToolCreateTenantPolicy_RequiredArgs asserts the tool rejects
// missing/empty required input + invalid action enum.
func TestMCPToolCreateTenantPolicy_RequiredArgs(t *testing.T) {
	session := &mcpSession{tenantID: "cs_test", tier: "Pro"}
	cases := []map[string]interface{}{
		{},
		{"name": "policy1"}, // missing other required
		{"name": "policy1", "connector_type": "claude_code.Bash", "pattern": ".*", "action": "invalid_action"},
		{"name": "  ", "connector_type": "claude_code.Bash", "pattern": ".*", "action": "block"},
	}
	for i, args := range cases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			_, err := mcpToolCreateTenantPolicy(context.Background(), session, args)
			if err == nil {
				t.Errorf("expected error for args=%v, got none", args)
			}
		})
	}
}

// TestWriteMCPGateError_AllLimitTypes asserts the JSON-RPC envelope
// wrapper produces a parseable response for every locked limit_type.
func TestWriteMCPGateError_AllLimitTypes(t *testing.T) {
	cases := []struct {
		name      string
		limitType string
	}{
		{"daily_quota", LimitTypeDailyQuota},
		{"active_policies", LimitTypeActivePolicies},
		{"hitl_approvals_window", LimitTypeHITLApprovalsWindow},
		{"feature_pro_only", LimitTypeFeatureProOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := &jsonRPCRequest{ID: 42}
			writeMCPGateError(rr, req, tc.limitType, "Free", 1, 0, "", nil)

			var env rateLimitEnvelope
			if err := extractEnvelopeFromMCPResult(rr.Body.Bytes(), &env); err != nil {
				t.Fatalf("could not extract envelope: %v\nbody: %s", err, rr.Body.String())
			}
			if env.LimitType != tc.limitType {
				t.Errorf("envelope.limit_type = %q, want %q", env.LimitType, tc.limitType)
			}
			if env.Tier != "Free" {
				t.Errorf("envelope.tier = %q, want Free", env.Tier)
			}
			if env.Upgrade.CompareURL != v1ProUpgradeCompareURL {
				t.Errorf("envelope.upgrade.compare_url drift: %q", env.Upgrade.CompareURL)
			}
			if env.Upgrade.BuyURL != v1ProUpgradeBuyURL {
				t.Errorf("envelope.upgrade.buy_url drift: %q", env.Upgrade.BuyURL)
			}
		})
	}
}

// TestMCPToolCreateTenantPolicy_HappyPath stands up an httptest server in
// place of the orchestrator and asserts the tool builds the expected
// request body shape, calls /api/v1/policies, and returns the policy
// fields lifted up into the MCP tool response shape with explicit
// success+created flags.
func TestMCPToolCreateTenantPolicy_HappyPath(t *testing.T) {
	var capturedBody map[string]interface{}
	var capturedPath string
	var capturedTenantHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedTenantHeader = r.Header.Get("X-Tenant-ID")
		_ = json.NewDecoder(r.Body).Decode(&capturedBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"policy": map[string]interface{}{
				"id":        "0d2a83cf-9b2e-4d3a-9f1a-7b9c2e1a4d56",
				"policy_id": "tenant-cs_test_p-orch-generated-uuid",
				"name":      "Block ssh-key writes",
				"tier":      "tenant",
				"enabled":   true,
			},
		})
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	session := &mcpSession{tenantID: "cs_test_pro_tenant", tier: "Pro"}
	result, err := mcpToolCreateTenantPolicy(context.Background(), session, map[string]interface{}{
		"name":           "Block ssh-key writes",
		"connector_type": "claude_code.Bash",
		"pattern":        ".*~/\\.ssh/.*",
		"action":         "block",
		"description":    "Prevent the AI from writing ssh keys",
	})
	if err != nil {
		t.Fatalf("happy path error: %v", err)
	}

	if capturedPath != "/api/v1/policies" {
		t.Errorf("orchestrator path = %q, want /api/v1/policies", capturedPath)
	}
	if capturedTenantHeader != "cs_test_pro_tenant" {
		t.Errorf("X-Tenant-ID = %q, want cs_test_pro_tenant", capturedTenantHeader)
	}
	if capturedBody["tier"] != "tenant" {
		t.Errorf("body.tier = %v, want tenant (this is what triggers IsPaidTier on orchestrator)", capturedBody["tier"])
	}
	if capturedBody["type"] != "content" {
		t.Errorf("body.type = %v, want content", capturedBody["type"])
	}
	// #3061: exactly ONE condition — the pattern. A {field:"connector"}
	// condition is deliberately NOT emitted: the orchestrator content engine
	// that governs the LLM/MAP/WCP planes cannot resolve `connector`, so adding
	// it would make the whole policy skip there (all conditions must match) and
	// trade enforcement where it already works for enforcement on the MCP
	// plane. See buildTenantPolicyConditions.
	conds, _ := capturedBody["conditions"].([]interface{})
	if len(conds) != 1 {
		t.Fatalf("conditions len = %d, want 1 (pattern only)", len(conds))
	}
	cond0, _ := conds[0].(map[string]interface{})
	if cond0["field"] != "query" || cond0["operator"] != "regex" || cond0["value"] != ".*~/\\.ssh/.*" {
		t.Errorf("pattern condition shape drift: %v", cond0)
	}
	for _, c := range conds {
		if m, _ := c.(map[string]interface{}); m["field"] == "connector" {
			t.Errorf("a connector condition breaks LLM/MAP/WCP enforcement (#3061): %v", m)
		}
	}
	actions, _ := capturedBody["actions"].([]interface{})
	if len(actions) != 1 {
		t.Fatalf("actions len = %d, want 1", len(actions))
	}
	act0, _ := actions[0].(map[string]interface{})
	if act0["type"] != "block" {
		t.Errorf("action.type = %v, want block (block→block mapping)", act0["type"])
	}

	m, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result not map: %T", result)
	}
	if m["success"] != true || m["created"] != true {
		t.Errorf("missing success/created flags: %v", m)
	}
	if m["id"] != "0d2a83cf-9b2e-4d3a-9f1a-7b9c2e1a4d56" {
		t.Errorf("id passthrough = %v", m["id"])
	}
	if m["policy_id"] != "tenant-cs_test_p-orch-generated-uuid" {
		t.Errorf("policy_id passthrough = %v", m["policy_id"])
	}
	if m["connector_type"] != "claude_code.Bash" {
		t.Errorf("connector_type echo = %v", m["connector_type"])
	}
}

// TestMCPToolCreateTenantPolicy_ActionMapping asserts every supported
// user-facing action maps to the right engine action type. Asserts on
// the body sent to the orchestrator (not just the response).
func TestMCPToolCreateTenantPolicy_ActionMapping(t *testing.T) {
	cases := []struct {
		userAction   string
		engineAction string
	}{
		{"block", "block"},
		{"warn", "alert"},
		{"audit", "log"},
		{"require_approval", "require_approval"},
	}

	for _, tc := range cases {
		t.Run(tc.userAction, func(t *testing.T) {
			var capturedAction string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if actions, ok := body["actions"].([]interface{}); ok && len(actions) > 0 {
					if a0, ok := actions[0].(map[string]interface{}); ok {
						capturedAction, _ = a0["type"].(string)
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"policy": map[string]interface{}{"id": "x"}})
			}))
			defer srv.Close()

			originalURL := orchestratorURL
			orchestratorURL = srv.URL
			defer func() { orchestratorURL = originalURL }()

			_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "t1", tier: "Pro"}, map[string]interface{}{
				"name":           "test",
				"connector_type": "test_connector",
				"pattern":        ".*",
				"action":         tc.userAction,
			})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if capturedAction != tc.engineAction {
				t.Errorf("user action %q → engine action %q, want %q", tc.userAction, capturedAction, tc.engineAction)
			}
		})
	}
}

// TestMCPToolCreateTenantPolicy_PaidTierReject asserts that when the
// orchestrator returns the IsPaidTier rejection (403 with the canonical
// "Enterprise license" wording), the MCP tool surfaces a clearer error
// that distinguishes deployment-license cause from SaaS Plugin tier cap.
// This is the bypass-closure assertion: a Community-tier process now
// correctly rejects tenant-policy creation through the MCP tool path.
func TestMCPToolCreateTenantPolicy_PaidTierReject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error":   "TIER_VALIDATION_FAILED",
			"code":    "tier_validation_enterprise_or_higher",
			"message": "Tenant-tier policies require Enterprise license. Get an Enterprise license at https://getaxonflow.com/enterprise",
		})
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "cs_pro", tier: "Pro"}, map[string]interface{}{
		"name":           "test",
		"connector_type": "x",
		"pattern":        ".*",
		"action":         "block",
	})
	if err == nil {
		t.Fatal("expected error from orchestrator 403 IsPaidTier reject")
	}
	if !strings.Contains(err.Error(), "license tier") || !strings.Contains(err.Error(), "Community caps at 20") {
		t.Errorf("error should surface deployment-license-tier cause and quota numbers, got: %v", err)
	}
}

// TestMCPToolCreateTenantPolicy_OrchestratorDown asserts that when the
// orchestrator URL isn't configured, the tool surfaces a clear error
// rather than panicking or silently succeeding.
func TestMCPToolCreateTenantPolicy_OrchestratorDown(t *testing.T) {
	originalURL := orchestratorURL
	orchestratorURL = ""
	defer func() { orchestratorURL = originalURL }()

	_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "t1", tier: "Pro"}, map[string]interface{}{
		"name":           "test",
		"connector_type": "x",
		"pattern":        ".*",
		"action":         "block",
	})
	if err == nil {
		t.Fatal("expected error when orchestrator not configured")
	}
	if !strings.Contains(err.Error(), "could not create tenant policy") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
}

// TestMCPToolCreateTenantPolicy_GenericOrchestratorError asserts that
// non-403 orchestrator errors (500, 400, etc.) bubble up as a generic
// "could not create" error rather than being misclassified as a
// paid-tier rejection.
func TestMCPToolCreateTenantPolicy_GenericOrchestratorError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"INTERNAL_ERROR","message":"database temporarily unavailable"}`))
	}))
	defer srv.Close()

	originalURL := orchestratorURL
	orchestratorURL = srv.URL
	defer func() { orchestratorURL = originalURL }()

	_, err := mcpToolCreateTenantPolicy(context.Background(), &mcpSession{tenantID: "t1", tier: "Pro"}, map[string]interface{}{
		"name":           "test",
		"connector_type": "x",
		"pattern":        ".*",
		"action":         "block",
	})
	if err == nil {
		t.Fatal("expected error from orchestrator 500")
	}
	if strings.Contains(err.Error(), "Evaluation or Enterprise license") {
		t.Errorf("500 error should NOT be classified as paid-tier reject, got: %v", err)
	}
	if !strings.Contains(err.Error(), "could not create tenant policy") {
		t.Errorf("expected wrapped error, got: %v", err)
	}
}

// TestIsOrchestratorPaidTierReject_Cases covers the classifier in
// isolation across realistic 403 / non-403 / paid-tier-vs-other-403
// inputs. Keeps the classifier honest if message text drifts.
func TestIsOrchestratorPaidTierReject_Cases(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"non-403", fmt.Errorf("orchestrator returned 500: internal error"), false},
		{"403 paid-tier with enterprise wording", fmt.Errorf(`orchestrator returned 403: {"code":"tier_validation_enterprise_or_higher","message":"Tenant policies require Enterprise license"}`), true},
		{"403 paid-tier with evaluation wording", fmt.Errorf(`orchestrator returned 403: {"code":"tier_validation_organization_or_higher","message":"Org policies require Evaluation or Enterprise license"}`), true},
		{"403 paid-tier matches on tier_validation prefix", fmt.Errorf(`orchestrator returned 403: {"code":"tier_validation_enterprise_or_higher"}`), true},
		{"403 policy-limit cap reached", fmt.Errorf(`orchestrator returned 403: {"code":"policy_limit_exceeded","message":"Policy limit of 20 reached for Community tier. Get a free Evaluation license for 50 policies"}`), true},
		{"403 policy-limit wording without code", fmt.Errorf(`orchestrator returned 403: {"message":"Policy limit reached"}`), true},
		{"403 unrelated", fmt.Errorf(`orchestrator returned 403: {"error":"FORBIDDEN","message":"Tenant ID mismatch"}`), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOrchestratorPaidTierReject(tc.err); got != tc.want {
				t.Errorf("isOrchestratorPaidTierReject(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestExtractPolicyFromResponse_Cases exercises the extractor against
// realistic + malformed shapes to catch any regression in response
// translation as the orchestrator's API evolves.
func TestExtractPolicyFromResponse_Cases(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want map[string]interface{}
	}{
		{
			"valid envelope",
			map[string]interface{}{"policy": map[string]interface{}{"id": "abc"}},
			map[string]interface{}{"id": "abc"},
		},
		{"non-map", "string-response", map[string]interface{}{}},
		{"missing policy key", map[string]interface{}{"other": "value"}, map[string]interface{}{}},
		{"policy not an object", map[string]interface{}{"policy": "string"}, map[string]interface{}{}},
		{"nil", nil, map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractPolicyFromResponse(tc.in)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("extractPolicyFromResponse(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
