// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
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
	if !strings.Contains(tone, "Pro removes the caps") {
		t.Errorf("tone missing locked phrase 'Pro removes the caps': %q", tone)
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
			_, err := mcpToolCreateTenantPolicy(context.Background(), nil, session, args)
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
